// Modified by Skwod (core/vendor/n0-mainline-0.7.2.patch).
pub(crate) mod config;
mod info;
pub(crate) mod socket;

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::MutableItem;
use crate::common::{
    FindNodeRequestArguments, Id, Message, MessageType, Node, PutRequestSpecific, RequestSpecific,
    RequestTypeSpecific, SignedAnnounce,
};
use crate::core::{
    Core, PutError, Response, iterative_query::GetRequestSpecific, put_query::PutQuery,
};

use socket::{DatagramHook, KrpcSocket};

pub use info::Info;

#[derive(Debug)]
/// Internal Rpc called in the Dht thread loop, useful to create your own actor setup.
pub(crate) struct Actor {
    pub(crate) socket: KrpcSocket,
    core: Core,

    put_senders: HashMap<Id, Vec<oneshot::Sender<Result<Id, PutError>>>>,
    get_senders: HashMap<Id, Vec<ResponseSender>>,

    /// Configured bootstrap hosts, kept so they can be resolved again.
    bootstrap_hosts: Box<[String]>,
    /// When the bootstrap hosts were last resolved.
    last_bootstrap_resolve: Instant,
    /// Resolution of the bootstrap hosts running in the background.
    bootstrap_resolve: Option<oneshot::Receiver<Vec<SocketAddrV4>>>,
}

/// Minimum time between resolving the bootstrap hosts again while the routing table is empty.
const BOOTSTRAP_RESOLVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long the first resolution holds requests back.
const BOOTSTRAP_WAIT: Duration = Duration::from_secs(5);
const BOOTSTRAP_WAIT_STEP: Duration = Duration::from_millis(100);

impl Actor {
    /// Create a new actor
    pub(crate) fn new(config: config::Config) -> io::Result<Self> {
        let id = if let Some(ip) = config.public_ip {
            Id::from_ip(ip.into())
        } else {
            Id::random()
        };

        let socket = KrpcSocket::new(&config)?;
        // Not here: the resolver may take half a minute, and this is an async runtime's thread.
        let bootstrap_resolve = resolve_in_background(config.bootstrap.clone().into());

        let address = socket.local_addr();
        info!(?address, "Mainline DHT started");

        Ok(Actor {
            socket,
            core: Core::new(id, Vec::new(), config.server_mode, config.server_settings),

            put_senders: HashMap::new(),
            get_senders: HashMap::new(),

            bootstrap_hosts: config.bootstrap.into(),
            last_bootstrap_resolve: Instant::now(),
            bootstrap_resolve: Some(bootstrap_resolve),
        })
    }

    // === Getters ===

    /// Returns the node's Id
    fn id(&self) -> &Id {
        self.core.routing_table.id()
    }

    /// Create a list of unique bootstrapping nodes from all our
    /// routing table to use as `extra_bootsrtap` in next sessions.
    fn to_bootstrap(&self) -> Vec<String> {
        let mut set = HashSet::new();
        for s in self.core.routing_table.to_bootstrap() {
            set.insert(s);
        }
        for s in self.core.signed_peers_routing_table.to_bootstrap() {
            set.insert(s);
        }

        set.iter().cloned().collect()
    }

    /// Returns a thread safe and lightweight summary of this node's
    /// information and statistics.
    fn info(&self) -> Info {
        Info::from(self)
    }

    // === Public Methods ===

    /// Advance the inflight queries, receive incoming requests,
    /// maintain the routing table, and everything else that needs
    /// to happen at every tick.
    fn tick(&mut self) {
        self.periodic_node_maintaenance();

        let mut done_put_queries = self.check_done_put_queries();

        for query in self.core.iterative_queries.values_mut() {
            query.visit_closest(&mut self.socket);
        }

        let done_iterative_queries = self.check_done_iterative_queries();

        self.start_put_queries(&done_iterative_queries, &mut done_put_queries);

        let should_ping_alleged_new_address = self
            .core
            .cleanup_done_queries(&done_iterative_queries, &done_put_queries);

        if let Some(address) = should_ping_alleged_new_address {
            self.ping(address);
        }

        // Cleanup done iterative queries
        for (id, closest_nodes) in done_iterative_queries {
            if let Some(senders) = self.get_senders.remove(&id) {
                for sender in senders {
                    // return closest_nodes to whoever was asking
                    if let ResponseSender::ClosestNodes(sender) = sender {
                        let _ = sender.send(closest_nodes.clone());
                    }
                }
            }
        }

        // Cleanup done PUT query and send a resulting error if any.
        for (id, error) in done_put_queries {
            if let Some(senders) = self.put_senders.remove(&id) {
                let result = if let Some(error) = error {
                    Err(error)
                } else {
                    Ok(id)
                };

                for sender in senders {
                    let _ = sender.send(result.clone());
                }
            }
        }
    }

    /// Process an incoming message from the network.
    fn process_message(&mut self, message: Message, from: SocketAddrV4) {
        let new_query_response = self.handle_incoming_message(message, from);

        // Response for an ongoing GET query
        if let Some((target, response)) = new_query_response
            && let Some(senders) = self.get_senders.get_mut(&target)
        {
            for sender in senders.iter_mut() {
                send(sender, response.clone());
            }
        }
    }

    /// Store a value in the closest nodes, optionally trigger a lookup query if
    /// the cached closest_nodes aren't fresh enough.
    fn put(
        &mut self,
        request: PutRequestSpecific,
        extra_nodes: Option<Box<[Node]>>,
    ) -> Result<(), PutError> {
        self.core.check_concurrency_errors(&request)?;

        let mut query = PutQuery::new(request.clone(), extra_nodes);

        let target = request.target();
        if let Some(closest_nodes) = self.core.get_cached_closest_nodes(target) {
            query.start(&mut self.socket, &closest_nodes)?
        } else {
            self.get(GetRequestSpecific::from(&request), None);
        };

        self.core.put_queries.insert(*target, query);

        Ok(())
    }

    /// Send a message to closer and closer nodes until we can't find any more nodes.
    ///
    /// Queries take few seconds to fully traverse the network, once it is done, it will be removed from
    /// self.iterative_queries. But until then, calling [Actor::get] multiple times, will just return the list
    /// of responses seen so far.
    ///
    /// Effectively, we are caching responses and backing off the network for the duration it takes
    /// to traverse it.
    ///
    /// - `request` [RequestTypeSpecific], except [RequestTypeSpecific::Ping] and
    ///   [RequestTypeSpecific::Put] which will be ignored.
    /// - `extra_nodes` option allows the query to visit specific nodes, that won't necessesarily be visited
    ///   through the query otherwise.
    fn get(
        &mut self,
        request: GetRequestSpecific,
        extra_nodes: Option<&[SocketAddrV4]>,
    ) -> Vec<Response> {
        let target = request.target();

        let mut responses = vec![];

        if let Some(response_from_outgoing_request) = self.core.check_outgoing_put_request(&target)
        {
            responses.push(response_from_outgoing_request);
        }

        if let Some(responses_from_active_query) =
            self.core.check_responses_from_active_query(&target)
        {
            responses.extend_from_slice(responses_from_active_query);

            // Terminate, no need to create another query.
            return responses;
        };

        if let Some((mut query, to_visit)) = self.core.create_iterative_query(request, extra_nodes)
        {
            let node_id = self.id();
            if target == *node_id {
                debug!(?node_id, "Bootstrapping the routing table");
            }

            for address in to_visit {
                query.visit(&mut self.socket, address);
            }

            self.core.iterative_queries.insert(target, query);
        }

        responses
    }

    // === Private Methods ===

    fn periodic_node_maintaenance(&mut self) {
        // Bootstrap if necessary
        if self.core.routing_table.is_empty() {
            self.maybe_resolve_bootstrap();
            self.populate();
        }

        // Every 15 minutes refresh the routing table.
        if self.core.should_refresh_table() {
            self.core.update_last_table_refresh();
            if !self.core.server_mode && !self.core.firewalled {
                info!(
                    "Adaptive mode: have been running long enough (not firewalled), switching to server mode"
                );

                self.set_server_mode(true);
            }
            self.populate();
        }

        if self.core.should_ping_table() {
            self.core.update_last_table_ping();
            let to_ping = self.core.check_nodes_to_ping_and_remove_stale_nodes();
            for address in to_ping {
                self.ping(address);
            }
        }
    }

    /// Resolves the bootstrap hosts again in the background.
    ///
    /// Runs at most every [`BOOTSTRAP_RESOLVE_INTERVAL`]. The hosts are first
    /// resolved when the actor is created. If DNS was not available then, or
    /// the addresses have changed since, the node could otherwise never
    /// bootstrap.
    fn maybe_resolve_bootstrap(&mut self) {
        if self.bootstrap_hosts.is_empty()
            || self.bootstrap_resolve.is_some()
            || self.last_bootstrap_resolve.elapsed() < BOOTSTRAP_RESOLVE_INTERVAL
        {
            return;
        }
        self.last_bootstrap_resolve = Instant::now();
        let hosts = self.bootstrap_hosts.clone();
        debug!("Resolving bootstrap hosts again");
        self.bootstrap_resolve = Some(resolve_in_background(hosts));
    }

    /// Replaces the bootstrap addresses with a finished resolution.
    fn set_bootstrap(&mut self, bootstrap: Vec<SocketAddrV4>) {
        self.bootstrap_resolve = None;
        if bootstrap.is_empty() {
            // Keep the previous addresses, they are better than none.
            return;
        }
        debug!(?bootstrap, "Resolved bootstrap hosts");
        self.core.bootstrap = bootstrap.into();
    }

    fn set_server_mode(&mut self, mode: bool) {
        self.socket.server_mode = mode;
        self.core.server_mode = mode;
    }

    fn handle_incoming_message(
        &mut self,
        message: Message,
        from: SocketAddrV4,
    ) -> Option<(Id, Response)> {
        match message.message_type {
            MessageType::Request(request_specific) => {
                let (response, should_repopulate_routing_tables) = self.core.handle_request(
                    from,
                    message.read_only,
                    message.version,
                    request_specific,
                );

                match response {
                    Some(MessageType::Error(error)) => {
                        self.socket.error(from, message.transaction_id, error)
                    }
                    Some(MessageType::Response(response)) => {
                        self.socket.response(from, message.transaction_id, response)
                    }
                    _ => {}
                }

                if should_repopulate_routing_tables {
                    self.populate();
                }

                None
            }
            _ => self.core.handle_response(from, message),
        }
    }

    fn check_done_put_queries(&self) -> Vec<(Id, Option<PutError>)> {
        self.core
            .put_queries
            .iter()
            .filter_map(|(id, query)| match query.check(&self.socket) {
                Ok(done) => {
                    if done {
                        Some((*id, None))
                    } else {
                        None
                    }
                }
                Err(error) => Some((*id, Some(error))),
            })
            .collect()
    }

    fn check_done_iterative_queries(&self) -> Vec<(Id, Box<[Node]>)> {
        self.core
            .iterative_queries
            .iter()
            .filter_map(|(id, query)| {
                let is_done = query.is_done(&self.socket);
                if is_done {
                    Some((
                        *id,
                        self.core.closest_nodes_from_done_iterative_query(query),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }

    fn start_put_queries(
        &mut self,
        done_iterative_queries: &[(Id, Box<[Node]>)],
        done_put_queries: &mut Vec<(Id, Option<PutError>)>,
    ) {
        for (id, _) in done_iterative_queries {
            if let Some(put_query) = self.core.put_queries.get_mut(id)
                && let Err(error) = put_query.start(
                    &mut self.socket,
                    done_iterative_queries
                        .iter()
                        .find(|(this_id, _)| this_id == id)
                        .map(|(_, closest_nodes)| closest_nodes)
                        .expect("done_iterative_queries"),
                )
            {
                done_put_queries.push((*id, Some(error)))
            }
        }
    }

    /// Ping bootstrap nodes, add them to the routing table with closest query.
    fn populate(&mut self) {
        if self.core.bootstrap.is_empty() {
            return;
        }

        self.get(
            GetRequestSpecific::FindNode(FindNodeRequestArguments { target: *self.id() }),
            None,
        );
    }

    fn ping(&mut self, address: SocketAddrV4) {
        self.socket.request(
            address,
            RequestSpecific {
                requester_id: *self.id(),
                request_type: RequestTypeSpecific::Ping,
            },
        );
    }
}

/// Async event loop driving an already-built [`Actor`].
///
/// [`crate::Dht::new`] builds the actor synchronously (so bind errors surface immediately
/// on the caller) and hands it off here to run in a spawned task.
pub(crate) async fn run(mut actor: Actor, mut receiver: mpsc::Receiver<ActorMessage>) {
    // Maintenance interval
    let mut maintenance = tokio::time::interval(Duration::from_secs(1));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // The bootstrap hosts first (what is asked meanwhile waits in the inbox), but not for long: a
    // resolver that does not answer is waited for in the loop below.
    if let Some(mut resolving) = actor.bootstrap_resolve.take() {
        let started = Instant::now();
        loop {
            match tokio::time::timeout(BOOTSTRAP_WAIT_STEP, &mut resolving).await {
                Ok(resolved) => {
                    actor.set_bootstrap(resolved.unwrap_or_default());
                    break;
                }
                // All senders dropped.
                Err(_) if receiver.is_closed() && receiver.is_empty() => return,
                Err(_) if started.elapsed() >= BOOTSTRAP_WAIT => {
                    actor.bootstrap_resolve = Some(resolving);
                    break;
                }
                Err(_) => {}
            }
        }
    }

    loop {
        // Whatever keeps this loop busy (a flood included), its thread is given back regularly.
        tokio::task::coop::consume_budget().await;

        // Flush any queued outgoing packets
        actor.socket.flush().await;

        let bootstrap_resolve = actor.bootstrap_resolve.as_mut();
        tokio::select! {
            msg = receiver.recv() => {
                match msg {
                    Some(actor_message) => match actor_message {
                        ActorMessage::Info(sender) => {
                            let _ = sender.send(actor.info());
                        }
                        ActorMessage::Put(request, sender, extra_nodes) => {
                            let target = *request.target();

                            match actor.put(request, extra_nodes) {
                                Ok(()) => {
                                    let senders = actor.put_senders.entry(target).or_default();
                                    senders.push(sender);
                                }
                                Err(error) => {
                                    let _ = sender.send(Err(error));
                                }
                            };
                        }
                        ActorMessage::Get(request, mut sender) => {
                            let target = request.target();

                            let responses = actor.get(request, None);
                            for response in responses {
                                send(&mut sender, response);
                            }

                            let senders = actor.get_senders.entry(target).or_default();
                            senders.push(sender);
                        }
                        ActorMessage::ToBootstrap(sender) => {
                            let _ = sender.send(actor.to_bootstrap());
                        }
                        ActorMessage::SetDatagramHook(hook) => {
                            actor.socket.set_datagram_hook(hook);
                        }
                        ActorMessage::SendDatagram(bytes, to) => {
                            actor.socket.send_datagram(bytes, to);
                        }
                    },
                    None => {
                        // All senders dropped, shutdown.
                        debug!("dht::Dht's actor task was shutdown after Drop.");
                        break;
                    }
                }
            }
            messages = actor.socket.recv_batch() => {
                for (message, from) in messages {
                    actor.process_message(message, from);
                }
            }
            resolved = async {
                match bootstrap_resolve {
                    Some(task) => task.await,
                    None => std::future::pending().await,
                }
            } => {
                actor.set_bootstrap(resolved.unwrap_or_default());
            }
            _ = maintenance.tick() => {
                // Wake the loop so actor.tick() runs even when idle,
                // ensuring routing table refresh and node pings happen on schedule.
            }
        }

        actor.tick();
    }
}

/// Tests: resolving this takes 15 s.
#[cfg(test)]
const SLOW_HOST: &str = "slow.invalid:";
#[cfg(test)]
static SLOW_RESOLUTIONS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Resolutions in progress, and who waits for each.
type Resolving = HashMap<Box<[String]>, Vec<oneshot::Sender<Vec<SocketAddrV4>>>>;
static RESOLVING: LazyLock<Mutex<Resolving>> = LazyLock::new(Mutex::default);

fn resolving() -> MutexGuard<'static, Resolving> {
    RESOLVING.lock().unwrap_or_else(|e| e.into_inner())
}

/// [`resolve_bootstrap_hosts`] on a thread of its own: neither a runtime being shut down nor the
/// process exiting waits for the resolver (as they would for a runtime's blocking task). One
/// thread at a time for the same hosts, however many nodes are built while a resolver hangs: the
/// later ones wait for the answer to the first.
fn resolve_in_background(hosts: Box<[String]>) -> oneshot::Receiver<Vec<SocketAddrV4>> {
    /// Takes the entry away whatever becomes of the thread (who waits sees the sender gone).
    struct InProgress(Box<[String]>);
    impl Drop for InProgress {
        fn drop(&mut self) {
            resolving().remove(&self.0);
        }
    }

    let (done, resolved) = oneshot::channel();
    {
        let mut resolving = resolving();
        if let Some(waiting) = resolving.get_mut(&hosts) {
            waiting.retain(|w| !w.is_closed());
            waiting.push(done);
            return resolved;
        }
        resolving.insert(hosts.clone(), vec![done]);
    }
    let in_progress = InProgress(hosts);
    // (Not started: the entry goes with the closure, and the hosts are resolved again later.)
    let _ = std::thread::Builder::new()
        .name("dht-bootstrap".into())
        .spawn(move || {
            let addresses = resolve_bootstrap_hosts(&in_progress.0);
            let waiting = resolving().remove(&in_progress.0).unwrap_or_default();
            for w in waiting {
                let _ = w.send(addresses.clone());
            }
            // (The entry is gone already, and may be another resolution's by now.)
            std::mem::forget(in_progress);
        });
    resolved
}

/// Resolves bootstrap hosts to IPv4 addresses, logging resolution errors.
fn resolve_bootstrap_hosts(hosts: &[String]) -> Vec<SocketAddrV4> {
    let mut resolved = Vec::new();
    for host in hosts {
        #[cfg(test)]
        if host.starts_with(SLOW_HOST) {
            SLOW_RESOLUTIONS.lock().unwrap().push(host.clone());
            std::thread::sleep(Duration::from_secs(15));
            continue;
        }
        match host.to_socket_addrs() {
            Ok(addrs) => resolved.extend(addrs.filter_map(|addr| match addr {
                SocketAddr::V4(addr_v4) => Some(addr_v4),
                _ => None,
            })),
            Err(error) => {
                warn!(host, %error, "Failed to resolve bootstrap host");
            }
        }
    }
    resolved
}

fn send(sender: &mut ResponseSender, response: Response) {
    match (sender, response) {
        (ResponseSender::Peers(s), Response::Peers(r)) => {
            let _ = s.send(r);
        }
        (ResponseSender::SignedPeers(s), Response::SignedPeers(r)) => {
            let _ = s.send(r);
        }
        (ResponseSender::Mutable(s), Response::Mutable(r)) => {
            let _ = s.send(r);
        }
        (ResponseSender::Immutable(s), Response::Immutable(r)) => {
            if let Some(tx) = s.take() {
                let _ = tx.send(r);
            }
        }
        _ => {}
    }
}

#[derive(Debug)]
pub(crate) enum ActorMessage {
    Info(oneshot::Sender<Info>),
    Put(
        PutRequestSpecific,
        oneshot::Sender<Result<Id, PutError>>,
        Option<Box<[Node]>>,
    ),
    Get(GetRequestSpecific, ResponseSender),
    ToBootstrap(oneshot::Sender<Vec<String>>),
    SetDatagramHook(Option<DatagramHook>),
    SendDatagram(Vec<u8>, SocketAddrV4),
}

/// Sender side for streaming GET query results back to the caller.
#[derive(Debug)]
pub(crate) enum ResponseSender {
    ClosestNodes(oneshot::Sender<Box<[Node]>>),
    Peers(mpsc::UnboundedSender<Vec<SocketAddrV4>>),
    #[allow(dead_code)]
    SignedPeers(mpsc::UnboundedSender<Vec<SignedAnnounce>>),
    Mutable(mpsc::UnboundedSender<MutableItem>),
    Immutable(Option<oneshot::Sender<Box<[u8]>>>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dht, Testnet};

    /// A node whose bootstrap hosts failed to resolve recovers once they resolve.
    #[tokio::test]
    async fn resolves_bootstrap_hosts_again() {
        let testnet = Testnet::new(3).await.unwrap();

        let config = config::Config {
            bootstrap: vec!["bootstrap.invalid:6881".to_string()],
            ..Default::default()
        };
        let mut actor = Actor::new(config).unwrap();
        assert!(actor.core.bootstrap.is_empty());

        // DNS works again: the hosts now resolve, and the interval has passed.
        actor.bootstrap_hosts = testnet.bootstrap.clone().into();
        actor.last_bootstrap_resolve = Instant::now() - BOOTSTRAP_RESOLVE_INTERVAL;

        let (sender, receiver) = mpsc::channel(16);
        tokio::spawn(run(actor, receiver));
        let dht = Dht(sender);

        tokio::time::timeout(Duration::from_secs(10), async {
            while !dht.bootstrapped().await.unwrap() {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("node did not bootstrap after its hosts resolved");
    }

    fn ticker() -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        let ticks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mine = ticks.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                mine.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });
        ticks
    }

    /// A flood of datagrams from outside never takes the runtime's only thread.
    #[tokio::test(flavor = "current_thread")]
    async fn a_flood_leaves_the_thread_to_others() {
        let dht = Dht::builder().no_bootstrap().build().unwrap();
        let to = ("127.0.0.1", dht.info().await.unwrap().local_addr().port());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let floods: Vec<_> = (0..2)
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        let _ = socket.send_to(&[b'x'; 200], to);
                    }
                })
            })
            .collect();
        let ticks = ticker();
        tokio::time::sleep(Duration::from_secs(1)).await;
        let n = ticks.load(std::sync::atomic::Ordering::SeqCst);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for f in floods {
            f.join().unwrap();
        }
        assert!(n > 30, "{n} ticks");
    }

    /// A resolver that takes its time: building a node does not wait for it, nor do others on the
    /// thread, nor the node's own end, nor the runtime's.
    #[test]
    fn a_slow_resolver_holds_up_nobody() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let started = Instant::now();
        runtime.block_on(async {
            let dht = Dht::builder().bootstrap(&[format!("{SLOW_HOST}1")]).build().unwrap();
            assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
            let ticks = ticker();
            // Answered as soon as the wait is over, without the hosts.
            let asked = Instant::now();
            let info = tokio::time::timeout(BOOTSTRAP_WAIT + Duration::from_secs(2), dht.info()).await;
            assert!(info.unwrap().is_ok());
            assert!(asked.elapsed() >= BOOTSTRAP_WAIT - Duration::from_secs(1));
            assert!(ticks.load(std::sync::atomic::Ordering::SeqCst) > 200);

            // Let go of while it resolves: the actor ends.
            let dht = Dht::builder().bootstrap(&[format!("{SLOW_HOST}1")]).build().unwrap();
            let before = tokio::runtime::Handle::current().metrics().num_alive_tasks();
            drop(dht);
            tokio::time::sleep(Duration::from_millis(400)).await;
            assert!(tokio::runtime::Handle::current().metrics().num_alive_tasks() < before);
            let _still_resolving = Dht::builder().bootstrap(&[format!("{SLOW_HOST}1")]).build().unwrap();
        });
        let ending = Instant::now();
        drop(runtime);
        assert!(ending.elapsed() < Duration::from_secs(1), "{:?}", ending.elapsed());
    }

    /// Endpoint after endpoint while the resolver hangs: one thread. Who was let go of is not kept.
    #[tokio::test(flavor = "current_thread")]
    async fn many_nodes_share_one_slow_resolution() {
        let host = format!("{SLOW_HOST}2");
        let mut kept = Vec::new();
        for n in 0..50 {
            let dht = Dht::builder().bootstrap(&[&host]).build().unwrap();
            if n % 10 == 0 {
                kept.push(dht);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let resolutions = SLOW_RESOLUTIONS.lock().unwrap().iter().filter(|h| **h == host).count();
        assert_eq!(resolutions, 1);
        let _one_more = Dht::builder().bootstrap(&[&host]).build().unwrap();
        let waiting = resolving().get(&vec![host.clone()].into_boxed_slice()).map_or(0, Vec::len);
        assert!(waiting <= kept.len() + 1, "{waiting} waiting");
    }
}
