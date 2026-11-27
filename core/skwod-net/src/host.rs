//! Host side: accept `skwod/1` connections and bridge their streams.
//!
//! The HTTP service itself is supplied by the server crate through [`HostBackend`], so this crate
//! stays independent of the web framework and the server never opens an extra TCP listener: each
//! QUIC bi-stream is handed over as an in-process byte stream.

use std::net::SocketAddr;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::time::Duration;

use iroh::endpoint::{Connection, IncomingAddr, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::Semaphore;

use crate::wire::{self, BiStream};
use crate::{BoxFuture, NetConfig, NetError};

/// Hard ceiling on concurrent member connections (a friend-group server; this only bounds abuse).
const MAX_CONNECTIONS: usize = 1024;
/// Slots only signed-in members may occupy. Node ids are free to mint and a QUIC handshake is
/// cheap, so anyone could otherwise take every slot with idle connections and lock the members
/// out; with this, strangers compete only among themselves.
const RESERVED_FOR_AUTHENTICATED: usize = 256;
/// A connection that has not shown a valid session is closed this long after it was opened or
/// last opened a stream…
const UNAUTHENTICATED_IDLE: Duration = Duration::from_secs(10);
/// …and at the latest after this long, however busy it keeps itself. (Signing up or in takes
/// one request; the member side redials on demand, so a real person at the login screen never
/// notices.)
const UNAUTHENTICATED_MAX: Duration = Duration::from_secs(60);
/// Connections one ACCOUNT may hold at once (its phone, laptop, tablet… each is one). Node ids
/// are free, so without this a single signed-in account — or a removed member whose session
/// still lives — could take every reserved slot.
pub const MAX_PER_ACCOUNT: usize = 4;
/// How often an authenticated connection's account is re-validated.
const AUTH_RECHECK: Duration = Duration::from_secs(60);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection that must prove work has to deliver its stamp.
const PROOF_GRACE: Duration = Duration::from_secs(3);
/// Handshakes in flight for connections that will have to prove work.
const MAX_PROVING: usize = 256;
/// Relayed dials one node id may make per minute.
const MAX_RELAYED_DIALS_PER_NODE: u32 = 12;
/// New connections one source address may open per minute. Node ids are free to mint, so the cost
/// of a fresh identity is bounded per SOURCE here (in memory only, never logged) rather than by a
/// shared bucket that a few throwaway keys could exhaust for everybody.
const MAX_HANDSHAKES_PER_SOURCE: u32 = 30;
/// Streams (≈ requests) one connection may open per window before it is dropped.
const MAX_STREAMS_PER_WINDOW: u32 = 600;
const STREAM_WINDOW: Duration = Duration::from_secs(10);

/// Sources tracked at once. When full (after expiring old windows) NEW sources are refused
/// rather than letting the table grow without bound; known sources keep their windows.
const MAX_TRACKED_SOURCES: usize = 8192;
/// Relayed dials carry no source address, so they share one token bucket: a burst of
/// `RELAY_BURST` new connections, refilled at `RELAY_PER_SEC`. It only gates NEW relayed
/// connections — established members (whose connections are long-lived) are never affected.
const RELAY_BURST: f64 = 60.0;
const RELAY_PER_SEC: f64 = 2.0;

/// The unit a source is counted as: an IPv4 address, or an IPv6 /64 (one subscriber typically
/// controls a whole /64, so per-address counting would be no limit at all).
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        v4 => v4,
    }
}

/// What a new connection has to do to get a slot. Decided before the handshake from what is
/// known then (a validated source address, or the relay's word for the dialing node), and
/// applied after it — when the peer's node id has been authenticated.
///
/// # Admission
///
/// 1. A direct dial whose source address is not validated is answered with a QUIC Retry and
///    counted nowhere.
/// 2. Within its source's allowance (direct) or the relay bucket (relayed) a connection is
///    admitted FREE: after the handshake it takes a slot as a stranger.
/// 3. Beyond that it MUST PROVE work: after the handshake its first stream has to be a valid
///    connection stamp (`pow::Purpose::Connection`), or it is closed. At most
///    [`MAX_PROVING`] such handshakes are in flight. A node the backend already knows as a
///    signed-in member is exempt.
/// 4. A connection that proved work — at admission or later — gives way, among strangers,
///    only to another that did ([`ConnTable`], rule (b)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Free,
    MustProve,
    Refuse,
}

/// Admission control for new connections. Holds source prefixes in memory for at most a minute;
/// nothing here is ever logged.
struct SourceLimiter {
    windows: HashMap<IpAddr, (Instant, u32)>,
    /// Relayed dials per node id (the relay vouches for which node is dialing).
    relayed: HashMap<[u8; 32], (Instant, u32)>,
    relay_tokens: f64,
    relay_refilled: Instant,
}

impl SourceLimiter {
    fn new(now: Instant) -> Self {
        Self { windows: HashMap::new(), relayed: HashMap::new(), relay_tokens: RELAY_BURST, relay_refilled: now }
    }

    /// A direct dial from `ip`.
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        const WINDOW: Duration = Duration::from_secs(60);
        let key = source_key(ip);
        if !self.windows.contains_key(&key) && self.windows.len() >= MAX_TRACKED_SOURCES {
            self.windows.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            if self.windows.len() >= MAX_TRACKED_SOURCES {
                return false;
            }
        }
        let entry = self.windows.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= MAX_HANDSHAKES_PER_SOURCE
    }

    /// A direct dial from the VALIDATED address `ip`: free within the source's allowance,
    /// for proof of work beyond it (someone sharing the address — a NAT, a campus — has used
    /// it up, or the table of sources is full).
    fn admit_direct(&mut self, ip: IpAddr, now: Instant) -> Admission {
        if self.allow(ip, now) {
            Admission::Free
        } else {
            Admission::MustProve
        }
    }

    /// A relayed dial by the node `id` (as the relay names it). One node id redialing faster
    /// than any app does is refused outright. Otherwise: free while the shared bucket has
    /// tokens, and for proof of work when it is dry — a drained bucket used to refuse EVERY
    /// new relayed connection, so two dials a second kept a host behind NAT closed to all.
    fn admit_relayed(&mut self, id: Option<[u8; 32]>, now: Instant) -> Admission {
        const WINDOW: Duration = Duration::from_secs(60);
        if let Some(id) = id {
            if !self.relayed.contains_key(&id) && self.relayed.len() >= MAX_TRACKED_SOURCES {
                self.relayed.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
            }
            if self.relayed.len() < MAX_TRACKED_SOURCES || self.relayed.contains_key(&id) {
                let entry = self.relayed.entry(id).or_insert((now, 0));
                if now.duration_since(entry.0) >= WINDOW {
                    *entry = (now, 0);
                }
                entry.1 += 1;
                if entry.1 > MAX_RELAYED_DIALS_PER_NODE {
                    return Admission::Refuse;
                }
            }
        }
        if self.allow_relayed(now) {
            Admission::Free
        } else {
            Admission::MustProve
        }
    }

    /// A dial with no source address (via a relay / custom transport).
    fn allow_relayed(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.relay_refilled).as_secs_f64();
        self.relay_tokens = (self.relay_tokens + elapsed * RELAY_PER_SEC).min(RELAY_BURST);
        self.relay_refilled = now;
        if self.relay_tokens < 1.0 {
            return false;
        }
        self.relay_tokens -= 1.0;
        true
    }
}

/// Where the host's LiveKit lives (always loopback / a private address — never dialed by members).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveKitTarget {
    /// LiveKit's signaling (HTTP/WS) port.
    pub signal: SocketAddr,
    /// LiveKit's UDP mux port as reachable FROM THE SERVER.
    pub udp: SocketAddr,
    /// The UDP port LiveKit puts in its `127.0.0.1` ICE candidate — the port the member-side
    /// forwarder must bind. Equal to `udp.port()` unless LiveKit sits behind a port mapping.
    pub advertised_udp_port: u16,
}

pub trait HostBackend: Send + Sync + 'static {
    /// Serve HTTP/1.1 on `io` for the authenticated peer `peer`. `relayed` says whether the
    /// connection currently runs through a relay (no source address was ever seen for it) —
    /// rate limiting keeps those two populations apart. Resolves when the stream is done.
    fn serve_http(&self, peer: EndpointId, relayed: bool, io: BiStream) -> BoxFuture<()>;
    /// May the holder of `bearer` use voice RIGHT NOW? Must reflect current state (session not
    /// expired/revoked, account still exists and is still a member): it is asked again for every
    /// LiveKit stream and every [`HostBackend::voice_recheck_interval`] while media flows, and a
    /// `false` tears the connection's voice access down.
    fn authorize_voice(&self, bearer: String) -> BoxFuture<bool>;
    /// May the holder of `bearer` be in LiveKit room `room` as participant `identity` RIGHT NOW?
    /// Asked for every LiveKit stream (the room/identity come from the LiveKit token the stream
    /// carries) and again on the recheck timer for every room the connection has joined — so
    /// being removed from ONE space cuts that space's rooms even if the user is still a member
    /// elsewhere on the instance.
    fn authorize_room(&self, bearer: String, room: String, identity: String) -> BoxFuture<bool>;
    /// The LiveKit to bridge to, if this instance runs one.
    fn livekit(&self) -> BoxFuture<Option<LiveKitTarget>>;
    /// The account `peer` (a node id) is signed in as RIGHT NOW, if any: the backend resolved a
    /// live session for a request from this node, that session is still valid, and the account
    /// is still a member. Asked when a connection opens, when its unauthenticated grace runs
    /// out, and every [`AUTH_RECHECK`] afterwards — a `None` then closes the connection.
    /// Connections without an account are short-lived and the first to go when the host is
    /// full; an account holds at most [`MAX_PER_ACCOUNT`] (see [`ConnTable`]). The default —
    /// nobody is signed in — suits a backend with no accounts.
    fn peer_account(&self, _peer: EndpointId) -> BoxFuture<Option<String>> {
        Box::pin(async { None })
    }
    /// When `user` became a member (unix ms): seniority, for [`ConnTable`] rule (d). The
    /// default (0 for everyone) makes that rule inert.
    fn account_since(&self, _user: String) -> BoxFuture<i64> {
        Box::pin(async { 0 })
    }
    /// The last connection of `peer` has closed: forget whatever standing the node had.
    fn peer_disconnected(&self, _peer: EndpointId) {}
    /// How often a connection's voice grant is re-validated while it is in use.
    fn voice_recheck_interval(&self) -> Duration {
        Duration::from_secs(30)
    }
}

/// Per-connection voice grant. Not a one-shot flag: it holds the token it was granted for and is
/// revoked the moment that token stops being valid.
struct VoiceGate {
    token: Mutex<Option<String>>,
    /// `(room, identity)` pairs this connection has been let into; each is re-validated.
    rooms: Mutex<HashSet<(String, String)>>,
    /// Bumped on every revocation; live LiveKit streams watch it and stop.
    revoked: tokio::sync::watch::Sender<u64>,
    /// The media forwarder and the LiveKit port it was started for.
    forwarder: Mutex<Option<(SocketAddr, tokio::task::AbortHandle)>>,
    recheck: Mutex<Option<tokio::task::AbortHandle>>,
}

impl VoiceGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            token: Mutex::new(None),
            rooms: Mutex::default(),
            revoked: tokio::sync::watch::channel(0).0,
            forwarder: Mutex::new(None),
            recheck: Mutex::new(None),
        })
    }

    fn token(&self) -> Option<String> {
        self.token.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Drop the grant: stop media forwarding and cut every LiveKit signaling stream.
    fn revoke(&self) {
        *self.token.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).clear();
        if let Some((_, task)) = self.forwarder.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        if let Some(task) = self.recheck.lock().unwrap_or_else(|e| e.into_inner()).take() {
            task.abort();
        }
        self.revoked.send_modify(|generation| *generation += 1);
    }

    /// Re-validate the session AND every room joined on this connection. Any failure revokes
    /// the whole grant (media has no per-room separation on the wire, so partial access is not
    /// a state we keep).
    async fn check(&self, backend: &dyn HostBackend) -> bool {
        let Some(token) = self.token() else { return false };
        let mut ok = backend.authorize_voice(token.clone()).await;
        let rooms: Vec<(String, String)> = self.rooms.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
        for (room, identity) in rooms {
            ok = ok && backend.authorize_room(token.clone(), room, identity).await;
        }
        if !ok {
            self.revoke();
        }
        ok
    }

    /// Admit one LiveKit stream bound for `room` as `identity`.
    async fn admit(&self, backend: &dyn HostBackend, room: String, identity: String) -> bool {
        let Some(token) = self.token() else { return false };
        if !backend.authorize_voice(token.clone()).await {
            self.revoke();
            return false;
        }
        if !backend.authorize_room(token, room.clone(), identity.clone()).await {
            return false;
        }
        self.rooms.lock().unwrap_or_else(|e| e.into_inner()).insert((room, identity));
        true
    }
}

/// A LiveKit signaling request that passed validation, with the request to send upstream.
#[derive(Debug)]
pub(crate) struct LiveKitRequest {
    pub room: String,
    pub identity: String,
    /// True only for a genuine WebSocket handshake; everything else is one request, then close.
    pub websocket: bool,
    /// Built from typed parts (`http::Uri`, `HeaderMap`) and carrying exactly ONE credential —
    /// the validated token — so LiveKit cannot be looking at a different token than the host
    /// authorized, and nothing the client sent is copied through as raw bytes.
    pub forward: hyper::Request<http_body_util::Empty<bytes::Bytes>>,
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if b[i] == b'%' {
            if let (Some(h), Some(l)) = (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Validate a LiveKit signaling request that hyper has ALREADY parsed (strict HTTP/1.1: no bare
/// CR/LF/NUL in the request line or headers, no obsolete folding) and build the upstream request.
///
/// `has_body` is hyper's view of whether the request carries a body.
///
/// Rejected (→ `None`): no credential; more than one credential of any kind (repeated
/// `access_token` — also when the KEY is percent-encoded — or query + `Authorization`, or two
/// `Authorization` headers); a non-bearer `Authorization`; a request body; a token that isn't
/// plain base64url. The token's SIGNATURE is not checked here — LiveKit does that; a forged
/// token only gets a forger refused twice.
pub(crate) fn validate_livekit_request(parts: &hyper::http::request::Parts, has_body: bool) -> Option<LiveKitRequest> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use hyper::header::{HeaderName, AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, UPGRADE};

    if has_body || parts.headers.contains_key(TRANSFER_ENCODING) {
        return None; // a signaling request has no body; refusing one removes every length trick
    }

    // Credentials: collect EVERY one, wherever it is, then require exactly one.
    let mut tokens: Vec<String> = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    for pair in parts.uri.query().unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(k) == "access_token" {
            tokens.push(percent_decode(v));
        } else {
            kept.push(pair);
        }
    }
    let token_in_query = !tokens.is_empty();
    for value in parts.headers.get_all(AUTHORIZATION) {
        let (scheme, token) = value.to_str().ok()?.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return None;
        }
        tokens.push(token.trim().to_string());
    }
    let [jwt] = tokens.as_slice() else { return None };
    if jwt.is_empty() || !jwt.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b'=')) {
        return None;
    }
    let claims = jwt.split('.').nth(1)?;
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims.trim_end_matches('=')).ok()?).ok()?;
    let room = claims["video"]["room"].as_str().filter(|r| !r.is_empty())?.to_string();
    let identity = claims["sub"].as_str().filter(|s| !s.is_empty())?.to_string();

    // A stream becomes a raw pipe ONLY for a genuine WebSocket handshake.
    let header_has = |name: HeaderName, want: &str| {
        parts.headers.get_all(name).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(|t| t.trim().eq_ignore_ascii_case(want))
    };
    let websocket = parts.method == hyper::Method::GET && header_has(UPGRADE, "websocket") && header_has(CONNECTION, "upgrade");

    // Upstream request, from typed parts only.
    let mut target = parts.uri.path().to_string();
    let mut sep = '?';
    for pair in kept {
        target.push(sep);
        target.push_str(pair);
        sep = '&';
    }
    if token_in_query {
        target.push(sep);
        target.push_str("access_token=");
        target.push_str(jwt);
    }
    let uri: hyper::Uri = target.parse().ok()?; // re-validated: no spaces / control bytes survive
    let mut forward = hyper::Request::new(http_body_util::Empty::new());
    *forward.method_mut() = parts.method.clone();
    *forward.uri_mut() = uri;
    for (name, value) in &parts.headers {
        // Hop-by-hop + credential + framing headers are never copied; they are set below.
        if [AUTHORIZATION, CONNECTION, UPGRADE, CONTENT_LENGTH, TRANSFER_ENCODING, HOST].contains(name) {
            continue;
        }
        forward.headers_mut().append(name.clone(), value.clone());
    }
    let h = forward.headers_mut();
    h.insert(HOST, hyper::header::HeaderValue::from_static("livekit"));
    if !token_in_query {
        h.insert(AUTHORIZATION, hyper::header::HeaderValue::from_str(&format!("Bearer {jwt}")).ok()?);
    }
    if websocket {
        h.insert(CONNECTION, hyper::header::HeaderValue::from_static("Upgrade"));
        h.insert(UPGRADE, hyper::header::HeaderValue::from_static("websocket"));
    } else {
        h.insert(CONNECTION, hyper::header::HeaderValue::from_static("close"));
    }
    Some(LiveKitRequest { room, identity, websocket, forward })
}

pub struct Host {
    slots: Slots,
    endpoint: Endpoint,
    accept: tokio::task::JoinHandle<()>,
    /// Opt-in LAN announcement (`lan.rs`); `None` unless the host turned it on.
    lan: Option<tokio::task::JoinHandle<()>>,
}

impl Host {
    pub async fn start(cfg: &NetConfig, backend: Arc<dyn HostBackend>) -> Result<Self, NetError> {
        let endpoint = crate::bind(cfg).await?;
        let slots: Slots = Arc::new(Shared {
            table: std::sync::Mutex::new(ConnTable::new(MAX_CONNECTIONS, RESERVED_FOR_AUTHENTICATED, MAX_PER_ACCOUNT)),
            promoted: tokio::sync::watch::channel(0).0,
            retried: Default::default(),
        });
        let accept = tokio::spawn(accept_loop(endpoint.clone(), backend, slots.clone()));
        let lan = match (cfg.plan().mdns_advertise, cfg.lan_key) {
            (true, Some(key)) => Some(crate::lan::advertise(&endpoint, key)),
            _ => None,
        };
        Ok(Self { slots, endpoint, accept, lan })
    }

    /// How many direct dials were made to validate their address (QUIC Retry) so far.
    pub fn address_validations(&self) -> u64 {
        self.slots.retried.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// For the backend: call it where a request's session has been resolved (see [`Promoter`]).
    pub fn promoter(&self) -> Promoter {
        Promoter(self.slots.clone())
    }

    /// Is this host announcing itself on the local network?
    pub fn lan_advertising(&self) -> bool {
        self.lan.is_some()
    }

    /// The skwod's address and pinned identity.
    pub fn node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Full dialing info (node id + currently known addresses) — for tests and same-machine dials.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Dialing info that reaches this host over loopback only — the same-machine path (and what
    /// the in-process tests use: no discovery, no network).
    pub fn loopback_addr(&self) -> EndpointAddr {
        let mut addr = EndpointAddr::new(self.endpoint.id());
        for sock in self.endpoint.bound_sockets() {
            let lo: SocketAddr = match sock {
                SocketAddr::V4(_) => ([127, 0, 0, 1], sock.port()).into(),
                SocketAddr::V6(_) => ([0u16, 0, 0, 0, 0, 0, 0, 1], sock.port()).into(),
            };
            addr = addr.with_ip_addr(lo);
        }
        addr
    }

    pub async fn shutdown(self) {
        if let Some(lan) = &self.lan {
            lan.abort(); // dropping the task drops the announcement
        }
        self.accept.abort();
        self.endpoint.close().await;
    }
}

/// Who holds the connection slots. Pure bookkeeping (no I/O), so the policy is testable.
///
/// # The policy
///
/// Let `max` be the slot count, `reserved` the part of it strangers may never use, and
/// `per_account` the most connections one account may hold. Every connection is either
/// *unauthenticated* (no account: the backend has not resolved a live session of a current
/// member for its node) or belongs to exactly one account.
///
/// **Invariants**
///
/// 1. `len ≤ max`.
/// 2. `unauthenticated ≤ max − reserved`.
/// 3. For every account `a`: `held(a) ≤ per_account`.
///
/// **A new connection** is admitted if the invariants hold with it added; otherwise room is
/// made by evicting ONE connection, chosen in this order, and if none qualifies the newcomer
/// is refused:
///
/// - (a) the newcomer's own account's oldest connection (only if the newcomer has an account);
/// - (b) the oldest unauthenticated connection that has not proven work; one that has gives
///   way only to a newcomer that is a member or proved work itself;
/// - (c) the oldest connection of the account that holds the MOST slots — but only if that
///   account holds more than its fair share, `fair = max / accounts` (integer division, at
///   least 1), where `accounts` is the number of distinct accounts connected, counting the
///   newcomer's. Only an authenticated newcomer may use (c);
/// - (d) a connection of the most recently admitted MEMBER, if the newcomer has been a member
///   for longer. Only an authenticated newcomer may use (d).
///
/// An unauthenticated newcomer therefore only ever displaces another stranger (b), and is
/// refused when every slot is a member's. A connection of an account at or below `fair` is
/// never evicted for someone else — no amount of reconnecting by one account, with any number
/// of node ids, can push another member out: its own churn hits (3) and then (a) first, and
/// (c) can only take from an account holding more than `fair`.
///
/// Arithmetic for the shipped numbers (`max` 1024, `reserved` 256, `per_account` 4): strangers
/// can hold at most 768 slots and 256 are always free for members; one account holds at most
/// 4; `fair` is ≥ 4 for up to 256 connected accounts, so with ≤ 256 accounts (c) never fires
/// (nobody can exceed a fair share that is ≥ the cap) and with more — more than 256 accounts
/// each wanting several devices on a friend-group server — the largest holders give up one
/// slot at a time down to `fair`. 20 members with 2 devices each need 40 slots.
///
/// **Promotion** ([`ConnTable::mark_authenticated`]): a connection that turns out to be
/// account `a`'s keeps its slot; if that puts `a` over `per_account`, `a`'s own oldest
/// connections are evicted. **Demotion** ([`ConnTable::downgrade`]): a connection whose
/// account is gone (signed out, expired, removed) is a stranger again and is closed by its
/// owner task.
///
/// "Idle" needs no rule of its own: an unauthenticated connection is closed by its task
/// [`UNAUTHENTICATED_IDLE`] after its last stream, and an authenticated one is re-validated
/// every [`AUTH_RECHECK`] and closed when its session or membership has ended.
pub(crate) struct ConnTable<H> {
    max: usize,
    reserved: usize,
    per_account: usize,
    next_id: u64,
    /// Ids are handed out in order: lower = older.
    conns: std::collections::BTreeMap<u64, Slot<H>>,
}

struct Slot<H> {
    account: Option<String>,
    /// When that account became a member (unix ms; 0 = unknown / as old as can be). Rule (d).
    since: i64,
    node: [u8; 32],
    /// The connection paid for its slot with a proof-of-work stamp (rule (b)).
    proven: bool,
    handle: H,
}

impl<H> ConnTable<H> {
    pub(crate) fn new(max: usize, reserved: usize, per_account: usize) -> Self {
        Self { max, reserved: reserved.min(max), per_account: per_account.max(1), next_id: 0, conns: Default::default() }
    }

    fn unauthenticated(&self) -> usize {
        self.conns.values().filter(|c| c.account.is_none()).count()
    }

    fn held(&self, user: &str) -> Vec<u64> {
        self.conns.iter().filter(|(_, c)| c.account.as_deref() == Some(user)).map(|(id, _)| *id).collect()
    }

    /// Rule (b): the stranger that gives way to a newcomer — the oldest one that has NOT paid
    /// for its slot; one that has, only to a newcomer who paid too (`for_proven`).
    fn stranger_to_evict(&self, for_proven: bool) -> Option<u64> {
        let oldest = |proven: bool| self.conns.iter().find(|(_, c)| c.account.is_none() && c.proven == proven).map(|(id, _)| *id);
        oldest(false).or_else(|| if for_proven { oldest(true) } else { None })
    }

    /// Rule (c): the oldest connection of the account holding the most slots, if that is more
    /// than the fair share with `newcomer` counted among the accounts.
    fn over_fair_share(&self, newcomer: &str) -> Option<u64> {
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for c in self.conns.values() {
            if let Some(a) = c.account.as_deref() {
                *counts.entry(a).or_default() += 1;
            }
        }
        let accounts = counts.len() + usize::from(!counts.contains_key(newcomer));
        let fair = (self.max / accounts.max(1)).max(1);
        let (top, n) = counts.iter().max_by_key(|(_, n)| **n).map(|(a, n)| (a.to_string(), *n))?;
        if n > fair {
            self.held(&top).first().copied()
        } else {
            None
        }
    }

    /// Rule (d): a connection of the most RECENT member, if that member is more recent than
    /// the newcomer. (Audit P3: with one connection per account nobody is above the fair
    /// share, so a thousand freshly made accounts used to hold every slot against the people
    /// who were there first. Seniority cannot be minted.)
    fn newer_member(&self, newcomer_since: i64) -> Option<u64> {
        self.conns.iter().filter(|(_, c)| c.account.is_some() && c.since > newcomer_since).max_by_key(|(id, c)| (c.since, std::cmp::Reverse(**id))).map(|(id, _)| *id)
    }

    fn evict(&mut self, id: u64, out: &mut Vec<H>) {
        if let Some(slot) = self.conns.remove(&id) {
            out.push(slot.handle);
        }
    }

    /// [`ConnTable::admit_with`] for a connection that has shown no proof of work, of an
    /// account whose seniority is unknown.
    #[cfg(test)]
    pub(crate) fn admit(&mut self, handle: H, node: [u8; 32], account: Option<String>) -> Option<(u64, Vec<H>)> {
        self.admit_with(handle, node, account.map(|a| (a, 0)), false)
    }

    /// Admit a new connection from `node`. `account` = who that node is signed in as, if the
    /// backend already knows, and since when they have been a member; `proven` = the
    /// connection presented a valid proof-of-work stamp. Returns its id and the handles
    /// evicted to make room, for the caller to close. `None` = refused. See the type docs.
    pub(crate) fn admit_with(&mut self, handle: H, node: [u8; 32], account: Option<(String, i64)>, proven: bool) -> Option<(u64, Vec<H>)> {
        let mut evicted = Vec::new();
        match &account {
            None => {
                if self.conns.len() >= self.max || self.unauthenticated() >= self.max - self.reserved {
                    let victim = self.stranger_to_evict(proven)?; // (b), or refused
                    self.evict(victim, &mut evicted);
                }
            }
            Some((user, since)) => {
                // Invariant 3 first: over the cap, the account pays with its own oldest.
                while self.held(user).len() >= self.per_account {
                    let oldest = self.held(user)[0];
                    self.evict(oldest, &mut evicted);
                }
                if self.conns.len() >= self.max {
                    let victim = self.held(user).first().copied() // (a)
                        .or_else(|| self.stranger_to_evict(true)) // (b)
                        .or_else(|| self.over_fair_share(user)) // (c)
                        .or_else(|| self.newer_member(*since))?; // (d), or refused
                    self.evict(victim, &mut evicted);
                }
            }
        }
        self.next_id += 1;
        let (account, since) = account.map(|(a, s)| (Some(a), s)).unwrap_or((None, 0));
        self.conns.insert(self.next_id, Slot { account, since, node, proven, handle });
        Some((self.next_id, evicted))
    }

    /// Connection `id` turned out to be `user`'s. Returns the connections evicted by the
    /// per-account cap (always `user`'s own, never this one).
    #[cfg(test)]
    pub(crate) fn mark_authenticated(&mut self, id: u64, user: &str) -> Vec<H> {
        self.mark_authenticated_since(id, user, 0)
    }

    pub(crate) fn mark_authenticated_since(&mut self, id: u64, user: &str, since: i64) -> Vec<H> {
        let mut evicted = Vec::new();
        if !self.conns.contains_key(&id) {
            return evicted;
        }
        loop {
            let others: Vec<u64> = self.held(user).into_iter().filter(|c| *c != id).collect();
            if others.len() < self.per_account {
                break;
            }
            self.evict(others[0], &mut evicted);
        }
        if let Some(slot) = self.conns.get_mut(&id) {
            slot.account = Some(user.to_string());
            slot.since = since;
        }
        evicted
    }

    /// Every connection of `node` is `user`'s — said by the backend the moment it resolved a
    /// live session for a request from that node (audit P2: promotion used to wait for the
    /// connection's 10–60 s timer, so every member was an evictable stranger for the start of
    /// every connection). Returns what the per-account cap evicted.
    pub(crate) fn mark_node_authenticated(&mut self, node: &[u8; 32], user: &str, since: i64) -> Vec<H> {
        let ids: Vec<u64> = self.conns.iter().filter(|(_, c)| c.node == *node && c.account.as_deref() != Some(user)).map(|(id, _)| *id).collect();
        let mut evicted = Vec::new();
        for id in ids {
            evicted.extend(self.mark_authenticated_since(id, user, since));
        }
        evicted
    }

    /// Connection `id` presented a valid proof-of-work stamp.
    pub(crate) fn mark_proven(&mut self, id: u64) {
        if let Some(slot) = self.conns.get_mut(&id) {
            slot.proven = true;
        }
    }

    pub(crate) fn is_authenticated(&self, id: u64) -> bool {
        self.conns.get(&id).is_some_and(|c| c.account.is_some())
    }

    /// Connection `id` no longer has an account behind it.
    pub(crate) fn downgrade(&mut self, id: u64) {
        if let Some(slot) = self.conns.get_mut(&id) {
            slot.account = None;
        }
    }

    /// Forget connection `id`. Returns `true` when no other connection of the same node
    /// remains — the backend is then told the node has gone.
    pub(crate) fn remove(&mut self, id: u64) -> bool {
        match self.conns.remove(&id) {
            Some(gone) => !self.conns.values().any(|c| c.node == gone.node),
            None => false,
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.conns.len()
    }
}

/// The table, and a counter that moves whenever the backend promotes a node: every
/// connection task watches it and re-reads its own standing.
struct Shared {
    table: std::sync::Mutex<ConnTable<Connection>>,
    promoted: tokio::sync::watch::Sender<u64>,
    /// Direct dials answered with a Retry so far (a count, nothing about who).
    retried: std::sync::atomic::AtomicU64,
}

type Slots = Arc<Shared>;

impl Shared {
    fn table(&self) -> std::sync::MutexGuard<'_, ConnTable<Connection>> {
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Handed to the backend ([`Host::promoter`]): "this node just made a request under a live
/// session of this member" — its connections stop being strangers NOW.
#[derive(Clone)]
pub struct Promoter(Slots);

impl Promoter {
    /// `since`: when the account became a member (unix ms), for seniority when the host is full.
    pub fn promote(&self, node: [u8; 32], user: &str, since: i64) {
        let evicted = self.0.table().mark_node_authenticated(&node, user, since);
        for old in evicted {
            old.close(2u32.into(), b"replaced by a newer connection");
        }
        self.0.promoted.send_modify(|n| *n += 1);
    }
}

/// Connection stamps already used (single use), until their window has passed.
#[derive(Default)]
struct SpentProofs(Mutex<HashMap<SpentKey, Instant>>);

/// (member node id, stamp window, stamp nonce).
type SpentKey = ([u8; 32], u64, u64);

impl SpentProofs {
    const CAP: usize = 65_536;
    const KEEP: Duration = Duration::from_secs(3 * crate::pow::WINDOW_SECS);

    /// Record the stamp; `false` if it was used before, or the record is full of live ones.
    fn spend(&self, member: [u8; 32], stamp: (u64, u64), now: Instant) -> bool {
        let mut used = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if used.len() >= Self::CAP {
            used.retain(|_, at| now.duration_since(*at) < Self::KEEP);
            if used.len() >= Self::CAP {
                return false;
            }
        }
        used.insert((member, stamp.0, stamp.1), now).is_none()
    }
}

/// Check a connection stamp for `member` against this host and spend it.
fn accept_proof(host: &[u8; 32], member: &[u8; 32], stamp: &[u8], spent: &SpentProofs, now: Instant) -> bool {
    let Ok(stamp) = std::str::from_utf8(stamp) else { return false };
    match crate::pow::verify_for(crate::pow::Purpose::Connection, host, member, stamp, crate::pow::current_window(), crate::pow::CONN_POW_BITS) {
        Ok(pair) => spent.spend(*member, pair, now),
        Err(_) => false,
    }
}

/// Read a `KIND_PROOF` stream's stamp (the kind byte is already consumed).
async fn read_proof(recv: &mut RecvStream) -> Option<Vec<u8>> {
    tokio::time::timeout(PROOF_GRACE, recv.read_to_end(64)).await.ok()?.ok()
}

async fn accept_loop(endpoint: Endpoint, backend: Arc<dyn HostBackend>, slots: Slots) {
    // Handshakes in flight are bounded separately (they hold no table slot yet): the ones
    // admitted freely, and the ones that will have to prove work before they get a slot.
    let handshakes = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let proving = Arc::new(Semaphore::new(MAX_PROVING));
    let spent = Arc::new(SpentProofs::default());
    let host_id = *endpoint.id().as_bytes();
    let mut sources = SourceLimiter::new(Instant::now());
    while let Some(incoming) = endpoint.accept().await {
        // Direct vs relayed is decided HERE, once, from the path the connection was admitted
        // through, and stays with the connection: iroh may later migrate it between a relay and
        // a direct path, and its rate-limit population must not change when that happens.
        let admission = match incoming.remote_addr() {
            IncomingAddr::Ip(addr) => {
                // Nothing is counted — no source window, no handshake permit — for an address
                // nobody has proven they can receive at (audit P1). A QUIC Initial's source
                // address is whatever the sender wrote: counting it let a few hundred spoofed
                // packets a second fill the source table and hold every handshake permit, and
                // thirty a minute carrying a member's address lock that member out. A Retry
                // costs this host one stateless packet; the dial comes back validated.
                if !incoming.remote_addr_validated() {
                    slots.retried.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _ = incoming.retry();
                    continue;
                }
                sources.admit_direct(addr.ip(), Instant::now())
            }
            IncomingAddr::Relay { endpoint_id, .. } => sources.admit_relayed(Some(*endpoint_id.as_bytes()), Instant::now()),
            _ => sources.admit_relayed(None, Instant::now()),
        };
        let relayed = !matches!(incoming.remote_addr(), IncomingAddr::Ip(_));
        let permit = match admission {
            Admission::Refuse => None,
            Admission::Free => handshakes.clone().try_acquire_owned().ok(),
            Admission::MustProve => proving.clone().try_acquire_owned().ok(),
        };
        let Some(permit) = permit else {
            incoming.refuse();
            continue;
        };
        let must_prove = admission == Admission::MustProve;
        let (backend, slots, spent) = (backend.clone(), slots.clone(), spent.clone());
        tokio::spawn(async move {
            // Handshake failures are routine internet noise; nothing about the peer is logged.
            // A handshake that does not finish in time gives its permit back.
            // (A dial that will have to prove work gets less time: it holds one of few permits.)
            let patience = if must_prove { PROOF_GRACE } else { HELLO_TIMEOUT };
            let Ok(Ok(conn)) = tokio::time::timeout(patience, incoming).await else { return };
            let peer = conn.remote_id();
            // From here the peer's node id is authenticated by the handshake. A node the
            // backend knows as signed in (a member reconnecting) starts authenticated.
            let account = backend.peer_account(peer).await;
            let mut proven = false;
            if must_prove && account.is_none() {
                // Over its source's (or the relay's) free allowance: this connection gets a
                // slot only for work — a stamp bound to this host, this node id and this
                // moment, as its first stream. Current members send one on every connection.
                let first = tokio::time::timeout(PROOF_GRACE, conn.accept_bi()).await;
                let stamp = match first {
                    Ok(Ok((_send, mut recv))) => {
                        let mut kind = [0u8; 1];
                        match recv.read_exact(&mut kind).await {
                            Ok(()) if kind[0] == wire::KIND_PROOF => read_proof(&mut recv).await,
                            _ => None,
                        }
                    }
                    _ => None,
                };
                proven = stamp.is_some_and(|s| accept_proof(&host_id, peer.as_bytes(), &s, &spent, Instant::now()));
                if !proven {
                    conn.close(4u32.into(), b"proof of work required");
                    return;
                }
            }
            drop(permit);
            let since = match &account {
                Some(user) => backend.account_since(user.clone()).await,
                None => 0,
            };
            let admitted = slots.table().admit_with(conn.clone(), *peer.as_bytes(), account.clone().map(|a| (a, since)), proven);
            let Some((id, evicted)) = admitted else {
                conn.close(2u32.into(), b"host is full");
                return;
            };
            for old in evicted {
                old.close(2u32.into(), b"replaced by a newer connection");
            }
            serve_connection(conn, relayed, backend.clone(), id, slots.clone(), account.is_some(), (host_id, spent)).await;
            // The node's standing ends with its (last) connection: a node id cannot be parked
            // as "signed in" and come back later to claim a member's treatment.
            let gone = slots.table().remove(id);
            if gone {
                backend.peer_disconnected(peer);
            }
        });
    }
}

async fn serve_connection(conn: Connection, relayed: bool, backend: Arc<dyn HostBackend>, id: u64, slots: Slots, mut authenticated: bool, proofs: ([u8; 32], Arc<SpentProofs>)) {
    let peer = conn.remote_id();
    let voice = VoiceGate::new();
    let watcher = tokio::spawn(crate::member::log_path_changes(conn.clone(), "member", None));
    let mut streams = tokio::task::JoinSet::new();
    let (mut window_start, mut opened) = (Instant::now(), 0u32);
    let born = tokio::time::Instant::now();
    let mut promoted = slots.promoted.subscribe();
    promoted.mark_unchanged();
    // Anyone not yet known as signed in is on the clock until the backend has resolved a live
    // session for a request from this node; a signed-in connection is re-validated on a timer.
    let mut deadline = if authenticated { born + AUTH_RECHECK } else { born + UNAUTHENTICATED_IDLE };
    loop {
        tokio::select! {
            // The backend promoted SOME node: if it was this one, the connection is a member's
            // from this moment — off the stranger's clock and out of the stranger's pool.
            Ok(()) = promoted.changed(), if !authenticated => {
                if slots.table().is_authenticated(id) {
                    authenticated = true;
                    deadline = tokio::time::Instant::now() + AUTH_RECHECK;
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                match backend.peer_account(peer).await {
                    Some(user) => {
                        if !authenticated {
                            authenticated = true;
                            let since = backend.account_since(user.clone()).await;
                            let evicted = slots.table().mark_authenticated_since(id, &user, since);
                            for old in evicted {
                                old.close(2u32.into(), b"replaced by a newer connection");
                            }
                        }
                        deadline = tokio::time::Instant::now() + AUTH_RECHECK;
                    }
                    None => {
                        // Never signed in — or signed out, expired, or removed since.
                        slots.table().downgrade(id);
                        conn.close(3u32.into(), b"not signed in");
                        break;
                    }
                }
            }
            accepted = conn.accept_bi() => {
                let Ok((send, mut recv)) = accepted else { break };
                if !authenticated {
                    deadline = (tokio::time::Instant::now() + UNAUTHENTICATED_IDLE).min(born + UNAUTHENTICATED_MAX);
                }
                if window_start.elapsed() >= STREAM_WINDOW {
                    (window_start, opened) = (Instant::now(), 0);
                }
                opened += 1;
                if opened > MAX_STREAMS_PER_WINDOW {
                    conn.close(1u32.into(), b"too many requests");
                    break;
                }
                let (backend, conn, voice, slots, proofs) = (backend.clone(), conn.clone(), voice.clone(), slots.clone(), proofs.clone());
                streams.spawn(async move {
                    let mut kind = [0u8; 1];
                    // A stream that never says what it is does not hold a task open.
                    if !matches!(tokio::time::timeout(HELLO_TIMEOUT, recv.read_exact(&mut kind)).await, Ok(Ok(()))) {
                        return;
                    }
                    match kind[0] {
                        wire::KIND_HTTP => backend.serve_http(peer, relayed, wire::join(send, recv)).await,
                        wire::KIND_LIVEKIT => livekit_stream(backend, voice, send, recv).await,
                        wire::KIND_VOICE_HELLO => voice_hello(&backend, &conn, &voice, send, recv).await,
                        // The connection pays for its slot: among strangers it now gives way
                        // only to another that paid.
                        wire::KIND_PROOF => {
                            if let Some(stamp) = read_proof(&mut recv).await {
                                if accept_proof(&proofs.0, peer.as_bytes(), &stamp, &proofs.1, Instant::now()) {
                                    slots.table().mark_proven(id);
                                }
                            }
                        }
                        _ => {}
                    }
                });
            }
            // Reap finished stream tasks so the set doesn't grow for a long-lived connection.
            Some(_) = streams.join_next(), if !streams.is_empty() => {}
        }
    }
    voice.revoke();
    streams.abort_all();
    watcher.abort();
}

type ProxyBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

fn refuse(code: hyper::StatusCode) -> hyper::Response<ProxyBody> {
    use http_body_util::BodyExt as _;
    let mut res = hyper::Response::new(http_body_util::Empty::<bytes::Bytes>::new().map_err(|never| match never {}).boxed());
    *res.status_mut() = code;
    res.headers_mut().insert(hyper::header::CONNECTION, hyper::header::HeaderValue::from_static("close"));
    res
}

/// One LiveKit signaling request: validate → admit to its room → forward → (maybe) upgrade.
async fn livekit_request(
    backend: Arc<dyn HostBackend>,
    voice: Arc<VoiceGate>,
    served: Arc<std::sync::atomic::AtomicBool>,
    mut req: hyper::Request<hyper::body::Incoming>,
) -> Result<hyper::Response<ProxyBody>, std::convert::Infallible> {
    use http_body_util::BodyExt as _;
    use hyper::body::Body as _;
    use hyper::StatusCode;
    use hyper_util::rt::TokioIo;

    // One request per stream. (hyper's `keep_alive(false)` would enforce this too, but it also
    // rewrites a 101's `Connection: Upgrade` to `close`, which breaks the WebSocket handshake.)
    if served.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Ok(refuse(StatusCode::BAD_REQUEST));
    }
    let has_body = !req.body().is_end_stream();
    let downstream = hyper::upgrade::on(&mut req);
    let (parts, _body) = req.into_parts();
    let Some(request) = validate_livekit_request(&parts, has_body) else { return Ok(refuse(StatusCode::BAD_REQUEST)) };
    // Session still valid AND this user may be in THIS room now (not merely "a member somewhere").
    if !voice.admit(&*backend, request.room, request.identity).await {
        return Ok(refuse(StatusCode::FORBIDDEN));
    }
    let Some(target) = backend.livekit().await else { return Ok(refuse(StatusCode::BAD_GATEWAY)) };
    let Ok(tcp) = tokio::net::TcpStream::connect(target.signal).await else { return Ok(refuse(StatusCode::BAD_GATEWAY)) };
    let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await else {
        return Ok(refuse(StatusCode::BAD_GATEWAY));
    };
    tokio::spawn(conn.with_upgrades());
    let Ok(mut res) = sender.send_request(request.forward).await else { return Ok(refuse(StatusCode::BAD_GATEWAY)) };

    if request.websocket && res.status() == StatusCode::SWITCHING_PROTOCOLS {
        // Only now — LiveKit answered 101 to a genuine WebSocket handshake — do the two sides
        // become a raw pipe, through hyper's upgrade API. It dies with the grant.
        let upstream = hyper::upgrade::on(&mut res);
        let mut revoked = voice.revoked.subscribe();
        revoked.mark_unchanged();
        tokio::spawn(async move {
            if let (Ok(down), Ok(up)) = (downstream.await, upstream.await) {
                let (mut down, mut up) = (TokioIo::new(down), TokioIo::new(up));
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut down, &mut up) => {}
                    _ = revoked.changed() => {}
                }
            }
        });
        return Ok(res.map(|b| b.boxed()));
    }
    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        return Ok(refuse(StatusCode::BAD_GATEWAY)); // a 101 nobody asked for
    }
    // Anything else: relay this one response and end the stream. No client bytes follow it upstream.
    res.headers_mut().insert(hyper::header::CONNECTION, hyper::header::HeaderValue::from_static("close"));
    Ok(res.map(|b| b.boxed()))
}

/// A LiveKit stream is served by hyper (strict HTTP/1.1 parsing; exactly one request is ever
/// forwarded — a second one on the same stream is refused and the stream closed) instead of being inspected as raw bytes.
async fn livekit_stream(backend: Arc<dyn HostBackend>, voice: Arc<VoiceGate>, send: SendStream, recv: RecvStream) {
    // Subscribe BEFORE serving so a revocation racing with this stream is not missed.
    let mut revoked = voice.revoked.subscribe();
    revoked.mark_unchanged();
    let io = hyper_util::rt::TokioIo::new(wire::join(send, recv));
    let gate = voice.clone();
    let served = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let service = hyper::service::service_fn(move |req| livekit_request(backend.clone(), gate.clone(), served.clone(), req));
    let serve = hyper::server::conn::http1::Builder::new()
        .max_buf_size(MAX_LIVEKIT_HEAD)
        .serve_connection(io, service)
        .with_upgrades();
    tokio::select! {
        _ = tokio::time::timeout(Duration::from_secs(12 * 60 * 60), serve) => {}
        _ = revoked.changed() => {}
    }
}

/// Largest request head hyper will buffer for a LiveKit stream.
const MAX_LIVEKIT_HEAD: usize = 16 * 1024;

async fn voice_hello(
    backend: &Arc<dyn HostBackend>,
    conn: &Connection,
    voice: &Arc<VoiceGate>,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let read = async {
        let mut len = [0u8; 2];
        recv.read_exact(&mut len).await.ok()?;
        let mut token = vec![0u8; u16::from_be_bytes(len) as usize];
        recv.read_exact(&mut token).await.ok()?;
        String::from_utf8(token).ok()
    };
    let Ok(Some(token)) = tokio::time::timeout(HELLO_TIMEOUT, read).await else { return };
    let target = if backend.authorize_voice(token.clone()).await { backend.livekit().await } else { None };
    let reply = match target {
        Some(t) => {
            *voice.token.lock().unwrap_or_else(|e| e.into_inner()) = Some(token);
            let mut forwarder = voice.forwarder.lock().unwrap_or_else(|e| e.into_inner());
            // Alive, but for another port: LiveKit was restarted there. The old forwarder would
            // keep sending this connection's media to a port nobody (or somebody else) holds.
            let running = forwarder.as_ref().filter(|(_, f)| !f.is_finished()).map(|(to, _)| *to);
            if running != Some(t.udp) {
                if let Some((_, old)) = forwarder.take() {
                    old.abort();
                }
                *forwarder = Some((t.udp, tokio::spawn(crate::voice::run_host(conn.clone(), t.udp)).abort_handle()));
            }
            let mut recheck_slot = voice.recheck.lock().unwrap_or_else(|e| e.into_inner());
            if recheck_slot.as_ref().is_none_or(|r| r.is_finished()) {
                // Media has no per-packet auth, so the grant is re-validated on a timer for as
                // long as the forwarder lives; a failed check revokes (which aborts both tasks).
                let (backend2, gate, every) = (backend.clone(), voice.clone(), backend.voice_recheck_interval());
                let recheck = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(every).await;
                        if !gate.check(&*backend2).await {
                            return;
                        }
                    }
                });
                *recheck_slot = Some(recheck.abort_handle());
            }
            serde_json::json!({ "ok": true, "udp_port": t.advertised_udp_port })
        }
        None => serde_json::json!({ "ok": false }),
    };
    let _ = send.write_all(reply.to_string().as_bytes()).await;
    let _ = send.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u32) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[..4].copy_from_slice(&n.to_be_bytes());
        k
    }

    fn holds(t: &ConnTable<u32>, user: &str) -> Vec<u32> {
        t.conns.values().filter(|c| c.account.as_deref() == Some(user)).map(|c| c.handle).collect()
    }

    /// Connect as a stranger, then authenticate — what a real client does. Returns what was
    /// closed for it, or `None` if it was refused.
    fn join(t: &mut ConnTable<u32>, handle: u32, user: &str) -> Option<Vec<u32>> {
        let (id, mut closed) = t.admit(handle, node(handle), None)?;
        closed.extend(t.mark_authenticated(id, user));
        Some(closed)
    }

    #[test]
    fn unauthenticated_floods_are_dropped_first_and_never_cost_a_member_a_slot() {
        // 8 slots, 3 of them only for members.
        let mut t: ConnTable<u32> = ConnTable::new(8, 3, 4);
        for n in 0..5 {
            assert!(t.admit(n, node(n), None).unwrap().1.is_empty());
        }
        // The stranger pool (8 − 3 = 5) is full: each further stranger evicts the OLDEST one.
        for n in 5..200 {
            let (_, evicted) = t.admit(n, node(n), None).unwrap();
            assert_eq!(evicted, vec![n - 5], "the oldest stranger made room");
            assert_eq!((t.len(), t.unauthenticated()), (5, 5), "strangers never exceed their pool");
        }
        // Members arrive mid-flood: each takes a stranger's slot on the way in, then is safe.
        for i in 0..8u32 {
            let closed = join(&mut t, 1000 + i, &format!("user-{i}")).expect("a member gets in");
            assert!(closed.iter().all(|h| *h < 1000), "only strangers were closed for a member");
        }
        assert_eq!((t.len(), t.unauthenticated()), (8, 0));
        // Full of members: the flood is refused outright, and nobody is thrown out.
        for n in 200..400 {
            assert!(t.admit(n, node(n), None).is_none());
        }
        assert_eq!(t.len(), 8);
        for i in 0..8u32 {
            assert_eq!(holds(&t, &format!("user-{i}")), vec![1000 + i]);
        }
        // A member who is signed out becomes a stranger again — evictable like one.
        let id = *t.conns.iter().find(|(_, c)| c.account.as_deref() == Some("user-2")).unwrap().0;
        t.downgrade(id);
        let (_, evicted) = t.admit(999, node(999), None).unwrap();
        assert_eq!(evicted, vec![1002]);
    }

    #[test]
    fn one_account_churning_node_ids_cannot_displace_other_members() {
        for (max, reserved) in [(64usize, 16usize), (44, 8), (14, 4)] {
            let mut t: ConnTable<u32> = ConnTable::new(max, reserved, MAX_PER_ACCOUNT);
            // Ten friends, one device each.
            for i in 0..10u32 {
                join(&mut t, 1000 + i, &format!("friend-{i}")).unwrap();
            }
            let friends = |t: &ConnTable<u32>| (0..10u32).all(|i| holds(t, &format!("friend-{i}")) == vec![1000 + i]);
            // One account (say a removed member whose session still lives, or a real member
            // being hostile) opens 100 node ids: half connect as strangers and authenticate,
            // half are already known as that account at the handshake.
            let mut closed = Vec::new();
            for n in 0..100u32 {
                if n % 2 == 0 {
                    // (As a stranger it is refused outright once the table is all members.)
                    closed.extend(join(&mut t, n, "greedy").unwrap_or_default());
                } else {
                    closed.extend(t.admit(n, node(n), Some("greedy".into())).unwrap().1);
                }
                assert!(holds(&t, "greedy").len() <= MAX_PER_ACCOUNT, "max {max}: the account is over its cap");
                assert!(friends(&t), "max {max}: a friend lost a slot after {n} connections");
            }
            assert_eq!(holds(&t, "greedy").len(), MAX_PER_ACCOUNT, "it ends with its cap and no more");
            assert!(holds(&t, "greedy").iter().all(|h| *h >= 90), "…the newest ones");
            assert!(closed.len() >= 46 && closed.iter().all(|h| *h < 1000), "only its OWN connections were closed");
            assert_eq!(t.len(), 10 + MAX_PER_ACCOUNT);
        }
    }

    #[test]
    fn twenty_members_with_two_devices_each_are_never_refused_in_a_table_sized_for_them() {
        // 40 slots for 40 devices; the reserve does not matter to members.
        let mut t: ConnTable<u32> = ConnTable::new(40, 8, MAX_PER_ACCOUNT);
        for device in 0..2u32 {
            for m in 0..20u32 {
                let closed = join(&mut t, m * 10 + device, &format!("member-{m}")).unwrap_or_else(|| panic!("member-{m} device {device} was refused"));
                assert!(closed.is_empty(), "nothing had to be closed");
            }
        }
        assert_eq!((t.len(), t.unauthenticated()), (40, 0));
        // The table is exactly full. Everyone reconnects (new connection, node already known):
        // each is admitted by replacing ITS OWN oldest connection — never refused, never at
        // anyone else's expense.
        for round in 0..5u32 {
            for m in 0..20u32 {
                let handle = 10_000 + round * 100 + m;
                let (_, evicted) = t.admit(handle, node(handle), Some(format!("member-{m}"))).unwrap_or_else(|| panic!("member-{m} was refused on reconnect"));
                assert_eq!(evicted.len(), 1);
                assert_eq!(t.len(), 40);
                for other in 0..20u32 {
                    assert_eq!(holds(&t, &format!("member-{other}")).len(), 2, "round {round}: member-{other} holds both devices");
                }
            }
        }
        // …and a stranger cannot get in at anyone's expense either.
        assert!(t.admit(7, node(7), None).is_none());
    }

    #[test]
    fn a_full_table_gives_way_only_from_an_account_above_its_fair_share() {
        // 8 slots. Two accounts hold 4 each: fair share with a third account arriving is
        // 8 / 3 = 2, so the largest holder (4 > 2) gives up ONE — its oldest.
        let mut t: ConnTable<u32> = ConnTable::new(8, 2, 4);
        for n in 0..4 {
            join(&mut t, n, "a").unwrap();
            join(&mut t, 10 + n, "b").unwrap();
        }
        let (_, evicted) = t.admit(100, node(100), Some("c".into())).unwrap();
        assert_eq!(evicted.len(), 1);
        assert!(evicted[0] == 0 || evicted[0] == 10, "the OLDEST connection of a largest holder");
        assert_eq!(t.len(), 8);
        // A fourth account: fair is 8 / 4 = 2 and the other of {a, b} still holds 4.
        assert_eq!(t.admit(101, node(101), Some("d".into())).unwrap().1.len(), 1);
        assert_eq!((holds(&t, "a").len(), holds(&t, "b").len(), holds(&t, "c").len(), holds(&t, "d").len()), (3, 3, 1, 1));
        // In a full table an account's own connections pay first (a): c reconnecting replaces
        // c's connection and takes nothing more from anyone.
        assert_eq!(t.admit(102, node(102), Some("c".into())).unwrap().1, vec![100]);
        assert_eq!((holds(&t, "a").len(), holds(&t, "b").len(), holds(&t, "c")), (3, 3, vec![102]));
        // Eight accounts with one slot each: fair is 1, nobody is above it, the ninth is refused.
        let mut t: ConnTable<u32> = ConnTable::new(8, 2, 4);
        for n in 0..8u32 {
            join(&mut t, n, &format!("u{n}")).unwrap();
        }
        assert!(t.admit(50, node(50), Some("ninth".into())).is_none(), "nobody at or below fair share is evicted");
        assert_eq!(t.len(), 8);
        // Removing a connection reports whether its node is gone entirely.
        let mut t: ConnTable<u32> = ConnTable::new(8, 2, 4);
        let (a, _) = t.admit(1, node(1), None).unwrap();
        let (b, _) = t.admit(2, node(1), None).unwrap();
        assert!(!t.remove(a), "the node still has another connection");
        assert!(t.remove(b));
    }

    /// Audit P1/P2: a stranger that paid for its slot is not pushed out by ones that did not,
    /// and a member is a member from its first authenticated request.
    #[test]
    fn proven_strangers_outlast_a_flood_and_a_promoted_node_is_a_member_at_once() {
        let node = |n: u32| { let mut b = [0u8; 32]; b[..4].copy_from_slice(&n.to_be_bytes()); b };
        // 8 slots, 3 reserved: 5 for strangers. A member-to-be connects and proves work.
        let mut t: ConnTable<u32> = ConnTable::new(8, 3, 4);
        let (alice, _) = t.admit_with(1, node(1), None, true).unwrap();
        for n in 2..=5 {
            t.admit_with(n, node(n), None, false).unwrap();
        }
        // A flood of connections that prove nothing only ever displaces its own kind…
        for n in 100..200 {
            let (_, evicted) = t.admit_with(n, node(n), None, false).unwrap();
            assert!(!evicted.contains(&1), "an unproven newcomer evicted a proven stranger");
        }
        // …and once every stranger slot is paid for, it is refused outright.
        let mut t2: ConnTable<u32> = ConnTable::new(8, 3, 4);
        for n in 1..=5 {
            t2.admit_with(n, node(n), None, true).unwrap();
        }
        assert!(t2.admit_with(99, node(99), None, false).is_none());
        assert_eq!(t2.admit_with(98, node(98), None, true).unwrap().1, vec![1], "paying strangers compete among themselves, oldest first");
        // A connection that proves LATER is protected from then on.
        let (late, _) = t.admit_with(300, node(300), None, false).unwrap();
        t.mark_proven(late);
        for n in 400..420 {
            assert!(!t.admit_with(n, node(n), None, false).unwrap().1.contains(&300));
        }
        // Promotion by node, the moment the backend says so: out of the stranger pool.
        assert!(!t.is_authenticated(alice));
        assert!(t.mark_node_authenticated(&node(1), "alice", 1_000).is_empty());
        assert!(t.is_authenticated(alice));
        for n in 500..600 {
            if let Some((_, evicted)) = t.admit_with(n, node(n), None, true) {
                assert!(!evicted.contains(&1), "a member was evicted by a stranger");
            }
        }
    }

    /// Audit P3: one connection per freshly made account does not hold the table against
    /// the people who were members first.
    #[test]
    fn seniority_breaks_a_full_table_of_one_connection_accounts() {
        let node = |n: u32| { let mut b = [0u8; 32]; b[..4].copy_from_slice(&n.to_be_bytes()); b };
        let mut t: ConnTable<u32> = ConnTable::new(8, 2, 4);
        // Eight accounts made today (since = 9_000 + n), one connection each: nobody is above
        // the fair share of 1.
        for n in 0..8 {
            t.admit_with(n, node(n), Some((format!("sybil-{n}"), 9_000 + n as i64)), false).unwrap();
        }
        // A long-standing member connects: the NEWEST account gives way.
        let (_, evicted) = t.admit_with(100, node(100), Some(("alice".into(), 1_000)), false).unwrap();
        assert_eq!(evicted, vec![7]);
        let (_, evicted) = t.admit_with(101, node(101), Some(("bob".into(), 2_000)), false).unwrap();
        assert_eq!(evicted, vec![6]);
        // An even newer account displaces nobody.
        assert!(t.admit_with(200, node(200), Some(("sybil-new".into(), 99_000)), false).is_none());
        // Unknown seniority on both sides (a backend without it): rule (d) is inert.
        let mut flat: ConnTable<u32> = ConnTable::new(4, 1, 4);
        for n in 0..4 {
            flat.admit(n, node(n), Some(format!("m{n}"))).unwrap();
        }
        assert!(flat.admit(9, node(9), Some("m9".into())).is_none());
    }

    /// Audit P1: what a dial has to do is decided from a validated address or the relay's
    /// node id — and a dry bucket asks for work instead of refusing everybody.
    #[test]
    fn a_dry_allowance_asks_for_work_instead_of_refusing_everyone() {
        let now = Instant::now();
        let mut l = SourceLimiter::new(now);
        let a: IpAddr = "203.0.113.9".parse().unwrap();
        for _ in 0..MAX_HANDSHAKES_PER_SOURCE {
            assert_eq!(l.admit_direct(a, now), Admission::Free);
        }
        assert_eq!(l.admit_direct(a, now), Admission::MustProve, "the member behind the same NAT still gets in — for work");
        assert_eq!(l.admit_direct("203.0.113.10".parse().unwrap(), now), Admission::Free);
        // Relayed: distinct node ids drain the shared bucket, after which dials must prove.
        let id = |n: u32| { let mut b = [7u8; 32]; b[..4].copy_from_slice(&n.to_be_bytes()); b };
        for n in 0..RELAY_BURST as u32 {
            assert_eq!(l.admit_relayed(Some(id(n)), now), Admission::Free);
        }
        assert_eq!(l.admit_relayed(Some(id(10_000)), now), Admission::MustProve, "never Refuse: a drained bucket used to shut everyone out");
        // One node id hammering the relay path is refused, whatever the bucket holds.
        let mut l = SourceLimiter::new(now);
        for _ in 0..MAX_RELAYED_DIALS_PER_NODE {
            assert_ne!(l.admit_relayed(Some(id(1)), now), Admission::Refuse);
        }
        assert_eq!(l.admit_relayed(Some(id(1)), now), Admission::Refuse);
        assert_ne!(l.admit_relayed(Some(id(2)), now), Admission::Refuse);
        assert_ne!(l.admit_relayed(Some(id(1)), now + Duration::from_secs(61)), Admission::Refuse);
    }

    #[test]
    fn a_connection_stamp_is_checked_and_spent_once() {
        let (host, member) = ([1u8; 32], [2u8; 32]);
        let spent = SpentProofs::default();
        let now = Instant::now();
        let stamp = crate::pow::solve_for(crate::pow::Purpose::Connection, &host, &member, crate::pow::current_window(), crate::pow::CONN_POW_BITS);
        assert!(!accept_proof(&host, &[3u8; 32], stamp.as_bytes(), &spent, now), "made for another node id");
        assert!(!accept_proof(&[9u8; 32], &member, stamp.as_bytes(), &spent, now), "made for another host");
        assert!(!accept_proof(&host, &member, b"1.2", &spent, now) && !accept_proof(&host, &member, &[0xff, 0xfe], &spent, now));
        let request = crate::pow::solve(&host, &member, crate::pow::current_window());
        assert!(!accept_proof(&host, &member, request.as_bytes(), &spent, now), "a sign-in stamp is not a connection stamp");
        assert!(accept_proof(&host, &member, stamp.as_bytes(), &spent, now));
        assert!(!accept_proof(&host, &member, stamp.as_bytes(), &spent, now), "single use");
    }

    #[test]
    fn handshakes_are_limited_per_source_not_globally() {
        let now = Instant::now();
        let mut l = SourceLimiter::new(now);
        let (a, b): (IpAddr, IpAddr) = ("203.0.113.1".parse().unwrap(), "203.0.113.2".parse().unwrap());
        for _ in 0..MAX_HANDSHAKES_PER_SOURCE {
            assert!(l.allow(a, now));
        }
        assert!(!l.allow(a, now), "one source minting identities is cut off…");
        assert!(l.allow(b, now), "…without affecting anyone else");
        assert!(l.allow(a, now + Duration::from_secs(61)), "and only for the window");
    }

    #[test]
    fn ipv6_sources_are_counted_per_64() {
        let now = Instant::now();
        let mut l = SourceLimiter::new(now);
        // 30 different addresses inside ONE /64 are one source…
        for i in 0..MAX_HANDSHAKES_PER_SOURCE {
            assert!(l.allow(format!("2001:db8:1:2::{:x}", i + 1).parse().unwrap(), now));
        }
        assert!(!l.allow("2001:db8:1:2:ffff::9".parse().unwrap(), now));
        // …a different /64 is a different source, and v4-mapped v6 is its IPv4 address.
        assert!(l.allow("2001:db8:1:3::1".parse().unwrap(), now));
        assert_eq!(source_key("::ffff:203.0.113.1".parse().unwrap()), "203.0.113.1".parse::<IpAddr>().unwrap());
        assert_eq!(l.windows.len(), 2);
    }

    #[test]
    fn source_table_is_bounded() {
        let now = Instant::now();
        let mut l = SourceLimiter::new(now);
        for i in 0..MAX_TRACKED_SOURCES as u32 {
            assert!(l.allow(IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000 + i)), now));
        }
        assert!(!l.allow("198.51.100.1".parse().unwrap(), now), "full table refuses NEW sources");
        assert_eq!(l.windows.len(), MAX_TRACKED_SOURCES, "and never grows past the cap");
        assert!(l.allow(IpAddr::V4(std::net::Ipv4Addr::from(0x0b00_0000)), now), "known sources are unaffected");
        assert!(l.allow("198.51.100.1".parse().unwrap(), now + Duration::from_secs(61)), "expired windows make room");
        assert!(l.windows.len() <= MAX_TRACKED_SOURCES);
    }

    #[test]
    fn relayed_dials_share_a_token_bucket() {
        let now = Instant::now();
        let mut l = SourceLimiter::new(now);
        for _ in 0..RELAY_BURST as u32 {
            assert!(l.allow_relayed(now));
        }
        assert!(!l.allow_relayed(now), "burst exhausted");
        assert!(l.allow("203.0.113.1".parse().unwrap(), now), "direct dials are not affected by the relay bucket");
        assert!(l.allow_relayed(now + Duration::from_secs(1)), "refills over time");
        assert!(l.allow_relayed(now + Duration::from_secs(1)));
        assert!(!l.allow_relayed(now + Duration::from_secs(1)), "at RELAY_PER_SEC");
    }

    fn jwt(claims: serde_json::Value) -> String {
        use base64::Engine;
        format!("hdr.{}.sig", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string()))
    }

    fn token(room: &str) -> String {
        jwt(serde_json::json!({ "sub": "user-1", "video": { "room": room, "roomJoin": true } }))
    }

    /// A typed request, as hyper would hand it over. `ws` adds a genuine WebSocket handshake.
    fn request(method: &str, target: &str, headers: &[(&str, &str)], ws: bool) -> hyper::http::request::Parts {
        let mut b = hyper::Request::builder().method(method).uri(target);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        if ws {
            b = b.header("upgrade", "websocket").header("connection", "keep-alive, Upgrade").header("sec-websocket-key", "abc");
        }
        b.body(()).unwrap().into_parts().0
    }

    fn check(method: &str, target: &str, headers: &[(&str, &str)], ws: bool) -> Option<LiveKitRequest> {
        validate_livekit_request(&request(method, target, headers, ws), false)
    }

    #[test]
    fn livekit_request_is_bound_to_the_room_in_its_token() {
        let t = token("skwod-chan-1");
        let r = check("GET", &format!("/rtc?protocol=15&access_token={t}&auto_subscribe=1"), &[], true).unwrap();
        assert_eq!((r.room.as_str(), r.identity.as_str(), r.websocket), ("skwod-chan-1", "user-1", true));
        assert_eq!(r.forward.uri().to_string(), format!("/rtc?protocol=15&auto_subscribe=1&access_token={t}"));
        assert_eq!(r.forward.headers()["upgrade"], "websocket");
        assert_eq!(r.forward.headers()["sec-websocket-key"], "abc", "handshake headers travel");
        // Token in the header: re-inserted as the only Authorization header.
        let bearer = format!("Bearer {t}");
        let r = check("GET", "/rtc/validate", &[("authorization", bearer.as_str()), ("connection", "keep-alive")], false).unwrap();
        assert_eq!(r.forward.headers().get_all("authorization").iter().count(), 1);
        assert_eq!(r.forward.headers()["authorization"], bearer.as_str());
        assert!(!r.websocket);
        assert_eq!(r.forward.headers()["connection"], "close");
        assert_eq!(r.forward.uri().to_string(), "/rtc/validate");
        // No token, no room claim, or garbage → refused.
        assert!(check("GET", "/rtc", &[], true).is_none());
        let no_room = jwt(serde_json::json!({ "sub": "user-1", "video": {} }));
        assert!(check("GET", &format!("/rtc?access_token={no_room}"), &[], true).is_none());
        assert!(check("GET", "/rtc?access_token=a.b.c", &[], true).is_none());
    }

    #[test]
    fn ambiguous_credentials_are_rejected_not_guessed() {
        let (a, b) = (token("skwod-allowed"), token("skwod-forbidden"));
        let (bearer_a, bearer_b, basic) = (format!("Bearer {a}"), format!("Bearer {b}"), format!("Basic {a}"));
        // Authorized with A in the query while LiveKit might prefer B from the header.
        assert!(check("GET", &format!("/rtc?access_token={a}"), &[("authorization", bearer_b.as_str())], true).is_none());
        // Duplicate query parameter: first-wins vs last-wins.
        assert!(check("GET", &format!("/rtc?access_token={a}&access_token={b}"), &[], true).is_none());
        // Same, with a KEY percent-encoded so a naive scan misses it.
        assert!(check("GET", &format!("/rtc?access_token={a}&access%5Ftoken={b}"), &[], true).is_none());
        assert!(check("GET", &format!("/rtc?%61ccess_token={b}&access_token={a}"), &[], true).is_none());
        // Two Authorization headers; a non-bearer one.
        assert!(check("GET", "/rtc", &[("authorization", bearer_a.as_str()), ("authorization", bearer_b.as_str())], true).is_none());
        assert!(check("GET", "/rtc", &[("authorization", basic.as_str())], true).is_none());
        // A body, or chunked framing.
        assert!(validate_livekit_request(&request("POST", &format!("/rtc?access_token={a}"), &[], false), true).is_none());
        assert!(check("POST", &format!("/rtc?access_token={a}"), &[("transfer-encoding", "chunked")], false).is_none());
        // A token carrying anything but base64url (e.g. smuggled via percent-encoding) is refused.
        assert!(check("GET", &format!("/rtc?access_token={a}%0d%0aX-Evil:%201"), &[], true).is_none());
        // A percent-encoded key on its own is still ONE credential: accepted, forwarded canonically.
        let r = check("GET", &format!("/rtc?access%5Ftoken={a}"), &[], true).unwrap();
        assert_eq!(r.room, "skwod-allowed");
        assert_eq!(r.forward.uri().to_string(), format!("/rtc?access_token={a}"));
    }

    #[test]
    fn control_bytes_cannot_be_expressed_in_a_forwarded_request() {
        // The forwarded request is built from typed parts; the types themselves refuse the bytes
        // header injection needs. (hyper's parser refuses them on the way in, too — see the
        // raw-bytes integration test in tests/tunnel.rs.)
        use hyper::header::{HeaderName, HeaderValue};
        assert!(HeaderValue::from_str("a\r\nX-Evil: 1").is_err());
        assert!(HeaderValue::from_bytes(b"a\0b").is_err());
        assert!(HeaderName::from_bytes(b"X-A\r\nX-Evil").is_err());
        assert!("/rtc?x=1\r\nX-Evil: 1".parse::<hyper::Uri>().is_err());
        assert!("/rtc x".parse::<hyper::Uri>().is_err());
    }

    #[test]
    fn only_a_real_websocket_handshake_keeps_the_stream_open() {
        let t = token("skwod-chan-1");
        let target = format!("/rtc?access_token={t}");
        let not_ws: [(&str, &[(&str, &str)]); 4] = [
            // `Upgrade` to something else: must not leave a raw pipe behind.
            ("GET", &[("upgrade", "h2c"), ("connection", "Upgrade")]),
            // `Upgrade: websocket` without `Connection: upgrade`.
            ("GET", &[("upgrade", "websocket"), ("connection", "keep-alive")]),
            ("GET", &[("upgrade", "websocket")]),
            // Not a GET.
            ("POST", &[("upgrade", "websocket"), ("connection", "Upgrade")]),
        ];
        for (method, headers) in not_ws {
            let r = check(method, &target, headers, false).unwrap();
            assert!(!r.websocket, "{method} {headers:?}");
            assert_eq!(r.forward.headers()["connection"], "close");
            assert!(!r.forward.headers().contains_key("upgrade"));
        }
    }
}
