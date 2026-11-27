//! p2p transport for the apps (see `docs/P2P.md`).
//!
//! The whole integration is ONE call: [`p2p_connect`] dials the host by its node id and returns a
//! [`P2pSession`] whose [`P2pSession::base_url`] is a drop-in replacement for the `https://…`
//! server URL — pass it to [`crate::signup`], [`crate::login`], [`crate::SkwodClient::new`], and
//! to the app's own URLSession / OkHttp / WebSocket code. It points at a loopback proxy inside the
//! app process (127.0.0.1, random port, unguessable path prefix) that carries every request to
//! the host over the p2p connection. Voice needs nothing extra: `SkwodClient::voice_token` returns
//! a loopback LiveKit URL when the session is p2p.
//!
//! `https://` server URLs keep working unchanged (VPS hosts) — just don't call `p2p_connect`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use skwod_net::{EndpointAddr, Invite, LocalProxy, Member, NetConfig};

use crate::CoreError;

fn net_err(e: skwod_net::NetError) -> CoreError {
    match e {
        skwod_net::NetError::Invite(_) => CoreError::Invalid { detail: e.to_string() },
        _ => CoreError::Engine { detail: e.to_string() },
    }
}

/// Why the voice tunnel did not open ([`CoreError::Voice`]). An address or a port is never in it.
fn voice_net_error(e: &skwod_net::NetError) -> CoreError {
    let code = match e {
        skwod_net::NetError::VoiceUnavailable => "unavailable",
        skwod_net::NetError::VoicePort => "port_taken",
        _ => "unreachable",
    };
    CoreError::Voice { code: code.into() }
}

/// A parsed invite: `skwod://join/<node id>#<join code>` or its share form
/// `https://skwod.io/join#<node id>.<join code>`.
#[derive(Debug, uniffi::Record)]
pub struct P2pInvite {
    /// The host's node id (z-base-32): its address AND its pinned identity.
    pub node_id: String,
    /// The join code to present at signup, if the link carried one.
    pub join_code: Option<String>,
    /// An `https://` address of the same skwod, if the host has one (VPS). Not used for p2p.
    pub fallback_url: Option<String>,
    /// The host's home relay when the link was made (`&r=`, allow-listed n0 relays only). Pass it
    /// to [`p2p_connect_hinted`] so the first dial needs no lookup.
    pub relay_url: Option<String>,
}

/// Parse an invite link. Errors with `Invalid` unless it is a well-formed `skwod://join/…` link
/// or a well-formed `https://skwod.io/join#…` share link (both spellings parse to the same invite).
#[uniffi::export]
pub fn p2p_parse_invite(link: String) -> Result<P2pInvite, CoreError> {
    let inv = Invite::parse(&link).map_err(net_err)?;
    Ok(P2pInvite { node_id: inv.node_id.to_z32(), join_code: inv.join_code, fallback_url: inv.fallback_url, relay_url: inv.relay_url })
}

/// Build an invite link from the host's node id (`GET /api/instance/p2p`) and a join code.
#[uniffi::export]
pub fn p2p_format_invite(node_id: String, join_code: Option<String>) -> Result<String, CoreError> {
    let node = skwod_net::invite::parse_node_id(&node_id).map_err(net_err)?;
    Ok(Invite::new(node, join_code.filter(|c| !c.trim().is_empty())).to_string())
}

/// Build the link people SHARE: `https://skwod.io/join#<node id>[.<join code>][&u=<https url>][&r=<relay url>]`.
/// It opens a static page (or, through universal links / app links, the app itself) that hands the
/// invite to the app. Everything identifying the skwod sits in the URL fragment, which is never
/// sent to a server. [`p2p_parse_invite`] accepts it, as do builds from 42 on; older builds only
/// understand the `skwod://` form from [`p2p_format_invite`], which the page forwards to.
/// `fallback_url` is kept only if it is an `https://` address; `relay_url` (the host's home relay,
/// `relay_url` in `GET /api/instance/p2p`) only if it is an allow-listed relay.
#[uniffi::export]
pub fn p2p_format_share_link(
    node_id: String,
    join_code: Option<String>,
    fallback_url: Option<String>,
    relay_url: Option<String>,
) -> Result<String, CoreError> {
    let node = skwod_net::invite::parse_node_id(&node_id).map_err(net_err)?;
    let mut invite = Invite::new(node, join_code.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()));
    invite.fallback_url = fallback_url.filter(|u| u.starts_with("https://"));
    invite.relay_url = relay_url.as_deref().and_then(skwod_net::invite::is_allowed_relay);
    let link = invite.share_link();
    // Never hand out a link we would refuse ourselves (e.g. a code outside the charset).
    Invite::parse(&link).map_err(net_err)?;
    Ok(link)
}

/// How we currently reach the host. Never contains an address.
#[derive(Debug, uniffi::Record)]
pub struct P2pPath {
    /// `"direct"` (straight UDP to the host), `"relay"` (via a relay — only with public fallback),
    /// or `"none"` (not connected right now; the next request re-dials).
    pub kind: String,
    /// Round-trip time of that path in milliseconds (0 when not connected).
    pub rtt_ms: u32,
}

/// Build 51: what [`P2pSession::ensure_front`] found.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct P2pFrontState {
    /// The listener was gone (or not proved ours) and was replaced.
    pub relistened: bool,
    /// Not proved ours and not replaced (it could not be, or — `ensure_front_deferring` — not yet):
    /// SUSPECT, it forwards nothing; ask again.
    pub failed: bool,
    /// The front's base URL now — different from before only when the old port could not be had.
    pub base_url: String,
    /// When it moved: the session's NEW credential (the old one maps to nothing). Rebind with it.
    pub credential: Option<String>,
}

/// Build 51: what [`P2pSession::check`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct P2pHealth {
    /// The loopback proxy is alive and ours. False: replace the session now.
    pub proxy_ok: bool,
    /// The host answered over the connection in time.
    pub upstream_ok: bool,
}

/// Build 51: is `base_url` the URL of one of this process's loopback fronts?
#[uniffi::export]
pub fn is_front_base(base_url: String) -> bool {
    skwod_sync::client::is_front_base(&base_url)
}

/// Build 51: is the front behind `base_url` SUSPECT (or dead)? Then the app sends nothing to it
/// until `ensure_front` has proved it ours.
#[uniffi::export]
pub fn is_front_suspect(base_url: String) -> bool {
    skwod_sync::client::is_front_suspect(&base_url)
}

/// Build 51: was this base URL a loopback proxy that has been closed? Nothing — no request of
/// the app's own HTTP / WebSocket code — may go to it any more: another local process could be
/// listening on that port by now.
#[uniffi::export]
pub fn is_retired_base(base_url: String) -> bool {
    skwod_sync::client::is_retired_base(&base_url)
}

/// Counters of the voice tunnel's media forwarder (UDP packets to/from LiveKit).
#[derive(Debug, uniffi::Record)]
pub struct P2pVoiceStats {
    pub packets_up: u64,
    pub bytes_up: u64,
    pub packets_down: u64,
    pub bytes_down: u64,
    /// Packets that came from the host and could not be handed to the call on this device.
    pub undelivered: u64,
    /// Signaling sockets the host's call server accepted (it was reached that many times).
    pub accepted: u64,
}

/// A live p2p connection to one skwod host, plus the loopback proxy in front of it.
#[derive(uniffi::Object)]
pub struct P2pSession {
    /// The member connection the front forwards to — swapped by [`P2pSession::reconnect`],
    /// invisible to the app: a reconnect changes neither the front's port nor its base URL.
    slot: Arc<MemberSlot>,
    proxy: LocalProxy,
    /// What the member was dialed with, for the next one (`public_fallback` may change).
    dial: Mutex<(NetConfig, EndpointAddr)>,
    /// One reconnect at a time.
    reconnecting: tokio::sync::Mutex<()>,
    /// Set by `disconnect`: a reconnect in progress stops, draining members close at once.
    cancel: tokio::sync::watch::Sender<bool>,
    /// Serializes everything that changes who the front speaks for: sign-in, rotate, logout,
    /// clear, and a re-key (`ensure_front`).
    auth: tokio::sync::Mutex<()>,
    /// SUSPECT + its epoch, for this session whichever secret is current.
    suspicion: Arc<skwod_sync::client::Suspicion>,
    /// Paces replacements (`Pacer`).
    pacer: Mutex<Pacer>,
    /// The host's node id (the slot may be empty).
    host_id: String,
}

/// Build 51: the member connection behind a stable front. Every stream the front opens is opened
/// on whatever member is current at that moment; a stream already open on the previous member
/// finishes or fails there — the front never replays it. The slot can be EMPTY (fail closed):
/// after a relay opt-out whose compliant dial has not succeeded yet, and after `disconnect`.
pub(crate) struct MemberSlot {
    state: Mutex<SlotState>,
    /// The bearer voice was authorized with, so a new member is authorized the same way.
    voice_bearer: Mutex<Option<String>>,
    /// Tests: a reconnect waits here between its dial and its voice start.
    #[cfg(test)]
    before_voice: Mutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
}

#[derive(Default)]
struct SlotState {
    current: Option<Arc<Member>>,
    /// Replaced members still finishing their streams (closed at the end of the grace, or at
    /// once by `disconnect`).
    draining: Vec<Arc<Member>>,
    /// `disconnect` ran: nothing is put in any more.
    closed: bool,
}

impl MemberSlot {
    fn new(member: Arc<Member>) -> Arc<Self> {
        Arc::new(Self { state: Mutex::new(SlotState { current: Some(member), ..Default::default() }), voice_bearer: Mutex::new(None),
            #[cfg(test)]
            before_voice: Mutex::new(None) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SlotState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The member to use — none when it is being closed or not allowed any more (relays off).
    pub(crate) fn member(&self) -> Option<Arc<Member>> {
        self.lock().current.clone().filter(|m| !m.is_closing())
    }

    fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Everything here must go: the closes start now (no runtime needed). Returns what to wait for.
    fn close_all(&self, st: &mut SlotState) -> Vec<Arc<Member>> {
        let all: Vec<_> = st.current.take().into_iter().chain(std::mem::take(&mut st.draining)).collect();
        for m in &all { m.start_close(); }
        all
    }
}

/// How long a disconnect waits for a member's close (which goes on either way).
const CLOSE_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

fn no_member() -> skwod_net::NetError {
    skwod_net::NetError::Unreachable("no connection to the host right now".into())
}

impl skwod_net::proxy::Upstream for MemberSlot {
    fn open_http(self: Arc<Self>) -> skwod_net::proxy::UpstreamFuture<Box<dyn skwod_net::proxy::Io>> {
        let member = self.member();
        Box::pin(async move { Ok(Box::new(member.ok_or_else(no_member)?.open_http().await?) as Box<dyn skwod_net::proxy::Io>) })
    }
    fn open_livekit(self: Arc<Self>) -> skwod_net::proxy::UpstreamFuture<Box<dyn skwod_net::proxy::Io>> {
        let member = self.member();
        Box::pin(async move { Ok(Box::new(member.ok_or_else(no_member)?.open_livekit().await?) as Box<dyn skwod_net::proxy::Io>) })
    }
    fn pow_identity(&self) -> Option<([u8; 32], [u8; 32])> {
        let m = self.member()?;
        Some((*m.host_id().as_bytes(), *m.id().as_bytes()))
    }
}

/// Build 51 (E): replacements are paced — at least `MIN_GAP` apart after one that worked, and
/// backing off (5 s doubling to 60 s) after ones that failed — so nothing (window focus, pull to
/// refresh, a flapping network) can make the app re-dial in a loop. A relay-setting change is
/// never paced. Pure, tested.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Pacer {
    last: Option<std::time::Instant>,
    failures: u32,
}

impl Pacer {
    pub(crate) const MIN_GAP: std::time::Duration = std::time::Duration::from_secs(10);

    /// How long until another attempt may run (zero: now).
    pub(crate) fn wait(&self, now: std::time::Instant) -> std::time::Duration {
        let Some(last) = self.last else { return std::time::Duration::ZERO };
        let gap = if self.failures == 0 { Self::MIN_GAP } else { std::time::Duration::from_secs((5u64 << (self.failures - 1).min(4)).min(60)) };
        gap.saturating_sub(now.saturating_duration_since(last))
    }

    pub(crate) fn record(&mut self, now: std::time::Instant, ok: bool) {
        self.last = Some(now);
        self.failures = if ok { 0 } else { self.failures.saturating_add(1) };
    }
}

/// The core's API requests to a front go over the member connection in process
/// (`skwod_sync::client::FrontTransport`): passwords and tokens never cross loopback.
fn install_transport() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let t: skwod_sync::client::FrontTransport = Arc::new(|secret, method, path, headers, body| {
            Box::pin(async move {
                let session = session_by_secret(&secret)?;
                skwod_net::proxy::direct_request(session.slot.clone(), &method, &path, headers, body,
                                                 8 * 1024 * 1024, std::time::Duration::from_secs(30)).await
            })
        });
        skwod_sync::client::set_front_transport(t);
    });
}

/// How long an opt-out may take to be confirmed.
const RELAYS_OFF_BOUND: std::time::Duration = std::time::Duration::from_secs(6);

/// Apply the stored relay setting at process start, before any dial (until then relay-allowed
/// dials are refused). The notification extension too.
#[uniffi::export]
pub fn p2p_relays_init(allowed: bool) {
    let gate = skwod_net::RelayGate::global();
    if allowed { gate.on() } else { gate.revoke() }
}

/// Relays turned OFF from this moment, without waiting for anything: no relay-allowed dial can
/// start, and everything that may use one starts closing. `p2p_relays_off` then confirms it.
#[uniffi::export]
pub fn p2p_relays_revoke() {
    skwod_net::RelayGate::global().revoke();
}

/// Relays turned ON.
#[uniffi::export]
pub fn p2p_relays_on() {
    skwod_net::RelayGate::global().on();
}

/// Build 51: relays turned OFF for this process, and CONFIRMED (`skwod_net::relay_gate`): from now
/// no relay-allowed dial can start, every one in progress stops, every relay-allowed endpoint —
/// whoever holds it — starts closing, and this returns Ok only when the last one has finished.
/// An error means one may still be open: the app must disconnect every session and say so.
#[uniffi::export(async_runtime = "tokio")]
pub async fn p2p_relays_off() -> Result<(), CoreError> {
    let gate = skwod_net::RelayGate::global();
    gate.revoke();
    let failed = |what: &str| CoreError::Engine { detail: format!("relays could not be turned off: {what}") };
    if tokio::runtime::Handle::try_current().is_err() { return Err(failed("no runtime")); }
    if gate.off(RELAYS_OFF_BOUND).await { Ok(()) } else { Err(failed("a connection did not close")) }
}

fn session_by_secret(secret: &str) -> Option<Arc<P2pSession>> {
    let map = sessions().lock().unwrap_or_else(|e| e.into_inner());
    map.values().filter_map(Weak::upgrade).find(|s| s.proxy.secret() == secret)
}

/// How long a replaced member stays open, so streams already on it can finish.
const SWAP_GRACE: std::time::Duration = std::time::Duration::from_secs(15);

fn sessions() -> &'static Mutex<HashMap<String, Weak<P2pSession>>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Weak<P2pSession>>>> = OnceLock::new();
    SESSIONS.get_or_init(Default::default)
}

/// The p2p session behind a base URL, if that URL is one of our loopback proxies.
pub(crate) fn session_for(base_url: &str) -> Option<Arc<P2pSession>> {
    sessions().lock().unwrap_or_else(|e| e.into_inner()).get(base_url.trim_end_matches('/')).and_then(Weak::upgrade)
}

/// Dial the skwod whose address is `node_id` (from [`p2p_parse_invite`]) and start the loopback
/// proxy. Finds the host through the Mainline DHT and connects directly when it can.
///
/// `public_fallback`: also allow n0's public relays + DNS (default choice: `true` — connects
/// through almost any NAT). `false` = strictly independent: DHT + direct connections only; fails
/// with an `Engine` error ("could not reach the host") when no direct path exists.
///
/// The member uses a fresh throwaway key per call, so the host cannot link sessions by node id.
#[uniffi::export(async_runtime = "tokio")]
pub async fn p2p_connect(node_id: String, public_fallback: bool) -> Result<Arc<P2pSession>, CoreError> {
    p2p_connect_hinted(node_id, public_fallback, None, None).await
}

/// [`p2p_connect`] with the host's home relay from the invite (`P2pInvite::relay_url`) or a
/// previous session. The hint is used only with `public_fallback` and only if it is an
/// allow-listed relay; the host is still identified by its key, so a wrong hint costs nothing.
///
/// Never hangs: the whole call (endpoint, lookup, dial) is bounded by
/// [`P2P_CONNECT_TIMEOUT_SECS`] and fails with `Engine { "could not reach the host: timed out" }`.
#[uniffi::export(async_runtime = "tokio")]
pub async fn p2p_connect_hinted(node_id: String, public_fallback: bool, relay_url: Option<String>, routes: Option<String>) -> Result<Arc<P2pSession>, CoreError> {
    let node = skwod_net::invite::parse_node_id(&node_id).map_err(net_err)?;
    let mut cfg = NetConfig::member();
    cfg.public_fallback = public_fallback;
    cfg.routes = skwod_net::Routes::load(node, routes.as_deref());
    connect_with(&cfg, skwod_net::invite::dial_addr(node, relay_url.as_deref(), public_fallback)).await
}

/// Seconds [`p2p_connect`] may take in total before it gives up (the apps add a small margin).
#[uniffi::export]
pub fn p2p_connect_timeout_secs() -> u32 {
    P2P_CONNECT_TIMEOUT_SECS
}
pub const P2P_CONNECT_TIMEOUT_SECS: u32 = 20;

/// [`p2p_connect`] with an explicit network configuration / dialing info (tests, same-machine dial).
pub async fn connect_with(cfg: &NetConfig, host: EndpointAddr) -> Result<Arc<P2pSession>, CoreError> {
    let permit = skwod_net::RelayPermit::new(cfg).map_err(net_err)?;
    // The whole of it (bind, dial, proxy start, registration) is given up when relays go off.
    permit.run(connect_permitted(cfg, host, &permit)).await.map_err(net_err)?
}

async fn connect_permitted(cfg: &NetConfig, host: EndpointAddr, permit: &skwod_net::RelayPermit) -> Result<Arc<P2pSession>, CoreError> {
    let budget = std::time::Duration::from_secs(P2P_CONNECT_TIMEOUT_SECS.into());
    let deadline = tokio::time::Instant::now() + budget;
    let member = Member::connect_within(cfg, host.clone(), budget).await.map_err(net_err)?;
    let slot = MemberSlot::new(member.clone());
    // The loopback proxy is local and instant, but it is under the same budget all the same.
    // The front injects the session token the core holds for it (`FRONT_BEARER`), read on every
    // forward — the token itself never crosses loopback.
    let tokens: skwod_net::proxy::TokenSource = Arc::new(|secret: &str, credential: &str| skwod_sync::client::front_token_for(secret, credential));
    let proxy = match tokio::time::timeout_at(deadline, LocalProxy::start_with_tokens(slot.clone(), tokens)).await {
        Ok(p) => p.map_err(net_err)?,
        Err(_) => {
            member.start_close();
            return Err(net_err(skwod_net::NetError::Unreachable("timed out".into())));
        }
    };
    let suspicion: Arc<skwod_sync::client::Suspicion> = Arc::default();
    skwod_sync::client::register_front_with(&proxy.secret(), proxy.port(), suspicion.clone());
    install_transport();
    // The listener failed for good: the port may be someone else's now — SUSPECT until a
    // challenge proves it ours (`ensure_front`). Holds only a receiver and the session's
    // suspicion, never the session.
    {
        let mut closed = proxy.closed_receiver();
        let suspicion = suspicion.clone();
        tokio::spawn(async move {
            while closed.changed().await.is_ok() {
                if *closed.borrow() { let _ = suspicion.raise(); }
            }
        });
    }
    let session = Arc::new(P2pSession {
        slot,
        proxy,
        host_id: host.id.to_z32(),
        dial: Mutex::new((cfg.clone(), host)),
        reconnecting: tokio::sync::Mutex::new(()),
        cancel: tokio::sync::watch::channel(false).0,
        pacer: Mutex::new(Pacer::default()),
        suspicion,
        auth: tokio::sync::Mutex::new(()),
    });
    if !permit.is_current() { return Err(relays_changed()); }
    let mut map = sessions().lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, s| s.strong_count() > 0);
    map.insert(session.proxy.base_url(), Arc::downgrade(&session));
    drop(map);
    Ok(session)
}

fn relays_changed() -> CoreError {
    CoreError::Engine { detail: "the relay setting changed".into() }
}

#[uniffi::export(async_runtime = "tokio")]
impl P2pSession {
    /// The server URL to use everywhere a `https://…` server URL was used:
    /// `http://127.0.0.1:<port>/<secret>`. Valid until [`P2pSession::close`] / app exit; it
    /// changes every launch, so persist the node id (not this URL) as the skwod's identity.
    pub fn base_url(&self) -> String {
        self.proxy.base_url()
    }

    /// The host's node id (z-base-32) this session is pinned to.
    pub fn node_id(&self) -> String {
        self.host_id.clone()
    }

    /// Build 51: dial the host afresh — a new endpoint, a new connection — and put it behind the
    /// SAME front: the base URL, the port and every client bound to them stay as they are.
    /// What a dead session needed a relaunch for (sockets the OS took away while the app was
    /// suspended) is this call. `public_fallback`: dial under a new relay setting (the setting
    /// changed); nil keeps the one the session has. Streams already open on the old connection
    /// finish or fail there (it stays open for a short grace) — nothing is replayed. Concurrent
    /// calls wait for the one running. Bounded like a connect.
    pub async fn reconnect(&self, public_fallback: Option<bool>) -> Result<(), CoreError> {
        let closed_err = || CoreError::Engine { detail: "the session was closed".into() };
        if self.slot.is_closed() { return Err(closed_err()); }
        // (What turning relays off closes and stops is `p2p_relays_off`'s, not a session's: here
        // it only says what the next dial may use — and that the gate has the last word on.)
        if let Some(f) = public_fallback {
            let mut dial = self.dial.lock().unwrap_or_else(|e| e.into_inner());
            dial.0.public_fallback = f;
            dial.1 = skwod_net::invite::dial_addr(dial.1.id, None, f);
        }
        let _one = self.reconnecting.lock().await;
        if self.slot.is_closed() { return Err(closed_err()); }
        // Paced (never for a relay-setting change, which must take effect).
        if public_fallback.is_none() {
            let wait = self.pacer.lock().unwrap_or_else(|e| e.into_inner()).wait(std::time::Instant::now());
            if !wait.is_zero() {
                return Err(CoreError::Engine { detail: format!("reconnect paced: next attempt in {} s", wait.as_secs().max(1)) });
            }
        }
        let result = self.reconnect_now().await;
        self.pacer.lock().unwrap_or_else(|e| e.into_inner()).record(std::time::Instant::now(), result.is_ok());
        result
    }

    /// Build 51: where this host was reached directly, if there is anything new to store — opaque, for
    /// [`p2p_connect_hinted`]'s `routes` next time. It tells where the host is: kept encrypted on this
    /// device only, with the workspace, and deleted when it is signed out of, removed or erased.
    pub fn take_routes(&self) -> Option<String> {
        self.dial.lock().unwrap_or_else(|e| e.into_inner()).0.routes.take_blob()
    }

    /// Direct or relayed, and the latency — for a connection indicator. Local only; no telemetry.
    pub async fn path(&self) -> P2pPath {
        let Some(member) = self.slot.member() else { return P2pPath { kind: "none".into(), rtt_ms: 0 } };
        let p = member.path().await;
        P2pPath { kind: p.kind.as_str().to_string(), rtt_ms: p.rtt_ms }
    }

    /// Start (or re-use) the voice tunnel for this session and return the URL to hand the LiveKit
    /// SDK instead of the server-reported one. `session_token` is the account's bearer token (it
    /// authorizes media forwarding on the host). `SkwodClient::voice_token` calls this for you.
    pub async fn voice_url(&self) -> Result<String, CoreError> {
        // The bearer is the session's own token, read in the core under the auth lock — never
        // one handed in by a caller, never a stale one after a sign-out or another sign-in.
        let _auth = self.auth.lock().await;
        let session_token = skwod_sync::client::front_current_token(&self.proxy.secret())
            .ok_or_else(|| CoreError::Engine { detail: "not signed in".into() })?;
        let member = self.slot.member().ok_or_else(|| net_err(no_member()))?;
        tokio::time::timeout(std::time::Duration::from_secs(10), member.voice_start(&session_token)).await
            .map_err(|_| voice_net_error(&skwod_net::NetError::Unreachable(String::new())))?.map_err(|e| voice_net_error(&e))?;
        // Never kept for a session that was closed meanwhile.
        let kept = {
            let st = self.slot.lock();
            if !st.closed { *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = Some(session_token); }
            !st.closed
        };
        if !kept { return Err(CoreError::Engine { detail: "the session was closed".into() }); }
        Ok(self.proxy.livekit_url())
    }

    /// Media carried by the voice tunnel so far — for a call-quality/debug readout. Local only.
    pub fn voice_stats(&self) -> P2pVoiceStats {
        let member = self.slot.member();
        let (packets_up, bytes_up, packets_down, bytes_down) = member.as_ref().map(|m| m.voice_stats()).unwrap_or_default();
        let undelivered = member.map(|m| m.voice_undelivered()).unwrap_or_default();
        P2pVoiceStats { packets_up, bytes_up, packets_down, bytes_down, undelivered, accepted: self.proxy.livekit_accepted() }
    }

    /// Tell the transport the device's network changed (Wi-Fi ↔ cellular). Required on Android,
    /// harmless elsewhere.
    pub async fn network_changed(&self) {
        if let Some(m) = self.slot.member() { m.network_changed().await; }
    }

    /// Close the connection and stop the loopback proxy. From here on no `SkwodClient` built on
    /// this base URL sends anything (`skwod_sync::client::retire_base`): unbind every other user
    /// of the URL (the app's own HTTP / WebSocket code) BEFORE calling this, and drop the
    /// session — which releases the port — only after that.
    pub async fn disconnect(&self) {
        skwod_sync::client::retire_base(&self.proxy.base_url());
        // Forgotten HERE only: a front closed because the skwod moved, the relay setting could not
        // be applied, or its host changed says nothing to the host — the session goes on elsewhere
        // (ending it there is `end_session`'s, for a sign-out, a removal or the account's end).
        skwod_sync::client::front_sign_out(&self.proxy.secret());
        sessions().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.proxy.base_url());
        // Wakes `wait_proxy_closed` (so its caller lets go of this session) and stops the listener.
        self.proxy.shutdown();
        // Closed first (a reconnect sees it before and at its swap), then everything goes: the
        // current member, every draining one, a reconnect in progress.
        let all = {
            let mut st = self.slot.lock();
            st.closed = true;
            self.slot.close_all(&mut st)
        };
        *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.cancel.send_replace(true);
        let deadline = tokio::time::Instant::now() + CLOSE_WAIT;
        for m in all { let _ = tokio::time::timeout_at(deadline, m.closed()).await; }
    }

    /// Build 51 (iOS listener reclaim): make sure the front is listening and PROVED ours —
    /// checked in process (accept-loop state + a one-time nonce to its own port). If not, it
    /// RE-KEYS — always a new secret, so the base URL changes on every re-listen and the app
    /// re-binds with the returned credential: in place on the port it still holds when the
    /// challenge was merely unanswered, else listening again (the same port if it can be had,
    /// a new one otherwise). Clears SUSPECT when proved ours. Call on become-active, before
    /// sending anything.
    pub async fn ensure_front(self: Arc<Self>) -> P2pFrontState {
        self.ensure_front_spawned(false).await
    }

    /// `ensure_front` while a call runs through this front: a challenge merely UNANSWERED does not
    /// re-key it yet (a flood must not be able to drop a call) — but it is SUSPECT from then on,
    /// carries nothing new, and is reported `failed`: ask again. Never trusted on the strength of
    /// a proof that failed; a port that answered as NOT ours, or a listener that is gone, re-keys
    /// at once, call or no call.
    pub async fn ensure_front_deferring(self: Arc<Self>) -> P2pFrontState {
        self.ensure_front_spawned(true).await
    }

    /// Build 51: the app is going to the background (or resigning active). Until `ensure_front`
    /// proves the front ours again, it is SUSPECT: the core sends nothing to it, pre-auth
    /// included, and the app's own requests must not either (`is_front_suspect`).
    pub fn suspend(&self) {
        let _ = self.suspicion.raise();
    }

    /// Build 51: sign-out. The host is told the session is over — over the member connection
    /// itself, never through the loopback port — and the token the front would inject is cleared
    /// BEFORE this returns, whether or not the host answered within `timeout_ms`. Returns
    /// whether it did.
    pub async fn logout(&self, timeout_ms: u32) -> bool {
        let token = {
            let _auth = self.auth.lock().await;
            let secret = self.proxy.secret();
            let token = skwod_sync::client::front_current_token(&secret);
            skwod_sync::client::front_sign_out(&secret);
            *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None;
            token
        };
        let Some(token) = token else { return false };
        let timeout = std::time::Duration::from_millis(timeout_ms.clamp(500, 10_000).into());
        let status = skwod_net::proxy::upstream_request(self.slot.clone(), "POST", "/api/auth/logout", &token, None, timeout).await;
        (200..300).contains(&status)
    }

    /// Build 51: the session ends (sign-out, erase, a duplicate removed). Under the auth lock the
    /// token is TAKEN and cleared in one step (nothing can use it after this point, and no
    /// re-key re-arms it); then, with the captured token, over the member connection — never the
    /// loopback port — push is unregistered (`unregister_push`) and the host told the session is
    /// over. Each bounded by `timeout_ms`. Returns whether the host acknowledged the logout
    /// (false also when there was no token).
    pub async fn end_session(&self, unregister_push: bool, timeout_ms: u32) -> bool {
        let token = {
            let _auth = self.auth.lock().await;
            let secret = self.proxy.secret();
            let token = skwod_sync::client::front_current_token(&secret);
            skwod_sync::client::front_sign_out(&secret);
            *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None;
            token
        };
        let Some(token) = token else { return false };
        let timeout = std::time::Duration::from_millis(timeout_ms.clamp(500, 10_000).into());
        if unregister_push {
            let _ = skwod_net::proxy::upstream_request(self.slot.clone(), "POST", "/api/push/unregister", &token, Some("{}".into()), timeout).await;
        }
        let status = skwod_net::proxy::upstream_request(self.slot.clone(), "POST", "/api/auth/logout", &token, None, timeout).await;
        (200..300).contains(&status)
    }

    /// Build 51: one request with the session's token, straight over the member connection (push
    /// unregister and the like — what must not depend on the loopback port). `body`: JSON text.
    /// Returns the HTTP status, 0 when there was no token or no answer within `timeout_ms`.
    pub async fn send_authed(&self, method: String, path: String, body: Option<String>, timeout_ms: u32) -> u16 {
        let Some(token) = skwod_sync::client::front_current_token(&self.proxy.secret()) else { return 0 };
        if !path.starts_with("/api/") { return 0 }
        let timeout = std::time::Duration::from_millis(timeout_ms.clamp(500, 10_000).into());
        skwod_net::proxy::upstream_request(self.slot.clone(), &method, &path, &token, body, timeout).await
    }

    /// Build 51: forget the token this front injects — if `token` is the one signed in now (the
    /// session the host ended). Another session signed in meanwhile is left alone. Returns
    /// whether it was cleared.
    pub async fn clear_session(&self, token: String) -> bool {
        let _auth = self.auth.lock().await;
        let cleared = skwod_sync::client::front_sign_out_token(&self.proxy.secret(), &token);
        if cleared { *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None; }
        cleared
    }

    /// The same by credential: what a sign-in that turned out not to be wanted handed out.
    pub async fn clear_credential(&self, credential: String) -> bool {
        let _auth = self.auth.lock().await;
        let cleared = skwod_sync::client::front_sign_out_credential(&self.proxy.secret(), &credential);
        if cleared { *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None; }
        cleared
    }

    /// Build 51: explicit sign-in (log in, sign up, a session restored at launch, pairing done):
    /// the core keeps `token` for this front and returns the opaque credential every client of
    /// this front presents instead (`Bearer <credential>`, as `SkwodClient`'s token and in the
    /// app's own requests). Idempotent for the token already signed in; for another, earlier
    /// credentials stop working. None for an empty token.
    pub async fn sign_in(&self, token: String) -> Option<String> {
        let _auth = self.auth.lock().await;
        // Another session: whatever voice was authorized with before is not carried over. (The
        // same one again changes nothing.)
        let secret = self.proxy.secret();
        if skwod_sync::client::front_current_token(&secret).as_deref() != Some(token.as_str()) {
            *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
        skwod_sync::client::front_sign_in(&secret, &token)
    }

    /// Build 51: the session's token was rotated. Refused (false) unless `credential` is the one
    /// signed in now — nothing re-arms a front after a sign-out but `sign_in`.
    pub async fn rotate_token(&self, credential: String, token: String) -> bool {
        let _auth = self.auth.lock().await;
        *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None;
        skwod_sync::client::front_rotate(&self.proxy.secret(), &credential, &token)
    }

    /// Build 51: this session was judged dead or foreign. From now on no client of this app
    /// sends anything to its URL (`skwod_sync::client::retire_base`) — but its port stays held
    /// until the app has unbound everything and calls [`P2pSession::disconnect`].
    pub fn retire(&self) {
        skwod_sync::client::retire_base(&self.proxy.base_url());
    }

    /// Build 51: is this session still usable? Two answers, because they mean different things:
    ///
    /// - `proxy_ok`: this session's front is alive, verified AND ours — a request sent to its
    ///   port reached THIS front's handler (a one-time nonce, checked in process: any reply from
    ///   whatever listens on the port proves nothing). A probe: it changes nothing; false means
    ///   the app calls `ensure_front`.
    /// - `upstream_ok`: the host answered `GET /health` over the connection within
    ///   `timeout_ms` (one slow answer is not a dead session; the app counts these).
    ///
    /// Takes at most 1.5 s + min(timeout, 3 s) for the proxy part, plus `timeout` for the host.
    pub async fn check(&self, timeout_ms: u32) -> P2pHealth {
        let timeout = std::time::Duration::from_millis(timeout_ms.clamp(500, 30_000).into());
        // Only a challenge PROVED ours counts: not ours, or silent (until it answers, the front
        // forwards nothing) — `ensure_front` listens again.
        let budgets = [std::time::Duration::from_millis(1_500), timeout.min(std::time::Duration::from_secs(3))];
        // A probe: it changes nothing (a health check never races `ensure_front`, which alone
        // decides trust under the auth lock).
        if self.proxy.probe(&budgets).await != skwod_net::proxy::Challenge::Ours {
            // Not proved: SUSPECT from now — nothing is sent to it until `ensure_front` proves it
            // (or re-keys), whatever the caller does with this answer.
            let _ = self.suspicion.raise();
            return P2pHealth { proxy_ok: false, upstream_ok: false };
        }
        P2pHealth { proxy_ok: true, upstream_ok: skwod_net::proxy::upstream_answers(self.slot.clone(), timeout).await }
    }

    /// Build 51: resolves when this session's loopback proxy has failed for good (at once if
    /// it already has) — the app replaces the session then, without waiting for a probe — or
    /// when the session is disconnected, so a waiter never keeps a released session alive.
    pub async fn wait_proxy_closed(&self) {
        self.proxy.closed().await;
    }

    /// Build 51: the loopback proxy failed for good (local only, instant).
    pub fn proxy_closed(&self) -> bool {
        self.proxy.is_closed()
    }
}

/// Not exported: everything in an exported `impl` block is, private or not.
impl P2pSession {
    #[cfg(test)]
    async fn clear_token(&self) {
        let _auth = self.auth.lock().await;
        skwod_sync::client::front_sign_out(&self.proxy.secret());
        *self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    async fn ensure_front_spawned(self: Arc<Self>, defer: bool) -> P2pFrontState {
        // Cancellation-safe: the check, the swap and the registry/session migration run to the
        // end in a task of their own even if the caller stops waiting.
        // The epoch is taken NOW — before the task, before waiting for `auth`: a suspicion
        // raised while this waits or runs is never cleared by it.
        let epoch = self.suspicion.epoch();
        let this = self.clone();
        match tokio::spawn(async move { this.ensure_front_inner(epoch, defer).await }).await {
            Ok(state) => state,
            Err(_) => P2pFrontState { relistened: false, failed: true, base_url: self.proxy.base_url(), credential: None },
        }
    }

    /// (Uninterrupted; see `ensure_front`.)
    async fn ensure_front_inner(&self, epoch: u64, defer: bool) -> P2pFrontState {
        // Serialized with sign-in, rotate, logout and clear (`auth`): a re-key can never
        // re-arm a session that a sign-out ended.
        let _auth = self.auth.lock().await;
        let before = self.proxy.base_url();
        let budgets = [std::time::Duration::from_secs(2), std::time::Duration::from_secs(4)];
        // A URL already retired (a re-listen that failed, a sign of distrust) is never reported
        // healthy again: it always re-listens.
        let verdict = if self.proxy.is_closed() || skwod_sync::client::is_retired_base(&before) {
            skwod_net::proxy::Challenge::NotOurs
        } else {
            self.proxy.verify(&budgets).await
        };
        if verdict == skwod_net::proxy::Challenge::Ours {
            self.suspicion.clear_if(epoch);
            return P2pFrontState { relistened: false, failed: false, base_url: before, credential: None };
        }
        if defer && verdict == skwod_net::proxy::Challenge::Slow {
            // Unanswered, with a call running: the re-key waits; the trust does not.
            let _ = self.suspicion.raise();
            return P2pFrontState { relistened: false, failed: true, base_url: before, credential: None };
        }
        // Not proved ours: the URL is retired FIRST (before any port is let go), then the front
        // re-keys: in place on the port it still holds when the challenge was merely unanswered
        // (published only once proved), else listening again (same port if it can be had).
        skwod_sync::client::retire_base(&before);
        let migrate = |old_secret: &str| {
            let (port, secret) = self.proxy.identity();
            // One registry step: the session (token, suspicion) carried to the current secret,
            // under a NEW credential if signed in — so logout always finds it.
            let credential = skwod_sync::client::front_rekey(old_secret, &secret, port);
            let after = self.proxy.base_url();
            let mut map = sessions().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(me) = map.remove(before.trim_end_matches('/')) { map.insert(after.clone(), me); }
            (after, credential)
        };
        match self.proxy.relisten(verdict == skwod_net::proxy::Challenge::Slow).await {
            skwod_net::proxy::FrontState::Relistened { old_secret, .. } => {
                let (after, credential) = migrate(&old_secret);
                // Proved ours (or freshly bound) by the re-key: trusted unless suspected since.
                self.suspicion.clear_if(epoch);
                P2pFrontState { relistened: true, failed: false, base_url: after, credential }
            }
            skwod_net::proxy::FrontState::Failed { old_secret: Some(old_secret) } => {
                // The secret changed before the bind failed: the session follows it (still
                // suspect, distrusted) — reachable for logout; the next call retries.
                let (after, credential) = migrate(&old_secret);
                let _ = self.suspicion.raise();
                P2pFrontState { relistened: false, failed: true, base_url: after, credential }
            }
            _ => {
                let _ = self.suspicion.raise();
                P2pFrontState { relistened: false, failed: true, base_url: before, credential: None }
            }
        }
    }

    /// (Holding the reconnect lock.) The dial and the swap.
    async fn reconnect_now(&self) -> Result<(), CoreError> {
        let closed_err = || CoreError::Engine { detail: "the session was closed".into() };
        let (cfg, host) = self.dial.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let permit = skwod_net::RelayPermit::new(&cfg).map_err(net_err)?;
        let mut cancel = self.cancel.subscribe();
        // All of it stops on a disconnect and when relays go off; a member dialed by then is
        // dropped with it, which closes it.
        let next = tokio::select! {
            biased;
            _ = cancel.wait_for(|c| *c) => return Err(closed_err()),
            r = permit.run(self.dial_next(&cfg, host, &permit)) => r.map_err(net_err)??,
        };
        // The swap and the checks are one step: a disconnect is either before (the new member is
        // closed, never used) or after (it closes it with the rest).
        let old = {
            let mut st = self.slot.lock();
            if st.closed || !permit.is_current() {
                next.start_close();
                return Err(closed_err());
            }
            let old = st.current.replace(next);
            if let Some(old) = &old { st.draining.push(old.clone()); }
            old
        };
        if let Some(old) = old {
            let (slot, mut cancel) = (self.slot.clone(), self.cancel.subscribe());
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(SWAP_GRACE) => {}
                    _ = cancel.wait_for(|c| *c) => {}
                    _ = old.closed() => {}
                }
                old.start_close();
                slot.lock().draining.retain(|m| !Arc::ptr_eq(m, &old));
            });
        }
        Ok(())
    }

    /// The next member, voice authorized on it if it was on.
    async fn dial_next(&self, cfg: &NetConfig, host: EndpointAddr, permit: &skwod_net::RelayPermit) -> Result<Arc<Member>, CoreError> {
        let budget = std::time::Duration::from_secs(P2P_CONNECT_TIMEOUT_SECS.into());
        let next = Member::connect_within(cfg, host, budget).await.map_err(net_err)?;
        #[cfg(test)]
        {
            let gate = self.slot.before_voice.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some((arrived, go)) = gate {
                arrived.notify_one();
                go.notified().await;
            }
        }
        // Read after the dial, and only as "voice was on": the bearer is the session's CURRENT
        // token (a sign-out meanwhile leaves none, and nothing re-authorizes voice).
        let voice_on = self.slot.voice_bearer.lock().unwrap_or_else(|e| e.into_inner()).is_some();
        let bearer = voice_on.then(|| skwod_sync::client::front_current_token(&self.proxy.secret())).flatten();
        if let Some(bearer) = bearer {
            if self.slot.is_closed() || !permit.is_current() { return Err(relays_changed()); }
            // Voice is re-authorized on the new connection before anything uses it (best effort:
            // the next LiveKit stream retries it). (`Member` sends no bearer once it is closing.)
            // The media port is the same one (it is the host's number), and the member being
            // replaced still holds it — for as long as its grace lasts, so a call that moved from
            // Wi-Fi to cellular had no media path until then. It goes over now; what it carried
            // was on the connection that is being given up.
            if let Some(old) = self.slot.member() {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), old.voice_release()).await;
            }
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), next.voice_start(&bearer)).await;
        }
        Ok(next)
    }
}

impl Drop for P2pSession {
    fn drop(&mut self) {
        // The proxy (and with it the port) goes now: nothing may send to this URL any more —
        // retired first, then the front (and its session) forgotten.
        skwod_sync::client::retire_base(&self.proxy.base_url());
        skwod_sync::client::unregister_front(&self.proxy.secret());
        // Dropped without a disconnect: its connections are closed all the same.
        let mut st = self.slot.lock();
        st.closed = true;
        self.slot.close_all(&mut st);
    }
}

#[cfg(test)]
mod share_link_tests {
    use super::*;

    /// A valid node id (any 32-byte ed25519 public key in z-base-32).
    fn node_id() -> String {
        skwod_net::SecretKey::generate().public().to_z32()
    }

    #[test]
    fn the_share_link_parses_back_to_the_same_invite_as_the_app_link() {
        let node = node_id();
        let share = p2p_format_share_link(node.clone(), Some("SKWD-AB12-CD34".into()), None, None).unwrap();
        assert_eq!(share, format!("https://skwod.io/join#{node}.SKWD-AB12-CD34"));
        let app = p2p_format_invite(node.clone(), Some("SKWD-AB12-CD34".into())).unwrap();
        assert_eq!(app, format!("skwod://join/{node}#SKWD-AB12-CD34"));
        for link in [share, app] {
            let inv = p2p_parse_invite(link).unwrap();
            assert_eq!(inv.node_id, node);
            assert_eq!(inv.join_code.as_deref(), Some("SKWD-AB12-CD34"));
            assert_eq!(inv.fallback_url, None);
        }
    }

    #[test]
    fn the_share_link_keeps_an_https_fallback_and_nothing_else() {
        let node = node_id();
        let with = p2p_format_share_link(node.clone(), Some("abc".into()), Some("https://chat.example.org".into()), None).unwrap();
        assert_eq!(with, format!("https://skwod.io/join#{node}.abc&u=https://chat.example.org"));
        assert_eq!(p2p_parse_invite(with).unwrap().fallback_url.as_deref(), Some("https://chat.example.org"));
        let dropped = p2p_format_share_link(node.clone(), Some("  ".into()), Some("http://chat.example.org".into()), None).unwrap();
        assert_eq!(dropped, format!("https://skwod.io/join#{node}"));
    }

    #[test]
    fn the_share_link_refuses_bad_input() {
        assert!(matches!(p2p_format_share_link("notakey".into(), None, None, None), Err(CoreError::Invalid { .. })));
        assert!(matches!(p2p_format_share_link(node_id(), Some("bad code!".into()), None, None), Err(CoreError::Invalid { .. })));
        assert!(matches!(p2p_parse_invite("https://evil.example/join#x.y".into()), Err(CoreError::Invalid { .. })));
    }

    #[test]
    fn the_share_link_carries_the_home_relay_only_if_allowed() {
        let node = node_id();
        let link = p2p_format_share_link(node.clone(), None, None, Some("https://use1-1.relay.n0.iroh.link./".into())).unwrap();
        assert_eq!(link, format!("https://skwod.io/join#{node}&r=https://use1-1.relay.n0.iroh.link/"));
        assert_eq!(p2p_parse_invite(link).unwrap().relay_url.as_deref(), Some("https://use1-1.relay.n0.iroh.link/"));
        let dropped = p2p_format_share_link(node.clone(), None, None, Some("https://evil.example/".into())).unwrap();
        assert_eq!(dropped, format!("https://skwod.io/join#{node}"));
    }
}

#[cfg(test)]
mod connect_timeout_tests {
    use super::*;

    /// An unreachable host (nothing to look up, no relay, no address) fails with a clear error
    /// inside the budget instead of hanging.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_host_fails_within_the_budget() {
        let mut cfg = NetConfig::member();
        cfg.public_fallback = false;
        cfg.discovery = skwod_net::Discovery::None;
        let node = skwod_net::SecretKey::generate().public();
        let started = std::time::Instant::now();
        let budget = std::time::Duration::from_secs(3);
        let err = match Member::connect_within(&cfg, EndpointAddr::new(node), budget).await {
            Err(e) => e,
            Ok(_) => panic!("connected to a host that does not exist"),
        };
        assert!(started.elapsed() < budget + std::time::Duration::from_secs(2), "took {:?}", started.elapsed());
        let msg = net_err(err).to_string();
        assert!(msg.contains("could not reach the host"), "{msg}");
    }

    #[test]
    fn the_budget_is_about_twenty_seconds() {
        assert_eq!(p2p_connect_timeout_secs(), 20);
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;
    use skwod_net::{BiStream, Discovery, EndpointId, Host, HostBackend, LiveKitTarget, SecretKey};
    use tokio::io::AsyncWriteExt;

    type Fut<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>;
    struct Ok200;
    impl HostBackend for Ok200 {
        fn serve_http(&self, _peer: EndpointId, _relayed: bool, mut io: BiStream) -> Fut<()> {
            Box::pin(async move {
                let mut buf = [0u8; 2048];
                let _ = tokio::io::AsyncReadExt::read(&mut io, &mut buf).await;
                let _ = io.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
                let _ = io.shutdown().await;
            })
        }
        fn authorize_voice(&self, _bearer: String) -> Fut<bool> { Box::pin(async { false }) }
        fn authorize_room(&self, _b: String, _r: String, _i: String) -> Fut<bool> { Box::pin(async { false }) }
        fn livekit(&self) -> Fut<Option<LiveKitTarget>> { Box::pin(async { None }) }
    }

    fn local(mut cfg: NetConfig) -> NetConfig {
        cfg.public_fallback = false;
        cfg.discovery = Discovery::None;
        cfg.portmapper = false;
        cfg
    }

    pub(super) async fn http_get(port: u16, path: &str, headers: &str) -> String {
        use tokio::io::AsyncReadExt;
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        tcp.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\n{headers}connection: close\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = String::new();
        let _ = tcp.read_to_string(&mut out).await;
        out
    }

    fn port_of(base: &str) -> u16 {
        base.trim_start_matches("http://127.0.0.1:").split('/').next().unwrap().parse().unwrap()
    }
    fn secret_of(base: &str) -> String {
        base.rsplit('/').next().unwrap().to_string()
    }

    /// E: replacements are paced — not again within the minimum gap, backing off after failures.
    #[test]
    fn replacements_are_paced() {
        let t0 = std::time::Instant::now();
        let mut p = Pacer::default();
        assert!(p.wait(t0).is_zero(), "the first one runs at once");
        p.record(t0, true);
        assert_eq!(p.wait(t0 + std::time::Duration::from_secs(3)), Pacer::MIN_GAP - std::time::Duration::from_secs(3));
        assert!(p.wait(t0 + Pacer::MIN_GAP).is_zero());
        p.record(t0, false);
        assert_eq!(p.wait(t0), std::time::Duration::from_secs(5));
        p.record(t0, false);
        assert_eq!(p.wait(t0), std::time::Duration::from_secs(10));
        for _ in 0..10 { p.record(t0, false); }
        assert_eq!(p.wait(t0), std::time::Duration::from_secs(60), "bounded");
        p.record(t0, true);
        assert_eq!(p.wait(t0), Pacer::MIN_GAP, "a success resets the backoff");
    }

    /// Build 51 (A): replacing the connection happens behind the front — the base URL and port
    /// stay, the member is a fresh endpoint, and requests keep working through the same URL.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_keeps_the_front_and_its_url() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        let path = format!("/{}/x", secret_of(&base));
        assert!(http_get(port_of(&base), &path, "").await.starts_with("HTTP/1.1 200"));
        let first = session.slot.member().unwrap().id();
        session.reconnect(None).await.unwrap();
        assert_eq!(session.base_url(), base, "the app sees nothing change");
        assert_ne!(session.slot.member().unwrap().id(), first, "a fresh endpoint behind the same front");
        assert!(http_get(port_of(&base), &path, "").await.starts_with("HTTP/1.1 200"));
        assert_eq!(session.check(3_000).await, P2pHealth { proxy_ok: true, upstream_ok: true });
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: a disconnect during a reconnect stops it; nothing ends up in the slot afterwards.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_disconnect_stops_a_reconnect_in_progress() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        host.shutdown().await;   // the dial now keeps trying until its budget
        let running = { let s = session.clone(); tokio::spawn(async move { s.reconnect(None).await }) };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        session.disconnect().await;
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), running).await.expect("stopped, not left to its 20 s budget").unwrap();
        assert!(r.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(session.slot.member().is_none(), "nothing is put in a closed session");
        assert!(session.reconnect(None).await.is_err(), "and nothing later either");
        assert!(session.voice_url().await.is_err(), "no bearer kept for a closed session");
    }

    /// Review: relays turned OFF — the old connection closes at once (no grace) and, while no
    /// compliant connection could be made, the front forwards nothing (fail closed).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relay_opt_out_fails_closed() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let gate = skwod_net::RelayGate::new(true);
        let session = connect_with(&relayed(&gate), host.loopback_addr()).await.unwrap();
        let old = session.slot.member().unwrap();
        assert!(gate.off(RELAYS_OFF_BOUND).await);
        assert!(old.is_closed());
        assert!(session.reconnect(None).await.is_err(), "no relay-allowed dial");
        host.shutdown().await;
        assert!(session.reconnect(Some(false)).await.is_err(), "no compliant connection could be made");
        assert!(session.slot.member().is_none(), "nothing to use");
        let base = session.base_url();
        let res = http_get(port_of(&base), &format!("/{}/x", secret_of(&base)), "").await;
        assert!(res.starts_with("HTTP/1.1 502"), "nothing forwarded: {res}");
        session.disconnect().await;
    }

    /// Review: members still draining after a swap are closed by `disconnect`, not left for the grace.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_disconnect_closes_draining_members_at_once() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let old = session.slot.member().unwrap();
        session.reconnect(None).await.unwrap();
        assert_eq!(session.slot.lock().draining.len(), 1);
        assert_ne!(old.path().await.kind, skwod_net::PathKind::None, "still draining (grace)");
        session.disconnect().await;
        assert_eq!(old.path().await.kind, skwod_net::PathKind::None, "closed by disconnect");
        assert!(session.slot.lock().draining.is_empty());
        host.shutdown().await;
    }

    /// Build 51 (C): a listener the OS took away is replaced on the same port under a NEW
    /// secret (the session carried over under a new credential) — and requests work again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reclaimed_listener_comes_back_on_the_same_port() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(EchoAuth)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        let old_credential = session.sign_in("tok".into()).await.unwrap();
        assert_eq!(session.clone().ensure_front().await, P2pFrontState { relistened: false, failed: false, base_url: base.clone(), credential: None });
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(!session.check(2_000).await.proxy_ok, "the port answers nothing");
        let state = session.clone().ensure_front().await;
        assert!(state.relistened && !state.failed);
        assert_eq!(port_of(&state.base_url), port_of(&base), "the same port");
        assert_ne!(secret_of(&state.base_url), secret_of(&base), "re-keyed: a port not held throughout is never trusted with the old secret");
        assert!(skwod_sync::client::is_retired_base(&base));
        let fresh = state.credential.expect("the signed-in session carried over under a new credential");
        assert_eq!(skwod_sync::client::front_token_for(&secret_of(&state.base_url), &old_credential), None);
        let res = http_get(port_of(&state.base_url), &format!("/{}/x", secret_of(&state.base_url)), &format!("authorization: Bearer {fresh}\r\n")).await;
        assert!(res.ends_with("Bearer tok"), "{res}");
        assert_eq!(session.proxy.livekit_url(), format!("ws://127.0.0.1:{}/{}/lk", port_of(&state.base_url), secret_of(&state.base_url)), "one snapshot");
        assert!(session.check(2_000).await.proxy_ok);
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: when no port can be had, the front is unverified (forwards nothing) and its URL
    /// retired; it says Failed, never Alive.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_relisten_forwards_nothing_and_retires_the_url() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        // The listener is gone (refused) and no port can be had.
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        session.proxy.fail_binds_for_test(true);
        let state = session.clone().ensure_front().await;
        assert!(state.failed && !state.relistened);
        assert!(!session.proxy.is_verified() && session.proxy.must_rekey(), "distrusted until a re-listen succeeds");
        assert!(skwod_sync::client::is_retired_base(&base));
        assert!(skwod_sync::ApiClient::new(base.clone()).get("/api/x").await.is_err(), "nothing sent to it");
        // A later attempt that can bind recovers (not stranded), never reporting the old URL healthy.
        session.proxy.fail_binds_for_test(false);
        let state = session.clone().ensure_front().await;
        assert!(state.relistened && !state.failed && state.base_url != base);
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: a sign-out and a re-key racing never end with the session armed again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_rekey_never_undoes_a_sign_out() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let _ = session.sign_in("tok".into()).await.unwrap();
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (a, b) = (session.clone(), session.clone());
        let rekey = tokio::spawn(async move { a.clone().ensure_front().await });
        let out = tokio::spawn(async move { b.clear_token().await });
        let state = rekey.await.unwrap();
        out.await.unwrap();
        assert_eq!(skwod_sync::client::front_current_token(&session.proxy.secret()), None, "signed out, whichever ran first");
        if state.relistened && state.credential.is_some() {
            assert_eq!(skwod_sync::client::front_token_for(&session.proxy.secret(), state.credential.as_deref().unwrap()), None);
        }
        // And sequentially: signed out, then re-keyed → no credential.
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let state = session.clone().ensure_front().await;
        assert!(state.relistened && state.credential.is_none(), "a re-key after sign-out yields no credential");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: a port that stays silent to every challenge (an impostor's effect) is UNVERIFIED —
    /// nothing is forwarded or injected meanwhile — and the front listens again (a new port:
    /// the old listener was not released), after which it forwards again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_silent_port_is_unverified_then_relistened_and_forwards_nothing_meanwhile() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(EchoAuth)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        let credential = session.sign_in("tok".into()).await.unwrap();
        session.proxy.mute_challenges_for_test(true);
        assert!(!session.check(3_000).await.proxy_ok, "silent is not ours");
        // While ensure_front decides, the front is unverified and forwards nothing.
        let (s2, b2, c2) = (session.clone(), base.clone(), credential.clone());
        let deciding = tokio::spawn(async move { s2.clone().ensure_front().await });
        // After the first unanswered challenge (2 s), and before the second ends (4 s more).
        tokio::time::sleep(std::time::Duration::from_millis(2_600)).await;
        let res = http_get(port_of(&b2), &format!("/{}/api/x", secret_of(&b2)), &format!("authorization: Bearer {c2}\r\n")).await;
        assert!(res.starts_with("HTTP/1.1 503") && !res.contains("tok"), "nothing forwarded or injected while unverified: {res}");
        let state = deciding.await.unwrap();
        assert!(state.relistened && !state.failed);
        // Still silent under the new secret too: not published in place — moved to a fresh port.
        assert_ne!(port_of(&state.base_url), port_of(&base), "an in-place re-key is published only once proved");
        assert_ne!(secret_of(&state.base_url), secret_of(&base));
        session.proxy.mute_challenges_for_test(false);
        assert!(session.proxy.is_verified());
        let fresh = state.credential.expect("a new credential");
        let res = http_get(port_of(&state.base_url), &format!("/{}/api/x", secret_of(&state.base_url)), &format!("authorization: Bearer {fresh}\r\n")).await;
        assert!(res.ends_with("Bearer tok"), "{res}");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: after a move, a request built for the old URL is refused and the old credential
    /// maps to nothing; the session continues under the new credential.
    #[tokio::test(flavor = "multi_thread")]
    async fn after_a_move_the_old_url_and_credential_are_dead() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(EchoAuth)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let old_base = session.base_url();
        let old_credential = session.sign_in("tok".into()).await.unwrap();
        let old_client = skwod_sync::ApiClient::new(old_base.clone()).with_token(old_credential.clone());
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let squatter = std::net::TcpListener::bind(("127.0.0.1", port_of(&old_base))).unwrap();
        let state = session.clone().ensure_front().await;
        assert_ne!(secret_of(&state.base_url), secret_of(&old_base), "a new secret too");
        let new_credential = state.credential.clone().expect("a new credential for the session");
        assert!(!is_front_base(old_base.clone()));
        assert!(skwod_sync::client::is_retired_base(&old_base));
        assert!(old_client.get("/api/x").await.is_err(), "a request built for the old URL is refused");
        assert_eq!(skwod_sync::client::front_token_for(&secret_of(&state.base_url), &old_credential), None, "the old credential maps to nothing");
        let res = http_get(port_of(&state.base_url), &format!("/{}/api/x", secret_of(&state.base_url)), &format!("authorization: Bearer {new_credential}\r\n")).await;
        assert!(res.ends_with("Bearer tok"), "{res}");
        drop(squatter);
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review (H2): the core's API requests to a front go over the member connection, never the
    /// loopback port — a log-in works with the front's listener GONE; and a SUSPECT front gets
    /// nothing at all (pre-auth included) until `ensure_front` proves it ours.
    #[tokio::test(flavor = "multi_thread")]
    async fn core_requests_bypass_loopback_and_a_suspect_front_gets_nothing() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(EchoAuth)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // EchoAuth answers 200 with a non-JSON body: a Shape error means the HOST answered.
        let r = skwod_sync::ApiClient::new(base.clone()).post("/api/auth/login", serde_json::json!({"username": "u", "password": "p"})).await;
        assert!(matches!(r, Err(skwod_sync::ClientError::Shape)), "reached the host without the loopback port: {r:?}");
        session.suspend();
        assert!(skwod_sync::client::is_front_suspect(&base));
        let r = skwod_sync::ApiClient::new(base.clone()).post("/api/auth/login", serde_json::json!({})).await;
        assert!(matches!(r, Err(skwod_sync::ClientError::Transport(_))), "suspect: nothing sent: {r:?}");
        let state = session.clone().ensure_front().await;
        assert!(state.relistened, "the listener was gone: re-listened");
        assert!(!skwod_sync::client::is_front_suspect(&state.base_url), "a fresh front is trusted");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Counts the voice bearers that reach the host.
    struct CountVoice(Arc<std::sync::atomic::AtomicUsize>);
    impl HostBackend for CountVoice {
        fn serve_http(&self, peer: EndpointId, relayed: bool, io: BiStream) -> Fut<()> { Ok200.serve_http(peer, relayed, io) }
        fn authorize_voice(&self, _bearer: String) -> Fut<bool> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { false })
        }
        fn authorize_room(&self, _b: String, _r: String, _i: String) -> Fut<bool> { Box::pin(async { false }) }
        fn livekit(&self) -> Fut<Option<LiveKitTarget>> { Box::pin(async { None }) }
    }

    /// A member that may use relays, under a gate of its own.
    fn relayed(gate: &Arc<skwod_net::RelayGate>) -> NetConfig {
        let mut cfg = local(NetConfig::member());
        cfg.public_fallback = true;
        cfg.relay_gate = gate.clone();
        cfg
    }

    /// Review: relays turned off while a reconnect's dial has COMPLETED but its voice start has
    /// not run: that member is closed before `off` returns, and no bearer reaches the host.
    /// Without the opt-out the same reconnect does send it (the control).
    #[tokio::test(flavor = "multi_thread")]
    async fn relays_off_closes_a_dialed_member_that_is_not_in_use_yet_and_sends_no_bearer() {
        use std::sync::atomic::Ordering::SeqCst;
        for opt_out in [true, false] {
            let bearers = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(CountVoice(bearers.clone()))).await.unwrap();
            let gate = skwod_net::RelayGate::new(true);
            gate.record_for_test();
            let session = connect_with(&relayed(&gate), host.loopback_addr()).await.unwrap();
            session.sign_in("tok".into()).await.unwrap();
            *session.slot.voice_bearer.lock().unwrap() = Some("tok".into());
            let (arrived, go) = (Arc::new(tokio::sync::Notify::new()), Arc::new(tokio::sync::Notify::new()));
            *session.slot.before_voice.lock().unwrap() = Some((arrived.clone(), go.clone()));
            let s = session.clone();
            let reconnect = tokio::spawn(async move { s.reconnect(None).await });
            tokio::time::timeout(std::time::Duration::from_secs(10), arrived.notified()).await.expect("dialed");
            assert_eq!(gate.open_for_test(), (2, 2), "the old one and the new one");
            if opt_out {
                assert!(gate.off(RELAYS_OFF_BOUND).await);
                assert_eq!(gate.open_for_test(), (0, 2));
            }
            go.notify_one();
            assert_eq!(reconnect.await.unwrap().is_err(), opt_out);
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            assert_eq!(bearers.load(SeqCst) == 0, opt_out, "the bearer reaches the host only without the opt-out");
            session.disconnect().await;
            host.shutdown().await;
        }
    }

    /// Review: an unfinished close is never taken for done, and nothing relay-allowed is dialed
    /// meanwhile; once it finishes, off is confirmed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_whose_close_is_stalled_makes_off_fail() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        for gone in ["kept", "disconnected", "dropped"] {
            let gate = skwod_net::RelayGate::new(true);
            let session = connect_with(&relayed(&gate), host.loopback_addr()).await.unwrap();
            let hold = session.slot.member().unwrap().hold_close_for_test();
            let mut session = Some(session);
            match gone {
                "disconnected" => session.as_ref().unwrap().disconnect().await,
                "dropped" => session = None,
                _ => {}
            }
            for _ in 0..2 { assert!(!gate.off(std::time::Duration::from_millis(400)).await, "{gone}"); }
            if let Some(s) = &session { assert!(s.reconnect(None).await.is_err(), "{gone}"); }
            assert!(connect_with(&relayed(&gate), host.loopback_addr()).await.is_err(), "{gone}");
            hold.notify_one();
            assert!(gate.off(RELAYS_OFF_BOUND).await, "{gone}");
            if let Some(s) = session { s.disconnect().await; }
        }
        host.shutdown().await;
    }

    /// Property: relays off, at a random moment, against everything a relay-allowed endpoint can
    /// be doing — a first dial (to a host and to nobody), a reconnect, one stalled before its
    /// voice start, draining members, a disconnect, a drop, a dial given up: once `off` says Ok,
    /// no relay-allowed endpoint is open (asked of the endpoints themselves), none is opened
    /// afterwards, and no relay-allowed dial can start.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn after_relays_off_nothing_relay_allowed_is_open_or_can_start() {
        use std::time::Duration;
        let host = Arc::new(Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap());
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = move |n: u64| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed % n };
        let (mut total, mut busy) = (0, 0);
        for round in 0..24 {
            let gate = skwod_net::RelayGate::new(true);
            gate.record_for_test();
            let cfg = relayed(&gate);
            let mut tasks = Vec::new();
            for _ in 0..4 {
                let (cfg, addr, what, a, b) = (cfg.clone(), host.loopback_addr(), rnd(8), rnd(120), rnd(120));
                tasks.push(tokio::spawn(async move {
                    let pause = |ms| tokio::time::sleep(Duration::from_millis(ms));
                    if what == 0 {   // a first dial that finds nobody, given up or not
                        let nobody = skwod_net::invite::dial_addr(SecretKey::generate().public(), None, true);
                        let _ = tokio::time::timeout(Duration::from_millis(100 + 10 * b), connect_with(&cfg, nobody)).await;
                        return None;
                    }
                    pause(a / 4).await;
                    let Ok(s) = connect_with(&cfg, addr).await else { return None };
                    s.sign_in("tok".into()).await;
                    match what {
                        1 => { let _ = s.reconnect(None).await; }   // then a draining member
                        2 => { *s.slot.voice_bearer.lock().unwrap() = Some("tok".into()); let _ = s.reconnect(None).await; }
                        3 => {   // stalled before its voice start
                            *s.slot.before_voice.lock().unwrap() = Some(Default::default());
                            let _ = tokio::time::timeout(Duration::from_secs(8), s.reconnect(None)).await;
                        }
                        4 => { let _ = tokio::time::timeout(Duration::from_millis(b), s.reconnect(None)).await; }   // given up
                        5 => { pause(b).await; s.disconnect().await; }
                        6 => { let s2 = s.clone(); let r = tokio::spawn(async move { let _ = s2.reconnect(None).await; }); pause(b).await; s.disconnect().await; let _ = r.await; }
                        _ => { pause(b).await; drop(s); return None }
                    }
                    Some(s)
                }));
            }
            tokio::time::sleep(Duration::from_millis(rnd(400))).await;
            if gate.open_for_test().0 > 0 { busy += 1; }
            assert!(gate.off(RELAYS_OFF_BOUND).await, "round {round}: confirmed");
            let (open, bound) = gate.open_for_test();
            assert_eq!((open, gate.live()), (0, 0), "round {round}: nothing open");
            assert!(connect_with(&cfg, host.loopback_addr()).await.is_err(), "round {round}: no dial can start");
            let sessions: Vec<_> = { let mut all = Vec::new(); for t in tasks { all.extend(t.await.unwrap()); } all };
            for s in &sessions { assert!(s.slot.member().is_none() && s.reconnect(None).await.is_err(), "round {round}: nothing usable"); }
            assert_eq!(gate.open_for_test(), (0, bound), "round {round}: and nothing was opened since");
            for s in sessions { s.disconnect().await; }
            total += bound;
        }
        assert!(total > 24 && busy > 12, "it was busy when relays went off: {total} endpoints, {busy} rounds");
    }

    /// Review: a call may DELAY a re-key, never keep a front trusted. Unanswered: suspect at once,
    /// nothing sent, the same URL; proved later, trusted again with no re-key. Gone (or answered
    /// as not ours): re-keyed at once, call or no call.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_proof_suspects_the_front_and_a_call_only_delays_the_re_key() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        session.proxy.mute_challenges_for_test(true);
        assert!(!session.check(6_000).await.proxy_ok);
        assert!(skwod_sync::client::is_front_suspect(&base), "a failed check suspects it at once");
        let r = skwod_sync::ApiClient::new(base.clone()).post("/api/auth/login", serde_json::json!({})).await;
        assert!(matches!(r, Err(skwod_sync::ClientError::Transport(_))), "nothing sent: {r:?}");
        let state = session.clone().ensure_front_deferring().await;
        assert!(state.failed && !state.relistened, "not proved, not re-keyed yet: {state:?}");
        assert!(skwod_sync::client::is_front_suspect(&base), "and still suspect");
        assert!(!session.proxy.is_verified(), "it forwards nothing");
        assert_eq!(session.base_url(), base);
        session.proxy.mute_challenges_for_test(false);
        let state = session.clone().ensure_front_deferring().await;
        assert!(!state.failed && !state.relistened, "answered: proved, as it was: {state:?}");
        assert!(!skwod_sync::client::is_front_suspect(&base));
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let state = session.clone().ensure_front_deferring().await;
        assert!(state.relistened, "gone: re-keyed, whatever runs through it: {state:?}");
        assert!(skwod_sync::client::is_front_suspect(&base) || skwod_sync::client::is_retired_base(&base));
        // Unanswered and NOT in a call: re-keyed.
        let base = session.base_url();
        session.proxy.mute_challenges_for_test(true);
        let state = session.clone().ensure_front().await;
        assert!(state.relistened && state.base_url != base, "{state:?}");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// A host that knows which tokens are valid: 401 for any other (and for none), counted.
    #[derive(Clone, Default)]
    struct Sessions { valid: Arc<Mutex<Vec<String>>>, refused: Arc<std::sync::atomic::AtomicUsize>, asked: Arc<std::sync::atomic::AtomicUsize> }
    impl HostBackend for Sessions {
        fn serve_http(&self, _peer: EndpointId, _relayed: bool, mut io: BiStream) -> Fut<()> {
            let me = self.clone();
            Box::pin(async move {
                use std::sync::atomic::Ordering::SeqCst;
                let mut buf = vec![0u8; 4096];
                let n = tokio::io::AsyncReadExt::read(&mut io, &mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                me.asked.fetch_add(1, SeqCst);
                let ok = me.valid.lock().unwrap().iter().any(|t| head.contains(&format!("authorization: bearer {t}\r")));
                if !ok { me.refused.fetch_add(1, SeqCst); }
                let status = if ok { "200 OK" } else { "401 Unauthorized" };
                let _ = io.write_all(format!("HTTP/1.1 {status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}").as_bytes()).await;
                let _ = io.shutdown().await;
            })
        }
        fn authorize_voice(&self, _b: String) -> Fut<bool> { Box::pin(async { false }) }
        fn authorize_room(&self, _b: String, _r: String, _i: String) -> Fut<bool> { Box::pin(async { false }) }
        fn livekit(&self) -> Fut<Option<LiveKitTarget>> { Box::pin(async { None }) }
    }

    /// Review (false sign-out): a credential that was replaced — another sign-in, a rotation the
    /// client did not see, a sign-out, a re-key — is refused HERE and never reaches the host: no
    /// 401 can come of it, so no app can read it as "the host ended your session". Over the front
    /// itself too. A request with no Authorization is still forwarded, anonymous.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_replaced_credential_is_a_local_error_and_never_a_sign_out() {
        use std::sync::atomic::Ordering::SeqCst;
        let backend = Sessions::default();
        backend.valid.lock().unwrap().extend(["one".to_string(), "two".to_string()]);
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(backend.clone())).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        let first = session.sign_in("one".into()).await.unwrap();
        let old = crate::SkwodClient::new(base.clone(), first.clone());
        assert_eq!(old.session_state().await, crate::SessionState::Valid);
        // Another sign-in, of another session, on this front.
        let second = session.sign_in("two".into()).await.unwrap();
        assert_ne!(first, second);
        assert_eq!(old.session_state().await, crate::SessionState::Unreachable, "replaced: nothing is known about its session");
        assert_eq!(crate::SkwodClient::new(base.clone(), second.clone()).session_state().await, crate::SessionState::Valid);
        // A client with no credential (a bind that had none) knows nothing either.
        assert_eq!(crate::SkwodClient::new(base.clone(), String::new()).session_state().await, crate::SessionState::Unreachable);
        assert_eq!(backend.refused.load(SeqCst), 0, "the host never saw any of it");
        // Through the port, as the app's own requests go.
        let (port, secret) = (port_of(&base), secret_of(&base));
        let res = http_get(port, &format!("/{secret}/api/auth/me"), &format!("authorization: Bearer {first}\r\n")).await;
        assert!(res.starts_with("HTTP/1.1 503") && res.to_lowercase().contains("x-skwod-front: stale-credential"), "{res}");
        assert_eq!(backend.refused.load(SeqCst), 0);
        let res = http_get(port, &format!("/{secret}/x"), "").await;
        assert!(res.starts_with("HTTP/1.1 401"), "no Authorization: forwarded, anonymous: {res}");
        // Signed out here: local too.
        session.clear_token().await;
        assert_eq!(crate::SkwodClient::new(base.clone(), second).session_state().await, crate::SessionState::Unreachable);
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: the typed error is made from the core's own refusal only. A host that says the same
    /// words (to keep an app re-binding, or to hide that it ended the session) gets a plain one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_host_cannot_say_that_a_sign_in_was_replaced() {
        struct Says;
        impl HostBackend for Says {
            fn serve_http(&self, _peer: EndpointId, _relayed: bool, mut io: BiStream) -> Fut<()> {
                Box::pin(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut io, &mut buf).await;
                    let body = format!("{{\"error\":\"{} SignInReplaced\"}}", skwod_sync::ClientError::StaleCredential);
                    let _ = io.write_all(format!("HTTP/1.1 503 X\r\nx-skwod-front: stale-credential\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
                    let _ = io.shutdown().await;
                })
            }
            fn authorize_voice(&self, _b: String) -> Fut<bool> { Box::pin(async { false }) }
            fn authorize_room(&self, _b: String, _r: String, _i: String) -> Fut<bool> { Box::pin(async { false }) }
            fn livekit(&self) -> Fut<Option<LiveKitTarget>> { Box::pin(async { None }) }
        }
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Says)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let client = crate::SkwodClient::new(session.base_url(), session.sign_in("one".into()).await.unwrap());
        let e = client.pending_rings().await.unwrap_err();
        assert!(matches!(e, CoreError::Engine { .. }), "a host's words stay words: {e:?}");
        session.sign_in("two".into()).await.unwrap();
        let e = client.pending_rings().await.unwrap_err();
        assert!(matches!(e, CoreError::SignInReplaced { .. }), "{e:?}");
        // Nor over the port: the front's own header is stripped from a host's answer.
        let base = session.base_url();
        let res = http_get(port_of(&base), &format!("/{}/x", secret_of(&base)), "").await;
        assert!(res.starts_with("HTTP/1.1 503") && !res.to_lowercase().contains("x-skwod-front"), "{res}");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: a session the HOST ended still signs out — and only after a second answer.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_the_host_ended_signs_out_once_confirmed() {
        use std::sync::atomic::Ordering::SeqCst;
        let backend = Sessions::default();
        backend.valid.lock().unwrap().push("one".into());
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(backend.clone())).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let client = crate::SkwodClient::new(session.base_url(), session.sign_in("one".into()).await.unwrap());
        assert_eq!(client.session_state().await, crate::SessionState::Valid);
        backend.valid.lock().unwrap().clear();
        assert_eq!(client.session_state().await, crate::SessionState::SignedOut);
        assert_eq!(backend.refused.load(SeqCst), 2, "asked twice before it is believed");
        // The host gone meanwhile is never a sign-out.
        host.shutdown().await;
        assert_eq!(client.session_state().await, crate::SessionState::Unreachable);
        session.disconnect().await;
    }

    /// Review (M3): closing a front forgets its token here and tells the host NOTHING — the session
    /// is still valid on it (the skwod moved; the same session continues at its new address).
    #[tokio::test(flavor = "multi_thread")]
    async fn closing_a_front_forgets_its_token_and_does_not_end_the_session() {
        use std::sync::atomic::Ordering::SeqCst;
        let backend = Sessions::default();
        backend.valid.lock().unwrap().push("one".into());
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(backend.clone())).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let secret = session.proxy.secret();
        let credential = session.sign_in("one".into()).await.unwrap();
        let before = backend.asked.load(SeqCst);
        session.disconnect().await;
        assert_eq!(skwod_sync::client::front_token_for(&secret, &credential), None, "forgotten at once, not when the last holder drops it");
        assert_eq!(backend.asked.load(SeqCst), before, "nothing was said to the host");
        // …where the session continues.
        let moved = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let client = crate::SkwodClient::new(moved.base_url(), moved.sign_in("one".into()).await.unwrap());
        assert_eq!(client.session_state().await, crate::SessionState::Valid);
        moved.disconnect().await;
        host.shutdown().await;
    }

    /// Review: signing in again with the SAME token changes nothing (what overlapping binds do);
    /// a stale credential, or another session's token, clears nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn sign_in_is_idempotent_and_only_the_match_is_cleared() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let a = session.sign_in("one".into()).await.unwrap();
        *session.slot.voice_bearer.lock().unwrap() = Some("one".into());
        let all = futures_util::future::join_all((0..8).map(|_| session.sign_in("one".into()))).await;
        assert!(all.iter().all(|c| c.as_deref() == Some(a.as_str())), "one credential for one session");
        assert!(session.slot.voice_bearer.lock().unwrap().is_some(), "and its voice is left alone");
        assert!(session.rotate_token(a.clone(), "fresh".into()).await);
        assert_eq!(session.sign_in("fresh".into()).await.as_deref(), Some(a.as_str()), "the rotated token: the same session");
        let b = session.sign_in("other".into()).await.unwrap();
        assert_ne!(a, b);
        assert!(!session.rotate_token(a.clone(), "late".into()).await, "a replaced credential rotates nothing");
        assert!(!session.clear_credential(a).await && !session.clear_session("one".into()).await);
        assert_eq!(skwod_sync::client::front_current_token(&session.proxy.secret()).as_deref(), Some("other"), "still armed");
        assert!(session.clear_session("other".into()).await);
        assert_eq!(skwod_sync::client::front_current_token(&session.proxy.secret()), None);
        let c = session.sign_in("other".into()).await.unwrap();
        assert!(session.clear_credential(c).await);
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: ending a session takes and clears the token first, then tells the host with it.
    #[tokio::test(flavor = "multi_thread")]
    async fn end_session_takes_the_token_then_tells_the_host() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        assert!(!session.end_session(true, 2_000).await, "no token: nothing to tell");
        let c = session.sign_in("tok".into()).await.unwrap();
        assert!(session.end_session(true, 3_000).await, "the host acknowledged");
        assert_eq!(skwod_sync::client::front_current_token(&session.proxy.secret()), None);
        assert!(!session.rotate_token(c, "late".into()).await, "nothing re-arms it");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review (M4): voice is authorized only with the session's own token, read in the core —
    /// none before a sign-in, none after a sign-out.
    #[tokio::test(flavor = "multi_thread")]
    async fn voice_takes_the_sessions_own_token_or_nothing() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        assert!(session.voice_url().await.is_err(), "not signed in: no voice");
        let _ = session.sign_in("tok".into()).await.unwrap();
        session.clear_token().await;
        assert!(session.voice_url().await.is_err(), "signed out: no voice");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review (M3): closing a member never waits behind a dial in progress.
    #[tokio::test(flavor = "multi_thread")]
    async fn closing_a_member_does_not_wait_for_a_dial() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let member = session.slot.member().unwrap();
        member.connection().await.unwrap().close(0u32.into(), b"test");
        host.shutdown().await;
        let dialing = { let m = member.clone(); tokio::spawn(async move { m.connection().await }) };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(4), member.close()).await.expect("close is not held by the dial");
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        assert!(tokio::time::timeout(std::time::Duration::from_secs(2), dialing).await.expect("the dial stopped").unwrap().is_err());
        session.disconnect().await;
    }

    /// Review: a suspend while ensure_front waits for the auth lock is not cleared by it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_suspend_while_ensure_front_waits_stays_suspect() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let held = session.auth.lock().await;
        let s2 = session.clone();
        let queued = tokio::spawn(async move { s2.ensure_front().await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        session.suspend();
        drop(held);
        let state = queued.await.unwrap();
        assert!(skwod_sync::client::is_front_suspect(&state.base_url), "suspended after it was called: still suspect");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: a suspicion raised while an in-place re-key is deciding is not cleared by it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_suspend_during_a_rekey_stays_suspect() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        session.proxy.mute_challenges_for_test(true);
        let s2 = session.clone();
        let deciding = tokio::spawn(async move { s2.ensure_front().await });
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        session.suspend();
        session.proxy.mute_challenges_for_test(false);
        let state = deciding.await.unwrap();
        assert!(skwod_sync::client::is_front_suspect(&state.base_url), "suspected while it decided: still suspect, whatever it decided");
        let state = session.clone().ensure_front().await;
        assert!(!skwod_sync::client::is_front_suspect(&state.base_url), "a later proof clears it");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: when the bind fails after the secret changed, the session follows to the current
    /// secret — still suspect — and logout still reaches the host and clears the token.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_bind_after_the_swap_keeps_the_session_reachable_for_logout() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let _ = session.sign_in("tok".into()).await.unwrap();
        session.proxy.mute_challenges_for_test(true);
        session.proxy.fail_binds_for_test(true);
        let state = session.clone().ensure_front().await;
        assert!(state.failed);
        assert_eq!(state.base_url, session.base_url(), "the current URL");
        assert!(skwod_sync::client::is_front_suspect(&state.base_url));
        assert_eq!(skwod_sync::client::front_current_token(&session.proxy.secret()).as_deref(), Some("tok"), "the session followed the secret");
        assert!(session.logout(3_000).await, "logout reaches the host");
        assert_eq!(skwod_sync::client::front_current_token(&session.proxy.secret()), None);
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Review: a caller that stops waiting mid-way leaves a consistent state (the work finishes).
    #[tokio::test(flavor = "multi_thread")]
    async fn cancelling_ensure_front_leaves_a_consistent_state() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let _ = session.sign_in("tok".into()).await.unwrap();
        session.proxy.drop_listener_for_test();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let s2 = session.clone();
        let waiting = tokio::spawn(async move { s2.ensure_front().await });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        waiting.abort();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let base = session.base_url();
        assert!(is_front_base(base.clone()), "the current URL is a registered front");
        assert!(session_for(&base).is_some(), "found under its current URL");
        assert_eq!(skwod_sync::client::front_current_token(&session.proxy.secret()).as_deref(), Some("tok"), "the session followed");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Echoes the Authorization the host received.
    struct EchoAuth;
    impl HostBackend for EchoAuth {
        fn serve_http(&self, _peer: EndpointId, _relayed: bool, mut io: BiStream) -> Fut<()> {
            Box::pin(async move {
                let mut buf = vec![0u8; 8192];
                let n = tokio::io::AsyncReadExt::read(&mut io, &mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let auth = head.lines().find_map(|l| l.to_lowercase().strip_prefix("authorization: ").map(|_| l[15..].trim().to_string())).unwrap_or_else(|| "none".into());
                let res = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{auth}", auth.len());
                let _ = io.write_all(res.as_bytes()).await;
                let _ = io.shutdown().await;
            })
        }
        fn authorize_voice(&self, _bearer: String) -> Fut<bool> { Box::pin(async { false }) }
        fn authorize_room(&self, _b: String, _r: String, _i: String) -> Fut<bool> { Box::pin(async { false }) }
        fn livekit(&self) -> Fut<Option<LiveKitTarget>> { Box::pin(async { None }) }
    }

    /// Build 51 (B): through a real front, end to end: the core's client sends the placeholder,
    /// the HOST receives the session token; the anonymous (sealed-sender) client reaches the host
    /// with no Authorization at all; a token a client sends itself is refused; logout goes over
    /// the member and clears the token before it returns.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_host_gets_the_token_loopback_never_does_and_sealed_sender_stays_anonymous() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(EchoAuth)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        assert!(is_front_base(base.clone()));
        let credential = session.sign_in("s3ss10n".into()).await.unwrap();
        let body = |r: &str| r.rsplit("\r\n\r\n").next().unwrap_or("").to_string();
        let path = format!("/{}/api/x", secret_of(&base));
        let port = port_of(&base);
        let via = |h: String| { let p = path.clone(); async move { http_get(port, &p, &h).await } };
        assert_eq!(body(&via(format!("authorization: Bearer {credential}\r\n")).await), "Bearer s3ss10n", "the credential becomes the token");
        assert_eq!(body(&via(String::new()).await), "none", "no Authorization: none injected (sealed sender)");
        let refused = |r: String| r.starts_with("HTTP/1.1 503") && r.to_lowercase().contains("x-skwod-front: stale-credential");
        assert!(refused(via("authorization: Bearer stolen\r\n".into()).await), "a client's own token: refused here, never sent on (nor anonymously)");
        *session.slot.voice_bearer.lock().unwrap() = Some("s3ss10n".into());
        assert!(session.logout(3_000).await, "logout reached the host over the member");
        assert_eq!(skwod_sync::client::front_current_token(&secret_of(&base)), None, "cleared before logout returned");
        assert!(session.slot.voice_bearer.lock().unwrap().is_none(), "the voice bearer goes with it");
        assert!(refused(via(format!("authorization: Bearer {credential}\r\n")).await), "signed out: refused here, never sent on");
        assert!(!session.rotate_token(credential.clone(), "late".into()).await, "no set after sign-out");
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Sealed sender, end to end over a real front: a deposit made by the sealed client of a
    /// signed-in session reaches the host with NO Authorization, whatever becomes of the session's
    /// own credential (current, replaced, signed out) — refusing a dead credential refuses only
    /// requests that present one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sealed_deposit_never_carries_a_credential() {
        struct Heads(Arc<Mutex<Vec<String>>>);
        impl HostBackend for Heads {
            fn serve_http(&self, _peer: EndpointId, _relayed: bool, mut io: BiStream) -> Fut<()> {
                let heads = self.0.clone();
                Box::pin(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = tokio::io::AsyncReadExt::read(&mut io, &mut buf).await.unwrap_or(0);
                    heads.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_lowercase());
                    let _ = io.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await;
                    let _ = io.shutdown().await;
                })
            }
            fn authorize_voice(&self, _b: String) -> Fut<bool> { Box::pin(async { false }) }
            fn authorize_room(&self, _b: String, _r: String, _i: String) -> Fut<bool> { Box::pin(async { false }) }
            fn livekit(&self) -> Fut<Option<LiveKitTarget>> { Box::pin(async { None }) }
        }
        let heads = Arc::new(Mutex::new(Vec::new()));
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Heads(heads.clone()))).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let credential = session.sign_in("s3ss10n".into()).await.unwrap();
        let api = skwod_sync::ApiClient::new(session.base_url()).with_token(credential);
        let sealed = api.anonymous();
        let deposit = || sealed.post("/api/e2ee/sealed/send", serde_json::json!({ "messages": [] }));
        api.get("/api/auth/me").await.unwrap();
        deposit().await.unwrap();
        session.sign_in("another".into()).await.unwrap();
        assert!(matches!(api.get("/api/auth/me").await, Err(skwod_sync::ClientError::StaleCredential)));
        deposit().await.unwrap();
        session.clear_token().await;
        deposit().await.unwrap();
        let heads = heads.lock().unwrap().clone();
        assert!(heads[0].contains("authorization: bearer s3ss10n"), "the control: the session's own request carries it");
        let deposits: Vec<_> = heads.iter().filter(|h| h.starts_with("post /api/e2ee/sealed/send")).collect();
        assert_eq!(deposits.len(), 3);
        for h in deposits { assert!(!h.contains("authorization") && !h.contains("s3ss10n") && !h.contains("front-") && !h.contains("x-skwod-build"), "{h}"); }
        session.disconnect().await;
        host.shutdown().await;
    }

    /// And nothing else deposits: the engine only through its sealed client; no app code at all.
    #[test]
    fn only_the_sealed_client_deposits() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let engine = std::fs::read_to_string(root.join("core/skwod-sync/src/engine.rs")).unwrap();
        let sends: Vec<_> = engine.match_indices(".post(\"/api/e2ee/sealed/send\"").collect();
        assert!(!sends.is_empty());
        for (i, _) in sends { assert!(engine[..i].ends_with("self.sealed_api"), "a deposit that is not the sealed client's"); }
        fn scan(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>, seen: &mut usize) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() { scan(&p, found, seen) }
                else if p.extension().is_some_and(|x| x == "swift" || x == "kt") {
                    *seen += 1;
                    if std::fs::read_to_string(&p).unwrap_or_default().contains("sealed/send") { found.push(p) }
                }
            }
        }
        let (mut found, mut seen) = (Vec::new(), 0);
        for d in ["apps/apple/Sources", "apps/apple/NotificationService", "apps/android/app/src/main/java/io/skwod/app"] { scan(&root.join(d), &mut found, &mut seen); }
        assert!(seen > 100 && found.is_empty(), "{seen} files, {found:?}");
    }

    /// Review: relays turned OFF closes the members still draining too, not only the current one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relay_opt_out_closes_the_draining_members() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let gate = skwod_net::RelayGate::new(true);
        let session = connect_with(&relayed(&gate), host.loopback_addr()).await.unwrap();
        let first = session.slot.member().unwrap();
        session.reconnect(None).await.unwrap();
        assert_eq!(session.slot.lock().draining.len(), 1);
        assert!(gate.off(RELAYS_OFF_BOUND).await);
        assert!(first.is_closed(), "the draining member closed at once");
        assert!(session.slot.member().is_none());
        session.disconnect().await;
        host.shutdown().await;
    }

    /// Build 51: a session the app lets go is really gone — its watcher (`wait_proxy_closed`,
    /// which holds the session the way the FFI does) is woken by `disconnect` — and its URL is
    /// refused from the moment it is retired.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_released_session_is_dropped_and_its_url_refused() {
        let host = Host::start(&local(NetConfig::host(SecretKey::generate())), Arc::new(Ok200)).await.unwrap();
        let session = connect_with(&local(NetConfig::member()), host.loopback_addr()).await.unwrap();
        let base = session.base_url();
        assert!(session.check(3_000).await == P2pHealth { proxy_ok: true, upstream_ok: true });
        let weak = Arc::downgrade(&session);
        let waiter = { let s = session.clone(); tokio::spawn(async move { s.wait_proxy_closed().await }) };
        session.retire();
        assert!(skwod_sync::client::is_retired_base(&base), "refused at once, port still held");
        assert_eq!(session.proxy.challenge(std::time::Duration::from_secs(2)).await, skwod_net::proxy::Challenge::Ours, "the port is still ours");
        session.disconnect().await;
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter).await.expect("the watcher is woken").unwrap();
        drop(session);
        assert!(weak.upgrade().is_none(), "nothing keeps a released session alive");
        host.shutdown().await;
    }
}
