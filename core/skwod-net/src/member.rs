//! Member side: dial the host by key, keep one connection alive, open streams on it.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::Mutex;

use crate::wire::{self, BiStream};
use crate::relay_gate::OwnedEndpoint;
use crate::{NetConfig, NetError};

/// The WHOLE first connect — binding the endpoint, the DHT / n0 lookup, hole punching, the
/// admission proof — has this long. A reachable host answers in 1–3 s (relay or direct); past
/// this the app shows "couldn't reach your host" with Try again, instead of spinning forever.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// The admission proof is best effort; it never holds a connect longer than this.
const PROOF_TIMEOUT: Duration = Duration::from_secs(5);
/// Closing a failed endpoint is bounded too, and done off the caller's path.
const RETRY_PAUSE: Duration = Duration::from_millis(750);
/// The voice hand-shake with the host never takes longer than this.
const VOICE_HELLO_TIMEOUT: Duration = Duration::from_secs(8);

/// A new signaling stream asks the host again where its LiveKit is, unless it was asked this
/// recently: a LiveKit that came back on another port must not leave a live connection's
/// forwarder on the old one.
const VOICE_ANSWER_FRESH: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// UDP straight to the host (LAN, public IP, port mapping, or a punched hole).
    Direct,
    /// Via a relay (only possible with `public_fallback` or a custom relay). The relay sees both
    /// IPs and ciphertext sizes/timing — never content.
    Relay,
    /// Not connected.
    None,
}

impl PathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PathKind::Direct => "direct",
            PathKind::Relay => "relay",
            PathKind::None => "none",
        }
    }
}

/// What the app may show ("direct · 14 ms"). Deliberately carries no address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathInfo {
    pub kind: PathKind,
    pub rtt_ms: u32,
}

pub(crate) fn path_info(conn: &Connection) -> PathInfo {
    if conn.close_reason().is_some() {
        return PathInfo { kind: PathKind::None, rtt_ms: 0 };
    }
    let paths = conn.paths();
    let Some(p) = paths.iter().find(|p| p.is_selected()).or_else(|| paths.iter().next()) else {
        return PathInfo { kind: PathKind::None, rtt_ms: 0 };
    };
    PathInfo {
        kind: if p.is_relay() { PathKind::Relay } else { PathKind::Direct },
        rtt_ms: p.rtt().as_millis().min(u32::MAX as u128) as u32,
    }
}

/// Where the selected path goes, if it is not a relay's.
fn direct_addr(conn: &Connection) -> Option<std::net::SocketAddr> {
    if conn.close_reason().is_some() { return None }
    conn.paths().iter().find(|p| p.is_selected()).and_then(|p| match p.remote_addr() {
        iroh::TransportAddr::Ip(addr) => Some(*addr),
        _ => None,
    })
}

/// Log direct↔relay transitions for one connection — locally, kind + RTT only, never an address.
/// With `routes`: what it runs over directly is remembered (from this sample; nothing waits for it).
pub(crate) async fn log_path_changes(conn: Connection, peer: &'static str, routes: Option<(crate::Routes, bool)>) {
    let mut last = PathKind::None;
    loop {
        if let (Some((routes, relays)), Some(addr)) = (&routes, direct_addr(&conn)) { routes.saw(addr, *relays); }
        let info = path_info(&conn);
        if info.kind != last {
            tracing::info!(peer, path = info.kind.as_str(), rtt_ms = info.rtt_ms, "p2p path");
            last = info.kind;
        }
        if info.kind == PathKind::None && conn.close_reason().is_some() {
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
            _ = conn.closed() => {}
        }
    }
}

#[derive(Default)]
struct VoiceState {
    bearer: Option<String>,
    /// `stable_id` of the connection the forwarder is attached to.
    conn_id: Option<usize>,
    udp_port: u16,
    /// When the host last said which port that is.
    asked: Option<tokio::time::Instant>,
    task: Option<tokio::task::JoinHandle<()>>,
}

pub struct Member {
    /// The endpoint, its lease (with relays) and its close (`relay_gate.rs`).
    owned: OwnedEndpoint,
    host: EndpointAddr,
    conn: Mutex<Option<Connection>>,
    /// The connection, to close it without any lock.
    live: std::sync::Mutex<Option<Connection>>,
    /// Where it is reached directly, and whether this member may use relays.
    routes: (crate::Routes, bool),
    voice: Mutex<VoiceState>,
    voice_stats: Arc<crate::voice::VoiceStats>,
    /// LAN listener (`lan.rs`), alive as long as the member so re-dials can use it.
    _lan: Option<swarm_discovery::DropGuard>,
}

/// The loopback UDP port the host asks us to bind for media (it is the port in LiveKit's
/// `127.0.0.1` ICE candidate, so it has to be the host's number) — but only within the
/// unprivileged, non-well-known range. The host does not get to make this device bind an
/// arbitrary port: anything below 1024, or out of range, is refused and voice is unavailable.
fn voice_port(port: u64) -> Option<u16> {
    u16::try_from(port).ok().filter(|p| *p >= MIN_VOICE_PORT)
}

/// Lowest loopback UDP port a host may ask a member to bind (see [`voice_port`]).
const MIN_VOICE_PORT: u16 = 1024;

impl Member {
    /// Bind a member endpoint and establish the first connection to `host`. With
    /// [`crate::Discovery::Dht`], `host` can be just `EndpointAddr::new(node_id)`.
    pub async fn connect(cfg: &NetConfig, host: impl Into<EndpointAddr>) -> Result<Arc<Self>, NetError> {
        Self::connect_within(cfg, host, CONNECT_TIMEOUT).await
    }

    /// [`Member::connect`] with an explicit overall budget. Every await in here is under it:
    /// nothing can turn an unreachable host into an endless "Finding your host…".
    pub async fn connect_within(cfg: &NetConfig, host: impl Into<EndpointAddr>, budget: Duration) -> Result<Arc<Self>, NetError> {
        let deadline = tokio::time::Instant::now() + budget;
        let owned = match tokio::time::timeout_at(deadline, OwnedEndpoint::bind(cfg)).await {
            Ok(r) => r?,
            Err(_) => return Err(NetError::Unreachable("timed out".into())),
        };
        let host = host.into();
        let lan = match (cfg.plan().mdns_lookup, cfg.lan_key) {
            (true, Some(key)) => crate::lan::listen(&owned.endpoint, key, host.id),
            _ => None,
        };
        let me = Arc::new(Self {
            owned, host, conn: Mutex::new(None), live: std::sync::Mutex::new(None),
            routes: (cfg.routes.clone(), cfg.public_fallback),
            voice: Mutex::default(), voice_stats: Arc::default(), _lan: lan,
        });
        // Remembered addresses are for the first dial of a fresh endpoint, without relays.
        let to = if cfg.public_fallback { me.host.clone() } else { cfg.routes.onto(me.host.clone()) };
        if let Err(e) = me.connection_to(&to, deadline).await {
            // Off the caller's path: a close stuck behind a relay or DNS task must not keep the
            // login screen spinning (and is never given up).
            me.start_close();
            return Err(e);
        }
        Ok(me)
    }

    pub fn host_id(&self) -> EndpointId {
        self.host.id
    }

    /// This member's own node id (a throwaway key unless one was configured).
    pub fn id(&self) -> EndpointId {
        self.owned.endpoint.id()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.owned.endpoint
    }

    /// The live connection, re-dialing if the previous one died (network change, host restart).
    pub async fn connection(&self) -> Result<Connection, NetError> {
        self.connection_until(tokio::time::Instant::now() + CONNECT_TIMEOUT).await
    }

    async fn connection_until(&self, deadline: tokio::time::Instant) -> Result<Connection, NetError> {
        self.connection_to(&self.host, deadline).await
    }

    async fn connection_to(&self, to: &EndpointAddr, deadline: tokio::time::Instant) -> Result<Connection, NetError> {
        let closed = || NetError::Unreachable("closed".into());
        if self.is_closing() { return Err(closed()); }
        let mut cancel = self.owned.closing.subscribe();
        let mut slot = tokio::select! {
            s = self.conn.lock() => s,
            _ = cancel.wait_for(|c| *c) => return Err(closed()),
        };
        if let Some(c) = slot.as_ref() {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        *slot = None;
        // Keep trying until the deadline: on a cold start the first DHT lookup can come back
        // empty simply because our own DHT client hasn't finished bootstrapping yet (iroh then
        // fails fast with "no addressing information"), and a host that just started may not
        // have published yet.
        let conn = loop {
            let dial = self.owned.endpoint.connect(to.clone(), crate::ALPN);
            let error = tokio::select! {
                r = tokio::time::timeout_at(deadline, dial) => match r {
                    Ok(Ok(c)) => break c,
                    Ok(Err(e)) => e.to_string(),
                    Err(_) => return Err(NetError::Unreachable("timed out".into())),
                },
                _ = cancel.wait_for(|c| *c) => return Err(closed()),
            };
            if tokio::time::Instant::now() + RETRY_PAUSE >= deadline {
                return Err(NetError::Unreachable(error));
            }
            tokio::time::sleep(RETRY_PAUSE).await;
        };
        tokio::spawn(log_path_changes(conn.clone(), "host", Some(self.routes.clone())));
        // Pay for the slot (`host.rs`, "Admission"): a small proof of work bound to this host,
        // this endpoint's node id and this moment, as the connection's FIRST stream — before
        // any request can race it. A host that is being flooded admits only connections that
        // bring one; an idle host does not need it, and an older host ignores the stream.
        // Best-effort: a failure here shows up as the first request failing, like any other.
        let (host, me, proof_conn) = (*self.host.id.as_bytes(), *self.owned.endpoint.id().as_bytes(), conn.clone());
        let proof = async move {
            let stamp = tokio::task::spawn_blocking(move || crate::pow::solve_for(crate::pow::Purpose::Connection, &host, &me, crate::pow::current_window(), crate::pow::CONN_POW_BITS)).await;
            if let (Ok(stamp), Ok((mut send, _recv))) = (stamp, proof_conn.open_bi().await) {
                let mut frame = vec![wire::KIND_PROOF];
                frame.extend_from_slice(stamp.as_bytes());
                let _ = send.write_all(&frame).await;
                let _ = send.finish();
            }
        };
        // Never past the caller's deadline either: the apps' backstop timer sits just after it.
        let proof_deadline = deadline.min(tokio::time::Instant::now() + PROOF_TIMEOUT);
        let _ = tokio::time::timeout_at(proof_deadline, proof).await;
        if self.is_closing() { conn.close(0u32.into(), b"bye"); return Err(closed()); }
        *slot = Some(conn.clone());
        *self.live.lock().unwrap_or_else(|e| e.into_inner()) = Some(conn.clone());
        Ok(conn)
    }

    async fn open_raw(&self, kind: u8) -> Result<(Connection, BiStream), NetError> {
        let mut last = None;
        // One retry: the cached connection may have died since we last looked.
        for _ in 0..2 {
            let conn = self.connection().await?;
            match conn.open_bi().await {
                Ok((mut send, recv)) => {
                    send.write_all(&[kind]).await.map_err(|e| NetError::Io(e.to_string()))?;
                    return Ok((conn, wire::join(send, recv)));
                }
                Err(e) => {
                    last = Some(e.to_string());
                    *self.conn.lock().await = None;
                }
            }
        }
        Err(NetError::Unreachable(last.unwrap_or_default()))
    }

    /// A stream speaking HTTP/1.1 to the skwod API.
    pub async fn open_http(&self) -> Result<BiStream, NetError> {
        Ok(self.open_raw(wire::KIND_HTTP).await?.1)
    }

    /// A stream speaking HTTP/1.1 to the host's LiveKit signaling port. Requires a prior
    /// [`Member::voice_start`]; re-authorizes transparently after a reconnect.
    pub async fn open_livekit(&self) -> Result<BiStream, NetError> {
        let conn = self.connection().await?;
        self.ensure_voice(&conn).await?;
        self.refresh_voice(&conn).await;
        Ok(self.open_raw(wire::KIND_LIVEKIT).await?.1)
    }

    /// Authorize this connection for voice with a session `bearer` token and start the loopback
    /// media forwarder. Returns the UDP port it listens on (the one LiveKit's ICE candidate names).
    pub async fn voice_start(&self, bearer: &str) -> Result<u16, NetError> {
        {
            // Always re-authorize: the host may have revoked the previous grant (logout, expiry).
            let mut v = self.voice.lock().await;
            v.bearer = Some(bearer.to_string());
            v.asked = None;
        }
        let conn = self.connection().await?;
        self.ensure_voice(&conn).await
    }

    /// Ask the host again which port its LiveKit is on (best effort: a refusal here changes
    /// nothing — the host decides about the stream itself).
    async fn refresh_voice(&self, conn: &Connection) {
        {
            let mut v = self.voice.lock().await;
            if v.asked.is_some_and(|t| t.elapsed() < VOICE_ANSWER_FRESH) {
                return;
            }
            v.asked = None;
        }
        if self.ensure_voice(conn).await.is_err() {
            self.voice.lock().await.asked.get_or_insert_with(tokio::time::Instant::now);
        }
    }

    async fn ensure_voice(&self, conn: &Connection) -> Result<u16, NetError> {
        // Bounded, and stopped by `close`: the host's answer can never hold the voice lock (and
        // so a close) indefinitely.
        let mut cancel = self.owned.closing.subscribe();
        tokio::select! {
            r = tokio::time::timeout(VOICE_HELLO_TIMEOUT, self.ensure_voice_inner(conn)) => r.unwrap_or_else(|_| Err(NetError::Unreachable("the host did not answer about voice".into()))),
            _ = cancel.wait_for(|c| *c) => Err(NetError::Unreachable("closed".into())),
        }
    }

    async fn ensure_voice_inner(&self, conn: &Connection) -> Result<u16, NetError> {
        let mut v = self.voice.lock().await;
        let forwarding = v.conn_id == Some(conn.stable_id()) && v.task.as_ref().is_some_and(|t| !t.is_finished());
        if forwarding && v.asked.is_some() {
            return Ok(v.udp_port);
        }
        let bearer = v.bearer.clone().ok_or(NetError::VoiceUnavailable)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| NetError::Unreachable(e.to_string()))?;
        let mut hello = vec![wire::KIND_VOICE_HELLO];
        hello.extend_from_slice(&(bearer.len() as u16).to_be_bytes());
        hello.extend_from_slice(bearer.as_bytes());
        // Never the bearer on a connection that is being closed (a relay opt-out, a sign-out).
        if self.is_closing() { return Err(NetError::Unreachable("closed".into())); }
        send.write_all(&hello).await.map_err(|e| NetError::Io(e.to_string()))?;
        let _ = send.finish();
        let reply = recv.read_to_end(1024).await.map_err(|e| NetError::Io(e.to_string()))?;
        let reply: serde_json::Value = serde_json::from_slice(&reply).map_err(|_| NetError::VoiceUnavailable)?;
        let port = reply["udp_port"].as_u64().filter(|_| reply["ok"] == true).and_then(voice_port).ok_or(NetError::VoiceUnavailable)?;
        v.asked = Some(tokio::time::Instant::now());
        // The same port on the same connection: the forwarder stays, and with it the flows of a
        // call in progress.
        if forwarding && v.udp_port == port {
            return Ok(port);
        }
        // Another port: bound before the old forwarder is let go (if it cannot be, the old one
        // stays). The same port on another connection: once the old one has released it.
        let old_port = v.udp_port;
        let sock = crate::voice::rebind_member(&mut v.task, old_port, port).await.map_err(|_| NetError::VoicePort)?;
        v.task = Some(crate::voice::start_member(conn.clone(), sock, self.voice_stats.clone()));
        v.conn_id = Some(conn.stable_id());
        v.udp_port = port;
        Ok(port)
    }

    /// Let go of the loopback media port: another member of this process is about to carry the
    /// call (a session that reconnects). Returns once the port is free. The grant on the host ends
    /// with the connection, or with its next check.
    pub async fn voice_release(&self) {
        let mut v = self.voice.lock().await;
        v.bearer = None; // nothing here starts it again
        if let Some(task) = v.task.take() {
            task.abort();
            let _ = task.await;
        }
        v.conn_id = None;
    }

    /// `(packets up, bytes up, packets down, bytes down)` moved by the media forwarder so far.
    pub fn voice_stats(&self) -> (u64, u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let s = &self.voice_stats;
        (s.packets_up.load(Relaxed), s.bytes_up.load(Relaxed), s.packets_down.load(Relaxed), s.bytes_down.load(Relaxed))
    }

    /// Packets from the host this device could not hand to the call ([`crate::voice::VoiceStats::undelivered`]).
    pub fn voice_undelivered(&self) -> u64 {
        self.voice_stats.undelivered.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Current path to the host: direct or relayed, and its RTT.
    pub async fn path(&self) -> PathInfo {
        // Lock-free: never waits behind a dial in progress.
        match self.live.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(c) => path_info(c),
            None => PathInfo { kind: PathKind::None, rtt_ms: 0 },
        }
    }

    /// Tell iroh the device's network changed (Android can't detect this natively).
    pub async fn network_changed(&self) {
        self.owned.endpoint.network_change().await;
    }

    /// Close: lock-free first — the flag (a dial or voice hand-shake in progress stops) and the
    /// live connection closed synchronously — then, best effort, the rest.
    pub async fn close(&self) {
        self.start_close();
        self.closed().await;
    }

    /// Start closing (a later call changes nothing): the connection goes now; the endpoint's close
    /// runs to its end in its owner's task whatever the caller does. Needs no runtime.
    pub fn start_close(&self) {
        self.owned.start_close();
        if let Some(c) = self.live.lock().unwrap_or_else(|e| e.into_inner()).take() {
            c.close(0u32.into(), b"bye");
        }
        if let Ok(mut v) = self.voice.try_lock() {
            if let Some(t) = v.task.take() { t.abort(); }
        }
        if let Ok(mut slot) = self.conn.try_lock() {
            if let Some(c) = slot.take() { c.close(0u32.into(), b"bye"); }
        }
    }

    /// Resolves when the close has finished (never before it was started).
    pub async fn closed(&self) { self.owned.closed().await }

    /// Has the close finished?
    pub fn is_closed(&self) -> bool { self.owned.is_closed() }

    /// Being closed, or not allowed any more (relays turned off): nothing new may use it.
    pub fn is_closing(&self) -> bool { self.owned.is_closing() }

    /// Tests: the close hangs until the returned handle is notified.
    #[doc(hidden)]
    pub fn hold_close_for_test(&self) -> Arc<tokio::sync::Notify> { self.owned.hold_close_for_test() }
}

impl Drop for Member {
    /// Let go without a close (a dial given up, a session dropped): closed all the same.
    fn drop(&mut self) { self.start_close(); }
}

#[cfg(test)]
mod voice_port_tests {
    use super::voice_port;

    #[test]
    fn host_cannot_make_a_member_bind_a_privileged_or_bogus_port() {
        for bad in [0u64, 53, 80, 443, 1023, 65_536, 70_000, u64::MAX] {
            assert_eq!(voice_port(bad), None, "{bad}");
        }
        assert_eq!(voice_port(1024), Some(1024));
        assert_eq!(voice_port(7882), Some(7882));
        assert_eq!(voice_port(65_535), Some(65_535));
    }
}
