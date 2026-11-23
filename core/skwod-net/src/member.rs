//! Member side: dial the host by key, keep one connection alive, open streams on it.

use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::Mutex;

use crate::wire::{self, BiStream};
use crate::{NetConfig, NetError};

/// DHT lookup + hole punching on a cold start can take a few seconds; past this we call it unreachable.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const RETRY_PAUSE: Duration = Duration::from_millis(750);

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

/// Log direct↔relay transitions for one connection — locally, kind + RTT only, never an address.
pub(crate) async fn log_path_changes(conn: Connection, peer: &'static str) {
    let mut last = PathKind::None;
    loop {
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
    task: Option<tokio::task::JoinHandle<()>>,
}

pub struct Member {
    endpoint: Endpoint,
    host: EndpointAddr,
    conn: Mutex<Option<Connection>>,
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
        let endpoint = crate::bind(cfg).await?;
        let host = host.into();
        let lan = match (cfg.plan().mdns_lookup, cfg.lan_key) {
            (true, Some(key)) => crate::lan::listen(&endpoint, key, host.id),
            _ => None,
        };
        let me = Arc::new(Self { endpoint, host, conn: Mutex::new(None), voice: Mutex::default(), voice_stats: Arc::default(), _lan: lan });
        if let Err(e) = me.connection().await {
            me.endpoint.close().await;
            return Err(e);
        }
        Ok(me)
    }

    pub fn host_id(&self) -> EndpointId {
        self.host.id
    }

    /// This member's own node id (a throwaway key unless one was configured).
    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The live connection, re-dialing if the previous one died (network change, host restart).
    pub async fn connection(&self) -> Result<Connection, NetError> {
        let mut slot = self.conn.lock().await;
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
        let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        let conn = loop {
            let dial = self.endpoint.connect(self.host.clone(), crate::ALPN);
            let error = match tokio::time::timeout_at(deadline, dial).await {
                Ok(Ok(c)) => break c,
                Ok(Err(e)) => e.to_string(),
                Err(_) => return Err(NetError::Unreachable("timed out".into())),
            };
            if tokio::time::Instant::now() + RETRY_PAUSE >= deadline {
                return Err(NetError::Unreachable(error));
            }
            tokio::time::sleep(RETRY_PAUSE).await;
        };
        tokio::spawn(log_path_changes(conn.clone(), "host"));
        // Pay for the slot (`host.rs`, "Admission"): a small proof of work bound to this host,
        // this endpoint's node id and this moment, as the connection's FIRST stream — before
        // any request can race it. A host that is being flooded admits only connections that
        // bring one; an idle host does not need it, and an older host ignores the stream.
        // Best-effort: a failure here shows up as the first request failing, like any other.
        let (host, me, proof_conn) = (*self.host.id.as_bytes(), *self.endpoint.id().as_bytes(), conn.clone());
        let stamp = tokio::task::spawn_blocking(move || crate::pow::solve_for(crate::pow::Purpose::Connection, &host, &me, crate::pow::current_window(), crate::pow::CONN_POW_BITS)).await;
        if let (Ok(stamp), Ok((mut send, _recv))) = (stamp, proof_conn.open_bi().await) {
            let mut frame = vec![wire::KIND_PROOF];
            frame.extend_from_slice(stamp.as_bytes());
            let _ = send.write_all(&frame).await;
            let _ = send.finish();
        }
        *slot = Some(conn.clone());
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
        Ok(self.open_raw(wire::KIND_LIVEKIT).await?.1)
    }

    /// Authorize this connection for voice with a session `bearer` token and start the loopback
    /// media forwarder. Returns the UDP port it listens on (the one LiveKit's ICE candidate names).
    pub async fn voice_start(&self, bearer: &str) -> Result<u16, NetError> {
        {
            // Always re-authorize: the host may have revoked the previous grant (logout, expiry).
            let mut v = self.voice.lock().await;
            v.bearer = Some(bearer.to_string());
            v.conn_id = None;
        }
        let conn = self.connection().await?;
        self.ensure_voice(&conn).await
    }

    async fn ensure_voice(&self, conn: &Connection) -> Result<u16, NetError> {
        let mut v = self.voice.lock().await;
        if v.conn_id == Some(conn.stable_id()) && v.task.as_ref().is_some_and(|t| !t.is_finished()) {
            return Ok(v.udp_port);
        }
        let bearer = v.bearer.clone().ok_or(NetError::VoiceUnavailable)?;
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| NetError::Unreachable(e.to_string()))?;
        let mut hello = vec![wire::KIND_VOICE_HELLO];
        hello.extend_from_slice(&(bearer.len() as u16).to_be_bytes());
        hello.extend_from_slice(bearer.as_bytes());
        send.write_all(&hello).await.map_err(|e| NetError::Io(e.to_string()))?;
        let _ = send.finish();
        let reply = recv.read_to_end(1024).await.map_err(|e| NetError::Io(e.to_string()))?;
        let reply: serde_json::Value = serde_json::from_slice(&reply).map_err(|_| NetError::VoiceUnavailable)?;
        let port = reply["udp_port"].as_u64().filter(|_| reply["ok"] == true).and_then(voice_port).ok_or(NetError::VoiceUnavailable)?;
        if let Some(old) = v.task.take() {
            old.abort();
            let _ = old.await; // the old forwarder must release the port before we rebind it
        }
        v.task = Some(crate::voice::start_member(conn.clone(), port, self.voice_stats.clone()).await.map_err(|e| NetError::Io(e.to_string()))?);
        v.conn_id = Some(conn.stable_id());
        v.udp_port = port;
        Ok(port)
    }

    /// `(packets up, bytes up, packets down, bytes down)` moved by the media forwarder so far.
    pub fn voice_stats(&self) -> (u64, u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let s = &self.voice_stats;
        (s.packets_up.load(Relaxed), s.bytes_up.load(Relaxed), s.packets_down.load(Relaxed), s.bytes_down.load(Relaxed))
    }

    /// Current path to the host: direct or relayed, and its RTT.
    pub async fn path(&self) -> PathInfo {
        match self.conn.lock().await.as_ref() {
            Some(c) => path_info(c),
            None => PathInfo { kind: PathKind::None, rtt_ms: 0 },
        }
    }

    /// Tell iroh the device's network changed (Android can't detect this natively).
    pub async fn network_changed(&self) {
        self.endpoint.network_change().await;
    }

    pub async fn close(&self) {
        if let Some(t) = self.voice.lock().await.task.take() {
            t.abort();
        }
        if let Some(c) = self.conn.lock().await.take() {
            c.close(0u32.into(), b"bye");
        }
        self.endpoint.close().await;
    }
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
