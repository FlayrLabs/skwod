//! The p2p front door (`docs/P2P.md`): the same axum router, served over iroh QUIC streams.
//!
//! `skwod run` keeps its TCP listener (loopback for app hosts, behind a reverse proxy for VPS
//! hosts) and ALSO accepts `skwod/1` connections addressed to this instance's node id. Each QUIC
//! bi-stream is handed to hyper in-process — there is no extra listener and no loopback hop.
//! Requests that arrive this way carry a [`P2pPeer`] extension instead of a socket address.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::extract::State;
use axum::{Extension, Json, Router};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use serde_json::{json, Value};
use skwod_net::{BiStream, EndpointId, HostBackend, Invite, LiveKitTarget, NetConfig};

use crate::auth::AuthUser;
use crate::client_key::P2pPeer;
use crate::error::ApiError;
use crate::state::AppState;

/// The instance's p2p secret key: `<data>/p2p.key`, 0600. Its public half is the skwod's address.
pub const KEY_FILE: &str = "p2p.key";

#[derive(Debug, Clone)]
pub struct P2pOptions {
    /// Allow n0's public relays + DNS when the DHT / a direct path isn't enough (default on).
    pub public_fallback: bool,
    pub port: Option<u16>,
    pub external_addrs: Vec<SocketAddr>,
    /// Opt-in: announce on the local network (mDNS, rotating keyed tag — `skwod_net::lan`) so
    /// same-LAN members connect without the DHT. Off unless the host asks for it.
    pub local_discovery: bool,
}

#[derive(Debug, Clone)]
pub struct P2pStatus {
    pub node_id: String,
    /// The same id as raw bytes (proof-of-work stamps are bound to it).
    pub node_bytes: [u8; 32],
    pub public_fallback: bool,
}

/// The host's current home relay, if it uses public fallback and the relay is one an invite may
/// name (`skwod_net::invite::is_allowed_relay`). Apps put it in share links (`&r=`) so a brand-new
/// device can dial at once, without waiting on a DHT or DNS lookup.
fn home_relay(state: &AppState, public_fallback: bool) -> Option<String> {
    if !public_fallback {
        return None;
    }
    let addr = state.p2p_endpoint.lock().expect("p2p endpoint lock").as_ref()?.addr();
    let relay = addr.relay_urls().find_map(|u| skwod_net::invite::is_allowed_relay(u.as_str()));
    relay
}

/// The LAN-discovery secret: `<data>/lan.key`, 0600, created when local discovery is first
/// turned on. Members get it in invites and from `/api/instance/p2p`; nobody else does.
pub const LAN_KEY_FILE: &str = "lan.key";

pub fn lan_key(data: &Path, create: bool) -> Option<skwod_net::lan::LanKey> {
    let path = data.join(LAN_KEY_FILE);
    if let Some(key) = std::fs::read_to_string(&path).ok().and_then(|t| skwod_net::lan::LanKey::from_hex(&t)) {
        // A key file left group/world-readable (restored from a backup, copied by hand, created
        // by an older build under a loose umask) is tightened every time it is loaded.
        restrict_to_owner(&path);
        return Some(key);
    }
    if !create {
        return None;
    }
    let key = skwod_net::lan::LanKey::generate();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(&path).and_then(|mut f| f.write_all(key.to_hex().as_bytes())).ok()?;
    Some(key)
}

/// Make a secret file readable and writable by its owner only (0600). Best-effort.
pub(crate) fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.permissions().mode() & 0o077 != 0 {
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// This instance's node id (creating the key on first use).
pub fn node_id(data: &Path) -> std::io::Result<EndpointId> {
    Ok(skwod_net::load_or_create_secret_key(&data.join(KEY_FILE))?.public())
}

/// The link a host hands out: the SHARE form, `https://skwod.io/join#<node id>[.<join code>]`.
///
/// It is a link every chat app, mail client and QR scanner turns into something tappable: on
/// a phone with Skwod it opens the app (universal link), and on one without it opens a page
/// that says where to get it. `skwod://join/…` (the app form) is neither clickable in most
/// places it gets pasted nor meaningful to a camera without the app. Everything after `#` is a
/// URL fragment, which a browser never sends to a server — skwod.io learns neither the host
/// key nor the code. The apps accept both forms.
pub fn invite_link(node: EndpointId, join_code: Option<&str>) -> String {
    invite_link_with(node, join_code, None)
}

/// …carrying the LAN-discovery key (`&l=`) when the host has local discovery on.
pub fn invite_link_with(node: EndpointId, join_code: Option<&str>, lan_key: Option<skwod_net::lan::LanKey>) -> String {
    let mut invite = Invite::new(node, join_code.map(str::to_string));
    invite.lan_key = lan_key;
    invite.share_link()
}

/// Which account each connected p2p node id is signed in as (in memory; bounded).
///
/// An entry is written in exactly one place — [`AuthenticatedNodes::note`], called where a
/// bearer token has been RESOLVED to a live session (`auth.rs`, `ws.rs`) — and only when that
/// account is a member of at least one space. Never from the mere presence of an
/// `Authorization` header or from a response status: plenty of routes answer 404/400/403 to a
/// garbage token.
///
/// Bounds, in the same spirit as the connection table (`skwod_net::host::ConnTable`):
/// - an account has at most [`skwod_net::host::MAX_PER_ACCOUNT`] entries; one more replaces
///   that account's OWN oldest;
/// - an entry is removed when its node's last connection closes, and when a re-check finds its
///   session or membership gone;
/// - when the map is at [`AuthenticatedNodes::CAP`] a new node is simply not recorded (it stays
///   an ordinary unauthenticated connection and can try again): nobody else's entry is ever
///   evicted to make room, so churning node ids cannot cost another member their standing.
#[derive(Clone, Default)]
pub struct AuthenticatedNodes(std::sync::Arc<std::sync::Mutex<std::collections::HashMap<[u8; 32], NodeAuth>>>, std::sync::Arc<std::sync::OnceLock<skwod_net::host::Promoter>>);

#[derive(Clone)]
struct NodeAuth {
    user_id: String,
    session_hash: Vec<u8>,
    seq: u64,
}

impl AuthenticatedNodes {
    /// 4 × the connection table: room for every member connection several times over.
    pub const CAP: usize = 4096;

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<[u8; 32], NodeAuth>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `node` just made a request under the live session `session_hash` of `user_id`.
    pub async fn note(&self, state: &AppState, node: [u8; 32], user_id: &str, session_hash: &[u8]) {
        // Already known as exactly this: nothing to do (and no query on the hot path).
        if self.lock().get(&node).is_some_and(|n| n.user_id == user_id && n.session_hash == session_hash) {
            return;
        }
        // Standing is for members. An account that exists but is in no space gets none.
        let Some(since) = member_since(state, user_id).await else { return };
        self.insert(node, user_id, session_hash);
        // …and it takes effect on the node's open connections NOW (net audit P2): they used
        // to stay evictable strangers until a 10–60 s timer came round.
        if self.lock().get(&node).is_some_and(|n| n.user_id == user_id) {
            if let Some(host) = self.1.get() {
                host.promote(node, user_id, since);
            }
        }
    }

    /// Connect this record to the running p2p host (once, at start).
    pub fn set_promoter(&self, promoter: skwod_net::host::Promoter) {
        let _ = self.1.set(promoter);
    }

    fn insert(&self, node: [u8; 32], user_id: &str, session_hash: &[u8]) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut map = self.lock();
        map.remove(&node);
        // Per-account cap: the account's own oldest entries make room.
        loop {
            let mut mine: Vec<([u8; 32], u64)> = map.iter().filter(|(_, v)| v.user_id == user_id).map(|(k, v)| (*k, v.seq)).collect();
            if mine.len() < skwod_net::host::MAX_PER_ACCOUNT {
                break;
            }
            mine.sort_by_key(|(_, seq)| *seq);
            map.remove(&mine[0].0);
        }
        if map.len() >= Self::CAP {
            return; // full of other accounts' entries: not recorded, nobody evicted
        }
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        map.insert(node, NodeAuth { user_id: user_id.to_string(), session_hash: session_hash.to_vec(), seq });
    }

    /// The node's last connection closed.
    pub fn forget(&self, node: &[u8; 32]) {
        self.lock().remove(node);
    }

    #[cfg(test)]
    pub(crate) fn user(&self, node: &[u8; 32]) -> Option<String> {
        self.lock().get(node).map(|n| n.user_id.clone())
    }

    #[cfg(test)]
    pub(crate) fn nodes_of(&self, user_id: &str) -> usize {
        self.lock().values().filter(|n| n.user_id == user_id).count()
    }

    #[cfg(test)]
    pub(crate) fn fill(&self, n: usize) {
        for i in 0..n {
            let mut node = [0xEEu8; 32];
            node[..8].copy_from_slice(&(i as u64).to_be_bytes());
            self.insert(node, &format!("filler-{}", i / skwod_net::host::MAX_PER_ACCOUNT), b"h");
        }
    }

    /// The account `node` is signed in as right now (see `Backend::peer_account`).
    pub async fn account(&self, state: &AppState, node: &[u8; 32]) -> Option<String> {
        let entry = self.lock().get(node).cloned()?;
        // Live, of an install that may still act (not superseded or removed), and a member.
        let mut live = crate::auth::current_session_user(state, &entry.session_hash).await.filter(|user| *user == entry.user_id);
        if let Some(user) = &live {
            if !is_member_somewhere(state, user).await {
                live = None;
            }
        }
        if live.is_none() {
            self.lock().remove(node);
        }
        live
    }
}

struct Backend {
    router: Router,
    state: AppState,
}

impl HostBackend for Backend {
    fn serve_http(&self, peer: EndpointId, relayed: bool, io: BiStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        // The node id is the caller's identity for rate limiting (see `client_key.rs`).
        let peer = P2pPeer { node: peer.to_z32(), node_bytes: *peer.as_bytes(), relayed };
        let svc = TowerToHyperService::new(self.router.clone().layer(Extension(peer)));
        Box::pin(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(io), svc)
                .with_upgrades()
                .await;
        })
    }

    /// Asked at the voice hello, again for every LiveKit stream, and on a timer while media
    /// flows — so it must answer for NOW: the session is live (not expired, not logged out; a
    /// deleted account's sessions cascade away) and the user is still a member of some space
    /// (kick/ban removes the membership row).
    /// The account behind this node, re-validated against the database every time it is asked:
    /// the session that vouched for the node must still be live and its user still a member of
    /// some space. A logout, an expiry or a removal therefore ends the node's standing.
    fn peer_account(&self, peer: EndpointId) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>> + Send>> {
        let state = self.state.clone();
        let node = *peer.as_bytes();
        Box::pin(async move { state.p2p_authenticated.account(&state, &node).await })
    }

    fn account_since(&self, user: String) -> std::pin::Pin<Box<dyn std::future::Future<Output = i64> + Send>> {
        let state = self.state.clone();
        Box::pin(async move { member_since(&state, &user).await.unwrap_or(i64::MAX) })
    }

    fn peer_disconnected(&self, peer: EndpointId) {
        self.state.p2p_authenticated.forget(peer.as_bytes());
    }

    fn authorize_voice(&self, bearer: String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
        let state = self.state.clone();
        Box::pin(async move { voice_allowed(&state, &bearer).await })
    }

    /// Bound to the room: `room` and `identity` come from the LiveKit token the stream carries.
    /// The session's user must BE that identity and must hold CONNECT_VOICE on that room's voice
    /// channel right now — membership of some other space on the instance is not enough.
    fn authorize_room(&self, bearer: String, room: String, identity: String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
        let state = self.state.clone();
        Box::pin(async move { room_allowed(&state, &bearer, &room, &identity).await })
    }

    fn livekit(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<LiveKitTarget>> + Send>> {
        let state = self.state.clone();
        Box::pin(async move { livekit_target(&state).await })
    }
}

/// When `user_id` first became a member of a space (unix ms); `None` = a member of none.
pub(crate) async fn member_since(state: &AppState, user_id: &str) -> Option<i64> {
    sqlx::query_scalar::<_, Option<i64>>("SELECT MIN(created_at) FROM server_members WHERE user_id = $1").bind(user_id).fetch_one(&state.db).await.ok().flatten()
}

async fn is_member_somewhere(state: &AppState, user_id: &str) -> bool {
    let member: Result<Option<i64>, _> = sqlx::query_scalar("SELECT 1 FROM server_members WHERE user_id = $1 LIMIT 1").bind(user_id).fetch_optional(&state.db).await;
    matches!(member, Ok(Some(_)))
}

pub(crate) async fn voice_allowed(state: &AppState, bearer: &str) -> bool {
    match crate::auth::current_session_user(state, &crate::auth::token_hash(bearer)).await {
        Some(user) => is_member_somewhere(state, &user).await,
        None => false,
    }
}

pub(crate) async fn room_allowed(state: &AppState, bearer: &str, room: &str, identity: &str) -> bool {
    let user: Option<String> = crate::auth::current_session_user(state, &crate::auth::token_hash(bearer)).await;
    let Some(user) = user.filter(|u| u == identity) else { return false };
    let Some(channel_id) = room.strip_prefix(crate::voice::ROOM_PREFIX) else { return false };
    let kind: Option<String> = sqlx::query_scalar("SELECT type FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    if kind.as_deref() != Some("voice") {
        return false;
    }
    let Ok(server_id) = crate::structure::channel_server(state, channel_id).await else { return false };
    // `effective_permissions` is the same gate the token endpoint uses; a non-member has none.
    let is_member: Option<i64> = sqlx::query_scalar("SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(&server_id)
        .bind(&user)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    if is_member.is_none() {
        return false;
    }
    match crate::structure::effective_permissions(state, &server_id, &user, Some(channel_id)).await {
        Ok(p) => crate::perms::has_permission(p, crate::perms::CONNECT_VOICE),
        Err(_) => false,
    }
}

async fn secret(state: &AppState, name: &str) -> Option<String> {
    let v: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = $1")
        .bind(name)
        .fetch_optional(&state.db)
        .await
        .ok()?;
    v.and_then(|b| String::from_utf8(b).ok())
}

/// The LiveKit this instance can bridge members to — only a LOCAL one: a plain `ws://` URL (host
/// loopback / compose network) with a known single UDP port. A `wss://` URL (LiveKit Cloud or
/// another public SFU) is not tunnelled; members connect to it themselves, as before.
pub async fn livekit_target(state: &AppState) -> Option<LiveKitTarget> {
    let url = secret(state, "livekit_url").await?;
    let authority = url.strip_prefix("ws://")?.split('/').next()?.to_string();
    let advertised_udp_port: u16 = secret(state, "livekit_udp_port").await?.parse().ok()?;
    let signal = tokio::net::lookup_host(&authority).await.ok()?.next()?;
    // `SKWOD_LIVEKIT_UDP_ADDR`: where the server reaches LiveKit's UDP port when that differs from
    // `<signal host>:<advertised port>` (LiveKit behind a container port mapping).
    let udp = match std::env::var("SKWOD_LIVEKIT_UDP_ADDR").ok().and_then(|a| a.parse().ok()) {
        Some(addr) => addr,
        None => SocketAddr::new(signal.ip(), advertised_udp_port),
    };
    Some(LiveKitTarget { signal, udp, advertised_udp_port })
}

/// Start accepting p2p connections for `router`. Returns the running host (keep it alive).
pub async fn start(state: AppState, router: Router, data: &Path, opts: &P2pOptions) -> Result<skwod_net::Host, String> {
    let key = skwod_net::load_or_create_secret_key(&data.join(KEY_FILE)).map_err(|e| format!("p2p key: {e}"))?;
    let mut cfg = NetConfig::host(key);
    cfg.public_fallback = opts.public_fallback;
    cfg.bind_port = opts.port;
    cfg.external_addrs = opts.external_addrs.clone();
    cfg.local_discovery = opts.local_discovery;
    cfg.lan_key = if opts.local_discovery { lan_key(data, true) } else { None };
    start_with(state, router, &cfg).await
}

/// [`start`] with an explicit network configuration (tests run with discovery + relays off).
pub async fn start_with(state: AppState, router: Router, cfg: &NetConfig) -> Result<skwod_net::Host, String> {
    let host = skwod_net::Host::start(cfg, Arc::new(Backend { router, state: state.clone() }))
        .await
        .map_err(|e| e.to_string())?;
    state.p2p_authenticated.set_promoter(host.promoter());
    *state.lan_key.lock().expect("lan key lock") = if host.lan_advertising() { cfg.lan_key } else { None };
    let _ = state.p2p.set(P2pStatus {
        node_id: host.node_id().to_z32(),
        node_bytes: *host.node_id().as_bytes(),
        public_fallback: cfg.public_fallback,
    });
    *state.p2p_endpoint.lock().expect("p2p endpoint lock") = Some(host.endpoint().clone());
    Ok(host)
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/instance/p2p", axum::routing::get(p2p_info))
}

/// The skwod's p2p address, for building invite links in the apps. Members only.
async fn p2p_info(State(state): State<AppState>, _auth: AuthUser) -> Result<Json<Value>, ApiError> {
    Ok(Json(match state.p2p.get() {
        Some(s) => json!({
            "enabled": true, "node_id": s.node_id, "public_fallback": s.public_fallback,
            // The home relay right now (allow-listed n0 relays only), for `&r=` in share links.
            "relay_url": home_relay(&state, s.public_fallback),
            "qr_pairing": state.qr_pairing,
            // Present only while the host announces itself on its LAN (opt-in).
            "lan_key": state.lan_key.lock().expect("lan key lock").map(|k| k.to_hex()),
        }),
        None => json!({ "enabled": false }),
    }))
}

#[cfg(all(test, unix))]
mod lan_key_tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lan_key_permissions_are_tightened_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let key = super::lan_key(dir.path(), true).expect("created");
        let path = dir.path().join(super::LAN_KEY_FILE);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // Someone (a restore, an old build) left it world-readable.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(super::lan_key(dir.path(), false).map(|k| k.to_hex()), Some(key.to_hex()));
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600, "not tightened on load");
    }
}
