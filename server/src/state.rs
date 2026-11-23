//! Shared application state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::limiter::{OnceSet, RateLimiter};
use crate::rt::RealtimeHub;

/// One pool type for either backend. Queries use `$N` placeholders + dialect-neutral SQL, so the
/// same code runs on SQLite (default, single-binary self-host) or Postgres (`--database-url`).
pub type Db = sqlx::Pool<sqlx::Any>;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub rt: RealtimeHub,
    pub limiter: RateLimiter,
    /// Proof-of-work stamps already spent (single use; see `client_key.rs`).
    pub used_stamps: OnceSet,
    /// Directory for encrypted blob storage (<data>/blobs).
    pub blob_dir: PathBuf,
    /// Directory for published app releases (<data>/releases): a `manifest.json` + the `.zip`/`.apk`
    /// artifacts served to clients by the self-update endpoints. Derived from `blob_dir`'s parent.
    pub releases_dir: PathBuf,
    /// Live WebSocket connections per user — presence is DERIVED from these: when a user's last
    /// socket closes they flip offline automatically (no goodbye frame needed).
    /// An async mutex, held ACROSS the offline DB write + broadcast, so a quick reconnect can never
    /// interleave its registration with a stale offline transition (write-after-online race).
    pub ws_conns: Arc<Mutex<HashMap<String, u32>>>,
    /// APNs sender for silent push wakeups, when configured via APNS_* env (else None = disabled).
    pub apns: Option<Arc<crate::apns::Apns>>,
    /// FCM sender for Android push wakeups, when configured via FCM_* env (else None = disabled).
    pub fcm: Option<Arc<crate::fcm::Fcm>>,
    /// Reverse proxies whose `X-Forwarded-For` is believed (`SKWOD_TRUSTED_PROXIES`, comma-separated
    /// IPs/CIDRs). Nothing is trusted by default — not even loopback. See `client_key.rs`.
    pub trusted_proxies: Arc<Vec<crate::client_key::IpNet>>,
    /// Sessions (by token hash) with a live WebSocket right now. The push gateway path never wakes
    /// a device that is connected (`gateway.rs`). In memory only.
    pub ws_sessions: Arc<std::sync::Mutex<HashMap<Vec<u8>, u32>>>,
    /// session hash → topic → how many of its REACHABLE sockets are subscribed to it. A push
    /// wake is skipped only for an event on a topic found here: an open socket that was never
    /// going to be handed the event does not stand in for the wake (`gateway.rs`, rule 3).
    pub ws_topics: Arc<std::sync::Mutex<SessionTopics>>,
    /// Coalescing/jittering scheduler for blind push-gateway wakes.
    pub waker: crate::gateway::Waker,
    /// `false` while the host has pressed Stop on the admin page: the API answers 503 (except
    /// `/health`). Always `true` unless `skwod run --wait-for-start` manages it (`control.rs`).
    pub serving: Arc<std::sync::atomic::AtomicBool>,
    /// The LAN-discovery key while the host is announcing on its local network (else `None`).
    pub lan_key: Arc<std::sync::Mutex<Option<skwod_net::lan::LanKey>>>,
    /// The p2p endpoint's public facts (node id, fallback policy), set once `skwod run` starts it.
    pub p2p: Arc<std::sync::OnceLock<crate::p2p::P2pStatus>>,
    /// Calls that are ringing right now (one per voice channel, ~45 s), so a device that
    /// connects late — woken by a push — still learns which room to join (`voice.rs`).
    pub rings: crate::voice::Rings,
    /// Who is in which voice room right now (in memory; `voice_state.rs`).
    pub voice_states: crate::voice_state::VoiceStates,
    /// Serializes "a member opens a server's first voice room" so two members arriving at once
    /// get the same room instead of two (`structure.rs`).
    pub voice_room_lock: Arc<Mutex<()>>,
    /// The public address(es) this instance is served at (`SKWOD_PUBLIC_URL`, comma-separated).
    /// Origin-bound instance proofs and the signed address record use them (`structure.rs`).
    pub public_urls: Arc<Vec<String>>,
    /// Most bytes of blobs one account may hold at once (`SKWOD_BLOB_QUOTA_MB`, default 5 GiB).
    pub blob_quota_bytes: i64,
    /// New uploads are refused while the data volume has less free space than this
    /// (`SKWOD_BLOB_FREE_FLOOR_MB`, default 1 GiB), so attachments cannot fill the host's disk.
    pub blob_free_floor_bytes: u64,
    /// Most bytes of message, DM, reaction and attachment-metadata ciphertext one account may
    /// have stored (`SKWOD_MESSAGE_QUOTA_MB`, default 512 MiB; 0 = unlimited). See `storage.rs`.
    pub message_quota_bytes: i64,
    /// Per-account stored-bytes counters behind that quota.
    pub usage: crate::storage::Usage,
    /// Refuse a session that is bound to no device once its account has one. On from build 45
    /// (every build-45 client binds before its first request); `SKWOD_REQUIRE_BOUND_SESSIONS=0`
    /// is the operator's way out while members are still on older builds. See
    /// `auth::install_standing`.
    pub require_bound_sessions: bool,
    /// Require a signed device proof for destructive actions, not just a session of a current
    /// install. On from build 45; `SKWOD_REQUIRE_DEVICE_PROOFS=0` turns it off. See
    /// `keydir::destructive_authority`.
    pub require_device_proofs: bool,
    /// How many accounts created with one invite may be unadmitted at once
    /// (`SKWOD_INVITE_PENDING_SIGNUPS`, default 10). See `join.rs`.
    pub invite_pending_signups: i64,
    /// How large ONE file may be, in bytes (`limits.rs`): `SKWOD_MAX_UPLOAD_MB`, default 100 MB,
    /// replaced by what the instance owner set from the app. Shared, so a change by the owner
    /// applies to every request at once.
    pub max_upload_bytes: Arc<std::sync::atomic::AtomicU64>,
    /// Story-music previews fetched for members (`music.rs`): a small, short-lived cache.
    pub music: crate::music::Previews,
    /// What `SKWOD_MAX_UPLOAD_MB` said (bounded), to go back to when the owner clears their value.
    pub max_upload_env_bytes: u64,
    /// A session lives this long after its last use (`SKWOD_SESSION_TTL_SECS`, default 30 days)…
    pub session_ttl_ms: i64,
    /// …but never longer than this after sign-in (`SKWOD_SESSION_MAX_SECS`, default 1 year).
    pub session_max_ms: i64,
    /// How often an open WebSocket is pinged (`SKWOD_WS_PING_SECS`, default 20). A socket that
    /// has said nothing for two intervals + 10 s is closed (`ws.rs`).
    pub ws_ping: std::time::Duration,
    /// How long a socket has to prove it read a message, sealed-mail or ring event before the
    /// device is push-woken anyway (`SKWOD_WS_ACK_MS`, default 3000; `ws.rs` "delivery acks").
    pub ws_ack: std::time::Duration,
    /// The ack deadline is `ws_ack` ± a random share of this (750 ms), so a wake for a socket
    /// that did not answer never fires at a fixed offset from the event.
    pub ws_ack_jitter: std::time::Duration,
    /// p2p node ids that recently showed a valid session (`p2p.rs`).
    pub p2p_authenticated: crate::p2p::AuthenticatedNodes,
    /// Devices seen behaving like a build that can no longer take part (`oldbuilds.rs`).
    pub old_devices: crate::oldbuilds::OldDevices,
}

fn env_num<T: std::str::FromStr>(name: &str) -> Option<T> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

impl AppState {
    pub fn new(db: Db, blob_dir: PathBuf) -> Self {
        // Releases sit next to blobs under the data dir (<data>/releases), so every existing
        // `AppState::new(pool, data.join("blobs"))` call site keeps working with no signature change.
        let releases_dir = blob_dir
            .parent()
            .map(|p| p.join("releases"))
            .unwrap_or_else(|| PathBuf::from("releases"));
        let max_upload_env_bytes = crate::limits::from_env_value(std::env::var("SKWOD_MAX_UPLOAD_MB").ok().as_deref());
        Self {
            max_upload_bytes: Arc::new(std::sync::atomic::AtomicU64::new(max_upload_env_bytes)),
            max_upload_env_bytes,
            music: Default::default(),
            db,
            rt: RealtimeHub::new(),
            limiter: RateLimiter::new(),
            used_stamps: OnceSet::default(),
            blob_dir,
            releases_dir,
            ws_conns: Arc::new(Mutex::new(HashMap::new())),
            apns: crate::apns::Apns::from_env().map(Arc::new),
            fcm: crate::fcm::Fcm::from_env().map(Arc::new),
            trusted_proxies: Arc::new(
                std::env::var("SKWOD_TRUSTED_PROXIES")
                    .map(|v| crate::client_key::parse_trusted_proxies(&v))
                    .unwrap_or_default(),
            ),
            ws_sessions: Arc::default(),
            ws_topics: Arc::default(),
            waker: crate::gateway::Waker::from_env(),
            serving: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            lan_key: Arc::default(),
            p2p: Arc::default(),
            rings: crate::voice::Rings::default(),
            voice_states: crate::voice_state::VoiceStates::default(),
            voice_room_lock: Arc::default(),
            public_urls: Arc::new(
                std::env::var("SKWOD_PUBLIC_URL").map(|v| v.split(',').map(|s| s.trim().to_string()).collect()).unwrap_or_default(),
            ),
            blob_quota_bytes: env_num::<i64>("SKWOD_BLOB_QUOTA_MB").unwrap_or(5 * 1024).max(1) * 1024 * 1024,
            blob_free_floor_bytes: env_num::<u64>("SKWOD_BLOB_FREE_FLOOR_MB").unwrap_or(1024) * 1024 * 1024,
            message_quota_bytes: env_num::<i64>("SKWOD_MESSAGE_QUOTA_MB").unwrap_or(512).max(0).saturating_mul(1024 * 1024),
            usage: Default::default(),
            require_device_proofs: env_on_by_default("SKWOD_REQUIRE_DEVICE_PROOFS"),
            require_bound_sessions: env_on_by_default("SKWOD_REQUIRE_BOUND_SESSIONS"),
            invite_pending_signups: env_num::<i64>("SKWOD_INVITE_PENDING_SIGNUPS").unwrap_or(crate::join::DEFAULT_INVITE_PENDING_SIGNUPS).max(1),
            session_ttl_ms: env_num::<i64>("SKWOD_SESSION_TTL_SECS").unwrap_or(30 * 24 * 60 * 60).max(60) * 1000,
            session_max_ms: env_num::<i64>("SKWOD_SESSION_MAX_SECS").unwrap_or(365 * 24 * 60 * 60).max(60) * 1000,
            p2p_authenticated: Default::default(),
            old_devices: Default::default(),
            ws_ping: std::time::Duration::from_secs(env_num::<u64>("SKWOD_WS_PING_SECS").unwrap_or(20).clamp(1, 120)),
            ws_ack: std::time::Duration::from_millis(env_num::<u64>("SKWOD_WS_ACK_MS").unwrap_or(3000).clamp(1000, 30_000)),
            ws_ack_jitter: std::time::Duration::from_millis(750),
        }
    }

    pub fn session_online(&self, session_hash: &[u8]) {
        *self.ws_sessions.lock().expect("ws sessions lock").entry(session_hash.to_vec()).or_insert(0) += 1;
    }

    pub fn session_offline(&self, session_hash: &[u8]) {
        let mut map = self.ws_sessions.lock().expect("ws sessions lock");
        match map.get_mut(session_hash) {
            Some(n) if *n > 1 => *n -= 1,
            _ => {
                map.remove(session_hash);
            }
        }
    }

    /// Does any socket of this session count as reachable? What decides a wake is
    /// [`Self::session_handed`]; this is how the tests observe a socket's reachability.
    #[cfg(test)]
    pub fn session_connected(&self, session_hash: &[u8]) -> bool {
        self.ws_sessions.lock().expect("ws sessions lock").contains_key(session_hash)
    }

    /// A reachable socket of this session subscribed to `topic` (`on`), or stopped being one.
    pub fn session_topic(&self, session_hash: &[u8], topic: &str, on: bool) {
        let mut map = self.ws_topics.lock().expect("ws topics lock");
        if on {
            *map.entry(session_hash.to_vec()).or_default().entry(topic.to_string()).or_insert(0) += 1;
            return;
        }
        let Some(topics) = map.get_mut(session_hash) else { return };
        match topics.get_mut(topic) {
            Some(n) if *n > 1 => *n -= 1,
            _ => {
                topics.remove(topic);
            }
        }
        if topics.is_empty() {
            map.remove(session_hash);
        }
    }

    /// Is an event on each of `topics` handed to a reachable socket of this session? False for
    /// no topics at all: a wake that cannot say what it is for is never skipped.
    pub fn session_handed<S: AsRef<str>>(&self, session_hash: &[u8], topics: &[S]) -> bool {
        let map = self.ws_topics.lock().expect("ws topics lock");
        let Some(have) = map.get(session_hash) else { return false };
        !topics.is_empty() && topics.iter().all(|t| have.contains_key(t.as_ref()))
    }
}

/// session hash → topic → number of reachable sockets subscribed to it.
pub type SessionTopics = HashMap<Vec<u8>, HashMap<String, u32>>;

/// Current time as unix milliseconds (the schema's timestamp convention).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before 1970")
        .as_millis() as i64
}

/// Fresh v4 UUID string (the schema's id convention).
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// A switch that is ON unless the operator turns it off (`0`, `false`, `no`, `off`). The
/// in-process test state leaves both strict modes off, so each test opts in by itself.
fn env_on_by_default(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no" | "off"),
        Err(_) => !cfg!(test),
    }
}
