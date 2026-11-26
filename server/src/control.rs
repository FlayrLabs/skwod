//! Hosting lifecycle — what the admin page's **Start server / Stop / Restart** buttons drive.
//!
//! The process (and its admin page) is always up; "the server" a host starts and stops is what
//! other people can reach: the p2p endpoint, the managed LiveKit, and the API itself (which
//! answers 503 while stopped). The choice is remembered (`hosting_enabled`), so a container that
//! was started stays started across restarts and one that was stopped stays stopped.

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

use axum::Router;

use crate::init::Bootstrap;
use crate::livekit::ManagedLiveKit;
use crate::p2p::P2pOptions;
use crate::state::{now_ms, AppState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Stopped,
    Starting,
    Running,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Stopped => "stopped",
            Phase::Starting => "starting",
            Phase::Running => "running",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Status {
    pub phase: Phase,
    /// Something the host should know (e.g. the p2p endpoint could not start).
    pub problem: Option<String>,
    pub p2p: bool,
    /// Announcing on the local network right now (opt-in).
    pub local_discovery: bool,
    /// The one-time owner setup code, while this process knows it (it is stored only as a hash).
    pub setup_code: Option<String>,
    /// A friend invite minted from the admin page: (code, expires_at).
    pub friend_invite: Option<(String, i64)>,
}

#[derive(Default)]
struct Running {
    p2p: Option<skwod_net::Host>,
    livekit: Option<ManagedLiveKit>,
}

pub struct HostControl {
    pub state: AppState,
    router: Router,
    data: PathBuf,
    /// `None` = `--no-p2p`.
    p2p: Option<P2pOptions>,
    running: tokio::sync::Mutex<Running>,
    status: Mutex<Status>,
    /// Fired by the admin page's "quit" (desktop host app) to end the process cleanly.
    pub quit: tokio::sync::Notify,
}

async fn secret(state: &AppState, name: &str) -> Option<String> {
    let v: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = $1").bind(name).fetch_optional(&state.db).await.ok()?;
    v.and_then(|b| String::from_utf8(b).ok())
}

async fn put_secret(state: &AppState, name: &str, value: &str) {
    let _ = sqlx::query(
        "INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, $3)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value, created_at = excluded.created_at",
    )
    .bind(name)
    .bind(value.as_bytes())
    .bind(now_ms())
    .execute(&state.db)
    .await;
}

impl HostControl {
    pub fn new(state: AppState, router: Router, data: PathBuf, p2p: Option<P2pOptions>) -> Self {
        let status = Status { phase: Phase::Stopped, problem: None, p2p: false, local_discovery: false, setup_code: None, friend_invite: None };
        Self { state, router, data, p2p, running: Default::default(), status: Mutex::new(status), quit: tokio::sync::Notify::new() }
    }

    pub fn status(&self) -> Status {
        self.status.lock().expect("status lock").clone()
    }

    fn set(&self, f: impl FnOnce(&mut Status)) {
        f(&mut self.status.lock().expect("status lock"));
    }

    pub async fn owner_claimed(&self) -> bool {
        secret(&self.state, "owner_user_id").await.is_some()
    }

    /// With `--wait-for-start`: should hosting begin without a click? Yes if the host started it
    /// before; also yes for an instance that already has an owner but predates this switch (an
    /// upgrade must not take a running skwod offline).
    pub async fn should_autostart(&self) -> bool {
        match secret(&self.state, "hosting_enabled").await.as_deref() {
            Some("1") => true,
            Some(_) => false,
            None => self.owner_claimed().await,
        }
    }

    /// The node id of this skwod (stable; derived from `<data>/p2p.key`).
    pub fn node_id(&self) -> Option<skwod_net::EndpointId> {
        self.p2p.as_ref()?;
        crate::p2p::node_id(&self.data).ok()
    }

    /// Start hosting. Idempotent. Returns the owner setup code if this call created one.
    pub async fn start(&self) -> Result<Option<String>, String> {
        let mut running = self.running.lock().await;
        if self.status().phase == Phase::Running {
            return Ok(None);
        }
        self.set(|s| {
            s.phase = Phase::Starting;
            s.problem = None;
        });

        // Never serve a fresh volume ownerless with open signup (see `init::ensure_initialized`).
        let mut fresh_code = None;
        match crate::init::ensure_initialized(&self.state.db).await {
            Ok(Bootstrap::AutoInitialized { join_code }) => fresh_code = Some(join_code),
            Ok(Bootstrap::LegacyOpen) => {
                tracing::warn!("this instance has accounts but was never initialized: SIGNUP IS OPEN and it has no owner. Run `skwod init --data <dir>` to gate it.");
            }
            Ok(Bootstrap::OpenByChoice) => {
                tracing::warn!("SKWOD_OPEN_SIGNUP is set: anyone who can reach this instance can create an account");
            }
            Ok(Bootstrap::Initialized) => {}
            Err(e) => {
                self.set(|s| s.phase = Phase::Stopped);
                return Err(format!("bootstrap check failed: {e}"));
            }
        }
        if let Some(code) = &fresh_code {
            self.set(|s| s.setup_code = Some(code.clone()));
        }

        // Voice: supervise a local LiveKit if its binary is available. Whether it runs is never
        // remembered here: `livekit::status` answers that when somebody asks.
        running.livekit = crate::livekit::spawn_managed(&self.state, &self.data).await;

        let mut problem = None;
        let mut lan = false;
        if let Some(opts) = &self.p2p {
            // LAN announcement: the command line can force it; otherwise it is the host's
            // remembered choice from the admin page. Default off.
            let mut opts = opts.clone();
            opts.local_discovery = opts.local_discovery || secret(&self.state, "local_discovery").await.as_deref() == Some("1");
            match self.start_p2p_with_retries(&opts).await {
                Ok(host) => {
                    lan = host.lan_advertising();
                    // Say what is actually published: the old line claimed "local network" even with
                    // LAN discovery off, and never mentioned n0 DNS, which is what new members
                    // without a DHT path depend on.
                    tracing::info!(
                        public_fallback = opts.public_fallback,
                        local_discovery = lan,
                        "p2p endpoint up (address = this instance's key; published to {})",
                        if opts.public_fallback { "Mainline DHT + n0 DNS, reachable via n0 relays" } else { "Mainline DHT only" }
                    );
                    running.p2p = Some(host);
                }
                // The TCP listener still works (VPS/reverse-proxy hosts), so this is not fatal.
                Err(e) => {
                    tracing::error!(error = %e, "p2p endpoint failed to start — serving TCP only");
                    problem = Some(format!("The peer-to-peer endpoint could not start ({e}). Friends cannot reach this server by invite until it does."));
                }
            }
        }
        self.state.serving.store(true, Ordering::SeqCst);
        put_secret(&self.state, "hosting_enabled", "1").await;
        let p2p = running.p2p.is_some();
        self.set(|s| {
            s.phase = Phase::Running;
            s.p2p = p2p;
            s.local_discovery = lan;
            s.problem = problem;
        });
        Ok(fresh_code)
    }

    /// Bring the p2p endpoint up, trying a few times: right after login (launch at login) or a
    /// wake from sleep the network is often not there for the first seconds.
    async fn start_p2p_with_retries(&self, opts: &crate::p2p::P2pOptions) -> Result<skwod_net::Host, String> {
        let mut last = String::new();
        for (attempt, pause_ms) in [0u64, 1_000, 3_000].into_iter().enumerate() {
            if pause_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(pause_ms)).await;
            }
            match crate::p2p::start(self.state.clone(), self.router.clone(), &self.data, opts).await {
                Ok(host) => return Ok(host),
                Err(e) => {
                    tracing::warn!(attempt = attempt + 1, error = %e, "p2p endpoint did not start");
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// Hosting is on, a p2p endpoint is wanted, and there is none.
    pub fn p2p_missing(&self) -> bool {
        let st = self.status();
        self.p2p.is_some() && st.phase == Phase::Running && !st.p2p
    }

    /// One more attempt at the p2p endpoint while hosting runs without it (called on a timer by
    /// `main`). `true` when it is up afterwards; the admin page's problem line is cleared.
    pub async fn retry_p2p(&self) -> bool {
        let mut running = self.running.lock().await;
        if !self.p2p_missing() || running.p2p.is_some() {
            return running.p2p.is_some();
        }
        let Some(opts) = &self.p2p else { return false };
        let mut opts = opts.clone();
        opts.local_discovery = opts.local_discovery || secret(&self.state, "local_discovery").await.as_deref() == Some("1");
        match crate::p2p::start(self.state.clone(), self.router.clone(), &self.data, &opts).await {
            Ok(host) => {
                let lan = host.lan_advertising();
                running.p2p = Some(host);
                tracing::info!("p2p endpoint up after a retry");
                self.set(|s| {
                    s.p2p = true;
                    s.local_discovery = lan;
                    s.problem = None;
                });
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "p2p endpoint still not starting");
                false
            }
        }
    }

    /// Stop hosting: close the p2p endpoint (members are disconnected), stop LiveKit, refuse the
    /// API. `remember = false` is process shutdown — the choice on disk is left as it was.
    pub async fn stop(&self, remember: bool) {
        let mut running = self.running.lock().await;
        self.state.serving.store(false, Ordering::SeqCst);
        if let Some(host) = running.p2p.take() {
            host.shutdown().await;
        }
        *self.state.lan_key.lock().expect("lan key lock") = None;
        if let Some(livekit) = running.livekit.take() {
            livekit.stop(&self.state).await;
        }
        if remember {
            put_secret(&self.state, "hosting_enabled", "0").await;
        }
        self.set(|s| {
            s.phase = Phase::Stopped;
            s.p2p = false;
            s.local_discovery = false;
            s.problem = None;
        });
    }

    /// The invite link for `join_code` (or the bare address), while the p2p endpoint is up.
    /// Carries the LAN key only while the host is announcing on its network.
    pub fn invite(&self, join_code: Option<&str>) -> Option<String> {
        if !self.status().p2p {
            return None;
        }
        let lan_key = *self.state.lan_key.lock().expect("lan key lock");
        Some(crate::p2p::invite_link_with(self.node_id()?, join_code, lan_key))
    }

    /// The host's "let people on this network find my server faster" choice. Remembered;
    /// applied by restarting the p2p endpoint if hosting is running.
    pub async fn set_local_discovery(&self, enabled: bool) -> Result<(), String> {
        put_secret(&self.state, "local_discovery", if enabled { "1" } else { "0" }).await;
        if self.status().phase == Phase::Running {
            self.restart().await?;
        }
        Ok(())
    }

    pub async fn restart(&self) -> Result<(), String> {
        self.stop(false).await;
        self.start().await.map(|_| ())
    }

    /// A new owner setup code, replacing the old one. Only while nobody owns the instance — the
    /// bootstrap code is dead forever once ownership is claimed (join.rs).
    pub async fn rotate_setup_code(&self) -> Result<String, &'static str> {
        if self.owner_claimed().await {
            return Err("this server already has an owner");
        }
        let code = crate::init::rotate_setup_code(&self.state.db).await.map_err(|_| "could not store a new code")?;
        self.set(|s| s.setup_code = Some(code.clone()));
        Ok(code)
    }

    /// Mint a friend invite on the owner's behalf for the instance's first space: a 7-day code
    /// that REQUIRES THE OWNER'S APPROVAL in the app. The admin page can therefore hand out a
    /// way to ask, never a way in.
    pub async fn friend_invite(&self) -> Result<(String, i64), &'static str> {
        let owner = secret(&self.state, "owner_user_id").await.ok_or("sign up as the owner first")?;
        let space: Option<String> = sqlx::query_scalar("SELECT id FROM servers ORDER BY created_at LIMIT 1").fetch_optional(&self.state.db).await.map_err(|_| "database error")?;
        let space = space.ok_or("create a space in the app first")?;
        self.state.limiter.check("admin_invite", 30, crate::limiter::HOUR).map_err(|_| "too many invites — try again later")?;
        let now = now_ms();
        let expires_at = now + crate::join::DEFAULT_INVITE_TTL_MS;
        for _ in 0..5 {
            let code = crate::structure::generate_code();
            let insert = sqlx::query(
                "INSERT INTO invites (id, server_id, inviter_id, code, kind, requires_approval, expires_at, status, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'code', 1, $5, 'active', $6, $6)",
            )
            .bind(crate::state::new_id())
            .bind(&space)
            .bind(&owner)
            .bind(&code)
            .bind(expires_at)
            .bind(now)
            .execute(&self.state.db)
            .await;
            if insert.is_ok() {
                self.set(|s| s.friend_invite = Some((code.clone(), expires_at)));
                return Ok((code, expires_at));
            }
        }
        Err("could not create an invite")
    }
}
