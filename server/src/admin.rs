//! The host admin page: one screen with a big **Start server** button, then the invite (copy +
//! QR), status, how many people are on it, and Stop / Restart. The Docker image, the NAS
//! templates and the desktop host app (`host/`) all show this same page.
//!
//! It is a separate HTTP listener with its own router. It is NOT part of the API router, so it
//! is never served over p2p or through a reverse proxy that fronts the API — reaching it takes
//! a TCP connection to its own port:
//!
//! - default `127.0.0.1:3477` — this machine only;
//! - in a container, the LAN (`SKWOD_ADMIN_LISTEN=0.0.0.0:3477`), where a **one-time token**
//!   printed to the log (Unraid/Synology show container logs in their UI) is the way in.
//!
//! On a loopback bind the desktop host app (`host/`) is the other client. `<data>/admin.url`
//! (0600) holds the page URL with the launch key and, on a second line, this process's pid.
//! Before the app sends that key anywhere it makes the listener prove it holds it
//! (`POST /admin/api/challenge`: an HMAC over the app's nonce) — so a local process that grabbed
//! the port of a dead server gets no credential. To open the page in a browser the app asks for
//! a single-use ticket (`POST /admin/api/ticket`), good for ten seconds and only for a login
//! that carries the page's own `Origin`; the app passes it to the browser inside a private file,
//! never on a command line.
//!
//! What a signed-in admin can do: start/stop/restart hosting, see and mint invites (friend
//! invites need the owner's approval in the app), see counts. What it cannot do: read anything
//! — the server holds only ciphertext — or see who the members are.
//!
//! Browser-facing hardening: `HttpOnly; SameSite=Strict` session cookie; every state change
//! needs a custom header (so a cross-site form can't send it) and a same-origin `Origin`; on a
//! loopback bind the `Host` header must be a loopback name (DNS rebinding); a strict CSP with no
//! inline script; no CORS; login attempts are rate limited.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::control::{HostControl, Phase};
use crate::state::now_ms;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:3477";
const COOKIE: &str = "skwod_admin";
const SESSION_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const MAX_SESSIONS: usize = 8;
/// File (0600, in the data dir) holding the admin URL with the launch key, for the desktop host
/// app. Written only when the page is bound to loopback.
pub const LAUNCH_FILE: &str = "admin.url";

const INDEX_HTML: &str = include_str!("admin_ui/index.html");
const APP_JS: &str = include_str!("admin_ui/admin.js");
const APP_CSS: &str = include_str!("admin_ui/admin.css");

fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill(buf.as_mut_slice());
    hex::encode(buf)
}

/// `XXXXX-XXXXX-XXXXX-XXXXX` (100 bits) from an alphabet without 0/O/1/I: typed from a log.
fn generate_token() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rngs::OsRng;
    let group = |rng: &mut rand::rngs::OsRng| (0..5).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect::<String>();
    (0..4).map(|_| group(&mut rng)).collect::<Vec<_>>().join("-")
}

fn normalize_token(t: &str) -> String {
    t.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect()
}

pub struct AdminAuth {
    /// Hash of the printed token; `None` once it has been used.
    one_time: Mutex<Option<[u8; 32]>>,
    /// Hash of the desktop app's launch key (loopback binds only). Reusable, loopback peers only.
    launch_key: Option<[u8; 32]>,
    /// Single-use, short-lived keys for handing a signed-in session to a browser (hash → expiry).
    /// The desktop app opens the page with one of these in the URL fragment instead of the
    /// launch key, because the URL is visible to other local users in the browser's command
    /// line; a ticket is worthless once the page has used it (or a minute later).
    tickets: Mutex<HashMap<[u8; 32], i64>>,
    sessions: Mutex<HashMap<[u8; 32], i64>>,
    loopback_only: bool,
}

/// Long enough for a browser to open the hand-off file and load the page; short enough that a
/// ticket seen anywhere is almost certainly dead.
const TICKET_TTL_MS: i64 = 10 * 1000;
/// Domain separation for [`AdminAuth::challenge`]: the proof is useless as anything else.
const CHALLENGE_CONTEXT: &[u8] = b"skwod-admin-challenge-v1:";
const MAX_TICKETS: usize = 8;

impl AdminAuth {
    /// Returns the auth state, the one-time token to print, and the launch key (loopback only).
    pub fn new(loopback_only: bool) -> (Self, String, Option<String>) {
        let token = generate_token();
        let launch = loopback_only.then(|| random_hex(32));
        let auth = Self {
            one_time: Mutex::new(Some(digest(&normalize_token(&token)))),
            launch_key: launch.as_deref().map(digest),
            tickets: Mutex::default(),
            sessions: Mutex::default(),
            loopback_only,
        };
        (auth, token, launch)
    }

    /// `from_page`: the request carried an `Origin` header naming this very page — what a
    /// browser running our page sends, and what a bare local HTTP client does not. A ticket is
    /// only redeemable that way (and is not consumed by an attempt that lacks it).
    fn login(&self, presented: &str, peer_is_loopback: bool, from_page: bool) -> Option<String> {
        let ok = {
            let mut one_time = self.one_time.lock().expect("admin lock");
            let hit = one_time.as_ref().is_some_and(|h| ct_eq(h, &digest(&normalize_token(presented))));
            if hit {
                *one_time = None; // single use
            }
            hit
        } || (peer_is_loopback && self.launch_key.as_ref().is_some_and(|h| ct_eq(h, &digest(presented))))
            || (peer_is_loopback && from_page && self.redeem_ticket(presented));
        if !ok {
            return None;
        }
        let session = random_hex(32);
        let now = now_ms();
        let mut sessions = self.sessions.lock().expect("admin lock");
        sessions.retain(|_, exp| *exp > now);
        if sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions.iter().min_by_key(|(_, exp)| **exp).map(|(k, _)| *k) {
                sessions.remove(&oldest);
            }
        }
        sessions.insert(digest(&session), now + SESSION_TTL_MS);
        Some(session)
    }

    /// Proof that this listener holds the launch key, for a caller that knows it too:
    /// `HMAC-SHA256(SHA-256(launch key), context ‖ nonce)`, hex. The desktop app checks this
    /// BEFORE it presents the key, so whoever answers on the port without the key learns
    /// nothing. Loopback binds only; the nonce is the caller's (32–128 hex characters).
    fn challenge(&self, nonce: &str) -> Option<String> {
        use hmac::Mac;
        let key = self.launch_key.as_ref()?;
        if !(32..=128).contains(&nonce.len()) || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).ok()?;
        mac.update(CHALLENGE_CONTEXT);
        mac.update(nonce.as_bytes());
        Some(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
    }

    /// A fresh ticket (loopback binds only): good for one login from this machine within
    /// [`TICKET_TTL_MS`].
    fn mint_ticket(&self) -> Option<String> {
        if !self.loopback_only {
            return None;
        }
        let ticket = random_hex(32);
        let now = now_ms();
        let mut tickets = self.tickets.lock().expect("admin lock");
        tickets.retain(|_, exp| *exp > now);
        if tickets.len() >= MAX_TICKETS {
            if let Some(oldest) = tickets.iter().min_by_key(|(_, exp)| **exp).map(|(k, _)| *k) {
                tickets.remove(&oldest);
            }
        }
        tickets.insert(digest(&ticket), now + TICKET_TTL_MS);
        Some(ticket)
    }

    fn redeem_ticket(&self, presented: &str) -> bool {
        // Looked up by hash, so the comparison leaks nothing about a stored ticket.
        self.tickets.lock().expect("admin lock").remove(&digest(presented)).is_some_and(|exp| exp > now_ms())
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        let Some(session) = cookie(headers) else { return false };
        self.sessions.lock().expect("admin lock").get(&digest(&session)).is_some_and(|exp| *exp > now_ms())
    }

    fn logout(&self, headers: &HeaderMap) {
        if let Some(session) = cookie(headers) {
            self.sessions.lock().expect("admin lock").remove(&digest(&session));
        }
    }
}

fn cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(COOKIE)?.strip_prefix('=').map(str::to_string))
}

#[derive(Clone)]
pub struct Admin {
    pub ctl: Arc<HostControl>,
    pub auth: Arc<AdminAuth>,
}

fn host_is_loopback(headers: &HeaderMap) -> bool {
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else { return false };
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    matches!(name, "127.0.0.1" | "localhost" | "[::1]")
}

/// The request names this very page as its `Origin` (a missing header does not count).
fn from_this_page(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else { return false };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
    !host.is_empty() && origin.strip_prefix("http://") == Some(host)
}

/// `Origin`, when a browser sends one, must be this very page.
fn same_origin(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else { return true };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
    origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) == Some(host)
}

/// Gate + headers for every admin response.
async fn guard(State(admin): State<Admin>, req: Request, next: Next) -> Response {
    let headers = req.headers();
    let refused = |status: StatusCode, msg: &'static str| harden((status, Json(json!({ "error": msg }))).into_response());
    if admin.auth.loopback_only && !host_is_loopback(headers) {
        return refused(StatusCode::FORBIDDEN, "open this page as http://127.0.0.1");
    }
    if req.method() != Method::GET {
        // A cross-site form/fetch cannot set a custom header without a CORS preflight, and this
        // listener never answers one.
        if req.method() != Method::POST || headers.get("x-skwod-admin").is_none() || !same_origin(headers) {
            return refused(StatusCode::FORBIDDEN, "forbidden");
        }
    }
    let public = matches!(req.uri().path(), "/" | "/admin.js" | "/admin.css" | "/admin/api/login" | "/admin/api/challenge" | "/favicon.ico");
    if !public && !admin.auth.authorized(headers) {
        return refused(StatusCode::UNAUTHORIZED, "sign in with the admin token");
    }
    harden(next.run(req).await)
}

fn harden(mut res: Response) -> Response {
    let h = res.headers_mut();
    for (name, value) in [
        ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"),
        ("x-frame-options", "DENY"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        h.insert(name, HeaderValue::from_static(value));
    }
    res
}

pub fn router(admin: Admin) -> Router {
    Router::new()
        .route("/", get(|| async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX_HTML) }))
        .route("/admin.js", get(|| async { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], APP_JS) }))
        .route("/admin.css", get(|| async { ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS) }))
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .route("/admin/api/login", post(login))
        .route("/admin/api/logout", post(logout))
        .route("/admin/api/status", get(status))
        .route("/admin/api/qr.svg", get(qr))
        .route("/admin/api/start", post(start))
        .route("/admin/api/stop", post(stop))
        .route("/admin/api/restart", post(restart))
        .route("/admin/api/invite", post(new_invite))
        .route("/admin/api/local-discovery", post(local_discovery))
        .route("/admin/api/quit", post(quit))
        .route("/admin/api/ticket", post(ticket))
        .route("/admin/api/challenge", post(challenge))
        .layer(axum::middleware::from_fn_with_state(admin.clone(), guard))
        .with_state(admin)
}

#[derive(Deserialize)]
struct LoginReq {
    token: String,
}

async fn login(State(admin): State<Admin>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, Json(req): Json<LoginReq>) -> Response {
    // Per peer (release audit M6): this used to be ONE bucket for everybody, so any device
    // on the network could keep the host from signing in by using it up. A loose overall
    // ceiling remains, so a crowd of addresses cannot grind on the token either.
    let per_peer = admin.ctl.state.limiter.check(&format!("admin_login:{}", crate::client_key::canonical(peer.ip())), 10, crate::limiter::MINUTE);
    let overall = admin.ctl.state.limiter.check("admin_login", 600, crate::limiter::MINUTE);
    if per_peer.is_err() || overall.is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({ "error": "too many attempts — wait a minute" }))).into_response();
    }
    match admin.auth.login(&req.token, peer.ip().is_loopback(), from_this_page(&headers)) {
        Some(session) => {
            let cookie = format!("{COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", SESSION_TTL_MS / 1000);
            ([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response()
        }
        None => (StatusCode::UNAUTHORIZED, Json(json!({ "error": "that token is not valid (each token works once — restart the server for a new one)" }))).into_response(),
    }
}

#[derive(Deserialize)]
struct ChallengeReq {
    nonce: String,
}

/// "Prove you are the server whose launch key I hold" — see [`AdminAuth::challenge`]. Needs no
/// session (it is asked before any credential is sent) and gives nothing to a caller without
/// the key. Loopback peers on a loopback bind only.
async fn challenge(State(admin): State<Admin>, ConnectInfo(peer): ConnectInfo<SocketAddr>, Json(req): Json<ChallengeReq>) -> Response {
    match admin.auth.challenge(&req.nonce).filter(|_| peer.ip().is_loopback()) {
        Some(proof) => Json(json!({ "proof": proof })).into_response(),
        None => (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" }))).into_response(),
    }
}

/// Desktop host app → browser hand-off: a signed-in caller gets a single-use key for the page
/// URL (`/#k=<ticket>`), which the page redeems with its own `Origin`. Loopback binds only.
async fn ticket(State(admin): State<Admin>) -> Response {
    match admin.auth.mint_ticket() {
        Some(ticket) => Json(json!({ "ticket": ticket })).into_response(),
        None => (StatusCode::FORBIDDEN, Json(json!({ "error": "only on this computer" }))).into_response(),
    }
}

async fn logout(State(admin): State<Admin>, headers: HeaderMap) -> Json<Value> {
    admin.auth.logout(&headers);
    Json(json!({ "ok": true }))
}

/// Is `peer` this computer — or, in a container, the machine running the container?
///
/// The admin page is plain HTTP. Whatever it sends to another machine crosses the network in
/// the clear, and the OWNER SETUP CODE makes whoever reads it first the owner of the skwod
/// (release audit M6). So that code goes only to:
/// - a loopback peer, and
/// - the container's default gateway: with the admin port published on `127.0.0.1` (the
///   shipped compose file), a browser on the Docker host arrives from the bridge gateway —
///   an address that never leaves that machine. Read from `/proc/net/route`; elsewhere there
///   is no such peer.
/// - anything the operator names in `SKWOD_ADMIN_LOCAL_PEERS` (addresses or CIDRs), for
///   setups this cannot see through.
fn is_local_peer(peer: std::net::IpAddr, extra: &[crate::client_key::IpNet]) -> bool {
    let peer = crate::client_key::canonical(peer);
    peer.is_loopback() || extra.iter().any(|n| n.contains(peer)) || default_gateway().is_some_and(|gw| std::net::IpAddr::V4(gw) == peer)
}

fn local_peers_from_env() -> Vec<crate::client_key::IpNet> {
    std::env::var("SKWOD_ADMIN_LOCAL_PEERS").map(|v| crate::client_key::parse_trusted_proxies(&v)).unwrap_or_default()
}

/// The IPv4 default gateway, only when this process runs in a container (`/.dockerenv` or
/// `/run/.containerenv`): on a bare host the gateway is the LAN's router, not "this machine".
fn default_gateway() -> Option<std::net::Ipv4Addr> {
    if !std::path::Path::new("/.dockerenv").exists() && !std::path::Path::new("/run/.containerenv").exists() {
        return None;
    }
    gateway_from_route_table(&std::fs::read_to_string("/proc/net/route").ok()?)
}

/// The gateway of the default route in a Linux `/proc/net/route` table (hex, little-endian).
fn gateway_from_route_table(table: &str) -> Option<std::net::Ipv4Addr> {
    table.lines().skip(1).find_map(|line| {
        let mut cols = line.split_whitespace();
        let (_iface, dest, gateway) = (cols.next()?, cols.next()?, cols.next()?);
        if dest != "00000000" {
            return None;
        }
        let raw = u32::from_str_radix(gateway, 16).ok().filter(|g| *g != 0)?;
        Some(std::net::Ipv4Addr::from(raw.to_le_bytes()))
    })
}

/// The invite to show right now, if any: `(link, kind, expires_at)`. `local` = the caller is
/// on this machine ([`is_local_peer`]); the owner setup code is shown to nobody else.
async fn current_invite(ctl: &HostControl, local: bool) -> Option<(String, &'static str, Option<i64>)> {
    let st = ctl.status();
    if st.phase != Phase::Running {
        return None;
    }
    if !ctl.owner_claimed().await {
        if !local {
            return None;
        }
        let code = st.setup_code?;
        return Some((ctl.invite(Some(&code))?, "owner", None));
    }
    match st.friend_invite.filter(|(_, exp)| *exp > now_ms()) {
        Some((code, exp)) => Some((ctl.invite(Some(&code))?, "friend", Some(exp))),
        None => Some((ctl.invite(None)?, "address", None)),
    }
}

async fn status(State(admin): State<Admin>, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Json<Value> {
    let local = is_local_peer(peer.ip(), &local_peers_from_env());
    let ctl = &admin.ctl;
    let st = ctl.status();
    let count = |sql: &'static str| async move { sqlx::query_scalar::<_, i64>(sql).fetch_one(&ctl.state.db).await.unwrap_or(0) };
    let owner_claimed = ctl.owner_claimed().await;
    let invite = current_invite(ctl, local).await.map(|(link, kind, expires_at)| json!({ "link": link, "kind": kind, "expires_at": expires_at }));
    Json(json!({
        "phase": st.phase.as_str(),
        "problem": st.problem,
        "version": env!("CARGO_PKG_VERSION"),
        "owner_claimed": owner_claimed,
        // The unclaimed code is stored only as a hash; after a restart the page offers a new one.
        "needs_new_code": st.phase == Phase::Running && !owner_claimed && st.setup_code.is_none(),
        "invite": invite,
        // Invites nobody else can sign up with until the owner lets people in (or revokes the
        // invite): they have as many accounts waiting as an invite may. A count, never who.
        "invites_full": sqlx::query_scalar::<_, i64>(
            "SELECT CAST(count(*) AS BIGINT) FROM (SELECT s.invite_id FROM invite_signups s JOIN invites i ON i.id = s.invite_id
              WHERE i.status = 'active' AND NOT EXISTS(SELECT 1 FROM server_members m WHERE m.user_id = s.user_id)
              GROUP BY s.invite_id HAVING count(*) >= $1) AS full_invites")
            .bind(ctl.state.invite_pending_signups).fetch_one(&ctl.state.db).await.unwrap_or(0),
        "invite_waiting_cap": ctl.state.invite_pending_signups,
        // The owner setup code exists but is not sent over the network in the clear: open
        // this page on the host itself (or through an SSH tunnel) to see it.
        "setup_code_hidden": st.phase == Phase::Running && !owner_claimed && !local && st.setup_code.is_some(),
        // Counts only: the admin page never learns who.
        "members": count("SELECT count(*) FROM users").await,
        "online": ctl.state.ws_conns.lock().await.len(),
        "spaces": count("SELECT count(*) FROM servers").await,
        "voice": st.voice,
        "p2p": st.p2p,
        "local_discovery": st.local_discovery,
        "public_fallback": ctl.state.p2p.get().map(|p| p.public_fallback),
        "local_only": admin.auth.loopback_only,
    }))
}

async fn qr(State(admin): State<Admin>, ConnectInfo(peer): ConnectInfo<SocketAddr>) -> Response {
    let Some((link, _, _)) = current_invite(&admin.ctl, is_local_peer(peer.ip(), &local_peers_from_env())).await else { return StatusCode::NOT_FOUND.into_response() };
    match qrcode::QrCode::new(link.as_bytes()) {
        Ok(code) => {
            let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(240, 240).quiet_zone(true).build();
            ([(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn outcome(result: Result<(), String>) -> Response {
    match result {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e }))).into_response(),
    }
}

async fn start(State(admin): State<Admin>) -> Response {
    let ctl = admin.ctl.clone();
    // Detached: the click must not be cancelled half-way if the browser tab goes away.
    let res = tokio::spawn(async move {
        ctl.start().await?;
        // Unclaimed and the code is not in memory (a restart since it was shown): make a new one.
        if !ctl.owner_claimed().await && ctl.status().setup_code.is_none() && crate::join::signup_requires_code(&ctl.state).await.unwrap_or(false) {
            ctl.rotate_setup_code().await.map_err(str::to_string)?;
        }
        Ok(())
    })
    .await
    .unwrap_or_else(|_| Err("start was interrupted".to_string()));
    outcome(res)
}

async fn stop(State(admin): State<Admin>) -> Response {
    let ctl = admin.ctl.clone();
    let _ = tokio::spawn(async move { ctl.stop(true).await }).await;
    outcome(Ok(()))
}

async fn restart(State(admin): State<Admin>) -> Response {
    let ctl = admin.ctl.clone();
    outcome(tokio::spawn(async move { ctl.restart().await }).await.unwrap_or_else(|_| Err("restart was interrupted".to_string())))
}

/// A fresh invite: a new owner setup code while unclaimed, an approval-required friend invite after.
async fn new_invite(State(admin): State<Admin>) -> Response {
    let res = if admin.ctl.owner_claimed().await {
        admin.ctl.friend_invite().await.map(|_| ())
    } else {
        admin.ctl.rotate_setup_code().await.map(|_| ())
    };
    outcome(res.map_err(str::to_string))
}

#[derive(Deserialize)]
struct Toggle {
    enabled: bool,
}

/// "Let people on this Wi-Fi find my server faster" — opt-in LAN announcement.
async fn local_discovery(State(admin): State<Admin>, Json(req): Json<Toggle>) -> Response {
    let ctl = admin.ctl.clone();
    outcome(tokio::spawn(async move { ctl.set_local_discovery(req.enabled).await }).await.unwrap_or_else(|_| Err("interrupted".to_string())))
}

/// End the whole process cleanly (the desktop host app's Quit). Local page only.
async fn quit(State(admin): State<Admin>) -> Response {
    if !admin.auth.loopback_only {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "stop the container instead" }))).into_response();
    }
    admin.ctl.quit.notify_one();
    outcome(Ok(()))
}

/// Bind the admin page and announce how to get in. `listen` is `ip:port`.
pub async fn serve(ctl: Arc<HostControl>, listen: &str, data: &Path) -> Result<tokio::task::JoinHandle<()>, String> {
    let addr: SocketAddr = listen.parse().map_err(|_| format!("admin listen address {listen:?} is not ip:port"))?;
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("cannot bind the admin page on {addr}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;
    let loopback_only = addr.ip().is_loopback();
    let (auth, token, launch) = AdminAuth::new(loopback_only);
    let launch_file = data.join(LAUNCH_FILE);
    let _ = std::fs::remove_file(&launch_file);
    if loopback_only {
        println!("[skwod] Admin page: http://{addr}/   (this computer only)");
        if let Some(key) = launch {
            // The desktop host app opens this; the key rides in the fragment, which browsers
            // never send to a server or put in a Referer.
            // Second line: who wrote this, so the app can tell a live server from a stale file.
            if let Err(e) = write_private(&launch_file, &format!("http://{addr}/#k={key}\npid={}\n", std::process::id())) {
                tracing::warn!(error = %e, "could not write the admin launch file");
            }
        }
    } else {
        println!("[skwod] Admin page: http://<this machine's address>:{}/", addr.port());
    }
    println!("[skwod] One-time admin token: {token}");
    println!("[skwod] (works once; restart for a new one)");
    let app = router(Admin { ctl, auth: Arc::new(auth) });
    Ok(tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    }))
}

fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(contents.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn admin(loopback_only: bool) -> (Router, Arc<HostControl>, String, Option<String>, tempfile::TempDir) {
        let state = crate::tests::test_state().await;
        let dir = tempfile::tempdir().unwrap();
        let api = crate::api::router(state.clone());
        // p2p off: these tests are about the page, not the network.
        let ctl = Arc::new(HostControl::new(state, api, dir.path().to_path_buf(), None));
        let (auth, token, launch) = AdminAuth::new(loopback_only);
        (router(Admin { ctl: ctl.clone(), auth: Arc::new(auth) }), ctl, token, launch, dir)
    }

    struct Call<'a> {
        method: &'a str,
        path: &'a str,
        cookie: Option<&'a str>,
        body: Option<Value>,
        host: &'a str,
        peer: &'a str,
        header: bool,
        origin: Option<&'a str>,
    }

    impl<'a> Call<'a> {
        fn new(method: &'a str, path: &'a str) -> Self {
            Self { method, path, cookie: None, body: None, host: "127.0.0.1:3477", peer: "127.0.0.1:50000", header: true, origin: None }
        }
    }

    async fn call(app: &Router, c: Call<'_>) -> (StatusCode, HeaderMap, Value) {
        let mut req = axum::http::Request::builder().method(c.method).uri(c.path).header(header::HOST, c.host);
        if c.header {
            req = req.header("x-skwod-admin", "1");
        }
        if let Some(o) = c.origin {
            req = req.header(header::ORIGIN, o);
        }
        if let Some(ck) = c.cookie {
            req = req.header(header::COOKIE, format!("{COOKIE}={ck}"));
        }
        let mut req = match c.body {
            Some(v) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(v.to_string())).unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        req.extensions_mut().insert(ConnectInfo(c.peer.parse::<SocketAddr>().unwrap()));
        let res = app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn session_of(headers: &HeaderMap) -> String {
        let set = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(set.contains("HttpOnly") && set.contains("SameSite=Strict"));
        set.split(';').next().unwrap().split_once('=').unwrap().1.to_string()
    }

    async fn login(app: &Router, token: &str) -> String {
        let (status, headers, _) = call(app, Call { body: Some(json!({ "token": token })), ..Call::new("POST", "/admin/api/login") }).await;
        assert_eq!(status, StatusCode::OK);
        session_of(&headers)
    }

    #[tokio::test]
    async fn the_token_works_once_and_everything_else_needs_the_session() {
        let (app, _ctl, token, _launch, _dir) = admin(false).await;
        // The page shell is public; the data is not.
        assert_eq!(call(&app, Call::new("GET", "/")).await.0, StatusCode::OK);
        for path in ["/admin/api/status", "/admin/api/qr.svg"] {
            assert_eq!(call(&app, Call::new("GET", path)).await.0, StatusCode::UNAUTHORIZED, "{path}");
        }
        for path in ["/admin/api/start", "/admin/api/stop", "/admin/api/restart", "/admin/api/invite", "/admin/api/quit", "/admin/api/local-discovery"] {
            assert_eq!(call(&app, Call::new("POST", path)).await.0, StatusCode::UNAUTHORIZED, "{path}");
        }
        let wrong = Call { body: Some(json!({ "token": "AAAAA-AAAAA-AAAAA-AAAAA" })), ..Call::new("POST", "/admin/api/login") };
        assert_eq!(call(&app, wrong).await.0, StatusCode::UNAUTHORIZED);
        // Typed sloppily (lower case, spaces) still works — once.
        let session = login(&app, &token.to_lowercase().replace('-', " ")).await;
        let again = Call { body: Some(json!({ "token": token })), ..Call::new("POST", "/admin/api/login") };
        assert_eq!(call(&app, again).await.0, StatusCode::UNAUTHORIZED, "one-time means one time");
        let (status, _, body) = call(&app, Call { cookie: Some(&session), ..Call::new("GET", "/admin/api/status") }).await;
        assert_eq!((status, body["phase"].as_str()), (StatusCode::OK, Some("stopped")));
        assert_eq!(call(&app, Call { cookie: Some("deadbeef"), ..Call::new("GET", "/admin/api/status") }).await.0, StatusCode::UNAUTHORIZED);
        // Logout kills the session.
        assert_eq!(call(&app, Call { cookie: Some(&session), ..Call::new("POST", "/admin/api/logout") }).await.0, StatusCode::OK);
        assert_eq!(call(&app, Call { cookie: Some(&session), ..Call::new("GET", "/admin/api/status") }).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cross_site_requests_and_rebinding_are_refused() {
        let (app, _ctl, token, launch, _dir) = admin(true).await;
        let session = login(&app, &token).await;
        let authed = |method: &'static str, path: &'static str| Call { cookie: Some(&session), ..Call::new(method, path) };
        // No custom header (what a cross-site <form> or no-cors fetch can send).
        assert_eq!(call(&app, Call { header: false, ..authed("POST", "/admin/api/stop") }).await.0, StatusCode::FORBIDDEN);
        // A foreign Origin.
        assert_eq!(call(&app, Call { origin: Some("http://evil.example"), ..authed("POST", "/admin/api/stop") }).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&app, Call { origin: Some("http://127.0.0.1:3477"), ..authed("POST", "/admin/api/stop") }).await.0, StatusCode::OK);
        // DNS rebinding: the browser thinks it is talking to evil.example.
        assert_eq!(call(&app, Call { host: "evil.example:3477", ..authed("GET", "/admin/api/status") }).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&app, Call { host: "evil.example:3477", ..Call::new("GET", "/") }).await.0, StatusCode::FORBIDDEN);
        // Only GET and POST exist.
        assert_eq!(call(&app, authed("DELETE", "/admin/api/status")).await.0, StatusCode::FORBIDDEN);
        // The launch key (desktop app) is reusable — from this machine only.
        let key = launch.unwrap();
        for _ in 0..2 {
            let (status, _, _) = call(&app, Call { body: Some(json!({ "token": key })), ..Call::new("POST", "/admin/api/login") }).await;
            assert_eq!(status, StatusCode::OK);
        }
        let remote = Call { body: Some(json!({ "token": key })), peer: "192.168.1.50:40000", ..Call::new("POST", "/admin/api/login") };
        assert_eq!(call(&app, remote).await.0, StatusCode::UNAUTHORIZED);
        // Every response carries the hardening headers.
        let (_, headers, _) = call(&app, Call::new("GET", "/")).await;
        assert!(headers.get("content-security-policy").unwrap().to_str().unwrap().contains("script-src 'self'"));
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert!(headers.get("access-control-allow-origin").is_none());
    }

    /// A loopback-bound page whose auth state the test can reach.
    async fn local_admin() -> (Router, Arc<AdminAuth>, String, tempfile::TempDir) {
        let state = crate::tests::test_state().await;
        let dir = tempfile::tempdir().unwrap();
        let ctl = Arc::new(HostControl::new(state.clone(), crate::api::router(state), dir.path().to_path_buf(), None));
        let (auth, _token, launch) = AdminAuth::new(true);
        let auth = Arc::new(auth);
        (router(Admin { ctl, auth: auth.clone() }), auth, launch.unwrap(), dir)
    }

    #[tokio::test]
    async fn the_listener_proves_it_holds_the_launch_key_before_any_credential_is_sent() {
        use hmac::Mac;
        let (app, _auth, launch, _dir) = local_admin().await;
        let nonce = "0123456789abcdef".repeat(4);
        let ask = |nonce: &str, peer: &'static str| Call { body: Some(json!({ "nonce": nonce })), peer, ..Call::new("POST", "/admin/api/challenge") };
        // No session needed; the answer is what only a holder of the key can compute.
        let (status, _, body) = call(&app, ask(&nonce, "127.0.0.1:50000")).await;
        assert_eq!(status, StatusCode::OK);
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(&digest(&launch)).unwrap();
        mac.update(b"skwod-admin-challenge-v1:");
        mac.update(nonce.as_bytes());
        let expected: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(body["proof"], expected.as_str());
        // A different nonce gives a different proof (no replaying an old answer).
        let (_, _, other) = call(&app, ask(&"f".repeat(64), "127.0.0.1:50000")).await;
        assert_ne!(other["proof"], body["proof"]);
        // The proof is not the key and does not sign in.
        assert_ne!(expected, launch);
        let try_it = Call { body: Some(json!({ "token": expected })), ..Call::new("POST", "/admin/api/login") };
        assert_eq!(call(&app, try_it).await.0, StatusCode::UNAUTHORIZED);
        // Malformed nonces, other machines, and LAN-bound pages (no launch key) get nothing.
        for bad in ["", "short", &"g".repeat(64), &"a".repeat(200)] {
            assert_eq!(call(&app, ask(bad, "127.0.0.1:50000")).await.0, StatusCode::FORBIDDEN, "{bad}");
        }
        assert_eq!(call(&app, ask(&nonce, "192.168.1.50:40000")).await.0, StatusCode::FORBIDDEN);
        let (lan, _ctl, _token, _launch, _dir) = admin(false).await;
        let c = Call { host: "tower.local:3477", peer: "192.168.1.50:40000", body: Some(json!({ "nonce": nonce })), ..Call::new("POST", "/admin/api/challenge") };
        assert_eq!(call(&lan, c).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn the_launch_file_names_the_process_that_wrote_it() {
        let state = crate::tests::test_state().await;
        let dir = tempfile::tempdir().unwrap();
        let ctl = Arc::new(HostControl::new(state.clone(), crate::api::router(state), dir.path().to_path_buf(), None));
        let task = serve(ctl, "127.0.0.1:0", dir.path()).await.unwrap();
        let text = std::fs::read_to_string(dir.path().join(LAUNCH_FILE)).unwrap();
        let mut lines = text.lines();
        let url = lines.next().unwrap();
        assert!(url.starts_with("http://127.0.0.1:") && url.contains("/#k="), "{url}");
        assert_eq!(lines.next(), Some(format!("pid={}", std::process::id()).as_str()));
        assert_eq!(lines.next(), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.path().join(LAUNCH_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        task.abort();
    }

    #[tokio::test]
    async fn a_ticket_signs_a_browser_in_once_from_this_machine_only() {
        let (app, _auth, launch, _dir) = local_admin().await;
        let session = login(&app, &launch).await;
        // Needs a session.
        assert_eq!(call(&app, Call::new("POST", "/admin/api/ticket")).await.0, StatusCode::UNAUTHORIZED);
        let mint = || async {
            let (status, _, body) = call(&app, Call { cookie: Some(&session), ..Call::new("POST", "/admin/api/ticket") }).await;
            assert_eq!(status, StatusCode::OK);
            body["ticket"].as_str().unwrap().to_string()
        };
        let ticket = mint().await;
        assert_eq!(ticket.len(), 64);
        const PAGE: &str = "http://127.0.0.1:3477";
        // Not from another machine, not without the page's Origin (a local process that read the
        // ticket somewhere and replays it with curl), not with someone else's Origin — and none
        // of those attempts burns it.
        let attempt = |peer: &'static str, origin: Option<&'static str>| Call { body: Some(json!({ "token": ticket })), peer, origin, ..Call::new("POST", "/admin/api/login") };
        assert_eq!(call(&app, attempt("192.168.1.50:40000", Some(PAGE))).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, attempt("127.0.0.1:50000", None)).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, attempt("127.0.0.1:50000", Some("http://127.0.0.1:9999"))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&app, attempt("127.0.0.1:50000", Some("null"))).await.0, StatusCode::FORBIDDEN);
        // …once from the page, never twice.
        let (status, headers, _) = call(&app, attempt("127.0.0.1:50000", Some(PAGE))).await;
        assert_eq!(status, StatusCode::OK);
        let browser = session_of(&headers);
        assert_eq!(call(&app, Call { cookie: Some(&browser), ..Call::new("GET", "/admin/api/status") }).await.0, StatusCode::OK);
        assert_eq!(call(&app, attempt("127.0.0.1:50000", Some(PAGE))).await.0, StatusCode::UNAUTHORIZED);
        // It lives ten seconds: one that has aged out is refused (and gone).
        assert_eq!(TICKET_TTL_MS, 10_000);
        let old = mint().await;
        for exp in _auth.tickets.lock().unwrap().values_mut() {
            *exp = now_ms() - 1;
        }
        let aged = Call { body: Some(json!({ "token": old })), origin: Some(PAGE), ..Call::new("POST", "/admin/api/login") };
        assert_eq!(call(&app, aged).await.0, StatusCode::UNAUTHORIZED);
        assert!(_auth.tickets.lock().unwrap().is_empty());
        // A LAN-bound page never mints tickets.
        let (lan, _ctl, token, _launch, _dir) = admin(false).await;
        let c = Call { host: "tower.local:3477", peer: "192.168.1.50:40000", body: Some(json!({ "token": token })), ..Call::new("POST", "/admin/api/login") };
        let lan_session = session_of(&call(&lan, c).await.1);
        let c = Call { host: "tower.local:3477", peer: "192.168.1.50:40000", cookie: Some(&lan_session), ..Call::new("POST", "/admin/api/ticket") };
        assert_eq!(call(&lan, c).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_lan_bound_page_has_no_launch_key_and_cannot_quit_the_process() {
        let (app, _ctl, token, launch, _dir) = admin(false).await;
        assert!(launch.is_none());
        // Reached by LAN name/IP: allowed (the token is the gate there).
        let c = Call { host: "tower.local:3477", peer: "192.168.1.50:40000", body: Some(json!({ "token": token })), ..Call::new("POST", "/admin/api/login") };
        let (status, headers, _) = call(&app, c).await;
        assert_eq!(status, StatusCode::OK);
        let session = session_of(&headers);
        let c = Call { host: "tower.local:3477", cookie: Some(&session), ..Call::new("POST", "/admin/api/quit") };
        assert_eq!(call(&app, c).await.0, StatusCode::FORBIDDEN);
    }

    /// Release audit M6: the owner setup code never crosses the network in the clear, and
    /// one device on the LAN cannot lock the host out of signing in.
    #[tokio::test]
    async fn m6_the_owner_setup_code_goes_to_this_machine_only_and_login_attempts_are_counted_per_peer() {
        let (app, ctl, token, _launch, _dir) = admin(false).await;
        let lan = |method: &'static str, path: &'static str| Call { host: "tower.local:3477", peer: "192.168.1.50:40000", ..Call::new(method, path) };
        // Ten wrong tokens from one LAN device use up THAT device's attempts, nobody else's.
        for _ in 0..10 {
            let c = Call { peer: "192.168.1.66:40000", body: Some(json!({ "token": "wrong" })), ..lan("POST", "/admin/api/login") };
            assert_eq!(call(&app, c).await.0, StatusCode::UNAUTHORIZED);
        }
        let c = Call { peer: "192.168.1.66:40000", body: Some(json!({ "token": "wrong" })), ..lan("POST", "/admin/api/login") };
        assert_eq!(call(&app, c).await.0, StatusCode::TOO_MANY_REQUESTS);
        let (status, headers, _) = call(&app, Call { body: Some(json!({ "token": token })), ..lan("POST", "/admin/api/login") }).await;
        assert_eq!(status, StatusCode::OK, "the host signs in from another address");
        let session = session_of(&headers);
        assert_eq!(call(&app, Call { cookie: Some(&session), ..lan("POST", "/admin/api/start") }).await.0, StatusCode::OK);
        assert!(ctl.status().setup_code.is_some());
        // Signed in from another machine: the page says there is a code, and does not send it.
        let (_, _, st) = call(&app, Call { cookie: Some(&session), ..lan("GET", "/admin/api/status") }).await;
        assert_eq!((st["setup_code_hidden"].as_bool(), st["invite"].is_null()), (Some(true), true), "{st}");
        assert_eq!(call(&app, Call { cookie: Some(&session), ..lan("GET", "/admin/api/qr.svg") }).await.0, StatusCode::NOT_FOUND);
        assert!(current_invite(&ctl, false).await.is_none());
        // On this machine it is shown.
        let (_, _, st) = call(&app, Call { cookie: Some(&session), host: "tower.local:3477", ..Call::new("GET", "/admin/api/status") }).await;
        assert_eq!(st["setup_code_hidden"], false, "{st}");

        // "This machine", seen from inside a container, is the default gateway and nothing else.
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\neth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        assert_eq!(gateway_from_route_table(table), Some("172.17.0.1".parse().unwrap()));
        assert_eq!(gateway_from_route_table("Iface\tDestination\tGateway\n"), None);
        let named = crate::client_key::parse_trusted_proxies("10.9.0.0/24");
        assert!(is_local_peer("127.0.0.1".parse().unwrap(), &[]) && is_local_peer("::1".parse().unwrap(), &[]));
        assert!(!is_local_peer("192.168.1.50".parse().unwrap(), &[]) && !is_local_peer("172.17.0.1".parse().unwrap(), &[]), "not in a container: the gateway is the LAN's router");
        assert!(is_local_peer("10.9.0.7".parse().unwrap(), &named) && !is_local_peer("10.9.1.7".parse().unwrap(), &named));
    }

    #[tokio::test]
    async fn start_shows_an_owner_invite_then_friend_invites_need_a_space_and_stop_refuses_the_api() {
        let (app, ctl, token, _launch, _dir) = admin(true).await;
        let session = login(&app, &token).await;
        let authed = |method: &'static str, path: &'static str| Call { cookie: Some(&session), ..Call::new(method, path) };
        let api = crate::api::router(ctl.state.clone());

        assert_eq!(call(&app, authed("POST", "/admin/api/start")).await.0, StatusCode::OK);
        let (_, _, st) = call(&app, authed("GET", "/admin/api/status")).await;
        assert_eq!(st["phase"], "running");
        assert_eq!(st["owner_claimed"], false);
        assert_eq!(st["members"], 0);
        // p2p is off in this test, so there is no node id to build a link from; the setup code
        // itself is what gates signup.
        let code = ctl.status().setup_code.expect("start created the owner code");
        let signup = |name: &'static str, code: Option<String>| {
            let api = api.clone();
            async move { crate::tests::send(&api, "POST", "/api/auth/signup", None, Some(json!({ "username": name, "password": "password123", "join_code": code }))).await }
        };
        assert_eq!(signup("stranger", None).await.0, StatusCode::FORBIDDEN, "a started server is never open");
        // "New invite" before anyone owns it replaces the code: the old one dies.
        assert_eq!(call(&app, authed("POST", "/admin/api/invite")).await.0, StatusCode::OK);
        let fresh = ctl.status().setup_code.unwrap();
        assert_ne!(code, fresh);
        assert_eq!(signup("owner", Some(code)).await.0, StatusCode::FORBIDDEN);
        let (status, owner) = signup("owner", Some(fresh)).await;
        assert_eq!(status, StatusCode::OK);
        let (_, _, st) = call(&app, authed("GET", "/admin/api/status")).await;
        assert_eq!((st["owner_claimed"].as_bool(), st["members"].as_i64()), (Some(true), Some(1)));

        // Friend invites: need a space; then they are approval-required codes from the owner.
        assert_eq!(call(&app, authed("POST", "/admin/api/invite")).await.0, StatusCode::INTERNAL_SERVER_ERROR);
        let owner_token = owner["token"].as_str().unwrap();
        let (status, _) = crate::tests::send(&api, "POST", "/api/servers", Some(owner_token), Some(json!({ "name_ciphertext": "AAAA" }))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(call(&app, authed("POST", "/admin/api/invite")).await.0, StatusCode::OK);
        let (invite, _) = ctl.status().friend_invite.unwrap();
        let (kind, approval, inviter): (String, i64, String) =
            sqlx::query_as("SELECT kind, requires_approval, inviter_id FROM invites WHERE code = $1").bind(&invite).fetch_one(&ctl.state.db).await.unwrap();
        assert_eq!((kind.as_str(), approval, inviter.as_str()), ("code", 1, owner["user_id"].as_str().unwrap()));

        // Stop: the API refuses everyone (health stays up), and the choice is remembered.
        assert_eq!(call(&app, authed("POST", "/admin/api/stop")).await.0, StatusCode::OK);
        assert_eq!(crate::tests::send(&api, "GET", "/api/auth/me", Some(owner_token), None).await.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(crate::tests::send(&api, "GET", "/health", None, None).await.0, StatusCode::OK);
        assert!(!ctl.should_autostart().await);
        assert_eq!(call(&app, authed("POST", "/admin/api/restart")).await.0, StatusCode::OK);
        assert_eq!(crate::tests::send(&api, "GET", "/api/auth/me", Some(owner_token), None).await.0, StatusCode::OK);
        assert!(ctl.should_autostart().await);
    }
}
