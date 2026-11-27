//! Server API + realtime client.
//!
//! [`ApiClient`] is a thin typed wrapper over the Phase-2 REST API (opaque ciphertext in/out —
//! this layer never sees plaintext; the [`crate::engine`] encrypts before calling it).
//! [`RealtimeClient`] owns the WebSocket: connect, auth, (re)subscribe, and yield events; the
//! caller reconnects and backfills over REST after a gap.

use serde::de::DeserializeOwned;
use serde_json::{json, Value};

/// Hard cap on a response body we will buffer (bytes). The server is untrusted; without a cap a
/// hostile or buggy server could stream an unbounded body and exhaust memory. 8 MiB comfortably
/// covers any JSON response this client expects (message pages are ciphertext-bounded).
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// Read a response body into a `String`, aborting if it exceeds `max` bytes. Streams chunk-by-chunk
/// so a chunked/unknown-length body can't blow past the cap (the `Content-Length` fast-path only
/// catches servers that honestly advertise the size).
async fn read_body_capped(mut res: reqwest::Response, max: usize) -> Result<String, ClientError> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| ClientError::Transport(e.to_string()))? {
        if buf.len() + chunk.len() > max {
            return Err(ClientError::Transport("response body exceeds maximum size".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| ClientError::Shape)
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("http status {status}: {body}")]
    Status { status: u16, body: String },
    #[error("transport error: {0}")]
    Transport(String),
    #[error("unexpected response shape")]
    Shape,
    /// NOT sent: this client presents a front credential that is not the one signed in there now
    /// (another sign-in, a sign-out, a re-key). Local — it says nothing about the session on the
    /// host; the app binds again.
    #[error("this connection's sign-in was replaced; reconnecting")]
    StaleCredential,
}

/// What a client knows about the session behind its token ([`ApiClient::session_check`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCheck {
    Valid,
    /// The HOST refused this client's CURRENT token, twice.
    Ended,
    /// Nothing is known: no answer, nothing sent, or not about the current token.
    Unknown,
}

/// The app build this core ships in. Named on every authenticated request (`x-skwod-build`) so
/// a server can tell a build that can no longer take part to update, in words — instead of the
/// guessing it has to do for builds ≤ 43, which named nothing. Bump with the wire format.
pub const CLIENT_BUILD: u32 = 44;
const BUILD_HEADER: &str = "x-skwod-build";

/// Is `id` a blob id as a server mints them — a canonical, lowercase, hyphenated UUID?
///
/// A blob id comes from the SERVER, and it ends up in two places a server must not be able to
/// write into: a request path, and the attachment descriptor inside an end-to-end encrypted
/// message (which recipients take as the sender's words). Anything that is not exactly a UUID
/// is refused wherever one is received or used.
pub fn valid_blob_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

/// What a chunk upload was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkOutcome {
    /// Accepted; the blob now holds this many bytes, and is (or is not) complete.
    Accepted { offset: u64, complete: bool },
    /// The server holds a different number of bytes than the chunk assumed: continue from here.
    Mismatch { offset: u64 },
}

/// Typed REST client. Cheap to clone (shares the reqwest pool).
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    base: String,
    token: Option<String>,
}

/// Reject plaintext `http://` to a NON-loopback host — the bearer token + E2EE routing metadata
/// would travel in the clear to a passive network attacker. Only loopback LITERALS
/// (`localhost`/`127.0.0.1`/`::1`) stay allowed — the host's own connection to its bundled server.
/// `.local` (mDNS) names are NOT exempt: they resolve over a real LAN a passive attacker can watch,
/// so they must use TLS like any other remote address.
fn is_insecure_remote(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or("");
    !(host == "localhost" || host == "127.0.0.1" || host == "::1")
}

/// Base URLs of loopback proxies that were closed (`retire_base`). Once a session's proxy lets go
/// of its port another local process could listen there, so a client built for that URL — one a
/// screen may still hold — never sends anything (its bearer token above all) to it again.
fn retired() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static RETIRED: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::OnceLock::new();
    RETIRED.get_or_init(Default::default)
}

/// Mark a loopback proxy's base URL as closed for good (called before its port is released).
pub fn retire_base(base_url: &str) {
    let mut set = retired().lock().unwrap_or_else(|e| e.into_inner());
    // Bounded: a front URL carries 128 random bits and is never reused, so forgetting the
    // oldest of many costs nothing (fronts that are gone also fail closed by shape).
    if set.len() >= MAX_RETIRED { set.clear(); }
    set.insert(base_url.trim_end_matches('/').to_string());
}

const MAX_RETIRED: usize = 1024;

/// Was this base URL retired? (Exact match: the URL carries the proxy's random secret.)
pub fn is_retired_base(base_url: &str) -> bool {
    retired().lock().unwrap_or_else(|e| e.into_inner()).contains(base_url.trim_end_matches('/'))
}

// ---- Build 51: the bearer never crosses loopback -------------------------------------------
//
// A p2p skwod is reached through a loopback front (`skwod_net::proxy`) in this process. The
// session token is kept HERE, in the core, per front, and set ONLY by an explicit sign-in
// ([`front_sign_in`], [`front_rotate`]) — never as a side effect of building a client. A sign-in
// hands out an opaque random credential `front-<hex>`; clients of that front hold and send ONLY
// that (`Authorization: Bearer front-<hex>`), and the front swaps it for the token on its way to
// the host. A request with no Authorization gets none (sealed-sender deposits stay anonymous);
// an unknown or signed-out credential is refused, not sent; the real token never exists in a client of a
// front and never crosses loopback.

/// The prefix of a front credential.
pub const FRONT_CREDENTIAL_PREFIX: &str = "front-";

#[derive(Default)]
struct FrontEntry {
    /// The port the front listens on: a base URL counts only with this exact port AND secret.
    port: u16,
    /// (credential, token) of the session signed in now; None = signed out.
    signed_in: Option<(String, String)>,
    /// SUSPECT: the app went to the background, or the listener failed — the port may be held
    /// by someone else now. Nothing at all is sent to it until a challenge proves it ours again.
    /// PER SESSION (the same object whichever secret is current — a re-key moves it along).
    suspicion: std::sync::Arc<Suspicion>,
}

/// Build 51: whether a front (a session) is SUSPECT, and the epoch of the latest suspicion. Lives
/// with the session, not with a secret: a re-key in progress cannot lose it.
#[derive(Debug, Default)]
pub struct Suspicion {
    /// How many suspicions were raised (the epoch).
    raised: std::sync::atomic::AtomicU64,
    /// The highest epoch a proof has cleared. Suspect = raised > cleared — one atomic each,
    /// nothing stored and restored.
    cleared: std::sync::atomic::AtomicU64,
}

impl Suspicion {
    /// Suspect from now on (going to the background, a listener failure). Returns the new epoch.
    pub fn raise(&self) -> u64 { self.raised.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1 }
    /// The epoch now: capture it BEFORE a challenge.
    pub fn epoch(&self) -> u64 { self.raised.load(std::sync::atomic::Ordering::SeqCst) }
    pub fn is_suspect(&self) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        self.raised.load(SeqCst) > self.cleared.load(SeqCst)
    }
    /// A proof that started at `epoch`: clears every suspicion up to it, none raised after.
    /// Returns whether the front is clear now.
    pub fn clear_if(&self, epoch: u64) -> bool {
        self.cleared.fetch_max(epoch, std::sync::atomic::Ordering::SeqCst);
        !self.is_suspect()
    }
}

fn fronts() -> &'static std::sync::Mutex<std::collections::HashMap<String, FrontEntry>> {
    static FRONTS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, FrontEntry>>> = std::sync::OnceLock::new();
    FRONTS.get_or_init(Default::default)
}

/// A front came up on `port` (keyed by its secret), with its session's [`Suspicion`]. Signed out.
pub fn register_front_with(secret: &str, port: u16, suspicion: std::sync::Arc<Suspicion>) {
    fronts().lock().unwrap_or_else(|e| e.into_inner()).insert(secret.to_string(), FrontEntry { port, signed_in: None, suspicion });
}

/// [`register_front_with`] a fresh, unsuspected session (tests, simple callers).
pub fn register_front(secret: &str, port: u16) {
    register_front_with(secret, port, std::sync::Arc::default());
}

/// The front is gone: its session goes with it.
pub fn unregister_front(secret: &str) {
    fronts().lock().unwrap_or_else(|e| e.into_inner()).remove(secret);
}

/// The front's secret, if `base_url` is the URL of a live front (`http://127.0.0.1:<port>/<secret>`).
pub fn front_secret_of(base_url: &str) -> Option<String> {
    let rest = base_url.strip_prefix("http://127.0.0.1:")?;
    let mut parts = rest.split('/');
    let port: u16 = parts.next()?.parse().ok()?;
    let secret = parts.next()?.split(['?', '#']).next()?;
    let map = fronts().lock().unwrap_or_else(|e| e.into_inner());
    (!secret.is_empty() && map.get(secret).is_some_and(|e| e.port == port)).then(|| secret.to_string())
}

/// Is `base_url` a live front?
pub fn is_front_base(base_url: &str) -> bool {
    front_secret_of(base_url).is_some()
}

/// Does `s` look like a front credential (never a token)?
pub fn is_front_credential(s: &str) -> bool {
    s.strip_prefix(FRONT_CREDENTIAL_PREFIX).is_some_and(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Explicit sign-in (log in, sign up, pairing, a restored session): this front's session token
/// is `token` from now on, under a NEW credential — every earlier credential stops working.
/// Idempotent: for the token already signed in, the credential it has.
/// Returns the credential its clients use; None for an empty token or a front that is gone.
pub fn front_sign_in(secret: &str, token: &str) -> Option<String> {
    if token.is_empty() { return None }
    let mut map = fronts().lock().unwrap_or_else(|e| e.into_inner());
    let entry = map.get_mut(secret)?;
    // The same session again (overlapping binds, a ring check): nothing changes — replacing the
    // credential would cut every client that already holds it.
    if let Some((credential, current)) = &entry.signed_in {
        if ct_eq(current.as_bytes(), token.as_bytes()) { return Some(credential.clone()); }
    }
    let credential = format!("{FRONT_CREDENTIAL_PREFIX}{}", hex::encode(rand::random::<[u8; 16]>()));
    entry.signed_in = Some((credential.clone(), token.to_string()));
    Some(credential)
}

/// Build 51: the front listens again under a new secret (and maybe port). In ONE step under the
/// registry lock: the old entry goes; the new one is registered at `port`; and if — and only if —
/// the session was signed in, it is signed in again under a NEW credential (returned). A session
/// signed out before (or concurrently, as long as its sign-out took the lock first) stays signed
/// out: a re-key never re-arms it.
pub fn front_rekey(old_secret: &str, new_secret: &str, port: u16) -> Option<String> {
    let mut map = fronts().lock().unwrap_or_else(|e| e.into_inner());
    let old = map.remove(old_secret);
    // The session's suspicion goes with it: a re-key does not make a front trusted.
    let suspicion = old.as_ref().map(|e| e.suspicion.clone()).unwrap_or_else(|| {
        let s = std::sync::Arc::new(Suspicion::default());
        let _ = s.raise();   // an unknown session is never trusted
        s
    });
    let token = old.and_then(|e| e.signed_in).map(|(_, t)| t);
    let credential = token.as_ref().map(|_| format!("{FRONT_CREDENTIAL_PREFIX}{}", hex::encode(rand::random::<[u8; 16]>())));
    let signed_in = credential.clone().zip(token);
    map.insert(new_secret.to_string(), FrontEntry { port, signed_in, suspicion });
    credential
}

/// The front may not be ours right now (the app went to the background, the listener failed):
/// nothing is sent to it — pre-auth requests included — until [`front_trust`].
pub fn front_suspect(secret: &str) -> Option<()> {
    fronts().lock().unwrap_or_else(|e| e.into_inner()).get(secret).map(|e| { let _ = e.suspicion.raise(); })
}

/// The suspicion epoch now (capture it before a challenge); None for an unknown front.
pub fn front_suspect_epoch(secret: &str) -> Option<u64> {
    fronts().lock().unwrap_or_else(|e| e.into_inner()).get(secret).map(|e| e.suspicion.epoch())
}

/// A challenge proved the front ours: clear SUSPECT only if no new suspicion arose since `epoch`.
/// Unknown front: never cleared (false).
pub fn front_trust_if(secret: &str, epoch: u64) -> bool {
    fronts().lock().unwrap_or_else(|e| e.into_inner()).get(secret).is_some_and(|e| e.suspicion.clear_if(epoch))
}

/// Is the front behind `base_url` suspect (or is it a dead front)? Then send nothing to it.
pub fn is_front_suspect(base_url: &str) -> bool {
    match front_secret_of(base_url) {
        Some(secret) => fronts().lock().unwrap_or_else(|e| e.into_inner()).get(&secret).is_none_or(|e| e.suspicion.is_suspect()),
        None => looks_like_front(base_url),
    }
}

/// Build 51: how the core's own API requests reach a front's host IN PROCESS, over the member
/// connection — never through the loopback port (so passwords at log-in / sign-up, the session
/// token, and everything else the core sends stay off loopback). Set by `skwod-core`.
/// (secret, method, path, headers, body) → (status, body), or None.
pub type FrontTransport = std::sync::Arc<dyn Fn(String, String, String, Vec<(String, String)>, Option<Vec<u8>>)
    -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(u16, Vec<u8>)>> + Send>> + Send + Sync>;

fn transport() -> &'static std::sync::Mutex<Option<FrontTransport>> {
    static T: std::sync::OnceLock<std::sync::Mutex<Option<FrontTransport>>> = std::sync::OnceLock::new();
    T.get_or_init(Default::default)
}

/// Install the in-process transport for fronts (once).
pub fn set_front_transport(t: FrontTransport) {
    let mut slot = transport().lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_none() { *slot = Some(t); }
}

/// Does `base_url` have the shape of a front URL (`http://127.0.0.1:<port>/<32 hex>`)? Then it
/// is either a live front or a dead one — and nothing is sent to a dead one.
pub fn looks_like_front(base_url: &str) -> bool {
    let Some(rest) = base_url.strip_prefix("http://127.0.0.1:") else { return false };
    let mut parts = rest.split('/');
    let port_ok = parts.next().is_some_and(|p| p.parse::<u16>().is_ok());
    let seg = parts.next().map(|s| s.split(['?', '#']).next().unwrap_or("")).unwrap_or("");
    port_ok && seg.len() == 32 && seg.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The token was rotated: the session behind `credential` has `token` now. Refused (false) when
/// that credential is not the one signed in — after a sign-out nothing can set a token again
/// except an explicit [`front_sign_in`].
pub fn front_rotate(secret: &str, credential: &str, token: &str) -> bool {
    if token.is_empty() { return false }
    let mut map = fronts().lock().unwrap_or_else(|e| e.into_inner());
    match map.get_mut(secret).and_then(|e| e.signed_in.as_mut()) {
        Some((c, t)) if c == credential => { *t = token.to_string(); true }
        _ => false,
    }
}

/// Signed out: the front injects nothing for any credential, until an explicit sign-in.
pub fn front_sign_out(secret: &str) {
    if let Some(e) = fronts().lock().unwrap_or_else(|e| e.into_inner()).get_mut(secret) {
        e.signed_in = None;
    }
}

/// Signed out, but only if `credential` is the one signed in now (a stale caller clears nothing).
pub fn front_sign_out_credential(secret: &str, credential: &str) -> bool {
    front_sign_out_if(secret, |c, _| ct_eq(c.as_bytes(), credential.as_bytes()))
}

/// Signed out, but only if `token` is the one signed in now.
pub fn front_sign_out_token(secret: &str, token: &str) -> bool {
    front_sign_out_if(secret, |_, t| ct_eq(t.as_bytes(), token.as_bytes()))
}

fn front_sign_out_if(secret: &str, matches: impl Fn(&str, &str) -> bool) -> bool {
    let mut map = fronts().lock().unwrap_or_else(|e| e.into_inner());
    let Some(e) = map.get_mut(secret) else { return false };
    let hit = e.signed_in.as_ref().is_some_and(|(c, t)| matches(c, t));
    if hit { e.signed_in = None; }
    hit
}

/// What the front injects for `credential`: the token of the session signed in under it, else
/// nothing.
pub fn front_token_for(secret: &str, credential: &str) -> Option<String> {
    let map = fronts().lock().unwrap_or_else(|e| e.into_inner());
    match map.get(secret).and_then(|e| e.signed_in.as_ref()) {
        // Constant time: how much of a guessed credential matched says nothing (review L6).
        Some((c, t)) if ct_eq(c.as_bytes(), credential.as_bytes()) => Some(t.clone()),
        _ => None,
    }
}

/// Equal, in time independent of where the inputs first differ (lengths are not secret: every
/// credential has the same shape).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) { diff |= x ^ y; }
    std::hint::black_box(diff) == 0
}

/// The token signed in on this front now (in-process uses: logout, push unregister, proofs).
pub fn front_current_token(secret: &str) -> Option<String> {
    fronts().lock().unwrap_or_else(|e| e.into_inner()).get(secret).and_then(|e| e.signed_in.as_ref()).map(|(_, t)| t.clone())
}

impl ApiClient {
    /// What goes in the Authorization header. A client of a front holds only its credential;
    /// once the front is gone it sends nothing at all (fail closed).
    fn wire_token<'a>(&self, token: &'a str) -> Result<&'a str, ClientError> {
        if is_front_credential(token) && !is_front_base(&self.base) {
            return Err(ClientError::Transport("this connection to the host was closed; reconnecting".into()));
        }
        if is_front_credential(token) && self.real_token().is_none() { return Err(ClientError::StaleCredential); }
        Ok(token)
    }

    /// Is the session behind this client over? Only the host can say so, only about the token
    /// this client stands for NOW (checked again after each answer: a rotation or another sign-in
    /// meanwhile makes the answer about something else), and only twice.
    pub async fn session_check(&self) -> SessionCheck {
        let Some(token) = self.real_token() else { return SessionCheck::Unknown };
        for attempt in 0..2 {
            if attempt > 0 { tokio::time::sleep(std::time::Duration::from_millis(300)).await; }
            match self.get("/api/auth/me").await {
                Ok(_) => return SessionCheck::Valid,
                Err(ClientError::Status { status: 401, .. }) if self.real_token().as_deref() == Some(token.as_str()) => {}
                Err(_) => return SessionCheck::Unknown,
            }
        }
        SessionCheck::Ended
    }

    /// Fail closed: nothing — with or without a credential — goes to a loopback URL that has a
    /// front's shape but is not a live front (a front that moved, or one that is gone).
    fn dead_front(&self) -> Result<(), ClientError> {
        if looks_like_front(&self.base) && !is_front_base(&self.base) {
            return Err(ClientError::Transport("this connection to the host was closed; reconnecting".into()));
        }
        Ok(())
    }

    /// The session token behind this client, for in-process use only (proofs that hash it):
    /// a front client's credential is resolved through the front, never stored here.
    pub fn real_token(&self) -> Option<String> {
        let t = self.token.as_deref()?;
        if is_front_credential(t) {
            let secret = front_secret_of(&self.base)?;
            return front_token_for(&secret, t);
        }
        Some(t.to_string())
    }

    /// A session token that was just handed out (pairing): on a front it is signed in there —
    /// an explicit sign-in — and the client keeps only the credential; elsewhere it is kept.
    pub fn signed_in(self, token: &str) -> Self {
        match front_secret_of(&self.base) {
            Some(secret) => match front_sign_in(&secret, token) {
                Some(credential) => self.with_token(credential),
                None => Self { token: None, ..self },
            },
            None => self.with_token(token.to_string()),
        }
    }

    pub fn new(base_url: impl Into<String>) -> Self {
        // connect + idle-read timeouts, NOT a total-request timeout: a request to a dead address
        // must fail fast (the moved-skwod recovery path counts failures — a hung request means the
        // beacon lookup never triggers), but a slow, still-flowing blob download must not be cut off.
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .read_timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { http, base: base_url.into().trim_end_matches('/').to_string(), token: None }
    }

    /// The credential this client presents. Empty: none. Decided here, once: a client of a front
    /// accepts only a front credential (`front_sign_in` hands them out) and never stores a real
    /// token — a real token given for a front is dropped (no auth: fail closed). Building a
    /// client never changes what any front injects.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.token = if token.is_empty() {
            None
        } else if looks_like_front(&self.base) {
            // A live front takes only its credential; a dead one takes nothing.
            (is_front_base(&self.base) && is_front_credential(&token)).then_some(token)
        } else if is_front_base(&self.base) {
            is_front_credential(&token).then_some(token)
        } else {
            Some(token)
        };
        self
    }

    /// A credential-less sibling of this client for **sealed-sender deposits**: no bearer token.
    /// Over https it has its own connection pool; through a p2p front it shares the device's
    /// member connection, so the host can link a deposit by connection (a known gap, tracked for
    /// build 52: SECURITY.md, Metadata).
    pub fn anonymous(&self) -> Self {
        Self::new(self.base.clone())
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    /// A request carrying a device proof header (account-security operations; see the engine).
    pub async fn signed(&self, method: reqwest::Method, path: &str, body: Option<Value>, proof: &str) -> Result<Value, ClientError> {
        self.request_with(method, path, body, Some(proof)).await
    }

    async fn request(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<Value, ClientError> {
        self.request_with(method, path, body, None).await
    }

    /// `GET` with one extra request header (the install secret a granted backup request is
    /// fetched with; see `Engine::fetch_key_backup`).
    pub async fn get_with_header(&self, path: &str, name: &'static str, value: &str) -> Result<Value, ClientError> {
        self.request_headers(reqwest::Method::GET, path, None, &[(name, value)]).await
    }

    /// `POST` with one extra request header (the key a rotation is asked for with).
    pub async fn post_with_header(&self, path: &str, body: Value, name: &'static str, value: &str) -> Result<Value, ClientError> {
        self.request_headers(reqwest::Method::POST, path, Some(body), &[(name, value)]).await
    }

    async fn request_with(&self, method: reqwest::Method, path: &str, body: Option<Value>, proof: Option<&str>) -> Result<Value, ClientError> {
        match proof {
            Some(p) => self.request_headers(method, path, body, &[("x-skwod-device-proof", p)]).await,
            None => self.request_headers(method, path, body, &[]).await,
        }
    }

    async fn request_headers(&self, method: reqwest::Method, path: &str, body: Option<Value>, headers: &[(&'static str, &str)]) -> Result<Value, ClientError> {
        if is_retired_base(&self.base) {
            return Err(ClientError::Transport("this connection to the host was closed; reconnecting".into()));
        }
        self.dead_front()?;
        if is_insecure_remote(&self.base) {
            return Err(ClientError::Transport(
                "refusing to send credentials over plaintext http to a remote host (use https)".into(),
            ));
        }
        if is_front_suspect(&self.base) {
            return Err(ClientError::Transport("the connection to the host is being checked; try again".into()));
        }
        if let Some(secret) = front_secret_of(&self.base) {
            return self.via_front(secret, method, path, body, headers).await;
        }
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            // Never on the credential-less sealed-sender client: that path says nothing about us.
            req = req.bearer_auth(self.wire_token(t)?).header(BUILD_HEADER, CLIENT_BUILD);
        }
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = res.status();
        // Fast reject: if the server advertises a Content-Length over the cap, don't even buffer it.
        if res.content_length().is_some_and(|len| len > MAX_RESPONSE as u64) {
            return Err(ClientError::Transport("response body exceeds maximum size".into()));
        }
        let text = read_body_capped(res, MAX_RESPONSE).await?;
        if !status.is_success() {
            return Err(ClientError::Status { status: status.as_u16(), body: text });
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| ClientError::Shape)
    }

    /// A JSON request to a front's host, in process over the member connection (never the
    /// loopback port). A credential is resolved to the token HERE (the front's rule: only the
    /// signed-in credential; any other is refused, not sent); no credential, no Authorization
    /// (sealed sender stays anonymous).
    async fn via_front(&self, secret: String, method: reqwest::Method, path: &str, body: Option<Value>, headers: &[(&'static str, &str)]) -> Result<Value, ClientError> {
        let Some(t) = transport().lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return Err(ClientError::Transport("no connection to the host".into()));
        };
        let mut hs: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        if let Some(cred) = &self.token {
            hs.push((BUILD_HEADER.to_string(), CLIENT_BUILD.to_string()));
            // A credential that stands for nothing (any more) is refused HERE: sent without an
            // Authorization the host would answer 401, and that reads as "session ended".
            let token = front_token_for(&secret, cred).ok_or(ClientError::StaleCredential)?;
            hs.push(("authorization".into(), format!("Bearer {token}")));
        }
        let bytes = match body {
            Some(b) => { hs.push(("content-type".into(), "application/json".into())); Some(serde_json::to_vec(&b).map_err(|_| ClientError::Shape)?) }
            None => None,
        };
        let (status, out) = t(secret, method.as_str().to_string(), path.to_string(), hs, bytes).await
            .ok_or_else(|| ClientError::Transport("the host did not answer".into()))?;
        let text = String::from_utf8(out).map_err(|_| ClientError::Shape)?;
        if !(200..300).contains(&status) {
            return Err(ClientError::Status { status, body: text });
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&text).map_err(|_| ClientError::Shape)
    }

    fn guarded(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder, ClientError> {
        if is_front_suspect(&self.base) {
            return Err(ClientError::Transport("the connection to the host is being checked; try again".into()));
        }
        if is_retired_base(&self.base) {
            return Err(ClientError::Transport("this connection to the host was closed; reconnecting".into()));
        }
        self.dead_front()?;
        if is_insecure_remote(&self.base) {
            return Err(ClientError::Transport("refusing to send credentials over plaintext http to a remote host (use https)".into()));
        }
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(t) = &self.token {
            req = req.bearer_auth(self.wire_token(t)?).header(BUILD_HEADER, CLIENT_BUILD);
        }
        Ok(req)
    }

    /// How many bytes of blob `blob_id` the server holds, and whether it is complete
    /// (`GET /api/blobs/:id/offset`). `Status { 404 }` when the blob is gone.
    pub async fn blob_offset(&self, blob_id: &str) -> Result<(u64, bool), ClientError> {
        if !valid_blob_id(blob_id) {
            return Err(ClientError::Shape); // never interpolated into a path
        }
        let res = self.guarded(reqwest::Method::GET, &format!("/api/blobs/{blob_id}/offset"))?.send().await.map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = res.status();
        let header = |name: &str| res.headers().get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        if !status.is_success() {
            return Err(ClientError::Status { status: status.as_u16(), body: read_body_capped(res, MAX_RESPONSE).await.unwrap_or_default() });
        }
        Ok((header("upload-offset").ok_or(ClientError::Shape)?, header("upload-complete") == Some(1)))
    }

    /// Upload one chunk of a blob at `offset` (`PATCH /api/blobs/:id`).
    pub async fn blob_chunk(&self, blob_id: &str, offset: u64, chunk: Vec<u8>) -> Result<ChunkOutcome, ClientError> {
        if !valid_blob_id(blob_id) {
            return Err(ClientError::Shape);
        }
        let res = self
            .guarded(reqwest::Method::PATCH, &format!("/api/blobs/{blob_id}"))?
            .header("upload-offset", offset)
            .header("content-type", "application/offset+octet-stream")
            .body(chunk)
            .send()
            .await
            .map_err(|e| ClientError::Transport(e.to_string()))?;
        let status = res.status();
        let header = |name: &str| res.headers().get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
        match (status.as_u16(), header("upload-offset")) {
            (204 | 200, Some(offset)) => Ok(ChunkOutcome::Accepted { offset, complete: header("upload-complete") == Some(1) }),
            // The resume answer: a 409 that names where the server actually is.
            (409, Some(offset)) => Ok(ChunkOutcome::Mismatch { offset }),
            _ => Err(ClientError::Status { status: status.as_u16(), body: read_body_capped(res, MAX_RESPONSE).await.unwrap_or_default() }),
        }
    }

    /// Delete a blob this account uploaded (`DELETE /api/blobs/:id`).
    pub async fn blob_delete(&self, blob_id: &str) -> Result<(), ClientError> {
        if !valid_blob_id(blob_id) {
            return Err(ClientError::Shape);
        }
        self.delete(&format!("/api/blobs/{blob_id}")).await.map(|_| ())
    }

    pub async fn get(&self, path: &str) -> Result<Value, ClientError> {
        self.request(reqwest::Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: Value) -> Result<Value, ClientError> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    pub async fn patch(&self, path: &str, body: Value) -> Result<Value, ClientError> {
        self.request(reqwest::Method::PATCH, path, Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<Value, ClientError> {
        self.request(reqwest::Method::DELETE, path, None).await
    }

    pub async fn put(&self, path: &str, body: Value) -> Result<Value, ClientError> {
        self.request(reqwest::Method::PUT, path, Some(body)).await
    }

    // ---- typed conveniences used by the engine/tests ----

    pub async fn signup(&self, username: &str, password: &str) -> Result<Session, ClientError> {
        self.signup_with_code(username, password, None).await
    }

    /// Sign up, optionally presenting a join code (required by initialized self-hosted instances).
    pub async fn signup_with_code(
        &self,
        username: &str,
        password: &str,
        join_code: Option<&str>,
    ) -> Result<Session, ClientError> {
        let mut body = json!({ "username": username, "password": password });
        if let Some(code) = join_code {
            body["join_code"] = json!(code);
        }
        let v = self.post("/api/auth/signup", body).await?;
        Session::from_value(&v)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<Session, ClientError> {
        let v = self.post("/api/auth/login", json!({ "username": username, "password": password })).await?;
        Session::from_value(&v)
    }

    /// POST an opaque ciphertext envelope to a channel; returns (message_id, created_at).
    pub async fn send_channel_message(&self, channel_id: &str, ciphertext_b64: &str) -> Result<(String, i64), ClientError> {
        // Every current build names the message itself (a server refuses a send without an id:
        // that is how it recognises builds 41/42).
        let message_id = skwod_crypto::new_distribution_id().to_string();
        let v = self.post(&format!("/api/channels/{channel_id}/messages"), json!({ "ciphertext": ciphertext_b64, "message_id": message_id })).await?;
        Ok((
            v["message_id"].as_str().ok_or(ClientError::Shape)?.to_string(),
            v["created_at"].as_i64().ok_or(ClientError::Shape)?,
        ))
    }

    /// Backfill channel messages older than `before` (ms); pass i64::MAX for the newest page.
    pub async fn channel_messages(&self, channel_id: &str, before: i64, limit: usize) -> Result<Vec<Value>, ClientError> {
        let v = self.get(&format!("/api/channels/{channel_id}/messages?before={before}&limit={limit}")).await?;
        Ok(v["messages"].as_array().cloned().unwrap_or_default())
    }
}

/// A logged-in session.
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub token: String,
    pub expires_at: i64,
}

impl Session {
    fn from_value(v: &Value) -> Result<Self, ClientError> {
        Ok(Self {
            user_id: v["user_id"].as_str().ok_or(ClientError::Shape)?.to_string(),
            token: v["token"].as_str().ok_or(ClientError::Shape)?.to_string(),
            expires_at: v["expires_at"].as_i64().ok_or(ClientError::Shape)?,
        })
    }
}

/// Deserialize a REST array field (e.g. `body["messages"]`) into typed rows.
pub fn parse_list<T: DeserializeOwned>(v: &Value, field: &str) -> Result<Vec<T>, ClientError> {
    let arr = v[field].as_array().ok_or(ClientError::Shape)?;
    arr.iter().map(|item| serde_json::from_value(item.clone()).map_err(|_| ClientError::Shape)).collect()
}

#[cfg(test)]
mod retired_base_tests {
    use super::*;

    /// Build 51: once a session's loopback proxy is closed, a client still holding its URL never
    /// sends to that port again — another process may be listening there by then.
    #[tokio::test]
    async fn a_retired_loopback_url_gets_no_request_and_no_token() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                use tokio::io::AsyncWriteExt;
                let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}").await;
            }
        });
        let base = format!("http://127.0.0.1:{port}/{}", "a".repeat(32));
        let client = ApiClient::new(base.clone()).with_token("secret-token");
        retire_base(&format!("{base}/"));
        assert!(is_retired_base(&base));
        let err = client.request(reqwest::Method::GET, "/api/auth/me", None).await.unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)), "{err:?}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0, "nothing reached the port");
        assert!(!is_retired_base(&format!("http://127.0.0.1:{port}/{}", "b".repeat(32))), "only that exact URL");
    }
}

#[cfg(test)]
mod front_tests {
    use super::*;

    /// A stand-in front: records the head of every request it gets, answers 200 {}.
    async fn recorder() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = heads.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 8192];
                    let n = tcp.read(&mut buf).await.unwrap_or(0);
                    seen.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).to_lowercase());
                    let _ = tcp.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await;
                });
            }
        });
        (port, heads)
    }

    fn front(port: u16) -> (String, String) {
        let secret = hex::encode(rand::random::<[u8; 16]>());
        register_front(&secret, port);
        (secret.clone(), format!("http://127.0.0.1:{port}/{secret}"))
    }

    /// A test transport: records (secret, headers) of every in-process request, answers 200 {}.
    type Recorded = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<(String, String)>)>>>;
    fn recorded() -> Recorded {
        static LOG: std::sync::OnceLock<Recorded> = std::sync::OnceLock::new();
        let log = LOG.get_or_init(Default::default).clone();
        let sink = log.clone();
        set_front_transport(std::sync::Arc::new(move |secret, _m, _p, headers, _b| {
            sink.lock().unwrap().push((secret, headers));
            Box::pin(async { Some((200u16, b"{}".to_vec())) })
        }));
        log
    }

    fn auth_of(log: &[(String, Vec<(String, String)>)], secret: &str) -> Vec<Option<String>> {
        log.iter().filter(|(s, _)| s == secret)
            .map(|(_, h)| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.clone())).collect()
    }

    /// Build 51 (B + review H2): the core's requests to a front go IN PROCESS (never to the
    /// loopback port — the recorder listening there gets nothing); a credential becomes the token
    /// there; a sealed-sender deposit carries no Authorization at all.
    #[tokio::test]
    async fn the_token_never_crosses_loopback_and_sealed_sender_stays_anonymous() {
        let log = recorded();
        let (port, heads) = recorder().await;
        let (secret, base) = front(port);
        let credential = front_sign_in(&secret, "real-session-token").unwrap();
        let client = ApiClient::new(base.clone()).with_token(credential.clone());
        assert_eq!(client.real_token().as_deref(), Some("real-session-token"), "resolved in process");
        client.request(reqwest::Method::GET, "/api/auth/me", None).await.unwrap();
        client.anonymous().request(reqwest::Method::POST, "/api/sealed/deposit", Some(serde_json::json!({}))).await.unwrap();
        let auths = auth_of(&log.lock().unwrap(), &secret);
        assert_eq!(auths, vec![Some("Bearer real-session-token".to_string()), None], "the deposit carries nothing");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(heads.lock().unwrap().is_empty(), "nothing went to the loopback port");
        unregister_front(&secret);
    }

    /// Review: an empty token means no token — no Authorization, no credential.
    #[tokio::test]
    async fn an_empty_token_client_gets_no_auth() {
        let log = recorded();
        let (secret, base) = front(4999);
        let _signed_in = front_sign_in(&secret, "someone-elses-session").unwrap();
        let client = ApiClient::new(base.clone()).with_token("");
        assert_eq!(client.token(), None);
        client.request(reqwest::Method::GET, "/api/x", None).await.unwrap();
        assert_eq!(auth_of(&log.lock().unwrap(), &secret), vec![None]);
        unregister_front(&secret);
    }

    /// Review (H2): a suspect front gets nothing, pre-auth included.
    #[tokio::test]
    async fn a_suspect_front_gets_nothing() {
        let log = recorded();
        let (secret, base) = front(4998);
        let epoch = front_suspect_epoch(&secret).unwrap();
        front_suspect(&secret);
        assert!(ApiClient::new(base.clone()).post("/api/auth/login", serde_json::json!({"password": "p"})).await.is_err());
        assert!(auth_of(&log.lock().unwrap(), &secret).is_empty(), "nothing sent");
        assert!(!front_trust_if(&secret, epoch), "a suspicion newer than the challenge is not cleared");
        let epoch = front_suspect_epoch(&secret).unwrap();
        assert!(front_trust_if(&secret, epoch));
        assert!(!front_trust_if("unknown", 0) && front_suspect_epoch("unknown").is_none(), "unknown: never trusted");
        // A re-key carries the suspicion over.
        front_suspect(&secret);
        let next = hex::encode(rand::random::<[u8; 16]>());
        front_rekey(&secret, &next, 4997);
        assert!(is_front_suspect(&format!("http://127.0.0.1:4997/{next}")), "still suspect after a re-key");
        unregister_front(&next);
        register_front(&secret, 4998);
        assert!(ApiClient::new(base).post("/api/auth/login", serde_json::json!({})).await.is_ok());
        unregister_front(&secret);
    }

    /// Review: building a client changes nothing a front injects; a real token given to a front
    /// client is not kept (fail closed) — only an explicit sign-in sets the token.
    #[test]
    fn building_a_client_does_not_change_the_front_token() {
        let (secret, base) = front(4000);
        let credential = front_sign_in(&secret, "t-signed-in").unwrap();
        let other = ApiClient::new(base.clone()).with_token("t-from-a-builder");
        assert_eq!(other.token(), None, "a real token is never kept by a front client");
        assert_eq!(front_token_for(&secret, &credential).as_deref(), Some("t-signed-in"));
        let _again = ApiClient::new(base).with_token(credential.clone());
        assert_eq!(front_token_for(&secret, &credential).as_deref(), Some("t-signed-in"));
        unregister_front(&secret);
    }

    /// Review: after a sign-out, a rotate (or anything but an explicit sign-in) sets nothing.
    #[test]
    fn a_set_after_sign_out_is_rejected() {
        let (secret, _) = front(4001);
        let credential = front_sign_in(&secret, "t1").unwrap();
        assert!(front_rotate(&secret, &credential, "t2"));
        assert_eq!(front_token_for(&secret, &credential).as_deref(), Some("t2"));
        front_sign_out(&secret);
        assert!(!front_rotate(&secret, &credential, "t3"), "signed out: refused");
        assert_eq!(front_token_for(&secret, &credential), None);
        assert_eq!(front_current_token(&secret), None);
        let fresh = front_sign_in(&secret, "t4").unwrap();
        assert_ne!(fresh, credential);
        assert_eq!(front_token_for(&secret, &credential), None, "the old credential stays dead");
        unregister_front(&secret);
    }

    /// Review: one credential never unlocks another session's token (nor another front's).
    #[test]
    fn one_credential_cannot_use_another_sessions_token() {
        let (a, _) = front(4002);
        let (b, _) = front(4003);
        let ca = front_sign_in(&a, "token-a").unwrap();
        let cb = front_sign_in(&b, "token-b").unwrap();
        assert_eq!(front_token_for(&a, &cb), None);
        assert_eq!(front_token_for(&b, &ca), None);
        assert_eq!(front_token_for(&a, &format!("{FRONT_CREDENTIAL_PREFIX}{}", "0".repeat(32))), None, "a guessed credential");
        assert_eq!(front_token_for(&a, &ca).as_deref(), Some("token-a"));
        unregister_front(&a);
        unregister_front(&b);
    }

    /// Review: a re-key carries a signed-in session over under a NEW credential (the old one maps
    /// to nothing); a signed-out session stays signed out — a re-key never re-arms it.
    #[test]
    fn a_rekey_moves_the_session_and_never_re_arms_a_signed_out_one() {
        let (a, _) = front(4100);
        let c1 = front_sign_in(&a, "tok").unwrap();
        let b = hex::encode(rand::random::<[u8; 16]>());
        let c2 = front_rekey(&a, &b, 4101).expect("signed in: a new credential");
        assert_ne!(c1, c2);
        assert_eq!(front_token_for(&b, &c1), None);
        assert_eq!(front_token_for(&b, &c2).as_deref(), Some("tok"));
        assert!(is_front_base(&format!("http://127.0.0.1:4101/{b}")) && !is_front_base(&format!("http://127.0.0.1:4100/{a}")));
        front_sign_out(&b);
        let c = hex::encode(rand::random::<[u8; 16]>());
        assert_eq!(front_rekey(&b, &c, 4102), None, "signed out stays signed out");
        assert_eq!(front_current_token(&c), None);
        unregister_front(&c);
    }

    /// Review: a front-shaped loopback URL that is not a live front gets nothing at all.
    #[tokio::test]
    async fn a_dead_front_url_gets_nothing() {
        let (port, heads) = recorder().await;
        let dead = format!("http://127.0.0.1:{port}/{}", "c".repeat(32));
        assert!(looks_like_front(&dead) && !is_front_base(&dead));
        let client = ApiClient::new(dead).with_token(format!("front-{}", "d".repeat(32)));
        assert_eq!(client.token(), None);
        assert!(client.request(reqwest::Method::GET, "/api/x", None).await.is_err());
        assert!(client.anonymous().request(reqwest::Method::POST, "/api/sealed/deposit", None).await.is_err());
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(heads.lock().unwrap().is_empty());
    }

    /// Review: compare-and-clear is atomic — a raise after the captured epoch always survives.
    #[test]
    fn a_raise_after_the_capture_survives_any_clear() {
        let s = Suspicion::default();
        assert!(!s.is_suspect());
        let e1 = s.raise();
        let captured = s.epoch();
        let _e2 = s.raise();
        assert!(!s.clear_if(captured), "raised after the capture: still suspect");
        assert!(s.is_suspect());
        assert!(s.clear_if(s.epoch()));
        assert!(!s.is_suspect());
        assert!(!s.clear_if(e1) || !s.is_suspect(), "an older clear changes nothing");
    }

    #[test]
    fn only_a_live_front_url_counts() {
        let secret = "e".repeat(32);
        assert!(!is_front_base(&format!("http://127.0.0.1:4000/{secret}")));
        register_front(&secret, 4000);
        assert!(!is_front_base(&format!("http://127.0.0.1:4001/{secret}")), "the exact port, not just the secret");
        assert!(is_front_base(&format!("http://127.0.0.1:4000/{secret}")));
        assert!(is_front_base(&format!("http://127.0.0.1:4000/{secret}/api/x")));
        assert!(!is_front_base(&format!("https://example.org/{secret}")), "never a remote URL");
        assert!(!is_front_base("http://127.0.0.1:4000/other"));
        unregister_front(&secret);
    }

    /// Review: a front client whose front is gone sends nothing (not even its credential).
    #[tokio::test]
    async fn a_front_client_fails_closed_when_the_front_is_gone() {
        let (port, heads) = recorder().await;
        let (secret, base) = front(port);
        let credential = front_sign_in(&secret, "t").unwrap();
        let client = ApiClient::new(base).with_token(credential);
        unregister_front(&secret);
        assert!(client.request(reqwest::Method::GET, "/api/x", None).await.is_err());
        assert!(client.guarded(reqwest::Method::GET, "/api/x").is_err(), "nor a blob request");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(heads.lock().unwrap().is_empty(), "nothing reached the port");
    }
}

#[cfg(test)]
mod ct_tests {
    #[test]
    fn credentials_compare_exactly() {
        assert!(super::ct_eq(b"front-abc", b"front-abc"));
        assert!(!super::ct_eq(b"front-abc", b"front-abd"));
        assert!(!super::ct_eq(b"front-abc", b"front-ab"));
        assert!(!super::ct_eq(b"", b"x"));
    }
}
