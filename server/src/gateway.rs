//! Blind push gateway client (docs/SECURITY.md "Push notifications").
//!
//! A self-hosted skwod has no Apple credentials, so iOS installs ask to be woken through a
//! *gateway* (a tiny stateless relay the app publisher runs; `push-gateway/`). This module is the
//! only code that talks to one, and it sends exactly:
//!
//! ```text
//! POST <gateway>/v1/wake   { "credential": "w1.…", "kind": "message" | "call" }
//! ```
//!
//! (For a registration made by a build <= 45, which handed over raw tokens:
//! `{ "token": "<hex>", "kind", "topic": "<bundle id>" }` plus an optional `"tag"`.)
//! No server identity, no sender, no channel, no message id, no content, no custom headers.
//!
//! Three rules shape everything here:
//!
//! 1. **The gateway URL comes from a client, so it is hostile input.** It is accepted only as
//!    `https://<public dns name>[/path]` on the default port ([`validate_gateway_url`]); at send
//!    time the name is resolved, *every* answer must be a globally routable address, the
//!    connection is pinned to the address that was checked (no second lookup to rebind), and
//!    redirects are never followed. An operator can additionally restrict the set of gateways
//!    with `SKWOD_PUSH_GATEWAYS`.
//! 2. **Timing is metadata.** Wakes for one token are coalesced. The FIRST message wake of a
//!    burst waits a uniform random 0–750 ms — short enough to feel instant, and enough that
//!    the members of one channel are not woken in the same instant, in a fixed order. (It was
//!    1.5–6 s; notifications that arrive seconds late were the complaint, and this is the
//!    price: the gateway now learns when a quiet conversation started to within a second.)
//!    Then a quiet period follows, and whatever arrived during it is ONE more wake after the
//!    longer jitter — so nothing is learned about how many messages followed or when. A call
//!    wake waits 0–150 ms only: a ring that arrives late is a missed call. A wake for a socket
//!    that did not answer its probe fires a randomised 3 s ± 750 ms after the event (`ws.rs`),
//!    never at a fixed offset from it.
//! 3. **A device that is handed the event on its socket, and reads it, is not woken** — it
//!    already has the event in-band, and a wake would only tell the gateway that someone wrote
//!    to it. Both halves are checked, not assumed. *Handed*: the wake is skipped only when a
//!    reachable socket of that install is subscribed to the event's topic
//!    (`AppState::session_handed`) — an open socket that never subscribed to that channel or
//!    conversation, or to nothing at all, stands in for no wake. *Reads*: an install that said
//!    it left the foreground is woken although its socket is still open, and a socket that
//!    does not answer the probe sent right after an event within `ws_ack` is woken for it
//!    (`ws.rs`, "delivery acks"). A phone that was suspended without a goodbye used to look
//!    connected for most of a minute, and every message in that minute was never notified.
//!    What this cannot tell apart: someone holding the install's session token who subscribes
//!    and answers the probes IS that install as far as the server can see.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::Rng;
use serde_json::json;

use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Message,
    Call,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Message => "message",
            Kind::Call => "call",
        }
    }
}

/// Which gateway URLs this instance will talk to.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// The only gateway hosts accepted: `SKWOD_PUSH_GATEWAYS` (comma-separated host names), or,
    /// when that is not set, the publisher's gateway baked into the build
    /// ([`DEFAULT_GATEWAY_HOSTS`]). `None` only when neither exists — then the instance owner's
    /// own registration decides the host for everyone (`push.rs`, "owner-pinned").
    pub allowed_hosts: Option<Vec<String>>,
    /// Accept `http://127.0.0.1:<port>` too. Tests, and debug builds with
    /// `SKWOD_DEV_INSECURE_PUSH_GATEWAY=1`; a release build cannot turn this on.
    pub insecure_loopback: bool,
}

impl Policy {
    pub fn from_env() -> Self {
        let allowed_hosts = Self::hosts(std::env::var("SKWOD_PUSH_GATEWAYS").ok().as_deref(), DEFAULT_GATEWAY_HOSTS);
        let insecure_loopback = cfg!(debug_assertions) && std::env::var("SKWOD_DEV_INSECURE_PUSH_GATEWAY").is_ok_and(|v| v == "1");
        Self { allowed_hosts, insecure_loopback }
    }

    /// The allowlist: the operator's list when it names at least one host, else the build's.
    pub(crate) fn hosts(env: Option<&str>, built_in: Option<&str>) -> Option<Vec<String>> {
        let parse = |v: &str| {
            let hosts: Vec<String> = v
                .split(',')
                .map(|h| h.trim().trim_start_matches("https://").trim_end_matches('/').to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect();
            (!hosts.is_empty()).then_some(hosts)
        };
        env.and_then(parse).or_else(|| built_in.and_then(parse))
    }
}

/// The publisher's push-gateway host(s), set when the server is BUILT
/// (`SKWOD_DEFAULT_PUSH_GATEWAY=push.example.org cargo build`; the Dockerfile passes the build
/// argument through). A release build carries it, so out of the box a skwod only ever calls
/// the gateway its apps were built for — not whatever host a member's registration names.
pub const DEFAULT_GATEWAY_HOSTS: Option<&str> = option_env!("SKWOD_DEFAULT_PUSH_GATEWAY");

/// The host part of a URL [`validate_gateway_url`] returned.
pub(crate) fn gateway_host(canonical: &str) -> &str {
    let rest = canonical.strip_prefix("https://").or_else(|| canonical.strip_prefix("http://")).unwrap_or(canonical);
    rest.split('/').next().unwrap_or(rest)
}

/// What a wake is addressed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Target {
    /// A capability the device got from the gateway (docs/PUSH.md): opaque here, revocable by
    /// the device, and all this server ever learns about where the push goes.
    Credential(String),
    /// Build <= 45: the raw APNs / PushKit token, with the bundle id and the optional tag.
    Raw { token: String, topic: String, tag: Option<String> },
}

/// Names that never denote a public host, whatever they resolve to.
const INTERNAL_SUFFIXES: [&str; 9] = [".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".home.arpa", ".onion", ".test"];

/// Check a client-supplied gateway URL and return its canonical form (no trailing slash).
///
/// Syntactic only — where the name points is checked again at send time ([`resolve_public`]),
/// because DNS can change between registration and use.
pub fn validate_gateway_url(raw: &str, policy: &Policy) -> Result<String, &'static str> {
    const BAD: &str = "gateway must be an https URL of a public host";
    if raw.len() > 200 || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(BAD);
    }
    let url = reqwest::Url::parse(raw).map_err(|_| BAD)?;
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return Err(BAD);
    }
    let path = url.path().trim_end_matches('/');
    if path.len() > 64 || path.contains("..") || !path.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.')) {
        return Err(BAD);
    }
    if policy.insecure_loopback && url.scheme() == "http" && url.host_str() == Some("127.0.0.1") {
        let port = url.port().ok_or(BAD)?;
        return Ok(format!("http://127.0.0.1:{port}{path}"));
    }
    // https on the default port only: nothing else on a host is reachable through this.
    if url.scheme() != "https" || url.port().is_some() {
        return Err(BAD);
    }
    // A DNS name, never an IP literal (v4, v6, or the decimal/hex spellings the parser folds to v4).
    let Some(url::Host::Domain(host)) = url.host() else { return Err(BAD) };
    let host = host.to_ascii_lowercase();
    if !host.contains('.') || host.ends_with('.') || host == "localhost" || INTERNAL_SUFFIXES.iter().any(|s| host.ends_with(s)) {
        return Err(BAD);
    }
    if let Some(allowed) = &policy.allowed_hosts {
        if !allowed.iter().any(|a| a == &host) {
            return Err("this skwod does not use that push gateway");
        }
    }
    Ok(format!("https://{host}{path}"))
}

/// Resolve `host` and return an address to connect to — only if EVERY answer is globally
/// routable. One private/loopback/link-local answer refuses the lot: a name that resolves to
/// both a public and an internal address is exactly what a rebinding attempt looks like.
async fn resolve_public(host: &str) -> Option<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 443)).await.ok()?.collect();
    if addrs.iter().any(|a| !skwod_net::endpoint::is_global(a.ip())) {
        return None;
    }
    addrs.into_iter().next()
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Sent,
    /// The gateway says the token is dead (HTTP 410): forget the registration.
    Gone,
    Failed,
}

/// How long to wait before the single retry of a failed wake.
fn retry_pause(kind: Kind) -> Duration {
    let (lo, hi) = match kind {
        Kind::Call => (300, 900),
        Kind::Message => (1500, 4000),
    };
    Duration::from_millis(rand::thread_rng().gen_range(lo..=hi))
}

/// One wake. The body has exactly three keys; the client adds no identifying header.
///
/// …plus, when the install registered one, `tag`: an opaque value the DEVICE chose for this
/// skwod, so a phone signed in to several skwods knows which one woke it (and cannot be told
/// otherwise by another of them). It identifies nothing to anyone but that device. A gateway
/// that predates the field answers 400 to it; the wake is then sent again without it.
async fn post_wake(policy: &Policy, gateway: &str, target: &Target, kind: Kind) -> Outcome {
    // Re-validate what the database holds: the policy may be stricter now than at registration.
    let Ok(base) = validate_gateway_url(gateway, policy) else { return Outcome::Failed };
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5));
    if let Some(rest) = base.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or_default().to_string();
        let Some(addr) = resolve_public(&host).await else { return Outcome::Failed };
        // Pin the connection to the address that passed the check.
        builder = builder.https_only(true).resolve(&host, addr);
    }
    let Ok(client) = builder.build() else { return Outcome::Failed };
    let (plain, mut body) = wake_bodies(target, kind);
    // One retry, after a jittered pause: a wake that failed on a transient error (the gateway
    // restarting, a dropped connection, a 5xx / 429) used to be simply lost, and with it the
    // notification. Never more than one — the next message schedules its own wake anyway.
    let mut retried = false;
    loop {
        match client.post(format!("{base}/v1/wake")).json(&body).send().await {
            Ok(res) if res.status().is_success() => return Outcome::Sent,
            Ok(res) if res.status() == reqwest::StatusCode::GONE => return Outcome::Gone,
            // An older gateway refuses the fourth field: the wake matters more than the tag.
            Ok(res) if res.status() == reqwest::StatusCode::BAD_REQUEST && body != plain => body = plain.clone(),
            // A definite refusal (bad request, forbidden…) will not improve on a second try.
            Ok(res) if res.status().is_client_error() && res.status() != reqwest::StatusCode::TOO_MANY_REQUESTS => return Outcome::Failed,
            _ if !retried => {
                retried = true;
                tokio::time::sleep(retry_pause(kind)).await;
            }
            _ => return Outcome::Failed,
        }
    }
}

/// The request body for a wake, and the one to fall back to when a gateway that predates the
/// `tag` field refuses it. A credential wake has exactly two keys: the credential and the kind.
pub(crate) fn wake_bodies(target: &Target, kind: Kind) -> (serde_json::Value, serde_json::Value) {
    match target {
        Target::Credential(credential) => {
            let body = json!({ "credential": credential, "kind": kind.as_str() });
            (body.clone(), body)
        }
        Target::Raw { token, topic, tag } => {
            let plain = json!({ "token": token, "kind": kind.as_str(), "topic": topic });
            let mut body = plain.clone();
            if let Some(tag) = tag {
                body["tag"] = json!(tag);
            }
            (plain, body)
        }
    }
}

/// Delays applied to wakes. `message_first` / `call_first` is the jitter before the first wake
/// of a burst (0–750 ms for a message, 0–150 ms for a call); `*_delay` is the jitter before each trailing
/// (coalesced) wake, which comes after `*_quiet`.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    pub message_first: (Duration, Duration),
    pub call_first: (Duration, Duration),
    pub message_delay: (Duration, Duration),
    pub message_quiet: Duration,
    pub call_delay: (Duration, Duration),
    pub call_quiet: Duration,
    /// The last wake of a registration whose session expired ([`final_wake`]) is sent this
    /// long after the sweep that found it, at random: sessions that expire together (everyone
    /// who signed up at the same party) are not woken in one burst, in a fixed order.
    pub last_wake: (Duration, Duration),
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            message_first: (Duration::ZERO, Duration::from_millis(750)),
            call_first: (Duration::ZERO, Duration::from_millis(150)),
            message_delay: (Duration::from_millis(1500), Duration::from_millis(6000)),
            message_quiet: Duration::from_secs(20),
            call_delay: (Duration::from_millis(0), Duration::from_millis(400)),
            call_quiet: Duration::from_secs(5),
            // Under the sweep interval (`retention::SWEEP_EVERY`, 5 min).
            last_wake: (Duration::ZERO, Duration::from_secs(240)),
        }
    }
}

impl Timing {
    /// Before the first wake of a burst.
    fn first(&self, kind: Kind) -> Duration {
        match kind {
            Kind::Message => Self::between(self.message_first),
            Kind::Call => Self::between(self.call_first),
        }
    }

    fn delay(&self, kind: Kind) -> Duration {
        Self::between(match kind {
            Kind::Message => self.message_delay,
            Kind::Call => self.call_delay,
        })
    }

    fn between((lo, hi): (Duration, Duration)) -> Duration {
        if hi <= lo {
            return lo;
        }
        lo + Duration::from_millis(rand::thread_rng().gen_range(0..=(hi - lo).as_millis() as u64))
    }

    fn quiet(&self, kind: Kind) -> Duration {
        match kind {
            Kind::Message => self.message_quiet,
            Kind::Call => self.call_quiet,
        }
    }
}

/// A stored registration (one signed-in app install), as read at fire time.
#[derive(Debug, Clone)]
struct Registration {
    session_hash: Vec<u8>,
    gateway: String,
    apns_token: String,
    voip_token: Option<String>,
    topic: String,
    wake_tag: Option<String>,
    /// Set for a capability registration; the token columns are then empty.
    wake_credential: Option<String>,
}

impl Registration {
    /// Where a wake of `kind` goes, and the kind it is sent as. A raw registration without a
    /// PushKit token degrades a call to a message wake here; with a credential the gateway
    /// knows whether a PushKit token was sealed in and degrades by itself.
    fn target(&self, kind: Kind) -> (Target, Kind) {
        if let Some(credential) = &self.wake_credential {
            return (Target::Credential(credential.clone()), kind);
        }
        let raw = |token: &str| Target::Raw { token: token.to_string(), topic: self.topic.clone(), tag: self.wake_tag.clone() };
        match (kind, &self.voip_token) {
            (Kind::Call, Some(voip)) => (raw(voip), Kind::Call),
            _ => (raw(&self.apns_token), Kind::Message),
        }
    }
}

async fn load(state: &AppState, registration_id: &str) -> Option<Registration> {
    type Row = (Vec<u8>, String, String, Option<String>, String, Option<String>, Option<String>);
    let row: Option<Row> =
        sqlx::query_as("SELECT session_hash, gateway, apns_token, voip_token, topic, wake_tag, wake_credential FROM push_registrations WHERE id = $1")
            .bind(registration_id)
            .fetch_optional(&state.db)
            .await
            .ok()?;
    row.map(|(session_hash, gateway, apns_token, voip_token, topic, wake_tag, wake_credential)| Registration { session_hash, gateway, apns_token, voip_token, topic, wake_tag, wake_credential })
}

/// One registration's wakes of one kind, from the first request until the quiet period ends.
#[derive(Default)]
struct Burst {
    /// Another wake was requested while pending/quiet.
    again: bool,
    /// The topics of the events it was requested for. `None`: one of them named no topic.
    topics: Option<std::collections::BTreeSet<String>>,
}

impl Burst {
    fn add(&mut self, topics: &[String]) {
        match (&mut self.topics, topics.is_empty()) {
            (Some(have), false) => have.extend(topics.iter().cloned()),
            _ => self.topics = None,
        }
    }
}

/// Coalescing, jittering wake scheduler.
///
/// One in-flight task per **registration** (and kind) — never per token. Keying on the token
/// would let two accounts that hold the same token share one schedule: a cross-account timing
/// link, and a way for one account to suppress or trigger another's wakes. (Registration also
/// refuses a token that is already bound to a different account — `push.rs`.)
#[derive(Clone)]
pub struct Waker {
    /// (registration id, kind) → the burst in flight.
    pending: Arc<Mutex<HashMap<(String, Kind), Burst>>>,
    pub policy: Arc<Policy>,
    timing: Timing,
}

impl Waker {
    pub fn new(policy: Policy, timing: Timing) -> Self {
        Self { pending: Arc::default(), policy: Arc::new(policy), timing }
    }

    pub fn from_env() -> Self {
        Self::new(Policy::from_env(), Timing::default())
    }

    /// Ask for the install behind `registration_id` to be woken. Returns immediately; the first
    /// wake of a burst is sent within 0–750 ms (a call: 0–150 ms) and the rest of the burst is one more wake after the
    /// quiet period and a jitter (coalescing), and everything about it —
    /// token, gateway, whether the device is connected, whether the registration still exists
    /// — is read from the database when it fires, not now.
    ///
    /// `topics`: the realtime topic(s) of the event(s) this wake is for. The wake is skipped —
    /// now, and again when it fires — only if a reachable socket of the install is subscribed
    /// to every one of them, i.e. was handed the events. With no topic it is never skipped.
    pub fn wake(&self, state: &AppState, registration_id: String, session_hash: &[u8], kind: Kind, topics: &[String]) {
        if state.session_handed(session_hash, topics) {
            return;
        }
        let key = (registration_id, kind);
        {
            let mut pending = self.pending.lock().expect("waker lock");
            if let Some(burst) = pending.get_mut(&key) {
                burst.again = true;
                burst.add(topics);
                return;
            }
            let mut burst = Burst { again: false, topics: Some(Default::default()) };
            burst.add(topics);
            pending.insert(key.clone(), burst);
        }
        let (this, state) = (self.clone(), state.clone());
        tokio::spawn(async move {
            let mut first = true;
            loop {
                // The first wake of a burst waits a fraction of a second at most; the trailing
                // ones get the longer jitter.
                let pause = if std::mem::take(&mut first) { this.timing.first(kind) } else { this.timing.delay(kind) };
                if !pause.is_zero() {
                    tokio::time::sleep(pause).await;
                }
                // Signed out / device removed during the delay → the row is gone → nothing is sent.
                let Some(reg) = load(&state, &key.0).await else { break };
                // The gateway rule as it stands NOW (allowlist, or the owner's pin): a row that
                // names any other host is not dialled. It is removed (its device registers
                // again) only when a rule positively excludes it — never because the check
                // failed, or because this skwod has no rule yet.
                match crate::push::gateway_allowed(&state, &reg.gateway).await {
                    Ok(true) => {}
                    Ok(false) => {
                        if crate::push::gateway_rule_exists(&state).await.unwrap_or(false) {
                            let _ = sqlx::query("DELETE FROM push_registrations WHERE id = $1").bind(&key.0).execute(&state.db).await;
                        }
                        break;
                    }
                    Err(_) => break,
                }
                // Handed everything this burst is about by now → it has the events in-band.
                let topics: Option<Vec<String>> = this.pending.lock().expect("waker lock").get(&key).and_then(|b| b.topics.as_ref().map(|t| t.iter().cloned().collect()));
                if !topics.is_some_and(|t| state.session_handed(&reg.session_hash, &t)) {
                    let (target, sent_kind) = reg.target(kind);
                    if post_wake(&this.policy, &reg.gateway, &target, sent_kind).await == Outcome::Gone {
                        forget_target(&state, &key.0, &target, sent_kind).await;
                    }
                }
                tokio::time::sleep(this.timing.quiet(kind)).await;
                let mut pending = this.pending.lock().expect("waker lock");
                match pending.get_mut(&key) {
                    Some(burst) if burst.again => burst.again = false, // something arrived meanwhile: one more round
                    _ => break,
                }
            }
            this.pending.lock().expect("waker lock").remove(&key);
        });
    }

    /// The quiet period after a message wake (also how often one socket may ask for a wake
    /// because it lagged — `ws.rs`).
    pub fn message_quiet(&self) -> Duration {
        self.timing.message_quiet
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.lock().expect("waker lock").len()
    }
}

/// The gateway reported `token` dead. A dead alert token ends the registration; a dead PushKit
/// token only ends call wakes.
///
/// A credential the gateway calls gone was revoked by its device, expired, or points at a dead
/// token: the registration ends (the device registers a new one when it is next here). Only on
/// a MESSAGE wake — "gone" to a call may mean just the PushKit half.
async fn forget_target(state: &AppState, registration_id: &str, target: &Target, kind: Kind) {
    match target {
        Target::Raw { token, .. } => forget_token(state, registration_id, token).await,
        Target::Credential(credential) if kind == Kind::Message => {
            let _ = sqlx::query("DELETE FROM push_registrations WHERE id = $1 AND wake_credential = $2")
                .bind(registration_id)
                .bind(credential)
                .execute(&state.db)
                .await;
        }
        Target::Credential(_) => {}
    }
}

async fn forget_token(state: &AppState, registration_id: &str, token: &str) {
    let _ = sqlx::query("DELETE FROM push_registrations WHERE id = $1 AND apns_token = $2")
        .bind(registration_id)
        .bind(token)
        .execute(&state.db)
        .await;
    let _ = sqlx::query("UPDATE push_registrations SET voip_token = NULL WHERE id = $1 AND voip_token = $2")
        .bind(registration_id)
        .bind(token)
        .execute(&state.db)
        .await;
}

/// One last wake for a registration that is about to be deleted with its expired session
/// (`retention.rs`), bypassing the scheduler. The row will be gone when the wake is sent, so
/// what it needs is read NOW; the wake itself goes out after a random share of
/// `Timing::last_wake`, on its own task — sessions that expire in the same sweep are neither
/// woken together nor in a fixed order.
pub async fn final_wake(state: &AppState, registration_id: &str) {
    if let Some(reg) = load(state, registration_id).await {
        if !crate::push::gateway_allowed(state, &reg.gateway).await.unwrap_or(false) {
            return;
        }
        let (target, kind) = reg.target(Kind::Message);
        let (policy, pause) = (state.waker.policy.clone(), Timing::between(state.waker.timing.last_wake));
        tokio::spawn(async move {
            tokio::time::sleep(pause).await;
            let _ = post_wake(&policy, &reg.gateway, &target, kind).await;
        });
    }
}

/// Request a wake for the install signed in with ONE session: an event was written to its
/// socket and nothing shows it was read (`ws.rs`, "delivery acks"). Same scheduler as every
/// other wake — coalesced with whatever is already pending for the registration, and skipped
/// only if another reachable socket of the same session is subscribed to all of `topics` (the
/// topics of those events): it was handed them too, and owes its own proof.
pub async fn wake_session(state: &AppState, session_hash: &[u8], kind: Kind, topics: &[String]) {
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM push_registrations WHERE session_hash = $1")
        .bind(session_hash)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    for id in ids {
        state.waker.wake(state, id, session_hash, kind, topics);
    }
}

/// Request a wake for every gateway-registered install of each user, for an event published
/// on that user's OWN topic (`user:<id>`: sealed mail, a ring). Best effort, never fails the
/// caller, logs nothing about who.
pub async fn wake_users(state: &AppState, user_ids: &[String], kind: Kind) {
    for user_id in user_ids {
        wake_users_on(state, std::slice::from_ref(user_id), kind, &crate::rt::user_topic(user_id)).await;
    }
}

/// The same for an event published on `topic` (a channel or a conversation). An install is
/// left alone only if a reachable socket of it is subscribed to exactly that topic.
pub async fn wake_users_on(state: &AppState, user_ids: &[String], kind: Kind, topic: &str) {
    let topics = [topic.to_string()];
    for user_id in user_ids {
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as("SELECT id, session_hash FROM push_registrations WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
        for (id, session_hash) in rows {
            state.waker.wake(state, id, &session_hash, kind, &topics);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{send, signup, test_state};
    use axum::http::StatusCode;
    use serde_json::Value;

    fn open() -> Policy {
        Policy::default()
    }

    #[test]
    fn only_https_urls_of_public_names_are_accepted() {
        let ok = |u: &str| validate_gateway_url(u, &open());
        assert_eq!(ok("https://push.example.org").unwrap(), "https://push.example.org");
        assert_eq!(ok("https://Push.Example.org/").unwrap(), "https://push.example.org");
        assert_eq!(ok("https://push.example.org:443/gw/").unwrap(), "https://push.example.org/gw");
        for bad in [
            "http://push.example.org",          // not https
            "https://push.example.org:8443",    // another port on the host
            "https://127.0.0.1",                // loopback literal
            "https://2130706433",               // 127.0.0.1 as a decimal integer
            "https://0x7f.1",                   // …and in hex
            "https://10.0.0.5/v1",              // private literal
            "https://169.254.169.254",          // cloud metadata
            "https://[::1]",                    // v6 loopback
            "https://[fd00::1]",                // ULA
            "https://8.8.8.8",                  // even a public literal: names only
            "https://localhost",
            "https://router",                   // single label
            "https://nas.local",
            "https://db.internal",
            "https://printer.lan",
            "https://abc.onion",
            "https://user:pw@push.example.org", // credentials
            "https://push.example.org/?x=1",
            "https://push.example.org/#frag",
            "https://push.example.org/a b",
            "ftp://push.example.org",
            "file:///etc/passwd",
            "gopher://push.example.org",
            "push.example.org",
            "",
        ] {
            assert!(ok(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(ok(&format!("https://push.example.org/{}", "a".repeat(300))).is_err());
        // Dot segments are resolved by the parser before the path is looked at.
        assert_eq!(ok("https://push.example.org/gw/../x").unwrap(), "https://push.example.org/x");
    }

    #[test]
    fn operator_allowlist_and_the_loopback_test_hook() {
        let only = Policy { allowed_hosts: Some(vec!["push.example.org".into()]), insecure_loopback: false };
        assert!(validate_gateway_url("https://push.example.org", &only).is_ok());
        assert!(validate_gateway_url("https://other.example.org", &only).is_err());
        // The loopback hook is off unless a test (or a debug build + env) turns it on…
        assert!(validate_gateway_url("http://127.0.0.1:8787", &open()).is_err());
        let dev = Policy { allowed_hosts: None, insecure_loopback: true };
        assert_eq!(validate_gateway_url("http://127.0.0.1:8787", &dev).unwrap(), "http://127.0.0.1:8787");
        // …and even then it is 127.0.0.1 only.
        assert!(validate_gateway_url("http://10.0.0.1:8787", &dev).is_err());
        assert!(validate_gateway_url("http://localhost:8787", &dev).is_err());
    }

    #[tokio::test]
    async fn names_that_resolve_to_internal_addresses_are_never_dialed() {
        assert_eq!(resolve_public("localhost").await, None);
        // And a wake to a syntactically fine URL whose name is not public goes nowhere.
        assert_eq!(post_wake(&open(), "https://localhost.example.invalid", &Target::Raw { token: "ab".into(), topic: "t".into(), tag: None }, Kind::Message).await, Outcome::Failed);
    }

    /// A fake gateway on 127.0.0.1 that records every request it receives.
    type Recorded = (String, Vec<(String, String)>, Value);
    #[derive(Clone, Default)]
    struct Seen(Arc<Mutex<Vec<Recorded>>>);

    async fn fake_gateway(status: StatusCode) -> (String, Seen) {
        let seen = Seen::default();
        let s = seen.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let s = s.clone();
            async move {
                let line = format!("{} {}", req.method(), req.uri());
                let headers = req.headers().iter().map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string())).collect();
                let body = axum::body::to_bytes(req.into_body(), 4096).await.unwrap();
                s.0.lock().unwrap().push((line, headers, serde_json::from_slice(&body).unwrap_or(Value::Null)));
                status
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    fn fast() -> Timing {
        Timing {
            message_first: (Duration::from_millis(30), Duration::from_millis(60)),
            call_first: (Duration::from_millis(0), Duration::from_millis(10)),
            message_delay: (Duration::from_millis(30), Duration::from_millis(60)),
            message_quiet: Duration::from_millis(150),
            call_delay: (Duration::from_millis(0), Duration::from_millis(10)),
            call_quiet: Duration::from_millis(50),
            last_wake: (Duration::from_millis(200), Duration::from_millis(400)),
        }
    }

    const APNS: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
    const VOIP: &str = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";

    async fn registered(gateway: &str, voip: bool) -> (axum::Router, AppState, String, String) {
        let mut state = test_state().await;
        state.waker = Waker::new(Policy { allowed_hosts: None, insecure_loopback: true }, fast());
        let app = crate::api::router(state.clone());
        let (user_id, token) = signup(&app, "sleeper").await;
        let body = json!({ "provider": "gateway", "gateway": gateway, "apns_token": APNS, "voip_token": if voip { Some(VOIP) } else { None }, "topic": "io.skwod.app" });
        let (status, res) = send(&app, "POST", "/api/push/register", Some(&token), Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{res}");
        (app, state, user_id, token)
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(700)).await;
    }

    #[tokio::test]
    async fn a_wake_is_exactly_three_fields_and_carries_no_identity() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (_app, state, user_id, _token) = registered(&url, true).await;
        wake_users(&state, &[user_id], Kind::Message).await;
        settle().await;
        let seen = seen.0.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        let (line, headers, body) = &seen[0];
        assert_eq!(line, "POST /v1/wake");
        assert_eq!(body, &json!({ "token": APNS, "kind": "message", "topic": "io.skwod.app" }));
        assert_eq!(body.as_object().unwrap().len(), 3, "token, kind, topic — nothing else");
        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        for forbidden in ["user-agent", "authorization", "cookie", "referer", "origin", "x-forwarded-for", "from"] {
            assert!(!names.contains(&forbidden), "the wake must not carry {forbidden}");
        }
        assert!(names.iter().all(|n| matches!(*n, "content-type" | "content-length" | "accept" | "host")), "unexpected header in {names:?}");
    }

    /// A phone in several skwods must know WHICH one woke it: each registration carries a tag
    /// the device chose, and the wake hands it back. A gateway too old for the field still wakes.
    #[tokio::test]
    async fn a_wake_carries_the_tag_the_device_chose_and_survives_an_old_gateway() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (app, state, user, token) = registered(&url, true).await;
        let reg = |tag: Value| json!({ "provider": "gateway", "gateway": url, "apns_token": APNS, "voip_token": VOIP, "topic": "io.skwod.app", "wake_tag": tag });
        for bad in [json!("short"), json!("has a space in it!!"), json!("x".repeat(33))] {
            assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(reg(bad))).await.0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(reg(json!("Zk3_device-chosen-tag")))).await.0, StatusCode::OK);
        wake_users(&state, std::slice::from_ref(&user), Kind::Call).await;
        settle().await;
        let got = seen.0.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2, json!({ "token": VOIP, "kind": "call", "topic": "io.skwod.app", "tag": "Zk3_device-chosen-tag" }));

        // An old gateway: 400 to the four-field body → sent again as the classic three fields.
        let old = Seen::default();
        let s = old.clone();
        let router = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let s = s.clone();
            async move {
                let body: Value = serde_json::from_slice(&axum::body::to_bytes(req.into_body(), 4096).await.unwrap()).unwrap_or(Value::Null);
                let status = if body.as_object().is_some_and(|o| o.len() == 3) { StatusCode::ACCEPTED } else { StatusCode::BAD_REQUEST };
                s.0.lock().unwrap().push((String::new(), Vec::new(), body));
                status
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let old_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let policy = Policy { allowed_hosts: None, insecure_loopback: true };
        assert_eq!(post_wake(&policy, &old_url, &Target::Raw { token: APNS.into(), topic: "io.skwod.app".into(), tag: Some("Zk3_device-chosen-tag".into()) }, Kind::Message).await, Outcome::Sent);
        let got = old.0.lock().unwrap().clone();
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].2, json!({ "token": APNS, "kind": "message", "topic": "io.skwod.app" }));
    }

    /// Capability wakes (audit H2): the device registers with the gateway itself and gives the
    /// skwod only the credential. The skwod stores no token, sends `{credential, kind}` and
    /// nothing else, and drops the registration when the gateway says the credential is gone.
    #[tokio::test]
    async fn a_credential_registration_holds_no_token_and_wakes_with_the_credential_only() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let mut state = test_state().await;
        state.waker = Waker::new(Policy { allowed_hosts: None, insecure_loopback: true }, fast());
        let app = crate::api::router(state.clone());
        let (user, token) = signup(&app, "sleeper").await;
        let credential = format!("w1.{}", "Ab3_-".repeat(40));
        let reg = |extra: Value| {
            let mut body = json!({ "provider": "gateway", "gateway": url, "wake_credential": credential });
            body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            body
        };
        // A credential AND a raw token is a client bug: refused, so no token is stored by accident.
        for extra in [json!({ "apns_token": APNS }), json!({ "voip_token": VOIP }), json!({ "topic": "io.skwod.app" }), json!({ "wake_tag": "Zk3_device-chosen-tag" })] {
            assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(reg(extra))).await.0, StatusCode::BAD_REQUEST);
        }
        for bad in ["w1.", "x1.abcdefghijklmnopqrstuvwxyz", "w1.has spaces in it, which is no credential", &format!("w1.{}", "a".repeat(3000))] {
            let body = json!({ "provider": "gateway", "gateway": url, "wake_credential": bad });
            assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(body)).await.0, StatusCode::BAD_REQUEST, "{bad}");
        }
        let (status, res) = send(&app, "POST", "/api/push/register", Some(&token), Some(reg(json!({})))).await;
        assert_eq!((status, res["wake_credentials"].as_bool()), (StatusCode::OK, Some(true)), "{res}");
        let row: (String, Option<String>, String, Option<String>) =
            sqlx::query_as("SELECT apns_token, voip_token, topic, wake_credential FROM push_registrations").fetch_one(&state.db).await.unwrap();
        assert_eq!(row, (String::new(), None, String::new(), Some(credential.clone())), "no token, no bundle id: only the capability");

        // One credential, one account.
        let (_, other) = signup(&app, "other").await;
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&other), Some(reg(json!({})))).await.0, StatusCode::CONFLICT);

        for kind in [Kind::Message, Kind::Call] {
            wake_users(&state, std::slice::from_ref(&user), kind).await;
        }
        settle().await;
        let got = seen.0.lock().unwrap().clone();
        let bodies: Vec<&Value> = got.iter().map(|(_, _, b)| b).collect();
        assert!(bodies.contains(&&json!({ "credential": credential, "kind": "message" })), "{bodies:?}");
        assert!(bodies.contains(&&json!({ "credential": credential, "kind": "call" })), "the gateway, not the skwod, knows whether there is a PushKit token");
        assert!(bodies.iter().all(|b| b.as_object().unwrap().len() == 2), "credential and kind — nothing else: {bodies:?}");

        // Going back to raw tokens (an old build signs in on the same session) clears the credential.
        let raw = json!({ "provider": "gateway", "gateway": url, "apns_token": APNS, "voip_token": null, "topic": "io.skwod.app" });
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(raw)).await.0, StatusCode::OK);
        assert_eq!(sqlx::query_scalar::<_, Option<String>>("SELECT wake_credential FROM push_registrations").fetch_one(&state.db).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_credential_the_gateway_calls_gone_ends_the_registration() {
        let (url, _seen) = fake_gateway(StatusCode::GONE).await;
        let mut state = test_state().await;
        state.waker = Waker::new(Policy { allowed_hosts: None, insecure_loopback: true }, fast());
        let app = crate::api::router(state.clone());
        let (user, token) = signup(&app, "sleeper").await;
        let body = json!({ "provider": "gateway", "gateway": url, "wake_credential": format!("w1.{}", "c".repeat(64)) });
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(body)).await.0, StatusCode::OK);
        // "Gone" to a call may be only the PushKit half: the registration stays…
        wake_users(&state, std::slice::from_ref(&user), Kind::Call).await;
        settle().await;
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap(), 1);
        // …"gone" to a message wake is the device revoking (or the credential expiring).
        wake_users(&state, std::slice::from_ref(&user), Kind::Message).await;
        settle().await;
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap(), 0);
    }

    /// Audit L8: with no operator list the build's own gateway is the allowlist.
    #[test]
    fn the_allowlist_defaults_to_the_gateway_the_build_was_made_for() {
        assert_eq!(Policy::hosts(None, None), None);
        assert_eq!(Policy::hosts(None, Some("push.skwod.example")), Some(vec!["push.skwod.example".to_string()]));
        assert_eq!(Policy::hosts(Some(" , "), Some("https://Push.Skwod.example/")), Some(vec!["push.skwod.example".to_string()]), "an empty list is no list");
        assert_eq!(Policy::hosts(Some("mine.example.org"), Some("push.skwod.example")), Some(vec!["mine.example.org".to_string()]), "the operator's list replaces it");
        let built_in = Policy { allowed_hosts: Policy::hosts(None, Some("push.skwod.example")), insecure_loopback: false };
        assert!(validate_gateway_url("https://push.skwod.example", &built_in).is_ok());
        assert!(validate_gateway_url("https://attacker.example.org", &built_in).is_err(), "a member cannot point the host at a server of their choosing");
        assert_eq!(gateway_host("https://push.example.org/gw"), "push.example.org");
    }

    #[tokio::test]
    async fn a_burst_is_one_wake_plus_one_trailing_wake() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (_app, state, user_id, _token) = registered(&url, false).await;
        for _ in 0..25 {
            wake_users(&state, std::slice::from_ref(&user_id), Kind::Message).await;
        }
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 2, "25 requests coalesce into the first wake and one after the quiet period");
        assert_eq!(state.waker.pending_len(), 0, "nothing lingers once the burst is over");
    }

    #[tokio::test]
    async fn calls_use_the_pushkit_token_and_fall_back_to_a_message_wake_without_one() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (_app, state, user_id, _token) = registered(&url, true).await;
        wake_users(&state, &[user_id], Kind::Call).await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap()[0].2, json!({ "token": VOIP, "kind": "call", "topic": "io.skwod.app" }));

        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (_app, state, user_id, _token) = registered(&url, false).await;
        wake_users(&state, &[user_id], Kind::Call).await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap()[0].2, json!({ "token": APNS, "kind": "message", "topic": "io.skwod.app" }));
    }

    #[tokio::test]
    async fn a_device_that_is_handed_the_event_is_never_woken() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (_app, state, user_id, token) = registered(&url, false).await;
        let hash = crate::auth::token_hash(&token);
        let own = crate::rt::user_topic(&user_id);
        // A reachable socket subscribed to the event's topic when the wake is requested.
        state.session_topic(&hash, &own, true);
        wake_users(&state, std::slice::from_ref(&user_id), Kind::Message).await;
        settle().await;
        assert!(seen.0.lock().unwrap().is_empty());
        // Subscribes during the jitter delay: still no wake.
        state.session_topic(&hash, &own, false);
        wake_users(&state, std::slice::from_ref(&user_id), Kind::Message).await;
        state.session_topic(&hash, &own, true);
        settle().await;
        assert!(seen.0.lock().unwrap().is_empty());
        // Gone again: now it is woken.
        state.session_topic(&hash, &own, false);
        wake_users(&state, &[user_id], Kind::Message).await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 1);
    }

    /// Audit C4: "connected" used to silence every wake. A socket stands in for a wake only
    /// for an event it is handed — one on a topic it is subscribed to.
    #[tokio::test]
    async fn an_open_socket_silences_no_wake_for_a_topic_it_is_not_subscribed_to() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (_app, state, user_id, token) = registered(&url, false).await;
        let hash = crate::auth::token_hash(&token);
        // An idle socket: open, reachable, subscribed to nothing.
        state.session_online(&hash);
        wake_users(&state, std::slice::from_ref(&user_id), Kind::Message).await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 1, "an idle socket does not silence the install's pushes");
        // Subscribed to its own topic and one channel: a message in ANOTHER conversation wakes.
        state.session_topic(&hash, &crate::rt::user_topic(&user_id), true);
        state.session_topic(&hash, "channel:known", true);
        wake_users_on(&state, std::slice::from_ref(&user_id), Kind::Message, "channel:known").await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 1, "handed in-band: no wake");
        wake_users_on(&state, std::slice::from_ref(&user_id), Kind::Message, "dm:brand-new").await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 2, "the first message of a new conversation is notified");
        // Several topics (a burst, an unanswered probe): handed only if ALL of them are, and
        // a wake that names no topic is never taken as handed.
        let own = crate::rt::user_topic(&user_id);
        assert!(state.session_handed(&hash, &[own.as_str(), "channel:known"]));
        assert!(!state.session_handed(&hash, &[own.as_str(), "dm:brand-new"]));
        assert!(!state.session_handed::<&str>(&hash, &[]));
        // The counts are per socket: the last one leaving forgets the session.
        state.session_topic(&hash, "channel:known", false);
        state.session_topic(&hash, &crate::rt::user_topic(&user_id), false);
        assert!(state.ws_topics.lock().unwrap().is_empty());
    }

    /// The same rules through the real route (`POST /api/channels/{id}/messages`): the wake is
    /// asked for on the message's own topic, and never for someone who blocked the author.
    #[tokio::test]
    async fn a_posted_message_wakes_by_its_topic_and_never_a_member_who_blocked_the_author() {
        use base64::Engine;
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (app, state, sleeper, token) = registered(&url, false).await;
        let hash = crate::auth::token_hash(&token);
        let (author_id, author) = signup(&app, "author").await;
        let envelope = base64::engine::general_purpose::STANDARD.encode(b"envelope");
        let (_, body) = send(&app, "POST", "/api/servers", Some(&token), Some(json!({ "name_ciphertext": envelope }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&token), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap().to_string();
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&author), None).await;
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&token), Some(json!({ "name_ciphertext": envelope }))).await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();
        let post = || async {
            let (status, body) = send(&app, "POST", &format!("/api/channels/{channel_id}/messages"), Some(&author), Some(json!({ "ciphertext": envelope }))).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            settle().await;
            seen.0.lock().unwrap().len()
        };
        assert_eq!(post().await, 1, "asleep: woken");
        // A socket on the install's own topic only — not on this channel: still woken.
        state.session_topic(&hash, &crate::rt::user_topic(&sleeper), true);
        assert_eq!(post().await, 2, "an open socket that is not subscribed to the channel does not have the message");
        // Subscribed to the channel: it is handed the message, no wake.
        state.session_topic(&hash, &crate::rt::channel_topic(&channel_id), true);
        assert_eq!(post().await, 2);
        state.session_topic(&hash, &crate::rt::channel_topic(&channel_id), false);
        // Blocked the author: their messages no longer wake this phone.
        let (status, body) = send(&app, "PUT", &format!("/api/blocks/{author_id}"), Some(&token), None).await;
        assert!(status.is_success(), "{body}");
        assert_eq!(post().await, 2);
        let (status, _) = send(&app, "DELETE", &format!("/api/blocks/{author_id}"), Some(&token), None).await;
        assert!(status.is_success());
        assert_eq!(post().await, 3);
    }

    /// A session that is bound to a device registers as THAT device, whatever the body says
    /// (audit C5: device removal can then find exactly its rows).
    #[tokio::test]
    async fn a_bound_session_registers_as_its_own_device() {
        let (url, _seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (app, state, user_id, token) = registered(&url, false).await;
        let device = |state: AppState, user_id: String| async move {
            sqlx::query_scalar::<_, Option<String>>("SELECT device_id FROM push_registrations WHERE user_id = $1").bind(user_id).fetch_one(&state.db).await.unwrap()
        };
        assert_eq!(device(state.clone(), user_id.clone()).await, None, "the raw shape of a build <= 45 names none");
        let reg = |device_id: Value| json!({ "provider": "gateway", "gateway": url, "apns_token": APNS, "voip_token": null, "topic": "io.skwod.app", "device_id": device_id });
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(reg(json!("claimed")))).await.0, StatusCode::OK);
        assert_eq!(device(state.clone(), user_id.clone()).await.as_deref(), Some("claimed"), "an unbound session: the body's word");
        // Bound to a device the account really has (a session bound to a device id with no row
        // is a removed install's, refused everything).
        crate::tests::seed_device(&state.db, &user_id, "bound").await;
        sqlx::query("UPDATE sessions SET device_id = 'bound', device_generation = 0 WHERE user_id = $1").bind(&user_id).execute(&state.db).await.unwrap();
        for body in [reg(json!("claimed")), json!({ "provider": "gateway", "gateway": url, "apns_token": APNS, "voip_token": null, "topic": "io.skwod.app" })] {
            assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(body)).await.0, StatusCode::OK);
            assert_eq!(device(state.clone(), user_id.clone()).await.as_deref(), Some("bound"));
        }
    }

    /// Audit C7: sessions that expired together were all woken in one pass, at once and in
    /// table order. Each last wake now goes out on its own, after a random pause — and still
    /// goes out although its row is deleted by the same sweep.
    #[tokio::test]
    async fn the_last_wake_of_an_expired_session_is_delayed_at_random_and_survives_the_sweep() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (_app, state, user_id, _token) = registered(&url, false).await;
        sqlx::query("UPDATE sessions SET expires_at = 1 WHERE user_id = $1").bind(&user_id).execute(&state.db).await.unwrap();
        let swept = crate::retention::sweep(&state).await;
        assert_eq!(swept.sessions, 1);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap();
        assert_eq!(rows, 0, "the registration went with the session");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(seen.0.lock().unwrap().is_empty(), "not in the same instant as the sweep");
        assert!(wakes_within(&seen, 1, Duration::from_secs(2)).await, "…but it is sent");
        assert_eq!(seen.0.lock().unwrap()[0].2["kind"], "message");
    }

    #[tokio::test]
    async fn logout_and_a_dead_token_end_the_registration() {
        let count = |state: AppState| async move {
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap()
        };
        // Logout: the session row goes and takes the registration with it; a wake already in
        // its jitter delay is dropped at fire time.
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (app, state, user_id, token) = registered(&url, false).await;
        assert_eq!(count(state.clone()).await, 1);
        wake_users(&state, &[user_id], Kind::Message).await;
        let (status, _) = send(&app, "POST", "/api/auth/logout", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(count(state.clone()).await, 0);
        settle().await;
        assert!(seen.0.lock().unwrap().is_empty(), "no wake after logout");

        // 410 from the gateway: the token is dead, the registration is deleted.
        let (url, seen) = fake_gateway(StatusCode::GONE).await;
        let (_app, state, user_id, _token) = registered(&url, false).await;
        wake_users(&state, &[user_id], Kind::Message).await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 1);
        assert_eq!(count(state).await, 0);
    }

    #[tokio::test]
    async fn a_token_bound_to_one_account_cannot_be_registered_by_another() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (app, state, victim, victim_token) = registered(&url, true).await;
        let (attacker, attacker_token) = signup(&app, "attacker").await;
        let reg = |apns: &str, voip: Option<&str>| json!({ "provider": "gateway", "gateway": url, "apns_token": apns, "voip_token": voip, "topic": "io.skwod.app" });
        // The victim's alert token, their PushKit token, and each in the other slot: all refused.
        for body in [reg(APNS, None), reg(&"cd".repeat(32), Some(VOIP)), reg(VOIP, None), reg(&"cd".repeat(32), Some(APNS))] {
            let (status, _) = send(&app, "POST", "/api/push/register", Some(&attacker_token), Some(body)).await;
            assert_eq!(status, StatusCode::CONFLICT);
        }
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap();
        assert_eq!(rows, 1, "only the victim's registration exists");
        // So activity addressed to the attacker wakes nobody, and cannot touch the victim's schedule…
        wake_users(&state, std::slice::from_ref(&attacker), Kind::Message).await;
        assert_eq!(state.waker.pending_len(), 0);
        // …while the victim is woken exactly as before.
        wake_users(&state, &[victim], Kind::Message).await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 1);
        // The same install registering again (same session) is fine and keeps one row…
        let (status, _) = send(&app, "POST", "/api/push/register", Some(&victim_token), Some(reg(APNS, Some(VOIP)))).await;
        assert_eq!(status, StatusCode::OK);
        // …and so is the same ACCOUNT signing in again on that device: the stale row is replaced.
        let (_, login) = send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "sleeper", "password": "correct horse" }))).await;
        let (status, _) = send(&app, "POST", "/api/push/register", Some(login["token"].as_str().unwrap()), Some(reg(APNS, Some(VOIP)))).await;
        assert_eq!(status, StatusCode::OK);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap();
        assert_eq!(rows, 1);
    }

    #[tokio::test]
    async fn schedules_are_per_registration_not_per_token() {
        // Two accounts whose rows carry the same token (not creatable through the API any more;
        // inserted directly, as a pre-existing database could hold it): each keeps its own
        // schedule, so one account's activity neither merges into nor suppresses the other's.
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (app, state, first, _token) = registered(&url, false).await;
        let (second, second_token) = signup(&app, "second").await;
        sqlx::query("INSERT INTO push_registrations (id, user_id, session_hash, gateway, apns_token, topic, created_at, updated_at) VALUES ('r2', $1, $2, $3, $4, 'io.skwod.app', 0, 0)")
            .bind(&second)
            .bind(crate::auth::token_hash(&second_token))
            .bind(&url)
            .bind(APNS)
            .execute(&state.db)
            .await
            .unwrap();
        wake_users(&state, std::slice::from_ref(&first), Kind::Message).await;
        wake_users(&state, std::slice::from_ref(&second), Kind::Message).await;
        assert_eq!(state.waker.pending_len(), 2, "two registrations, two schedules");
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 2);
        // The second account being handed its event does not silence the first.
        state.session_topic(&crate::auth::token_hash(&second_token), &crate::rt::user_topic(&second), true);
        wake_users(&state, &[first, second], Kind::Message).await;
        settle().await;
        assert_eq!(seen.0.lock().unwrap().len(), 3);
    }
    // ---- instant wakes: declared state, delivery acks, no jitter before the first wake ----

    /// Trailing wakes are far away, so anything that arrives fast was not delayed by jitter.
    fn slow_trailing() -> Timing {
        Timing {
            message_first: Timing::default().message_first,
            call_first: Timing::default().call_first,
            message_delay: (Duration::from_secs(20), Duration::from_secs(20)),
            message_quiet: Duration::from_millis(300),
            call_delay: (Duration::from_secs(20), Duration::from_secs(20)),
            call_quiet: Duration::from_millis(300),
            last_wake: (Duration::ZERO, Duration::ZERO),
        }
    }

    type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

    /// A signed-in install with a gateway registration and an open socket subscribed to its
    /// own user topic, on a server whose ack window is 300 ms.
    async fn connected(gateway: &str, voip: bool) -> (AppState, String, Vec<u8>, Ws) {
        let (state, user_id, hash, mut ws) = connected_unread(gateway, voip).await;
        // Read up to here: the subscription is confirmed.
        say(&mut ws, json!({"type":"ping"})).await;
        (state, user_id, hash, ws)
    }

    /// …the same, but the client has not read a single frame (so it has echoed nothing).
    async fn connected_unread(gateway: &str, voip: bool) -> (AppState, String, Vec<u8>, Ws) {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let mut state = test_state().await;
        state.waker = Waker::new(Policy { allowed_hosts: None, insecure_loopback: true }, slow_trailing());
        state.ws_ack = Duration::from_millis(300);
        state.ws_ack_jitter = Duration::from_millis(100);
        let app = crate::api::router(state.clone());
        let (user_id, token) = signup(&app, "sleeper").await;
        let body = json!({ "provider": "gateway", "gateway": gateway, "apns_token": APNS, "voip_token": if voip { Some(VOIP) } else { None }, "topic": "io.skwod.app" });
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(body)).await.0, StatusCode::OK);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={token}")).await.unwrap();
        ws.send(Message::Text(json!({"type":"subscribe","topic":format!("user:{user_id}")}).to_string())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await; // the server has subscribed it
        (state, user_id, crate::auth::token_hash(&token), ws)
    }

    /// Send one frame and wait until the server has acted on it (it answers the ping after it).
    async fn say(ws: &mut Ws, frame: Value) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        if frame["type"] != "ping" {
            ws.send(Message::Text(frame.to_string())).await.unwrap();
        }
        ws.send(Message::Text(json!({"type":"ping"}).to_string())).await.unwrap();
        while let Some(Ok(m)) = ws.next().await {
            if matches!(&m, Message::Text(t) if t.contains("\"pong\"")) {
                break;
            }
        }
    }

    /// What the server does when sealed mail arrives for `user_id` (`keydir.rs`).
    async fn deliver(state: &AppState, user_id: &str) {
        state.rt.publish(&crate::rt::user_topic(user_id), "sealed", json!({}));
        wake_users(state, &[user_id.to_string()], Kind::Message).await;
    }

    async fn wakes_within(seen: &Seen, n: usize, limit: Duration) -> bool {
        tokio::time::timeout(limit, async {
            while seen.0.lock().unwrap().len() < n {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }

    #[tokio::test]
    async fn a_session_that_said_background_is_woken_at_once_although_its_socket_is_open() {
        use futures_util::StreamExt;
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, mut ws) = connected(&url, false).await;
        assert!(state.session_connected(&hash));
        say(&mut ws, json!({"type":"push","state":"background"})).await;
        assert!(!state.session_connected(&hash), "an install that left the foreground is push-wakeable");

        deliver(&state, &user_id).await;
        assert!(wakes_within(&seen, 1, Duration::from_secs(1)).await, "woken within a second: no waiting for the socket to die");

        // Back in front: in-band again, and (it answers the probe) not woken.
        tokio::time::sleep(Duration::from_millis(400)).await; // past the quiet period
        say(&mut ws, json!({"type":"push","state":"active"})).await;
        assert!(state.session_connected(&hash));
        deliver(&state, &user_id).await;
        let _ = tokio::time::timeout(Duration::from_millis(900), async { while ws.next().await.is_some() {} }).await;
        assert_eq!(seen.0.lock().unwrap().len(), 1);
    }

    /// A build that speaks `push` frames and is backgrounded during a call says "offline" to
    /// everyone and "active" to the push logic: its process is running, it stays in-band.
    #[tokio::test]
    async fn presence_offline_from_a_push_aware_client_in_a_call_does_not_make_it_wakeable() {
        let (url, _seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, _user_id, hash, mut ws) = connected(&url, false).await;
        // An older build: offline presence alone means away.
        say(&mut ws, json!({"type":"presence","status":"offline"})).await;
        assert!(!state.session_connected(&hash));
        say(&mut ws, json!({"type":"presence","status":"online"})).await;
        // A build-45 client has said where it is; from then on only that counts.
        say(&mut ws, json!({"type":"push","state":"active"})).await;
        say(&mut ws, json!({"type":"presence","status":"offline"})).await;
        assert!(state.session_connected(&hash));
        say(&mut ws, json!({"type":"push","state":"background"})).await;
        assert!(!state.session_connected(&hash));
    }

    /// The phone was suspended before any goodbye got out: its socket is open and takes the
    /// event, and nothing reads it. This used to be no notification at all — the wake was
    /// skipped ("connected") and nothing asked again when the socket was finally given up.
    #[tokio::test]
    async fn an_event_delivered_to_a_socket_nobody_reads_wakes_within_the_ack_window() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, ws) = connected(&url, false).await;
        deliver(&state, &user_id).await;
        assert!(seen.0.lock().unwrap().is_empty(), "inside the ack window nothing is sent yet");
        assert!(wakes_within(&seen, 1, Duration::from_millis(1500)).await, "unacked after 300 ± 100 ms → woken (+ ≤ 750 ms)");
        assert!(!state.session_connected(&hash), "…and unreachable until it speaks again");
        // The next message does not wait for an ack at all (it is coalesced as usual).
        tokio::time::sleep(Duration::from_millis(500)).await;
        deliver(&state, &user_id).await;
        assert!(wakes_within(&seen, 2, Duration::from_secs(1)).await);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert_eq!(seen.0.lock().unwrap().len(), 2, "one wake per message, never two");
        drop(ws);
    }

    #[tokio::test]
    async fn an_event_a_live_socket_answers_for_never_wakes_not_even_after_it_closes() {
        use futures_util::StreamExt;
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, mut ws) = connected(&url, false).await;
        for _ in 0..3 {
            deliver(&state, &user_id).await;
            // Reading is what answers the probe (the client stack pongs by itself).
            let _ = tokio::time::timeout(Duration::from_millis(500), async { while ws.next().await.is_some() {} }).await;
            assert!(state.session_connected(&hash));
        }
        ws.close(None).await.unwrap();
        drop(ws);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!state.session_connected(&hash));
        assert!(seen.0.lock().unwrap().is_empty(), "a device that had every event in-band is never woken");
    }

    #[tokio::test]
    async fn a_socket_that_dies_still_owing_an_ack_is_woken_on_the_way_out() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, _hash, ws) = connected(&url, false).await;
        deliver(&state, &user_id).await;
        drop(ws); // gone before it read anything, well inside the ack window
        assert!(wakes_within(&seen, 1, Duration::from_millis(1500)).await);
    }

    #[tokio::test]
    async fn a_ring_into_a_socket_nobody_reads_becomes_a_call_wake() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, _hash, ws) = connected(&url, true).await;
        ring(&state, &user_id).await;
        assert!(wakes_within(&seen, 1, Duration::from_millis(1000)).await);
        assert_eq!(seen.0.lock().unwrap()[0].2, json!({ "token": VOIP, "kind": "call", "topic": "io.skwod.app" }));
        drop(ws);
    }

    /// What `voice.rs` does when someone rings `user_id`.
    async fn ring(state: &AppState, user_id: &str) {
        ring_state(state, user_id);
        state.rt.publish(&crate::rt::user_topic(user_id), "ring", json!({ "ring_id": "r1" }));
        wake_users(state, &[user_id.to_string()], Kind::Call).await;
    }

    #[tokio::test]
    async fn a_ring_that_ended_before_the_ack_deadline_is_not_a_late_call_wake() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, ws) = connected(&url, true).await;
        ring(&state, &user_id).await;
        // The caller hangs up inside the ack window; the socket never answers.
        assert!(state.rings.cancel("voice1", "caller").is_some());
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!state.session_connected(&hash), "the socket is given up all the same");
        assert!(seen.0.lock().unwrap().is_empty(), "no phone rings for a call that is over");
        drop(ws);
    }

    /// Event A, then event B while A's Pong is still on its way, then the phone is suspended:
    /// the Pong for A must not settle B.
    #[tokio::test]
    async fn a_pong_for_an_earlier_event_does_not_settle_a_later_one() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, mut ws) = connected(&url, false).await;
        // A is followed by Ping 1, B by Ping 2. Nothing is read; A's Pong arrives after B.
        deliver(&state, &user_id).await;
        deliver(&state, &user_id).await;
        ws.send(Message::Pong(1u64.to_be_bytes().to_vec())).await.unwrap();
        assert!(wakes_within(&seen, 1, Duration::from_millis(1500)).await, "B was never answered for");
        assert!(!state.session_connected(&hash));
        // …while the Pong for the newest one does settle both.
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, mut ws) = connected(&url, false).await;
        deliver(&state, &user_id).await;
        deliver(&state, &user_id).await;
        ws.send(Message::Pong(2u64.to_be_bytes().to_vec())).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(state.session_connected(&hash));
        assert!(seen.0.lock().unwrap().is_empty());
    }

    /// A client stack that answers Pings without handing the counter back must not be woken
    /// for every message while it is plainly alive — and is still woken when it goes silent.
    #[tokio::test]
    async fn a_client_whose_pongs_are_empty_is_acked_by_any_pong_and_still_woken_when_silent() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, mut ws) = connected_unread(&url, false).await;
        for _ in 0..3 {
            deliver(&state, &user_id).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            ws.send(Message::Pong(Vec::new())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(700)).await;
            assert!(state.session_connected(&hash), "an empty Pong after the probe is an ack");
        }
        assert!(seen.0.lock().unwrap().is_empty(), "never woken while it answers");
        // Suspended: nothing comes back at all.
        deliver(&state, &user_id).await;
        assert!(wakes_within(&seen, 1, Duration::from_millis(1500)).await);
        drop(ws);
    }

    /// One client flooding the bus (typing frames, say) makes other sockets lag. Nothing that
    /// anyone is woken for was dropped: nobody is woken — not at once, not later.
    #[tokio::test]
    async fn a_flood_of_typing_frames_wakes_nobody() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, ws) = connected(&url, true).await;
        // (Even with a ring live for this user.)
        ring_state(&state, &user_id);
        for _ in 0..3000 {
            state.rt.publish("channel:elsewhere", "typing", json!({}));
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(seen.0.lock().unwrap().is_empty());
        assert!(state.session_connected(&hash));
        drop(ws);
    }

    /// Lag that DID drop message events: the socket counts as unreachable and ONE message wake
    /// follows through the jittered ack window — never at once, never a call wake (a live
    /// ring drives those), and not again for further lag inside the quiet period.
    #[tokio::test]
    async fn lag_that_dropped_messages_is_one_delayed_message_wake_and_never_a_call_wake() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, ws) = connected(&url, true).await;
        ring_state(&state, &user_id);
        for round in 0..2 {
            for i in 0..3000 {
                state.rt.publish("channel:elsewhere", if i % 100 == 0 { "message" } else { "typing" }, json!({}));
            }
            if round == 0 {
                tokio::time::sleep(Duration::from_millis(120)).await;
                assert!(seen.0.lock().unwrap().is_empty(), "not at the instant of the flood");
            }
        }
        assert!(wakes_within(&seen, 1, Duration::from_millis(1500)).await);
        assert!(!state.session_connected(&hash));
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let got = seen.0.lock().unwrap().clone();
        assert_eq!(got.len(), 1, "one wake for the lot");
        assert_eq!(got[0].2["kind"], "message", "lag never rings a phone");
        drop(ws);
    }

    /// Audit C4: a `ring` that was dropped for a lagging socket got a message wake only — the
    /// call wake asked for when the ring was published had been skipped because that socket
    /// was going to be handed it. It is rung now.
    #[tokio::test]
    async fn lag_that_dropped_a_ring_is_a_call_wake_too() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, ws) = connected(&url, true).await;
        ring_state(&state, &user_id);
        // The ring, then a flood before the socket's task runs again: the ring is dropped.
        state.rt.publish(&crate::rt::user_topic(&user_id), "ring", json!({}));
        for _ in 0..3000 {
            state.rt.publish("channel:elsewhere", "typing", json!({}));
        }
        // The ring's own wake: skipped, because a socket of the install is on that topic.
        wake_users(&state, std::slice::from_ref(&user_id), Kind::Call).await;
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(seen.0.lock().unwrap().is_empty(), "not at the instant of the flood");
        let two = wakes_within(&seen, 2, Duration::from_millis(3000)).await;
        assert!(two, "{:?}", seen.0.lock().unwrap());
        assert!(!state.session_connected(&hash));
        let kinds: Vec<String> = seen.0.lock().unwrap().iter().map(|w| w.2["kind"].as_str().unwrap_or_default().to_string()).collect();
        assert!(kinds.contains(&"call".to_string()) && kinds.contains(&"message".to_string()), "{kinds:?}");
        drop(ws);
    }

    /// What `AppState::ws_topics` holds is exactly the live, reachable sockets' subscriptions:
    /// a leftover entry would silence an install for good.
    #[tokio::test]
    async fn a_sockets_topics_are_forgotten_when_it_goes_away_or_closes() {
        let (url, _seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, hash, mut ws) = connected(&url, false).await;
        let own = crate::rt::user_topic(&user_id);
        assert!(state.session_handed(&hash, &[own.as_str()]));
        say(&mut ws, json!({"type":"push","state":"background"})).await;
        assert!(!state.session_handed(&hash, &[own.as_str()]), "away: its subscriptions stand in for nothing");
        assert!(state.ws_topics.lock().unwrap().is_empty());
        say(&mut ws, json!({"type":"push","state":"active"})).await;
        assert!(state.session_handed(&hash, &[own.as_str()]));
        say(&mut ws, json!({"type":"unsubscribe","topic":own})).await;
        assert!(!state.session_handed(&hash, &[own.as_str()]));
        say(&mut ws, json!({"type":"subscribe","topic":own})).await;
        assert!(state.session_handed(&hash, &[own.as_str()]));
        drop(ws);
        let gone = tokio::time::timeout(Duration::from_secs(5), async {
            while !state.ws_topics.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(gone.is_ok(), "{:?}", state.ws_topics.lock().unwrap());
    }

    /// A ring recorded as live for `user_id` (no event, no wake).
    fn ring_state(state: &AppState, user_id: &str) {
        let active = crate::voice::ActiveRing {
            ring_id: "r1".into(),
            server_id: "s1".into(),
            from: "caller".into(),
            targets: [user_id.to_string()].into_iter().collect(),
            expires_at: crate::state::now_ms() + 30_000,
        };
        state.rings.start("voice1", active, crate::state::now_ms());
    }

    /// The relay forwards at most one typing signal a second per connection: one client
    /// cannot fill the shared bus with them.
    #[tokio::test]
    async fn typing_is_rate_limited_per_connection() {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message;
        let (url, _seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let (state, user_id, _hash, mut ws) = connected(&url, false).await;
        let mut bus = state.rt.subscribe();
        for _ in 0..200 {
            ws.send(Message::Text(json!({"type":"typing","topic":format!("user:{user_id}")}).to_string())).await.unwrap();
        }
        say(&mut ws, json!({"type":"ping"})).await;
        let mut typing = 0;
        while let Ok(ev) = bus.try_recv() {
            if ev.frame.contains("\"typing\"") {
                typing += 1;
            }
        }
        assert_eq!(typing, 1);
    }

    #[tokio::test]
    async fn the_first_wake_of_a_burst_is_immediate_and_the_rest_is_one_trailing_wake() {
        let (url, seen) = fake_gateway(StatusCode::ACCEPTED).await;
        let mut state = test_state().await;
        // The production jitter before the first wake (0–750 ms); 1.5 s before a trailing one.
        let timing = Timing {
            message_first: Timing::default().message_first,
            message_delay: (Duration::from_millis(1500), Duration::from_millis(1500)),
            message_quiet: Duration::from_millis(200),
            ..fast()
        };
        state.waker = Waker::new(Policy { allowed_hosts: None, insecure_loopback: true }, timing);
        let app = crate::api::router(state.clone());
        let (user_id, token) = signup(&app, "sleeper").await;
        let body = json!({ "provider": "gateway", "gateway": url, "apns_token": APNS, "topic": "io.skwod.app" });
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&token), Some(body)).await.0, StatusCode::OK);
        for _ in 0..25 {
            wake_users(&state, std::slice::from_ref(&user_id), Kind::Message).await;
        }
        assert!(wakes_within(&seen, 1, Duration::from_secs(1)).await, "the first wake goes out within a second");
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(seen.0.lock().unwrap().len(), 1, "the rest of the burst waits out the quiet period and the jitter");
        assert!(wakes_within(&seen, 2, Duration::from_millis(2000)).await, "…and is one wake");
        tokio::time::sleep(Duration::from_millis(2200)).await;
        assert_eq!(seen.0.lock().unwrap().len(), 2);
        assert_eq!(state.waker.pending_len(), 0);
    }
}
