//! Authenticated WebSocket relay: encrypted-envelope fan-out + presence/typing.
//!
//! Protocol (JSON text frames):
//!   client → server: {"type":"subscribe"|"unsubscribe","topic":"channel:<id>"|"dm:<id>"|"server:<id>"|"user:<id>"}
//!                    {"type":"typing","topic":"channel:<id>"|"dm:<id>"}
//!                    {"type":"presence","status":"online"|"idle"|"dnd"|"offline"}
//!                    {"type":"push","state":"background"|"active"}
//!                    {"type":"ping"}
//!   server → client: {"type":"subscribed"|"unsubscribed","topic":...}
//!                    {"type":"event","topic":...,"event":...,"payload":...}   (see rt.rs publishers)
//!                    {"type":"error","message":...} · {"type":"pong"}
//!
//! Subscribing to your own `user:<id>` topic also replays any call still ringing for you
//! (`ring`, payload `replay: true` — see `voice.rs`).
//!
//! Push reachability ("is this install woken through the push gateway, or does it have the event
//! already?") is decided here, per socket, and never by the socket merely being open:
//!   * the client says so — `push: background` the moment the app leaves the foreground (or
//!     `presence: offline`, which older builds send), `push: active` when it is back. An install
//!     that is not in front is woken for every message although its socket may still be open;
//!   * delivery acks — a socket that counts as active is handed a `message`, `sealed` or `ring`
//!     event followed at once by a WebSocket Ping carrying a per-connection counter. The Pong
//!     that echoes it proves the event was read by a running process (every client stack
//!     answers it by itself; no new field, no message id). A client whose Pongs do not carry
//!     the counter back (none has been seen to) is not punished for it: until a socket has
//!     echoed once, ANY frame heard after the probe counts, so such a client is never woken
//!     over and over while it is plainly alive. No Pong within `ws_ack` (3 s, ±
//!     a random 0–750 ms so the wake is not at a fixed offset from the event): the
//!     install is woken anyway and counts as unreachable until it is heard from again. That
//!     covers a phone suspended before its goodbye got out, a half-dead p2p stream, a network
//!     switch.
//!
//! Subscriptions are authorization-checked at subscribe time (channel READ permission, DM
//! participation, server membership, own user topic) AND again before every delivery and typing
//! signal, so a kick, ban, leave, or permission change takes effect on already-open sockets. A
//! revoked topic is dropped from the connection and the client gets
//! {"type":"unsubscribed","topic":...,"reason":"revoked"}. The relay carries ciphertext and
//! routing metadata only; it cannot read what it fans out.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::error::ApiError;
use crate::gateway::Kind;
use crate::perms;
use crate::rt::{server_topic, user_topic};
use crate::state::{now_ms, AppState};
use crate::structure::{channel_server, effective_permissions};

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

/// Upgrade handler. Native clients pass the bearer token either as a header or `?token=`.
///
/// SECURITY / OPS: the `?token=` fallback exists because some native WebSocket clients can't set
/// request headers on the upgrade. It puts a long-lived bearer token in the request URL, so it can
/// leak into reverse-proxy / access logs and browser history. Two mitigations are in force:
///   1. The `Authorization` header is preferred here in code order — a client that CAN set the
///      header never puts its token in the query string.
///   2. Operators MUST scrub `token` (and any query string on the WS upgrade path) from proxy and
///      access logs. The bundled Caddy config does not log query strings for the WS route; any
///      custom reverse proxy in front of this server must do the same.
///
/// If a short-lived single-use WS ticket is added later (a REST endpoint minting a ~30s one-time
/// ticket the upgrade accepts instead of the long-lived token), it should slot in alongside the
/// header path here without removing it — but that requires a coordinated client change to be
/// useful, so it's intentionally deferred rather than shipped as unused, unexercised surface.
/// Open sockets one account may have at once.
pub(crate) const MAX_SOCKETS_PER_USER: u32 = 16;
/// Text frames one connection may send per [`FRAME_WINDOW`]. A client subscribes to every
/// channel and conversation when it connects (hundreds of frames at once on a big skwod) and
/// afterwards sends a ping or a typing signal every few seconds; nothing honest comes near
/// this. A connection that goes over it is closed.
pub(crate) const FRAMES_PER_WINDOW: u32 = 600;
pub(crate) const FRAME_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
/// Topics one connection may be subscribed to.
pub(crate) const MAX_TOPICS: usize = 4096;
/// Presence changes are written to the database and broadcast to every server the user is in:
/// at most this many per [`FRAME_WINDOW`] per connection. (A real client changes status a
/// handful of times an hour; the allowance covers "online, then straight to offline".) Extra
/// ones still count for push purposes — whether this install is woken — but are not written
/// or broadcast.
const PRESENCE_PER_WINDOW: u32 = 6;

/// A per-connection frame budget: a fixed window counter. `false` = over budget.
pub(crate) struct FrameBudget {
    started: std::time::Instant,
    used: u32,
}

impl FrameBudget {
    pub(crate) fn new() -> Self {
        Self { started: std::time::Instant::now(), used: 0 }
    }
    pub(crate) fn take(&mut self, now: std::time::Instant) -> bool {
        if now.duration_since(self.started) >= FRAME_WINDOW {
            self.started = now;
            self.used = 0;
        }
        self.used += 1;
        self.used <= FRAMES_PER_WINDOW
    }
}

pub async fn ws_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<WsQuery>,
    peer: Option<axum::Extension<crate::client_key::P2pPeer>>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    // Prefer the Authorization header; fall back to `?token=` only when it's absent (see the
    // SECURITY note above on why the query fallback is a last resort).
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
        .or(q.token)
        .ok_or(ApiError::Unauthorized)?;
    let hash = Sha256::digest(token.as_bytes()).to_vec();
    // Opening the socket is a use of the session: it slides (auth.rs).
    // …by an install that may still act: a superseded or removed install gets no socket
    // (409 / 410, typed like on every REST route — `auth::install_standing`).
    let user_id = crate::auth::touch_current_session(&state, &hash).await?.ok_or(ApiError::Unauthorized)?;
    if let Some(axum::Extension(peer)) = peer {
        state.p2p_authenticated.note(&state, peer.node_bytes, &user_id, &hash).await;
    }
    // An account has at most five devices; a few sockets each covers reconnect overlap. Beyond
    // that, more sockets are only a way to multiply the work every broadcast costs.
    if state.ws_conns.lock().await.get(&user_id).copied().unwrap_or(0) >= MAX_SOCKETS_PER_USER {
        return Err(ApiError::RateLimited);
    }
    Ok(ws.on_upgrade(move |socket| connection(state, user_id, hash, socket)))
}

/// May `user_id` subscribe to `topic`?
pub(crate) async fn may_subscribe(state: &AppState, user_id: &str, topic: &str) -> Result<bool, ApiError> {
    if let Some(channel_id) = topic.strip_prefix("channel:") {
        let server_id = match channel_server(state, channel_id).await {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        let p = match effective_permissions(state, &server_id, user_id, Some(channel_id)).await {
            Ok(p) => p,
            Err(_) => return Ok(false),
        };
        return Ok(perms::has_permission(p, perms::READ_MESSAGES));
    }
    if let Some(conversation_id) = topic.strip_prefix("dm:") {
        // The waiting room has no conversations (`admission.rs`): an account removed from
        // every server keeps its old conversation rows, and must not keep hearing them.
        if !crate::admission::is_admitted(state, user_id).await? {
            return Ok(false);
        }
        let ok: i64 =
            sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM dm_participants WHERE conversation_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)")
                .bind(conversation_id)
                .bind(user_id)
                .fetch_one(&state.db)
                .await?;
        return Ok(ok == 1);
    }
    if let Some(server_id) = topic.strip_prefix("server:") {
        let ok: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)")
            .bind(server_id)
            .bind(user_id)
            .fetch_one(&state.db)
            .await?;
        return Ok(ok == 1);
    }
    if let Some(topic_user) = topic.strip_prefix("user:") {
        return Ok(topic_user == user_id);
    }
    Ok(false)
}

/// Current authorization for a cached topic. Any error (DB, missing channel) counts as revoked.
async fn still_authorized(state: &AppState, user_id: &str, topic: &str) -> bool {
    matches!(may_subscribe(state, user_id, topic).await, Ok(true))
}

fn revoked_frame(topic: &str) -> String {
    json!({"type":"unsubscribed","topic":topic,"reason":"revoked"}).to_string()
}

/// If `frame` is a `revoke` event, return the server_id whose access was revoked.
fn revoked_server(frame: &str) -> Option<String> {
    let v: Value = serde_json::from_str(frame).ok()?;
    if v.get("event")?.as_str()? != "revoke" {
        return None;
    }
    Some(v.get("payload")?.get("server_id")?.as_str()?.to_string())
}

/// Fan a presence change out to every server the user is a member of.
async fn broadcast_presence(state: &AppState, user_id: &str, status: &str) {
    if let Ok(server_ids) = sqlx::query_scalar::<_, String>(
        "SELECT server_id FROM server_members WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    {
        for sid in server_ids {
            state.rt.publish(&server_topic(&sid), "presence", json!({ "user_id": user_id, "status": status }));
        }
    }
}

/// How often an open socket's session is re-checked (`SKWOD_WS_SESSION_RECHECK_SECS`, default
/// 60; clamped to 1 s – 10 min).
fn session_recheck_interval() -> std::time::Duration {
    let secs = std::env::var("SKWOD_WS_SESSION_RECHECK_SECS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(60);
    std::time::Duration::from_secs(secs.clamp(1, 600))
}

/// Is the session behind this socket still valid right now? A DB error counts as "no": fail
/// closed (the client reconnects and re-authenticates). Why it may no longer be served, if it
/// may not: the session is gone, or
/// its install was superseded or removed since the socket opened (audit H-1 — the device was
/// restored elsewhere; the old install's open socket must not keep receiving).
async fn session_ended(state: &AppState, session_hash: &[u8]) -> Option<&'static str> {
    // A socket that stays open is the session being used: this also slides its expiry, so an
    // app that is connected for weeks is not signed out underneath itself.
    match crate::auth::touch_current_session(state, session_hash).await {
        Ok(Some(_)) => None,
        Err(ApiError::DeviceSuperseded) => Some("device superseded"),
        Err(ApiError::DeviceRemoved) => Some("device removed"),
        _ => Some("session ended"),
    }
}

/// Close frame for a socket whose session ended.
async fn end_session(sink: &mut futures_util::stream::SplitSink<WebSocket, Message>, why: &str) {
    let _ = sink.send(Message::Text(json!({"type":"error","message":why}).to_string())).await;
    let _ = sink.send(Message::Close(None)).await;
}

/// How long this event's probe may go unanswered: `ws_ack` ± a uniform random 0–`ws_ack_jitter`
/// (3 s ± 750 ms), so the wake that follows is not at a fixed offset from the event.
fn ack_window(state: &AppState) -> std::time::Duration {
    use rand::Rng;
    let jitter = state.ws_ack_jitter.min(state.ws_ack / 2).as_millis() as i64;
    let offset = if jitter == 0 { 0 } else { rand::thread_rng().gen_range(-jitter..=jitter) };
    std::time::Duration::from_millis((state.ws_ack.as_millis() as i64 + offset) as u64)
}

/// Events written to a socket that has not yet proven it read them.
#[derive(Clone, Copy)]
struct Owed {
    /// The Ping that followed the newest of them; its echo settles the debt.
    seq: u64,
    /// When the first of them stops waiting.
    due: tokio::time::Instant,
    /// Which wakes stand behind them.
    message: bool,
    call: bool,
}

impl Owed {
    /// Nothing answered: wake the install for what it was handed. A call wake only while that
    /// ring is still live — one that was answered elsewhere, cancelled or timed out in the
    /// meantime must not make a phone ring for nothing.
    ///
    /// `on`: the topics of the owed events. The wake is skipped only if another reachable
    /// socket of the same install is subscribed to all of them (it was handed the same events
    /// and owes its own proof) — never because some socket of the session is merely open.
    async fn wake(self, state: &AppState, session_hash: &[u8], user_id: &str, on: &HashSet<String>) {
        if self.call && !state.rings.for_user(user_id, now_ms()).is_empty() {
            crate::gateway::wake_session(state, session_hash, Kind::Call, &[user_topic(user_id)]).await;
        }
        if self.message {
            let on: Vec<String> = on.iter().cloned().collect();
            crate::gateway::wake_session(state, session_hash, Kind::Message, &on).await;
        }
    }
}

/// Whether ONE socket counts as "this install has its events in-band" (`AppState::session_online`).
#[derive(Default)]
struct Reach {
    /// The client said `presence: offline`.
    away_presence: bool,
    /// The client said `push: background`.
    away_push: bool,
    /// The client speaks `push` frames at all. Then only they say whether it is away: such a
    /// client still sends `presence: offline` when it is backgrounded DURING A CALL (so
    /// others see it offline), while its process and socket keep running — it stays in-band.
    push_aware: bool,
    /// An event was written to it and the probe that followed went unanswered.
    stale: bool,
    /// What `AppState` currently holds for this socket.
    registered: bool,
    /// The topics this connection is subscribed to. While the socket counts as reachable they
    /// are mirrored into `AppState::ws_topics`: only an event on one of them is handed to it,
    /// so only for those does it stand in for a push wake.
    topics: HashSet<String>,
}

impl Reach {
    fn sync(&mut self, state: &AppState, session_hash: &[u8]) {
        let away = if self.push_aware { self.away_push } else { self.away_presence };
        let want = !(away || self.stale);
        if want != self.registered {
            self.registered = want;
            if want { state.session_online(session_hash) } else { state.session_offline(session_hash) }
            for topic in &self.topics {
                state.session_topic(session_hash, topic, want);
            }
        }
    }

    fn subscribe(&mut self, state: &AppState, session_hash: &[u8], topic: &str) {
        if self.topics.insert(topic.to_string()) && self.registered {
            state.session_topic(session_hash, topic, true);
        }
    }

    fn unsubscribe(&mut self, state: &AppState, session_hash: &[u8], topic: &str) -> bool {
        let had = self.topics.remove(topic);
        if had && self.registered {
            state.session_topic(session_hash, topic, false);
        }
        had
    }

    fn close(&mut self, state: &AppState, session_hash: &[u8]) {
        if std::mem::take(&mut self.registered) {
            state.session_offline(session_hash);
            for topic in &self.topics {
                state.session_topic(session_hash, topic, false);
            }
        }
    }
}

async fn connection(state: AppState, user_id: String, session_hash: Vec<u8>, socket: WebSocket) {
    let (mut sink, mut stream) = socket.split();
    // This install is reachable in-band from now on: no push wake for it (gateway.rs) …unless
    // it says it is going away, or stops proving that it reads what it is sent (`Reach`).
    let mut reach = Reach::default();
    reach.sync(&state, &session_hash);
    // Delivery acks: the Ping counter, and the event this socket has not yet proven it read —
    // (the Ping that proves it, when the proof is due, which wake stands behind it).
    let mut ping_seq: u64 = 0;
    let mut owed: Option<Owed> = None;
    // The topics of the events behind `owed` (reset when a new debt starts).
    let mut owed_on: HashSet<String> = HashSet::new();
    // Has this socket ever echoed a Ping's counter? Until it has, any frame heard after a
    // probe is taken as the proof (`Owed`); once it has, only the echo is.
    let mut echoes = false;
    let mut said_blind = false;
    // Lag (this task fell behind the bus and events were dropped for it): the last
    // wake-bearing event number seen, whether a gap is to be checked on the next event, when
    // the wake for a gap is due, and when the last such wake was asked for.
    let mut wake_seen = state.rt.wake_no();
    let mut lagged = false;
    let mut lag_due: Option<tokio::time::Instant> = None;
    let mut lag_woke: Option<tokio::time::Instant> = None;
    // …and the same for `ring` events: was one among what was dropped?
    let mut call_seen = state.rt.call_no();
    let mut lag_call = false;
    // Typing signals are forwarded at most once a second per connection.
    let mut typed: Option<std::time::Instant> = None;
    let mut presence = (std::time::Instant::now(), 0u32);
    let mut budget = FrameBudget::new();
    // Ping on a timer and give the socket up when NOTHING has been heard for two intervals and
    // a bit. A phone that was suspended or lost its network leaves a socket that looks open for
    // minutes; until it is closed the device counts as connected and is not sent push wakes.
    let ping_every = state.ws_ping;
    let deadline = ping_every * 2 + ping_every.min(std::time::Duration::from_secs(10));
    let mut ping = tokio::time::interval(ping_every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let mut last_heard = std::time::Instant::now();
    let mut bus = state.rt.subscribe();

    // Register this live connection. The async lock is held ACROSS the status transition so a
    // quick reconnect (old socket closing while the new one opens) can never interleave — the
    // stale close's offline write cannot land after the new open's refresh.
    {
        let mut conns = state.ws_conns.lock().await;
        let n = conns.entry(user_id.clone()).or_insert(0);
        *n += 1;
        if *n == 1 {
            // First socket: refresh liveness for a visible status. A stored "offline" is NOT
            // promoted — it's indistinguishable from Invisible-by-choice, and promoting it would
            // flash an invisible user online to everyone on every (re)connect. The client's own
            // presence frame (sent as its first frame) authoritatively sets the visible status.
            let current: Option<String> = sqlx::query_scalar("SELECT status FROM profiles WHERE id = $1")
                .bind(&user_id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
            if let Some(status) = current.filter(|s| s != "offline") {
                let _ = sqlx::query("UPDATE profiles SET last_seen_at = $1 WHERE id = $2")
                    .bind(now_ms())
                    .bind(&user_id)
                    .execute(&state.db)
                    .await;
                broadcast_presence(&state, &user_id, &status).await;
            }
        }
    }

    // The session was valid at the upgrade. It can stop being valid while the socket stays open
    // (logout, expiry, a password change or account deletion revoking it), and a socket that is
    // only ever checked once would keep delivering for as long as it stays connected. Re-check
    // on a timer and close when the session is gone.
    let mut session_check = tokio::time::interval(session_recheck_interval());
    session_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    session_check.tick().await; // the first tick completes immediately

    loop {
        // The earlier of: the ack deadline, the (equally jittered) wake for a lag gap.
        let ack_due = match (owed.map(|o| o.due), lag_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        tokio::select! {
            _ = async { match ack_due { Some(at) => tokio::time::sleep_until(at).await, None => std::future::pending().await } } => {
                // Handed an event and silent since: the process behind this socket is not
                // running (or the path to it is dead). Wake the install now, and stop counting
                // it as reachable until it speaks.
                let now = tokio::time::Instant::now();
                if lag_due.is_some_and(|at| at <= now) {
                    // Events were dropped for this socket: it has not got them, so it is
                    // woken for them through the scheduler like any other — a message wake,
                    // and a call wake too if a `ring` was among what was dropped and a ring
                    // for this user is still live (the wake asked for when it was published
                    // was skipped because this socket was going to be handed it). Which
                    // topics were dropped is unknown, so none is named and the wake is never
                    // skipped.
                    lag_due = None;
                    lag_woke = Some(now);
                    reach.stale = true;
                    reach.sync(&state, &session_hash);
                    if std::mem::take(&mut lag_call) && !state.rings.for_user(&user_id, now_ms()).is_empty() {
                        crate::gateway::wake_session(&state, &session_hash, Kind::Call, &[]).await;
                    }
                    crate::gateway::wake_session(&state, &session_hash, Kind::Message, &[]).await;
                }
                if owed.is_some_and(|o| o.due <= now) {
                    let Some(debt) = owed.take() else { continue };
                    reach.stale = true;
                    reach.sync(&state, &session_hash);
                    debt.wake(&state, &session_hash, &user_id, &owed_on).await;
                }
            }
            _ = session_check.tick() => {
                if let Some(why) = session_ended(&state, &session_hash).await {
                    end_session(&mut sink, why).await;
                    break;
                }
            }
            _ = ping.tick() => {
                if last_heard.elapsed() > deadline {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                ping_seq += 1;
                if sink.send(Message::Ping(ping_seq.to_be_bytes().to_vec())).await.is_err() {
                    break;
                }
            }
            incoming = stream.next() => {
                let Some(Ok(msg)) = incoming else { break };
                last_heard = std::time::Instant::now();
                // It speaks: whatever the last unanswered probe said about it is over.
                if reach.stale {
                    reach.stale = false;
                    reach.sync(&state, &session_hash);
                }
                let Message::Text(text) = msg else {
                    if matches!(msg, Message::Close(_)) { break; }
                    if let Message::Pong(echo) = &msg {
                        // A counter this socket was sent, come back: its stack echoes.
                        let counter = <[u8; 8]>::try_from(echo.as_slice()).ok().map(u64::from_be_bytes).filter(|c| (1..=ping_seq).contains(c));
                        match counter {
                            Some(c) => {
                                echoes = true;
                                // The Pong for the probe that followed the newest event: read.
                                if owed.is_some_and(|o| c >= o.seq) {
                                    owed = None;
                                }
                            }
                            // A Pong without the counter, from a socket that has never echoed
                            // one: taken as the answer. Said once, so it can be noticed.
                            None if !echoes => {
                                owed = None;
                                if !std::mem::replace(&mut said_blind, true) {
                                    tracing::info!("a client answers pings without echoing them; delivery acks fall back to any reply");
                                }
                            }
                            None => {}
                        }
                    }
                    continue;
                };
                // Any frame from a socket that has not shown it echoes: it is alive and reading.
                if !echoes {
                    owed = None;
                }
                // Every text frame costs a parse and most cost database queries: a connection
                // that floods is closed, not served.
                if !budget.take(last_heard) {
                    let _ = sink.send(Message::Text(json!({"type":"error","message":"too many frames"}).to_string())).await;
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                let Ok(frame) = serde_json::from_str::<Value>(&text) else {
                    let _ = sink.send(Message::Text(json!({"type":"error","message":"invalid json"}).to_string())).await;
                    continue;
                };
                match frame["type"].as_str() {
                    Some("ping") => {
                        let _ = sink.send(Message::Text(json!({"type":"pong"}).to_string())).await;
                    }
                    Some("subscribe") => {
                        let Some(topic) = frame["topic"].as_str() else { continue };
                        if reach.topics.len() >= MAX_TOPICS && !reach.topics.contains(topic) {
                            let _ = sink.send(Message::Text(json!({"type":"error","message":"subscription refused","topic":topic}).to_string())).await;
                            continue;
                        }
                        match may_subscribe(&state, &user_id, topic).await {
                            Ok(true) => {
                                reach.subscribe(&state, &session_hash, topic);
                                let _ = sink.send(Message::Text(json!({"type":"subscribed","topic":topic}).to_string())).await;
                                // A call that started ringing before this socket existed (the
                                // device was asleep and a push woke it) is replayed now, so
                                // answering joins the right room. Only on the user's own topic.
                                if topic == user_topic(&user_id) {
                                    for payload in crate::voice::pending_rings(&state, &user_id).await {
                                        let frame = json!({ "type": "event", "topic": topic, "event": "ring", "payload": payload });
                                        let _ = sink.send(Message::Text(frame.to_string())).await;
                                    }
                                }
                            }
                            _ => {
                                let _ = sink.send(Message::Text(json!({"type":"error","message":"subscription refused","topic":topic}).to_string())).await;
                            }
                        }
                    }
                    Some("unsubscribe") => {
                        if let Some(topic) = frame["topic"].as_str() {
                            reach.unsubscribe(&state, &session_hash, topic);
                            let _ = sink.send(Message::Text(json!({"type":"unsubscribed","topic":topic}).to_string())).await;
                        }
                    }
                    Some("typing") => {
                        // Typing may only be signaled into a topic this connection is subscribed to
                        // and is still authorized for.
                        if let Some(topic) = frame["topic"].as_str() {
                            if reach.topics.contains(topic) {
                                // One a second per connection (clients send one every few
                                // seconds): a client cannot flood the shared bus with them.
                                if typed.is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(1)) {
                                    continue;
                                }
                                typed = Some(std::time::Instant::now());
                                // Authorization may have changed since subscribe (kick, ban,
                                // permission override): re-check and fail closed.
                                if !still_authorized(&state, &user_id, topic).await {
                                    reach.unsubscribe(&state, &session_hash, topic);
                                    let _ = sink.send(Message::Text(revoked_frame(topic))).await;
                                    continue;
                                }
                                // Block enforcement in the relay: a blocked user's typing indicator
                                // must not reach their blocker in a 1:1 DM (sends are already
                                // refused; the indicator would leak that they're still trying).
                                // Cheap here — one EXISTS on user ids per (client-throttled) typing
                                // frame. Server-topic presence fan-out is NOT filtered: it's a
                                // shared-membership broadcast, and per-viewer filtering would need
                                // per-connection block caches (noted as an accepted gap).
                                if let Some(conversation_id) = topic.strip_prefix("dm:") {
                                    let peer = crate::messages::dm_peer(&state, conversation_id, &user_id).await;
                                    if let Ok(Some(peer)) = peer {
                                        if crate::safety::pair_blocked(&state, &user_id, &peer).await.unwrap_or(false) {
                                            continue;
                                        }
                                    }
                                }
                                state.rt.publish(topic, "typing", json!({ "user_id": user_id }));
                            }
                        }
                    }
                    Some("push") => {
                        // The app left the foreground / came back. Says nothing to anyone else
                        // (unlike presence): it only decides whether this install is woken.
                        match frame["state"].as_str() {
                            Some("background") => reach.away_push = true,
                            Some("active") => reach.away_push = false,
                            _ => continue,
                        }
                        reach.push_aware = true;
                        reach.sync(&state, &session_hash);
                    }
                    Some("presence") => {
                        let Some(status) = frame["status"].as_str() else { continue };
                        if !matches!(status, "online" | "idle" | "dnd" | "offline") { continue; }
                        // Going away / coming back, for push purposes (see `Reach`).
                        reach.away_presence = status == "offline";
                        reach.sync(&state, &session_hash);
                        if presence.0.elapsed() >= FRAME_WINDOW {
                            presence = (std::time::Instant::now(), 0);
                        }
                        presence.1 += 1;
                        if presence.1 > PRESENCE_PER_WINDOW { continue; }
                        if sqlx::query("UPDATE profiles SET status = $1, last_seen_at = $2 WHERE id = $3")
                            .bind(status)
                            .bind(now_ms())
                            .bind(&user_id)
                            .execute(&state.db)
                            .await
                            .is_ok()
                        {
                            // Announce to every server the user is a member of.
                            if let Ok(server_ids) = sqlx::query_scalar::<_, String>(
                                "SELECT server_id FROM server_members WHERE user_id = $1",
                            )
                            .bind(&user_id)
                            .fetch_all(&state.db)
                            .await
                            {
                                for sid in server_ids {
                                    state.rt.publish(&server_topic(&sid), "presence", json!({ "user_id": user_id, "status": status }));
                                }
                            }
                        }
                    }
                    _ => {
                        let _ = sink.send(Message::Text(json!({"type":"error","message":"unknown type"}).to_string())).await;
                    }
                }
            }
            event = bus.recv() => {
                match event {
                    Ok(ev) => {
                        // After a lag: was anything dropped that someone is woken for? (The
                        // numbers before this event, against the last one seen.) If so, and
                        // this socket counts as reachable, it is owed a wake — after the same
                        // jittered window as an unanswered probe, never at the instant of the
                        // flood, and at most once per quiet period.
                        if lagged && ev.call_no - u64::from(ev.wake == Some(Kind::Call)) > call_seen {
                            lag_call = true;
                        }
                        call_seen = ev.call_no;
                        let before = ev.wake_no - u64::from(ev.wake.is_some());
                        if std::mem::take(&mut lagged)
                            && before > wake_seen
                            && reach.registered
                            && lag_due.is_none()
                            && lag_woke.is_none_or(|at| at.elapsed() >= state.waker.message_quiet())
                        {
                            lag_due = Some(tokio::time::Instant::now() + ack_window(&state));
                        }
                        wake_seen = ev.wake_no;
                        // Revocation (kick / ban): the server publishes a "revoke" frame to the
                        // user's own topic. Evict the affected server's server + channel topics
                        // from this connection right away and tell the client, rather than waiting
                        // for the next event on each topic to trip the per-delivery re-check
                        // below. The revoke frame itself is consumed here, not forwarded.
                        if ev.topic == user_topic(&user_id) {
                            // The account's devices or sessions just changed (a restore, a
                            // removal, a password change): is this socket's install still one
                            // that may be served? Checked now, BEFORE this or any later event
                            // is written to it — not at the next timer tick.
                            if ev.security {
                                if let Some(why) = session_ended(&state, &session_hash).await {
                                    end_session(&mut sink, why).await;
                                    break;
                                }
                            }
                            if let Some(sid) = revoked_server(&ev.frame) {
                                let mut evicted: Vec<String> = Vec::new();
                                if reach.unsubscribe(&state, &session_hash, &server_topic(&sid)) {
                                    evicted.push(server_topic(&sid));
                                }
                                let channel_topics: Vec<String> = reach
                                    .topics
                                    .iter()
                                    .filter(|t| t.starts_with("channel:"))
                                    .cloned()
                                    .collect();
                                for t in channel_topics {
                                    let cid = &t["channel:".len()..];
                                    if channel_server(&state, cid).await.ok().as_deref() == Some(sid.as_str()) {
                                        reach.unsubscribe(&state, &session_hash, &t);
                                        evicted.push(t);
                                    }
                                }
                                let mut closed = false;
                                for t in evicted {
                                    if sink.send(Message::Text(revoked_frame(&t))).await.is_err() {
                                        closed = true;
                                        break;
                                    }
                                }
                                if closed {
                                    break;
                                }
                                continue;
                            }
                        }
                        if !reach.topics.contains(&ev.topic) {
                            continue;
                        }
                        // Membership/permissions may have changed since subscribe: re-check, fail
                        // closed, and evict the topic so later events skip the query.
                        if !still_authorized(&state, &user_id, &ev.topic).await {
                            reach.unsubscribe(&state, &session_hash, &ev.topic);
                            if sink.send(Message::Text(revoked_frame(&ev.topic))).await.is_err() {
                                break;
                            }
                            continue;
                        }
                        // Delivery ack: a socket that counts as reachable owes proof that it read
                        // this (not the author's own sockets — nobody is woken for their own
                        // message). The debt is recorded BEFORE the write, so a socket that
                        // dies or stalls under it is woken on the way out.
                        let probe = match ev.wake {
                            Some(kind) if reach.registered && ev.author.as_deref() != Some(user_id.as_str()) => {
                                // Every such event gets a Ping of its own, and only the echo of
                                // the NEWEST one settles the debt — a Pong for an earlier event
                                // that was still in flight says nothing about this one. The
                                // first unanswered event's deadline stands.
                                if owed.is_none() {
                                    owed_on.clear();
                                }
                                owed_on.insert(ev.topic.clone());
                                let mut debt = owed.unwrap_or(Owed { seq: 0, due: tokio::time::Instant::now() + ack_window(&state), message: false, call: false });
                                debt.seq = ping_seq + 1;
                                match kind {
                                    Kind::Message => debt.message = true,
                                    Kind::Call => debt.call = true,
                                }
                                owed = Some(debt);
                                true
                            }
                            _ => false,
                        };
                        // A write that cannot complete within the ack window is a dead path.
                        let write = async {
                            sink.send(Message::Text(ev.frame)).await?;
                            if probe {
                                ping_seq += 1;
                                sink.send(Message::Ping(ping_seq.to_be_bytes().to_vec())).await?;
                            }
                            Ok::<_, axum::Error>(())
                        };
                        if !matches!(tokio::time::timeout(state.ws_ack + state.ws_ack_jitter, write).await, Ok(Ok(()))) {
                            break;
                        }
                    }
                    // Lagged: this slow consumer missed events; clients recover via REST backfill.
                    // Whether what was missed matters is decided on the next event (above).
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        lagged = true;
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    reach.close(&state, &session_hash);
    // The socket ended while it still owed proof for an event: nothing says the device has it.
    if let Some(debt) = owed {
        debt.wake(&state, &session_hash, &user_id, &owed_on).await;
    }
    // Deregister; the LAST connection closing flips the user offline instantly (app quit, crash,
    // network drop — no goodbye frame required). The lock is held across the write + broadcast so
    // a concurrent reconnect (see registration above) serializes after us and re-establishes the
    // correct state — never the other way around.
    {
        let mut conns = state.ws_conns.lock().await;
        let last = match conns.get_mut(&user_id) {
            Some(n) if *n > 1 => { *n -= 1; false }
            _ => { conns.remove(&user_id); true }
        };
        if last {
            let _ = sqlx::query("UPDATE profiles SET status = 'offline', last_seen_at = $1 WHERE id = $2")
                .bind(now_ms())
                .bind(&user_id)
                .execute(&state.db)
                .await;
            broadcast_presence(&state, &user_id, "offline").await;
        }
    }
}
