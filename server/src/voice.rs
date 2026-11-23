//! Voice/video access tokens (LiveKit).
//!
//! Mints a LiveKit-compatible JWT (HS256 over the API secret) scoped to a channel's room, for a
//! caller who is a member with `CONNECT_VOICE`. **Fail-closed (ADR-007):** if LiveKit isn't
//! configured on this instance, the endpoint returns an error rather than any token — there is no
//! path that yields an unencrypted/unauthenticated media join.
//!
//! The token only grants SFU room access; media itself is E2EE via LiveKit insertable streams
//! with per-participant keys the clients derive — the server never holds media keys.

use axum::extract::{Path, State};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::perms;
use crate::state::{now_ms, AppState};
use crate::structure::{channel_server, effective_permissions, require_instance_owner};

/// A room token only has to be valid at the moment of joining (LiveKit refreshes it in-session),
/// so it is short-lived: a member removed from a space can't sit on a still-valid token for hours.
/// Every issue re-checks membership + CONNECT_VOICE for the room's own server.
const TOKEN_TTL_SECS: i64 = 10 * 60;

/// LiveKit room name = this prefix + the voice channel id.
pub(crate) const ROOM_PREFIX: &str = "skwod-";

pub fn routes() -> Router<AppState> {
    use axum::routing::{get, post};
    Router::new()
        .route("/channels/:channel_id/voice-token", post(voice_token))
        .route("/channels/:channel_id/ring", post(ring).delete(cancel_ring))
        // Calls ringing for the caller right now (a device woken by a push asks before its
        // WebSocket is up).
        .route("/rings", get(list_rings))
        // Voice/video setup: the instance owner (host) supplies LiveKit creds; any member reads status.
        .route("/voice/config", get(get_voice_config).put(set_voice_config))
}

/// The configured LiveKit ws URL (`wss://…`), if voice is set up on this instance.
async fn livekit_url(state: &AppState) -> Result<Option<String>, ApiError> {
    let url: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'livekit_url'")
        .fetch_optional(&state.db)
        .await?;
    Ok(url.and_then(|b| String::from_utf8(b).ok()))
}

/// Public-to-members status: is voice/video set up, and (if so) the SFU URL clients connect to.
/// Never returns the API secret — that stays server-side for token minting.
async fn get_voice_config(State(state): State<AppState>, _auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let url = livekit_url(&state).await?;
    let configured = url.is_some() && livekit_creds(&state).await?.is_some();
    Ok(Json(json!({ "configured": configured, "url": if configured { url } else { None } })))
}

#[derive(Deserialize)]
struct VoiceConfigReq {
    url: String,
    api_key: String,
    api_secret: String,
}

/// Host-only: store the LiveKit URL + API key/secret so voice/video turns on for everyone on this
/// skwod. Only the instance owner may do this (ADR-007 fail-closed until it's set).
async fn set_voice_config(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<VoiceConfigReq>,
) -> Result<Json<Value>, ApiError> {
    require_instance_owner(&state, &auth.user_id).await?;
    let url = req.url.trim();
    if !(url.starts_with("wss://") || url.starts_with("ws://")) {
        return Err(ApiError::BadRequest("LiveKit URL must start with wss:// (or ws:// for localhost)"));
    }
    let key = req.api_key.trim();
    let secret = req.api_secret.trim();
    if key.is_empty() || secret.is_empty() {
        return Err(ApiError::BadRequest("API key and secret are required"));
    }
    // These three values end up in `livekit.yaml` and in every caller's dial: printable, no
    // whitespace or control characters, bounded (L-5: a newline injected configuration).
    if [url, key, secret].iter().any(|v| v.len() > 512 || v.chars().any(|c| c.is_control() || c.is_whitespace())) {
        return Err(ApiError::BadRequest("LiveKit URL, key and secret must not contain spaces or control characters"));
    }
    // Whoever sets this decides which SFU every caller dials — an attacker's, with a stolen
    // owner token, learned every caller's address and call membership. A device, not just a
    // token (audit M-3).
    let payload = skwod_crypto::link::op_payload(&[url.as_bytes(), key.as_bytes(), secret.as_bytes()]);
    crate::keydir::destructive_authority(&state, &auth, &headers, "voice-config", "", &payload).await?;
    for (name, value) in [("livekit_url", url), ("livekit_api_key", key), ("livekit_api_secret", secret)] {
        sqlx::query(
            "INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, $3)
             ON CONFLICT (name) DO UPDATE SET value = excluded.value, created_at = excluded.created_at",
        )
        .bind(name)
        .bind(value.as_bytes())
        .bind(now_ms())
        .execute(&state.db)
        .await?;
    }
    Ok(Json(json!({ "configured": true, "url": url })))
}

/// LiveKit API key + secret, if this instance has voice configured.
async fn livekit_creds(state: &AppState) -> Result<Option<(String, String)>, ApiError> {
    let key: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'livekit_api_key'")
        .fetch_optional(&state.db)
        .await?;
    let secret: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'livekit_api_secret'")
            .fetch_optional(&state.db)
            .await?;
    match (key, secret) {
        (Some(k), Some(s)) => Ok(Some((
            String::from_utf8(k).map_err(|_| ApiError::Internal)?,
            String::from_utf8(s).map_err(|_| ApiError::Internal)?,
        ))),
        _ => Ok(None),
    }
}

fn sign_jwt(api_key: &str, api_secret: &str, room: &str, identity: &str, now_secs: i64, can_publish: bool) -> String {
    let header = json!({ "alg": "HS256", "typ": "JWT" });
    // LiveKit video-grant claims. `canPublish` is gated on SPEAK_VOICE so a connect-only member
    // can listen but not transmit.
    let claims = json!({
        "iss": api_key,
        "sub": identity,
        "iat": now_secs,
        "nbf": now_secs,
        "exp": now_secs + TOKEN_TTL_SECS,
        "video": {
            "room": room,
            "roomJoin": true,
            "canPublish": can_publish,
            "canSubscribe": true,
        },
    });
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).unwrap()),
        B64URL.encode(serde_json::to_vec(&claims).unwrap())
    );
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(api_secret.as_bytes()).expect("hmac key");
    mac.update(signing_input.as_bytes());
    let sig = B64URL.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig}")
}

async fn voice_token(
    State(state): State<AppState>,
    auth: AuthUser,
    p2p_peer: Option<axum::Extension<crate::client_key::P2pPeer>>,
    Path(channel_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Fail closed: no LiveKit config → no token, ever.
    let (api_key, api_secret) = livekit_creds(&state).await?.ok_or(ApiError::Forbidden)?;

    // Must be a voice channel the caller may connect to.
    let kind: Option<String> =
        sqlx::query_scalar("SELECT type FROM channels WHERE id = $1").bind(&channel_id).fetch_optional(&state.db).await?;
    if kind.as_deref() != Some("voice") {
        return Err(ApiError::BadRequest("not a voice channel"));
    }
    let server_id = channel_server(&state, &channel_id).await?;
    let p = effective_permissions(&state, &server_id, &auth.user_id, Some(&channel_id)).await?;
    if !perms::has_permission(p, perms::CONNECT_VOICE) {
        return Err(ApiError::Forbidden);
    }
    let can_publish = perms::has_permission(p, perms::SPEAK_VOICE);

    let room = format!("{ROOM_PREFIX}{channel_id}");
    let now_secs = now_ms() / 1000;
    let token = sign_jwt(&api_key, &api_secret, &room, &auth.user_id, now_secs, can_publish);
    // Include the SFU URL so the client knows where to connect (it isn't surfaced anywhere else).
    let url = livekit_url(&state).await?;
    // `tunnel`: the caller is on the p2p transport and the SFU is the host's local one — it must
    // reach LiveKit THROUGH its p2p connection (the client core swaps in its loopback URL); `url`
    // is the host-local address and is not dialable from the member's device.
    let tunnel = p2p_peer.is_some() && crate::p2p::livekit_target(&state).await.is_some();
    // Joining answers a ring: stop replaying it to this user's other devices.
    if state.rings.answered(&channel_id, &auth.user_id) {
        state.rt.publish(&crate::rt::user_topic(&auth.user_id), "ring_cancel", json!({ "channel_id": channel_id, "server_id": server_id, "reason": "answered" }));
    }
    Ok(Json(json!({ "token": token, "room": room, "url": url, "tunnel": tunnel, "expires_at": (now_secs + TOKEN_TTL_SECS) * 1000 })))
}

/// How long a call keeps ringing. Matches the apps' ring screens (docs/APPLE.md).
pub const RING_TTL_MS: i64 = 45_000;

/// One ringing call. Held in memory only; nothing about calls is ever written to the database.
#[derive(Clone, Debug)]
pub struct ActiveRing {
    pub ring_id: String,
    pub server_id: String,
    pub from: String,
    /// Members still being rung (an answer or the caller's cancel removes them).
    pub targets: std::collections::HashSet<String>,
    pub expires_at: i64,
}

impl ActiveRing {
    fn payload(&self, channel_id: &str, replay: bool) -> Value {
        json!({
            "channel_id": channel_id, "server_id": self.server_id, "from": self.from,
            "ring_id": self.ring_id, "expires_at": self.expires_at, "replay": replay,
        })
    }
}

/// The active ring per voice channel. A `ring` WebSocket event is one-shot, and a device woken by
/// a push connects after it was sent — so the ring is kept here for [`RING_TTL_MS`] and handed to
/// that user's sockets when they subscribe to their own topic (`ws.rs`) or ask `GET /api/rings`.
/// Bounded by the ring rate limits: at most one entry per channel, expired ones swept on insert.
#[derive(Clone, Default)]
pub struct Rings(std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, ActiveRing>>>);

impl Rings {
    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, ActiveRing>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn start(&self, channel_id: &str, ring: ActiveRing, now: i64) {
        let mut map = self.lock();
        map.retain(|_, r| r.expires_at > now);
        map.insert(channel_id.to_string(), ring);
    }

    /// Live rings that target `user_id`, as `(channel id, ring)`.
    pub(crate) fn for_user(&self, user_id: &str, now: i64) -> Vec<(String, ActiveRing)> {
        self.lock().iter().filter(|(_, r)| r.expires_at > now && r.targets.contains(user_id)).map(|(c, r)| (c.clone(), r.clone())).collect()
    }

    /// `user_id` joined the call: they are no longer rung. `true` if they were.
    pub(crate) fn answered(&self, channel_id: &str, user_id: &str) -> bool {
        let mut map = self.lock();
        let Some(ring) = map.get_mut(channel_id) else { return false };
        let was = ring.targets.remove(user_id);
        if ring.targets.is_empty() {
            map.remove(channel_id);
        }
        was
    }

    /// The caller gave up. Returns the ring if `from` is the one who started it.
    pub(crate) fn cancel(&self, channel_id: &str, from: &str) -> Option<ActiveRing> {
        let mut map = self.lock();
        if map.get(channel_id).is_some_and(|r| r.from == from) {
            return map.remove(channel_id);
        }
        None
    }
}

/// May `user_id` be rung for `channel_id` by `from` RIGHT NOW: still allowed to connect to the
/// channel, and no block either way. Fails closed.
async fn may_be_rung(state: &AppState, server_id: &str, channel_id: &str, user_id: &str, from: &str) -> bool {
    let can = effective_permissions(state, server_id, user_id, Some(channel_id)).await.is_ok_and(|p| perms::has_permission(p, perms::CONNECT_VOICE));
    can && !crate::safety::pair_blocked(state, from, user_id).await.unwrap_or(true)
}

/// The `ring` payloads `user_id` should (still) be shown, re-authorized at the time of asking —
/// a member kicked, or blocked by the caller, since the ring started gets nothing.
pub(crate) async fn pending_rings(state: &AppState, user_id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for (channel_id, ring) in state.rings.for_user(user_id, now_ms()) {
        if may_be_rung(state, &ring.server_id, &channel_id, user_id, &ring.from).await {
            out.push(ring.payload(&channel_id, true));
        }
    }
    out
}

async fn list_rings(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "rings": pending_rings(&state, &auth.user_id).await })))
}

#[derive(Deserialize, Default)]
struct RingReq {
    /// Ring only these members (default: everyone who may connect to the channel).
    user_ids: Option<Vec<String>>,
}

/// The voice channel's server, if the caller is a member who may connect to it.
async fn voice_channel_for(state: &AppState, user_id: &str, channel_id: &str) -> Result<String, ApiError> {
    let kind: Option<String> =
        sqlx::query_scalar("SELECT type FROM channels WHERE id = $1").bind(channel_id).fetch_optional(&state.db).await?;
    if kind.as_deref() != Some("voice") {
        return Err(ApiError::BadRequest("not a voice channel"));
    }
    let server_id = channel_server(state, channel_id).await?;
    // Errors `Forbidden` for a non-member.
    let p = effective_permissions(state, &server_id, user_id, Some(channel_id)).await?;
    if !perms::has_permission(p, perms::CONNECT_VOICE) {
        return Err(ApiError::Forbidden);
    }
    Ok(server_id)
}

/// "I am calling": ask the other members' devices to ring. Connected devices get a realtime
/// `ring` event; sleeping ones get a `call` wake through the blind push gateway (PushKit) and
/// then learn who calls and where from the server — the ring is kept for [`RING_TTL_MS`] and
/// replayed to them when they connect ([`Rings`]). The wake itself says nothing.
///
/// Members only (CONNECT_VOICE on this channel), and rate-limited per caller — per channel and
/// overall — because every ring can wake every member's phone.
async fn ring(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<String>,
    body: Option<Json<RingReq>>,
) -> Result<Json<Value>, ApiError> {
    let server_id = voice_channel_for(&state, &auth.user_id, &channel_id).await?;
    state.limiter.check(&format!("ring:{}:{channel_id}", auth.user_id), 3, crate::limiter::MINUTE)?;
    state.limiter.check(&format!("ring:{}", auth.user_id), 6, crate::limiter::MINUTE)?;
    let members: Vec<String> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1 AND user_id <> $2")
        .bind(&server_id)
        .bind(&auth.user_id)
        .fetch_all(&state.db)
        .await?;
    let only = body.and_then(|Json(b)| b.user_ids);
    let mut targets = Vec::new();
    for user_id in members {
        if only.as_ref().is_some_and(|o| !o.contains(&user_id)) {
            continue;
        }
        // Only people who could actually pick up, and never across a block.
        if may_be_rung(&state, &server_id, &channel_id, &user_id, &auth.user_id).await {
            targets.push(user_id);
        }
    }
    let now = now_ms();
    let active = ActiveRing {
        ring_id: crate::state::new_id(),
        server_id: server_id.clone(),
        from: auth.user_id.clone(),
        targets: targets.iter().cloned().collect(),
        expires_at: now + RING_TTL_MS,
    };
    let payload = active.payload(&channel_id, false);
    if !targets.is_empty() {
        state.rings.start(&channel_id, active, now);
    }
    for user_id in &targets {
        state.rt.publish(&crate::rt::user_topic(user_id), "ring", payload.clone());
    }
    crate::gateway::wake_users(&state, &targets, crate::gateway::Kind::Call).await;
    Ok(Json(json!({ "rang": targets.len(), "ring_id": payload["ring_id"], "expires_at": payload["expires_at"] })))
}

/// The caller hung up before anyone answered: stop the ring everywhere. Only the member who
/// started the ring can end it.
async fn cancel_ring(State(state): State<AppState>, auth: AuthUser, Path(channel_id): Path<String>) -> Result<Json<Value>, ApiError> {
    voice_channel_for(&state, &auth.user_id, &channel_id).await?;
    let Some(ring) = state.rings.cancel(&channel_id, &auth.user_id) else { return Ok(Json(json!({ "cancelled": false }))) };
    for user_id in &ring.targets {
        state.rt.publish(
            &crate::rt::user_topic(user_id),
            "ring_cancel",
            json!({ "channel_id": channel_id, "server_id": ring.server_id, "ring_id": ring.ring_id, "reason": "cancelled" }),
        );
    }
    Ok(Json(json!({ "cancelled": true })))
}

/// The LiveKit HTTP API base for a signaling URL (`ws://h:p` → `http://h:p`).
fn livekit_http_base(ws_url: &str) -> Option<String> {
    let rest = ws_url.strip_prefix("ws://").map(|r| format!("http://{r}")).or_else(|| ws_url.strip_prefix("wss://").map(|r| format!("https://{r}")))?;
    Some(rest.trim_end_matches('/').to_string())
}

/// Kick/ban follow-through: remove `user_id` from every LiveKit room of `server_id` right now
/// (LiveKit `RoomService/RemoveParticipant`). Best effort — the tunnel's own re-validation and
/// the short token TTL are the backstops; this just makes the cut immediate, and is the only cut
/// for members connected to an external (non-tunnelled) SFU.
pub async fn evict_from_server_rooms(state: &AppState, server_id: &str, user_id: &str) {
    let (Ok(Some((api_key, api_secret))), Ok(Some(url))) = (livekit_creds(state).await, livekit_url(state).await) else { return };
    let Some(base) = livekit_http_base(&url) else { return };
    let channels: Vec<String> = sqlx::query_scalar("SELECT id FROM channels WHERE server_id = $1 AND type = 'voice'")
        .bind(server_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    let Ok(http) = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build() else { return };
    let now_secs = now_ms() / 1000;
    for channel_id in channels {
        let room = format!("{ROOM_PREFIX}{channel_id}");
        let claims = json!({
            "iss": api_key, "sub": "skwod-server", "iat": now_secs, "nbf": now_secs, "exp": now_secs + 60,
            "video": { "room": room, "roomAdmin": true },
        });
        let signing_input = format!(
            "{}.{}",
            B64URL.encode(serde_json::to_vec(&json!({ "alg": "HS256", "typ": "JWT" })).unwrap_or_default()),
            B64URL.encode(serde_json::to_vec(&claims).unwrap_or_default())
        );
        let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(api_secret.as_bytes()) else { return };
        mac.update(signing_input.as_bytes());
        let admin = format!("{signing_input}.{}", B64URL.encode(mac.finalize().into_bytes()));
        // 404 (not in the room) is the common, fine outcome.
        let _ = http
            .post(format!("{base}/twirp/livekit.RoomService/RemoveParticipant"))
            .bearer_auth(admin)
            .json(&json!({ "room": room, "identity": user_id }))
            .send()
            .await;
    }
}

#[cfg(test)]
pub(crate) mod verify {
    //! Test-only JWT verification so integration tests can assert a minted token is valid.
    use super::*;

    pub fn verify(token: &str, api_secret: &str) -> Option<Value> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(api_secret.as_bytes()).ok()?;
        mac.update(format!("{}.{}", parts[0], parts[1]).as_bytes());
        let expected = B64URL.encode(mac.finalize().into_bytes());
        if expected != parts[2] {
            return None;
        }
        let claims = B64URL.decode(parts[1]).ok()?;
        serde_json::from_slice(&claims).ok()
    }
}
