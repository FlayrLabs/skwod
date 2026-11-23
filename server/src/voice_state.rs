//! Who is in each voice room right now (build 47): the list under a voice channel in the apps'
//! sidebar.
//!
//! **Source of truth: LiveKit itself.** The server asks the SFU's room service (Twirp
//! `ListRooms` + `ListParticipants`, signed with the instance's API key exactly like
//! `voice::evict_from_server_rooms`) and keeps the answer in memory — nothing about calls is
//! written to the database. It asks every [`FAST`] while a call is going on or a room token
//! was minted recently (someone is about to join: `voice_token` wakes it at once), and every
//! [`IDLE`] otherwise, which is also the reconciliation for anything missed. Webhooks are not
//! used: they would need an ingress LiveKit can call and do not exist for an owner-supplied
//! external SFU.
//!
//! **Who learns it:** a change is published as one `voice_state` event per changed room, with
//! the room's FULL roster (idempotent — a lost or reordered event is corrected by the next one),
//! on the `server:<id>` topic, and handed only to a subscriber who may SEE that voice channel
//! ([`may_see`]: a member with Read Messages and Connect on it), checked by the relay before
//! every delivery (`RtEvent::gate_channel`). A socket subscribing to `server:<id>` is handed the
//! current rosters of the rooms it may see at once (`ws.rs`), and
//! `GET /api/servers/:id/voice-state` answers the same. A permission change applies to the next
//! event and the next subscribe (a client that lost access keeps what it was last shown until it
//! reconnects; it is never handed anything new). Call membership was always visible to the host (it mints the tokens and
//! runs the SFU); now it is also visible to the server's members (docs/SECURITY.md).
//!
//! **What an SFU says is not trusted blindly:** only rooms named `skwod-<voice channel id>` of
//! a voice channel that exists count, and only identities that are members of that channel's
//! server are listed. Speaking is not here (it changes many times a second; the apps show it
//! for the call they are in, from their own connection), nor is "deafened" (a local setting
//! LiveKit never sees). Muted (the microphone track is muted or absent), camera and screen
//! share are what the SFU knows.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::{now_ms, AppState};
use crate::voice::ROOM_PREFIX;

/// Poll period while a call is going on (or about to).
pub(crate) const FAST: Duration = Duration::from_secs(2);
/// Poll period otherwise — the reconciliation that catches anything missed.
pub(crate) const IDLE: Duration = Duration::from_secs(20);
/// After a token is minted, the poll stays fast this long (a token is valid for 10 minutes).
const HOT_AFTER_MINT_MS: i64 = 11 * 60 * 1000;
/// Listed per room at most (a sidebar, not a directory).
const MAX_LISTED: usize = 64;

/// One person in a voice room, as the SFU reports them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceMember {
    pub user_id: String,
    /// No unmuted microphone track.
    pub muted: bool,
    pub video: bool,
    pub screen: bool,
    /// Unix seconds (LiveKit's `joined_at`); 0 when not said. Orders the list.
    pub joined_at: i64,
}

impl VoiceMember {
    fn json(&self) -> Value {
        json!({ "user_id": self.user_id, "muted": self.muted, "video": self.video, "screen": self.screen, "joined_at": self.joined_at })
    }
}

#[derive(Default)]
struct Inner {
    /// voice channel id → (server id, roster in join order). Empty rooms are not kept.
    rooms: HashMap<String, (String, Vec<VoiceMember>)>,
    /// Poll fast until this (unix ms).
    hot_until: i64,
}

/// The in-memory voice state of this instance.
#[derive(Clone, Default)]
pub struct VoiceStates {
    inner: Arc<Mutex<Inner>>,
    wake: Arc<tokio::sync::Notify>,
}

impl VoiceStates {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A room token was minted: someone is about to join. Look now, and keep looking often.
    /// (It never adds anyone: only the SFU's answer does.)
    pub fn token_minted(&self, now: i64) {
        self.lock().hot_until = now + HOT_AFTER_MINT_MS;
        self.wake.notify_one();
    }

    /// Something changed membership (a kick): look again now.
    pub fn nudge(&self) {
        self.wake.notify_one();
    }

    fn busy(&self, now: i64) -> bool {
        let g = self.lock();
        !g.rooms.is_empty() || g.hot_until > now
    }

    /// Replace one room's roster. `Some(payload)` when it changed (the event to publish).
    fn set(&self, channel_id: &str, server_id: &str, mut members: Vec<VoiceMember>) -> Option<Value> {
        members.sort_by(|a, b| a.joined_at.cmp(&b.joined_at).then_with(|| a.user_id.cmp(&b.user_id)));
        members.dedup_by(|a, b| a.user_id == b.user_id);
        members.truncate(MAX_LISTED);
        let mut g = self.lock();
        let old = g.rooms.get(channel_id).map(|(_, m)| m.clone()).unwrap_or_default();
        if old == members {
            return None;
        }
        if members.is_empty() {
            g.rooms.remove(channel_id);
        } else {
            g.rooms.insert(channel_id.to_string(), (server_id.to_string(), members.clone()));
        }
        Some(payload(server_id, channel_id, &members))
    }

    /// Every room currently listed: (channel id, server id).
    fn rooms(&self) -> Vec<(String, String)> {
        self.lock().rooms.iter().map(|(c, (s, _))| (c.clone(), s.clone())).collect()
    }

    /// The `voice_state` payloads of one server's non-empty rooms.
    pub fn snapshot(&self, server_id: &str) -> Vec<Value> {
        let g = self.lock();
        let mut out: Vec<(&String, Value)> =
            g.rooms.iter().filter(|(_, (s, _))| s == server_id).map(|(c, (s, m))| (c, payload(s, c, m))).collect();
        out.sort_by(|a, b| a.0.cmp(b.0));
        out.into_iter().map(|(_, v)| v).collect()
    }
}

fn payload(server_id: &str, channel_id: &str, members: &[VoiceMember]) -> Value {
    json!({
        "server_id": server_id,
        "channel_id": channel_id,
        "participants": members.iter().map(VoiceMember::json).collect::<Vec<_>>(),
    })
}

/// An enum LiveKit may send as its name or its number.
fn enum_is(v: &Value, name: &str, number: i64) -> bool {
    v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(name)) || v.as_i64() == Some(number)
}

/// LiveKit `ParticipantInfo` (protojson, snake_case or lowerCamelCase) → who and what, or
/// `None` for someone who is not really in the room (disconnected, no identity).
pub(crate) fn parse_participant(p: &Value) -> Option<VoiceMember> {
    let user_id = p["identity"].as_str().filter(|s| !s.is_empty() && s.len() <= 128)?.to_string();
    // State: JOINING 0 · JOINED 1 · ACTIVE 2 · DISCONNECTED 3.
    if enum_is(&p["state"], "DISCONNECTED", 3) {
        return None;
    }
    let tracks = p["tracks"].as_array().cloned().unwrap_or_default();
    let live = |source: (&str, i64)| {
        tracks.iter().any(|t| enum_is(&t["source"], source.0, source.1) && !t["muted"].as_bool().unwrap_or(false))
    };
    let joined = p.get("joined_at").or_else(|| p.get("joinedAt")).cloned().unwrap_or(Value::Null);
    let joined_at = joined.as_i64().or_else(|| joined.as_str().and_then(|s| s.parse().ok())).unwrap_or(0);
    Some(VoiceMember {
        user_id,
        // Track source: CAMERA 1 · MICROPHONE 2 · SCREEN_SHARE 3.
        muted: !live(("MICROPHONE", 2)),
        video: live(("CAMERA", 1)),
        screen: live(("SCREEN_SHARE", 3)),
        joined_at,
    })
}

/// What the SFU listed: room name → participants (raw `ParticipantInfo`s).
pub(crate) type Listing = Vec<(String, Vec<Value>)>;

/// Apply a complete listing: every voice room of this instance not in it is empty. Publishes a
/// `voice_state` for each room whose roster changed. Returns whether any room is non-empty.
pub(crate) async fn apply_listing(state: &AppState, listing: Listing) -> bool {
    let mut seen = std::collections::HashSet::new();
    for (room, participants) in listing {
        let Some(channel_id) = room.strip_prefix(ROOM_PREFIX) else { continue };
        let server_id: Option<String> = sqlx::query_scalar("SELECT server_id FROM channels WHERE id = $1 AND type = 'voice'")
            .bind(channel_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
        let Some(server_id) = server_id else { continue };
        seen.insert(channel_id.to_string());
        let mut members = Vec::new();
        for p in participants.iter().take(MAX_LISTED * 2) {
            let Some(m) = parse_participant(p) else { continue };
            if is_member(state, &server_id, &m.user_id).await {
                members.push(m);
            }
        }
        if let Some(event) = state.voice_states.set(channel_id, &server_id, members) {
            state.rt.publish(&crate::rt::server_topic(&server_id), "voice_state", event);
        }
    }
    for (channel_id, server_id) in state.voice_states.rooms() {
        if !seen.contains(&channel_id) {
            if let Some(event) = state.voice_states.set(&channel_id, &server_id, Vec::new()) {
                state.rt.publish(&crate::rt::server_topic(&server_id), "voice_state", event);
            }
        }
    }
    !state.voice_states.rooms().is_empty()
}

/// May `user_id` see who is in voice channel `channel_id`: a member of its server with Read
/// Messages (seeing the channel) and Connect (could join it) there. Fails closed.
pub(crate) async fn may_see(state: &AppState, user_id: &str, channel_id: &str) -> bool {
    let Ok(server_id) = crate::structure::channel_server(state, channel_id).await else { return false };
    if !is_member(state, &server_id, user_id).await {
        return false;
    }
    crate::structure::effective_permissions(state, &server_id, user_id, Some(channel_id))
        .await
        .is_ok_and(|p| crate::perms::has_permission(p, crate::perms::READ_MESSAGES) && crate::perms::has_permission(p, crate::perms::CONNECT_VOICE))
}

/// The `voice_state` payloads of one server's rooms that `user_id` may see.
pub(crate) async fn visible_snapshot(state: &AppState, server_id: &str, user_id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    for payload in state.voice_states.snapshot(server_id) {
        if may_see(state, user_id, payload["channel_id"].as_str().unwrap_or_default()).await {
            out.push(payload);
        }
    }
    out
}

async fn is_member(state: &AppState, server_id: &str, user_id: &str) -> bool {
    crate::ws::may_subscribe(state, user_id, &format!("server:{server_id}")).await.unwrap_or(false)
}

/// Ask the SFU who is where. `None` = voice is not configured (or the answer was unusable).
async fn fetch_listing(state: &AppState) -> Result<Option<Listing>, ()> {
    let Some((api_key, api_secret, url)) = crate::voice::livekit_admin(state).await else { return Ok(None) };
    let Some(base) = crate::voice::livekit_http_base(&url) else { return Ok(None) };
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(5));
    if url.starts_with("ws://") {
        builder = builder.no_proxy();
    }
    let http = builder.build().map_err(|_| ())?;
    let token = crate::voice::admin_token(&api_key, &api_secret, json!({ "roomList": true }));
    let rooms: Value = http
        .post(format!("{base}/twirp/livekit.RoomService/ListRooms"))
        .bearer_auth(token)
        .json(&json!({}))
        .send()
        .await
        .map_err(|_| ())?
        .error_for_status()
        .map_err(|_| ())?
        .json()
        .await
        .map_err(|_| ())?;
    let mut out = Vec::new();
    for room in rooms["rooms"].as_array().cloned().unwrap_or_default() {
        let Some(name) = room["name"].as_str().filter(|n| n.starts_with(ROOM_PREFIX)) else { continue };
        let token = crate::voice::admin_token(&api_key, &api_secret, json!({ "room": name, "roomAdmin": true }));
        let listed: Value = http
            .post(format!("{base}/twirp/livekit.RoomService/ListParticipants"))
            .bearer_auth(token)
            .json(&json!({ "room": name }))
            .send()
            .await
            .map_err(|_| ())?
            .error_for_status()
            .map_err(|_| ())?
            .json()
            .await
            .map_err(|_| ())?;
        out.push((name.to_string(), listed["participants"].as_array().cloned().unwrap_or_default()));
    }
    Ok(Some(out))
}

/// One look at the SFU. Voice not configured (or withdrawn: the managed LiveKit is down) →
/// nobody is in any call. A failed request changes nothing (the next look decides).
/// Returns whether any room is non-empty.
pub(crate) async fn reconcile_once(state: &AppState) -> bool {
    match fetch_listing(state).await {
        Ok(Some(listing)) => apply_listing(state, listing).await,
        Ok(None) => apply_listing(state, Vec::new()).await,
        Err(()) => !state.voice_states.rooms().is_empty(),
    }
}

/// The reconciler: runs for the life of the server.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            reconcile_once(&state).await;
            let pause = if state.voice_states.busy(now_ms()) { FAST } else { IDLE };
            let wake = state.voice_states.wake.clone();
            tokio::select! {
                _ = tokio::time::sleep(pause) => {}
                _ = wake.notified() => {
                    // A join takes LiveKit a moment; look just after it.
                    tokio::time::sleep(Duration::from_millis(700)).await;
                }
            }
        }
    })
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/servers/:server_id/voice-state", axum::routing::get(get_voice_state))
}

/// The server's voice rooms and who is in them — members of that server only, and only the
/// rooms each may see ([`may_see`]).
async fn get_voice_state(State(state): State<AppState>, auth: AuthUser, Path(server_id): Path<String>) -> Result<Json<Value>, ApiError> {
    if !is_member(&state, &server_id, &auth.user_id).await {
        return Err(ApiError::Forbidden);
    }
    let rooms: BTreeMap<String, Value> = visible_snapshot(&state, &server_id, &auth.user_id)
        .await
        .into_iter()
        .filter_map(|v| Some((v["channel_id"].as_str()?.to_string(), v["participants"].clone())))
        .collect();
    let channels: Vec<Value> = rooms.into_iter().map(|(c, p)| json!({ "channel_id": c, "participants": p })).collect();
    Ok(Json(json!({ "server_id": server_id, "channels": channels })))
}
