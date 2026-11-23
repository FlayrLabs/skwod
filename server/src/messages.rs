//! Ciphertext message relay — channel messages and DMs.
//!
//! The server stores and routes opaque envelopes; edit/delete/pin/reactions/read-states are
//! METADATA operations on those envelopes. Deleting a message blanks its ciphertext (the server
//! shouldn't keep bytes the author asked to remove). Reactions carry a client-computed keyed
//! `emoji_hash` so uniqueness is enforceable without the server learning the emoji.

#![allow(clippy::type_complexity)]

use axum::extract::{Path, Query, State};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::perms;
use crate::rt::{channel_topic, dm_topic};
use crate::state::{new_id, now_ms, AppState};
use crate::structure::{channel_server, effective_permissions};

/// Channel sends per account per minute. One allowance for everything a client sends into a
/// channel — the server cannot (and must not be able to) tell a chat line from a whiteboard
/// stroke — so it is sized for a person drawing, not only for a person typing.
const SENDS_PER_MINUTE: u32 = 600;
/// Reactions added per account per minute (channel and DM together).
const REACTIONS_PER_MINUTE: u32 = 120;
/// Conversations opened per account per hour.
const DMS_PER_HOUR: u32 = 30;
const DEFAULT_PAGE: i64 = 50;
const MAX_PAGE: i64 = 100;

pub fn routes() -> Router<AppState> {
    use axum::routing::{delete, post, put};
    Router::new()
        .route("/channels/:channel_id/messages", post(send_message).get(list_messages).delete(clear_channel))
        .route("/messages/:message_id", axum::routing::patch(edit_message).delete(delete_message))
        .route("/messages/:message_id/pin", put(pin_message).delete(unpin_message))
        .route("/messages/:message_id/reactions", post(add_reaction).get(list_reactions))
        .route("/messages/:message_id/reactions/:emoji_hash", delete(remove_reaction))
        .route("/dms", post(create_dm).get(list_dms))
        .route("/dms/:conversation_id/messages", post(send_dm).get(list_dm_messages))
        .route("/dm-messages/:message_id", axum::routing::patch(edit_dm).delete(delete_dm))
        .route("/dm-messages/:message_id/reactions", post(add_dm_reaction))
        .route("/dm-messages/:message_id/reactions/:emoji_hash", delete(remove_dm_reaction))
        .route("/read-states/:channel_id", put(put_read_state))
        // One message per request, and a message is at most `MAX_MESSAGE_CIPHERTEXT`.
        .layer(axum::extract::DefaultBodyLimit::max(crate::storage::MESSAGE_BODY_LIMIT))
}

/// Decode a message ciphertext, refusing an empty one and one larger than any client accepts.
fn message_ciphertext(b64: &str) -> Result<Vec<u8>, ApiError> {
    // Checked on the encoded length first, so an oversized body is not even decoded.
    if b64.len() > crate::storage::MAX_MESSAGE_CIPHERTEXT.div_ceil(3) * 4 {
        return Err(ApiError::PayloadTooLarge("that message is too big to send"));
    }
    let ciphertext = b64_decode(b64)?;
    if ciphertext.is_empty() {
        return Err(ApiError::BadRequest("empty ciphertext"));
    }
    if ciphertext.len() > crate::storage::MAX_MESSAGE_CIPHERTEXT {
        return Err(ApiError::PayloadTooLarge("that message is too big to send"));
    }
    Ok(ciphertext)
}

/// A reaction's two fields, size-checked; the limiter and the quota are charged here too, so
/// the channel and DM routes cannot drift apart.
async fn checked_reaction(state: &AppState, user_id: &str, req: &AddReaction) -> Result<Vec<u8>, ApiError> {
    state.limiter.check(&format!("reaction:{user_id}"), REACTIONS_PER_MINUTE, crate::limiter::MINUTE)?;
    if req.emoji_hash.is_empty() || req.emoji_hash.len() > crate::storage::MAX_REACTION_HASH {
        return Err(ApiError::BadRequest("emoji_hash size"));
    }
    if req.emoji_ciphertext.len() > crate::storage::MAX_REACTION_CIPHERTEXT * 2 {
        return Err(ApiError::BadRequest("reaction too large"));
    }
    let emoji = b64_decode(&req.emoji_ciphertext)?;
    if emoji.len() > crate::storage::MAX_REACTION_CIPHERTEXT {
        return Err(ApiError::BadRequest("reaction too large"));
    }
    crate::storage::charge(state, user_id, emoji.len() + req.emoji_hash.len()).await?;
    Ok(emoji)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(s).map_err(|_| ApiError::BadRequest("invalid base64"))
}

async fn require_channel_permission(
    state: &AppState,
    channel_id: &str,
    user_id: &str,
    permission: i64,
) -> Result<(), ApiError> {
    let server_id = channel_server(state, channel_id).await?;
    let p = effective_permissions(state, &server_id, user_id, Some(channel_id)).await?;
    if perms::has_permission(p, permission) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

async fn require_dm_participant(state: &AppState, conversation_id: &str, user_id: &str) -> Result<(), ApiError> {
    let ok: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM dm_participants WHERE conversation_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(conversation_id)
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    if ok == 1 {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

// ---- channel messages ----

#[derive(Deserialize)]
pub struct SendMessage {
    pub ciphertext: String, // b64 opaque envelope
    pub reply_to_id: Option<String>,
    pub mention_user_ids: Option<Vec<String>>,
    pub author_device_id: Option<String>,
    /// The id the CLIENT chose for this message (a UUID). Current clients always send one: the
    /// id is sealed inside the ciphertext and receivers drop a ciphertext filed under any other
    /// id, so the server must use exactly it — or refuse. Absent only from build-42 clients.
    pub message_id: Option<String>,
    /// Blobs this message's (encrypted) body refers to. Linked to the message in the same
    /// transaction, so whoever can read the message can fetch them (`blobs.rs`).
    #[serde(default)]
    pub blob_ids: Vec<String>,
}

// Deliberately NOT here: any field that says what KIND of message this is ("silent", a
// separate lane for game moves, …). To the server every channel message is the same opaque
// envelope — a chat line, a like, a chess move and an avatar update are indistinguishable, are
// stored the same way and wake devices the same way (coalesced and jittered, `gateway.rs`).
// What deserves a notification is decided by the recipient after decrypting.

/// A send whose id is already taken. `Some(created_at)` when it is the SAME author's message in
/// the SAME channel: the client is retrying a send whose answer it never saw (its outbox), so
/// it gets the original's answer and nothing is stored or announced twice. Anything else — the
/// id belongs to another author or channel — is `409`: an id never shadows an existing message.
/// A message the author has since deleted also answers as sent (the retry must not revive it).
async fn resent(state: &AppState, id: &str, channel_id: &str, author: &str) -> Result<Option<i64>, ApiError> {
    let row: Option<(String, Option<String>, i64)> =
        sqlx::query_as("SELECT channel_id, author_id, created_at FROM messages WHERE id = $1").bind(id).fetch_optional(&state.db).await?;
    match row {
        None => Ok(None),
        Some((c, a, created_at)) if c == channel_id && a.as_deref() == Some(author) => Ok(Some(created_at)),
        Some(_) => Err(ApiError::Conflict("message id already exists")),
    }
}

async fn send_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<SendMessage>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("msg_send:{}", auth.user_id), SENDS_PER_MINUTE, crate::limiter::MINUTE)?;
    require_channel_permission(&state, &channel_id, &auth.user_id, perms::SEND_MESSAGES).await?;
    let ciphertext = message_ciphertext(&req.ciphertext)?;
    crate::storage::charge(&state, &auth.user_id, ciphertext.len()).await?;
    require_author_device(&state, &auth, req.author_device_id.as_deref()).await?;
    let mentions = req.mention_user_ids.map(|m| serde_json::to_string(&m).expect("string vec"));
    // Honour a client-chosen id exactly: it must be a canonical UUID, and one that is already
    // taken (by ANY message, deleted or not) is refused with 409 — never silently replaced by an
    // id of ours, and never allowed to shadow an existing message.
    let id = match req.message_id {
        Some(id) => {
            if uuid::Uuid::parse_str(&id).map(|u| u.hyphenated().to_string()) != Ok(id.clone()) {
                return Err(ApiError::BadRequest("message_id must be a lowercase UUID"));
            }
            crate::oldbuilds::seen_current(&state, &auth.user_id, req.author_device_id.as_deref());
            if let Some(created_at) = resent(&state, &id, &channel_id, &auth.user_id).await? {
                return Ok(Json(json!({ "message_id": id, "created_at": created_at, "duplicate": true })));
            }
            id
        }
        // Builds 41/42 let the server choose the id. Their messages cannot carry what newer
        // members check (the id inside the ciphertext), and they cannot read anything a newer
        // member writes — so the send is refused with a sentence those builds show.
        None => {
            crate::oldbuilds::seen_old(&state, &auth.user_id, req.author_device_id.as_deref());
            return Err(ApiError::UpgradeRequired(crate::oldbuilds::UPDATE_REQUIRED));
        }
    };
    if !req.blob_ids.is_empty() {
        require_channel_permission(&state, &channel_id, &auth.user_id, perms::ATTACH_FILES).await?;
    }
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO messages (id, channel_id, author_id, author_device_id, ciphertext, reply_to_id, mention_user_ids, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id)
    .bind(&channel_id)
    .bind(&auth.user_id)
    .bind(&req.author_device_id)
    .bind(&ciphertext)
    .bind(&req.reply_to_id)
    .bind(&mentions)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await;
    if let Err(e) = inserted {
        // Two sends racing on one id: the primary key decides. The loser is told what a retry
        // would be told — its own message is there — or 409 when the id is someone else's.
        drop(tx);
        return match ApiError::from(e) {
            ApiError::Conflict(_) => match resent(&state, &id, &channel_id, &auth.user_id).await? {
                Some(created_at) => Ok(Json(json!({ "message_id": id, "created_at": created_at, "duplicate": true }))),
                None => Err(ApiError::Conflict("message id already exists")),
            },
            other => Err(other),
        };
    }
    // The attachments become readable by the channel in the same commit as the message.
    crate::blobs::link_to_message(&mut tx, &auth.user_id, &id, &req.blob_ids, now).await?;
    tx.commit().await?;
    state.rt.publish(
        &channel_topic(&channel_id),
        "message",
        json!({
            "message_id": id,
            "channel_id": channel_id,
            "author_id": auth.user_id,
            "author_device_id": req.author_device_id,
            "ciphertext": req.ciphertext,
            "reply_to_id": req.reply_to_id,
            "created_at": now,
        }),
    );
    dispatch_push(&state, &format!("channel:{channel_id}"), &id, &auth.user_id, PushScope::Channel(&channel_id)).await;
    Ok(Json(json!({ "message_id": id, "created_at": now })))
}

/// A message (or an edit) names the device that sealed it; readers decrypt it as that device.
/// It must be a device REGISTERED on the author's account right now — a removed device cannot
/// post, whatever session it still holds — and the session must speak for exactly that device at
/// its current generation (`keydir::require_device_session`: a superseded install gets 409).
pub(crate) async fn require_author_device(state: &AppState, auth: &AuthUser, device_id: Option<&str>) -> Result<(), ApiError> {
    let Some(device_id) = device_id else {
        // No device named (a build-42 edit; nothing can decrypt a new message without one).
        // A session that speaks for a device must say so.
        return if auth.device_id.is_some() { Err(ApiError::BadRequest("author_device_id required")) } else { Ok(()) };
    };
    crate::keydir::require_device_session(state, auth, device_id).await
}

/// Data-only push wakeup for ONE user: "you have sealed mail". Carries no sender, scope or message
/// id — the server does not know them. Best-effort.
pub(crate) async fn wake_user(state: &AppState, user_id: &str) {
    crate::gateway::wake_users(state, &[user_id.to_string()], crate::gateway::Kind::Message).await;
    let Ok(wakeups) = crate::push::build_wakeups(state, "sealed", "", "", &[user_id.to_string()]).await else { return };
    for w in wakeups {
        match w.platform.as_str() {
            "ios" | "macos" => {
                if let Some(apns) = state.apns.clone() {
                    tokio::spawn(async move { apns.send(&w.token, &w.scope, &w.message_id).await; });
                }
            }
            "android" => {
                if let Some(fcm) = state.fcm.clone() {
                    tokio::spawn(async move { fcm.send(&w.token, &w.scope, &w.message_id).await; });
                }
            }
            _ => {}
        }
    }
}

/// Which recipient set a push wakeup targets.
enum PushScope<'a> {
    Channel(&'a str),
    Dm(&'a str),
}

/// Build and hand off data-only wakeups for a new message. Best-effort: a push failure never
/// fails the send. No plaintext is ever included (SECURITY.md invariant #4).
async fn dispatch_push(state: &AppState, scope: &str, message_id: &str, author_id: &str, target: PushScope<'_>) {
    let recipients = match target {
        PushScope::Channel(id) => crate::push::channel_recipients(state, id).await,
        PushScope::Dm(id) => crate::push::dm_recipients(state, id).await,
    };
    let Ok(recipients) = recipients else { return };
    // Nobody who has blocked the author is woken for them (a failed lookup wakes nobody).
    let Ok(recipients) = crate::push::without_blockers(state, author_id, recipients).await else { return };
    // Blind gateway installs: a contentless, coalesced, jittered wake (gateway.rs). `scope` is
    // the realtime topic the message was published on: an install is left alone only if a
    // socket of it is subscribed to that topic.
    let others: Vec<String> = recipients.iter().filter(|u| u.as_str() != author_id).cloned().collect();
    crate::gateway::wake_users_on(state, &others, crate::gateway::Kind::Message, scope).await;
    match crate::push::build_wakeups(state, scope, message_id, author_id, &recipients).await {
        Ok(wakeups) if !wakeups.is_empty() => {
            // Deliver via APNs when configured (silent wakeups; the device fetches + decrypts and
            // posts its own local notification). Fire-and-forget so send latency never blocks chat.
            for w in wakeups {
                match w.platform.as_str() {
                    "ios" | "macos" => {
                        if let Some(apns) = state.apns.clone() {
                            tokio::spawn(async move { apns.send(&w.token, &w.scope, &w.message_id).await; });
                        }
                    }
                    "android" => {
                        if let Some(fcm) = state.fcm.clone() {
                            tokio::spawn(async move { fcm.send(&w.token, &w.scope, &w.message_id).await; });
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

#[derive(Deserialize)]
pub struct PageQuery {
    /// Return messages created strictly before this unix-ms timestamp (backfill cursor),
    /// newest first.
    pub before: Option<i64>,
    /// Catch-up cursor: return messages whose `updated_at` is at or after this unix-ms time —
    /// new ones, edited ones and tombstones alike — OLDEST change first. A client keeps the
    /// highest `updated_at` it has seen and asks again from there; rows it already has are
    /// served again at the boundary and are harmless. Takes precedence over `before`.
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

/// Reactions on a page of messages, grouped per message: `(user_id, emoji_hash, sealed emoji)`.
async fn reactions_for(state: &AppState, ids: &[String]) -> Result<std::collections::HashMap<String, Vec<Value>>, ApiError> {
    let mut out: std::collections::HashMap<String, Vec<Value>> = std::collections::HashMap::new();
    if ids.is_empty() {
        return Ok(out);
    }
    let placeholders: Vec<String> = (1..=ids.len()).map(|i| format!("${i}")).collect();
    let sql = format!("SELECT message_id, user_id, emoji_hash, emoji_ciphertext FROM reactions WHERE message_id IN ({}) ORDER BY created_at", placeholders.join(", "));
    let mut q = sqlx::query_as::<_, (String, String, String, Vec<u8>)>(&sql);
    for id in ids {
        q = q.bind(id);
    }
    for (message_id, user_id, emoji_hash, sealed) in q.fetch_all(&state.db).await? {
        out.entry(message_id).or_default().push(json!({ "user_id": user_id, "emoji_hash": emoji_hash, "emoji_ciphertext": B64.encode(sealed) }));
    }
    Ok(out)
}

fn message_row_json(
    (id, author_id, author_device_id, ciphertext, is_edited, is_pinned, reply_to_id, deleted_at, mentions, created_at, updated_at): (
        String,
        Option<String>,
        Option<String>,
        Vec<u8>,
        i64,
        i64,
        Option<String>,
        Option<i64>,
        Option<String>,
        i64,
        i64,
    ),
) -> Value {
    json!({
        "message_id": id,
        "author_id": author_id,
        "author_device_id": author_device_id,
        "ciphertext": B64.encode(ciphertext),
        "is_edited": is_edited == 1,
        "is_pinned": is_pinned == 1,
        "reply_to_id": reply_to_id,
        "deleted_at": deleted_at,
        "mention_user_ids": mentions.and_then(|m| serde_json::from_str::<Value>(&m).ok()),
        "created_at": created_at,
        "updated_at": updated_at,
    })
}

async fn list_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    require_channel_permission(&state, &channel_id, &auth.user_id, perms::READ_MESSAGES).await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let (sql, cursor) = match page.after {
        Some(after) => (
            "SELECT id, author_id, author_device_id, ciphertext, is_edited, is_pinned, reply_to_id, deleted_at, mention_user_ids, created_at, updated_at
             FROM messages WHERE channel_id = $1 AND updated_at >= $2
             ORDER BY updated_at ASC, id ASC LIMIT $3",
            after,
        ),
        None => (
            "SELECT id, author_id, author_device_id, ciphertext, is_edited, is_pinned, reply_to_id, deleted_at, mention_user_ids, created_at, updated_at
             FROM messages WHERE channel_id = $1 AND created_at < $2
             ORDER BY created_at DESC, id DESC LIMIT $3",
            page.before.unwrap_or(i64::MAX),
        ),
    };
    let rows: Vec<(String, Option<String>, Option<String>, Vec<u8>, i64, i64, Option<String>, Option<i64>, Option<String>, i64, i64)> =
        sqlx::query_as(sql).bind(&channel_id).bind(cursor).bind(limit).fetch_all(&state.db).await?;
    let ids: Vec<String> = rows.iter().map(|r| r.0.clone()).collect();
    // Reactions ride along, so a client never has to ask per message.
    let mut reactions = reactions_for(&state, &ids).await?;
    let messages: Vec<Value> = rows
        .into_iter()
        .map(|row| {
            let r = reactions.remove(&row.0).unwrap_or_default();
            let mut v = message_row_json(row);
            v["reactions"] = Value::Array(r);
            v
        })
        .collect();
    let cleared_at: Option<i64> = sqlx::query_scalar("SELECT cleared_at FROM channels WHERE id = $1").bind(&channel_id).fetch_optional(&state.db).await?.flatten();
    Ok(Json(json!({ "messages": messages, "cleared_at": cleared_at })))
}

#[derive(Deserialize)]
pub struct EditMessage {
    pub ciphertext: String,
    /// The device that made THIS edit. An edit is re-encrypted under the editing device's
    /// sender key, so readers must be told which device to decrypt it as — which is not
    /// necessarily the one that sent the original.
    pub author_device_id: Option<String>,
}

/// Resolve a channel message to (channel_id, author_id).
async fn message_meta(state: &AppState, message_id: &str) -> Result<(String, Option<String>), ApiError> {
    sqlx::query_as("SELECT channel_id, author_id FROM messages WHERE id = $1 AND deleted_at IS NULL")
        .bind(message_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn edit_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
    Json(req): Json<EditMessage>,
) -> Result<Json<Value>, ApiError> {
    let (channel_id, author) = message_meta(&state, &message_id).await?;
    // Only the author can edit (re-encrypt) their message — MANAGE_MESSAGES doesn't help,
    // moderators can't forge content they can't read.
    if author.as_deref() != Some(auth.user_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    // ...and only while they may still post there: a kicked or banned author (no membership ⇒
    // no permissions), or one whose SEND_MESSAGES was taken away, must not be able to rewrite
    // what is on show in a channel they were removed from.
    require_channel_permission(&state, &channel_id, &auth.user_id, perms::SEND_MESSAGES).await?;
    require_author_device(&state, &auth, req.author_device_id.as_deref()).await?;
    // An edit stores a ciphertext like a send does: same allowance, same size cap, same quota.
    state.limiter.check(&format!("msg_send:{}", auth.user_id), SENDS_PER_MINUTE, crate::limiter::MINUTE)?;
    let ciphertext = message_ciphertext(&req.ciphertext)?;
    crate::storage::charge(&state, &auth.user_id, ciphertext.len()).await?;
    // COALESCE: a build-42 client sends no device and keeps the original (its edits only ever
    // decrypted when made on the sending device).
    sqlx::query("UPDATE messages SET ciphertext = $1, is_edited = 1, updated_at = $2, author_device_id = COALESCE($3, author_device_id) WHERE id = $4")
        .bind(&ciphertext)
        .bind(now_ms())
        .bind(&req.author_device_id)
        .bind(&message_id)
        .execute(&state.db)
        .await?;
    let device: Option<String> = sqlx::query_scalar("SELECT author_device_id FROM messages WHERE id = $1").bind(&message_id).fetch_optional(&state.db).await?.flatten();
    state.rt.publish(
        &channel_topic(&channel_id),
        "message_update",
        json!({ "message_id": message_id, "channel_id": channel_id, "author_id": auth.user_id, "author_device_id": device, "ciphertext": req.ciphertext, "is_edited": true }),
    );
    Ok(Json(json!({ "success": true })))
}

async fn delete_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (channel_id, author) = message_meta(&state, &message_id).await?;
    if author.as_deref() != Some(auth.user_id.as_str()) {
        require_channel_permission(&state, &channel_id, &auth.user_id, perms::MANAGE_MESSAGES).await?;
    }
    // Tombstone: keep the row for ordering/references, drop the payload (empty blob bound, not the
    // SQLite-only `x''` literal which Postgres reads as a bit-string). The attachment links and
    // the deleter's own no-longer-referenced blobs go in the same transaction (`blobs.rs`).
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE messages SET ciphertext = $1, deleted_at = $2, updated_at = $3 WHERE id = $4")
        .bind(Vec::<u8>::new())
        .bind(now)
        .bind(now)
        .bind(&message_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM reactions WHERE message_id = $1").bind(&message_id).execute(&mut *tx).await?;
    let blobs = crate::blobs::unlink_message(&mut tx, &auth.user_id, &message_id).await?;
    tx.commit().await?;
    crate::blobs::remove_files(&state, &blobs);
    state.rt.publish(&channel_topic(&channel_id), "message_delete", json!({ "message_id": message_id, "channel_id": channel_id }));
    Ok(Json(json!({ "success": true })))
}

/// Owner/moderator action: HARD-delete every message in a channel — keeping the channel, its
/// members, and roles. Attachment/reaction/link-preview rows cascade with the messages; the blob
/// files they point at and the channel's relayed sender keys (neither FK-cascaded) are removed
/// explicitly. Gated on MANAGE_MESSAGES, the same permission single-message moderation uses.
async fn clear_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(channel_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_channel_permission(&state, &channel_id, &auth.user_id, perms::MANAGE_MESSAGES).await?;
    // Irreversible: a device, not just a token (audit M-3).
    crate::keydir::destructive_authority(&state, &auth, &headers, "clear-channel", &channel_id, b"").await?;

    // Capture attachment blob files before the rows cascade away.
    let blob_ids: Vec<String> = sqlx::query_scalar(
        "SELECT a.storage_path FROM message_attachments a
         JOIN messages m ON m.id = a.message_id WHERE m.channel_id = $1",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await?;

    let res = sqlx::query("DELETE FROM messages WHERE channel_id = $1")
        .bind(&channel_id)
        .execute(&state.db)
        .await?;
    for blob_id in &blob_ids {
        sqlx::query("DELETE FROM blobs WHERE id = $1").bind(blob_id).execute(&state.db).await?;
        let _ = std::fs::remove_file(state.blob_dir.join(blob_id));
    }
    // Remembered on the channel: a member whose device was offline for the event below learns of
    // the clear from its next history page and purges its cache too.
    let cleared_at = now_ms();
    sqlx::query("UPDATE channels SET cleared_at = $1 WHERE id = $2").bind(cleared_at).bind(&channel_id).execute(&state.db).await?;
    state.rt.publish(&channel_topic(&channel_id), "channel_cleared", json!({ "channel_id": channel_id, "cleared_at": cleared_at }));
    Ok(Json(json!({ "cleared_messages": res.rows_affected(), "cleared_blobs": blob_ids.len() })))
}

async fn set_pinned(state: &AppState, auth: &AuthUser, message_id: &str, pinned: bool) -> Result<Json<Value>, ApiError> {
    let (channel_id, _) = message_meta(state, message_id).await?;
    require_channel_permission(state, &channel_id, &auth.user_id, perms::MANAGE_MESSAGES).await?;
    sqlx::query("UPDATE messages SET is_pinned = $1, updated_at = $2 WHERE id = $3")
        .bind(pinned as i64)
        .bind(now_ms())
        .bind(message_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

async fn pin_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    set_pinned(&state, &auth, &message_id, true).await
}

async fn unpin_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    set_pinned(&state, &auth, &message_id, false).await
}

// ---- reactions ----

#[derive(Deserialize)]
pub struct AddReaction {
    pub emoji_ciphertext: String, // b64
    pub emoji_hash: String,       // client-side keyed hash (uniqueness without plaintext)
}

async fn add_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
    Json(req): Json<AddReaction>,
) -> Result<Json<Value>, ApiError> {
    let (channel_id, _) = message_meta(&state, &message_id).await?;
    require_channel_permission(&state, &channel_id, &auth.user_id, perms::ADD_REACTIONS).await?;
    let emoji = checked_reaction(&state, &auth.user_id, &req).await?;
    let insert = sqlx::query(
        "INSERT INTO reactions (id, message_id, user_id, emoji_hash, emoji_ciphertext, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(new_id())
    .bind(&message_id)
    .bind(&auth.user_id)
    .bind(&req.emoji_hash)
    .bind(&emoji)
    .bind(now_ms())
    .execute(&state.db)
    .await;
    match insert {
        Ok(_) => {
            reactions_changed(&state, &channel_id, &message_id).await;
            Ok(Json(json!({ "success": true })))
        }
        Err(e) => match ApiError::from(e) {
            ApiError::Conflict(_) => Ok(Json(json!({ "success": true, "already_reacted": true }))),
            other => Err(other),
        },
    }
}

/// A message's reactions changed: bump its `updated_at` so the catch-up cursor (`?after=`)
/// serves it again with the new set, and tell connected readers. Never pushes.
async fn reactions_changed(state: &AppState, channel_id: &str, message_id: &str) {
    let _ = sqlx::query("UPDATE messages SET updated_at = $1 WHERE id = $2").bind(now_ms()).bind(message_id).execute(&state.db).await;
    state.rt.publish(&channel_topic(channel_id), "reaction", json!({ "message_id": message_id, "channel_id": channel_id }));
}

async fn remove_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((message_id, emoji_hash)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let removed = sqlx::query("DELETE FROM reactions WHERE message_id = $1 AND user_id = $2 AND emoji_hash = $3")
        .bind(&message_id)
        .bind(&auth.user_id)
        .bind(&emoji_hash)
        .execute(&state.db)
        .await?
        .rows_affected();
    if removed > 0 {
        if let Ok((channel_id, _)) = message_meta(&state, &message_id).await {
            reactions_changed(&state, &channel_id, &message_id).await;
        }
    }
    Ok(Json(json!({ "success": true })))
}

/// Reactions on a message — (user_id, emoji_hash) pairs, so clients can count each reaction and see
/// which ones they added. The emoji itself stays E2EE (only its hash is public).
async fn list_reactions(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (channel_id, _) = message_meta(&state, &message_id).await?;
    require_channel_permission(&state, &channel_id, &auth.user_id, perms::READ_MESSAGES).await?;
    let rows: Vec<(String, String, Vec<u8>)> =
        sqlx::query_as("SELECT user_id, emoji_hash, emoji_ciphertext FROM reactions WHERE message_id = $1")
            .bind(&message_id)
            .fetch_all(&state.db)
            .await?;
    // `emoji_hash` is a keyed tag (HMAC under the space key) the server can group and count by
    // but not read; `emoji_ciphertext` is the emoji sealed under the same key, for members.
    let reactions: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, emoji_hash, sealed)| json!({ "user_id": user_id, "emoji_hash": emoji_hash, "emoji_ciphertext": B64.encode(sealed) }))
        .collect();
    Ok(Json(json!({ "reactions": reactions })))
}

// ---- DMs ----

/// For a 1:1 conversation, the OTHER participant's user id; None for group DMs (or if `user_id`
/// somehow has no counterpart). Used for block enforcement, which is pairwise by design.
pub(crate) async fn dm_peer(state: &AppState, conversation_id: &str, user_id: &str) -> Result<Option<String>, ApiError> {
    let is_group: Option<i64> = sqlx::query_scalar("SELECT is_group FROM dm_conversations WHERE id = $1")
        .bind(conversation_id)
        .fetch_optional(&state.db)
        .await?;
    if is_group != Some(0) {
        return Ok(None);
    }
    Ok(sqlx::query_scalar("SELECT user_id FROM dm_participants WHERE conversation_id = $1 AND user_id != $2 LIMIT 1")
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?)
}

/// Participants of one conversation, the caller included (the apps allow 10 in a group).
const MAX_DM_PARTICIPANTS: usize = 32;

#[derive(Deserialize)]
pub struct CreateDm {
    pub participant_ids: Vec<String>,
    pub name_ciphertext: Option<String>,
}

async fn create_dm(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateDm>,
) -> Result<Json<Value>, ApiError> {
    let mut participants: Vec<String> = req.participant_ids;
    if !participants.contains(&auth.user_id) {
        participants.push(auth.user_id.clone());
    }
    participants.sort();
    participants.dedup();
    if participants.is_empty() {
        return Err(ApiError::BadRequest("a DM needs at least one participant"));
    }
    if participants.len() > MAX_DM_PARTICIPANTS {
        return Err(ApiError::BadRequest("too many participants"));
    }

    // A single participant (only the caller) is a SELF-conversation: the channel a user's own
    // devices use to sync — provisioning + sender-key hand-off between the phone and the Mac of one
    // account. Messages still travel device-to-device over pairwise E2EE sessions; the server sees
    // one participant row and only ciphertext.
    let is_self = participants.len() == 1;
    let is_group = participants.len() > 2;

    // Block enforcement (metadata-only — user ids, never content): refuse to open a conversation
    // between any pair with a block in either direction. Applies to groups too, so a blocked user
    // can't reach their blocker by wrapping the DM in a 3-person group.
    for other in participants.iter().filter(|p| **p != auth.user_id) {
        if crate::safety::pair_blocked(&state, &auth.user_id, other).await? {
            return Err(ApiError::Forbidden);
        }
    }

    // Singleton reuse: a self-conversation is unique per user (exactly one participant = me); a 1:1
    // is unique per pair. Group DMs are never deduped.
    if is_self {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT c.id FROM dm_conversations c
             WHERE c.is_group = 0
               AND (SELECT count(*) FROM dm_participants WHERE conversation_id = c.id) = 1
               AND EXISTS(SELECT 1 FROM dm_participants WHERE conversation_id = c.id AND user_id = $1)",
        )
        .bind(&auth.user_id)
        .fetch_optional(&state.db)
        .await?;
        if let Some(id) = existing {
            return Ok(Json(json!({ "conversation_id": id, "existing": true })));
        }
    } else if !is_group {
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT c.id FROM dm_conversations c
             WHERE c.is_group = 0
               AND (SELECT count(*) FROM dm_participants WHERE conversation_id = c.id) = 2
               AND EXISTS(SELECT 1 FROM dm_participants WHERE conversation_id = c.id AND user_id = $1)
               AND EXISTS(SELECT 1 FROM dm_participants WHERE conversation_id = c.id AND user_id = $2)",
        )
        .bind(&participants[0])
        .bind(&participants[1])
        .fetch_optional(&state.db)
        .await?;
        if let Some(id) = existing {
            return Ok(Json(json!({ "conversation_id": id, "existing": true })));
        }
    }

    // A conversation row is not a way to reach a stranger: the caller must already know every
    // other participant — share a server with them, or have a conversation in which both have
    // written (`keydir::knows`). An unknown id and a real account the caller has no business
    // with get the same answer, so this does not enumerate accounts either.
    for user in participants.iter().filter(|p| **p != auth.user_id) {
        if !crate::keydir::knows(&state, &auth.user_id, user).await? {
            return Err(ApiError::NotFound);
        }
    }
    // Counted only when a row is actually created (re-opening an existing one is free).
    state.limiter.check(&format!("dm_create:{}", auth.user_id), DMS_PER_HOUR, crate::limiter::HOUR)?;

    let id = new_id();
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO dm_conversations (id, is_group, name_ciphertext, owner_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(is_group as i64)
    .bind(req.name_ciphertext.as_deref().map(b64_decode).transpose()?)
    .bind(is_group.then_some(&auth.user_id))
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    for user in &participants {
        sqlx::query("INSERT INTO dm_participants (id, conversation_id, user_id, created_at) VALUES ($1, $2, $3, $4)")
            .bind(new_id())
            .bind(&id)
            .bind(user)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "conversation_id": id })))
}

async fn list_dms(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(String, i64, Option<Vec<u8>>, i64)> = sqlx::query_as(
        "SELECT c.id, c.is_group, c.name_ciphertext, c.updated_at
         FROM dm_conversations c JOIN dm_participants p ON p.conversation_id = c.id
         WHERE p.user_id = $1 ORDER BY c.updated_at DESC",
    )
    .bind(&auth.user_id)
    .fetch_all(&state.db)
    .await?;
    let mut conversations = Vec::with_capacity(rows.len());
    for (id, is_group, name, updated_at) in rows {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT dp.user_id, p.username FROM dm_participants dp JOIN profiles p ON p.id = dp.user_id WHERE dp.conversation_id = $1 ORDER BY dp.user_id",
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await?;
        let participants: Vec<&str> = rows.iter().map(|(u, _)| u.as_str()).collect();
        // Usernames ride along so a device that did not start the conversation can label it.
        let names: serde_json::Map<String, Value> = rows.iter().map(|(u, n)| (u.clone(), json!(n))).collect();
        conversations.push(json!({
            "conversation_id": id,
            "participant_names": names,
            "is_group": is_group == 1,
            "name_ciphertext": name.map(|n| B64.encode(n)),
            "participants": participants,
            "updated_at": updated_at,
        }));
    }
    Ok(Json(json!({ "conversations": conversations })))
}

async fn send_dm(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    Json(req): Json<SendMessage>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("msg_send:{}", auth.user_id), SENDS_PER_MINUTE, crate::limiter::MINUTE)?;
    require_dm_participant(&state, &conversation_id, &auth.user_id).await?;
    // Block enforcement on existing 1:1 conversations: if the other participant has blocked the
    // sender (or vice versa), the relay refuses the send. Keys on user ids only — the envelope
    // stays opaque. Group DMs are left alone (a member who wants out of a group can leave it).
    if let Some(peer) = dm_peer(&state, &conversation_id, &auth.user_id).await? {
        if crate::safety::pair_blocked(&state, &auth.user_id, &peer).await? {
            return Err(ApiError::Forbidden);
        }
        // A row left over from before conversations needed a relationship (or from a server
        // the two no longer share) is not a licence to keep writing to a stranger.
        if !crate::keydir::knows(&state, &auth.user_id, &peer).await? {
            return Err(ApiError::Forbidden);
        }
    }
    let ciphertext = message_ciphertext(&req.ciphertext)?;
    crate::storage::charge(&state, &auth.user_id, ciphertext.len()).await?;
    let mentions = req.mention_user_ids.map(|m| serde_json::to_string(&m).expect("string vec"));
    let id = new_id();
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO dm_messages (id, conversation_id, author_id, author_device_id, ciphertext, reply_to_id, mention_user_ids, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(&id)
    .bind(&conversation_id)
    .bind(&auth.user_id)
    .bind(&req.author_device_id)
    .bind(&ciphertext)
    .bind(&req.reply_to_id)
    .bind(&mentions)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE dm_conversations SET updated_at = $1 WHERE id = $2")
        .bind(now)
        .bind(&conversation_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.rt.publish(
        &dm_topic(&conversation_id),
        "message",
        json!({
            "message_id": id,
            "conversation_id": conversation_id,
            "author_id": auth.user_id,
            "author_device_id": req.author_device_id,
            "ciphertext": req.ciphertext,
            "reply_to_id": req.reply_to_id,
            "created_at": now,
        }),
    );
    dispatch_push(&state, &format!("dm:{conversation_id}"), &id, &auth.user_id, PushScope::Dm(&conversation_id)).await;
    Ok(Json(json!({ "message_id": id, "created_at": now })))
}

async fn list_dm_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(conversation_id): Path<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    require_dm_participant(&state, &conversation_id, &auth.user_id).await?;
    let limit = page.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let before = page.before.unwrap_or(i64::MAX);
    let rows: Vec<(String, Option<String>, Option<String>, Vec<u8>, i64, Option<String>, Option<i64>, Option<String>, i64, i64)> =
        sqlx::query_as(
            "SELECT id, author_id, author_device_id, ciphertext, is_edited, reply_to_id, deleted_at, mention_user_ids, created_at, updated_at
             FROM dm_messages WHERE conversation_id = $1 AND created_at < $2
             ORDER BY created_at DESC, id DESC LIMIT $3",
        )
        .bind(&conversation_id)
        .bind(before)
        .bind(limit)
        .fetch_all(&state.db)
        .await?;
    let messages: Vec<Value> = rows
        .into_iter()
        .map(|(id, author_id, author_device_id, ciphertext, is_edited, reply_to_id, deleted_at, mentions, created_at, updated_at)| {
            json!({
                "message_id": id,
                "author_id": author_id,
                "author_device_id": author_device_id,
                "ciphertext": B64.encode(ciphertext),
                "is_edited": is_edited == 1,
                "reply_to_id": reply_to_id,
                "deleted_at": deleted_at,
                "mention_user_ids": mentions.and_then(|m| serde_json::from_str::<Value>(&m).ok()),
                "created_at": created_at,
                "updated_at": updated_at,
            })
        })
        .collect();
    Ok(Json(json!({ "messages": messages })))
}

/// Resolve a DM message to (conversation_id, author_id).
async fn dm_message_meta(state: &AppState, message_id: &str) -> Result<(String, Option<String>), ApiError> {
    sqlx::query_as("SELECT conversation_id, author_id FROM dm_messages WHERE id = $1 AND deleted_at IS NULL")
        .bind(message_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn edit_dm(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
    Json(req): Json<EditMessage>,
) -> Result<Json<Value>, ApiError> {
    let (_, author) = dm_message_meta(&state, &message_id).await?;
    if author.as_deref() != Some(auth.user_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    state.limiter.check(&format!("msg_send:{}", auth.user_id), SENDS_PER_MINUTE, crate::limiter::MINUTE)?;
    let ciphertext = message_ciphertext(&req.ciphertext)?;
    crate::storage::charge(&state, &auth.user_id, ciphertext.len()).await?;
    sqlx::query("UPDATE dm_messages SET ciphertext = $1, is_edited = 1, updated_at = $2 WHERE id = $3")
        .bind(&ciphertext)
        .bind(now_ms())
        .bind(&message_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

async fn delete_dm(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let (_, author) = dm_message_meta(&state, &message_id).await?;
    // DMs have no moderators: only the author may delete.
    if author.as_deref() != Some(auth.user_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("UPDATE dm_messages SET ciphertext = $1, deleted_at = $2, updated_at = $3 WHERE id = $4")
        .bind(Vec::<u8>::new())
        .bind(now_ms())
        .bind(now_ms())
        .bind(&message_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

async fn add_dm_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
    Json(req): Json<AddReaction>,
) -> Result<Json<Value>, ApiError> {
    let (conversation_id, _) = dm_message_meta(&state, &message_id).await?;
    require_dm_participant(&state, &conversation_id, &auth.user_id).await?;
    let emoji = checked_reaction(&state, &auth.user_id, &req).await?;
    let insert = sqlx::query(
        "INSERT INTO dm_reactions (id, dm_message_id, user_id, emoji_hash, emoji_ciphertext, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(new_id())
    .bind(&message_id)
    .bind(&auth.user_id)
    .bind(&req.emoji_hash)
    .bind(&emoji)
    .bind(now_ms())
    .execute(&state.db)
    .await;
    match insert {
        Ok(_) => Ok(Json(json!({ "success": true }))),
        Err(e) => match ApiError::from(e) {
            ApiError::Conflict(_) => Ok(Json(json!({ "success": true, "already_reacted": true }))),
            other => Err(other),
        },
    }
}

async fn remove_dm_reaction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((message_id, emoji_hash)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    sqlx::query("DELETE FROM dm_reactions WHERE dm_message_id = $1 AND user_id = $2 AND emoji_hash = $3")
        .bind(&message_id)
        .bind(&auth.user_id)
        .bind(&emoji_hash)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

// ---- read states ----

#[derive(Deserialize)]
pub struct PutReadState {
    pub last_read_message_id: Option<String>,
    #[serde(default)]
    pub mention_count: i64,
}

async fn put_read_state(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<PutReadState>,
) -> Result<Json<Value>, ApiError> {
    require_channel_permission(&state, &channel_id, &auth.user_id, perms::READ_MESSAGES).await?;
    sqlx::query(
        "INSERT INTO read_states (id, user_id, channel_id, last_read_message_id, mention_count, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id, channel_id) DO UPDATE SET last_read_message_id = excluded.last_read_message_id,
             mention_count = excluded.mention_count, updated_at = excluded.updated_at",
    )
    .bind(new_id())
    .bind(&auth.user_id)
    .bind(&channel_id)
    .bind(&req.last_read_message_id)
    .bind(req.mention_count)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true })))
}
