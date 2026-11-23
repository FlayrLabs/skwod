//! Blob store — resumable (TUS-style) uploads of client-side-encrypted files.
//!
//! Flow: POST /blobs {total_size} → blob_id → PATCH /blobs/:id with `Upload-Offset` header +
//! binary chunk (offset must equal bytes received so far; on mismatch the server answers 409
//! with the current offset so the client resumes) → completion at total_size. HEAD reports the
//! GET /blobs/:id/offset reports the resume point; GET /blobs/:id streams the ciphertext back.
//!
//! Access model. Content is E2EE (the per-file key travels only inside the encrypted message
//! that describes the attachment), so a download yields ciphertext only. Uploads are writable
//! by their owner exclusively. A download is allowed to:
//!
//! - the owner;
//! - anyone who may READ a channel the blob is attached in. The sender names its blobs in the
//!   channel send (`blob_ids`) and the server links them in the same transaction
//!   ([`link_to_message`]) — so the link exists the moment the message does, and it is deleted
//!   with the message;
//! - whoever presents the blob's **download token** (`x-skwod-blob-token`). This is the DM path:
//!   a sealed DM has no row on the server to hang access on, so the uploader registers the
//!   SHA-256 of a random token at creation and puts the token inside the E2EE descriptor. The
//!   request needs no session, so the server does not learn which account fetched it. A blob
//!   that is attached in a channel is NOT served by token: channel access can be revoked, a
//!   token cannot.
//!
//! Limits: only accounts that are a member of some space may upload; the host's per-file limit
//! (`limits.rs`); a per-account byte quota and creation rate; a free-space floor on the data volume; and a sweep ([`sweep`]) that
//! removes uploads never finished or never attached to anything within 24 hours.

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Digest;
use std::io::{Seek, SeekFrom, Write};
use tokio_util::io::ReaderStream;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::{new_id, now_ms, AppState};

/// 16 MiB per chunk keeps request bodies bounded; clients loop.
pub const MAX_CHUNK: usize = 16 * 1024 * 1024;
/// 2 GiB per blob (matches the original app's file cap).
pub const MAX_BLOB: i64 = 2 * 1024 * 1024 * 1024;

pub fn routes() -> Router<AppState> {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, patch, post};
    Router::new()
        .route("/blobs", post(create_blob))
        .route("/blobs/:blob_id", patch(upload_chunk).get(download).delete(delete_blob))
        .route("/blobs/:blob_id/offset", get(upload_offset))
        // Axum's default request-body cap is 2 MB — far below MAX_CHUNK; raise it so full-size
        // chunks are actually accepted (upload_chunk still enforces MAX_CHUNK itself).
        .layer(DefaultBodyLimit::max(MAX_CHUNK + 4096))
        // The attachment-metadata routes carry a small JSON descriptor, never file bytes: they
        // are merged in AFTER the chunk-sized limit so it does not apply to them.
        .merge(
            Router::new()
                .route("/messages/:message_id/attachments", post(attach_to_message).get(list_message_attachments))
                .route("/dm-messages/:message_id/attachments", post(attach_to_dm).get(list_dm_attachments))
                .layer(DefaultBodyLimit::max(crate::storage::SMALL_BODY_LIMIT)),
        )
}

/// Attachment rows one account may add per minute.
const ATTACHES_PER_MINUTE: u32 = 120;

/// An attachment descriptor, size-checked and charged to the author's quota.
async fn checked_metadata(state: &AppState, user_id: &str, b64: &str) -> Result<Vec<u8>, ApiError> {
    state.limiter.check(&format!("attach:{user_id}"), ATTACHES_PER_MINUTE, crate::limiter::MINUTE)?;
    let metadata = b64_decode(b64)?;
    if metadata.len() > crate::storage::MAX_ATTACHMENT_METADATA {
        return Err(ApiError::PayloadTooLarge("attachment description too large"));
    }
    crate::storage::charge(state, user_id, metadata.len()).await?;
    Ok(metadata)
}

fn blob_path(state: &AppState, blob_id: &str) -> Result<std::path::PathBuf, ApiError> {
    // Defense-in-depth against path traversal: blob ids are always server-generated UUIDs
    // (new_id = Uuid::new_v4). Reject anything that isn't a valid UUID so a crafted id like
    // "../../etc/passwd" can never become a filesystem path — independent of the DB lookup that
    // also gates these handlers.
    if uuid::Uuid::parse_str(blob_id).is_err() {
        return Err(ApiError::BadRequest("invalid blob id"));
    }
    Ok(state.blob_dir.join(blob_id))
}

// ---- upload ----

#[derive(Deserialize)]
pub struct CreateBlob {
    pub total_size: i64,
    /// Lowercase hex SHA-256 of a random download token (≥ 16 bytes) the uploader keeps inside
    /// the encrypted attachment descriptor. Optional: channel attachments do not need one.
    pub download_token_hash: Option<String>,
}

/// Blob creations per account per hour.
const CREATES_PER_HOUR: u32 = 240;
/// An upload nobody finished, or a finished one nothing refers to, is removed after this long.
pub const ORPHAN_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Free bytes on the volume holding `dir`, when the platform can say.
pub(crate) fn free_space(dir: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        let v = nix::sys::statvfs::statvfs(dir).ok()?;
        Some(v.blocks_available() as u64 * v.fragment_size() as u64)
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        None
    }
}

async fn create_blob(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateBlob>,
) -> Result<Json<Value>, ApiError> {
    if req.total_size <= 0 || req.total_size > MAX_BLOB {
        return Err(ApiError::BadRequest("invalid total_size"));
    }
    // The host's per-file limit (`limits.rs`). The apps check it first; this is what holds.
    crate::limits::refuse_oversized(&state, req.total_size)?;
    let token_hash = match req.download_token_hash.as_deref() {
        Some(h) => Some(hex::decode(h).ok().filter(|b| b.len() == 32).ok_or(ApiError::BadRequest("download_token_hash must be a hex SHA-256"))?),
        None => None,
    };
    state.limiter.check(&format!("blob_create:{}", auth.user_id), CREATES_PER_HOUR, crate::limiter::HOUR)?;
    // Storage is for the people of this skwod. An account that merely exists (signed up with a
    // code, never admitted anywhere — or since removed from everywhere) gets none.
    let member: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_members WHERE user_id = $1) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(&auth.user_id)
        .fetch_one(&state.db)
        .await?;
    if member == 0 {
        return Err(ApiError::Forbidden);
    }
    let used: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(SUM(total_size), 0) AS BIGINT) FROM blobs WHERE owner_id = $1")
        .bind(&auth.user_id)
        .fetch_one(&state.db)
        .await?;
    if used.saturating_add(req.total_size) > state.blob_quota_bytes {
        return Err(ApiError::PayloadTooLarge("you have used all of your attachment storage on this skwod; delete some messages with attachments, or ask the host for more"));
    }
    if let Some(free) = free_space(&state.blob_dir) {
        if free < state.blob_free_floor_bytes.saturating_add(req.total_size as u64) {
            return Err(ApiError::InsufficientStorage("this skwod's host is almost out of disk space, so it is not accepting attachments right now"));
        }
    }
    let id = new_id();
    let now = now_ms();
    sqlx::query("INSERT INTO blobs (id, owner_id, total_size, received_bytes, complete, created_at, updated_at, token_hash) VALUES ($1, $2, $3, 0, 0, $4, $5, $6)")
        .bind(&id)
        .bind(&auth.user_id)
        .bind(req.total_size)
        .bind(now)
        .bind(now)
        .bind(token_hash)
        .execute(&state.db)
        .await?;
    std::fs::File::create(blob_path(&state, &id)?).map_err(|_| ApiError::Internal)?;
    Ok(Json(json!({ "blob_id": id, "max_chunk": MAX_CHUNK })))
}

/// (total_size, received_bytes, complete) for an owned blob.
async fn owned_blob(state: &AppState, user_id: &str, blob_id: &str) -> Result<(i64, i64, i64), ApiError> {
    sqlx::query_as("SELECT total_size, received_bytes, complete FROM blobs WHERE id = $1 AND owner_id = $2")
        .bind(blob_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn upload_chunk(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiError> {
    // Everything that can refuse the chunk is decided BEFORE its bytes are read (audit M-2):
    // the body used to be buffered first — any signed-in account could make the server hold
    // 16 MiB per request for a blob id it does not own, or does not exist.
    let (total, received, complete) = owned_blob(&state, &auth.user_id, &blob_id).await?;
    if complete == 1 {
        return Err(ApiError::Conflict("already complete"));
    }
    let offset: i64 = headers
        .get("upload-offset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or(ApiError::BadRequest("missing Upload-Offset header"))?;
    if offset != received {
        // Resume point mismatch — tell the client where we actually are.
        return Ok((StatusCode::CONFLICT, [("upload-offset", received.to_string())]).into_response());
    }
    // No more is read than this blob still has room for (and never more than one chunk).
    let room = usize::try_from(total - received).unwrap_or(0).min(MAX_CHUNK);
    let declared = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_CHUNK) {
        return Err(ApiError::BadRequest("chunk must be 1 byte to 16 MiB"));
    }
    if declared.is_some_and(|n| n > room) {
        return Err(ApiError::BadRequest("chunk exceeds declared total_size"));
    }
    let body: Bytes = axum::body::to_bytes(body, room).await.map_err(|_| ApiError::BadRequest("chunk exceeds declared total_size"))?;
    if body.is_empty() {
        return Err(ApiError::BadRequest("chunk must be 1 byte to 16 MiB"));
    }

    let path = blob_path(&state, &blob_id)?;
    let body_len = body.len() as i64;
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        f.seek(SeekFrom::Start(offset as u64))?;
        f.write_all(&body)?;
        f.sync_all()
    })
    .await
    .map_err(|_| ApiError::Internal)?
    .map_err(|_| ApiError::Internal)?;

    let new_received = received + body_len;
    let complete = (new_received == total) as i64;
    sqlx::query("UPDATE blobs SET received_bytes = $1, complete = $2, updated_at = $3 WHERE id = $4")
        .bind(new_received)
        .bind(complete)
        .bind(now_ms())
        .bind(&blob_id)
        .execute(&state.db)
        .await?;
    Ok((
        StatusCode::NO_CONTENT,
        [("upload-offset", new_received.to_string()), ("upload-complete", complete.to_string())],
    )
        .into_response())
}

async fn upload_offset(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<String>,
) -> Result<Response, ApiError> {
    let (total, received, complete) = owned_blob(&state, &auth.user_id, &blob_id).await?;
    Ok((
        StatusCode::OK,
        [
            ("upload-offset", received.to_string()),
            ("upload-length", total.to_string()),
            ("upload-complete", complete.to_string()),
        ],
    )
        .into_response())
}

async fn delete_blob(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    owned_blob(&state, &auth.user_id, &blob_id).await?;
    sqlx::query("DELETE FROM blobs WHERE id = $1").bind(&blob_id).execute(&state.db).await?;
    let _ = std::fs::remove_file(blob_path(&state, &blob_id)?);
    Ok(Json(json!({ "success": true })))
}

// ---- download ----

/// May `user_id` download the blob `blob_id`? The blob id is a 128-bit random capability, but we
/// gate downloads on membership too (defense-in-depth): a caller may fetch a blob only if they own
/// it, or if it's attached to a message/DM they're currently authorized to read. This means a
/// kicked member — who can no longer read the channel — can't pull *new* blob ids they were handed,
/// while a legitimately-shared blob (attached to something the caller can still read) keeps working.
async fn may_download_blob(state: &AppState, user_id: &str, blob_id: &str) -> Result<bool, ApiError> {
    // The owner can always fetch their own blob (e.g. verifying an upload before/after attaching).
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM blobs WHERE id = $1")
        .bind(blob_id)
        .fetch_optional(&state.db)
        .await?;
    if owner.as_deref() == Some(user_id) {
        return Ok(true);
    }

    // DM attachment: the caller participates in a conversation this blob is attached in.
    let dm_ok: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(
             SELECT 1 FROM dm_attachments a
             JOIN dm_messages m ON m.id = a.dm_message_id
             JOIN dm_participants p ON p.conversation_id = m.conversation_id
             WHERE a.storage_path = $1 AND p.user_id = $2) THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(blob_id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    if dm_ok == 1 {
        return Ok(true);
    }

    // Channel attachment: the caller has READ_MESSAGES on a channel this blob is attached in.
    // Permissions are computed in Rust (not pure SQL), so fetch the candidate channels and check.
    let channel_ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT m.channel_id FROM message_attachments a
         JOIN messages m ON m.id = a.message_id
         WHERE a.storage_path = $1",
    )
    .bind(blob_id)
    .fetch_all(&state.db)
    .await?;
    for channel_id in channel_ids {
        let server_id = match crate::structure::channel_server(state, &channel_id).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        // effective_permissions returns Err(Forbidden/NotFound) for a non-member or a gone channel —
        // treat that as "no access to this channel" and keep checking, don't propagate it as the
        // handler's error (mirrors ws::may_subscribe).
        let p = match crate::structure::effective_permissions(state, &server_id, user_id, Some(&channel_id)).await {
            Ok(p) => p,
            Err(_) => continue,
        };
        if crate::perms::has_permission(p, crate::perms::READ_MESSAGES) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Is this blob attached in any channel message? (Then access follows the channel, not a token.)
async fn channel_linked(state: &AppState, blob_id: &str) -> Result<bool, ApiError> {
    let n: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM message_attachments WHERE storage_path = $1) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(blob_id)
        .fetch_one(&state.db)
        .await?;
    Ok(n == 1)
}

async fn download(
    State(state): State<AppState>,
    client: crate::client_key::ClientKey,
    headers: HeaderMap,
    Path(blob_id): Path<String>,
) -> Result<Response, ApiError> {
    let path = blob_path(&state, &blob_id)?;
    let row: Option<(i64, Option<Vec<u8>>)> = sqlx::query_as("SELECT complete, token_hash FROM blobs WHERE id = $1")
        .bind(&blob_id)
        .fetch_optional(&state.db)
        .await?;
    // Every refusal below is NotFound, so this is not an oracle for which ids exist.
    let Some((1, token_hash)) = row else { return Err(ApiError::NotFound) };
    let presented = headers.get("x-skwod-blob-token").and_then(|v| v.to_str().ok());
    let allowed = match (presented, token_hash) {
        // Capability path (DM attachments): no session is looked at, so nothing ties the fetch
        // to an account. Throttled per caller, since it is reachable without signing in.
        (Some(token), Some(hash)) => {
            client.limit(&state, "blob_token", 600)?;
            use subtle::ConstantTimeEq;
            let given = sha2::Sha256::digest(token.as_bytes());
            bool::from(given.as_slice().ct_eq(&hash)) && !channel_linked(&state, &blob_id).await?
        }
        _ => {
            let bearer = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .ok_or(ApiError::Unauthorized)?;
            let user_id = crate::auth::authenticate(&state, bearer).await?;
            may_download_blob(&state, &user_id, &blob_id).await?
        }
    };
    if !allowed {
        return Err(ApiError::NotFound);
    }
    // STREAM the ciphertext off disk (constant memory) instead of reading up to MAX_BLOB (2 GiB)
    // into RAM per request — otherwise concurrent large downloads can push the server into OOM.
    let file = tokio::fs::File::open(&path).await.map_err(|_| ApiError::NotFound)?;
    let len = file.metadata().await.map_err(|_| ApiError::NotFound)?.len();
    let body = Body::from_stream(ReaderStream::new(file));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        body,
    )
        .into_response())
}

/// Attach `blob_ids` to channel message `message_id`, inside the transaction that inserts the
/// message. Each must be a COMPLETE upload owned by the author; anything else fails the send
/// (and rolls the message back), so a message never names an attachment its readers cannot get.
pub(crate) async fn link_to_message(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    author_id: &str,
    message_id: &str,
    blob_ids: &[String],
    now: i64,
) -> Result<(), ApiError> {
    if blob_ids.len() > MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(ApiError::BadRequest("too many attachments on one message"));
    }
    for blob_id in blob_ids {
        let row: Option<(i64, i64)> = sqlx::query_as("SELECT total_size, complete FROM blobs WHERE id = $1 AND owner_id = $2")
            .bind(blob_id)
            .bind(author_id)
            .fetch_optional(&mut **tx)
            .await?;
        let size = match row {
            Some((size, 1)) => size,
            Some(_) => return Err(ApiError::BadRequest("an attachment has not finished uploading")),
            None => return Err(ApiError::BadRequest("unknown attachment")),
        };
        sqlx::query("INSERT INTO message_attachments (id, message_id, storage_path, file_size, metadata_ciphertext, created_at) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(new_id())
            .bind(message_id)
            .bind(blob_id)
            .bind(size)
            .bind(Vec::<u8>::new())
            .bind(now)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 16;

/// Unlink a deleted channel message's attachments and delete the blobs that can safely go,
/// all inside the caller's transaction. Returns the ids whose FILES the caller removes after
/// the commit ([`remove_files`]).
///
/// A blob is deleted with the message only when ALL of these hold:
/// - `deleter` owns it (a moderator removing someone else's message does not destroy that
///   person's file — its link goes, and the orphan sweep collects it a day later if nothing
///   else refers to it);
/// - no other channel message carries it;
/// - no DM attachment row carries it;
/// - it has no download token (a token means it may be referenced from a sealed DM, which the
///   server cannot see — only its owner can delete it, explicitly).
pub(crate) async fn unlink_message(tx: &mut sqlx::Transaction<'_, sqlx::Any>, deleter: &str, message_id: &str) -> Result<Vec<String>, ApiError> {
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT a.storage_path FROM message_attachments a JOIN blobs b ON b.id = a.storage_path
          WHERE a.message_id = $1 AND b.owner_id = $2 AND b.token_hash IS NULL
            AND NOT EXISTS (SELECT 1 FROM message_attachments o WHERE o.storage_path = a.storage_path AND o.message_id <> a.message_id)
            AND NOT EXISTS (SELECT 1 FROM dm_attachments d WHERE d.storage_path = a.storage_path)",
    )
    .bind(message_id)
    .bind(deleter)
    .fetch_all(&mut **tx)
    .await?;
    sqlx::query("DELETE FROM message_attachments WHERE message_id = $1").bind(message_id).execute(&mut **tx).await?;
    for blob_id in &candidates {
        sqlx::query("DELETE FROM blobs WHERE id = $1 AND owner_id = $2").bind(blob_id).bind(deleter).execute(&mut **tx).await?;
    }
    Ok(candidates)
}

/// Remove the files of blobs whose rows are already gone. Best effort.
pub(crate) fn remove_files(state: &AppState, blob_ids: &[String]) {
    for blob_id in blob_ids {
        if let Ok(path) = blob_path(state, blob_id) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Remove blob rows and their files. Best effort on the files.
pub(crate) async fn remove_blobs(state: &AppState, blob_ids: &[String]) -> u64 {
    let mut n = 0;
    for blob_id in blob_ids {
        if let Ok(r) = sqlx::query("DELETE FROM blobs WHERE id = $1").bind(blob_id).execute(&state.db).await {
            n += r.rows_affected();
        }
        if let Ok(path) = blob_path(state, blob_id) {
            let _ = std::fs::remove_file(path);
        }
    }
    n
}

/// Retention: uploads abandoned half-way, and finished uploads that nothing refers to (no
/// channel attachment and no download token), once they are [`ORPHAN_TTL_MS`] old. Also removes
/// files in the blob directory that have no row at all (a crash between the two writes).
pub async fn sweep(state: &AppState) -> u64 {
    let cutoff = now_ms() - ORPHAN_TTL_MS;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM blobs WHERE updated_at < $1 AND (complete = 0 OR (token_hash IS NULL
           AND NOT EXISTS (SELECT 1 FROM message_attachments a WHERE a.storage_path = blobs.id)
           AND NOT EXISTS (SELECT 1 FROM dm_attachments d WHERE d.storage_path = blobs.id)))",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut n = remove_blobs(state, &ids).await;
    if let Ok(dir) = std::fs::read_dir(&state.blob_dir) {
        for entry in dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let old = entry.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).is_some_and(|age| age.as_millis() as i64 > ORPHAN_TTL_MS);
            if !old || uuid::Uuid::parse_str(&name).is_err() {
                continue;
            }
            let known: Option<String> = sqlx::query_scalar("SELECT id FROM blobs WHERE id = $1").bind(&name).fetch_optional(&state.db).await.ok().flatten();
            if known.is_none() && std::fs::remove_file(entry.path()).is_ok() {
                n += 1;
            }
        }
    }
    n
}

// ---- attachment linkage ----

#[derive(Deserialize)]
pub struct Attach {
    pub blob_id: String,
    pub metadata_ciphertext: String, // b64: name/mime/dimensions/duration/spoiler + content key
}

async fn complete_owned_blob_size(state: &AppState, user_id: &str, blob_id: &str) -> Result<i64, ApiError> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT total_size, complete FROM blobs WHERE id = $1 AND owner_id = $2")
            .bind(blob_id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    match row {
        Some((size, 1)) => Ok(size),
        Some(_) => Err(ApiError::BadRequest("blob upload not complete")),
        None => Err(ApiError::NotFound),
    }
}

fn b64_decode(s: &str) -> Result<Vec<u8>, ApiError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|_| ApiError::BadRequest("invalid base64"))
}

async fn attach_to_message(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
    Json(req): Json<Attach>,
) -> Result<Json<Value>, ApiError> {
    // Only the message author attaches to their own message (upload → send → attach flow).
    let author: Option<Option<String>> = sqlx::query_scalar("SELECT author_id FROM messages WHERE id = $1")
        .bind(&message_id)
        .fetch_optional(&state.db)
        .await?;
    if author.flatten().as_deref() != Some(auth.user_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    // The author must still be allowed to attach THERE, now: a kicked or banned author has no
    // membership (so no permissions) and must not keep adding files to their old messages.
    let channel_id: String = sqlx::query_scalar("SELECT channel_id FROM messages WHERE id = $1 AND deleted_at IS NULL")
        .bind(&message_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let server_id = crate::structure::channel_server(&state, &channel_id).await?;
    let p = crate::structure::effective_permissions(&state, &server_id, &auth.user_id, Some(&channel_id)).await?;
    if !crate::perms::has_permission(p, crate::perms::ATTACH_FILES) {
        return Err(ApiError::Forbidden);
    }
    let size = complete_owned_blob_size(&state, &auth.user_id, &req.blob_id).await?;
    let metadata = checked_metadata(&state, &auth.user_id, &req.metadata_ciphertext).await?;
    let id = new_id();
    sqlx::query(
        "INSERT INTO message_attachments (id, message_id, storage_path, file_size, metadata_ciphertext, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&message_id)
    .bind(&req.blob_id)
    .bind(size)
    .bind(&metadata)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "attachment_id": id })))
}

async fn attach_to_dm(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
    Json(req): Json<Attach>,
) -> Result<Json<Value>, ApiError> {
    // The author's own message, one that still exists…
    let row: Option<(Option<String>, String)> = sqlx::query_as("SELECT author_id, conversation_id FROM dm_messages WHERE id = $1 AND deleted_at IS NULL")
        .bind(&message_id)
        .fetch_optional(&state.db)
        .await?;
    let (author, conversation_id) = row.ok_or(ApiError::NotFound)?;
    if author.as_deref() != Some(auth.user_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    // …in a conversation the author is still part of, with nobody blocking in between — the
    // same conditions as sending there (audit M-2: this route checked neither, so a blocked
    // or departed author kept adding files to old messages).
    let participant: Option<i64> = sqlx::query_scalar("SELECT 1 FROM dm_participants WHERE conversation_id = $1 AND user_id = $2")
        .bind(&conversation_id)
        .bind(&auth.user_id)
        .fetch_optional(&state.db)
        .await?;
    if participant.is_none() {
        return Err(ApiError::Forbidden);
    }
    if let Some(peer) = crate::messages::dm_peer(&state, &conversation_id, &auth.user_id).await? {
        if crate::safety::pair_blocked(&state, &auth.user_id, &peer).await? {
            return Err(ApiError::Forbidden);
        }
    }
    let size = complete_owned_blob_size(&state, &auth.user_id, &req.blob_id).await?;
    let metadata = checked_metadata(&state, &auth.user_id, &req.metadata_ciphertext).await?;
    let id = new_id();
    sqlx::query(
        "INSERT INTO dm_attachments (id, dm_message_id, storage_path, file_size, metadata_ciphertext, created_at) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&message_id)
    .bind(&req.blob_id)
    .bind(size)
    .bind(&metadata)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "attachment_id": id })))
}

async fn list_attachments_rows(
    state: &AppState,
    table: &str,
    fk: &str,
    message_id: &str,
) -> Result<Vec<Value>, ApiError> {
    use base64::Engine;
    let rows: Vec<(String, String, i64, Vec<u8>)> = sqlx::query_as(&format!(
        "SELECT id, storage_path, file_size, metadata_ciphertext FROM {table} WHERE {fk} = $1 ORDER BY created_at"
    ))
    .bind(message_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, blob_id, file_size, metadata)| {
            json!({
                "attachment_id": id,
                "blob_id": blob_id,
                "file_size": file_size,
                "metadata_ciphertext": base64::engine::general_purpose::STANDARD.encode(metadata),
            })
        })
        .collect())
}

async fn list_message_attachments(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Reader must be able to read the channel.
    let channel_id: Option<String> = sqlx::query_scalar("SELECT channel_id FROM messages WHERE id = $1")
        .bind(&message_id)
        .fetch_optional(&state.db)
        .await?;
    let channel_id = channel_id.ok_or(ApiError::NotFound)?;
    let server_id = crate::structure::channel_server(&state, &channel_id).await?;
    let p = crate::structure::effective_permissions(&state, &server_id, &auth.user_id, Some(&channel_id)).await?;
    if !crate::perms::has_permission(p, crate::perms::READ_MESSAGES) {
        return Err(ApiError::Forbidden);
    }
    let attachments = list_attachments_rows(&state, "message_attachments", "message_id", &message_id).await?;
    Ok(Json(json!({ "attachments": attachments })))
}

async fn list_dm_attachments(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(message_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let convo: Option<String> = sqlx::query_scalar("SELECT conversation_id FROM dm_messages WHERE id = $1")
        .bind(&message_id)
        .fetch_optional(&state.db)
        .await?;
    let convo = convo.ok_or(ApiError::NotFound)?;
    let ok: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM dm_participants WHERE conversation_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(&convo)
        .bind(&auth.user_id)
        .fetch_one(&state.db)
        .await?;
    if ok == 0 {
        return Err(ApiError::Forbidden);
    }
    let attachments = list_attachments_rows(&state, "dm_attachments", "dm_message_id", &message_id).await?;
    Ok(Json(json!({ "attachments": attachments })))
}
