//! What an account may store in the database, and when the host is too full to take more.
//!
//! Blobs have had a per-account quota and a free-space floor since `blobs.rs`; messages, DMs,
//! reactions and attachment metadata had neither, so one account could fill the host's disk
//! through the message routes. Every route that stores caller-supplied bytes calls [`charge`]:
//!
//! - **Free-space floor** (`SKWOD_BLOB_FREE_FLOOR_MB`, the same floor uploads use): while the
//!   data volume has less free space than that, nothing new is stored.
//! - **Per-account quota** (`SKWOD_MESSAGE_QUOTA_MB`, default 512 MiB; `0` = unlimited): the
//!   bytes of ciphertext an account has in messages, DM rows, reactions and attachment metadata.
//!   The sum is taken from the database at most once an hour per account and counted up in
//!   memory in between, so a send costs no extra query.
//!
//! Size caps per item are with the routes: [`MAX_MESSAGE_CIPHERTEXT`] is exactly what receivers
//! accept (`MAX_WIRE_ENVELOPE` in the core — a bigger ciphertext is dropped unread by every
//! current client, so storing it only ever wasted the disk).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::ApiError;
use crate::state::{now_ms, AppState};

/// Largest channel or DM ciphertext stored (decoded bytes). The core refuses to SEND anything
/// whose wire form is larger (`MAX_WIRE_ENVELOPE`, 256 KiB: 150 KiB of text — a feed post with
/// its thumbnail is the biggest real message — plus sealing, padding and the sender-key frame)
/// and drops anything larger on RECEIVE.
pub const MAX_MESSAGE_CIPHERTEXT: usize = 256 * 1024;
/// A reaction is one emoji (≤ 64 bytes in the core), sealed: nonce + tag + a little framing.
pub const MAX_REACTION_CIPHERTEXT: usize = 512;
/// The keyed hash that makes a reaction unique without its plaintext (hex/base64 of 32 bytes).
pub const MAX_REACTION_HASH: usize = 128;
/// An attachment's sealed descriptor (name, type, key, digest).
pub const MAX_ATTACHMENT_METADATA: usize = 16 * 1024;
/// Body limit for the JSON routes that carry one message: base64 of [`MAX_MESSAGE_CIPHERTEXT`]
/// plus ids and mentions.
pub const MESSAGE_BODY_LIMIT: usize = 512 * 1024;
/// Body limit for the small JSON routes (reactions, attachment metadata).
pub const SMALL_BODY_LIMIT: usize = 64 * 1024;

const RECOUNT_AFTER_MS: i64 = 60 * 60 * 1000;
const FULL: &str = "this skwod's host is almost out of disk space, so it is not accepting new messages right now";
const OVER_QUOTA: &str = "you have used all of your message storage on this skwod; delete some messages, or ask the host for more";

/// Account → (bytes stored, when that was last summed from the database).
#[derive(Clone, Default)]
pub struct Usage(Arc<Mutex<HashMap<String, (i64, i64)>>>);

async fn stored_bytes(state: &AppState, user_id: &str) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar(
        "SELECT CAST(
             (SELECT COALESCE(SUM(length(ciphertext)), 0) FROM messages WHERE author_id = $1)
           + (SELECT COALESCE(SUM(length(ciphertext)), 0) FROM dm_messages WHERE author_id = $1)
           + (SELECT COALESCE(SUM(length(emoji_ciphertext) + length(emoji_hash)), 0) FROM reactions WHERE user_id = $1)
           + (SELECT COALESCE(SUM(length(emoji_ciphertext) + length(emoji_hash)), 0) FROM dm_reactions WHERE user_id = $1)
           + (SELECT COALESCE(SUM(length(a.metadata_ciphertext)), 0) FROM message_attachments a JOIN messages m ON m.id = a.message_id WHERE m.author_id = $1)
           + (SELECT COALESCE(SUM(length(a.metadata_ciphertext)), 0) FROM dm_attachments a JOIN dm_messages m ON m.id = a.dm_message_id WHERE m.author_id = $1)
         AS BIGINT)",
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await?)
}

/// Account for `bytes` more stored by `user_id`, or refuse: 507 when the host is below its
/// free-space floor, 413 when the account is over its quota. Call BEFORE the insert.
pub(crate) async fn charge(state: &AppState, user_id: &str, bytes: usize) -> Result<(), ApiError> {
    if let Some(free) = crate::blobs::free_space(&state.blob_dir) {
        if free < state.blob_free_floor_bytes.saturating_add(bytes as u64) {
            return Err(ApiError::InsufficientStorage(FULL));
        }
    }
    let quota = state.message_quota_bytes;
    if quota <= 0 {
        return Ok(());
    }
    let now = now_ms();
    let cached = state.usage.0.lock().expect("usage lock").get(user_id).copied().filter(|(_, at)| now - at < RECOUNT_AFTER_MS);
    let (used, at) = match cached {
        Some(entry) => entry,
        None => (stored_bytes(state, user_id).await?, now),
    };
    let after = used.saturating_add(bytes as i64);
    if after > quota {
        return Err(ApiError::PayloadTooLarge(OVER_QUOTA));
    }
    let mut usage = state.usage.0.lock().expect("usage lock");
    if usage.len() > 50_000 {
        usage.retain(|_, (_, at)| now - *at < RECOUNT_AFTER_MS);
    }
    usage.insert(user_id.to_string(), (after, at));
    Ok(())
}
