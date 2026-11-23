//! The per-file upload limit — a setting of the HOST's.
//!
//! How large one attachment may be. It was a number hard-coded into the apps (100 MB); it is now
//! the host's to choose:
//!
//! - `SKWOD_MAX_UPLOAD_MB` (default 100) for Docker and every other way of running `skwod run`;
//! - `PUT /api/instance/limits` by the instance owner (the Mac app's host settings do this),
//!   stored in the database, effective at once and across restarts. A value set this way wins
//!   over the environment variable; `null` removes it again.
//!
//! Members read it with `GET /api/instance/limits`, check a file before they encrypt it and show
//! the real number. That is a courtesy: [`refuse_oversized`] in `POST /api/blobs` is what
//! enforces it, on the size the server itself is told to reserve.
//!
//! Bounds. Never under 1 MB (a photo must fit) and never over 1900 MB: a file is uploaded as
//! padded ciphertext (up to ~6 % larger), and that has to stay under the 2 GiB blob ceiling. A value set by the owner must also fit
//! on the disk as it is now: not more than the free space above the free-disk floor
//! (`SKWOD_BLOB_FREE_FLOOR_MB`). The floor itself and the per-account quota
//! (`SKWOD_BLOB_QUOTA_MB`) are checked on every upload exactly as before.

use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::{now_ms, AppState};

pub const DEFAULT_MAX_UPLOAD_MB: u64 = 100;
pub const MIN_UPLOAD_MB: u64 = 1;
/// The largest file whose padded ciphertext ([`blob_ceiling`]) still fits a blob (`blobs::MAX_BLOB`, 2 GiB).
pub const MAX_UPLOAD_MB: u64 = 1900;
const MIB: u64 = 1024 * 1024;
const SETTING: &str = "max_upload_mb";

/// A configured value brought inside the bounds (an environment variable is clamped, not refused:
/// a server that will not start over a typo in an optional limit helps nobody).
pub fn clamp_mb(mb: u64) -> u64 {
    mb.clamp(MIN_UPLOAD_MB, MAX_UPLOAD_MB)
}

/// The limit from `SKWOD_MAX_UPLOAD_MB` as the variable's text, in bytes.
pub fn from_env_value(raw: Option<&str>) -> u64 {
    clamp_mb(raw.and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(DEFAULT_MAX_UPLOAD_MB)) * MIB
}

/// The largest BLOB a file of `limit` bytes can become. What is uploaded is ciphertext: the
/// plaintext padded up to a size bucket (at most ~5 %), plus IV, block padding and MAC. The same
/// allowance the core uses when it opens one.
pub fn blob_ceiling(limit: u64) -> u64 {
    limit.saturating_add(limit / 16).saturating_add(1024)
}

/// The limit in force, in bytes of the file as the user sees it.
pub fn max_upload_bytes(state: &AppState) -> u64 {
    state.max_upload_bytes.load(Ordering::Relaxed)
}

/// `POST /api/blobs`: is a blob of `total_size` bytes more than one file may be here?
pub fn refuse_oversized(state: &AppState, total_size: i64) -> Result<(), ApiError> {
    let limit = max_upload_bytes(state);
    if total_size as u64 > blob_ceiling(limit) {
        return Err(ApiError::FileTooLarge { max_upload_bytes: limit });
    }
    Ok(())
}

async fn stored_mb(state: &AppState) -> Result<Option<u64>, ApiError> {
    let raw: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = $1").bind(SETTING).fetch_optional(&state.db).await?;
    Ok(raw.and_then(|b| String::from_utf8(b).ok()).and_then(|s| s.trim().parse::<u64>().ok()))
}

/// At startup: a limit the owner set from the app replaces the environment's.
pub async fn load(state: &AppState) {
    match stored_mb(state).await {
        Ok(Some(mb)) => state.max_upload_bytes.store(clamp_mb(mb) * MIB, Ordering::Relaxed),
        Ok(None) => {}
        Err(_) => tracing::warn!("could not read the stored upload limit; using SKWOD_MAX_UPLOAD_MB"),
    }
}

pub fn routes() -> Router<AppState> {
    use axum::routing::get;
    Router::new().route("/instance/limits", get(get_limits).put(set_limits))
}

fn describe(state: &AppState, host_set: bool) -> Value {
    let bytes = max_upload_bytes(state);
    json!({
        "max_upload_bytes": bytes,
        "max_upload_mb": bytes / MIB,
        "min_upload_mb": MIN_UPLOAD_MB,
        "max_upload_mb_allowed": MAX_UPLOAD_MB,
        "host_set": host_set,
    })
}

/// Any signed-in account: how large one file may be here. Says nothing about the host's disk.
async fn get_limits(State(state): State<AppState>, _auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let host_set = stored_mb(&state).await?.is_some();
    Ok(Json(describe(&state, host_set)))
}

#[derive(Deserialize)]
struct SetLimits {
    /// Megabytes; `null` goes back to `SKWOD_MAX_UPLOAD_MB` (or the default).
    max_upload_mb: Option<u64>,
}

/// Instance owner only: set (or clear) the per-file limit.
async fn set_limits(State(state): State<AppState>, auth: AuthUser, Json(req): Json<SetLimits>) -> Result<Json<Value>, ApiError> {
    crate::structure::require_instance_owner(&state, &auth.user_id).await?;
    let Some(mb) = req.max_upload_mb else {
        sqlx::query("DELETE FROM instance_secrets WHERE name = $1").bind(SETTING).execute(&state.db).await?;
        state.max_upload_bytes.store(state.max_upload_env_bytes, Ordering::Relaxed);
        return Ok(Json(describe(&state, false)));
    };
    if !(MIN_UPLOAD_MB..=MAX_UPLOAD_MB).contains(&mb) {
        return Err(ApiError::BadRequest("the upload limit must be between 1 MB and 1900 MB"));
    }
    // A limit the disk could not take even once is a promise the host cannot keep.
    if let Some(free) = crate::blobs::free_space(&state.blob_dir) {
        if free < state.blob_free_floor_bytes.saturating_add(mb * MIB) {
            return Err(ApiError::BadRequest(
                "this host does not have that much free disk space above its reserve (SKWOD_BLOB_FREE_FLOOR_MB); choose a smaller limit or free up space",
            ));
        }
    }
    sqlx::query(
        "INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, $3)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value, created_at = excluded.created_at",
    )
    .bind(SETTING)
    .bind(mb.to_string().into_bytes())
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    state.max_upload_bytes.store(mb * MIB, Ordering::Relaxed);
    Ok(Json(describe(&state, true)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{send, signup, test_state};
    use axum::http::StatusCode;

    async fn make_owner(state: &AppState, user_id: &str) {
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('owner_user_id', $1, 0)")
            .bind(user_id.as_bytes().to_vec())
            .execute(&state.db)
            .await
            .unwrap();
    }

    async fn join_a_space(app: &Router, token: &str) {
        use base64::Engine;
        let name = base64::engine::general_purpose::STANDARD.encode(b"s");
        let (st, body) = send(app, "POST", "/api/servers", Some(token), Some(json!({ "name_ciphertext": name }))).await;
        assert_eq!(st, StatusCode::OK, "{body}");
    }

    #[test]
    fn the_environment_value_is_bounded() {
        assert_eq!(from_env_value(None), 100 * MIB);
        assert_eq!(from_env_value(Some("250")), 250 * MIB);
        assert_eq!(from_env_value(Some(" 50 ")), 50 * MIB);
        assert_eq!(from_env_value(Some("0")), MIB, "never under 1 MB");
        assert_eq!(from_env_value(Some("999999")), MAX_UPLOAD_MB * MIB, "never over what fits a blob");
        assert_eq!(from_env_value(Some("lots")), 100 * MIB, "nonsense is the default");
        assert_eq!(from_env_value(Some("-5")), 100 * MIB);
        // The ceiling stays under the 2 GiB a blob may be.
        assert!(blob_ceiling(MAX_UPLOAD_MB * MIB) < crate::blobs::MAX_BLOB as u64);
    }

    #[tokio::test]
    async fn the_limit_is_reported_and_enforced_by_the_server() {
        let state = test_state().await;
        let app = crate::api::router(state.clone());
        let (owner_id, owner) = signup(&app, "host").await;
        make_owner(&state, &owner_id).await;
        let (_, member) = signup(&app, "member").await;
        join_a_space(&app, &owner).await;

        // Signed out: nothing. Signed in: the default, and that the host has not chosen one.
        assert_eq!(send(&app, "GET", "/api/instance/limits", None, None).await.0, StatusCode::UNAUTHORIZED);
        let (st, body) = send(&app, "GET", "/api/instance/limits", Some(&member), None).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["max_upload_bytes"], 100 * MIB);
        assert_eq!(body["max_upload_mb"], 100);
        assert_eq!(body["host_set"], false);
        assert_eq!(body["min_upload_mb"], MIN_UPLOAD_MB);
        assert_eq!(body["max_upload_mb_allowed"], MAX_UPLOAD_MB);

        // Only the owner may change it.
        let (st, _) = send(&app, "PUT", "/api/instance/limits", Some(&member), Some(json!({ "max_upload_mb": 5 }))).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let (st, body) = send(&app, "PUT", "/api/instance/limits", Some(&owner), Some(json!({ "max_upload_mb": 2 }))).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["max_upload_bytes"], 2 * MIB);
        let (_, body) = send(&app, "GET", "/api/instance/limits", Some(&member), None).await;
        assert_eq!((body["max_upload_mb"].as_u64(), body["host_set"].as_bool()), (Some(2), Some(true)));

        // The server enforces it, whatever the app believed: the largest blob a 2 MB file can
        // become is accepted, one byte more is refused with the number in the answer.
        let at_limit = blob_ceiling(2 * MIB);
        let (st, body) = send(&app, "POST", "/api/blobs", Some(&owner), Some(json!({ "total_size": at_limit }))).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        let (st, body) = send(&app, "POST", "/api/blobs", Some(&owner), Some(json!({ "total_size": at_limit + 1 }))).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        assert_eq!(body["max_upload_bytes"], 2 * MIB);
        assert!(body["error"].as_str().unwrap().contains("2 MB"), "{body}");

        // It survives a restart (a new state over the same database)…
        let restarted = AppState::new(state.db.clone(), state.blob_dir.clone());
        assert_eq!(max_upload_bytes(&restarted), 100 * MIB);
        load(&restarted).await;
        assert_eq!(max_upload_bytes(&restarted), 2 * MIB);

        // …and clearing it goes back to the environment's value.
        let (st, body) = send(&app, "PUT", "/api/instance/limits", Some(&owner), Some(json!({ "max_upload_mb": null }))).await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!((body["max_upload_mb"].as_u64(), body["host_set"].as_bool()), (Some(100), Some(false)));
        let (st, _) = send(&app, "POST", "/api/blobs", Some(&owner), Some(json!({ "total_size": at_limit + 1 }))).await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_owner_cannot_set_a_limit_outside_the_bounds_or_beyond_the_disk() {
        let mut state = test_state().await;
        let app = crate::api::router(state.clone());
        let (owner_id, owner) = signup(&app, "host").await;
        make_owner(&state, &owner_id).await;

        for bad in [json!(0), json!(MAX_UPLOAD_MB + 1), json!(u64::MAX)] {
            let (st, body) = send(&app, "PUT", "/api/instance/limits", Some(&owner), Some(json!({ "max_upload_mb": bad }))).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        }
        for odd in [json!(-1), json!("12"), json!(1.5)] {
            let (st, _) = send(&app, "PUT", "/api/instance/limits", Some(&owner), Some(json!({ "max_upload_mb": odd }))).await;
            assert!(st.is_client_error(), "{st}");
        }
        assert_eq!(max_upload_bytes(&state), 100 * MIB, "a refused value changes nothing");
        let (st, _) = send(&app, "PUT", "/api/instance/limits", Some(&owner), Some(json!({ "max_upload_mb": MIN_UPLOAD_MB }))).await;
        assert_eq!(st, StatusCode::OK);

        // The free-disk floor: a limit the volume could not hold above its reserve is refused.
        state.blob_free_floor_bytes = u64::MAX / 2;
        let tight = crate::api::router(state.clone());
        let (st, body) = send(&tight, "PUT", "/api/instance/limits", Some(&owner), Some(json!({ "max_upload_mb": 50 }))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"].as_str().unwrap().contains("free disk space"), "{body}");
        assert_eq!(max_upload_bytes(&state), MIN_UPLOAD_MB * MIB);
    }

    #[tokio::test]
    async fn the_per_account_quota_still_applies_under_a_larger_limit() {
        let mut state = test_state().await;
        state.blob_quota_bytes = 3 * MIB as i64;
        state.max_upload_bytes.store(500 * MIB, Ordering::Relaxed);
        let app = crate::api::router(state.clone());
        let (_, alice) = signup(&app, "alice").await;
        join_a_space(&app, &alice).await;
        // Within the per-file limit, over the account's quota: the quota's refusal, not the limit's.
        let (st, body) = send(&app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 4 * MIB }))).await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
        assert!(body["error"].as_str().unwrap().contains("attachment storage"), "{body}");
        assert!(body.get("max_upload_bytes").is_none());
        let (st, _) = send(&app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 2 * MIB }))).await;
        assert_eq!(st, StatusCode::OK);
    }
}
