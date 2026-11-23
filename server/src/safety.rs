//! User-safety endpoints: user blocks and abuse reports.
//!
//! Everything here operates on PUBLIC routing metadata only (user ids, server ids) — the server
//! never needs, and never gets, plaintext content. The one plaintext field (`abuse_reports.body`)
//! is the reporter's OWN description/excerpt they chose to include when filing, Signal-style:
//! user-initiated disclosure, not server-side decryption. Server bans live in `structure.rs`
//! (they need the permission/rank helpers there); this module hosts the shared ban lookup.

use axum::extract::{Path, State};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::{new_id, now_ms, AppState};

pub fn routes() -> Router<AppState> {
    use axum::routing::{get, post, put};
    Router::new()
        .route("/blocks", get(list_blocks))
        .route("/blocks/:user_id", put(block_user).delete(unblock_user))
        .route("/reports", post(create_report).get(list_reports))
        .route("/reports/:report_id/resolve", post(resolve_report))
}

// ---- shared enforcement helpers ----

// NOTE: the ban check (`EXISTS(... server_bans ...)`) is intentionally inlined at each
// membership-granting path (`accept_invite`, `approve_join_request` in structure.rs) rather than
// funneled through a pooled helper: those paths must read the ban on their OPEN transaction (the
// same connection as the member INSERT) so a ban committing mid-request can't be raced past under
// Postgres READ COMMITTED, and so the read can't deadlock SQLite's single writer.

/// Does a block exist between the two users, in EITHER direction? Symmetric on purpose (the
/// Signal model): a blocked user can't reach their blocker, and the blocker must unblock
/// before contacting the blocked user — otherwise "blocked" messages would still land on the
/// other phone. Keys on user ids only.
pub async fn pair_blocked(state: &AppState, a: &str, b: &str) -> Result<bool, ApiError> {
    let blocked: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM user_blocks
            WHERE (blocker_id = $1 AND blocked_id = $2) OR (blocker_id = $3 AND blocked_id = $4))
         THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(a)
    .bind(b)
    .bind(b)
    .bind(a)
    .fetch_one(&state.db)
    .await?;
    Ok(blocked == 1)
}

// ---- blocks (self-scoped) ----

/// Block a user: they can no longer open a DM with me or send into our existing 1:1 DM
/// (enforced in `messages.rs`), and their DM typing indicators stop reaching me (`ws.rs`).
/// Blocking says nothing to the blocked user — sends just start failing.
async fn block_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if user_id == auth.user_id {
        return Err(ApiError::BadRequest("you can't block yourself"));
    }
    let exists: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM profiles WHERE id = $1) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await?;
    if exists == 0 {
        return Err(ApiError::NotFound);
    }
    sqlx::query(
        "INSERT INTO user_blocks (blocker_id, blocked_id, created_at) VALUES ($1, $2, $3)
         ON CONFLICT (blocker_id, blocked_id) DO NOTHING",
    )
    .bind(&auth.user_id)
    .bind(&user_id)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true })))
}

async fn unblock_user(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    sqlx::query("DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2")
        .bind(&auth.user_id)
        .bind(&user_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

/// My block list (self-scoped — nobody can read anyone else's).
async fn list_blocks(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT b.blocked_id, p.username, b.created_at FROM user_blocks b
         JOIN profiles p ON p.id = b.blocked_id
         WHERE b.blocker_id = $1 ORDER BY b.created_at DESC",
    )
    .bind(&auth.user_id)
    .fetch_all(&state.db)
    .await?;
    let blocks: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, username, created_at)| json!({ "user_id": user_id, "username": username, "created_at": created_at }))
        .collect();
    Ok(Json(json!({ "blocks": blocks })))
}

// ---- abuse reports ----

const MAX_CATEGORY_LEN: usize = 64;
const MAX_BODY_LEN: usize = 4000;

#[derive(Deserialize)]
pub struct CreateReport {
    /// Free-form category ("spam", "harassment", "csam", ...). Kept as text so clients can evolve
    /// their taxonomies without a server migration.
    pub category: String,
    /// The reporter's own plaintext description and/or excerpt they choose to include. The server
    /// never decrypts anything — this is user-initiated disclosure (Signal-style reporting).
    pub body: Option<String>,
    pub subject_user_id: Option<String>,
    pub server_id: Option<String>,
}

/// Any authenticated user may file a report. Rate-limited so one account can't flood the
/// operator's queue.
async fn create_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateReport>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("report:{}", auth.user_id), 5, crate::limiter::HOUR)?;
    let category = req.category.trim();
    if category.is_empty() || category.len() > MAX_CATEGORY_LEN {
        return Err(ApiError::BadRequest("category must be 1..=64 chars"));
    }
    if req.body.as_deref().is_some_and(|b| b.len() > MAX_BODY_LEN) {
        return Err(ApiError::BadRequest("body too long (max 4000 chars)"));
    }
    // Referential fields are best-effort pointers: a bogus subject/server is stored as NULL rather
    // than erroring, so a report about a just-deleted account still lands in the queue.
    let subject: Option<String> = match req.subject_user_id.as_deref() {
        Some(id) => sqlx::query_scalar("SELECT id FROM profiles WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?,
        None => None,
    };
    let server: Option<String> = match req.server_id.as_deref() {
        Some(id) => sqlx::query_scalar("SELECT id FROM servers WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await?,
        None => None,
    };
    // A server-scoped report must come from someone actually in that server: otherwise any account
    // could attribute reports to servers it has never seen. (An unknown server id is still just
    // dropped to NULL above.)
    if let Some(server_id) = &server {
        crate::structure::effective_permissions(&state, server_id, &auth.user_id, None).await?;
    }
    let id = new_id();
    sqlx::query(
        "INSERT INTO abuse_reports (id, reporter_id, subject_user_id, server_id, category, body, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'open', $7)",
    )
    .bind(&id)
    .bind(&auth.user_id)
    .bind(&subject)
    .bind(&server)
    .bind(category)
    .bind(&req.body)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "report_id": id })))
}

/// Instance-owner only: the abuse queue, newest first, with usernames resolved for triage.
#[allow(clippy::type_complexity)]
async fn list_reports(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    crate::structure::require_instance_owner(&state, &auth.user_id).await?;
    let rows: Vec<(String, String, Option<String>, Option<String>, Option<String>, String, Option<String>, String, i64)> = sqlx::query_as(
        "SELECT r.id, r.reporter_id, rp.username, r.subject_user_id, sp.username, r.category, r.body, r.status, r.created_at
         FROM abuse_reports r
         LEFT JOIN profiles rp ON rp.id = r.reporter_id
         LEFT JOIN profiles sp ON sp.id = r.subject_user_id
         ORDER BY r.created_at DESC LIMIT 500",
    )
    .fetch_all(&state.db)
    .await?;
    let reports: Vec<Value> = rows
        .into_iter()
        .map(|(id, reporter_id, reporter_username, subject_user_id, subject_username, category, body, status, created_at)| {
            json!({
                "report_id": id,
                "reporter_id": reporter_id,
                "reporter_username": reporter_username,
                "subject_user_id": subject_user_id,
                "subject_username": subject_username,
                "category": category,
                "body": body,
                "status": status,
                "created_at": created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "reports": reports })))
}

/// Instance-owner only: mark a report handled.
async fn resolve_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(report_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    crate::structure::require_instance_owner(&state, &auth.user_id).await?;
    let n = sqlx::query("UPDATE abuse_reports SET status = 'resolved' WHERE id = $1")
        .bind(&report_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "success": true })))
}
