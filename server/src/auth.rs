//! Auth: signup, login, logout, sessions.
//!
//! - Passwords: Argon2id, PHC string at rest (`users.password_hash`).
//! - Sessions: 32 random bytes, hex-encoded bearer token; only its SHA-256 lives in the DB.
//!   A session **slides**: every use pushes its expiry out to `session_ttl` (30 days) from now,
//!   capped at `session_max` (1 year) after the sign-in it descends from. Someone who opens the
//!   app now and then stays signed in; a token nobody uses dies after 30 days; and nothing
//!   outlives a year without the password. `POST /api/auth/rotate` swaps the token for a fresh
//!   one (same sign-in, same absolute limit); clients do that every week or so, so a token
//!   copied out of a backup stops working soon after.
//! - Join-code gating (see `join.rs`): required once the instance is initialized via `skwod init`;
//!   open signup on a fresh instance. Payment is not a server concern (mobile = store IAP).

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::{Json, Router};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::state::{new_id, now_ms, AppState};

/// The expiry is only rewritten when it has drifted this far from "ttl from now" — so a busy
/// client costs one extra column write an hour, not one per request.
const SLIDE_SLACK_MS: i64 = 60 * 60 * 1000;
/// After a rotation the previous token keeps working this long, for requests already in flight
/// and for a client that never saw the response.
pub const ROTATE_GRACE_MS: i64 = 5 * 60 * 1000;

pub fn routes() -> Router<AppState> {
    use axum::routing::{delete, get, post};
    Router::new()
        .route("/signup", post(signup))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/rotate", post(rotate))
        .route("/password", post(change_password))
        .route("/me", get(me))
        .route("/users", get(list_users))
        .route("/users/:user_id", delete(delete_user))
        // Unauthenticated routes that take JSON: the default cap (2 MB) is two orders of
        // magnitude more than any of them needs (audit M-1).
        .layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT))
}

/// Guard: the caller must be the instance owner (the bootstrap account).
async fn require_owner(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    let owner: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'owner_user_id'")
            .fetch_optional(&state.db)
            .await?;
    if owner.as_deref() != Some(auth.user_id.as_bytes()) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// Instance-owner-only: every account on this server — including ones that signed up but never
/// joined a space — so the host can manage stranded or forgotten accounts. Usernames are the
/// public login identity; nothing E2EE is exposed.
async fn list_users(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_owner(&state, &auth).await?;
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT p.id, p.username, u.created_at,
                CAST(CASE WHEN EXISTS(SELECT 1 FROM server_members sm WHERE sm.user_id = p.id) THEN 1 ELSE 0 END AS BIGINT)
         FROM profiles p JOIN users u ON u.id = p.id
         ORDER BY u.created_at",
    )
    .fetch_all(&state.db)
    .await?;
    let users: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(id, username, created_at, is_member)| {
            serde_json::json!({ "user_id": id, "username": username, "created_at": created_at, "is_member": is_member == 1 })
        })
        .collect();
    Ok(Json(serde_json::json!({ "users": users })))
}

/// Delete an account entirely: the instance owner can delete anyone (forgot password, abuse), and
/// any non-owner can delete THEMSELF ("delete all my data"). The `users` row is the cascade root —
/// profile, sessions, devices, memberships, and messages all go with it, and the username is freed.
/// The owner can never be deleted (that would orphan the instance).
///
/// Irreversible, so a session token alone is not enough: once the CALLER's account has a device,
/// the request must carry a proof signed by one of its devices over exactly this deletion
/// (`delete-account`, the account being deleted), from the session bound to that device — the
/// same rule as `change_password`. A stolen or unbound token (password-only login, a token out
/// of an old backup) deletes nothing.
///
/// `?ban=1` (the instance owner, deleting someone else): an instance-level ban that survives
/// re-signup as far as a server that stores no addresses can make one. The account's username
/// and its devices' identity keys are remembered as banned (`instance_bans`), and the invite
/// the account signed up with is revoked — the code that let the person in lets nobody else
/// in either. Without it a deleted account simply signed up again with the same code.
async fn delete_user(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    axum::extract::Path(user_id): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<DeleteUserQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.limiter.check(&format!("delete_user:{}", auth.user_id), 20, crate::limiter::HOUR)?;
    let is_self = user_id == auth.user_id;
    if !is_self {
        require_owner(&state, &auth).await?;
    }
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
    if devices > 0 {
        crate::keydir::device_authority(&state, &auth, &headers, "delete-account", &user_id, b"").await?;
    }
    let owner: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'owner_user_id'")
            .fetch_optional(&state.db)
            .await?;
    if owner.as_deref() == Some(user_id.as_bytes()) {
        return Err(ApiError::BadRequest("the owner's account can't be deleted"));
    }
    let ban = q.ban.unwrap_or(0) != 0 && !is_self;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let mut invite_revoked = false;
    if ban {
        let username: Option<String> = sqlx::query_scalar("SELECT username FROM profiles WHERE id = $1").bind(&user_id).fetch_optional(&mut *tx).await?;
        let identities: Vec<Vec<u8>> = sqlx::query_scalar("SELECT identity_key FROM user_devices WHERE user_id = $1").bind(&user_id).fetch_all(&mut *tx).await?;
        let banned = username.iter().map(|u| ("username", u.as_bytes().to_vec())).chain(identities.into_iter().map(|k| ("identity_key", k)));
        for (kind, value) in banned {
            sqlx::query("INSERT INTO instance_bans (kind, value, created_at) VALUES ($1, $2, $3) ON CONFLICT (kind, value) DO NOTHING")
                .bind(kind)
                .bind(value)
                .bind(now)
                .execute(&mut *tx)
                .await?;
        }
        invite_revoked = sqlx::query("UPDATE invites SET status = 'revoked', updated_at = $1 WHERE status = 'active' AND id IN (SELECT invite_id FROM invite_signups WHERE user_id = $2)")
            .bind(now)
            .bind(&user_id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
            > 0;
    }
    let res = sqlx::query("DELETE FROM users WHERE id = $1").bind(&user_id).execute(&mut *tx).await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    tx.commit().await?;
    Ok(Json(serde_json::json!({ "success": true, "banned": ban, "invite_revoked": invite_revoked })))
}

#[derive(Deserialize)]
pub struct DeleteUserQuery {
    /// Owner only: also ban what identifies the account (see [`delete_user`]).
    pub ban: Option<u8>,
}

/// Is this value under an instance-level ban (`kind` = `username` or `identity_key`)?
pub(crate) async fn instance_banned(state: &AppState, kind: &str, value: &[u8]) -> Result<bool, ApiError> {
    let hit: Option<i64> = sqlx::query_scalar("SELECT 1 FROM instance_bans WHERE kind = $1 AND value = $2").bind(kind).bind(value).fetch_optional(&state.db).await?;
    Ok(hit.is_some())
}

// ---- extractor ----

/// The authenticated caller. Extracting it enforces a valid, unexpired bearer token.
pub struct AuthUser {
    pub user_id: String,
    /// The device this session speaks for, once it registered, restored or proved one
    /// (`keydir::bind_session`). A bound session may only act as that device.
    pub device_id: Option<String>,
    /// The generation of that device this session was bound at — recorded by the server.
    pub device_generation: Option<i64>,
    /// SHA-256 of the bearer token (the session's key).
    pub session_hash: Vec<u8>,
}

pub(crate) fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// Resolve a bearer token to its user, and slide the session's expiry (see the module docs).
/// `Unauthorized` when there is no such session or it has expired.
pub(crate) async fn authenticate(state: &AppState, token: &str) -> Result<String, ApiError> {
    touch_current_session(state, &token_hash(token)).await?.ok_or(ApiError::Unauthorized)
}

/// Mark the session behind `hash` as used now; returns its user while it is still valid, and
/// the device the session is bound to (if any). Says nothing about whether that install may
/// still act: callers go through [`touch_current_session`] or the [`AuthUser`] extractor.
pub(crate) async fn touch_session_device(state: &AppState, hash: &[u8]) -> Result<Option<(String, Option<String>, Option<i64>)>, ApiError> {
    let now = now_ms();
    let ttl = state.session_ttl_ms;
    // new expiry = min(now + ttl, origin + max), and never earlier than the current one (a
    // rotated-away token is left to run out its grace period).
    let live: Option<(String, Option<String>, Option<i64>)> = sqlx::query_as(
        "UPDATE sessions SET last_used_at = $1,
                expires_at = CASE
                    WHEN expires_at - $1 > $2 - $3 THEN expires_at
                    WHEN origin_at + $4 < $1 + $2 THEN CASE WHEN origin_at + $4 > expires_at THEN origin_at + $4 ELSE expires_at END
                    ELSE $1 + $2 END
          WHERE token_hash = $5 AND expires_at > $1 AND superseded = 0
         RETURNING user_id, device_id, device_generation",
    )
    .bind(now)
    .bind(ttl)
    .bind(SLIDE_SLACK_MS.min(ttl / 2))
    .bind(state.session_max_ms)
    .bind(hash)
    .fetch_optional(&state.db)
    .await?;
    match live {
        Some(row) => Ok(Some(row)),
        None => superseded_user(state, hash, now).await,
    }
}

/// A token that was rotated away: valid (without sliding) until its grace period ends.
async fn superseded_user(state: &AppState, hash: &[u8], now: i64) -> Result<Option<(String, Option<String>, Option<i64>)>, ApiError> {
    Ok(sqlx::query_as("SELECT user_id, device_id, device_generation FROM sessions WHERE token_hash = $1 AND expires_at > $2 AND superseded = 1")
        .bind(hash)
        .bind(now)
        .fetch_optional(&state.db)
        .await?)
}

/// Is the install behind a session still one that may act? (Audit H-1.)
///
/// A session is **bound** to a device at the generation that device had when the session
/// registered, restored or proved it (`keydir::bind_session`). The generation goes up when the
/// device is restored onto another install (`keydir::rekey_device`), and the row goes away when
/// the device is removed. From that moment the old install is somebody else's copy — a stolen
/// phone, a clone out of a backup — and it gets NOTHING: not the device-scoped routes
/// (`keydir::require_device_session` always refused those), and not channel history, DM tables,
/// member lists, blobs, voice or the WebSocket either, which used to keep answering.
///
/// - bound, device gone → [`ApiError::DeviceRemoved`];
/// - bound at an older generation → [`ApiError::DeviceSuperseded`];
/// - not bound → allowed, unless the host requires bound sessions
///   (`SKWOD_REQUIRE_BOUND_SESSIONS`) and the account has a device a session could be bound to:
///   then [`ApiError::BindRequired`]. A password alone then reaches only the routes of
///   [`stopped_install_allows`] — enough to link, restore or bind, and nothing else.
pub(crate) async fn install_standing(state: &AppState, user_id: &str, device_id: Option<&str>, generation: Option<i64>) -> Result<(), ApiError> {
    match device_id {
        Some(device_id) => {
            let current: Option<i64> = sqlx::query_scalar("SELECT generation FROM user_devices WHERE user_id = $1 AND device_id = $2")
                .bind(user_id)
                .bind(device_id)
                .fetch_optional(&state.db)
                .await?;
            match (current, generation) {
                (None, _) => Err(ApiError::DeviceRemoved),
                (Some(current), Some(bound)) if bound == current => Ok(()),
                (Some(_), _) => Err(ApiError::DeviceSuperseded),
            }
        }
        None if state.require_bound_sessions => {
            // A `legacy_unbound` row (registered before sessions were bound) may still be
            // claimed by its install; until every device of the account has been, an unbound
            // session is that install's only way in.
            let bindable: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1 AND legacy_unbound = 0").bind(user_id).fetch_one(&state.db).await?;
            let legacy: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1 AND legacy_unbound <> 0").bind(user_id).fetch_one(&state.db).await?;
            if bindable > 0 && legacy == 0 {
                Err(ApiError::BindRequired)
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

/// What a session that fails [`install_standing`] may still reach: how it learns why it
/// stopped (`/auth/me`, its own device list), and how an install becomes current — proving it
/// is the current install after all (`bind`), asking for a recovery (`rekey`, with the
/// recovery-key challenge), or being linked again as a NEW device (`link-requests`,
/// `register`). Each of those routes authenticates the install by itself. Deny by default.
pub(crate) fn stopped_install_allows(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    let path = path.trim_end_matches('/');
    if method == Method::GET {
        return matches!(path, "/api/auth/me" | "/api/e2ee/devices" | "/api/e2ee/trust-root")
            || path.starts_with("/api/instance/")
            || path.starts_with("/api/updates/")
            || path.strip_prefix("/api/e2ee/link-requests/").is_some_and(|id| !id.is_empty() && !id.contains('/'));
    }
    if method == Method::POST {
        return matches!(path, "/api/e2ee/devices/register" | "/api/e2ee/link-requests" | "/api/e2ee/key-backup/challenge")
            || path
                .strip_prefix("/api/e2ee/devices/")
                .and_then(|rest| rest.split_once('/'))
                .is_some_and(|(id, op)| !id.is_empty() && matches!(op, "rekey" | "bind"));
    }
    false
}

/// The user behind `hash` if the session is live AND its install may act
/// ([`install_standing`]). For everything that authenticates a bearer token without the
/// [`AuthUser`] extractor: the WebSocket, blob downloads, voice. Slides the session.
pub(crate) async fn touch_current_session(state: &AppState, hash: &[u8]) -> Result<Option<String>, ApiError> {
    let Some((user_id, device_id, generation)) = touch_session_device(state, hash).await? else { return Ok(None) };
    install_standing(state, &user_id, device_id.as_deref(), generation).await?;
    Ok(Some(user_id))
}

/// [`touch_current_session`] without sliding the expiry: for re-checks that are not a use of
/// the session by its holder (p2p standing, voice grants). `None` on any failure.
pub(crate) async fn current_session_user(state: &AppState, hash: &[u8]) -> Option<String> {
    let (user_id, device_id, generation): (String, Option<String>, Option<i64>) =
        sqlx::query_as("SELECT user_id, device_id, device_generation FROM sessions WHERE token_hash = $1 AND expires_at > $2")
            .bind(hash)
            .bind(now_ms())
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()?;
    install_standing(state, &user_id, device_id.as_deref(), generation).await.ok()?;
    Some(user_id)
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let session_hash = token_hash(token);
        let (user_id, device_id, device_generation) = touch_session_device(state, &session_hash).await?.ok_or(ApiError::Unauthorized)?;
        // (Nested routers strip their prefix from `parts.uri`; the original is kept in the
        // extensions.)
        let path = parts.extensions.get::<axum::extract::OriginalUri>().map(|u| u.0.path().to_string()).unwrap_or_else(|| parts.uri.path().to_string());
        // Which install is this? A session of an install that was superseded (the device was
        // restored somewhere else) or removed is refused HERE — on every authenticated route,
        // including ones added later — except the few by which it learns why it stopped or
        // becomes a current install again. Checked before the node gains any p2p standing.
        let mut current = true;
        if let Err(stopped) = install_standing(state, &user_id, device_id.as_deref(), device_generation).await {
            // A session that is merely not bound yet (strict mode) is on its way to a restore:
            // it may also fetch the key backup and ask for a withheld one to be released
            // (restore by approval, `request_backup`, which authenticates the install by its
            // install hash and an approval / the PIN / the hold) — neither of which a
            // superseded or removed install may do.
            let restoring = matches!(stopped, ApiError::BindRequired)
                && matches!(
                    (&parts.method, path.trim_end_matches('/')),
                    (&axum::http::Method::GET, "/api/e2ee/key-backup") | (&axum::http::Method::POST, "/api/e2ee/key-backup/request")
                );
            if !restoring && !stopped_install_allows(&parts.method, &path) {
                return Err(stopped);
            }
            current = false;
        }
        // Over p2p: THIS is what makes a node "signed in" for the connection-slot policy — a
        // token that resolved to a live session, not a header that merely looked like one.
        if let Some(peer) = parts.extensions.get::<crate::client_key::P2pPeer>().filter(|_| current) {
            state.p2p_authenticated.note(state, peer.node_bytes, &user_id, &session_hash).await;
        }
        // The waiting room (`admission.rs`): an account nobody has admitted reaches only the
        // routes it needs to wait and be let in. Checked here so every authenticated route is
        // covered, including ones added later.
        if !crate::admission::waiting_room_allows(&parts.method, &path, &user_id) && !crate::admission::is_admitted(state, &user_id).await? {
            return Err(ApiError::NotAdmitted);
        }
        Ok(AuthUser { user_id, device_id, device_generation, session_hash })
    }
}

// ---- handlers ----

#[derive(Deserialize)]
pub struct SignupRequest {
    pub username: String,
    pub password: String,
    /// Join code (admin setup code or a server invite). Required once the instance is initialized
    /// (ADR-003); the very first signup on a fresh instance is allowed without one.
    pub join_code: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub user_id: String,
    pub token: String,
    pub expires_at: i64,
}

/// Wrong passwords one account takes per minute, from everyone together.
pub(crate) const LOGIN_FAILURES_PER_MINUTE: u32 = 10;
/// Longest password accepted (it is hashed with Argon2; nothing longer is ever legitimate).
const MAX_PASSWORD: usize = 1024;
/// Body limit for the auth routes: a name, a password, a join code.
const AUTH_BODY_LIMIT: usize = 16 * 1024;

pub(crate) fn is_valid_username(u: &str) -> bool {
    valid_username(u)
}

fn valid_username(u: &str) -> bool {
    (3..=32).contains(&u.len())
        && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

pub(crate) fn hash_secret(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::Internal)
}

pub(crate) fn verify_secret(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

pub(crate) async fn create_session(state: &AppState, user_id: &str) -> Result<SessionResponse, ApiError> {
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = hex::encode(raw);
    let now = now_ms();
    let expires_at = now + state.session_ttl_ms.min(state.session_max_ms);
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_used_at, origin_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(new_id())
    .bind(user_id)
    .bind(token_hash(&token))
    .bind(now)
    .bind(expires_at)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;
    Ok(SessionResponse { user_id: user_id.to_string(), token, expires_at })
}

/// Swap the caller's token for a fresh one. The new session descends from the same sign-in
/// (`origin_at`), so rotating never extends the absolute lifetime. The push registration made
/// under the old token moves to the new one — a rotation must not cost the device its wakes —
/// and the old token keeps working for [`ROTATE_GRACE_MS`] and then is gone.
async fn rotate(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Result<Json<SessionResponse>, ApiError> {
    let old = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let old_hash = token_hash(old);
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    // Only a live, not-yet-rotated session can be rotated (a stolen old token cannot mint new ones
    // once its owner has rotated).
    #[allow(clippy::type_complexity)]
    let row: Option<(String, i64, Option<String>, Option<i64>, i64)> = sqlx::query_as("SELECT user_id, origin_at, device_id, device_generation, pre_migration FROM sessions WHERE token_hash = $1 AND expires_at > $2 AND superseded = 0")
        .bind(&old_hash)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
    let (user_id, origin_at, device_id, device_generation, pre_migration) = row.ok_or(ApiError::Unauthorized)?;
    state.limiter.check(&format!("rotate:{user_id}"), 30, crate::limiter::HOUR)?;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = hex::encode(raw);
    let new_hash = token_hash(&token);
    let expires_at = (now + state.session_ttl_ms).min(origin_at + state.session_max_ms);
    if expires_at <= now {
        return Err(ApiError::Unauthorized);
    }
    // The new token speaks for the same device as the one it replaces.
    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_used_at, origin_at, device_id, device_generation, pre_migration)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(new_id())
    .bind(&user_id)
    .bind(&new_hash)
    .bind(now)
    .bind(expires_at)
    .bind(now)
    .bind(origin_at)
    .bind(&device_id)
    .bind(device_generation)
    // A rotated token is the same sign-in: it keeps what the old one could do.
    .bind(pre_migration)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE push_registrations SET session_hash = $1, updated_at = $2 WHERE session_hash = $3")
        .bind(&new_hash)
        .bind(now)
        .bind(&old_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE push_tokens SET session_hash = $1 WHERE session_hash = $2").bind(&new_hash).bind(&old_hash).execute(&mut *tx).await?;
    sqlx::query("UPDATE sessions SET superseded = 1, expires_at = CASE WHEN expires_at < $1 THEN expires_at ELSE $1 END WHERE token_hash = $2")
        .bind(now + ROTATE_GRACE_MS)
        .bind(&old_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(SessionResponse { user_id, token, expires_at }))
}

async fn signup(
    State(state): State<AppState>,
    client: crate::client_key::ClientKey,
    Json(req): Json<SignupRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    // Per-IP AND per-username windows: the username window stops targeted brute force; the IP
    // window stops password-spraying many usernames from one host (unthrottled with per-name only).
    client.limit_unauthenticated(&state, "signup", 20)?;
    // The name is checked BEFORE it becomes a limiter key (audit M-1): the key used to be the
    // raw field, megabytes of it if the caller liked, kept in memory for the whole window.
    if !valid_username(&req.username) {
        return Err(ApiError::BadRequest("username must be 3-32 chars of a-z, 0-9, _"));
    }
    state.limiter.check(&format!("signup:{}", req.username), 10, crate::limiter::MINUTE)?;
    if req.password.len() < 8 {
        return Err(ApiError::BadRequest("password too short (min 8)"));
    }
    if req.password.len() > MAX_PASSWORD {
        return Err(ApiError::BadRequest("password too long"));
    }
    // A name the instance owner banned (`delete_user`, `?ban=1`) is not available again.
    // Answered like a name that is in use.
    if instance_banned(&state, "username", req.username.as_bytes()).await? {
        return Err(ApiError::Conflict("username taken"));
    }

    // Join-code gate (ADR-003): required once the instance is initialized. We track HOW the code
    // validated so a bootstrap (admin_setup_code) signup can claim instance ownership below.
    let mut is_bootstrap = false;
    let mut invite_code = None;
    if crate::join::signup_requires_code(&state).await? {
        let code = req.join_code.as_deref().ok_or(ApiError::Forbidden)?;
        match crate::join::authorize_join(&state, code).await? {
            crate::join::JoinAuth::Bootstrap => is_bootstrap = true,
            crate::join::JoinAuth::Invite => invite_code = Some(code),
            crate::join::JoinAuth::Invalid => return Err(ApiError::Forbidden),
        }
    }

    let user_id = new_id();
    let phc = hash_secret(&req.password)?;
    let now = now_ms();

    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO users (id, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $4)")
        .bind(&user_id)
        .bind(&phc)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    let username_taken = sqlx::query("INSERT INTO profiles (id, username) VALUES ($1, $2)")
        .bind(&user_id)
        .bind(&req.username)
        .execute(&mut *tx)
        .await;
    if let Err(e) = username_taken {
        return Err(map_unique(e, "username taken"));
    }

    // Bootstrap: claim instance ownership ATOMICALLY, inside the signup transaction, so exactly the
    // one signup that wins the `owner_user_id` INSERT is authorized. `authorize_join` reported
    // Bootstrap only from a read of `!owner_claimed()`; two concurrent admin-code signups could both
    // pass that read, so we make bootstrap success conditional on the claim actually inserting. The
    // loser's ON CONFLICT DO NOTHING affects 0 rows → it is rejected and its transaction rolls back,
    // so the admin_setup_code still mints exactly one account even under a race.
    if is_bootstrap {
        let claimed = crate::join::claim_ownership_tx(&mut tx, &user_id).await?;
        if !claimed {
            return Err(ApiError::Forbidden);
        }
    }
    // An invite signup uses the invite up: one of its uses, and one of the few places it has
    // for accounts nobody has admitted yet. In the same transaction as the account, so a code
    // cannot mint more accounts than it allows however the requests race.
    if let Some(code) = invite_code {
        match crate::join::consume_signup_tx(&mut tx, code, &user_id, state.invite_pending_signups, now).await? {
            crate::join::SignupClaim::Claimed => {}
            crate::join::SignupClaim::Invalid => return Err(ApiError::Forbidden),
            crate::join::SignupClaim::Full { invite_id, waiting } => {
                // Nothing of this signup is kept; the people who can free a place are told.
                drop(tx);
                crate::structure::notify_invite_full(&state, &invite_id, waiting).await;
                return Err(ApiError::InviteFull);
            }
        }
    }
    tx.commit().await?;

    Ok(Json(create_session(&state, &user_id).await?))
}

fn map_unique(e: sqlx::Error, msg: &'static str) -> ApiError {
    match ApiError::from(e) {
        ApiError::Conflict(_) => ApiError::Conflict(msg),
        other => other,
    }
}

async fn login(
    State(state): State<AppState>,
    client: crate::client_key::ClientKey,
    Json(req): Json<LoginRequest>,
) -> Result<Json<SessionResponse>, ApiError> {
    // Per-IP AND per-account windows: the account window is the credential-stuffing brake; the IP
    // window stops password-spraying (one password across many usernames from one host).
    client.limit_unauthenticated(&state, "login", 30)?;
    // Only something that can BE a username is looked up or becomes a limiter key (audit
    // M-1). Anything else is "wrong credentials", like an unknown name.
    let username = req.username.to_lowercase();
    if !valid_username(&username) || req.password.len() > MAX_PASSWORD {
        return Err(ApiError::Unauthorized);
    }
    // The per-account brake counts FAILED attempts only (net audit P6): the window used to
    // be spent by every attempt before the password was looked at, so the owner's own
    // sign-ins used it up, and ten requests a minute naming someone kept that person from
    // signing in whatever they typed. A full window still refuses before any verification —
    // it is what protects the password, and no number of callers gets around it.
    // The attempt is TAKEN here, before anything is verified, and given back only when the
    // password turns out right — so a parallel burst cannot all get in ahead of the count.
    let failures = format!("login:{username}");
    state.limiter.take(&failures, LOGIN_FAILURES_PER_MINUTE, crate::limiter::MINUTE)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT u.id, u.password_hash FROM users u JOIN profiles p ON p.id = u.id WHERE p.username = $1")
            .bind(&username)
            .fetch_optional(&state.db)
            .await?;
    // Verify against a real or dummy hash either way, so response timing doesn't
    // reveal whether the username exists.
    const DUMMY_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let (user_id, phc) = match &row {
        Some((id, phc)) => (Some(id.as_str()), phc.as_str()),
        None => (None, DUMMY_PHC),
    };
    let verified = verify_secret(&req.password, phc);
    let Some(user_id) = user_id.filter(|_| verified) else { return Err(ApiError::Unauthorized) };
    state.limiter.refund(&failures);
    Ok(Json(create_session(&state, user_id).await?))
}

async fn logout(State(state): State<AppState>, parts: axum::http::HeaderMap) -> Result<(), ApiError> {
    let token = parts
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(token_hash(token))
        .execute(&state.db)
        .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct ChangePassword {
    pub old_password: String,
    pub new_password: String,
}

/// Change the account password. Needs the OLD password and — once the account has a device —
/// a proof signed by one of its devices over the new password: a stolen session token alone
/// cannot lock the owner out, and neither can someone who only knows the old password.
/// Every OTHER session of the account ends (and its push registration with it); the calling
/// session carries on.
async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChangePassword>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.limiter.check(&format!("password:{}", auth.user_id), 10, crate::limiter::HOUR)?;
    if req.new_password.len() < 8 {
        return Err(ApiError::BadRequest("password too short (min 8)"));
    }
    if req.new_password.len() > MAX_PASSWORD {
        return Err(ApiError::BadRequest("password too long"));
    }
    let phc: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
    if !verify_secret(&req.old_password, &phc) {
        return Err(ApiError::Forbidden);
    }
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
    if devices > 0 {
        // Proof by a device AND this session being that device's current install.
        crate::keydir::device_authority(&state, &auth, &headers, "password", "", req.new_password.as_bytes()).await?;
    }
    let new_phc = hash_secret(&req.new_password)?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $1, updated_at = $2 WHERE id = $3")
        .bind(&new_phc)
        .bind(now_ms())
        .bind(&auth.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM push_registrations WHERE user_id = $1 AND session_hash <> $2")
        .bind(&auth.user_id)
        .bind(&auth.session_hash)
        .execute(&mut *tx)
        .await?;
    let revoked = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
        .bind(&auth.user_id)
        .bind(&auth.session_hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    // Open sockets of the ended sessions notice at their next session re-check (ws.rs).
    state.rt.publish(&crate::rt::user_topic(&auth.user_id), "sessions_revoked", serde_json::json!({}));
    Ok(Json(serde_json::json!({ "success": true, "revoked_sessions": revoked })))
}

#[derive(Serialize)]
struct MeResponse {
    user_id: String,
    username: String,
}

async fn me(State(state): State<AppState>, auth: AuthUser) -> Result<Json<MeResponse>, ApiError> {
    let username: String = sqlx::query_scalar(
        "SELECT p.username FROM profiles p WHERE p.id = $1",
    )
    .bind(&auth.user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(MeResponse { user_id: auth.user_id, username }))
}
