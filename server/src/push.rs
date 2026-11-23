//! Push notifications — registration + **contentless** wakeup fan-out.
//!
//! Invariant #4 (SECURITY.md): notifications carry NO plaintext, and no scope or message id
//! either — a wake says "sync", nothing more; the device fetches and decrypts on receipt.
//! Three registration shapes end here (docs/PUSH.md): a gateway wake credential (current
//! apps), raw tokens for the gateway (builds <= 45), and a direct token for an operator with
//! its own APNs/FCM keys. This module also decides WHO is woken for a message
//! ([`channel_recipients`], [`without_blockers`]).

use axum::extract::State;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::{new_id, now_ms, AppState};

pub fn routes() -> Router<AppState> {
    use axum::routing::post;
    Router::new()
        .route("/push/register", post(register_token))
        .route("/push/unregister", post(unregister_token))
}

/// Two shapes share this endpoint:
///
/// - **direct** (operators with their own APNs/FCM keys): `{ "token", "platform" }`;
/// - **blind gateway** (everyone else on iOS): `{ "provider": "gateway", "gateway": "<url>",
///   "wake_credential": "w1.…" }` (builds <= 45: `"apns_token": "<hex>", "voip_token":
///   "<hex or null>", "topic": "<bundle id>"` in its place), plus an optional `"device_id"`
///   so removing that device removes exactly this registration. A session that is bound to a
///   device (`AuthUser::device_id`) registers as that device whatever the body says.
#[derive(Deserialize)]
pub struct RegisterToken {
    pub token: Option<String>,
    pub platform: Option<String>, // ios | macos | android (ADR-009: no web)
    pub provider: Option<String>,
    pub gateway: Option<String>,
    pub apns_token: Option<String>,
    pub voip_token: Option<String>,
    pub topic: Option<String>,
    pub device_id: Option<String>,
    /// Gateway shape only, optional: 16–32 chars of `[A-Za-z0-9_-]` the device made up for THIS
    /// skwod. Sent back with every wake (see `gateway.rs`).
    pub wake_tag: Option<String>,
    /// Gateway shape, build >= 46: the capability the device got from the gateway
    /// (`POST <gateway>/v1/register`, docs/PUSH.md). Sent INSTEAD of `apns_token`, `voip_token`,
    /// `topic` and `wake_tag` — with it, this server never learns the device's push tokens.
    pub wake_credential: Option<String>,
}

/// A gateway wake credential: `w1.` + base64url. Opaque here; bounded so it is not a storage
/// or relay channel.
fn valid_wake_credential(c: &str) -> bool {
    (16..=2048).contains(&c.len()) && c.starts_with("w1.") && c[3..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

const PINNED_GATEWAY: &str = "push_gateway_host";

async fn pinned_gateway(state: &AppState) -> Result<Option<Vec<u8>>, ApiError> {
    Ok(sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = $1").bind(PINNED_GATEWAY).fetch_optional(&state.db).await?)
}

/// May this instance call `gateway` (a URL `validate_gateway_url` returned)? THE answer, asked
/// when a device registers AND every time a wake is about to be sent — so a row written under
/// an older, laxer rule cannot keep the server dialling a host it would refuse today.
///
/// - an allowlist (the operator's `SKWOD_PUSH_GATEWAYS`, else the publisher's gateway baked into
///   the build): the host must be on it;
/// - no allowlist: the host the instance OWNER's app registered first ("owner-pinned"), and
///   until there is one, none — a member can never make this server call a host of the
///   member's choosing (which would show that host the server's address);
/// - an instance nobody owns yet (development), and the loopback test hook: not restricted.
pub(crate) async fn gateway_allowed(state: &AppState, gateway: &str) -> Result<bool, ApiError> {
    let policy = &state.waker.policy;
    if policy.insecure_loopback && gateway.starts_with("http://127.0.0.1:") {
        return Ok(true);
    }
    let host = crate::gateway::gateway_host(gateway);
    if let Some(allowed) = &policy.allowed_hosts {
        return Ok(allowed.iter().any(|a| a == host));
    }
    if crate::structure::instance_owner(state).await?.is_none() {
        return Ok(true);
    }
    Ok(pinned_gateway(state).await?.is_some_and(|p| p == host.as_bytes()))
}

/// Is there a rule to judge a stored registration by — a list, or the owner's pin? Without one
/// nothing is dialled, but nothing is deleted either: the rows are kept for the rule to come.
pub(crate) async fn gateway_rule_exists(state: &AppState) -> Result<bool, ApiError> {
    Ok(state.waker.policy.allowed_hosts.is_some() || pinned_gateway(state).await?.is_some())
}

async fn pin_gateway(state: &AppState, host: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, $3) ON CONFLICT(name) DO NOTHING")
        .bind(PINNED_GATEWAY)
        .bind(host.as_bytes())
        .bind(now_ms())
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Registration-time check: [`gateway_allowed`], plus the one way a pin comes to exist — the
/// owner registering while there is neither a list nor a pin.
async fn check_pinned_gateway(state: &AppState, user_id: &str, gateway: &str) -> Result<(), ApiError> {
    if gateway_allowed(state, gateway).await? {
        return Ok(());
    }
    let unpinned = state.waker.policy.allowed_hosts.is_none() && pinned_gateway(state).await?.is_none();
    if unpinned && crate::structure::instance_owner(state).await?.as_deref() == Some(user_id) {
        return pin_gateway(state, crate::gateway::gateway_host(gateway)).await;
    }
    Err(ApiError::BadRequest(if unpinned { "this skwod has not chosen a push gateway yet" } else { "this skwod does not use that push gateway" }))
}

/// At startup: bring stored registrations in line with today's gateway rule. With neither a
/// list nor a pin, the owner's existing registration (made before pins existed) becomes the
/// pin, so an upgrade does not silence a skwod whose owner already uses push. Then, IF there is
/// a rule (a list or a pin), every registration naming a gateway it excludes is deleted — those
/// devices simply register again, and are told no if their host is not the one. With no rule
/// yet, nothing is deleted (and nothing is dialled). Returns how many went.
pub async fn enforce_gateway_policy(state: &AppState) -> Result<u64, ApiError> {
    if state.waker.policy.allowed_hosts.is_none() && pinned_gateway(state).await?.is_none() {
        if let Some(owner) = crate::structure::instance_owner(state).await? {
            let theirs: Option<String> = sqlx::query_scalar("SELECT gateway FROM push_registrations WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 1").bind(&owner).fetch_optional(&state.db).await?;
            if let Some(gateway) = theirs {
                pin_gateway(state, crate::gateway::gateway_host(&gateway)).await?;
            }
        }
    }
    if !gateway_rule_exists(state).await? {
        return Ok(0);
    }
    let gateways: Vec<String> = sqlx::query_scalar("SELECT DISTINCT gateway FROM push_registrations").fetch_all(&state.db).await?;
    let mut removed = 0;
    for gateway in gateways {
        if !gateway_allowed(state, &gateway).await? {
            removed += sqlx::query("DELETE FROM push_registrations WHERE gateway = $1").bind(&gateway).execute(&state.db).await?.rows_affected();
        }
    }
    Ok(removed)
}

fn valid_wake_tag(t: &str) -> bool {
    (16..=32).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// An APNs device token as hex. 32 bytes today; Apple says not to assume a length.
fn valid_push_token(t: &str) -> bool {
    (64..=200).contains(&t.len()) && t.len().is_multiple_of(2) && t.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_topic(t: &str) -> bool {
    (1..=155).contains(&t.len())
        && t.as_bytes()[0].is_ascii_alphanumeric()
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

fn bearer_hash(headers: &axum::http::HeaderMap) -> Result<Vec<u8>, ApiError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(crate::auth::token_hash)
        .ok_or(ApiError::Unauthorized)
}

async fn register_token(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterToken>,
) -> Result<Json<Value>, ApiError> {
    match req.provider.as_deref() {
        Some("gateway") => return register_gateway(&state, &auth, &headers, req).await,
        Some(_) => return Err(ApiError::BadRequest("unknown push provider")),
        None => {}
    }
    let (Some(token), Some(platform)) = (req.token, req.platform) else {
        return Err(ApiError::BadRequest("token and platform are required"));
    };
    let req = LegacyToken { token, platform };
    if !matches!(req.platform.as_str(), "ios" | "macos" | "android") {
        return Err(ApiError::BadRequest("platform must be ios, macos, or android"));
    }
    state.limiter.check(&format!("push_register:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    // An Apple token ends up in a URL path (`apns.rs`), so it is stored in one spelling.
    let token = if req.platform == "android" { req.token } else { req.token.to_ascii_lowercase() };
    if !valid_direct_token(&token, &req.platform) {
        return Err(ApiError::BadRequest("token is not a push token for that platform"));
    }
    // A device token is globally unique. Re-registration is idempotent for the SAME user, but a
    // conflict on a token already bound to a DIFFERENT user is a no-op (the `WHERE` fails) — so an
    // attacker who learns a victim's token can't hijack/detach the victim's push binding by
    // registering it to their own account. The legitimate device keeps ownership; a genuinely new
    // install has a fresh token and inserts cleanly.
    //
    // The row belongs to the SESSION that registered it (migration 0017): logout, expiry, a
    // removed device and a password change end it with the session, by cascade.
    sqlx::query(
        "INSERT INTO push_tokens (id, user_id, token, platform, created_at, session_hash) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (token) DO UPDATE SET platform = excluded.platform, session_hash = excluded.session_hash, created_at = excluded.created_at
         WHERE push_tokens.user_id = excluded.user_id",
    )
    .bind(new_id())
    .bind(&auth.user_id)
    .bind(&token)
    .bind(&req.platform)
    .bind(now_ms())
    .bind(&auth.session_hash)
    .execute(&state.db)
    .await?;
    // A handful per account (an account has at most five devices): the oldest go. Every
    // message loads these rows for every recipient, so the number is not the member's to pick.
    sqlx::query(
        "DELETE FROM push_tokens WHERE user_id = $1 AND id NOT IN
           (SELECT id FROM push_tokens WHERE user_id = $2 ORDER BY created_at DESC, id DESC LIMIT 8)",
    )
    .bind(&auth.user_id)
    .bind(&auth.user_id)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true })))
}

/// A token for the direct route, by platform. Apple: lowercase hex ([`valid_push_token`]) —
/// it is put into the path of the request to Apple, so nothing else may ever get through.
/// FCM: a registration token (URL-safe base64 and `:`), bounded.
pub(crate) fn valid_direct_token(token: &str, platform: &str) -> bool {
    match platform {
        "ios" | "macos" => valid_push_token(token) && !token.bytes().any(|b| b.is_ascii_uppercase()),
        "android" => (32..=512).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':')),
        _ => false,
    }
}

struct LegacyToken {
    token: String,
    platform: String,
}

/// Blind-gateway registration: one per session (= per signed-in install). The gateway URL is
/// client input and is treated as hostile — see `gateway::validate_gateway_url`.
async fn register_gateway(state: &AppState, auth: &AuthUser, headers: &axum::http::HeaderMap, req: RegisterToken) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("push_register:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    let gateway = req.gateway.as_deref().ok_or(ApiError::BadRequest("gateway is required"))?;
    let gateway = crate::gateway::validate_gateway_url(gateway, &state.waker.policy).map_err(ApiError::BadRequest)?;
    check_pinned_gateway(state, &auth.user_id, &gateway).await?;
    if req.device_id.as_deref().is_some_and(|d| d.is_empty() || d.len() > 64) {
        return Err(ApiError::BadRequest("device_id"));
    }
    // The device the SESSION speaks for is the registration's device, whatever the body says
    // (and when it says nothing — the raw shape of builds <= 45 never did): removing a device
    // then removes exactly its registrations.
    let mut req = req;
    if auth.device_id.is_some() {
        req.device_id = auth.device_id.clone();
    }
    if let Some(credential) = req.wake_credential.as_deref() {
        return register_credential(state, auth, headers, &gateway, credential, &req).await;
    }
    let apns_token = req.apns_token.as_deref().map(str::to_ascii_lowercase).filter(|t| valid_push_token(t)).ok_or(ApiError::BadRequest("apns_token must be hex"))?;
    let voip_token = match req.voip_token.as_deref().map(str::to_ascii_lowercase) {
        Some(t) if valid_push_token(&t) => Some(t),
        Some(_) => return Err(ApiError::BadRequest("voip_token must be hex or null")),
        None => None,
    };
    let topic = req.topic.as_deref().filter(|t| valid_topic(t)).ok_or(ApiError::BadRequest("topic must be a bundle id"))?;
    if req.wake_tag.as_deref().is_some_and(|t| !valid_wake_tag(t)) {
        return Err(ApiError::BadRequest("wake_tag must be 16-32 characters of A-Z a-z 0-9 _ -"));
    }
    let session_hash = bearer_hash(headers)?;
    let now = now_ms();
    // A push token belongs to one account at a time. If another account already holds either
    // token (in either slot), refuse: otherwise that account's activity would wake this device
    // (or the reverse), linking the two accounts in time at the gateway and letting one drive
    // the other's notifications. The first holder keeps it; a stale row (a sign-out that never
    // reached the server) ends with its session.
    let mut tokens = vec![apns_token.clone()];
    tokens.extend(voip_token.clone());
    for t in &tokens {
        let taken: Option<i64> = sqlx::query_scalar("SELECT 1 FROM push_registrations WHERE user_id <> $1 AND (apns_token = $2 OR voip_token = $2) LIMIT 1")
            .bind(&auth.user_id)
            .bind(t)
            .fetch_optional(&state.db)
            .await?;
        if taken.is_some() {
            return Err(ApiError::Conflict("push token is registered to another account"));
        }
        // The same account signing in again on the same device: its older row is superseded.
        sqlx::query("DELETE FROM push_registrations WHERE user_id = $1 AND session_hash <> $2 AND (apns_token = $3 OR voip_token = $3)")
            .bind(&auth.user_id)
            .bind(&session_hash)
            .bind(t)
            .execute(&state.db)
            .await?;
    }
    sqlx::query(
        "INSERT INTO push_registrations (id, user_id, session_hash, device_id, gateway, apns_token, voip_token, topic, created_at, updated_at, wake_tag)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10)
         ON CONFLICT (session_hash) DO UPDATE SET device_id = excluded.device_id, gateway = excluded.gateway,
           apns_token = excluded.apns_token, voip_token = excluded.voip_token, topic = excluded.topic, updated_at = excluded.updated_at,
           wake_tag = excluded.wake_tag, wake_credential = NULL",
    )
    .bind(new_id())
    .bind(&auth.user_id)
    .bind(&session_hash)
    .bind(&req.device_id)
    .bind(&gateway)
    .bind(&apns_token)
    .bind(&voip_token)
    .bind(topic)
    .bind(now)
    .bind(&req.wake_tag)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true, "wake_credentials": true })))
}

/// Capability registration: the row holds the credential and no token. What the raw path's
/// "this token belongs to another account" check did is done on the credential itself — one
/// credential, one account — and the gateway budgets each credential separately, so two
/// accounts can no longer share a wake schedule through a registration either.
async fn register_credential(state: &AppState, auth: &AuthUser, headers: &axum::http::HeaderMap, gateway: &str, credential: &str, req: &RegisterToken) -> Result<Json<Value>, ApiError> {
    if !valid_wake_credential(credential) {
        return Err(ApiError::BadRequest("wake_credential"));
    }
    // The whole point is that the tokens stay on the device: a request carrying both is a
    // client bug, and is refused rather than quietly stored.
    if req.apns_token.is_some() || req.voip_token.is_some() || req.topic.is_some() || req.wake_tag.is_some() {
        return Err(ApiError::BadRequest("send wake_credential without apns_token, voip_token, topic or wake_tag"));
    }
    let session_hash = bearer_hash(headers)?;
    let now = now_ms();
    let taken: Option<i64> = sqlx::query_scalar("SELECT 1 FROM push_registrations WHERE user_id <> $1 AND wake_credential = $2 LIMIT 1")
        .bind(&auth.user_id)
        .bind(credential)
        .fetch_optional(&state.db)
        .await?;
    if taken.is_some() {
        return Err(ApiError::Conflict("push credential is registered to another account"));
    }
    sqlx::query("DELETE FROM push_registrations WHERE user_id = $1 AND session_hash <> $2 AND wake_credential = $3")
        .bind(&auth.user_id)
        .bind(&session_hash)
        .bind(credential)
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO push_registrations (id, user_id, session_hash, device_id, gateway, apns_token, voip_token, topic, created_at, updated_at, wake_tag, wake_credential)
         VALUES ($1, $2, $3, $4, $5, '', NULL, '', $6, $6, NULL, $7)
         ON CONFLICT (session_hash) DO UPDATE SET device_id = excluded.device_id, gateway = excluded.gateway,
           apns_token = '', voip_token = NULL, topic = '', updated_at = excluded.updated_at,
           wake_tag = NULL, wake_credential = excluded.wake_credential",
    )
    .bind(new_id())
    .bind(&auth.user_id)
    .bind(&session_hash)
    .bind(&req.device_id)
    .bind(gateway)
    .bind(now)
    .bind(credential)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true, "wake_credentials": true })))
}

/// Device removal: drop the gateway registration(s) of that device — the rows that name it,
/// and the rows of the sessions that speak for it (those sessions are deleted next, and their
/// rows would go by cascade anyway). A registration that names no device and whose session is
/// bound to none is NOT that device's as far as anyone can tell, and stays: deleting it only
/// silenced the account's OTHER phones until they were next opened, while the install behind
/// it keeps its session either way and could simply register again.
pub(crate) async fn forget_device(tx: &mut sqlx::Transaction<'_, sqlx::Any>, user_id: &str, device_id: &str) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM push_registrations WHERE user_id = $1 AND (device_id = $2
           OR session_hash IN (SELECT token_hash FROM sessions WHERE user_id = $3 AND device_id = $4))",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(user_id)
    .bind(device_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `{ "token": "<token>" }` removes that token (either mode); an empty object removes this
/// session's gateway registration.
#[derive(Deserialize)]
pub struct UnregisterToken {
    pub token: Option<String>,
}

async fn unregister_token(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<UnregisterToken>,
) -> Result<Json<Value>, ApiError> {
    match req.token {
        Some(token) => {
            sqlx::query("DELETE FROM push_tokens WHERE token = $1 AND user_id = $2").bind(&token).bind(&auth.user_id).execute(&state.db).await?;
            sqlx::query("DELETE FROM push_registrations WHERE user_id = $1 AND (apns_token = $2 OR voip_token = $2)")
                .bind(&auth.user_id)
                .bind(token.to_ascii_lowercase())
                .execute(&state.db)
                .await?;
        }
        None => {
            sqlx::query("DELETE FROM push_registrations WHERE session_hash = $1").bind(bearer_hash(&headers)?).execute(&state.db).await?;
        }
    }
    Ok(Json(json!({ "success": true })))
}

/// A data-only push wakeup. Deliberately carries NO message content — only enough routing for the
/// device to fetch + decrypt the referenced message.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PushWakeup {
    pub token: String,
    pub platform: String,
    pub scope: String,
    pub message_id: String,
}

/// Build data-only wakeups for everyone who should be notified of a new message in `scope`,
/// excluding the author. `recipients` is the set of user ids eligible (channel members or DM
/// participants — resolved by the caller). Returns one wakeup per registered device token.
pub async fn build_wakeups(
    state: &AppState,
    scope: &str,
    message_id: &str,
    author_id: &str,
    recipients: &[String],
) -> Result<Vec<PushWakeup>, ApiError> {
    let mut wakeups = Vec::new();
    for user_id in recipients {
        if user_id == author_id {
            continue;
        }
        // Only tokens of a session that is still signed in (a row from before rows were tied
        // to sessions has none and is never used), a bounded number, and nothing that would
        // not pass today's registration check — the token goes into a URL path.
        let tokens: Vec<(String, String)> = sqlx::query_as(
            "SELECT t.token, t.platform FROM push_tokens t JOIN sessions s ON s.token_hash = t.session_hash
             WHERE t.user_id = $1 AND s.expires_at > $2 ORDER BY t.created_at DESC LIMIT 8",
        )
        .bind(user_id)
        .bind(now_ms())
        .fetch_all(&state.db)
        .await?;
        for (token, platform) in tokens {
            if !valid_direct_token(&token, &platform) {
                continue;
            }
            wakeups.push(PushWakeup {
                token,
                platform,
                scope: scope.to_string(),
                message_id: message_id.to_string(),
            });
        }
    }
    Ok(wakeups)
}

/// Who is woken for a message in a channel: the members who may READ that channel right now.
/// A member without access to a private channel is not woken for it — the wake would tell
/// them (and the gateway) when it is active. A member whose permissions cannot be worked out
/// is left out. Mutes are the device's business: the server is not told about them.
pub async fn channel_recipients(state: &AppState, channel_id: &str) -> Result<Vec<String>, ApiError> {
    let members: Vec<(String, String)> = sqlx::query_as(
        "SELECT m.user_id, c.server_id FROM server_members m JOIN channels c ON c.server_id = m.server_id WHERE c.id = $1",
    )
    .bind(channel_id)
    .fetch_all(&state.db)
    .await?;
    let mut readers = Vec::with_capacity(members.len());
    for (user_id, server_id) in members {
        let p = crate::structure::effective_permissions(state, &server_id, &user_id, Some(channel_id)).await;
        if p.is_ok_and(|p| crate::perms::has_permission(p, crate::perms::READ_MESSAGES)) {
            readers.push(user_id);
        }
    }
    Ok(readers)
}

/// `recipients` without everyone who has blocked `author_id`: their devices would drop the
/// message anyway, and until this a blocked member could still make a blocker's phone wake.
/// (Only that direction — leaving out the people the AUTHOR blocked would be no use to them.)
pub async fn without_blockers(state: &AppState, author_id: &str, recipients: Vec<String>) -> Result<Vec<String>, ApiError> {
    let blockers: Vec<String> = sqlx::query_scalar("SELECT blocker_id FROM user_blocks WHERE blocked_id = $1").bind(author_id).fetch_all(&state.db).await?;
    Ok(recipients.into_iter().filter(|u| !blockers.contains(u)).collect())
}

pub async fn dm_recipients(state: &AppState, conversation_id: &str) -> Result<Vec<String>, ApiError> {
    Ok(sqlx::query_scalar("SELECT user_id FROM dm_participants WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_all(&state.db)
        .await?)
}
