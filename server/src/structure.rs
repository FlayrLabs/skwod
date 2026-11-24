//! Server/channel/role/member/invite metadata CRUD.
//!
//! The server governs STRUCTURE (who is in what, who may do what) — names/topics are ciphertext
//! blobs it stores but cannot read. Rules ported from the original RLS/triggers/RPCs:
//! owner is immutable (no transfer endpoint exists), the @everyone role is `is_default` and
//! applies to every member, invites are 8-char codes with expiry/max-use, `accept_invite` is
//! atomic, and the owner cannot be kicked or leave (delete the server instead).

#![allow(clippy::type_complexity)]

use axum::extract::{Path, State};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::Rng;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::perms::{self, Override};
use crate::state::{new_id, now_ms, AppState};

pub fn routes() -> Router<AppState> {
    use axum::routing::{delete, get, post, put};
    Router::new()
        .route("/servers", post(create_server).get(list_servers))
        .route("/servers/:server_id", axum::routing::patch(update_server).delete(delete_server))
        .route("/servers/:server_id/categories", post(create_category))
        .route("/servers/:server_id/channels", post(create_channel).get(list_channels))
        .route("/channels/:channel_id", axum::routing::patch(update_channel).delete(delete_channel))
        .route("/channels/:channel_id/overrides", put(put_override))
        .route("/servers/:server_id/roles", post(create_role).get(list_roles))
        .route("/roles/:role_id", axum::routing::patch(update_role).delete(delete_role))
        .route("/servers/:server_id/members", get(list_members))
        .route("/profiles/me/status", put(set_status))
        .route("/servers/:server_id/members/:user_id", delete(kick_member))
        .route("/servers/:server_id/bans", get(list_bans))
        .route("/servers/:server_id/bans/:user_id", post(ban_member).delete(unban_member))
        .route("/servers/:server_id/members/:user_id/roles/:role_id", put(assign_role).delete(remove_role))
        .route("/servers/:server_id/invites", post(create_invite).get(list_invites))
        .route("/invites/:code", delete(revoke_invite))
        .route("/invites/:code/accept", post(accept_invite))
        .route("/invites/:code/check", get(check_invite))
        .route("/servers/:server_id/member-approvals", get(list_member_approvals).post(put_member_approval))
        .route("/servers/:server_id/owner-attestation", get(owner_attestation))
        .route("/servers/:server_id/join-requests", get(list_join_requests))
        .route("/servers/:server_id/join-requests/:user_id/approve", post(approve_join_request))
        .route("/servers/:server_id/join-requests/:user_id/deny", post(deny_join_request))
        .route("/servers/:server_id/purge", post(purge_messages))
        .route("/servers/:server_id/clear", post(clear_server))
        .route("/users/lookup", get(lookup_user))
        // Instance-level "who may create servers" grant (host-only, delegatable).
        .route("/instance/can-create-servers", get(can_create_servers_me))
        .route("/instance/server-creators", get(list_server_creators))
        .route("/instance/server-creators/:user_id", put(grant_server_creator).delete(revoke_server_creator))
        // Instance identity + proof-of-possession — UNAUTHENTICATED so a client can pin/verify the
        // server BEFORE sending its token. Lets a moved skwod be recognized as the same one.
        .route("/instance/identity", get(instance_identity))
        .route("/instance/name", get(get_instance_name).put(set_instance_name))
        .route("/instance/prove", post(instance_prove))
        .route("/instance/address-record", get(address_record))
        .route("/instance/owner-attestation", get(instance_owner_attestation))
}

/// Domain-separation tag so an instance-proof signature can NEVER collide with a sender-certificate
/// signature (both use the same Ed25519 key) — otherwise `/prove` would be a certificate-forging
/// signing oracle. The signed message is always `PROOF_TAG || nonce`.
const PROOF_TAG: &[u8] = b"skwod-instance-proof-v1:";

/// The instance's stable identity: its Ed25519 signing public key (unique per instance, survives
/// address changes) plus a short opaque `instance_id` (its hash) for quick matching/display.
/// The skwod's display name, set by its owner (build 46). Members read it signed in (a name is
/// not public: `/instance/identity` is fetched before log-in and stays name-free). `null` until
/// the owner sets one. It is a LABEL: clients clean it, refuse look-alikes of their other
/// skwods' names and always show the host key beside it.
async fn get_instance_name(State(state): State<AppState>, _auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let raw: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'instance_name'")
        .fetch_optional(&state.db)
        .await?;
    Ok(Json(json!({ "name": raw.and_then(|v| String::from_utf8(v).ok()) })))
}

/// Longest skwod name, in characters.
pub(crate) const INSTANCE_NAME_MAX: usize = 64;

/// A name the server will keep: trimmed, 1–64 characters, no control, format (bidi, zero-width)
/// or line-separator characters. `Ok(None)` = clear it.
pub(crate) fn clean_instance_name(raw: &str) -> Result<Option<String>, ApiError> {
    let name = raw.trim();
    if name.is_empty() {
        return Ok(None);
    }
    let hidden = |c: char| {
        c.is_control()
            || matches!(c as u32, 0x00AD | 0x061C | 0x180E | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x206F | 0xFEFF | 0xFFF9..=0xFFFB)
    };
    if name.chars().count() > INSTANCE_NAME_MAX || name.chars().any(hidden) {
        return Err(ApiError::BadRequest("a skwod name is 1-64 characters with no control or invisible characters"));
    }
    Ok(Some(name.to_string()))
}

#[derive(Deserialize)]
struct InstanceNameReq {
    #[serde(default)]
    name: String,
}

/// Owner only, signed by a device like the other instance-wide owner operations (op
/// `instance-name`, payload: the name's bytes as sent). An empty name clears it.
async fn set_instance_name(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<InstanceNameReq>,
) -> Result<Json<Value>, ApiError> {
    require_instance_owner(&state, &auth.user_id).await?;
    let cleaned = clean_instance_name(&req.name)?;
    crate::keydir::destructive_authority(&state, &auth, &headers, "instance-name", "", req.name.as_bytes()).await?;
    match &cleaned {
        Some(name) => {
            sqlx::query(
                "INSERT INTO instance_secrets (name, value, created_at) VALUES ('instance_name', $1, $2)
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value, created_at = excluded.created_at",
            )
            .bind(name.as_bytes())
            .bind(now_ms())
            .execute(&state.db)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM instance_secrets WHERE name = 'instance_name'").execute(&state.db).await?;
        }
    }
    Ok(Json(json!({ "name": cleaned })))
}

async fn instance_identity(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (_secret, public) = crate::keydir::server_signing_key(&state).await?;
    use sha2::{Digest, Sha256};
    let id = hex::encode(&Sha256::digest(&public)[..16]);
    // `e2ee_protocol` lets a client tell "this server predates libsignal" (field absent) from a
    // compatible one BEFORE it registers a device.
    Ok(Json(json!({ "instance_id": id, "server_public": B64.encode(&public), "e2ee_protocol": skwod_crypto::PROTOCOL_VERSION })))
}

#[derive(Deserialize)]
struct ProveReq {
    /// Client-chosen random nonce (base64). The server signs it to prove it holds the private key.
    nonce: String,
    /// The address the client dialed (`https://host[:port]`, or `skwod-p2p:<node id>`). When
    /// present the proof is bound to it — and refused unless this instance serves that address.
    #[serde(default)]
    origin: Option<String>,
}

/// The addresses this instance is served at, for origin-bound proofs: every entry of
/// `SKWOD_PUBLIC_URL` (comma-separated), the `domain` that `skwod init` wrote to
/// `<data>/config.toml`, and the p2p node id. Deliberately NOT derived from the request's `Host`
/// header: whoever relays a challenge to us chooses that header.
pub(crate) fn served_origins(state: &AppState) -> Vec<String> {
    let mut out = public_https_origins(state);
    if let Some(p2p) = state.p2p.get() {
        out.push(skwod_crypto::instance::p2p_origin(&p2p.node_id));
    }
    out
}

/// The public `https://` origins of this instance, most authoritative first.
pub(crate) fn public_https_origins(state: &AppState) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |raw: &str| {
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        let url = if raw.contains("://") { raw.to_string() } else { format!("https://{raw}") };
        if let Some(o) = skwod_crypto::instance::normalize_origin(&url) {
            if o.starts_with("https://") && !skwod_crypto::instance::is_loopback_origin(&o) && !out.contains(&o) {
                out.push(o);
            }
        }
    };
    state.public_urls.iter().for_each(|u| push(u));
    if let Some(domain) = configured_domain(state) {
        // `skwod init` defaults to `localhost:3000` when no domain was given: not a public origin.
        if !domain.starts_with("localhost") && !domain.contains(':') {
            push(&domain);
        }
    }
    out
}

fn configured_domain(state: &AppState) -> Option<String> {
    let text = std::fs::read_to_string(state.blob_dir.parent()?.join("config.toml")).ok()?;
    text.lines().find_map(|l| {
        let v = l.trim().strip_prefix("domain")?.trim_start().strip_prefix('=')?.trim();
        Some(v.trim_matches('"').to_string()).filter(|d| !d.is_empty())
    })
}

/// Sign a client nonce with the instance signing key — proof the server actually HOLDS the private
/// key matching the pinned public key (not just presenting a copy).
///
/// With an `origin` (every current client sends one) the signature covers
/// `PROOF_TAG_V2 ‖ len ‖ nonce ‖ origin` and is only produced for an address this instance
/// serves. Without that binding the proof is relayable: an impostor at another address forwards
/// the client's nonce here and hands back our signature, "proving" a key it does not hold — and
/// the client then follows it and sends its session token. The unbound v1 form (`PROOF_TAG ‖
/// nonce`) is still answered for build-42 clients; current clients never accept it.
async fn instance_prove(
    State(state): State<AppState>,
    peer: Option<axum::Extension<crate::client_key::P2pPeer>>,
    tcp: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProveReq>,
) -> Result<Json<Value>, ApiError> {
    let nonce = B64.decode(req.nonce.as_bytes()).map_err(|_| ApiError::BadRequest("bad nonce"))?;
    if nonce.is_empty() || nonce.len() > 128 {
        return Err(ApiError::BadRequest("nonce must be 1..=128 bytes"));
    }
    let (secret, public) = crate::keydir::server_signing_key(&state).await?;
    let msg = match req.origin.as_deref() {
        Some(origin) => {
            use skwod_crypto::instance::{is_loopback_origin, normalize_origin, proof_message_v2};
            if origin.len() > 512 {
                return Err(ApiError::BadRequest("bad origin"));
            }
            // A loopback origin is only meaningful to a client ON THIS MACHINE talking to us
            // directly, so it is signed only when the request provably is that: the socket peer
            // itself is loopback, the request came through no proxy hop (a reverse proxy on this
            // host also connects from loopback — and anything behind it could be an attacker's
            // relay claiming `http://127.0.0.1:…`), and it did not arrive over p2p. No
            // forwarded-for / trusted-proxy reasoning is applied: any forwarding header at all
            // disqualifies the request. (A dev setup that needs more lists the exact loopback
            // origin in `SKWOD_PUBLIC_URL`.)
            let canonical_loopback = normalize_origin(origin).is_some_and(|o| o == origin && is_loopback_origin(&o));
            let direct_local = peer.is_none()
                && tcp.is_some_and(|c| crate::client_key::canonical(c.0.ip()).is_loopback())
                && !["x-forwarded-for", "forwarded", "x-real-ip", "x-forwarded-host", "via"].iter().any(|h| headers.contains_key(*h));
            let listed_loopback = state.public_urls.iter().any(|u| normalize_origin(u).as_deref() == Some(origin));
            let allowed = if canonical_loopback { direct_local || listed_loopback } else { served_origins(&state).iter().any(|o| o == origin) };
            if !allowed {
                return Err(ApiError::Forbidden);
            }
            proof_message_v2(&nonce, origin).ok_or(ApiError::Internal)?
        }
        None => {
            let mut msg = Vec::with_capacity(PROOF_TAG.len() + nonce.len());
            msg.extend_from_slice(PROOF_TAG);
            msg.extend_from_slice(&nonce);
            msg
        }
    };
    let sig = sign_with_instance_key(&secret, &msg)?;
    Ok(Json(json!({ "server_public": B64.encode(&public), "signature": B64.encode(&sig) })))
}

/// The instance's signed address record: `{address, ts, signature}` — "as of `ts` this instance
/// is served at `address`", signed by the instance key. This is the ONLY way a client learns a new
/// https address for a skwod it already pinned (a moved server, or a p2p host's https fallback):
/// it accepts a record only under the pinned key and only with a newer `ts`, then still makes the
/// new address prove the key (origin-bound) before using it. `ts` is minted once per address and
/// kept, so it only moves forward when the address really changes. 404 when no public address is
/// configured (`SKWOD_PUBLIC_URL` / the init-time domain).
async fn address_record(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let address = public_https_origins(&state).into_iter().next().ok_or(ApiError::NotFound)?;
    let (secret, _public) = crate::keydir::server_signing_key(&state).await?;
    let stored: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'address_record'")
        .fetch_optional(&state.db)
        .await?;
    let stored = stored.and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let ts = match stored.as_ref().filter(|v| v["address"].as_str() == Some(address.as_str())).and_then(|v| v["ts"].as_i64()) {
        Some(ts) => ts,
        None => {
            // Strictly after any earlier record, even if the clock went backwards.
            let prev = stored.as_ref().and_then(|v| v["ts"].as_i64()).unwrap_or(0);
            let ts = now_ms().max(prev + 1);
            sqlx::query(
                "INSERT INTO instance_secrets (name, value, created_at) VALUES ('address_record', $1, $2)
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value, created_at = excluded.created_at",
            )
            .bind(json!({ "address": address, "ts": ts }).to_string().into_bytes())
            .bind(now_ms())
            .execute(&state.db)
            .await?;
            ts
        }
    };
    let sig = skwod_crypto::instance::sign_address_record(&secret, &address, ts).ok_or(ApiError::Internal)?;
    Ok(Json(json!({ "address": address, "ts": ts, "signature": B64.encode(sig) })))
}

fn sign_with_instance_key(secret: &[u8], msg: &[u8]) -> Result<Vec<u8>, ApiError> {
    skwod_crypto::instance::sign(secret, msg).ok_or(ApiError::Internal)
}

/// The instance owner (bootstrap account) as a user id, or None on an un-bootstrapped/open instance.
pub(crate) async fn instance_owner(state: &AppState) -> Result<Option<String>, ApiError> {
    let owner: Option<Vec<u8>> = sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'owner_user_id'")
        .fetch_optional(&state.db)
        .await?;
    Ok(owner.and_then(|b| String::from_utf8(b).ok()))
}

/// May `user_id` create a new server in this skwod? The instance owner always may; other accounts
/// only if the owner granted them (a row in `server_creators`). An un-bootstrapped/open instance
/// (no owner claimed) stays open so dev/test and self-host-before-init flows keep working.
async fn can_create_servers(state: &AppState, user_id: &str) -> Result<bool, ApiError> {
    match instance_owner(state).await? {
        None => Ok(true),
        Some(owner) if owner == user_id => Ok(true),
        Some(_) => {
            let row: Option<String> = sqlx::query_scalar("SELECT user_id FROM server_creators WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&state.db)
                .await?;
            Ok(row.is_some())
        }
    }
}

/// Guard for the grant-management endpoints: only the instance owner may hand out the right.
/// Also gates the abuse-report queue in `safety.rs` (same authority as `delete_user`).
pub(crate) async fn require_instance_owner(state: &AppState, user_id: &str) -> Result<(), ApiError> {
    match instance_owner(state).await? {
        Some(owner) if owner == user_id => Ok(()),
        _ => Err(ApiError::Forbidden),
    }
}

/// Does the caller have permission to create servers? Lets clients hide the "Create a server" UI.
async fn can_create_servers_me(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let can = can_create_servers(&state, &auth.user_id).await?;
    let is_owner = instance_owner(&state).await?.as_deref() == Some(auth.user_id.as_str());
    Ok(Json(json!({ "can_create": can, "is_owner": is_owner })))
}

/// Owner-only: every account granted server-creation, with usernames.
async fn list_server_creators(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    require_instance_owner(&state, &auth.user_id).await?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT p.id, p.username FROM server_creators sc JOIN profiles p ON p.id = sc.user_id ORDER BY p.username",
    )
    .fetch_all(&state.db)
    .await?;
    let creators: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, username)| json!({ "user_id": user_id, "username": username }))
        .collect();
    Ok(Json(json!({ "creators": creators })))
}

/// Owner-only: grant `user_id` the right to create servers.
async fn grant_server_creator(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_instance_owner(&state, &auth.user_id).await?;
    sqlx::query("INSERT INTO server_creators (user_id, granted_at) VALUES ($1, $2) ON CONFLICT(user_id) DO NOTHING")
        .bind(&user_id)
        .bind(now_ms())
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

/// Owner-only: revoke `user_id`'s right to create servers.
async fn revoke_server_creator(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_instance_owner(&state, &auth.user_id).await?;
    sqlx::query("DELETE FROM server_creators WHERE user_id = $1")
        .bind(&user_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

/// Username lookups per account per minute.
/// (The apps cross-check every unfamiliar name on a roster once per launch, so this is sized
/// for a large server, not for a person typing names.)
const LOOKUPS_PER_MINUTE: u32 = 120;

#[derive(Deserialize)]
pub struct LookupQuery {
    pub username: String,
}

/// Find a user by username → their id + a device id to start a DM with (public routing info only).
///
/// Only for accounts the caller already has something to do with: one that shares a server with
/// it, or one whose pending join request the caller decides on (the waiting-room check that a
/// name belongs to the account asking). Anyone else is "not found", exactly like a name nobody
/// has — the directory does not confirm that an account exists. Rate-limited, so even the
/// allowed set cannot be swept.
async fn lookup_user(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Query(q): axum::extract::Query<LookupQuery>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("lookup_user:{}", auth.user_id), LOOKUPS_PER_MINUTE, crate::limiter::MINUTE)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT id, username FROM profiles WHERE username = $1")
            .bind(q.username.to_lowercase())
            .fetch_optional(&state.db)
            .await?;
    let (user_id, username) = row.ok_or(ApiError::NotFound)?;
    if !crate::keydir::knows(&state, &auth.user_id, &user_id).await? && !crate::keydir::decides_join_of(&state, &auth.user_id, &user_id).await? {
        return Err(ApiError::NotFound);
    }
    // Most-recently-active device, NOT oldest: a re-login/backup-restore leaves dead older device
    // rows behind, and handing a joiner a dead device makes their sender-key share undecryptable
    // for this user forever (one-way channel visibility). Must match the join-outcome query.
    let device_id: Option<String> =
        sqlx::query_scalar("SELECT device_id FROM user_devices WHERE user_id = $1 ORDER BY last_active_at DESC, created_at DESC LIMIT 1")
            .bind(&user_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(Json(json!({ "user_id": user_id, "username": username, "device_id": device_id })))
}

#[derive(Deserialize)]
pub struct PurgeRequest {
    /// Delete channel messages older than this many milliseconds.
    pub older_than_ms: i64,
}

/// Retention purge (ports the original `purge_server_messages`): hard-deletes messages older
/// than the cutoff across all of a server's channels. Attachment rows cascade; their blob files
/// are removed too.
async fn purge_messages(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(server_id): Path<String>,
    Json(req): Json<PurgeRequest>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_SERVER).await?;
    if req.older_than_ms < 0 {
        return Err(ApiError::BadRequest("older_than_ms must be >= 0"));
    }
    // Irreversible: a device, not just a token (audit M-3).
    crate::keydir::destructive_authority(&state, &auth, &headers, "purge-messages", &server_id, &req.older_than_ms.to_be_bytes()).await?;
    let cutoff = now_ms() - req.older_than_ms;

    // Collect blob files of purged attachments before the rows cascade away.
    let blob_ids: Vec<String> = sqlx::query_scalar(
        "SELECT a.storage_path FROM message_attachments a
         JOIN messages m ON m.id = a.message_id
         JOIN channels c ON c.id = m.channel_id
         WHERE c.server_id = $1 AND m.created_at < $2",
    )
    .bind(&server_id)
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;

    let res = sqlx::query(
        "DELETE FROM messages WHERE created_at < $1
         AND channel_id IN (SELECT id FROM channels WHERE server_id = $2)",
    )
    .bind(cutoff)
    .bind(&server_id)
    .execute(&state.db)
    .await?;

    for blob_id in &blob_ids {
        sqlx::query("DELETE FROM blobs WHERE id = $1").bind(blob_id).execute(&state.db).await?;
        let _ = std::fs::remove_file(state.blob_dir.join(blob_id));
    }

    Ok(Json(json!({ "purged_messages": res.rows_affected(), "purged_blobs": blob_ids.len() })))
}

/// Owner/manager action: HARD-delete ALL content across a server — every channel's messages plus the
/// server's stories and feed posts — while keeping the server, its channels, members, roles, and
/// invites. Attachment/reaction/comment rows cascade; blob files, the channels' relayed sender keys,
/// and feed posts left cross-posted to no other server (none FK-cascaded here) are cleaned by hand.
/// Gated on MANAGE_SERVER, matching the retention purge.
async fn clear_server(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_SERVER).await?;
    // Irreversible: a device, not just a token (audit M-3).
    crate::keydir::destructive_authority(&state, &auth, &headers, "clear-server", &server_id, b"").await?;

    // Collect every blob file this clear will orphan: message attachments, story media, and feed
    // photos on posts that live ONLY on this server (so a cross-posted photo elsewhere is kept).
    let mut blob_ids: Vec<String> = sqlx::query_scalar(
        "SELECT a.storage_path FROM message_attachments a
         JOIN messages m ON m.id = a.message_id
         JOIN channels c ON c.id = m.channel_id
         WHERE c.server_id = $1",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    let story_blobs: Vec<String> = sqlx::query_scalar(
        "SELECT sm.storage_path FROM story_media sm
         JOIN stories s ON s.id = sm.story_id
         WHERE s.server_id = $1",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    blob_ids.extend(story_blobs);
    let feed_blobs: Vec<String> = sqlx::query_scalar(
        "SELECT fp.storage_path FROM feed_posts fp
         WHERE fp.storage_path IS NOT NULL
           AND fp.id IN (SELECT post_id FROM feed_post_servers WHERE server_id = $1)
           AND fp.id NOT IN (SELECT post_id FROM feed_post_servers WHERE server_id <> $1)",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    blob_ids.extend(feed_blobs);

    let res = sqlx::query(
        "DELETE FROM messages WHERE channel_id IN (SELECT id FROM channels WHERE server_id = $1)",
    )
    .bind(&server_id)
    .execute(&state.db)
    .await?;
    // Stories are server-scoped (story_media/story_views cascade with them).
    sqlx::query("DELETE FROM stories WHERE server_id = $1").bind(&server_id).execute(&state.db).await?;
    // Feed posts are global, linked to servers via feed_post_servers. Unlink this server, then drop
    // posts no longer shown on any server (comments/likes cascade with the post).
    sqlx::query("DELETE FROM feed_post_servers WHERE server_id = $1").bind(&server_id).execute(&state.db).await?;
    sqlx::query("DELETE FROM feed_posts WHERE id NOT IN (SELECT post_id FROM feed_post_servers)")
        .execute(&state.db)
        .await?;

    for blob_id in &blob_ids {
        sqlx::query("DELETE FROM blobs WHERE id = $1").bind(blob_id).execute(&state.db).await?;
        let _ = std::fs::remove_file(state.blob_dir.join(blob_id));
    }

    // Nudge every open client on this server to reload the (now empty) channels.
    let channels: Vec<String> = sqlx::query_scalar("SELECT id FROM channels WHERE server_id = $1")
        .bind(&server_id)
        .fetch_all(&state.db)
        .await?;
    let cleared_at = crate::state::now_ms();
    sqlx::query("UPDATE channels SET cleared_at = $1 WHERE server_id = $2").bind(cleared_at).bind(&server_id).execute(&state.db).await?;
    for ch in &channels {
        state.rt.publish(&crate::rt::channel_topic(ch), "channel_cleared", json!({ "channel_id": ch, "cleared_at": cleared_at }));
    }

    Ok(Json(json!({ "cleared_messages": res.rows_affected(), "cleared_blobs": blob_ids.len() })))
}

// ---- permission resolution ----

/// Effective permission mask for `user_id` in `server_id` (optionally within a channel).
/// Errors `Forbidden` if the user isn't a member at all.
pub async fn effective_permissions(
    state: &AppState,
    server_id: &str,
    user_id: &str,
    channel_id: Option<&str>,
) -> Result<i64, ApiError> {
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_optional(&state.db)
        .await?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    if owner == user_id {
        return Ok(perms::ALL_PERMISSIONS);
    }

    let member_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM server_members WHERE server_id = $1 AND user_id = $2")
            .bind(server_id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    let member_id = member_id.ok_or(ApiError::Forbidden)?;

    // @everyone (is_default) + explicitly assigned roles.
    let role_perms: Vec<i64> = sqlx::query_scalar(
        "SELECT permissions FROM roles
         WHERE server_id = $1 AND (is_default = 1
            OR id IN (SELECT role_id FROM member_roles WHERE server_member_id = $2))",
    )
    .bind(server_id)
    .bind(&member_id)
    .fetch_all(&state.db)
    .await?;

    let overrides = match channel_id {
        None => Vec::new(),
        Some(ch) => {
            // Role overrides (default first, then by role position), then the user-specific one —
            // the original applied them in array order with deny-then-allow.
            let rows: Vec<(i64, i64)> = sqlx::query_as(
                "SELECT o.allow, o.deny FROM channel_permission_overrides o
                 JOIN roles r ON r.id = o.role_id
                 WHERE o.channel_id = $1 AND (r.is_default = 1
                    OR o.role_id IN (SELECT role_id FROM member_roles WHERE server_member_id = $2))
                 ORDER BY r.is_default DESC, r.position",
            )
            .bind(ch)
            .bind(&member_id)
            .fetch_all(&state.db)
            .await?;
            let mut v: Vec<Override> = rows.into_iter().map(|(allow, deny)| Override { allow, deny }).collect();
            let user_override: Option<(i64, i64)> = sqlx::query_as(
                "SELECT allow, deny FROM channel_permission_overrides WHERE channel_id = $1 AND user_id = $2",
            )
            .bind(ch)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
            if let Some((allow, deny)) = user_override {
                v.push(Override { allow, deny });
            }
            v
        }
    };

    Ok(perms::compute_permissions(false, &role_perms, &overrides))
}

/// Require a permission in a server context, resolving the channel's server automatically.
pub async fn require_permission(
    state: &AppState,
    server_id: &str,
    user_id: &str,
    permission: i64,
) -> Result<(), ApiError> {
    let p = effective_permissions(state, server_id, user_id, None).await?;
    if perms::has_permission(p, permission) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// The set of permission bits `user_id` is allowed to GRANT to others — you can never hand out a
/// permission you don't hold yourself (the "permission ceiling" that stops a MANAGE_ROLES member
/// from minting an ADMINISTRATOR role and self-assigning it). Administrators/owner can grant
/// anything; everyone else is capped at their own effective permissions.
pub async fn grantable_permissions(state: &AppState, server_id: &str, user_id: &str) -> Result<i64, ApiError> {
    let p = effective_permissions(state, server_id, user_id, None).await?;
    Ok(if perms::has_permission(p, perms::ADMINISTRATOR) { perms::ALL_PERMISSIONS } else { p })
}

/// Reject an attempt to grant `bits` beyond what `user_id` may grant.
async fn require_grantable(state: &AppState, server_id: &str, user_id: &str, bits: i64) -> Result<(), ApiError> {
    let ceiling = grantable_permissions(state, server_id, user_id).await?;
    if bits & !ceiling != 0 {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// The owner's rank: above everyone, administrators included.
const OWNER_RANK: i64 = i64::MAX;
/// An administrator's rank: above every role position, below the owner. (Both used to be
/// `i64::MAX`, and since acting on someone needs a STRICTLY higher rank the owner could not
/// kick, ban or demote an administrator.) Two administrators are equals: neither acts on the other.
const ADMIN_RANK: i64 = i64::MAX - 1;

/// A member's rank = the highest `position` among their roles (position-based hierarchy). The owner
/// outranks everyone ([`OWNER_RANK`]); an administrator outranks everyone but the owner
/// ([`ADMIN_RANK`]). A member with no non-default role ranks 0.
/// Rank gates who you can ACT ON: you can only kick / edit / demote a member or role strictly below
/// your own rank — without this a `MANAGE_ROLES` mod could strip an admin, and `KICK_MEMBERS` could
/// kick admins. (`require_grantable` already stops *gaining* power; this stops *acting upward*.)
async fn member_rank(state: &AppState, server_id: &str, user_id: &str) -> Result<i64, ApiError> {
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_optional(&state.db)
        .await?;
    if owner.as_deref() == Some(user_id) {
        return Ok(OWNER_RANK);
    }
    let p = effective_permissions(state, server_id, user_id, None).await?;
    if perms::has_permission(p, perms::ADMINISTRATOR) {
        return Ok(ADMIN_RANK);
    }
    let rank: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(r.position) FROM roles r
         JOIN member_roles mr ON mr.role_id = r.id
         JOIN server_members sm ON sm.id = mr.server_member_id
         WHERE sm.server_id = $1 AND sm.user_id = $2 AND r.is_default = 0",
    )
    .bind(server_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .flatten();
    Ok(rank.unwrap_or(0))
}

/// The `position` of a role (0 for the default/@everyone role).
async fn role_rank(state: &AppState, role_id: &str) -> Result<i64, ApiError> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT position, is_default FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_optional(&state.db)
            .await?;
    let (position, is_default) = row.ok_or(ApiError::NotFound)?;
    Ok(if is_default == 1 { 0 } else { position })
}

/// Require that `actor` outranks the `target` member — else Forbidden. The owner passes for
/// everyone else; an administrator passes for everyone but the owner and other administrators.
async fn require_outranks_member(state: &AppState, server_id: &str, actor: &str, target: &str) -> Result<(), ApiError> {
    if member_rank(state, server_id, actor).await? <= member_rank(state, server_id, target).await? {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// Require that `actor` outranks `role_id` — you can't edit/assign/remove a role at or above your rank.
async fn require_outranks_role(state: &AppState, server_id: &str, actor: &str, role_id: &str) -> Result<(), ApiError> {
    if member_rank(state, server_id, actor).await? <= role_rank(state, role_id).await? {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// Require that a role `position` is strictly below `actor`'s rank (and not negative). The owner
/// and administrators may use any position below [`ADMIN_RANK`] (so no role ever ranks with them).
async fn require_position_below(state: &AppState, server_id: &str, actor: &str, position: i64) -> Result<(), ApiError> {
    if position < 0 {
        return Err(ApiError::BadRequest("position must not be negative"));
    }
    if position >= ADMIN_RANK.min(member_rank(state, server_id, actor).await?) {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// Is `user_id` currently a member of `server_id`?
pub(crate) async fn is_server_member(state: &AppState, server_id: &str, user_id: &str) -> Result<bool, ApiError> {
    let row: Option<String> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(server_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.is_some())
}

// ---- signed member approvals (ADR-012 interim) ----

/// A removed member's approvals — the ones naming them and the ones they issued — go with them.
/// (Clients additionally refuse an approval older than the removal they observed, so a server
/// that keeps and replays one gains nothing.)
async fn forget_member_approvals(state: &AppState, server_id: &str, user_id: &str) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM member_approvals WHERE server_id = $1 AND (user_id = $2 OR approver_user_id = $3)")
        .bind(server_id)
        .bind(user_id)
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

#[derive(Deserialize)]
struct MemberApproval {
    user_id: String,
    approver_device_id: String,
    ts: i64,
    signature: String,
}

/// Publish a member approval: the caller's device signed "`user_id` is a member of this server
/// as of `ts`". The server checks only that it is well-formed and really signed by a device of
/// the caller (so the table cannot be filled with junk); whether the approver is someone whose
/// word counts is decided by each CLIENT, against the identities it has verified.
async fn put_member_approval(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
    Json(req): Json<MemberApproval>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("member_approval:{}", auth.user_id), 120, crate::limiter::HOUR)?;
    if !is_server_member(&state, &server_id, &auth.user_id).await? {
        return Err(ApiError::Forbidden);
    }
    if req.user_id == auth.user_id || !is_server_member(&state, &server_id, &req.user_id).await? {
        return Err(ApiError::BadRequest("not a member of this server"));
    }
    let signature = b64_decode(&req.signature)?;
    let identity: Option<Vec<u8>> = sqlx::query_scalar("SELECT identity_key FROM user_devices WHERE user_id = $1 AND device_id = $2")
        .bind(&auth.user_id)
        .bind(&req.approver_device_id)
        .fetch_optional(&state.db)
        .await?;
    let identity = identity.ok_or(ApiError::BadRequest("unknown approver device"))?;
    // The approval is signed by a device key; it must also come from that device's current
    // install (a copied identity key approves nobody).
    crate::keydir::require_bound_device_session(&state, &auth, &req.approver_device_id).await?;
    if (req.ts - now_ms()).abs() > 10 * 60 * 1000
        || !skwod_crypto::link::verify_member_approval(&identity, &server_id, &req.user_id, &auth.user_id, req.ts, &signature)
    {
        return Err(ApiError::BadRequest("bad approval signature"));
    }
    sqlx::query(
        "INSERT INTO member_approvals (server_id, user_id, approver_user_id, approver_device_id, ts, signature, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (server_id, user_id, approver_user_id) DO UPDATE SET
             approver_device_id = excluded.approver_device_id, ts = excluded.ts, signature = excluded.signature, created_at = excluded.created_at",
    )
    .bind(&server_id)
    .bind(&req.user_id)
    .bind(&auth.user_id)
    .bind(&req.approver_device_id)
    .bind(req.ts)
    .bind(&signature)
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    // Members' clients re-check who may hold their keys.
    state.rt.publish(&crate::rt::server_topic(&server_id), "member_approved", json!({ "user_id": req.user_id }));
    Ok(Json(json!({ "success": true })))
}

/// "This account owns this instance", signed by the instance key (any signed-in account).
/// Clients pin the first one that verifies under the instance key they pinned and accept the
/// skwod (instance) icon only from that account. 404 until ownership has been claimed.
async fn instance_owner_attestation(State(state): State<AppState>, _auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let owner = instance_owner(&state).await?.ok_or(ApiError::NotFound)?;
    let (secret, _public) = crate::keydir::server_signing_key(&state).await?;
    let sig = sign_with_instance_key(&secret, &skwod_crypto::instance::instance_owner_message(&owner))?;
    Ok(Json(json!({ "owner_id": owner, "signature": B64.encode(sig) })))
}

/// "This user owns this server", signed by the instance key (members only). A client uses it
/// solely to re-confirm an owner it had ALREADY pinned before pins carried a provenance — it is
/// the pinned server's word, so it cannot introduce or change an owner on the client.
async fn owner_attestation(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !is_server_member(&state, &server_id, &auth.user_id).await? {
        return Err(ApiError::Forbidden);
    }
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1").bind(&server_id).fetch_optional(&state.db).await?;
    let owner = owner.ok_or(ApiError::NotFound)?;
    let (secret, _public) = crate::keydir::server_signing_key(&state).await?;
    let msg = skwod_crypto::instance::owner_attestation_message(&server_id, &owner).ok_or(ApiError::Internal)?;
    let sig = sign_with_instance_key(&secret, &msg)?;
    Ok(Json(json!({ "server_id": server_id, "owner_id": owner, "signature": B64.encode(sig) })))
}

/// Every member approval on record for a server (members only).
async fn list_member_approvals(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !is_server_member(&state, &server_id, &auth.user_id).await? {
        return Err(ApiError::Forbidden);
    }
    let rows: Vec<(String, String, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT user_id, approver_user_id, approver_device_id, ts, signature FROM member_approvals WHERE server_id = $1 ORDER BY created_at",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    let approvals: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, approver_user_id, approver_device_id, ts, signature)| {
            json!({ "user_id": user_id, "approver_user_id": approver_user_id, "approver_device_id": approver_device_id, "ts": ts, "signature": B64.encode(signature) })
        })
        .collect();
    Ok(Json(json!({ "approvals": approvals })))
}

/// Look up the server owning a channel.
pub async fn channel_server(state: &AppState, channel_id: &str) -> Result<String, ApiError> {
    sqlx::query_scalar("SELECT server_id FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(s).map_err(|_| ApiError::BadRequest("invalid base64"))
}

// ---- servers ----

#[derive(Deserialize)]
pub struct CreateServer {
    pub name_ciphertext: String, // b64
    pub description_ciphertext: Option<String>,
}

/// A sealed server name, at most (a 400-byte name, its version and renamer, nonce and tag fit
/// several times over). Anything longer is not a name.
pub(crate) const MAX_NAME_CIPHERTEXT: usize = 2048;

/// A sealed server description, at most.
pub(crate) const MAX_DESCRIPTION_CIPHERTEXT: usize = 8192;

fn bounded_description(b64: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = b64_decode(b64)?;
    if bytes.len() > MAX_DESCRIPTION_CIPHERTEXT {
        return Err(ApiError::BadRequest("description_ciphertext must be at most 8192 bytes"));
    }
    Ok(bytes)
}

fn bounded_name(b64: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = b64_decode(b64)?;
    if bytes.is_empty() || bytes.len() > MAX_NAME_CIPHERTEXT {
        return Err(ApiError::BadRequest("name_ciphertext must be 1..=2048 bytes"));
    }
    Ok(bytes)
}

async fn create_server(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateServer>,
) -> Result<Json<Value>, ApiError> {
    // Host-only + grantable: the instance owner may always create; others only if granted. An
    // un-bootstrapped/open instance stays open (see `can_create_servers`).
    if !can_create_servers(&state, &auth.user_id).await? {
        return Err(ApiError::Forbidden);
    }
    let name = bounded_name(&req.name_ciphertext)?;
    let description = req.description_ciphertext.as_deref().map(bounded_description).transpose()?;
    let now = now_ms();
    let server_id = new_id();

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO servers (id, name_ciphertext, description_ciphertext, owner_id, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&server_id)
    .bind(&name)
    .bind(&description)
    .bind(&auth.user_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    // @everyone role: is_default, applies to every member.
    // Placeholder blob for the @everyone role name (never displayed) — bound (not a `x'..'` literal,
    // which Postgres reads as a bit-string, not bytea).
    sqlx::query(
        "INSERT INTO roles (id, server_id, name_ciphertext, permissions, position, is_default, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 0, 1, $5, $6)",
    )
    .bind(new_id())
    .bind(&server_id)
    .bind(vec![0u8])
    .bind(perms::DEFAULT_PERMISSIONS)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO server_members (id, server_id, user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(new_id())
        .bind(&server_id)
        .bind(&auth.user_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "server_id": server_id })))
}

async fn list_servers(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(String, Vec<u8>, Option<Vec<u8>>, String, i64)> = sqlx::query_as(
        "SELECT s.id, s.name_ciphertext, s.description_ciphertext, s.owner_id, s.created_at
         FROM servers s JOIN server_members m ON m.server_id = s.id
         WHERE m.user_id = $1 ORDER BY s.created_at",
    )
    .bind(&auth.user_id)
    .fetch_all(&state.db)
    .await?;
    let servers: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, desc, owner_id, created_at)| {
            json!({
                "server_id": id,
                "name_ciphertext": B64.encode(name),
                "description_ciphertext": desc.map(|d| B64.encode(d)),
                "owner_id": owner_id,
                "created_at": created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "servers": servers })))
}

#[derive(Deserialize)]
pub struct UpdateServer {
    pub name_ciphertext: Option<String>,
    pub description_ciphertext: Option<String>,
}

async fn update_server(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
    Json(req): Json<UpdateServer>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_SERVER).await?;
    let now = now_ms();
    if let Some(name) = &req.name_ciphertext {
        sqlx::query("UPDATE servers SET name_ciphertext = $1, updated_at = $2 WHERE id = $3")
            .bind(bounded_name(name)?)
            .bind(now)
            .bind(&server_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(desc) = &req.description_ciphertext {
        sqlx::query("UPDATE servers SET description_ciphertext = $1, updated_at = $2 WHERE id = $3")
            .bind(bounded_description(desc)?)
            .bind(now)
            .bind(&server_id)
            .execute(&state.db)
            .await?;
    }
    Ok(Json(json!({ "success": true })))
}

async fn delete_server(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Owner only — deliberately NOT a permission (even ADMINISTRATOR can't delete).
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1")
        .bind(&server_id)
        .fetch_optional(&state.db)
        .await?;
    if owner.ok_or(ApiError::NotFound)? != auth.user_id {
        return Err(ApiError::Forbidden);
    }
    // Irreversible, and it takes every message with it: a device, not just a token (audit M-3).
    crate::keydir::destructive_authority(&state, &auth, &headers, "delete-server", &server_id, b"").await?;
    // Who to tell, read BEFORE the memberships go with the server: the socket re-checks
    // authorization before every delivery, so an event on the server's own topic after the
    // delete would reach nobody.
    let members: Vec<String> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1")
        .bind(&server_id)
        .fetch_all(&state.db)
        .await?;
    sqlx::query("DELETE FROM servers WHERE id = $1").bind(&server_id).execute(&state.db).await?;
    // Each member's own topic: their apps drop the server now (they re-check the server list;
    // nothing in the event is trusted beyond "look again"), and their sockets drop its topics.
    for member in &members {
        state.rt.publish(&crate::rt::user_topic(member), "server_deleted", json!({ "server_id": server_id }));
        state.rt.publish(&crate::rt::user_topic(member), "revoke", json!({ "server_id": server_id }));
    }
    Ok(Json(json!({ "success": true })))
}

// ---- categories & channels ----

#[derive(Deserialize)]
pub struct CreateCategory {
    pub name_ciphertext: String,
    #[serde(default)]
    pub position: i64,
}

async fn create_category(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
    Json(req): Json<CreateCategory>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_CHANNELS).await?;
    let id = new_id();
    let now = now_ms();
    sqlx::query(
        "INSERT INTO channel_categories (id, server_id, name_ciphertext, position, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&server_id)
    .bind(b64_decode(&req.name_ciphertext)?)
    .bind(req.position)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "category_id": id })))
}

#[derive(Deserialize)]
pub struct CreateChannel {
    pub name_ciphertext: String,
    pub topic_ciphertext: Option<String>,
    #[serde(rename = "type", default = "default_channel_kind")]
    pub kind: String,
    pub category_id: Option<String>,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub is_private: bool,
    /// `"feed"`: this server's ONE hidden feed channel (posts, stories, likes and comments).
    /// Creating it when it exists hands back the existing one.
    pub purpose: Option<String>,
}

fn default_channel_kind() -> String {
    "text".to_string()
}

async fn create_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
    Json(req): Json<CreateChannel>,
) -> Result<Json<Value>, ApiError> {
    // Errors `Forbidden` for a non-member.
    let p = effective_permissions(&state, &server_id, &auth.user_id, None).await?;
    if !perms::has_permission(p, perms::MANAGE_CHANNELS) {
        return open_first_voice_room(&state, &server_id, &auth.user_id, p, req).await;
    }
    if !matches!(req.kind.as_str(), "text" | "voice" | "announcement") {
        return Err(ApiError::BadRequest("invalid channel type"));
    }
    let feed = match req.purpose.as_deref() {
        None => false,
        Some("feed") if req.kind == "text" && !req.is_private => true,
        Some(_) => return Err(ApiError::BadRequest("invalid channel purpose")),
    };
    let existing_feed = "SELECT id FROM channels WHERE server_id = $1 AND purpose = 'feed'";
    if feed {
        if let Some(id) = sqlx::query_scalar::<_, String>(existing_feed).bind(&server_id).fetch_optional(&state.db).await? {
            return Ok(Json(json!({ "channel_id": id, "existing": true })));
        }
    }
    let id = new_id();
    let now = now_ms();
    let inserted = sqlx::query(
        "INSERT INTO channels (id, server_id, category_id, name_ciphertext, topic_ciphertext, type, position, is_private, created_at, updated_at, purpose)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(&id)
    .bind(&server_id)
    .bind(&req.category_id)
    .bind(b64_decode(&req.name_ciphertext)?)
    .bind(req.topic_ciphertext.as_deref().map(b64_decode).transpose()?)
    .bind(&req.kind)
    .bind(req.position)
    .bind(req.is_private as i64)
    .bind(now)
    .bind(now)
    .bind(feed.then_some("feed"))
    .execute(&state.db)
    .await;
    if let Err(e) = inserted {
        // Two owner devices creating the feed channel at once: the unique index picks one.
        if feed {
            if let Some(id) = sqlx::query_scalar::<_, String>(existing_feed).bind(&server_id).fetch_optional(&state.db).await? {
                return Ok(Json(json!({ "channel_id": id, "existing": true })));
            }
        }
        return Err(e.into());
    }
    state.rt.publish(&crate::rt::server_topic(&server_id), "channels_changed", json!({ "server_id": server_id }));
    Ok(Json(json!({ "channel_id": id })))
}

/// A member who may NOT manage channels starts a call. Calls live in the server's voice room; if
/// the host never opened one, the first member to call would be stuck (403) until the host did.
/// So exactly this is allowed without MANAGE_CHANNELS: a member holding CONNECT_VOICE creates the
/// server's FIRST voice channel — plain (not private, no category, no topic, position 0) — or,
/// if one exists, is handed its id. Everything else stays `Forbidden`. Serialized, so two members
/// calling at the same moment land in one room.
async fn open_first_voice_room(state: &AppState, server_id: &str, user_id: &str, permissions: i64, req: CreateChannel) -> Result<Json<Value>, ApiError> {
    if req.kind != "voice" || !perms::has_permission(permissions, perms::CONNECT_VOICE) {
        return Err(ApiError::Forbidden);
    }
    if req.is_private || req.category_id.is_some() || req.topic_ciphertext.is_some() {
        return Err(ApiError::Forbidden);
    }
    let name = b64_decode(&req.name_ciphertext)?;
    if name.is_empty() || name.len() > 512 {
        return Err(ApiError::BadRequest("invalid channel name"));
    }
    state.limiter.check(&format!("voice-room:{user_id}"), 6, crate::limiter::MINUTE)?;
    let _one_at_a_time = state.voice_room_lock.lock().await;
    let existing: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE server_id = $1 AND type = 'voice' ORDER BY position, created_at LIMIT 1")
            .bind(server_id)
            .fetch_optional(&state.db)
            .await?;
    if let Some(id) = existing {
        return Ok(Json(json!({ "channel_id": id, "existing": true })));
    }
    let id = new_id();
    let now = now_ms();
    sqlx::query(
        "INSERT INTO channels (id, server_id, category_id, name_ciphertext, topic_ciphertext, type, position, is_private, created_at, updated_at)
         VALUES ($1, $2, NULL, $3, NULL, 'voice', 0, 0, $4, $5)",
    )
    .bind(&id)
    .bind(server_id)
    .bind(name)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "channel_id": id })))
}

async fn list_channels(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Any member may list; per-channel READ enforcement happens on message fetch.
    effective_permissions(&state, &server_id, &auth.user_id, None).await?;
    let rows: Vec<(String, Option<String>, Vec<u8>, Option<Vec<u8>>, String, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT id, category_id, name_ciphertext, topic_ciphertext, type, position, is_private, purpose
         FROM channels WHERE server_id = $1 ORDER BY position, created_at, id",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    let channels: Vec<Value> = rows
        .into_iter()
        .map(|(id, category_id, name, topic, kind, position, is_private, purpose)| {
            json!({
                "channel_id": id,
                "purpose": purpose,
                "category_id": category_id,
                "name_ciphertext": B64.encode(name),
                "topic_ciphertext": topic.map(|t| B64.encode(t)),
                "type": kind,
                "position": position,
                "is_private": is_private == 1,
            })
        })
        .collect();
    Ok(Json(json!({ "channels": channels })))
}

#[derive(Deserialize)]
pub struct UpdateChannel {
    pub name_ciphertext: Option<String>,
    pub topic_ciphertext: Option<String>,
    pub position: Option<i64>,
    pub category_id: Option<String>,
}

async fn update_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<UpdateChannel>,
) -> Result<Json<Value>, ApiError> {
    let server_id = channel_server(&state, &channel_id).await?;
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_CHANNELS).await?;
    let now = now_ms();
    if let Some(v) = &req.name_ciphertext {
        sqlx::query("UPDATE channels SET name_ciphertext = $1, updated_at = $2 WHERE id = $3")
            .bind(b64_decode(v)?)
            .bind(now)
            .bind(&channel_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(v) = &req.topic_ciphertext {
        sqlx::query("UPDATE channels SET topic_ciphertext = $1, updated_at = $2 WHERE id = $3")
            .bind(b64_decode(v)?)
            .bind(now)
            .bind(&channel_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(v) = req.position {
        sqlx::query("UPDATE channels SET position = $1, updated_at = $2 WHERE id = $3")
            .bind(v)
            .bind(now)
            .bind(&channel_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(v) = &req.category_id {
        sqlx::query("UPDATE channels SET category_id = $1, updated_at = $2 WHERE id = $3")
            .bind(v)
            .bind(now)
            .bind(&channel_id)
            .execute(&state.db)
            .await?;
    }
    Ok(Json(json!({ "success": true })))
}

async fn delete_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let server_id = channel_server(&state, &channel_id).await?;
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_CHANNELS).await?;
    sqlx::query("DELETE FROM channels WHERE id = $1").bind(&channel_id).execute(&state.db).await?;
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct PutOverride {
    pub role_id: Option<String>,
    pub user_id: Option<String>,
    pub allow: i64,
    pub deny: i64,
}

async fn put_override(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<PutOverride>,
) -> Result<Json<Value>, ApiError> {
    let server_id = channel_server(&state, &channel_id).await?;
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_ROLES).await?;
    if req.role_id.is_none() == req.user_id.is_none() {
        return Err(ApiError::BadRequest("exactly one of role_id or user_id"));
    }
    if (req.allow | req.deny) & !perms::ALL_PERMISSIONS != 0 {
        return Err(ApiError::BadRequest("unknown permission bits"));
    }
    // Ceiling: an override can't grant (allow) powers you don't hold — no channel-level escalation.
    // Nor take away (deny) powers you don't hold: a mod must not be able to mute an admin role's
    // MANAGE_* in a channel.
    require_grantable(&state, &server_id, &auth.user_id, req.allow | req.deny).await?;
    // Scope: the target must belong to THIS server (a role id from another server, or a user who
    // is not a member, has no business in this channel's overrides).
    // Rank: an override on a role or member at or above the actor is acting upward — it would
    // let a mod deny an admin (or a peer) access to a channel.
    if let Some(role_id) = &req.role_id {
        let in_server: Option<i64> = sqlx::query_scalar("SELECT is_default FROM roles WHERE id = $1 AND server_id = $2")
            .bind(role_id)
            .bind(&server_id)
            .fetch_optional(&state.db)
            .await?;
        in_server.ok_or(ApiError::NotFound)?;
        require_outranks_role(&state, &server_id, &auth.user_id, role_id).await?;
    }
    if let Some(user_id) = &req.user_id {
        let member: Option<String> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1 AND user_id = $2")
            .bind(&server_id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
        member.ok_or(ApiError::NotFound)?;
        if user_id == &auth.user_id {
            // No self-exemption: an override on YOURSELF replaces whatever an admin set on you,
            // so a moderator who was denied something in this channel could simply lift it.
            // Only the owner / an administrator (top rank) may set their own override.
            if member_rank(&state, &server_id, &auth.user_id).await? < ADMIN_RANK {
                return Err(ApiError::Forbidden);
            }
        } else {
            require_outranks_member(&state, &server_id, &auth.user_id, user_id).await?;
        }
    }
    let now = now_ms();
    // No natural upsert key (role_id/user_id are nullable): delete-then-insert in a tx.
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "DELETE FROM channel_permission_overrides
         WHERE channel_id = $1 AND (role_id = $2 OR (role_id IS NULL AND $3 IS NULL))
           AND (user_id = $4 OR (user_id IS NULL AND $5 IS NULL))",
    )
    .bind(&channel_id)
    .bind(&req.role_id)
    .bind(&req.role_id)
    .bind(&req.user_id)
    .bind(&req.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO channel_permission_overrides (id, channel_id, role_id, user_id, allow, deny, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(new_id())
    .bind(&channel_id)
    .bind(&req.role_id)
    .bind(&req.user_id)
    .bind(req.allow)
    .bind(req.deny)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true })))
}

// ---- roles ----

#[derive(Deserialize)]
pub struct CreateRole {
    pub name_ciphertext: String,
    #[serde(default)]
    pub permissions: i64,
    pub color: Option<String>,
    #[serde(default)]
    pub position: i64,
}

async fn create_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
    Json(req): Json<CreateRole>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_ROLES).await?;
    if req.permissions & !perms::ALL_PERMISSIONS != 0 {
        return Err(ApiError::BadRequest("unknown permission bits"));
    }
    // Permission ceiling: you can't create a role granting powers you don't hold yourself.
    require_grantable(&state, &server_id, &auth.user_id, req.permissions).await?;
    // Hierarchy: a new role sits strictly BELOW its creator. Rank is "highest position among
    // your roles", so a role created above you (then self-assigned, or handed to an ally) would
    // be a rank you never had.
    require_position_below(&state, &server_id, &auth.user_id, req.position).await?;
    let id = new_id();
    let now = now_ms();
    sqlx::query(
        "INSERT INTO roles (id, server_id, name_ciphertext, color, permissions, position, is_default, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, 0, $7, $8)",
    )
    .bind(&id)
    .bind(&server_id)
    .bind(b64_decode(&req.name_ciphertext)?)
    .bind(&req.color)
    .bind(req.permissions)
    .bind(req.position)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "role_id": id })))
}

async fn list_roles(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    effective_permissions(&state, &server_id, &auth.user_id, None).await?;
    let rows: Vec<(String, Vec<u8>, Option<String>, i64, i64, i64)> = sqlx::query_as(
        "SELECT id, name_ciphertext, color, permissions, position, is_default
         FROM roles WHERE server_id = $1 ORDER BY position, created_at",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    let roles: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, color, permissions, position, is_default)| {
            json!({
                "role_id": id,
                "name_ciphertext": B64.encode(name),
                "color": color,
                "permissions": permissions,
                "position": position,
                "is_default": is_default == 1,
            })
        })
        .collect();
    Ok(Json(json!({ "roles": roles })))
}

#[derive(Deserialize)]
pub struct UpdateRole {
    pub name_ciphertext: Option<String>,
    pub permissions: Option<i64>,
    pub color: Option<String>,
    pub position: Option<i64>,
}

async fn update_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(role_id): Path<String>,
    Json(req): Json<UpdateRole>,
) -> Result<Json<Value>, ApiError> {
    let server_id: Option<String> =
        sqlx::query_scalar("SELECT server_id FROM roles WHERE id = $1").bind(&role_id).fetch_optional(&state.db).await?;
    let server_id = server_id.ok_or(ApiError::NotFound)?;
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_ROLES).await?;
    // Can't edit a role at or above your own rank (blocks zeroing an admin role's permissions).
    require_outranks_role(&state, &server_id, &auth.user_id, &role_id).await?;
    // Validate everything before writing anything (no half-applied update on a refusal).
    if let Some(v) = req.permissions {
        if v & !perms::ALL_PERMISSIONS != 0 {
            return Err(ApiError::BadRequest("unknown permission bits"));
        }
        require_grantable(&state, &server_id, &auth.user_id, v).await?;
    }
    if let Some(v) = req.position {
        require_position_below(&state, &server_id, &auth.user_id, v).await?;
    }
    // Ceiling on the role as it stands: editing a role that carries powers you do not hold
    // (renaming it, lowering it, moving it) is acting on power above you.
    let current: i64 = sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1").bind(&role_id).fetch_one(&state.db).await?;
    require_grantable(&state, &server_id, &auth.user_id, current).await?;
    let now = now_ms();
    if let Some(v) = &req.name_ciphertext {
        sqlx::query("UPDATE roles SET name_ciphertext = $1, updated_at = $2 WHERE id = $3")
            .bind(b64_decode(v)?)
            .bind(now)
            .bind(&role_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(v) = req.permissions {
        if v & !perms::ALL_PERMISSIONS != 0 {
            return Err(ApiError::BadRequest("unknown permission bits"));
        }
        // Ceiling: can't raise a role to include powers you don't hold (blocks admin-ing @everyone).
        require_grantable(&state, &server_id, &auth.user_id, v).await?;
        sqlx::query("UPDATE roles SET permissions = $1, updated_at = $2 WHERE id = $3")
            .bind(v)
            .bind(now)
            .bind(&role_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(v) = &req.color {
        sqlx::query("UPDATE roles SET color = $1, updated_at = $2 WHERE id = $3")
            .bind(v)
            .bind(now)
            .bind(&role_id)
            .execute(&state.db)
            .await?;
    }
    if let Some(v) = req.position {
        // Moving a role is a hierarchy change: the new position must also be below the actor.
        // (Otherwise: create a low role, take it, then raise it above the admins.)
        require_position_below(&state, &server_id, &auth.user_id, v).await?;
        sqlx::query("UPDATE roles SET position = $1, updated_at = $2 WHERE id = $3")
            .bind(v)
            .bind(now)
            .bind(&role_id)
            .execute(&state.db)
            .await?;
    }
    Ok(Json(json!({ "success": true })))
}

async fn delete_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(role_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let row: Option<(String, i64, i64)> =
        sqlx::query_as("SELECT server_id, is_default, permissions FROM roles WHERE id = $1").bind(&role_id).fetch_optional(&state.db).await?;
    let (server_id, is_default, role_perms) = row.ok_or(ApiError::NotFound)?;
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_ROLES).await?;
    require_outranks_role(&state, &server_id, &auth.user_id, &role_id).await?;
    // Ceiling: deleting a role strips its powers from everyone holding it — not for someone who
    // could not have granted those powers.
    require_grantable(&state, &server_id, &auth.user_id, role_perms).await?;
    if is_default == 1 {
        return Err(ApiError::BadRequest("cannot delete the default role"));
    }
    sqlx::query("DELETE FROM roles WHERE id = $1").bind(&role_id).execute(&state.db).await?;
    Ok(Json(json!({ "success": true })))
}

async fn assign_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, user_id, role_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_ROLES).await?;
    let member_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM server_members WHERE server_id = $1 AND user_id = $2")
            .bind(&server_id)
            .bind(&user_id)
            .fetch_optional(&state.db)
            .await?;
    let member_id = member_id.ok_or(ApiError::NotFound)?;
    let role_perms: Option<i64> = sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1 AND server_id = $2 AND is_default = 0")
        .bind(&role_id)
        .bind(&server_id)
        .fetch_optional(&state.db)
        .await?;
    let role_perms = role_perms.ok_or(ApiError::NotFound)?;
    // Ceiling: can't assign a role that carries powers you don't hold (blocks self-assigning a
    // pre-existing ADMINISTRATOR role). Hierarchy: can't assign a role at or above your own rank.
    require_grantable(&state, &server_id, &auth.user_id, role_perms).await?;
    require_outranks_role(&state, &server_id, &auth.user_id, &role_id).await?;
    sqlx::query("INSERT INTO member_roles (id, server_member_id, role_id, created_at) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING")
        .bind(new_id())
        .bind(&member_id)
        .bind(&role_id)
        .bind(now_ms())
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

async fn remove_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, user_id, role_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_ROLES).await?;
    let role_perms: Option<i64> = sqlx::query_scalar("SELECT permissions FROM roles WHERE id = $1 AND server_id = $2 AND is_default = 0")
        .bind(&role_id)
        .bind(&server_id)
        .fetch_optional(&state.db)
        .await?;
    let role_perms = role_perms.ok_or(ApiError::NotFound)?;
    // Can't strip a role at or above your own rank (blocks demoting an admin)...
    require_outranks_role(&state, &server_id, &auth.user_id, &role_id).await?;
    // ...nor a role carrying powers you do not hold (ceiling), nor ANY role from a member at or
    // above you (dropping your own lower role is fine).
    require_grantable(&state, &server_id, &auth.user_id, role_perms).await?;
    if user_id != auth.user_id {
        require_outranks_member(&state, &server_id, &auth.user_id, &user_id).await?;
    }
    sqlx::query(
        "DELETE FROM member_roles WHERE role_id = $1
         AND server_member_id = (SELECT id FROM server_members WHERE server_id = $2 AND user_id = $3)",
    )
    .bind(&role_id)
    .bind(&server_id)
    .bind(&user_id)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true })))
}

// ---- members ----

#[derive(serde::Deserialize)]
struct SetStatus {
    status: String,
}

/// Presence heartbeat: set my status (online/idle/dnd/offline) and bump last_seen_at. Clients call
/// this periodically; members lists stale anyone silent for 3 minutes back to offline.
async fn set_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<SetStatus>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(req.status.as_str(), "online" | "idle" | "dnd" | "offline") {
        return Err(ApiError::BadRequest("status must be online, idle, dnd, or offline"));
    }
    sqlx::query("UPDATE profiles SET status = $1, last_seen_at = $2, updated_at = $2 WHERE id = $3")
        .bind(&req.status)
        .bind(now_ms())
        .bind(&auth.user_id)
        .execute(&state.db)
        .await?;
    // Fan the change out live to every server the user is a member of (same as the WS presence
    // frame) — without this, REST heartbeats only become visible on the next poll cycle.
    let server_ids: Vec<String> =
        sqlx::query_scalar("SELECT server_id FROM server_members WHERE user_id = $1")
            .bind(&auth.user_id)
            .fetch_all(&state.db)
            .await?;
    for sid in server_ids {
        state.rt.publish(
            &crate::rt::server_topic(&sid),
            "presence",
            json!({ "user_id": auth.user_id, "status": req.status }),
        );
    }
    Ok(Json(json!({ "success": true })))
}

async fn list_members(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    effective_permissions(&state, &server_id, &auth.user_id, None).await?;
    let rows: Vec<(String, String, Option<Vec<u8>>, i64, String, i64)> = sqlx::query_as(
        "SELECT m.user_id, p.username, m.nickname_ciphertext, m.created_at, p.status, p.last_seen_at
         FROM server_members m JOIN profiles p ON p.id = m.user_id
         WHERE m.server_id = $1 ORDER BY m.created_at",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    // Role assignments, grouped per member, so clients can render/toggle them in one fetch.
    let role_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT sm.user_id, mr.role_id FROM member_roles mr
         JOIN server_members sm ON sm.id = mr.server_member_id
         WHERE sm.server_id = $1",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let mut roles_by_member: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for (uid, rid) in role_rows {
        roles_by_member.entry(uid).or_default().push(rid);
    }
    let members: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, username, nickname, created_at, status, last_seen_at)| {
            // Presence: a client heartbeats its status; without one for 3 minutes it reads offline.
            let effective = if status != "offline" && now_ms() - last_seen_at <= 180_000 { status } else { "offline".to_string() };
            let role_ids = roles_by_member.get(&user_id).cloned().unwrap_or_default();
            json!({
                "user_id": user_id,
                "username": username,
                "status": effective,
                "role_ids": role_ids,
                "nickname_ciphertext": nickname.map(|n| B64.encode(n)),
                "joined_at": created_at,
            })
        })
        .collect();
    Ok(Json(json!({ "members": members })))
}

async fn kick_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    // Leaving is kicking yourself. Kicking others: first the permission (a non-mod gets Forbidden),
    // then the owner protection (so an admin kicking the owner gets the specific BadRequest), then
    // the rank check (a mod can't kick admins/other mods at or above them).
    if user_id != auth.user_id {
        require_permission(&state, &server_id, &auth.user_id, perms::KICK_MEMBERS).await?;
    }
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1")
        .bind(&server_id)
        .fetch_optional(&state.db)
        .await?;
    if owner.ok_or(ApiError::NotFound)? == user_id {
        return Err(ApiError::BadRequest("the owner cannot be removed; delete the server instead"));
    }
    if user_id != auth.user_id {
        require_outranks_member(&state, &server_id, &auth.user_id, &user_id).await?;
    }
    let res = sqlx::query("DELETE FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(&server_id)
        .bind(&user_id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    forget_member_approvals(&state, &server_id, &user_id).await?;
    // Two signals, both needed. `member_removed` on the server topic tells the REMAINING members'
    // clients to rotate their channel sender keys. `revoke` on the removed user's own topic makes
    // each of their open sockets drop this server's topics immediately; ws.rs additionally
    // re-checks authorization before every delivery, so access is cut even if this frame is missed.
    state.rt.publish(&crate::rt::server_topic(&server_id), "member_removed", json!({ "user_id": user_id }));
    state.rt.publish(&crate::rt::user_topic(&user_id), "revoke", json!({ "server_id": server_id }));
    // …and out of this server's voice rooms, now (not when their room token expires).
    crate::voice::evict_from_server_rooms(&state, &server_id, &user_id).await;
    Ok(Json(json!({ "success": true })))
}

// ---- bans ----

#[derive(Deserialize, Default)]
pub struct BanRequest {
    /// Optional moderator note (the moderator's own words, kept for the audit trail — not content).
    pub reason: Option<String>,
}

/// Ban a user from a server: removes their membership (if any), kills any pending join request,
/// and records a `server_bans` row that EVERY join path checks — unlike a kick, they cannot come
/// back with a fresh invite until unbanned. Requires `BAN_MEMBERS` plus outranking the target
/// (same hierarchy rule as kick, so a mod can't ban an admin). A non-member can be banned too
/// (pre-emptively, or after they left to dodge moderation).
async fn ban_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, user_id)): Path<(String, String)>,
    body: Option<Json<BanRequest>>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::BAN_MEMBERS).await?;
    if user_id == auth.user_id {
        return Err(ApiError::BadRequest("you can't ban yourself"));
    }
    let owner: Option<String> = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1")
        .bind(&server_id)
        .fetch_optional(&state.db)
        .await?;
    if owner.ok_or(ApiError::NotFound)? == user_id {
        return Err(ApiError::BadRequest("the owner cannot be banned"));
    }
    let target_exists: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM profiles WHERE id = $1) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await?;
    if target_exists == 0 {
        return Err(ApiError::NotFound);
    }
    let is_member: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(&server_id)
        .bind(&user_id)
        .fetch_one(&state.db)
        .await?;
    // Rank check only applies to current members — a non-member has no roles to rank
    // (and `member_rank` would reject them as Forbidden).
    if is_member == 1 {
        require_outranks_member(&state, &server_id, &auth.user_id, &user_id).await?;
    }
    let reason = body.and_then(|Json(b)| b.reason).filter(|r| !r.trim().is_empty());
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO server_bans (server_id, user_id, banned_by, reason, created_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (server_id, user_id) DO NOTHING",
    )
    .bind(&server_id)
    .bind(&user_id)
    .bind(&auth.user_id)
    .bind(&reason)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(&server_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    // (inside the ban's transaction — see `forget_member_approvals`)
    sqlx::query("DELETE FROM member_approvals WHERE server_id = $1 AND (user_id = $2 OR approver_user_id = $3)")
        .bind(&server_id)
        .bind(&user_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    // A pending join request must not survive the ban (approve would otherwise re-admit).
    sqlx::query("UPDATE join_requests SET status = 'denied', updated_at = $1 WHERE server_id = $2 AND user_id = $3 AND status = 'pending'")
        .bind(now)
        .bind(&server_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    // Same pair of signals as a kick: remaining members rotate sender keys, and the banned user's
    // live sockets lose this server's topics.
    state.rt.publish(&crate::rt::server_topic(&server_id), "member_removed", json!({ "user_id": user_id }));
    state.rt.publish(&crate::rt::user_topic(&user_id), "revoke", json!({ "server_id": server_id }));
    // …and out of this server's voice rooms, now (not when their room token expires).
    crate::voice::evict_from_server_rooms(&state, &server_id, &user_id).await;
    Ok(Json(json!({ "success": true })))
}

/// Lift a ban. The user is NOT re-admitted — they need a fresh invite like anyone else.
async fn unban_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::BAN_MEMBERS).await?;
    let n = sqlx::query("DELETE FROM server_bans WHERE server_id = $1 AND user_id = $2")
        .bind(&server_id)
        .bind(&user_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    state.rt.publish(&crate::rt::user_topic(&user_id), "join_denied", json!({ "server_id": server_id }));
    Ok(Json(json!({ "success": true })))
}

/// The server's ban list (admins with `BAN_MEMBERS` only), with usernames for display.
async fn list_bans(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::BAN_MEMBERS).await?;
    let rows: Vec<(String, Option<String>, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT b.user_id, p.username, b.banned_by, b.reason, b.created_at
         FROM server_bans b LEFT JOIN profiles p ON p.id = b.user_id
         WHERE b.server_id = $1 ORDER BY b.created_at DESC",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    let bans: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, username, banned_by, reason, created_at)| {
            json!({ "user_id": user_id, "username": username, "banned_by": banned_by, "reason": reason, "created_at": created_at })
        })
        .collect();
    Ok(Json(json!({ "bans": bans })))
}

// ---- invites ----

/// 8-char join code from an unambiguous alphabet (no 0/O/1/I).
pub(crate) fn generate_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..8).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

#[derive(Deserialize)]
pub struct CreateInvite {
    pub max_uses: Option<i64>,
    pub expires_at: Option<i64>,
    /// "code" (default, host must approve), "token" (one-time link, auto-approve), or
    /// "username" (reserved for `reserved_username`, auto-approve that name only).
    #[serde(default = "default_invite_kind")]
    pub kind: String,
    /// For kind="username": the username auto-approved by this invite.
    pub reserved_username: Option<String>,
}

fn default_invite_kind() -> String {
    "code".to_string()
}

async fn create_invite(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
    Json(req): Json<CreateInvite>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_INVITES).await?;
    // Per-user window: invites double as signup codes (join.rs), so unthrottled minting lets one
    // compromised MANAGE_INVITES account spray the instance with working join codes.
    state.limiter.check(&format!("create_invite:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    if req.max_uses.is_some_and(|m| m <= 0) {
        return Err(ApiError::BadRequest("max_uses must be positive"));
    }
    // Kind determines trust: token/username are host-vouched (auto-approve); a bare code needs the
    // host to approve each request. A one-time token is single-use by definition.
    let (kind, requires_approval, max_uses, reserved) = match req.kind.as_str() {
        "token" => ("token", 0i64, Some(1i64), None),
        "username" => {
            let name = req.reserved_username.as_deref().map(str::to_lowercase);
            if name.as_deref().is_none_or(str::is_empty) {
                return Err(ApiError::BadRequest("username invite needs reserved_username"));
            }
            ("username", 0i64, req.max_uses, name)
        }
        "code" => ("code", 1i64, req.max_uses, None),
        _ => return Err(ApiError::BadRequest("invalid invite kind")),
    };
    let now = now_ms();
    // Default a 7-day expiry when the host doesn't set one, so a leaked code can't work forever.
    // An explicit expires_at is honored (including a far-future one for a deliberately long link).
    let expires_at = req.expires_at.unwrap_or(now + crate::join::DEFAULT_INVITE_TTL_MS);
    // Retry on the (unlikely) code collision.
    for _ in 0..5 {
        let code = generate_code();
        let insert = sqlx::query(
            "INSERT INTO invites (id, server_id, inviter_id, code, kind, reserved_username, requires_approval, max_uses, expires_at, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11)",
        )
        .bind(new_id())
        .bind(&server_id)
        .bind(&auth.user_id)
        .bind(&code)
        .bind(kind)
        .bind(&reserved)
        .bind(requires_approval)
        .bind(max_uses)
        .bind(expires_at)
        .bind(now)
        .bind(now)
        .execute(&state.db)
        .await;
        match insert {
            Ok(_) => return Ok(Json(json!({ "code": code, "kind": kind, "requires_approval": requires_approval == 1, "expires_at": expires_at }))),
            Err(e) => match ApiError::from(e) {
                ApiError::Conflict(_) => continue,
                other => return Err(other),
            },
        }
    }
    Err(ApiError::Internal)
}

async fn list_invites(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_INVITES).await?;
    let rows: Vec<(String, String, Option<i64>, i64, Option<i64>, String, String)> = sqlx::query_as(
        "SELECT code, inviter_id, max_uses, use_count, expires_at, status, id
         FROM invites WHERE server_id = $1 ORDER BY created_at",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    // Accounts created with each invite that no server has admitted: while an invite has
    // `waiting_cap` of them, nobody else can sign up with it. Shown to the host as a notice.
    let waiting: std::collections::HashMap<String, i64> = crate::join::invite_waiting(&state.db, &server_id).await?.into_iter().collect();
    let cap = state.invite_pending_signups;
    let invites: Vec<Value> = rows
        .into_iter()
        .map(|(code, inviter_id, max_uses, use_count, expires_at, status, id)| {
            let waiting = waiting.get(&id).copied().unwrap_or(0);
            json!({
                "waiting": waiting,
                "waiting_cap": cap,
                "waiting_full": waiting >= cap,
                "code": code,
                "inviter_id": inviter_id,
                "max_uses": max_uses,
                "use_count": use_count,
                "expires_at": expires_at,
                "status": status,
            })
        })
        .collect();
    Ok(Json(json!({ "invites": invites })))
}

async fn revoke_invite(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(code): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let server_id: Option<String> =
        sqlx::query_scalar("SELECT server_id FROM invites WHERE code = $1").bind(&code).fetch_optional(&state.db).await?;
    let server_id = server_id.ok_or(ApiError::NotFound)?;
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_INVITES).await?;
    sqlx::query("UPDATE invites SET status = 'revoked', updated_at = $1 WHERE code = $2")
        .bind(now_ms())
        .bind(&code)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

/// Redeem an invite. Trust-gated per kind (security-first):
/// - **token** / **username**: host already vouched → the caller is admitted immediately.
///   A username invite only admits the reserved username; anyone else is rejected.
/// - **code**: files a *pending join request* the host must approve. The caller is NOT a member
///   until approval (see `approve_join_request`).
async fn accept_invite(
    State(state): State<AppState>,
    auth: AuthUser,
    client: crate::client_key::ClientKey,
    Path(code): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Rate-limit per source IP: redeeming an invite probes whether a code is valid, so an
    // unthrottled endpoint lets an authed user brute-force the 8-char invite space. Mirrors the
    // per-IP windows on the auth routes.
    // Authenticated route: limited per caller AND per account, with no bucket shared between
    // accounts (so nobody else's traffic can lock this user out).
    client.limit(&state, "accept_invite", 10)?;
    state.limiter.check(&format!("accept_invite:user:{}", auth.user_id), 10, crate::limiter::MINUTE)?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let row: Option<(String, String, String, Option<String>, i64, Option<i64>, i64, Option<i64>, String)> = sqlx::query_as(
        "SELECT id, server_id, kind, reserved_username, requires_approval, max_uses, use_count, expires_at, status
         FROM invites WHERE code = $1",
    )
    .bind(&code)
    .fetch_optional(&mut *tx)
    .await?;
    let (invite_id, server_id, kind, reserved_username, requires_approval, max_uses, use_count, expires_at, status) =
        row.ok_or(ApiError::NotFound)?;
    if status != "active" || expires_at.is_some_and(|t| t < now) || max_uses.is_some_and(|m| use_count >= m) {
        return Err(ApiError::BadRequest("invite is no longer valid"));
    }

    // Ban enforcement: a banned user is barred from EVERY join path — a valid invite (even a
    // host-vouched token/username one minted before the ban) doesn't override a ban. Checked on
    // the open transaction (a separate pooled connection would deadlock SQLite's single writer).
    let banned: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_bans WHERE server_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(&server_id)
    .bind(&auth.user_id)
    .fetch_one(&mut *tx)
    .await?;
    if banned == 1 {
        return Err(ApiError::Forbidden);
    }

    // The server owner + one of their devices: the joining member polls this DM to receive the
    // provision bundle (space key + channel keys) the host relays on approval (auto-discover).
    let host_user_id: String = sqlx::query_scalar("SELECT owner_id FROM servers WHERE id = $1")
        .bind(&server_id)
        .fetch_one(&mut *tx)
        .await?;
    let host_device_id: Option<String> = sqlx::query_scalar(
        "SELECT device_id FROM user_devices WHERE user_id = $1 ORDER BY last_active_at DESC LIMIT 1",
    )
    .bind(&host_user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let already: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(&server_id)
        .bind(&auth.user_id)
        .fetch_one(&mut *tx)
        .await?;
    if already == 1 {
        return Ok(Json(json!({ "server_id": server_id, "already_member": true,
            "host_user_id": host_user_id, "host_device_id": host_device_id })));
    }

    // A username invite admits only the reserved name.
    if kind == "username" {
        let my_username: String = sqlx::query_scalar("SELECT username FROM profiles WHERE id = $1")
            .bind(&auth.user_id)
            .fetch_one(&mut *tx)
            .await?;
        if reserved_username.as_deref() != Some(my_username.as_str()) {
            return Err(ApiError::Forbidden);
        }
    }

    // Approval-required (bare code): file a pending request instead of joining.
    if requires_approval == 1 {
        let existing: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT status, invite_id FROM join_requests WHERE server_id = $1 AND user_id = $2")
                .bind(&server_id)
                .bind(&auth.user_id)
                .fetch_optional(&mut *tx)
                .await?;
        match existing.as_ref().map(|(status, invite)| (status.as_str(), invite.as_deref())) {
            Some(("pending", _)) => {
                tx.commit().await?;
                return Ok(Json(json!({ "server_id": server_id, "pending": true,
                    "host_user_id": host_user_id, "host_device_id": host_device_id })));
            }
            // A denial is final for that invite (audit H-2): asking again with the same code
            // used to flip the request back to pending — and notify and push-wake everyone
            // who decides, ten times a minute, for as long as the requester liked. The host
            // lets a declined person in by sending them another invite.
            Some(("denied", invite)) if invite == Some(invite_id.as_str()) => {
                return Err(ApiError::Conflict("this request was declined; ask the host for a new invite"));
            }
            _ => {
                // Requests count against the invite like signups do: no more of them waiting
                // than the invite has uses left, and never more than the waiting-room cap —
                // also for accounts that did not sign up with this code (`join.rs` counts
                // only those).
                let waiting: i64 = sqlx::query_scalar("SELECT CAST(count(*) AS BIGINT) FROM join_requests WHERE invite_id = $1 AND status = 'pending'")
                    .bind(&invite_id)
                    .fetch_one(&mut *tx)
                    .await?;
                if waiting >= state.invite_pending_signups || max_uses.is_some_and(|m| use_count + waiting >= m) {
                    return Err(ApiError::BadRequest("too many people are already waiting on this invite; ask the host to answer them, or for a new invite"));
                }
                sqlx::query(
                    "INSERT INTO join_requests (id, server_id, user_id, invite_id, status, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, 'pending', $5, $6)
                     ON CONFLICT(server_id, user_id) DO UPDATE SET status = 'pending', invite_id = excluded.invite_id, updated_at = excluded.updated_at",
                )
                .bind(new_id())
                .bind(&server_id)
                .bind(&auth.user_id)
                .bind(&invite_id)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                notify_join_request(&state, &server_id, &auth.user_id).await;
                return Ok(Json(json!({ "server_id": server_id, "pending": true,
                    "host_user_id": host_user_id, "host_device_id": host_device_id })));
            }
        }
    }

    // Auto-approve (token / username): join now.
    // Atomically consume a use under the SAME validity predicates as the initial check — race-safe
    // across concurrent redemptions of a single-use invite. Under Postgres the UPDATE row-locks; under
    // SQLite the single-writer model serializes it. If a concurrent redemption exhausted it first, the
    // WHERE matches no row and we reject (no member added). Done BEFORE the member insert so a failed
    // consume can't leave a stray membership.
    let consumed: Option<i64> = sqlx::query_scalar(
        "UPDATE invites
            SET use_count = use_count + 1,
                status = CASE WHEN kind = 'token' THEN 'revoked' ELSE status END,
                updated_at = $1
          WHERE id = $2
            AND status = 'active'
            AND (expires_at IS NULL OR expires_at > $3)
            AND (max_uses IS NULL OR use_count < max_uses)
         RETURNING use_count",
    )
    .bind(now)
    .bind(&invite_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    if consumed.is_none() {
        // Another concurrent redemption took the last use between the read check and now.
        return Err(ApiError::BadRequest("invite is no longer valid"));
    }
    sqlx::query("INSERT INTO server_members (id, server_id, user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(new_id())
        .bind(&server_id)
        .bind(&auth.user_id)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.rt.publish(&crate::rt::server_topic(&server_id), "member_joined", json!({ "server_id": server_id, "user_id": auth.user_id }));
    Ok(Json(json!({ "server_id": server_id,
        "host_user_id": host_user_id, "host_device_id": host_device_id })))
}

/// Everyone who decides on join requests for `server_id`: the owner and members whose roles
/// carry MANAGE_INVITES.
async fn join_deciders(state: &AppState, server_id: &str) -> Vec<String> {
    let members: Vec<String> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1")
        .bind(server_id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for user in members {
        if let Ok(p) = effective_permissions(state, server_id, &user, None).await {
            if perms::has_permission(p, perms::MANAGE_INVITES) {
                out.push(user);
            }
        }
    }
    out
}

/// Someone is waiting to be let in: tell the people who can let them in — in-band if they are
/// connected, and with a (contentless) push wake if they are not. Without this the request sat
/// unseen until the owner happened to open the right screen.
async fn notify_join_request(state: &AppState, server_id: &str, requester: &str) {
    let deciders = join_deciders(state, server_id).await;
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM join_requests WHERE server_id = $1 AND status = 'pending'")
        .bind(server_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(1);
    for user in &deciders {
        state.rt.publish(
            &crate::rt::user_topic(user),
            "join_request",
            json!({ "server_id": server_id, "user_id": requester, "pending": pending }),
        );
        crate::messages::wake_user(state, user).await;
    }
}

/// A signup was just refused because `invite_id` already has `waiting` accounts nobody has let
/// in: tell the people who can do something about it (in-band, and a contentless wake), at most
/// once an hour per invite — a refused signup is something a stranger with the code can repeat.
/// The standing fact is also in the invite list (`waiting`, `waiting_full`) and on the host
/// admin page, so it does not depend on this event being seen.
pub async fn notify_invite_full(state: &AppState, invite_id: &str, waiting: i64) {
    tracing::warn!(waiting, "a signup was refused: its invite has as many accounts waiting for approval as it may");
    if state.limiter.check(&format!("invite_full:{invite_id}"), 1, 60 * 60 * 1000).is_err() {
        return;
    }
    let Ok(Some((server_id, code))) = sqlx::query_as::<_, (String, String)>("SELECT server_id, code FROM invites WHERE id = $1").bind(invite_id).fetch_optional(&state.db).await else { return };
    for user in &join_deciders(state, &server_id).await {
        state.rt.publish(
            &crate::rt::user_topic(user),
            "invite_full",
            json!({ "server_id": server_id, "code": code, "waiting": waiting, "waiting_cap": state.invite_pending_signups }),
        );
        crate::messages::wake_user(state, user).await;
    }
}

/// Unauthenticated: "would this invite still let someone in?" — asked BEFORE the friend picks a
/// name and a password, so an expired link is reported up front instead of after signup.
/// Answers only valid / not (and, when not, whether it expired) — never which skwod, who made
/// it or how many uses are left. Throttled like the other code-probing routes.
async fn check_invite(
    State(state): State<AppState>,
    client: crate::client_key::ClientKey,
    Path(code): Path<String>,
) -> Result<Json<Value>, ApiError> {
    client.limit(&state, "check_invite", 20)?;
    if code.len() > 128 {
        return Err(ApiError::BadRequest("invalid code"));
    }
    if crate::join::authorize_join(&state, &code).await? != crate::join::JoinAuth::Invalid {
        let approval: Option<i64> = sqlx::query_scalar("SELECT requires_approval FROM invites WHERE code = $1").bind(&code).fetch_optional(&state.db).await?;
        return Ok(Json(json!({ "valid": true, "requires_approval": approval == Some(1) })));
    }
    let row: Option<(String, Option<i64>, Option<i64>, i64)> = sqlx::query_as("SELECT status, expires_at, max_uses, use_count FROM invites WHERE code = $1")
        .bind(&code)
        .fetch_optional(&state.db)
        .await?;
    let reason = match row {
        Some((status, expires_at, _, _)) if status == "active" && expires_at.is_some_and(|t| t <= now_ms()) => "expired",
        Some((status, _, max_uses, use_count)) if status != "active" || max_uses.is_some_and(|m| use_count >= m) => "used",
        _ => "unknown",
    };
    Ok(Json(json!({ "valid": false, "reason": reason })))
}

// ---- host approval of pending join requests ----

/// List pending join requests for a server (host-only). Each entry is a username awaiting approval.
async fn list_join_requests(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_INVITES).await?;
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT jr.user_id, p.username, jr.created_at
         FROM join_requests jr JOIN profiles p ON p.id = jr.user_id
         WHERE jr.server_id = $1 AND jr.status = 'pending' ORDER BY jr.created_at",
    )
    .bind(&server_id)
    .fetch_all(&state.db)
    .await?;
    let requests: Vec<Value> = rows
        .into_iter()
        .map(|(user_id, username, created_at)| json!({ "user_id": user_id, "username": username, "created_at": created_at }))
        .collect();
    Ok(Json(json!({ "requests": requests })))
}

/// Approve a pending join request (host-only): admit the user as a member.
async fn approve_join_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_INVITES).await?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let pending: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM join_requests WHERE server_id = $1 AND user_id = $2 AND status = 'pending') THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(&server_id)
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await?;
    if pending == 0 {
        return Err(ApiError::NotFound);
    }
    // Ban enforcement on the approval path too: a request filed before the ban (or a stale admin
    // UI) must not re-admit a banned user. `ban_member` denies pending requests, but this closes
    // the TOCTOU race where a ban commits between the approve click and this transaction. Checked
    // on the OPEN transaction (same connection as the INSERT below), as late as possible, rather
    // than on a separate pooled connection before `begin`: a pre-`begin` read that happens before
    // a concurrent ban commits returns "not banned", and under Postgres READ COMMITTED nothing
    // re-reads it before the member INSERT — so the ban is raced past. Reading here, immediately
    // before the INSERT, gets a fresh snapshot that sees any already-committed ban and shrinks the
    // window to near zero (a separate pooled read would also deadlock SQLite's single writer).
    // Mirrors `accept_invite`.
    let banned: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_bans WHERE server_id = $1 AND user_id = $2) THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(&server_id)
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await?;
    if banned == 1 {
        return Err(ApiError::BadRequest("user is banned from this server"));
    }
    // Guard the approve on `status = 'pending'`: a concurrently-denied (or ban-triggered) request
    // that flipped out of 'pending' after our read above must not be resurrected. If no row still
    // matches, the request changed under us — abort without inserting a membership.
    let approved = sqlx::query("UPDATE join_requests SET status = 'approved', updated_at = $1 WHERE server_id = $2 AND user_id = $3 AND status = 'pending'")
        .bind(now)
        .bind(&server_id)
        .bind(&user_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if approved == 0 {
        return Err(ApiError::NotFound);
    }
    // An approval is a use of the invite the request came in on (audit H-2: `max_uses` was
    // never counted for "code" invites, so a "single-use" code admitted without limit). One
    // conditional UPDATE, as in `accept_invite`; when the invite has no use left the approval
    // is refused and the whole transaction — the status change above included — rolls back.
    // An invite that has since expired or been revoked does not stop the host from saying
    // yes to someone who asked while it was good.
    let invite: Option<(String, Option<i64>)> = sqlx::query_as(
        "SELECT i.id, i.max_uses FROM join_requests r JOIN invites i ON i.id = r.invite_id WHERE r.server_id = $1 AND r.user_id = $2",
    )
    .bind(&server_id)
    .bind(&user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((invite_id, _)) = invite {
        let used = sqlx::query("UPDATE invites SET use_count = use_count + 1, updated_at = $1 WHERE id = $2 AND (max_uses IS NULL OR use_count < max_uses)")
            .bind(now)
            .bind(&invite_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if used == 0 {
            return Err(ApiError::BadRequest("this invite has no uses left; raise its limit or send a new invite"));
        }
    }
    // Idempotent membership insert.
    sqlx::query(
        "INSERT INTO server_members (id, server_id, user_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT(server_id, user_id) DO NOTHING",
    )
    .bind(new_id())
    .bind(&server_id)
    .bind(&user_id)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    // Tell the joiner (so the app walks in without a relaunch) and the space (so member lists
    // refresh). A joiner whose app is closed gets a push wake.
    state.rt.publish(&crate::rt::user_topic(&user_id), "join_approved", json!({ "server_id": server_id }));
    state.rt.publish(&crate::rt::server_topic(&server_id), "member_joined", json!({ "server_id": server_id, "user_id": user_id }));
    crate::messages::wake_user(&state, &user_id).await;
    Ok(Json(json!({ "success": true, "server_id": server_id, "user_id": user_id })))
}

/// Deny a pending join request (host-only).
async fn deny_join_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, user_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    require_permission(&state, &server_id, &auth.user_id, perms::MANAGE_INVITES).await?;
    let n = sqlx::query("UPDATE join_requests SET status = 'denied', updated_at = $1 WHERE server_id = $2 AND user_id = $3 AND status = 'pending'")
        .bind(now_ms())
        .bind(&server_id)
        .bind(&user_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "success": true })))
}
