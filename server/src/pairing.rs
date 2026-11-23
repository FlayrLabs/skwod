//! "Add a device" by QR without a password (build 48). See docs/SECURITY.md "Adding a device by
//! QR" and `core/skwod-core/src/pairing.rs`.
//!
//! Its own table, `device_pair_requests`: nothing in the typed-code link flow
//! (`/link-requests`) can list, approve or replace one of these rows, and these handlers never
//! touch `device_link_requests`.
//!
//! 0. The device showing the QR registers its offer first (`POST /pair-offers`, device-signed):
//!    offer id (a hash of the QR's code), username, expiry (stored as at most 5 minutes).
//! 1. The new device (no session) opens ONE request for a REGISTERED, unexpired offer. Anything
//!    else — an unknown offer, another username, an expired offer — gets the same answer as a
//!    valid request (a request id that never completes) and stores nothing: no oracle for
//!    usernames or offers, and nobody without an offer can fill or block anything. A second
//!    request for the same offer never replaces the first: it silently marks the offer
//!    **contested**, and a contested offer is never approved or claimed.
//! 2. The account's existing device reads the request by offer id. Having seen the requester's
//!    key, it **reveals** its commit-then-reveal nonce for exactly that key (`/reveal`, once);
//!    the QR carries the commitment, so the new device checks the nonce, and the emoji are
//!    computed over (code, requester key, nonce) — a key chosen before the nonce existed cannot
//!    be ground to match. The person picks the new device's emoji among decoys, and the existing
//!    device approves exactly the identity key it revealed for (link signature verified here).
//! 3. The new device polls the claim, proving with a signature by the request's identity key over
//!    (request, offer, poll secret) — holding the poll secret alone is not enough. It gets the
//!    nonce once revealed, and after approval ONE session.
//!
//! The offer is **consumed** (no new request is ever opened for it) on approve, deny, contest
//! and register. Every step checks the offer's expiry. A session that was claimed but has not
//! registered a device is revoked if the request is contested or expires.
//!
//! Off unless the operator sets `SKWOD_QR_PAIRING=1` ([`AppState::qr_pairing`]).

// Row-shaped tuples from sqlx are the idiomatic untyped-query form.
#![allow(clippy::type_complexity)]

use axum::extract::{Path, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::keydir::{b64_decode, own_device_identity, require_bound_device_session, LinkApproval, LINK_REQUEST_TTL_MS, MAX_LINK_BUNDLE};
use crate::state::{new_id, now_ms, AppState};

/// The device-op the claim signature is made for.
pub const CLAIM_OP: &str = "pair-claim";
/// How far a claim's timestamp may be from the server's clock.
const CLAIM_SKEW_MS: i64 = 10 * 60 * 1000;
/// The longest an offer lives on the server (a longer claimed expiry is cut to this).
pub(crate) const MAX_OFFER_TTL_MS: i64 = 5 * 60 * 1000;
/// Clock skew tolerated on the expiry a device asks for (its clock may run ahead of ours).
const OFFER_SKEW_MS: i64 = 60 * 1000;
/// Signature-checked claims per minute for one request (its device polls about 30 a minute).
/// Only a caller holding the request's poll secret is counted, so wrong guesses never use it up.
pub(crate) const CLAIM_PER_REQUEST_PER_MINUTE: u32 = 60;
/// Denials per hour per account.
const DENY_PER_HOUR: u32 = 30;

/// Revoke the session of every request that was claimed but never registered a device, once it
/// expired (its offer lapsed, or the request outlived the link TTL); then drop expired rows.
async fn sweep(state: &AppState, now: i64) -> Result<(), ApiError> {
    let stale: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT id, session_hash FROM device_pair_requests
         WHERE claimed = 1 AND registered = 0 AND session_hash IS NOT NULL
           AND (created_at < $1 OR offer_id NOT IN (SELECT offer_id FROM device_pair_offers WHERE expires_at >= $2))",
    )
    .bind(now - LINK_REQUEST_TTL_MS)
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    for (id, hash) in stale {
        revoke(state, &id, &hash).await?;
    }
    sqlx::query("DELETE FROM device_pair_requests WHERE created_at < $1 AND (session_hash IS NULL OR registered = 1)").bind(now - LINK_REQUEST_TTL_MS).execute(&state.db).await?;
    sqlx::query("DELETE FROM device_pair_offers WHERE expires_at < $1").bind(now).execute(&state.db).await?;
    Ok(())
}

/// Revoke request `id`'s claimed session, unless it already bound a device (registered).
async fn revoke(state: &AppState, id: &str, session_hash: &[u8]) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1 AND device_id IS NULL").bind(session_hash).execute(&state.db).await?;
    sqlx::query("UPDATE device_pair_requests SET session_hash = NULL WHERE id = $1").bind(id).execute(&state.db).await?;
    Ok(())
}

async fn consume_offer(state: &AppState, offer_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE device_pair_offers SET consumed = 1 WHERE offer_id = $1").bind(offer_id).execute(&state.db).await?;
    Ok(())
}

/// Is `offer_id` registered and unexpired at `now`?
async fn offer_live(state: &AppState, offer_id: &str, now: i64) -> Result<bool, ApiError> {
    let e: Option<i64> = sqlx::query_scalar("SELECT expires_at FROM device_pair_offers WHERE offer_id = $1").bind(offer_id).fetch_optional(&state.db).await?;
    Ok(e.is_some_and(|e| e >= now))
}

fn enabled(state: &AppState) -> Result<(), ApiError> {
    if state.qr_pairing { Ok(()) } else { Err(ApiError::NotFound) }
}

fn valid_offer_id(o: &str) -> bool {
    o.len() == 32 && o.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The bytes the claim signature covers (with op [`CLAIM_OP`], the account, the request id as
/// target, and the timestamp — `skwod_crypto::link::device_op_message`).
pub fn claim_payload(offer_id: &str, poll_secret: &[u8]) -> Vec<u8> {
    skwod_crypto::link::op_payload(&[offer_id.as_bytes(), &Sha256::digest(poll_secret)])
}

#[derive(Deserialize)]
pub struct OfferReq {
    offer_id: String,
    /// Unix milliseconds.
    expires_at: i64,
}

/// The payload an offer registration's device proof covers (op `pair-offer`, target offer id).
pub fn offer_payload(expires_at: i64, username: &str) -> Vec<u8> {
    skwod_crypto::link::op_payload(&[&expires_at.to_be_bytes(), username.as_bytes()])
}

/// The existing device registers the offer its QR shows, signed by that device.
pub async fn register_offer(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<OfferReq>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    state.limiter.check(&format!("e2ee_pair_offer:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    let now = now_ms();
    if !valid_offer_id(&req.offer_id) || req.expires_at <= now || req.expires_at > now + MAX_OFFER_TTL_MS + OFFER_SKEW_MS {
        return Err(ApiError::BadRequest("bad pair offer"));
    }
    let username: String = sqlx::query_scalar("SELECT username FROM profiles WHERE id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
    let device_id = crate::keydir::device_authority(&state, &auth, &headers, "pair-offer", &req.offer_id, &offer_payload(req.expires_at, &username)).await?;
    sweep(&state, now).await?;
    sqlx::query("INSERT INTO device_pair_offers (offer_id, user_id, device_id, username, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(&req.offer_id)
        .bind(&auth.user_id)
        .bind(&device_id)
        .bind(&username)
        .bind(req.expires_at.min(now + MAX_OFFER_TTL_MS))
        .bind(now)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct CreateReq {
    username: String,
    offer_id: String,
    identity_key: String,
    proof: String,
    /// 32 random bytes only the new device knows.
    poll_secret: String,
}

/// Open a pair request (no session). Accepted only for a registered, unexpired offer for that
/// username; everything else gets the same answer and stores nothing. Never replaces a request.
pub async fn create(
    State(state): State<AppState>,
    client: crate::client_key::ClientKey,
    Json(req): Json<CreateReq>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    client.limit_unauthenticated(&state, "pair", 30)?;
    let now = now_ms();
    let decoy = || Json(json!({ "request_id": new_id(), "expires_at": now + LINK_REQUEST_TTL_MS }));
    let (Ok(identity_key), Ok(proof), Ok(poll_secret)) = (b64_decode(&req.identity_key), b64_decode(&req.proof), b64_decode(&req.poll_secret)) else {
        return Ok(decoy());
    };
    let username = req.username.to_lowercase();
    if !crate::auth::is_valid_username(&username)
        || !valid_offer_id(&req.offer_id)
        || !skwod_crypto::certs::is_valid_identity_key(&identity_key)
        || proof.len() != 32
        || poll_secret.len() != 32
    {
        return Ok(decoy());
    }
    let poll_hash = Sha256::digest(&poll_secret).to_vec();
    sweep(&state, now).await?;

    let offer: Option<(String, i64, i64)> = sqlx::query_as("SELECT user_id, expires_at, consumed FROM device_pair_offers WHERE offer_id = $1 AND username = $2")
        .bind(&req.offer_id)
        .bind(&username)
        .fetch_optional(&state.db)
        .await?;
    let Some((user_id, _, consumed)) = offer.filter(|(_, e, _)| *e >= now) else { return Ok(decoy()) };

    // A request for this offer already exists: the same device retrying gets it back; anyone
    // else silently contests the offer (nobody will be approved), and replaces nothing.
    let existing: Option<(String, Vec<u8>, Vec<u8>)> =
        sqlx::query_as("SELECT id, identity_key, poll_hash FROM device_pair_requests WHERE offer_id = $1").bind(&req.offer_id).fetch_optional(&state.db).await?;
    if let Some((id, key, hash)) = existing {
        if key == identity_key && bool::from(hash.ct_eq(&poll_hash)) {
            return Ok(Json(json!({ "request_id": id, "expires_at": now + LINK_REQUEST_TTL_MS })));
        }
        // A consumed offer (approved, denied, registered) opens nothing and changes nothing.
        if consumed == 0 {
            contest(&state, &req.offer_id).await?;
        }
        return Ok(decoy());
    }
    if consumed != 0 {
        return Ok(decoy());
    }
    let id = new_id();
    let inserted = sqlx::query(
        "INSERT INTO device_pair_requests (id, offer_id, user_id, identity_key, proof, poll_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&req.offer_id)
    .bind(&user_id)
    .bind(&identity_key)
    .bind(&proof)
    .bind(&poll_hash)
    .bind(now)
    .execute(&state.db)
    .await;
    match inserted.map_err(ApiError::from) {
        Ok(_) => Ok(Json(json!({ "request_id": id, "expires_at": now + LINK_REQUEST_TTL_MS }))),
        // Lost a race to another request for the same offer: that is a contest too.
        Err(ApiError::Conflict(_)) => {
            contest(&state, &req.offer_id).await?;
            Ok(decoy())
        }
        Err(e) => Err(e),
    }
}

/// Two devices used one offer: nobody is approved, the offer is spent, and a session already
/// claimed for it (not yet registered) is revoked.
async fn contest(state: &AppState, offer_id: &str) -> Result<(), ApiError> {
    sqlx::query("UPDATE device_pair_requests SET contested = 1 WHERE offer_id = $1 AND registered = 0").bind(offer_id).execute(&state.db).await?;
    consume_offer(state, offer_id).await?;
    let claimed: Option<(String, Vec<u8>)> =
        sqlx::query_as("SELECT id, session_hash FROM device_pair_requests WHERE offer_id = $1 AND registered = 0 AND session_hash IS NOT NULL")
            .bind(offer_id)
            .fetch_optional(&state.db)
            .await?;
    if let Some((id, hash)) = claimed {
        revoke(state, &id, &hash).await?;
    }
    Ok(())
}

/// For the account's existing device: the request made for one of its offers.
pub async fn by_offer(State(state): State<AppState>, auth: AuthUser, Path(offer_id): Path<String>) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    state.limiter.check(&format!("e2ee_pair_read:{}", auth.user_id), 120, crate::limiter::MINUTE)?;
    let now = now_ms();
    let row: Option<(String, Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT r.id, r.identity_key, r.proof, r.contested, r.link_sig, r.nonce FROM device_pair_requests r
         JOIN device_pair_offers o ON o.offer_id = r.offer_id AND o.user_id = r.user_id
         WHERE r.offer_id = $1 AND r.user_id = $2 AND r.created_at >= $3 AND o.expires_at >= $4 AND r.denied = 0",
    )
    .bind(&offer_id)
    .bind(&auth.user_id)
    .bind(now - LINK_REQUEST_TTL_MS)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    let (id, identity_key, proof, contested, sig, nonce) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({
        "request_id": id,
        "identity_key": B64.encode(identity_key),
        "proof": B64.encode(proof),
        "contested": contested != 0,
        "revealed": nonce.is_some(),
        "approved": sig.is_some(),
    })))
}

#[derive(Deserialize)]
pub struct RevealReq {
    /// The requester key the existing device saw; must be the request's.
    identity_key: String,
    /// The nonce whose commitment the QR carries (32 bytes).
    nonce: String,
}

/// The existing device, having seen the request's identity key, releases its nonce for exactly
/// that key — once. Before this the new device has no nonce, so the emoji cannot be computed by
/// anyone choosing a key; after it, the key is fixed (a second request only contests).
pub async fn reveal(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(request_id): Path<String>,
    Json(req): Json<RevealReq>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    state.limiter.check(&format!("e2ee_pair_reveal:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    let device_id = auth.device_id.clone().ok_or(ApiError::BindRequired)?;
    require_bound_device_session(&state, &auth, &device_id).await?;
    let expected = b64_decode(&req.identity_key)?;
    let nonce = b64_decode(&req.nonce)?;
    if nonce.len() != 32 {
        return Err(ApiError::BadRequest("bad pair nonce"));
    }
    let now = now_ms();
    let row: Option<(String, Vec<u8>, i64, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT r.offer_id, r.identity_key, r.contested, r.nonce FROM device_pair_requests r
         JOIN device_pair_offers o ON o.offer_id = r.offer_id AND o.user_id = r.user_id
         WHERE r.id = $1 AND r.user_id = $2 AND r.created_at >= $3 AND o.expires_at >= $4 AND r.denied = 0 AND r.link_sig IS NULL",
    )
    .bind(&request_id)
    .bind(&auth.user_id)
    .bind(now - LINK_REQUEST_TTL_MS)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    let (_, identity_key, contested, existing) = row.ok_or(ApiError::NotFound)?;
    if contested != 0 {
        return Err(ApiError::Conflict("two devices used this code"));
    }
    if identity_key != expected {
        return Err(ApiError::BadRequest("bad pair reveal"));
    }
    match existing {
        Some(n) if bool::from(n.ct_eq(&nonce)) => return Ok(Json(json!({ "ok": true }))),
        Some(_) => return Err(ApiError::Conflict("already revealed")),
        None => {}
    }
    let done = sqlx::query("UPDATE device_pair_requests SET nonce = $1 WHERE id = $2 AND user_id = $3 AND nonce IS NULL AND contested = 0")
        .bind(&nonce)
        .bind(&request_id)
        .bind(&auth.user_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if done != 1 {
        return Err(ApiError::Conflict("two devices used this code"));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ApproveReq {
    #[serde(flatten)]
    approval: LinkApproval,
    /// The identity key whose emoji the person confirmed; must be the request's.
    identity_key: String,
}

/// The existing device approves exactly the confirmed identity key, once, if uncontested.
pub async fn approve(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(request_id): Path<String>,
    Json(req): Json<ApproveReq>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    state.limiter.check(&format!("e2ee_link:{}", auth.user_id), 10, crate::limiter::HOUR)?;
    let a = &req.approval;
    require_bound_device_session(&state, &auth, &a.device_id).await?;
    let approver_identity = own_device_identity(&state, &auth.user_id, &a.device_id).await?;
    let expected = b64_decode(&req.identity_key)?;
    let signature = b64_decode(&a.signature)?;
    let approval_mac = b64_decode(&a.approval_mac)?;
    let bundle = a.bundle.as_deref().map(b64_decode).transpose()?;
    if approval_mac.len() != 32 || bundle.as_ref().is_some_and(|b| b.len() > MAX_LINK_BUNDLE) {
        return Err(ApiError::BadRequest("bad pair approval"));
    }
    let now = now_ms();
    let row: Option<(String, Vec<u8>, i64, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT r.offer_id, r.identity_key, r.contested, r.nonce FROM device_pair_requests r
         JOIN device_pair_offers o ON o.offer_id = r.offer_id AND o.user_id = r.user_id
         WHERE r.id = $1 AND r.user_id = $2 AND r.created_at >= $3 AND o.expires_at >= $4 AND r.link_sig IS NULL AND r.denied = 0",
    )
    .bind(&request_id)
    .bind(&auth.user_id)
    .bind(now - LINK_REQUEST_TTL_MS)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    let (offer_id, identity_key, contested, nonce) = row.ok_or(ApiError::NotFound)?;
    if contested != 0 {
        return Err(ApiError::Conflict("two devices used this code"));
    }
    // The emoji the person compared include the nonce: nothing is approved before it was released.
    if nonce.is_none() {
        return Err(ApiError::BadRequest("pair nonce not revealed"));
    }
    if identity_key != expected || !skwod_crypto::link::verify_link(&approver_identity, &auth.user_id, &identity_key, &signature) {
        return Err(ApiError::BadRequest("bad pair approval"));
    }
    let done = sqlx::query(
        "UPDATE device_pair_requests SET approver_device_id = $1, approver_identity_key = $2, link_sig = $3, approval_mac = $4, approval_bundle = $5
         WHERE id = $6 AND user_id = $7 AND contested = 0 AND denied = 0 AND link_sig IS NULL",
    )
    .bind(&a.device_id)
    .bind(&approver_identity)
    .bind(&signature)
    .bind(&approval_mac)
    .bind(bundle)
    .bind(&request_id)
    .bind(&auth.user_id)
    .execute(&state.db)
    .await?
    .rows_affected();
    if done != 1 {
        return Err(ApiError::Conflict("two devices used this code"));
    }
    consume_offer(&state, &offer_id).await?;
    Ok(Json(json!({ "ok": true })))
}

/// The existing device refuses a request (the emoji did not match, or the person said no).
/// Only a session bound to a current device of the account may deny, and only so often.
pub async fn deny(State(state): State<AppState>, auth: AuthUser, Path(request_id): Path<String>) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    let device_id = auth.device_id.clone().ok_or(ApiError::BindRequired)?;
    require_bound_device_session(&state, &auth, &device_id).await?;
    state.limiter.check(&format!("e2ee_pair_deny:{}", auth.user_id), DENY_PER_HOUR, crate::limiter::HOUR)?;
    let offer: Option<String> = sqlx::query_scalar("SELECT offer_id FROM device_pair_requests WHERE id = $1 AND user_id = $2 AND link_sig IS NULL")
        .bind(&request_id)
        .bind(&auth.user_id)
        .fetch_optional(&state.db)
        .await?;
    // Marked, not deleted: the new device is told it was refused (on a signed claim).
    sqlx::query("UPDATE device_pair_requests SET denied = 1 WHERE id = $1 AND user_id = $2 AND link_sig IS NULL").bind(&request_id).bind(&auth.user_id).execute(&state.db).await?;
    if let Some(offer_id) = offer {
        consume_offer(&state, &offer_id).await?;
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ClaimReq {
    poll_secret: String,
    timestamp: i64,
    /// By the request's identity key over [`claim_payload`] (device-op [`CLAIM_OP`]).
    signature: String,
}

/// The new device polls: `approved: false` until approved; then the approval and ONE session,
/// only for the holder of the approved identity key (signature) AND the poll secret. A claim that
/// does not match a request (unknown id, wrong secret or signature) looks like "not yet" — the
/// same answer a decoy request id gets forever. Only the request's own device, proving its key,
/// learns that its offer was contested, denied or expired (404).
pub async fn claim(
    State(state): State<AppState>,
    client: crate::client_key::ClientKey,
    Path(request_id): Path<String>,
    Json(req): Json<ClaimReq>,
) -> Result<Json<Value>, ApiError> {
    enabled(&state)?;
    // No proof of work here, unlike the create: a claim tests nothing guessable (a 256-bit poll
    // secret AND a signature by the approved identity key), and the new device polls it every
    // couple of seconds — a stamp per poll would fill the spent-stamp record that guards
    // sign-ins. A plain per-caller window, as for invite checks.
    client.limit(&state, "pair_claim", 120)?;
    let not_yet = || Json(json!({ "approved": false }));
    let (Ok(secret), Ok(signature)) = (b64_decode(&req.poll_secret), b64_decode(&req.signature)) else { return Ok(not_yet()) };
    type Row = (String, String, Vec<u8>, Vec<u8>, i64, i64, i64, i64, Option<String>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT user_id, offer_id, identity_key, poll_hash, contested, claimed, denied, created_at, approver_device_id, approver_identity_key, link_sig, approval_mac, approval_bundle, nonce
         FROM device_pair_requests WHERE id = $1",
    )
    .bind(&request_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((user_id, offer_id, identity_key, poll_hash, contested, claimed, denied, created_at, device_id, approver, sig, mac, bundle, nonce)) = row else {
        return Ok(not_yet());
    };
    // Cheap checks first: an existing request whose poll secret matches. A flood of wrong guesses
    // ends here and charges nothing a real claimant needs.
    let hash = Sha256::digest(&secret).to_vec();
    if !bool::from(poll_hash.ct_eq(&hash)) {
        return Ok(not_yet());
    }
    // Then a ceiling on the signature checks one request can cost (only its holder gets here).
    state.limiter.check(&format!("pair_claim:request:{request_id}"), CLAIM_PER_REQUEST_PER_MINUTE, crate::limiter::MINUTE)?;
    let fresh = (req.timestamp - now_ms()).abs() <= CLAIM_SKEW_MS;
    let signed = fresh
        && u64::try_from(req.timestamp).is_ok_and(|ts| {
            skwod_crypto::link::verify_device_op(&identity_key, CLAIM_OP, &user_id, &request_id, ts, &claim_payload(&offer_id, &secret), &signature)
        });
    if !signed {
        return Ok(not_yet());
    }
    // From here on the caller is the request's own device.
    let now = now_ms();
    if contested != 0 || claimed != 0 || denied != 0 || created_at < now - LINK_REQUEST_TTL_MS || !offer_live(&state, &offer_id, now).await? {
        sweep(&state, now).await?;
        return Err(ApiError::NotFound);
    }
    let (Some(device_id), Some(approver), Some(sig), Some(mac)) = (device_id, approver, sig, mac) else {
        // Not approved yet; the existing device's nonce once it has seen this key.
        return Ok(Json(json!({ "approved": false, "nonce": nonce.map(|n| B64.encode(n)) })));
    };
    // The session exists before the row says it was claimed, and the row names it in the same
    // statement that claims it: a session is never handed out untracked, and a session whose
    // claim lost (a contest or a second claim in between) is deleted at once.
    let session = crate::auth::create_session(&state, &user_id).await?;
    let session_hash = crate::auth::token_hash(&session.token);
    let won = sqlx::query("UPDATE device_pair_requests SET claimed = 1, session_hash = $1 WHERE id = $2 AND claimed = 0 AND contested = 0 AND denied = 0 AND registered = 0")
        .bind(&session_hash)
        .bind(&request_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if won != 1 {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(&session_hash).execute(&state.db).await?;
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({
        "approved": true,
        "bundle": bundle.map(|b| B64.encode(b)),
        "device_id": device_id,
        "identity_key": B64.encode(approver),
        "signature": B64.encode(sig),
        "approval_mac": B64.encode(mac),
        "nonce": nonce.map(|n| B64.encode(n)),
        "session": session,
    })))
}

/// Contest `offer_id` directly (a race the HTTP path cannot stage deterministically).
#[cfg(test)]
pub(crate) async fn contest_for_tests(state: &AppState, offer_id: &str) {
    contest(state, offer_id).await.unwrap();
}
