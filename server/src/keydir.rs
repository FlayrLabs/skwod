//! Key directory — the server side of E2EE (ADR-004: public keys and ciphertext only; no private
//! key material ever lands here). Protocol v2 = Signal's libsignal (ADR-011).
//!
//! - **Devices + prekeys** in libsignal's formats: identity key, signed EC prekey, last-resort
//!   Kyber-1024 prekey, one-time EC + Kyber prekeys. Every signature is verified on upload.
//! - **Prekey bundles**: served only to accounts that share a server or a DM with the target,
//!   rate-limited per caller and per (caller, target); one-time keys are claimed atomically and the
//!   last-resort Kyber key is served once they run out (never a non-PQ bundle).
//! - **Sealed-sender certificates**: libsignal `SenderCertificate`s chained to a trust root that the
//!   instance's invite-pinned Ed25519 key vouches for.
//! - **Sealed mailbox**: a per-device queue of sealed-sender envelopes. Depositing takes no
//!   credentials (only the recipient's delivery key), so the server does not learn who sent what.
//! - Passphrase key backup, registration lock, key-transparency log, device attestation.
//!
//! Binary fields travel as base64 in JSON.

// Row-shaped tuples from sqlx look "complex" to clippy but are the idiomatic untyped-query form.
#![allow(clippy::type_complexity)]

use axum::extract::{Path, Query, State};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use skwod_crypto::certs::{self, CertAuthority};
use skwod_crypto::{DeviceAddress, PROTOCOL_VERSION};
use subtle::ConstantTimeEq;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::{new_id, now_ms, AppState};

const MAX_DEVICES_PER_USER: i64 = 5;
const MAX_PREKEYS_PER_UPLOAD: usize = 100;
pub(crate) const PIN_MAX_ATTEMPTS: i64 = 5;
const PIN_LOCK_MS: i64 = 15 * 60 * 1000;
/// How long an un-authenticated-by-second-factor device reset waits, so the account's existing
/// devices can see and cancel it (Signal's registration-lock expiry is the same length).
pub(crate) const RESET_DELAY_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Accepted clock skew on signed device operations.
const DEVICE_OP_WINDOW_MS: i64 = 10 * 60 * 1000;
/// Sender-certificate lifetime. A certificate keeps working until it expires even if its device
/// is removed from the account meanwhile, so this is how long a removed device can still deposit
/// sealed envelopes "as" that account: kept short. (Clients refresh with an hour to spare, and
/// independently drop anything from a device the directory no longer lists.)
const CERTIFICATE_TTL_MS: u64 = 6 * 60 * 60 * 1000;
/// The instance's Ed25519 identity (what invites pin). Name kept from v1 so existing instances
/// keep the identity their members already pinned.
const SERVER_SIGNING_SECRET_NAME: &str = "sealed_sender_signing_v1";
/// The libsignal certificate authority (trust root + server certificate), postcard-free: four
/// length-prefixed fields.
const CERT_AUTHORITY_SECRET_NAME: &str = "sealed_sender_authority_v2";

/// Largest sealed envelope accepted (bytes). Envelopes are padded message bodies or key hand-offs.
const MAX_ENVELOPE: usize = 256 * 1024;
/// Envelopes a single deposit request may carry (one message fanned out to a group's devices).
const MAX_ENVELOPES_PER_SEND: usize = 256;
/// Undelivered envelopes kept per device; deposits beyond this are refused (mailbox-flood bound).
const MAX_MAILBOX: i64 = 5_000;
/// Undelivered BYTES kept per device. 5,000 envelopes of 256 KiB would be 1.2 GiB per device;
/// real mail is a few hundred bytes to a few KiB (a DM, a sender key, a call key), and the rare
/// large one (a DM carrying a thumbnail) is still far under this in any number a person sends.
const MAX_MAILBOX_BYTES: i64 = 64 * 1024 * 1024;
/// Deposit REQUESTS one source may make per minute (a message fanned out to a group is one
/// request of up to 256 envelopes).
const SEALED_REQUESTS_PER_MINUTE: u32 = 240;
/// Once a mailbox is this full its device is clearly not reading (offline, or being flooded)…
const MAILBOX_CROWDED: i64 = MAX_MAILBOX / 2;
/// …and from then on ONE source may add only this many more envelopes to it per day. Deposits
/// are anonymous, so what is already queued cannot be attributed to anyone and nothing can be
/// evicted fairly — evicting the oldest would let a flooder push out exactly the real mail that
/// arrived before the flood. So the newest is refused, as before, but a single source can no
/// longer take the whole box: after it has filled its share, the rest stays free for everyone
/// else. (Counted per source address or p2p node, in memory only; never stored with an
/// envelope, so the mailbox still records nothing about who deposited what.)
const CROWDED_PER_SOURCE_PER_DAY: u32 = 500;
/// Undelivered envelopes older than this are dropped.
const MAILBOX_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
const INBOX_PAGE: i64 = 200;

pub fn routes() -> Router<AppState> {
    use axum::routing::{delete, get, post, put};
    Router::new()
        .route("/devices", get(list_devices))
        .route("/devices/register", post(register_device))
        .route("/devices/:device_id", delete(delete_device))
        .route("/devices/reset/cancel", post(cancel_reset))
        .route("/devices/:device_id/rekey", post(rekey_device))
        .route("/devices/:device_id/delivery-key", put(rotate_delivery_key))
        .route("/devices/:device_id/bind", post(bind_session))
        .route("/devices/:device_id/recovery/approve", post(approve_recovery))
        .route("/devices/:device_id/recovery/cancel", post(cancel_recovery))
        .route("/devices/:device_id/name", put(set_device_name))
        .route("/link-requests", post(create_link_request).get(list_link_requests))
        .route("/link-requests/:request_id", get(get_link_request))
        .route("/link-requests/:request_id/approve", post(approve_link_request))
        .route("/pair-offers", post(crate::pairing::register_offer))
        .route("/pair-requests", post(crate::pairing::create))
        .route("/pair-requests/by-offer/:offer_id", get(crate::pairing::by_offer))
        .route("/pair-requests/:request_id", delete(crate::pairing::deny))
        .route("/pair-requests/:request_id/reveal", post(crate::pairing::reveal))
        .route("/pair-requests/:request_id/approve", post(crate::pairing::approve))
        .route("/pair-requests/:request_id/claim", post(crate::pairing::claim))
        .route("/users/:user_id/devices", get(user_devices))
        .route("/member-devices", get(member_devices))
        .route("/prekey-bundle", post(prekey_bundle))
        .route("/prekeys/replenish", post(replenish_prekeys))
        .route("/prekeys/count", get(prekey_count))
        .route("/spk/rotate", post(rotate_spk))
        .route("/trust-root", get(trust_root))
        .route("/certificates", post(issue_cert))
        .route("/sealed/send", post(sealed_send))
        .route("/sealed/inbox", get(sealed_inbox))
        .route("/sealed/ack", post(sealed_ack))
        .route("/key-backup", put(put_backup).get(get_backup).delete(delete_backup))
        .route("/key-backup/request", post(request_backup))
        .route("/key-backup/challenge", post(backup_challenge))
        .route("/key-backup/compromised", post(recovery_key_compromised))
        .route("/devices/tombstones/remove", post(remove_tombstoned_device))
        .route("/registration-pin", post(set_registration_pin))
}

// ---- helpers ----

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(s).map_err(|_| ApiError::BadRequest("invalid base64"))
}

/// Ensure `device_id` belongs to `user_id`; returns the device's identity key.
pub(crate) async fn own_device_identity(state: &AppState, user_id: &str, device_id: &str) -> Result<Vec<u8>, ApiError> {
    sqlx::query_scalar("SELECT identity_key FROM user_devices WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Do `a` and `b` already know each other, as far as this server can tell? True when they share
/// a server, or share a conversation in which BOTH have written. A conversation row alone is
/// not enough: one side creates it without the other's consent, so it proves nothing about the
/// other side (and used to be how a stranger unlocked a member's keys).
pub(crate) async fn knows(state: &AppState, a: &str, b: &str) -> Result<bool, ApiError> {
    if a == b {
        return Ok(true);
    }
    // One CASE folding both EXISTS: `bigint OR boolean` is invalid on Postgres.
    let known: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(
             SELECT 1 FROM server_members x JOIN server_members y ON x.server_id = y.server_id
             WHERE x.user_id = $1 AND y.user_id = $2)
         OR EXISTS(
             SELECT 1 FROM dm_participants x JOIN dm_participants y ON x.conversation_id = y.conversation_id
             WHERE x.user_id = $3 AND y.user_id = $4
               AND EXISTS(SELECT 1 FROM dm_messages m WHERE m.conversation_id = x.conversation_id AND m.author_id = $5)
               AND EXISTS(SELECT 1 FROM dm_messages m WHERE m.conversation_id = x.conversation_id AND m.author_id = $6))
         THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(a)
    .bind(b)
    .bind(a)
    .bind(b)
    .bind(a)
    .bind(b)
    .fetch_one(&state.db)
    .await?;
    Ok(known == 1)
}

/// Is `decider` someone who decides on a PENDING join request of `requester` — the owner of that
/// server, or a member of it who may manage invites?
pub(crate) async fn decides_join_of(state: &AppState, decider: &str, requester: &str) -> Result<bool, ApiError> {
    let servers: Vec<(String, String)> = sqlx::query_as(
        "SELECT s.id, s.owner_id FROM join_requests r JOIN servers s ON s.id = r.server_id WHERE r.status = 'pending' AND r.user_id = $1",
    )
    .bind(requester)
    .fetch_all(&state.db)
    .await?;
    for (server_id, owner_id) in servers {
        if owner_id == decider {
            return Ok(true);
        }
        if crate::structure::is_server_member(state, &server_id, decider).await? {
            let p = crate::structure::effective_permissions(state, &server_id, decider, None).await?;
            if crate::perms::has_permission(p, crate::perms::MANAGE_INVITES) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// May `caller` start an E2EE session with `target`? Only if they are the same account, already
/// know each other ([`knows`]), or `caller` is deciding on `target`'s pending join request (the
/// host reads the newcomer's fingerprint and, once it has let them in, sends them the keys).
/// NOT the other way round: an account in the waiting room has no claim on the host's prekeys.
/// Without this, any account on the instance could pull (and burn) any other account's one-time
/// prekeys and learn its device list.
async fn may_contact(state: &AppState, caller: &str, target: &str) -> Result<bool, ApiError> {
    if caller == target {
        return Ok(true);
    }
    // A block (either direction) cuts off key material: the blocked party can no longer start a
    // session with, or learn the delivery key of, the other's devices. Sealed deposits carry no
    // sender, so THIS is where a block is enforced server-side (see `rotate_delivery_key`).
    if crate::safety::pair_blocked(state, caller, target).await? {
        return Ok(false);
    }
    Ok(knows(state, caller, target).await? || decides_join_of(state, caller, target).await?)
}

/// THE gate for key material. Every endpoint that hands out a prekey bundle, a delivery key or an
/// identity key for another account goes through this (directly, or via [`directory_devices`]) —
/// so "may this caller reach that account" has exactly one answer, and a block cuts off every
/// path at once (bundle fetch, per-user device list, per-server member-device list).
async fn require_contact(state: &AppState, caller: &str, target: &str) -> Result<(), ApiError> {
    if may_contact(state, caller, target).await? {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// The directory entries (device id, delivery key, identity key, link proof) of `target`'s devices
/// as visible to `caller`, or `None` when `caller` may not contact `target` at all.
async fn directory_devices(state: &AppState, caller: &str, target: &str) -> Result<Option<Vec<Value>>, ApiError> {
    if !may_contact(state, caller, target).await? {
        return Ok(None);
    }
    let rows: Vec<(String, Vec<u8>, Vec<u8>, Option<String>, Option<Vec<u8>>, i64)> = sqlx::query_as(
        "SELECT device_id, delivery_key, identity_key, linked_by, link_sig, generation FROM user_devices WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(target)
    .fetch_all(&state.db)
    .await?;
    Ok(Some(
        rows.into_iter()
            .map(|(device_id, delivery_key, identity_key, linked_by, link_sig, generation)| {
                json!({
                    "user_id": target,
                    "device_id": device_id,
                    // Which install of the device this is: it rises when the device is
                    // restored onto another install, and a peer that sees it rise rotates what
                    // the old install held.
                    "generation": generation,
                    "delivery_key": B64.encode(delivery_key),
                    "identity_key": B64.encode(identity_key),
                    "linked_by": linked_by,
                    "link_sig": link_sig.map(|s| B64.encode(s)),
                })
            })
            .collect(),
    ))
}

/// A client that does not announce protocol v2 is a pre-libsignal build. Tell it so explicitly
/// instead of failing its requests in confusing ways.
fn require_protocol(version: Option<u32>) -> Result<(), ApiError> {
    match version {
        Some(v) if v == PROTOCOL_VERSION => Ok(()),
        Some(v) if v > PROTOCOL_VERSION => Err(ApiError::UpgradeRequired("this server is older than your app; ask the host to update skwod")),
        _ => Err(ApiError::UpgradeRequired("update required: this skwod now uses the Signal protocol; update the app to keep chatting")),
    }
}

/// Header carrying a device proof: `<unix-ms timestamp>.<base64 signature>`. (A header, not the
/// query string: query strings end up in access logs.)
pub(crate) const DEVICE_PROOF_HEADER: &str = "x-skwod-device-proof";

/// Proof that an account-security request comes from a device currently on the account, not
/// merely from a session token. True only if the header carries a signature that is
/// - fresh (within `DEVICE_OP_WINDOW_MS`),
/// - by the identity key of a device currently registered on the account,
/// - over exactly this (`op`, account, `target`) **and this request's `payload`** — so it cannot be
///   re-used with different contents, and
/// - not seen before: every accepted signature is recorded and refused a second time.
///
/// Returns WHICH of the account's devices signed (its device id), or `None`.
pub(crate) async fn device_proof_signer(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    user_id: &str,
    op: &str,
    target: &str,
    payload: &[u8],
) -> Result<Option<String>, ApiError> {
    let Some((timestamp, signature)) = headers
        .get(DEVICE_PROOF_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once('.'))
        .and_then(|(ts, sig)| Some((ts.parse::<i64>().ok()?, B64.decode(sig).ok()?)))
    else {
        return Ok(None);
    };
    let now = now_ms();
    if timestamp < 0 || (now - timestamp).abs() > DEVICE_OP_WINDOW_MS {
        return Ok(None);
    }
    let identities: Vec<(String, Vec<u8>)> =
        sqlx::query_as("SELECT device_id, identity_key FROM user_devices WHERE user_id = $1").bind(user_id).fetch_all(&state.db).await?;
    let Some(signer) = identities
        .into_iter()
        .find(|(_, ik)| skwod_crypto::link::verify_device_op(ik, op, user_id, target, timestamp as u64, payload, &signature))
        .map(|(device, _)| device)
    else {
        return Ok(None);
    };
    // Single use. The record is keyed on WHAT WAS SIGNED (op, account, target, timestamp, payload
    // hash), not on the signature bytes: a signature can be re-encoded, and the signer can produce
    // many signatures for one message, but none of them is a new authorization. (Non-canonical
    // encodings are also refused outright by `verify_device_op`.) The primary key makes "first
    // one wins" atomic; rows outlive the freshness window.
    sqlx::query("DELETE FROM device_op_proofs WHERE expires_at < $1").bind(now).execute(&state.db).await?;
    let recorded = sqlx::query("INSERT INTO device_op_proofs (proof_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hex::encode(skwod_crypto::link::device_op_id(op, user_id, target, timestamp as u64, payload)))
        .bind(user_id)
        .bind(timestamp + 2 * DEVICE_OP_WINDOW_MS)
        .execute(&state.db)
        .await;
    Ok(recorded.is_ok().then_some(signer))
}

// ---- which install may act as a device (the anti-clone rule) ----
//
// THREAT. Someone holds a copy of a device's IDENTITY KEY — lifted from a stolen key-backup
// file whose passphrase they have, or from a cloned disk image — and has (or can get) a session
// for the account. They do NOT hold the live install's *install secret*: 32 random bytes made on
// the install, never backed up, never sent to a sibling, of which the server keeps only a hash.
// With the identity key alone they can produce any device proof. That must not be enough to
// act as the device, to replace its keys, to remove devices, or to touch the account's
// recovery settings.
//
// RULES.
//
// 1. A device row carries a `generation` and an `install_hash`. A SESSION records, server-side,
//    the device and generation it was bound at; nothing the client later says about either is
//    read. A session is bound in exactly three ways: it registered the device, it completed a
//    re-key of it, or it presented the install secret together with the device's signature
//    (`bind_session`).
//
// 2. Every device-scoped request goes through [`require_device_session`]: the caller's session
//    must be bound to that device at its CURRENT generation.
//
// 3. Every account-security MUTATION (delete a device, cancel a reset, rotate keys, set the
//    PIN, write or delete the backup, change the password, approve a link / a recovery / a
//    member) goes through [`device_authority`]: (a) a payload-bound device proof, AND (b) the
//    caller's session bound to the SIGNING device at its current generation. A proof signed
//    with a copied key therefore authorizes nothing — on that device's own routes or, via the
//    "any device of the account may sign" routes, on a sibling's.
//
// 4. A re-key by an install WITHOUT the current install secret is not a re-key but a RECOVERY
//    (`rekey_device`). It completes AT ONCE for whoever proves the RECOVERY KEY (a signature,
//    over a server nonce, by the key derived from the backup key — `recovery_key_proven`): the
//    recovery key is the one strong secret only the owner holds, and it is what a restore is.
//    Like the registration PIN it only counts once SEASONED: the verifier must have been in
//    place for the length of the hold. Otherwise whoever briefly holds an unlocked device
//    could plant a recovery key of their own (`backup-put` needs only that device's current
//    install) and restore with it from anywhere at once.
//    Recovery keys live in an append-only history that no backup write and no backup delete
//    can erase: `backup_keys` (one row per key) and `backup_blobs` (the backup contents sealed
//    under a key, every version, never rewritten). Whether a key is valid is decided ONLY by
//    its `backup_keys` row; a blob is served only while its key is valid — it has no validity
//    of its own and cannot keep a key alive. How a key leaves force:
//    - CHANGED by a backup write or delete (no device was removed): if it was seasoned it stays
//      good for ONE immediate restore during one more hold period (the overlap) — the owner,
//      who holds it, can take the account back while the key that replaced it is too young to
//      be used. That restore CONSUMES it: it retires, the newer unseasoned key is cancelled,
//      and the account has no recovery key until a new one is saved (which seasons from zero).
//      An overlap never brings a key back into force. An UNSEASONED key that is replaced is
//      retired on the spot: no proof by it counts and none of its blobs is served.
//    - COMPROMISED: a device was removed from the account, an erased device was reported lost,
//      or the user said "my recovery key is compromised". EVERY key still in force or in its
//      overlap is retired AT ONCE: never served, never accepted, never un-retired. The
//      remaining devices are told to save a new one.
//    - Same key, new backup contents: a new blob under the same key (the key's age is
//      unchanged); earlier versions stay restorable for the hold period.
//    Later changes never touch a row that already left force. Every change, delete and
//    retirement is announced to all devices. There is no undo to attack.
//    Challenges are per session and consumed only by a valid proof, so a second session
//    cannot burn the owner's.
//    Without it — a copy of the identity key and a session, nothing more — it completes only
//    with approval by a current device of the account (`approve_recovery`), the registration
//    PIN, or a 7-day hold during which every current device is notified and can cancel
//    (`cancel_recovery`). The same proof seats a FRESH device row when the backed-up device
//    was erased (`register_device`, "recovered" admission). When it completes the
//    generation goes up and the new install's secret replaces the old: every session of the
//    previous install is refused with 409 `device superseded` from then on, and cannot bind
//    again.
//
//    A recovery is completed by the install that ASKED for it and nobody else: the pending
//    request stores SHA-256 of that install's secret, the completing re-key must present the
//    secret itself, and the hash is never returned by any route. Approving and refusing
//    devices sign a random, server-issued request id — not the hash — so listing an account's
//    devices (which any session of the account may do, the copied-key holder included) yields
//    nothing that completes, approves or redirects a recovery.
//
// 5. `install_hash` is REQUIRED at registration and re-key. The only sessions allowed to act
//    unbound are those using a device row that existed before this scheme (`legacy_unbound`,
//    set by the migration, never afterwards) — and only for the device's ordinary traffic
//    (mailbox, certificate, posting), so a build that predates binding keeps working. An
//    unbound session is NEVER enough for rule 3 or for a re-key: those need a bound session,
//    or go through recovery (rule 4). A legacy row is bound once, and only by a session that
//    already existed when the migration ran (`sessions.pre_migration`): a sign-in made
//    afterwards cannot claim it. Everything else fails closed.
//
// 6. A new device joins only through the link-request flow: the approval is recorded by a
//    session of the LINKER's current install (rule 2), and registration consumes that recorded
//    approval. A link signature presented inline — which a copied identity key can produce —
//    admits nobody.
//
// ASSUMPTION. A current, UNLOCKED device of the account is fully authoritative — as a linked
// device is in Signal. Whoever holds one can change the recovery key, remove devices, read
// everything. The protocol does not try to defend against a current device from the inside;
// the mitigations for a stolen unlocked phone are the app lock and REMOVING it from another
// device (which also retires the recovery key, above). What the rules do ensure is that what
// such a holder sets up for LATER — a planted recovery key — cannot be used at once, is
// announced, and dies when the device is removed or the owner restores.
//
// What this does not do: stop someone who holds BOTH the identity key and the install secret
// (a full, current disk clone). Nothing server-side can tell two such installs apart.

/// Rule 2: may this session act as `device_id`?
/// - device not registered → `DeviceRemoved`;
/// - session bound to another device → `Forbidden`;
/// - session bound to this device at an older generation → `DeviceSuperseded` (409);
/// - session bound to no device → allowed only for a `legacy_unbound` row; else `BindRequired`.
pub(crate) async fn require_device_session(state: &AppState, auth: &AuthUser, device_id: &str) -> Result<(), ApiError> {
    let row: Option<(i64, i64)> = sqlx::query_as("SELECT generation, legacy_unbound FROM user_devices WHERE user_id = $1 AND device_id = $2")
        .bind(&auth.user_id)
        .bind(device_id)
        .fetch_optional(&state.db)
        .await?;
    let Some((current, legacy_unbound)) = row else { return Err(ApiError::DeviceRemoved) };
    match (&auth.device_id, auth.device_generation) {
        (Some(bound), _) if bound != device_id => Err(ApiError::Forbidden),
        (Some(_), Some(g)) if g == current => Ok(()),
        (Some(_), _) => Err(ApiError::DeviceSuperseded),
        (None, _) if legacy_unbound != 0 => Ok(()),
        (None, _) => Err(ApiError::BindRequired),
    }
}

/// Rule 2 without the legacy exception: the session must be BOUND to `device_id` at its current
/// generation. What rule 3 and a re-key require.
pub(crate) async fn require_bound_device_session(state: &AppState, auth: &AuthUser, device_id: &str) -> Result<(), ApiError> {
    require_device_session(state, auth, device_id).await?;
    if auth.device_id.as_deref() == Some(device_id) {
        Ok(())
    } else {
        Err(ApiError::BindRequired)
    }
}

/// Rule 3: authorize an account-security mutation. Returns the SIGNING device's id.
/// (a) the header carries a fresh, single-use proof over exactly (`op`, account, `target`,
///     `payload`) by the identity key of a device currently on the account; and
/// (b) the calling session is bound to that signing device at its current generation.
pub(crate) async fn device_authority(
    state: &AppState,
    auth: &AuthUser,
    headers: &axum::http::HeaderMap,
    op: &str,
    target: &str,
    payload: &[u8],
) -> Result<String, ApiError> {
    let signer = device_proof_signer(state, headers, &auth.user_id, op, target, payload).await?.ok_or(ApiError::Forbidden)?;
    require_bound_device_session(state, auth, &signer).await?;
    Ok(signer)
}

/// Authorize a DESTRUCTIVE or instance-wide action that is not an account-security mutation:
/// wiping a channel or a space, deleting a space, pointing voice at another SFU (audit M-3 —
/// a bare session token used to be enough for all of them).
///
/// - The account has no device yet → the token is all there is (a host setting up).
/// - The request carries a device proof (`x-skwod-device-proof`) → it must hold, exactly as
///   for [`device_authority`]: over (`op`, account, `target`, `payload`), by a device of the
///   account, from the session bound to that device's current install.
/// - No proof → the calling session must at least BE a current install of one of the
///   account's devices: a password-only sign-in, a token out of an old backup and a superseded
///   install are refused. With `SKWOD_REQUIRE_DEVICE_PROOFS=1` (once every client signs these
///   requests) the proof is required and a bound session alone is refused too.
pub(crate) async fn destructive_authority(
    state: &AppState,
    auth: &AuthUser,
    headers: &axum::http::HeaderMap,
    op: &str,
    target: &str,
    payload: &[u8],
) -> Result<(), ApiError> {
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
    if devices == 0 {
        return Ok(());
    }
    if headers.contains_key(DEVICE_PROOF_HEADER) || state.require_device_proofs {
        return device_authority(state, auth, headers, op, target, payload).await.map(|_| ());
    }
    let device = auth.device_id.as_deref().ok_or(ApiError::BindRequired)?;
    require_bound_device_session(state, auth, device).await
}

/// Point the calling session at `device_id` at `generation` (it registered, restored or proved
/// that install of the device).
async fn bind_session_to(db: impl sqlx::Executor<'_, Database = sqlx::Any>, auth: &AuthUser, device_id: &str, generation: i64) -> Result<(), ApiError> {
    let bound = sqlx::query("UPDATE sessions SET device_id = $1, device_generation = $2 WHERE token_hash = $3 AND user_id = $4")
        .bind(device_id)
        .bind(generation)
        .bind(&auth.session_hash)
        .bind(&auth.user_id)
        .execute(db)
        .await?
        .rows_affected();
    // The session was revoked (or expired away) while the request was in flight: bind nothing.
    if bound != 1 {
        return Err(ApiError::Unauthorized);
    }
    Ok(())
}

/// A register / rekey body's `install_hash`: 32 bytes, base64.
fn install_hash_of(field: Option<&str>) -> Result<Option<Vec<u8>>, ApiError> {
    match field.map(b64_decode).transpose()? {
        Some(h) if h.len() != 32 => Err(ApiError::BadRequest("install_hash must be 32 bytes")),
        other => Ok(other),
    }
}

// ---- key uploads ----

#[derive(Deserialize)]
pub struct SignedKeyUpload {
    pub id: u32,
    pub public: String,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct PrekeyUpload {
    pub id: u32,
    pub public: String,
}

struct SignedKey {
    id: u32,
    public: Vec<u8>,
    signature: Vec<u8>,
}

/// The public keys of one uploaded batch as one length-prefixed blob (a field of a device-proof
/// payload). Clients build the same bytes from the keys they generated.
fn keys_digest_input<'a>(keys: impl Iterator<Item = &'a [u8]>) -> Vec<u8> {
    let keys: Vec<&[u8]> = keys.collect();
    skwod_crypto::link::op_payload(&keys)
}

/// Decode a signed prekey upload and verify its signature under `identity_key`.
fn verified_signed_key(identity_key: &[u8], up: &SignedKeyUpload, kyber: bool) -> Result<SignedKey, ApiError> {
    let public = b64_decode(&up.public)?;
    let signature = b64_decode(&up.signature)?;
    if !certs::verify_prekey_signature(identity_key, &public, &signature, kyber) {
        return Err(ApiError::BadRequest(if kyber { "bad kyber prekey signature" } else { "bad signed prekey signature" }));
    }
    Ok(SignedKey { id: up.id, public, signature })
}

struct OneTimeKeys {
    ec: Vec<(u32, Vec<u8>)>,
    kyber: Vec<SignedKey>,
}

fn verified_one_time_keys(identity_key: &[u8], ec: &[PrekeyUpload], kyber: &[SignedKeyUpload]) -> Result<OneTimeKeys, ApiError> {
    if ec.len() > MAX_PREKEYS_PER_UPLOAD || kyber.len() > MAX_PREKEYS_PER_UPLOAD {
        return Err(ApiError::BadRequest("at most 100 one-time prekeys of each kind per upload"));
    }
    let mut ec_out = Vec::with_capacity(ec.len());
    for pk in ec {
        let public = b64_decode(&pk.public)?;
        if !certs::is_valid_public_key(&public) {
            return Err(ApiError::BadRequest("bad one-time prekey"));
        }
        ec_out.push((pk.id, public));
    }
    let kyber_out = kyber.iter().map(|k| verified_signed_key(identity_key, k, true)).collect::<Result<Vec<_>, _>>()?;
    Ok(OneTimeKeys { ec: ec_out, kyber: kyber_out })
}

async fn insert_one_time_keys(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    user_id: &str,
    device_id: &str,
    keys: &OneTimeKeys,
    now: i64,
) -> Result<(), ApiError> {
    for (key_id, public) in &keys.ec {
        sqlx::query(
            "INSERT INTO one_time_prekeys (id, user_id, device_id, kind, key_id, public_key, signature, used, created_at)
             VALUES ($1, $2, $3, 'ec', $4, $5, NULL, 0, $6)",
        )
        .bind(new_id())
        .bind(user_id)
        .bind(device_id)
        .bind(*key_id as i64)
        .bind(public)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    for k in &keys.kyber {
        sqlx::query(
            "INSERT INTO one_time_prekeys (id, user_id, device_id, kind, key_id, public_key, signature, used, created_at)
             VALUES ($1, $2, $3, 'kyber', $4, $5, $6, 0, $7)",
        )
        .bind(new_id())
        .bind(user_id)
        .bind(device_id)
        .bind(k.id as i64)
        .bind(&k.public)
        .bind(&k.signature)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Remove one device and everything keyed to it.
async fn purge_device(tx: &mut sqlx::Transaction<'_, sqlx::Any>, user_id: &str, device_id: &str) -> Result<u64, ApiError> {
    let deleted = sqlx::query("DELETE FROM user_devices WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
    crate::push::forget_device(tx, user_id, device_id).await?;
    // The sessions that spoke for this device are over: a removed device is signed out.
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND device_id = $2").bind(user_id).bind(device_id).execute(&mut **tx).await?;
    for table in ["one_time_prekeys", "sealed_envelopes", "device_recoveries"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id = $1 AND device_id = $2"))
            .bind(user_id)
            .bind(device_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(deleted)
}

// ---- device registration ----

#[derive(Deserialize)]
pub struct RegisterDeviceRequest {
    pub device_name_ciphertext: Option<String>,
    pub registration_id: Option<u32>,
    pub identity_key: Option<String>,
    pub signed_prekey: Option<SignedKeyUpload>,
    pub last_resort_kyber_prekey: Option<SignedKeyUpload>,
    #[serde(default)]
    pub one_time_prekeys: Vec<PrekeyUpload>,
    #[serde(default)]
    pub one_time_kyber_prekeys: Vec<SignedKeyUpload>,
    /// 32 random bytes: the capability needed to deposit sealed envelopes for this device.
    pub delivery_key: Option<String>,
    /// Account reset: wipe every device and register this one as the only device. Needs the
    /// registration-lock PIN, or goes through the cancellable waiting period.
    #[serde(default)]
    pub force: bool,
    pub pin: Option<String>,
    /// SHA-256 of this install's secret (see `bind_session`).
    pub install_hash: Option<String>,
    /// A restore whose device row is gone (the device was erased): proof of the recovery key
    /// (see `recovery_key_proven`), signed for purpose `"register"` and this identity key.
    pub recovery_auth: Option<String>,
    /// The registration-lock PIN is lost. The reset then goes through the cancellable waiting
    /// period, exactly as if no PIN had been set (Signal's registration lock lapses the same way).
    #[serde(default)]
    pub forgot_pin: bool,
    /// Required for every device after the account's first: an existing device's vouching.
    pub link: Option<LinkProof>,
}

#[derive(Deserialize)]
pub struct LinkProof {
    /// The existing device that vouches for the new one.
    pub device_id: String,
    /// That device's identity-key signature over (account, new identity key) — see
    /// `skwod_crypto::link`.
    pub signature: String,
}

/// Registration-lock check: Argon2id-verified PIN with attempt counting and lockout.
pub(crate) async fn verify_registration_pin(state: &AppState, user_id: &str, pin: Option<&str>) -> Result<(), ApiError> {
    let row: Option<(Option<String>, i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT registration_pin_hash, registration_lock_enabled, pin_attempt_count, pin_locked_until
         FROM profiles WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((stored_hash, lock_enabled, attempts, locked_until)) = row else {
        return Err(ApiError::NotFound);
    };
    if lock_enabled == 0 {
        return Ok(());
    }
    let now = now_ms();
    if let Some(until) = locked_until.filter(|t| *t > now) {
        return Err(ApiError::PinIncorrect { attempts_left: 0, locked_until: Some(until) });
    }
    let stored = stored_hash.ok_or(ApiError::Forbidden)?;
    let presented = pin.filter(|p| !p.is_empty()).ok_or(ApiError::PinRequired)?;
    let _ = attempts;
    // The attempt is taken BEFORE the PIN is looked at, in one conditional UPDATE (audit M-5).
    // The counter used to be read, Argon2 run, and the counter written: a burst of parallel
    // requests all read the same count and got many guesses inside one "5 attempts" window.
    // Now each guess has to win one of the attempts that are left before it is verified at
    // all; a burst gets exactly as many verifications as a patient attacker.
    let taken: Option<i64> = sqlx::query_scalar(
        "UPDATE profiles SET pin_attempt_count = pin_attempt_count + 1
          WHERE id = $1 AND pin_attempt_count < $2 AND (pin_locked_until IS NULL OR pin_locked_until <= $3)
         RETURNING pin_attempt_count",
    )
    .bind(user_id)
    .bind(PIN_MAX_ATTEMPTS)
    .bind(now)
    .fetch_optional(&state.db)
    .await?;
    let lock = || async {
        let until = now + PIN_LOCK_MS;
        sqlx::query("UPDATE profiles SET pin_attempt_count = 0, pin_locked_until = $1 WHERE id = $2").bind(until).bind(user_id).execute(&state.db).await?;
        Ok::<_, ApiError>(ApiError::PinIncorrect { attempts_left: 0, locked_until: Some(until) })
    };
    // Every attempt is taken (by guesses still being verified): this one is not looked at.
    let Some(attempts) = taken else { return Err(lock().await?) };
    if crate::auth::verify_secret(presented, &stored) {
        sqlx::query("UPDATE profiles SET pin_attempt_count = 0, pin_locked_until = NULL WHERE id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await?;
        Ok(())
    } else if attempts >= PIN_MAX_ATTEMPTS {
        Err(lock().await?)
    } else {
        Err(ApiError::PinIncorrect { attempts_left: PIN_MAX_ATTEMPTS - attempts, locked_until: None })
    }
}

async fn register_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(raw): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    // Check the protocol generation on the raw JSON BEFORE shape-checking the body: a protocol-v1
    // client sends differently-shaped fields, and it must get "update required", not a 422.
    require_protocol(raw.get("protocol_version").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()))?;
    let req: RegisterDeviceRequest = serde_json::from_value(raw).map_err(|_| ApiError::BadRequest("malformed registration"))?;
    state.limiter.check(&format!("e2ee_register:{}", auth.user_id), 10, crate::limiter::HOUR)?;
    let registration_id = req.registration_id.filter(|r| (1..=16380).contains(r)).ok_or(ApiError::BadRequest("registration_id"))?;
    let identity_key = b64_decode(req.identity_key.as_deref().ok_or(ApiError::BadRequest("identity_key required"))?)?;
    if !certs::is_valid_identity_key(&identity_key) {
        return Err(ApiError::BadRequest("bad identity key"));
    }
    let signed = verified_signed_key(&identity_key, req.signed_prekey.as_ref().ok_or(ApiError::BadRequest("signed_prekey required"))?, false)?;
    // Post-quantum is not optional: a device without a last-resort Kyber key cannot be registered,
    // so no bundle this server serves can ever lack a KEM key.
    let last_resort = verified_signed_key(
        &identity_key,
        req.last_resort_kyber_prekey.as_ref().ok_or(ApiError::BadRequest("last_resort_kyber_prekey required"))?,
        true,
    )?;
    let one_time = verified_one_time_keys(&identity_key, &req.one_time_prekeys, &req.one_time_kyber_prekeys)?;
    let delivery_key = b64_decode(req.delivery_key.as_deref().ok_or(ApiError::BadRequest("delivery_key required"))?)?;
    if delivery_key.len() != 32 {
        return Err(ApiError::BadRequest("delivery_key must be 32 bytes"));
    }
    let device_name = req.device_name_ciphertext.as_deref().map(b64_decode).transpose()?.filter(|n| n.len() <= MAX_DEVICE_NAME);
    // Rule 5: no device is created without an install secret.
    let install_hash = install_hash_of(req.install_hash.as_deref())?.ok_or(ApiError::BadRequest("install_hash required"))?;
    // An identity the instance owner banned (`auth::delete_user`, `?ban=1`) registers nowhere
    // on this instance again, under any account.
    if crate::auth::instance_banned(&state, "identity_key", &identity_key).await? {
        return Err(ApiError::Forbidden);
    }

    let now = now_ms();
    let device_id = new_id();

    // "Is this the account's first device?" is a DURABLE fact (a row in e2ee_accounts), not the
    // current number of device rows — otherwise deleting the rows would bring back the unguarded
    // first-device path.
    let account: Option<(Option<i64>, Option<Vec<u8>>, Option<i64>)> =
        sqlx::query_as("SELECT reset_requested_at, reset_identity_key, pin_set_at FROM e2ee_accounts WHERE user_id = $1")
            .bind(&auth.user_id)
            .fetch_optional(&state.db)
            .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1")
        .bind(&auth.user_id)
        .fetch_one(&state.db)
        .await?;

    // How this device is allowed onto the account.
    enum Admission {
        First,
        /// A key-backup restore of a device whose row is gone: proven by the recovery key.
        Recovered,
        Linked(String, Vec<u8>),
        /// Reset authorized by a long-standing PIN.
        ResetByPin,
        /// Reset that waited out the hold: the exact pending request it is completing.
        ResetAfterHold(i64, Vec<u8>),
    }
    let mut recovery_key_consumed = false;
    // The QR pair request this registration rides on (build 48), claimed again atomically below.
    let mut pair_request: Option<String> = None;
    let admission = match (&account, req.link.as_ref()) {
        (None, _) if count == 0 => Admission::First,
        // A link from a device CURRENTLY on the account.
        (_, Some(proof)) if !req.force => {
            let signature = b64_decode(&proof.signature)?;
            let linker_identity: Option<Vec<u8>> =
                sqlx::query_scalar("SELECT identity_key FROM user_devices WHERE user_id = $1 AND device_id = $2")
                    .bind(&auth.user_id)
                    .bind(&proof.device_id)
                    .fetch_optional(&state.db)
                    .await?;
            let linker_identity = linker_identity.ok_or(ApiError::LinkRequired)?;
            if !skwod_crypto::link::verify_link(&linker_identity, &auth.user_id, &identity_key, &signature) {
                return Err(ApiError::LinkRequired);
            }
            // Rule 6: the signature alone admits nobody (a copied identity key can make one).
            // There must be an unexpired link request for THIS identity key that the linker's
            // current install approved (`approve_link_request` is gated on its bound session)
            // with exactly this signature.
            let approved: Option<Vec<u8>> = sqlx::query_scalar(
                "SELECT link_sig FROM device_link_requests
                 WHERE user_id = $1 AND identity_key = $2 AND approver_device_id = $3 AND link_sig IS NOT NULL AND created_at >= $4",
            )
            .bind(&auth.user_id)
            .bind(&identity_key)
            .bind(&proof.device_id)
            .bind(now - LINK_REQUEST_TTL_MS)
            .fetch_optional(&state.db)
            .await?;
            // Or (build 48) a QR pair request the linker approved for this key, uncontested,
            // whose one session was claimed by the holder of this identity key.
            let paired: Option<(String, Vec<u8>)> = if approved.is_none() && state.qr_pairing {
                // ...by THIS session (the one the claim issued), before its offer expired, once.
                sqlx::query_as(
                    "SELECT r.id, r.link_sig FROM device_pair_requests r
                     JOIN device_pair_offers o ON o.offer_id = r.offer_id AND o.user_id = r.user_id
                     WHERE r.user_id = $1 AND r.identity_key = $2 AND r.approver_device_id = $3 AND r.link_sig IS NOT NULL
                       AND r.contested = 0 AND r.claimed = 1 AND r.registered = 0 AND r.session_hash = $4
                       AND r.created_at >= $5 AND o.expires_at >= $6",
                )
                .bind(&auth.user_id)
                .bind(&identity_key)
                .bind(&proof.device_id)
                .bind(&auth.session_hash)
                .bind(now - LINK_REQUEST_TTL_MS)
                .bind(now)
                .fetch_optional(&state.db)
                .await?
            } else {
                None
            };
            let via_pair = approved.is_none() && paired.is_some();
            let (paired_id, paired_sig) = paired.map_or((None, None), |(id, sig)| (Some(id), Some(sig)));
            if approved.or(paired_sig).as_deref() != Some(signature.as_slice()) {
                return Err(ApiError::LinkRequired);
            }
            if via_pair {
                pair_request = paired_id;
            }
            Admission::Linked(proof.device_id.clone(), signature)
        }
        // A restore after the backed-up device was erased: whoever proves the recovery key may
        // seat the restored identity as a device of its own (rule 4). No link, no hold.
        (_, None) if !req.force && req.recovery_auth.is_some() => {
            let signature = b64_decode(req.recovery_auth.as_deref().unwrap_or_default())?;
            // What would refuse this registration anyway is looked at BEFORE the proof is
            // taken: a key in its overlap restores once, and a refusal after that would have
            // spent it on nothing. (Both are checked again inside the transaction below.)
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
            if count >= MAX_DEVICES_PER_USER {
                return Err(ApiError::Conflict("this account already has 5 devices; remove one first"));
            }
            let removed: Option<String> = sqlx::query_scalar("SELECT reason FROM device_tombstones WHERE user_id = $1 AND identity_key = $2 AND reason = 'removed'")
                .bind(&auth.user_id)
                .bind(&identity_key)
                .fetch_optional(&state.db)
                .await?;
            if removed.is_some() {
                return Err(ApiError::DeviceRemoved);
            }
            match recovery_key_proven(&state, &auth, "register", &identity_key, &install_hash, &signature).await? {
                RecoveryProof::Seasoned { consumed } => {
                    recovery_key_consumed = consumed;
                    Admission::Recovered
                }
                // The right key, set too recently to count yet: say when it will.
                RecoveryProof::TooNew(counts_from) => return Err(ApiError::RecoveryPending(counts_from, None)),
                RecoveryProof::Invalid => return Err(ApiError::Forbidden),
            }
        }
        // Account reset. A session token is not enough; it needs a second factor:
        //  - the registration-lock PIN, when the account set one; otherwise
        //  - time: the request is recorded, every existing device is notified and any of them can
        //    cancel it, and it only completes after RESET_DELAY_MS for the SAME identity key.
        _ if req.force => {
            let lock_enabled: i64 = sqlx::query_scalar("SELECT registration_lock_enabled FROM profiles WHERE id = $1")
                .bind(&auth.user_id)
                .fetch_one(&state.db)
                .await?;
            // A PIN that is set must be presented (typed `PinRequired` otherwise) — unless the
            // user says it is lost, which costs them the full waiting period below.
            let pin_checked = lock_enabled != 0 && !req.forgot_pin;
            if pin_checked {
                verify_registration_pin(&state, &auth.user_id, req.pin.as_deref()).await?;
            }
            // The PIN only waives the hold if it has been in place for at least the hold itself.
            // (Setting a PIN needs a device signature; this is the second line of defence, so a
            // PIN can never be planted and cashed in at once.)
            let pin_set_at = account.as_ref().and_then(|a| a.2);
            let seasoned_pin = pin_checked && pin_set_at.is_some_and(|t| now >= t + RESET_DELAY_MS);
            if seasoned_pin {
                Admission::ResetByPin
            } else {
                let pending = account.as_ref().and_then(|a| a.0.zip(a.1.clone()));
                match pending {
                    Some((requested_at, key)) if key == identity_key => {
                        if now < requested_at + RESET_DELAY_MS {
                            return Err(ApiError::ResetPending(requested_at + RESET_DELAY_MS));
                        }
                        Admission::ResetAfterHold(requested_at, key)
                    }
                    _ => {
                        sqlx::query(
                            "INSERT INTO e2ee_accounts (user_id, first_device_at, reset_requested_at, reset_identity_key)
                             VALUES ($1, $2, $3, $4)
                             ON CONFLICT (user_id) DO UPDATE SET reset_requested_at = excluded.reset_requested_at,
                                 reset_identity_key = excluded.reset_identity_key",
                        )
                        .bind(&auth.user_id)
                        .bind(now)
                        .bind(now)
                        .bind(&identity_key)
                        .execute(&state.db)
                        .await?;
                        state.rt.publish(&crate::rt::user_topic(&auth.user_id), "device_reset_requested", json!({ "completes_at": now + RESET_DELAY_MS }));
                        crate::messages::wake_user(&state, &auth.user_id).await;
                        return Err(ApiError::ResetPending(now + RESET_DELAY_MS));
                    }
                }
            }
        }
        _ => return Err(ApiError::LinkRequired),
    };

    let mut tx = state.db.begin().await?;
    if let Admission::ResetAfterHold(requested_at, key) = &admission {
        // Claim the pending request atomically, INSIDE the transaction, before deleting anything:
        // the check above ran outside it, and a device may have cancelled (or another reset may
        // have completed) in between. Zero rows ⇒ the request we validated is no longer there.
        let claimed = sqlx::query(
            "UPDATE e2ee_accounts SET reset_requested_at = NULL, reset_identity_key = NULL
             WHERE user_id = $1 AND reset_requested_at = $2 AND reset_identity_key = $3",
        )
        .bind(&auth.user_id)
        .bind(*requested_at)
        .bind(key)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if claimed == 0 {
            return Err(ApiError::Conflict("reset was cancelled or already completed"));
        }
    }
    if matches!(admission, Admission::ResetByPin | Admission::ResetAfterHold(..)) {
        // The account starts its device list over: every previous device, its prekeys and its
        // mailbox go, so every peer sees a new device with a new identity (safety number changes).
        for table in ["user_devices", "one_time_prekeys", "sealed_envelopes", "device_link_requests", "device_pair_requests", "device_recoveries", "push_registrations", "push_tokens"] {
            sqlx::query(&format!("DELETE FROM {table} WHERE user_id = $1")).bind(&auth.user_id).execute(&mut *tx).await?;
        }
        // Every session of the old device set ends with it; only the resetting session stays.
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2")
            .bind(&auth.user_id)
            .bind(&auth.session_hash)
            .execute(&mut *tx)
            .await?;
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM user_devices WHERE user_id = $1")
        .bind(&auth.user_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= MAX_DEVICES_PER_USER {
        return Err(ApiError::Conflict("this account already has 5 devices; remove one first"));
    }
    // An identity another device REMOVED from this account comes back only by a link approval
    // from a current device — not by a reset, not by a recovery-key restore, not as a "first"
    // device. (An approval clears the tombstone: that is the explicit re-trust.)
    let removed: Option<String> = sqlx::query_scalar("SELECT reason FROM device_tombstones WHERE user_id = $1 AND identity_key = $2 AND reason = 'removed'")
        .bind(&auth.user_id)
        .bind(&identity_key)
        .fetch_optional(&mut *tx)
        .await?;
    if removed.is_some() && !matches!(admission, Admission::Linked(..)) {
        return Err(ApiError::DeviceRemoved);
    }
    sqlx::query("DELETE FROM device_tombstones WHERE user_id = $1 AND identity_key = $2").bind(&auth.user_id).bind(&identity_key).execute(&mut *tx).await?;
    let recovered = matches!(admission, Admission::Recovered);
    if matches!(admission, Admission::First) {
        // Plain INSERT: two racing "first" registrations cannot both win — the loser hits the
        // primary key and is told to link instead.
        let inserted = sqlx::query("INSERT INTO e2ee_accounts (user_id, first_device_at) VALUES ($1, $2)")
            .bind(&auth.user_id)
            .bind(now)
            .execute(&mut *tx)
            .await;
        if inserted.is_err() {
            return Err(ApiError::LinkRequired);
        }
    } else {
        sqlx::query("UPDATE e2ee_accounts SET reset_requested_at = NULL, reset_identity_key = NULL WHERE user_id = $1")
            .bind(&auth.user_id)
            .execute(&mut *tx)
            .await?;
    }
    if matches!(admission, Admission::ResetByPin | Admission::ResetAfterHold(..)) {
        // The lock belonged to the previous device set. The new sole device sets its own.
        sqlx::query(
            "UPDATE profiles SET registration_pin_hash = NULL, registration_lock_enabled = 0,
                 pin_attempt_count = 0, pin_locked_until = NULL WHERE id = $1",
        )
        .bind(&auth.user_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE e2ee_accounts SET pin_set_at = NULL WHERE user_id = $1").bind(&auth.user_id).execute(&mut *tx).await?;
    }
    let link: Option<(String, Vec<u8>)> = match admission {
        Admission::Linked(device, sig) => Some((device, sig)),
        _ => None,
    };

    sqlx::query(
        "INSERT INTO user_devices (id, user_id, device_id, device_name_ciphertext, protocol_version, registration_id,
             identity_key, signed_prekey_id, signed_prekey, signed_prekey_sig,
             kyber_last_resort_id, kyber_last_resort, kyber_last_resort_sig, delivery_key,
             spk_timestamp, created_at, last_active_at, linked_by, link_sig, install_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)",
    )
    .bind(new_id())
    .bind(&auth.user_id)
    .bind(&device_id)
    .bind(device_name)
    .bind(PROTOCOL_VERSION as i64)
    .bind(registration_id as i64)
    .bind(&identity_key)
    .bind(signed.id as i64)
    .bind(&signed.public)
    .bind(&signed.signature)
    .bind(last_resort.id as i64)
    .bind(&last_resort.public)
    .bind(&last_resort.signature)
    .bind(&delivery_key)
    .bind(now)
    .bind(now)
    .bind(now)
    .bind(link.as_ref().map(|(d, _)| d.clone()))
    .bind(link.as_ref().map(|(_, s)| s.clone()))
    .bind(install_hash)
    .execute(&mut *tx)
    .await?;
    insert_one_time_keys(&mut tx, &auth.user_id, &device_id, &one_time, now).await?;
    sqlx::query("DELETE FROM device_link_requests WHERE user_id = $1 AND identity_key = $2").bind(&auth.user_id).bind(&identity_key).execute(&mut *tx).await?;
    // A QR pair request is marked, never deleted, and its offer consumed: a deleted row let a
    // later request for the same (still unexpired) offer start afresh.
    sqlx::query(
        "UPDATE device_pair_offers SET consumed = 1
         WHERE offer_id IN (SELECT offer_id FROM device_pair_requests WHERE user_id = $1 AND identity_key = $2)",
    )
    .bind(&auth.user_id)
    .bind(&identity_key)
    .execute(&mut *tx)
    .await?;
    if let Some(id) = &pair_request {
        // Everything checked above, checked again in the one statement that takes the row, so a
        // contest, revocation or expiry in between cannot slip through.
        let took = sqlx::query(
            "UPDATE device_pair_requests SET registered = 1
             WHERE id = $1 AND user_id = $2 AND identity_key = $3 AND contested = 0 AND claimed = 1 AND registered = 0 AND session_hash = $4
               AND offer_id IN (SELECT offer_id FROM device_pair_offers WHERE expires_at >= $5)",
        )
        .bind(id)
        .bind(&auth.user_id)
        .bind(&identity_key)
        .bind(&auth.session_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if took != 1 {
            return Err(ApiError::LinkRequired);
        }
    }
    sqlx::query("UPDATE device_pair_requests SET registered = 1 WHERE user_id = $1 AND identity_key = $2").bind(&auth.user_id).bind(&identity_key).execute(&mut *tx).await?;
    bind_session_to(&mut *tx, &auth, &device_id, 0).await?;
    tx.commit().await?;
    // Tell the account's other devices right away that a device was added.
    state.rt.publish(&crate::rt::user_topic(&auth.user_id), "device_added", json!({ "device_id": device_id }));
    if recovered {
        state.rt.publish(&crate::rt::user_topic(&auth.user_id), "account_restored", json!({ "device_id": device_id }));
    }
    crate::messages::wake_user(&state, &auth.user_id).await;

    Ok(Json(json!({
        "device_id": device_id,
        "user_id": auth.user_id,
        "recovered": recovered,
        // The restore used a recovery key that had been replaced (its one overlap use): the
        // account has no recovery key now — save a new one.
        "recovery_key_consumed": recovery_key_consumed,
        "generation": 0,
        "protocol_version": PROTOCOL_VERSION,
        "prekeys_uploaded": one_time.ec.len(),
        "kyber_prekeys_uploaded": one_time.kyber.len(),
    })))
}

#[derive(Deserialize)]
pub struct RekeyRequest {
    pub protocol_version: Option<u32>,
    pub registration_id: u32,
    pub signed_prekey: SignedKeyUpload,
    pub last_resort_kyber_prekey: SignedKeyUpload,
    #[serde(default)]
    pub one_time_prekeys: Vec<PrekeyUpload>,
    #[serde(default)]
    pub one_time_kyber_prekeys: Vec<SignedKeyUpload>,
    pub delivery_key: String,
    /// The device's (re-sealed) name, if the restoring install has one.
    pub device_name_ciphertext: Option<String>,
    /// SHA-256 of the re-keying install's secret. Required; covered by the device proof.
    pub install_hash: Option<String>,
    /// The re-keying install's secret itself (base64): the preimage of `install_hash`. Required —
    /// a re-key is always made by the install that will hold the device, and it proves so.
    pub install_secret: Option<String>,
    /// Recovery only: the registration PIN (completes the recovery at once).
    pub pin: Option<String>,
    /// Recovery only: proof of the recovery key (see `recovery_key_proven`), signed for purpose
    /// `"rekey"` and this device id. Completes the recovery at once.
    pub recovery_auth: Option<String>,
}

/// Replace ALL prekeys of an existing device while keeping its identity key and device id — used
/// after a key-backup restore, where the identity survives but every prekey private half is gone.
/// The new prekey signatures must verify under the device's STORED identity key, which proves the
/// caller holds that identity's private key (a stolen session token alone cannot rekey a device
/// into something the thief can read).
async fn rekey_device(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<RekeyRequest>,
) -> Result<Json<Value>, ApiError> {
    require_protocol(req.protocol_version)?;
    // An install waiting for a restore asks again every few seconds (both apps: every 15 s
    // while the waiting screen is up) and is answered "pending" until it is approved or the
    // hold ends. Those asks get a budget of their own: counted against the budget of re-keys
    // that go ahead (below) they used it up in under three minutes, and the approval that
    // came after that could not complete until the hour was over.
    state.limiter.check(&format!("e2ee_rekey_ask:{}", auth.user_id), 600, crate::limiter::HOUR)?;
    // The budget of re-keys that go ahead is looked at HERE — before the device proof and a
    // recovery-key proof are used up (an overlap key restores once) — and counted only when
    // the re-key has committed (below). Refusing in between would burn them for nothing.
    let rekey_budget = format!("e2ee_rekey:{}", auth.user_id);
    state.limiter.has_room(&rekey_budget, 10)?;
    let identity_key = own_device_identity(&state, &auth.user_id, &device_id).await?;
    let signed = verified_signed_key(&identity_key, &req.signed_prekey, false)?;
    let last_resort = verified_signed_key(&identity_key, &req.last_resort_kyber_prekey, true)?;
    let one_time = verified_one_time_keys(&identity_key, &req.one_time_prekeys, &req.one_time_kyber_prekeys)?;
    let delivery_key = b64_decode(&req.delivery_key)?;
    if delivery_key.len() != 32 || !(1..=16380).contains(&req.registration_id) {
        return Err(ApiError::BadRequest("bad rekey parameters"));
    }
    // The prekey signatures above are PUBLIC (they are served in every bundle), so replaying the
    // device's current ones proves nothing — with them alone a stolen session token could
    // "rekey" a device: wipe its mailbox and one-time prekeys and point its delivery key
    // elsewhere. The request must carry a fresh, single-use signature by a device of the account
    // over exactly these keys.
    let payload = skwod_crypto::link::op_payload(&[
        &req.registration_id.to_be_bytes(),
        &signed.public,
        &last_resort.public,
        &delivery_key,
        &keys_digest_input(one_time.ec.iter().map(|k| k.1.as_slice())),
        &keys_digest_input(one_time.kyber.iter().map(|k| k.public.as_slice())),
    ]);
    // The proof covers the new install secret's hash too (a relayed re-key cannot swap it).
    let install_hash = install_hash_of(req.install_hash.as_deref())?.ok_or(ApiError::BadRequest("install_hash required"))?;
    // The caller holds the SECRET behind that hash. This is what ties a recovery's completion
    // to the install that requested it: the hash of a pending request may be known or guessed;
    // its preimage is only on that install.
    {
        use sha2::{Digest, Sha256};
        let secret = req.install_secret.as_deref().map(b64_decode).transpose()?.filter(|s| s.len() == 32).ok_or(ApiError::BadRequest("install_secret required"))?;
        if !bool::from(Sha256::digest(&secret).as_slice().ct_eq(&install_hash)) {
            return Err(ApiError::Forbidden);
        }
    }
    let payload = skwod_crypto::link::op_payload(&[&payload, &install_hash]);
    let signer = device_proof_signer(&state, &headers, &auth.user_id, "rekey", &device_id, &payload).await?;
    if signer.as_deref() != Some(device_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    // Rule 4. The current install re-keying itself just proceeds. Anyone else holding this
    // identity key — a restore from backup, or a thief with a copy — is asking for a RECOVERY.
    let mut restored = false;
    let mut recovery_key_consumed = false;
    if require_bound_device_session(&state, &auth, &device_id).await.is_err() {
        restored = true;
        let proof = match req.recovery_auth.as_deref() {
            Some(sig) => Some(recovery_key_proven(&state, &auth, "rekey", device_id.as_bytes(), &install_hash, &b64_decode(sig)?).await?),
            None => None,
        };
        match proof {
            // Proof of a seasoned recovery key IS the restore: at once.
            Some(RecoveryProof::Seasoned { consumed }) => recovery_key_consumed = consumed,
            // A proof that was offered and does not hold is refused outright rather than
            // quietly downgraded to a waiting request.
            Some(RecoveryProof::Invalid) => return Err(ApiError::Forbidden),
            // No recovery key — or the right one, set too recently to skip the wait (it may
            // have been planted): approval by a current device, the PIN, or the hold.
            Some(RecoveryProof::TooNew(_)) | None => authorize_recovery(&state, &auth, &device_id, &install_hash, req.pin.as_deref()).await?,
        }
    }
    let device_name = req.device_name_ciphertext.as_deref().map(b64_decode).transpose()?.filter(|n| n.len() <= MAX_DEVICE_NAME);
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    // A re-key means the device moved to another install (a key-backup restore). The generation
    // goes up, so the install it was restored FROM — if it is still around, holding the same
    // identity key — is refused from here on (`require_device_session`) instead of running as a clone.
    sqlx::query(
        "UPDATE user_devices SET registration_id = $1, signed_prekey_id = $2, signed_prekey = $3, signed_prekey_sig = $4,
             kyber_last_resort_id = $5, kyber_last_resort = $6, kyber_last_resort_sig = $7, delivery_key = $8,
             spk_timestamp = $9, last_active_at = $10, generation = generation + 1,
             device_name_ciphertext = COALESCE($13, device_name_ciphertext), install_hash = $14, legacy_unbound = 0
         WHERE user_id = $11 AND device_id = $12",
    )
    .bind(req.registration_id as i64)
    .bind(signed.id as i64)
    .bind(&signed.public)
    .bind(&signed.signature)
    .bind(last_resort.id as i64)
    .bind(&last_resort.public)
    .bind(&last_resort.signature)
    .bind(&delivery_key)
    .bind(now)
    .bind(now)
    .bind(&auth.user_id)
    .bind(&device_id)
    .bind(device_name)
    .bind(&install_hash)
    .execute(&mut *tx)
    .await?;
    // Old prekeys and queued envelopes were for key material that no longer exists.
    for table in ["one_time_prekeys", "sealed_envelopes"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE user_id = $1 AND device_id = $2"))
            .bind(&auth.user_id)
            .bind(&device_id)
            .execute(&mut *tx)
            .await?;
    }
    insert_one_time_keys(&mut tx, &auth.user_id, &device_id, &one_time, now).await?;
    sqlx::query("DELETE FROM device_recoveries WHERE user_id = $1 AND device_id = $2").bind(&auth.user_id).bind(&device_id).execute(&mut *tx).await?;
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM user_devices WHERE user_id = $1 AND device_id = $2")
        .bind(&auth.user_id)
        .bind(&device_id)
        .fetch_one(&mut *tx)
        .await?;
    // The restoring session speaks for the device at the NEW generation. Every session bound
    // at an older one — the install this was restored from — now fails `require_device_session`
    // with 409; it stays signed in, so that install can be told why it stopped.
    bind_session_to(&mut *tx, &auth, &device_id, generation).await?;
    // The install this was restored from is not woken any more: a push wake says "something
    // happened in your account now" to whoever holds that phone. Its registrations go (and
    // ones that never said which device they belong to — those installs register again).
    sqlx::query("DELETE FROM push_registrations WHERE user_id = $1 AND session_hash <> $2 AND (device_id = $3 OR device_id IS NULL)")
        .bind(&auth.user_id)
        .bind(&auth.session_hash)
        .bind(&device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.limiter.hit(&rekey_budget, crate::limiter::HOUR);
    // To the account's own devices — every open socket of the account re-checks its session
    // on this event, so the superseded install's socket closes now (`ws.rs`) — and to
    // everyone who may hold keys for the device: the old install still has what it held, so
    // peers re-read the directory (the generation is listed) and rotate.
    announce_device_rekeyed(&state, &auth.user_id, &device_id, generation).await;
    if restored {
        // Every other device of the account says so ("your account was restored on a new device").
        state.rt.publish(&crate::rt::user_topic(&auth.user_id), "account_restored", json!({ "device_id": device_id }));
        crate::messages::wake_user(&state, &auth.user_id).await;
    }
    Ok(Json(json!({ "success": true, "generation": generation, "recovery_key_consumed": recovery_key_consumed })))
}

/// Longest sealed device name the directory keeps.
const MAX_DEVICE_NAME: usize = 512;

/// How long a recovery-key challenge may be answered, and how many one session may hold.
const RECOVERY_NONCE_TTL_MS: i64 = 10 * 60 * 1000;
const RECOVERY_NONCES_PER_SESSION: i64 = 4;

/// Issue the nonce a recovery-key proof signs — to THIS session. Only the session it was
/// issued to can answer it, so another session of the account (which any holder of the
/// password can open) can neither use nor use up the owner's challenge. Limited per session,
/// with a looser ceiling per account. 404 without a backup that has a verifier.
async fn backup_challenge(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_backup_challenge:{}", hex::encode(&auth.session_hash)), 20, crate::limiter::HOUR)?;
    state.limiter.check(&format!("e2ee_backup_challenge_user:{}", auth.user_id), 600, crate::limiter::HOUR)?;
    let now = now_ms();
    let has_verifier: Option<i64> = sqlx::query_scalar(&format!("SELECT 1 FROM backup_keys WHERE user_id = $1 AND {KEY_VALID} LIMIT 1"))
        .bind(&auth.user_id)
        .bind(now)
        .fetch_optional(&state.db)
        .await?;
    if has_verifier.is_none() {
        return Err(ApiError::NotFound);
    }
    sqlx::query("DELETE FROM backup_auth_nonces WHERE created_at < $1").bind(now - RECOVERY_NONCE_TTL_MS).execute(&state.db).await?;
    // A session keeps only its newest few (it has no use for more).
    sqlx::query(
        "DELETE FROM backup_auth_nonces WHERE session_hash = $1 AND nonce NOT IN
             (SELECT nonce FROM backup_auth_nonces WHERE session_hash = $2 ORDER BY created_at DESC LIMIT $3)",
    )
    .bind(&auth.session_hash)
    .bind(&auth.session_hash)
    .bind(RECOVERY_NONCES_PER_SESSION - 1)
    .execute(&state.db)
    .await?;
    let nonce = format!("{}{}", new_id(), new_id());
    sqlx::query("INSERT INTO backup_auth_nonces (nonce, user_id, session_hash, created_at) VALUES ($1, $2, $3, $4)")
        .bind(&nonce)
        .bind(&auth.user_id)
        .bind(&auth.session_hash)
        .bind(now)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "nonce": nonce })))
}

/// What a recovery-key proof established.
enum RecoveryProof {
    /// A valid proof by a verifier that has been in place for the length of the hold.
    /// `consumed`: it was a key that had been replaced, used for its one overlap restore — the
    /// account has no recovery key in force any more.
    Seasoned { consumed: bool },
    /// A valid proof, but the verifier is younger than the hold: it counts from this time.
    TooNew(i64),
    Invalid,
}

/// Does the caller hold the account's RECOVERY KEY? A valid proof is a signature — by the key
/// whose public half was stored with the backup — over a nonce issued to THIS session and still
/// fresh, bound to this purpose, target and install. A nonce is consumed only by the valid
/// signature over it (single use); a wrong signature consumes nothing, so it cannot be used to
/// burn anyone's challenge — attempts are bounded by the caller's own rate limits instead.
async fn recovery_key_proven(state: &AppState, auth: &AuthUser, purpose: &str, target: &[u8], install_hash: &[u8], signature: &[u8]) -> Result<RecoveryProof, ApiError> {
    state.limiter.check(&format!("e2ee_recovery_proof:{}", hex::encode(&auth.session_hash)), 20, crate::limiter::HOUR)?;
    let now = now_ms();
    // Judged by the KEY row and nothing else: the key in force, then keys in their overlap.
    // Compromised, consumed, cancelled and replaced-while-unseasoned keys are retired as of
    // the moment it happened and never appear here — whatever blobs exist under them.
    let verifiers: Vec<(String, Vec<u8>, i64, Option<i64>)> = sqlx::query_as(&format!(
        "SELECT id, verifier, set_at, retired_at FROM backup_keys WHERE user_id = $1 AND {KEY_VALID}
         ORDER BY CASE WHEN retired_at IS NULL THEN 0 ELSE 1 END, set_at"
    ))
    .bind(&auth.user_id)
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    let nonces: Vec<String> = sqlx::query_scalar("SELECT nonce FROM backup_auth_nonces WHERE session_hash = $1 AND user_id = $2 AND created_at >= $3 ORDER BY created_at DESC")
        .bind(&auth.session_hash)
        .bind(&auth.user_id)
        .bind(now - RECOVERY_NONCE_TTL_MS)
        .fetch_all(&state.db)
        .await?;
    let proven = verifiers.iter().find_map(|(id, verifier, set_at, retired_at)| {
        let nonce = nonces.iter().find(|nonce| {
            let message = skwod_crypto::backup::recovery_auth_message(&auth.user_id, purpose, target, nonce, install_hash);
            skwod_crypto::backup::verify_recovery_auth(verifier, &message, signature)
        })?;
        Some((id.clone(), *set_at, retired_at.is_none(), nonce.clone()))
    });
    let Some((key_id, set_at, in_force, nonce)) = proven else { return Ok(RecoveryProof::Invalid) };
    // Single use: the row goes, and only the request that removed it counts.
    let consumed = sqlx::query("DELETE FROM backup_auth_nonces WHERE nonce = $1 AND session_hash = $2").bind(&nonce).bind(&auth.session_hash).execute(&state.db).await?.rows_affected();
    if consumed == 0 {
        return Ok(RecoveryProof::Invalid);
    }
    let counts_from = set_at + RESET_DELAY_MS;
    if now < counts_from {
        // The right key, too young to skip the wait. (An unseasoned key that was replaced is
        // retired on the spot and never gets here.)
        return Ok(RecoveryProof::TooNew(counts_from));
    }
    if in_force {
        return Ok(RecoveryProof::Seasoned { consumed: false });
    }
    // The owner came back with the key that was replaced, inside its overlap. The restore goes
    // through — and that was the key's one use: it is CONSUMED (every row of it), the newer
    // key(s) that have not seasoned are cancelled, and whatever backup was put in its place is
    // gone. The key is not brought back into force: the account has no recovery key until the
    // owner saves a new one, which seasons from zero like any other.
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE backup_keys SET retired_at = $1, retire_reason = 'consumed' WHERE id = $2").bind(now).bind(&key_id).execute(&mut *tx).await?;
    sqlx::query(
        "UPDATE backup_keys SET retired_at = $1, retire_reason = 'cancelled', replaced_at = COALESCE(replaced_at, $1)
         WHERE user_id = $2 AND set_at > $3 AND set_at + $4 > $1 AND (retired_at IS NULL OR retired_at > $1)",
    )
    .bind(now)
    .bind(&auth.user_id)
    .bind(set_at)
    .bind(RESET_DELAY_MS)
    .execute(&mut *tx)
    .await?;
    let still_in_force: Option<i64> = sqlx::query_scalar("SELECT 1 FROM backup_keys WHERE user_id = $1 AND retired_at IS NULL LIMIT 1").bind(&auth.user_id).fetch_optional(&mut *tx).await?;
    if still_in_force.is_none() {
        sqlx::query("DELETE FROM e2ee_key_backups WHERE user_id = $1").bind(&auth.user_id).execute(&mut *tx).await?;
    }
    sqlx::query("DELETE FROM backup_auth_nonces WHERE user_id = $1").bind(&auth.user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(RecoveryProof::Seasoned { consumed: true })
}

/// How the recovery key in force is leaving force.
#[derive(Clone, Copy, PartialEq)]
enum Retire {
    /// A backup write or delete put another key (or none) in its place: overlap if seasoned.
    Replaced,
    /// It may be known to someone else: at once, no overlap, and the backup sealed under it
    /// is no longer served.
    Compromised,
}

/// Is a `backup_keys` row valid as of `$2` (= now)? In force, or in its overlap. THE test of a
/// recovery key — used for proofs, for challenges and for which blobs a restore is offered.
const KEY_VALID: &str = "(retired_at IS NULL OR (retired_at > $2 AND retire_reason = 'replaced'))";

/// The recovery key in force is being changed or removed (`new` = the verifier taking its
/// place, if any). Returns whether anything changed. Keys that already left force are never
/// touched by `Replaced`; `Compromised` retires EVERY key still valid — the one in force and
/// any in its overlap — and with them (validity being the key's) every blob under them.
async fn replace_verifier(tx: &mut sqlx::Transaction<'_, sqlx::Any>, user_id: &str, new: Option<&[u8]>, now: i64, how: Retire) -> Result<bool, ApiError> {
    if how == Retire::Compromised {
        let retired = sqlx::query(
            "UPDATE backup_keys SET retired_at = $1, retire_reason = 'compromised', replaced_at = COALESCE(replaced_at, $1)
             WHERE user_id = $2 AND (retired_at IS NULL OR retired_at > $1)",
        )
        .bind(now)
        .bind(user_id)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        // Whatever is in the account's backup slot was sealed under a key that is now dead.
        sqlx::query("DELETE FROM e2ee_key_backups WHERE user_id = $1").bind(user_id).execute(&mut **tx).await?;
        sqlx::query("DELETE FROM backup_auth_nonces WHERE user_id = $1").bind(user_id).execute(&mut **tx).await?;
        return Ok(retired > 0);
    }
    let in_force: Option<(String, Vec<u8>, i64)> =
        sqlx::query_as("SELECT id, verifier, set_at FROM backup_keys WHERE user_id = $1 AND retired_at IS NULL ORDER BY set_at DESC LIMIT 1").bind(user_id).fetch_optional(&mut **tx).await?;
    match in_force {
        Some((_, verifier, _)) if Some(verifier.as_slice()) == new => Ok(false),
        Some((id, _, set_at)) => {
            // Seasoned: one more hold period, for one restore. Unseasoned: retired on the spot
            // — and since validity is the key's, none of its blobs is usable from here on.
            let retires = if now >= set_at + RESET_DELAY_MS { now + RESET_DELAY_MS } else { now };
            sqlx::query("UPDATE backup_keys SET replaced_at = $1, retired_at = $2, retire_reason = 'replaced' WHERE id = $3").bind(now).bind(retires).bind(&id).execute(&mut **tx).await?;
            Ok(true)
        }
        // Nothing in force. A first key is not a change — unless a key was in force recently
        // (it was removed and is now being followed by another): that is one.
        None => {
            let recent: Option<i64> = sqlx::query_scalar("SELECT 1 FROM backup_keys WHERE user_id = $1 AND replaced_at > $2 LIMIT 1")
                .bind(user_id)
                .bind(now - RESET_DELAY_MS)
                .fetch_optional(&mut **tx)
                .await?;
            Ok(new.is_some() && recent.is_some())
        }
    }
}

/// "My recovery key is compromised" — from a current device of the account. The key in force
/// is retired at once (no overlap: the point is that someone else may hold it) and the backup
/// sealed under it is no longer served. The devices are told to save a new one.
async fn recovery_key_compromised(State(state): State<AppState>, auth: AuthUser, headers: axum::http::HeaderMap) -> Result<Json<Value>, ApiError> {
    device_authority(&state, &auth, &headers, "backup-compromised", "backup", b"").await?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let retired = replace_verifier(&mut tx, &auth.user_id, None, now, Retire::Compromised).await?;
    tx.commit().await?;
    if retired {
        announce_recovery_key_change(&state, &auth.user_id, now).await;
    }
    Ok(Json(json!({ "success": true, "retired": retired })))
}

#[derive(Deserialize)]
pub struct TombstoneRemove {
    pub identity_key: String,
}

/// A device that erased ITSELF turns out to have been lost or stolen: a current device
/// converts its tombstone to `removed`. From then on that identity is refused like any removed
/// device's (no restore, no reset — a link approval only), and, as with any removal, the
/// recovery key in force is retired as compromised.
async fn remove_tombstoned_device(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<TombstoneRemove>,
) -> Result<Json<Value>, ApiError> {
    let identity_key = b64_decode(&req.identity_key)?;
    device_authority(&state, &auth, &headers, "tombstone-remove", "tombstone", &identity_key).await?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let converted = sqlx::query("UPDATE device_tombstones SET reason = 'removed' WHERE user_id = $1 AND identity_key = $2")
        .bind(&auth.user_id)
        .bind(&identity_key)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if converted == 0 {
        return Err(ApiError::NotFound);
    }
    let retired = replace_verifier(&mut tx, &auth.user_id, None, now, Retire::Compromised).await?;
    tx.commit().await?;
    if retired {
        announce_recovery_key_change(&state, &auth.user_id, now).await;
    }
    Ok(Json(json!({ "success": true, "recovery_key_retired": retired })))
}

/// Tell every device of the account that its recovery key was changed or removed.
async fn announce_recovery_key_change(state: &AppState, user_id: &str, now: i64) {
    state.rt.publish(&crate::rt::user_topic(user_id), "recovery_key_changed", json!({ "at": now }));
    crate::messages::wake_user(state, user_id).await;
}

/// Live restore requests one device may have at once — pending, approved, or past an
/// uncontested hold and not yet used — one per requesting install (audit L1). Past this many,
/// a new one is refused until one is cancelled, used or expires.
pub(crate) const MAX_PENDING_RECOVERIES: i64 = 3;
/// A request is kept this long after it was filed (its hold, then as long again for the
/// install it was granted to to finish), then swept.
pub(crate) const RECOVERY_REQUEST_LIFETIME_MS: i64 = 2 * RESET_DELAY_MS;
/// New restore requests one SESSION may file per day. A session is server-issued and costs a
/// (rate-limited) password check; nothing the caller chooses keys this. Asking again for a
/// request already on record is not a filing; a refused filing is given back.
const RECOVERY_FILINGS_PER_SESSION_PER_DAY: u32 = 3;
/// New restore requests one account may file per day — counting only filings that were MADE,
/// so refused attempts cannot use up the owner's allowance.
const RECOVERY_FILINGS_PER_ACCOUNT_PER_DAY: u32 = 10;
/// The answer to a new restore request while `MAX_PENDING_RECOVERIES` are live.
pub(crate) const RECOVERY_REQUESTS_FULL: &str = "several restores of this device are already waiting; approve or cancel them on one of your devices, or use your PIN or recovery key";
/// The answer to a new restore request while another one is granted (approved, or past an
/// uncontested hold) and not yet used.
pub(crate) const RECOVERY_REQUEST_TAKEN: &str = "another restore of this device was already approved; cancel it on one of your devices first";

/// Is this request granted? Approved by a current device (or the PIN), or past its hold
/// WITHOUT ever having been contested: a request that another install's request ran beside
/// during its hold completes only by an approval, the PIN or the recovery key (audit L1).
fn recovery_granted(requested_at: i64, approved_by: Option<&str>, contested_at: Option<i64>, now: i64) -> bool {
    approved_by.is_some() || (contested_at.is_none() && now >= requested_at + RESET_DELAY_MS)
}

/// Take the per-device restore lock inside `tx`: every filing and approval writes this row
/// first, so they are serialized per (account, device) on SQLite and Postgres alike.
async fn lock_recoveries(tx: &mut sqlx::Transaction<'_, sqlx::Any>, user_id: &str, device_id: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO device_recovery_locks (user_id, device_id, bumped) VALUES ($1, $2, 0) ON CONFLICT (user_id, device_id) DO NOTHING")
        .bind(user_id)
        .bind(device_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE device_recovery_locks SET bumped = bumped + 1 WHERE user_id = $1 AND device_id = $2").bind(user_id).bind(device_id).execute(&mut **tx).await?;
    Ok(())
}

/// Yes with the registration PIN, with a recorded approval by a current device, or once the
/// hold has run out, uncontested, for this same install secret. Otherwise the request is
/// recorded beside any other install's (audit L1: up to `MAX_PENDING_RECOVERIES` live, none
/// while one is granted; a second one makes every waiting one contested), every device of the
/// account is told and woken, and the caller gets `RecoveryPending`.
async fn authorize_recovery(state: &AppState, auth: &AuthUser, device_id: &str, install_hash: &[u8], pin: Option<&str>) -> Result<(), ApiError> {
    let now = now_ms();
    let lock_enabled: i64 = sqlx::query_scalar("SELECT registration_lock_enabled FROM profiles WHERE id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
    if lock_enabled != 0 && pin.is_some_and(|p| !p.is_empty()) {
        // Wrong PIN: counted towards the lockout, and nothing is recorded.
        verify_registration_pin(state, &auth.user_id, pin).await?;
        // Right PIN: at once — but only a PIN that has itself been in place for the hold
        // period, exactly as in the reset path (`register_device`). A PIN set last week by the
        // owner waives the wait; one set five minutes ago by whoever held the unlocked phone
        // does not, and the request takes the ordinary hold below (announced to every device).
        let pin_set_at: Option<i64> = sqlx::query_scalar("SELECT pin_set_at FROM e2ee_accounts WHERE user_id = $1").bind(&auth.user_id).fetch_optional(&state.db).await?.flatten();
        if pin_set_at.is_some_and(|t| now >= t + RESET_DELAY_MS) {
            return Ok(());
        }
    }
    // THIS install's request, if it filed one. Other installs' requests are theirs: nothing
    // here replaces or voids them (audit L1).
    let mine: Option<(i64, Option<String>, Option<i64>)> =
        sqlx::query_as("SELECT requested_at, approved_by, contested_at FROM device_recoveries WHERE user_id = $1 AND device_id = $2 AND install_hash = $3")
            .bind(&auth.user_id)
            .bind(device_id)
            .bind(install_hash)
            .fetch_optional(&state.db)
            .await?;
    if let Some((requested_at, approved_by, contested_at)) = mine {
        return if recovery_granted(requested_at, approved_by.as_deref(), contested_at, now) {
            Ok(())
        } else {
            // (A contested request does not complete by the hold; the time is when it would
            // have, and asking again after it says "waiting" until someone decides. The
            // contest is said too, so the install does not promise the hold.)
            Err(ApiError::RecoveryPending(requested_at + RESET_DELAY_MS, contested_at))
        };
    }
    // A NEW request. Rationed per server-issued session, and per account for filings made.
    let per_session = format!("e2ee_recovery_file:{}", hex::encode(&auth.session_hash));
    let per_account = format!("e2ee_recovery_filed:{}", auth.user_id);
    state.limiter.take(&per_session, RECOVERY_FILINGS_PER_SESSION_PER_DAY, 24 * crate::limiter::HOUR)?;
    if let Err(e) = state.limiter.has_room(&per_account, RECOVERY_FILINGS_PER_ACCOUNT_PER_DAY) {
        state.limiter.refund(&per_session);
        return Err(e);
    }
    let refused = |e: ApiError| {
        state.limiter.refund(&per_session);
        Err(e)
    };
    // The cap and the exclusivity are decided under the per-device lock, in one transaction.
    let mut tx = state.db.begin().await?;
    lock_recoveries(&mut tx, &auth.user_id, device_id).await?;
    sqlx::query("DELETE FROM device_recoveries WHERE user_id = $1 AND device_id = $2 AND requested_at + $3 <= $4")
        .bind(&auth.user_id)
        .bind(device_id)
        .bind(RECOVERY_REQUEST_LIFETIME_MS)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    let live: Vec<(i64, Option<String>, Option<i64>)> = sqlx::query_as("SELECT requested_at, approved_by, contested_at FROM device_recoveries WHERE user_id = $1 AND device_id = $2")
        .bind(&auth.user_id)
        .bind(device_id)
        .fetch_all(&mut *tx)
        .await?;
    // One is granted and not yet used: it is the account's decision; nothing files beside it.
    if live.iter().any(|(at, by, contested)| recovery_granted(*at, by.as_deref(), *contested, now)) {
        drop(tx);
        return refused(ApiError::Conflict(RECOVERY_REQUEST_TAKEN));
    }
    if live.len() as i64 >= MAX_PENDING_RECOVERIES {
        drop(tx);
        return refused(ApiError::Conflict(RECOVERY_REQUESTS_FULL));
    }
    // Any other request still waiting is contested from now on (and so is this one): none of
    // them completes by the hold alone any more.
    let contested = (!live.is_empty()).then_some(now);
    if contested.is_some() {
        sqlx::query("UPDATE device_recoveries SET contested_at = $1 WHERE user_id = $2 AND device_id = $3 AND contested_at IS NULL")
            .bind(now)
            .bind(&auth.user_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("INSERT INTO device_recoveries (user_id, device_id, install_hash, requested_at, approved_by, nonce, contested_at) VALUES ($1, $2, $3, $4, NULL, $5, $6)")
        .bind(&auth.user_id)
        .bind(device_id)
        .bind(install_hash)
        .bind(now)
        // Every request has its own id: an approval names exactly one.
        .bind(new_id())
        .bind(contested)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.limiter.hit(&per_account, 24 * crate::limiter::HOUR);
    // Every filing is announced to every device, and wakes them. More than one waiting for the
    // same device is said in so many words: someone else is trying too.
    let waiting = live.len() as i64 + 1;
    let topic = crate::rt::user_topic(&auth.user_id);
    state.rt.publish(&topic, "device_recovery_requested", json!({ "device_id": device_id, "completes_at": now + RESET_DELAY_MS, "waiting": waiting }));
    if waiting > 1 {
        state.rt.publish(&topic, "device_recovery_multiple", json!({ "device_id": device_id, "waiting": waiting, "at": now }));
    }
    crate::messages::wake_user(state, &auth.user_id).await;
    Err(ApiError::RecoveryPending(now + RESET_DELAY_MS, contested))
}

#[derive(Deserialize)]
pub struct RecoveryDecision {
    /// The request the USER was shown (from the listing / the notice). The decision applies to
    /// exactly that request: if another has taken its place since, it is refused.
    pub request_id: String,
}

/// Check that `request_id` is still THE pending recovery of `device_id`. `NotFound` when none
/// is pending; 409 when a different request has replaced the one the caller means.
async fn pending_recovery(state: &AppState, user_id: &str, device_id: &str, request_id: &str) -> Result<(), ApiError> {
    let nonces: Vec<String> = sqlx::query_scalar("SELECT nonce FROM device_recoveries WHERE user_id = $1 AND device_id = $2")
        .bind(user_id)
        .bind(device_id)
        .fetch_all(&state.db)
        .await?;
    if nonces.is_empty() {
        return Err(ApiError::NotFound);
    }
    if nonces.iter().any(|n| bool::from(n.as_bytes().ct_eq(request_id.as_bytes()))) {
        Ok(())
    } else {
        Err(ApiError::Conflict("recovery request changed"))
    }
}

/// A current device of the account approves a pending recovery of `device_id` (which may be
/// itself: "yes, move me to that install"). The approval names the request the user was shown
/// (`request_id`) and the proof is over that id: it approves that request and no other — a
/// request swapped in afterwards is not approved by it — and it is useless to anyone but the
/// install holding the secret the request was made with.
async fn approve_recovery(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<RecoveryDecision>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_recovery:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    pending_recovery(&state, &auth.user_id, &device_id, &req.request_id).await?;
    let signer = device_authority(&state, &auth, &headers, "approve-recovery", &device_id, req.request_id.as_bytes()).await?;
    // Approving one and ending the others is ONE step, under the per-device lock: no filing
    // lands between them. Conditional on the id: a request gone since the check is untouched.
    let mut tx = state.db.begin().await?;
    lock_recoveries(&mut tx, &auth.user_id, &device_id).await?;
    let approved = sqlx::query("UPDATE device_recoveries SET approved_by = $1 WHERE user_id = $2 AND device_id = $3 AND nonce = $4")
        .bind(&signer)
        .bind(&auth.user_id)
        .bind(&device_id)
        .bind(&req.request_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if approved == 0 {
        return Err(ApiError::Conflict("recovery request changed"));
    }
    // One restore of a device is approved: every other request for it is over (audit L1).
    sqlx::query("DELETE FROM device_recoveries WHERE user_id = $1 AND device_id = $2 AND nonce <> $3")
        .bind(&auth.user_id)
        .bind(&device_id)
        .bind(&req.request_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true })))
}

/// A current device of the account refuses a pending recovery of `device_id` — the one named.
async fn cancel_recovery(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<RecoveryDecision>,
) -> Result<Json<Value>, ApiError> {
    pending_recovery(&state, &auth.user_id, &device_id, &req.request_id).await?;
    device_authority(&state, &auth, &headers, "cancel-recovery", &device_id, req.request_id.as_bytes()).await?;
    sqlx::query("DELETE FROM device_recoveries WHERE user_id = $1 AND device_id = $2 AND nonce = $3")
        .bind(&auth.user_id)
        .bind(&device_id)
        .bind(&req.request_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct BindSession {
    /// This install's secret (base64) — the preimage of the device's `install_hash`.
    pub install_secret: Option<String>,
}

/// "This session is device X, and I am its current install": a sign-in on an install that
/// already holds a device identity (signed out and back in — no re-link). Needs BOTH a proof
/// signed by that device's identity key over this session's token hash and the secret's hash,
/// AND the install secret itself. The install a recovery was made FROM holds the identity key
/// but not the new secret: 409, however it asks.
///
/// A `legacy_unbound` row (rule 5) has no secret on record: its first bind records the one
/// presented and clears the flag.
async fn bind_session(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<BindSession>,
) -> Result<Json<Value>, ApiError> {
    use sha2::{Digest, Sha256};
    state.limiter.check(&format!("e2ee_bind:{}", auth.user_id), 60, crate::limiter::HOUR)?;
    let row: Option<(i64, Option<Vec<u8>>, i64)> =
        sqlx::query_as("SELECT generation, install_hash, legacy_unbound FROM user_devices WHERE user_id = $1 AND device_id = $2")
            .bind(&auth.user_id)
            .bind(&device_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((generation, install_hash, legacy_unbound)) = row else { return Err(ApiError::DeviceRemoved) };
    let secret = req.install_secret.as_deref().map(b64_decode).transpose()?.filter(|s| s.len() == 32).ok_or(ApiError::BadRequest("install_secret required"))?;
    let presented = Sha256::digest(&secret).to_vec();
    let payload = skwod_crypto::link::op_payload(&[&auth.session_hash, &presented]);
    let signer = device_proof_signer(&state, &headers, &auth.user_id, "bind-session", &device_id, &payload).await?;
    if signer.as_deref() != Some(device_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    let pre_migration: i64 = sqlx::query_scalar("SELECT pre_migration FROM sessions WHERE token_hash = $1").bind(&auth.session_hash).fetch_one(&state.db).await?;
    let migrating = match &install_hash {
        Some(stored) if bool::from(stored.as_slice().ct_eq(&presented)) => false,
        // A legacy row is claimed only by a sign-in that predates the migration (rule 5).
        None if legacy_unbound != 0 && pre_migration != 0 => true,
        // Not the current install: a superseded copy, or one that never had the secret.
        _ => return Err(ApiError::DeviceSuperseded),
    };
    let mut tx = state.db.begin().await?;
    if migrating {
        // First come, first recorded — and only while still flagged (two installs racing: one wins).
        let set = sqlx::query("UPDATE user_devices SET install_hash = $1, legacy_unbound = 0 WHERE user_id = $2 AND device_id = $3 AND legacy_unbound <> 0 AND install_hash IS NULL")
            .bind(&presented)
            .bind(&auth.user_id)
            .bind(&device_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if set == 0 {
            return Err(ApiError::DeviceSuperseded);
        }
    }
    bind_session_to(&mut *tx, &auth, &device_id, generation).await?;
    sqlx::query("UPDATE user_devices SET last_active_at = $1 WHERE user_id = $2 AND device_id = $3")
        .bind(now_ms())
        .bind(&auth.user_id)
        .bind(&device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true, "generation": generation })))
}

#[derive(Deserialize)]
pub struct DeviceName {
    /// The name sealed under the account key (which only this account's devices hold), base64.
    pub device_name_ciphertext: Option<String>,
}

/// Set (or clear) a device's sealed name. Only the device itself may name itself.
async fn set_device_name(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(device_id): Path<String>,
    Json(req): Json<DeviceName>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_name:{}", auth.user_id), 60, crate::limiter::HOUR)?;
    require_device_session(&state, &auth, &device_id).await?;
    if auth.device_id.as_deref() != Some(device_id.as_str()) {
        return Err(ApiError::Forbidden);
    }
    let name = req.device_name_ciphertext.as_deref().map(b64_decode).transpose()?;
    if name.as_ref().is_some_and(|n| n.len() > MAX_DEVICE_NAME) {
        return Err(ApiError::BadRequest("device name too long"));
    }
    sqlx::query("UPDATE user_devices SET device_name_ciphertext = $1 WHERE user_id = $2 AND device_id = $3")
        .bind(name)
        .bind(&auth.user_id)
        .bind(&device_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

#[derive(Deserialize)]
pub struct DeliveryKeyRequest {
    pub delivery_key: String,
}

/// Replace a device's delivery key. Everyone holding the old key gets "gone" on their next sealed
/// deposit and must re-fetch it — which `may_contact` refuses to anyone the owner has blocked. This
/// is how a block takes effect against a sender the server cannot identify.
async fn rotate_delivery_key(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<String>,
    Json(req): Json<DeliveryKeyRequest>,
) -> Result<Json<Value>, ApiError> {
    require_device_session(&state, &auth, &device_id).await?;
    state.limiter.check(&format!("e2ee_delivery:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    own_device_identity(&state, &auth.user_id, &device_id).await?;
    let delivery_key = b64_decode(&req.delivery_key)?;
    if delivery_key.len() != 32 {
        return Err(ApiError::BadRequest("delivery_key must be 32 bytes"));
    }
    // The proof covers the new key itself.
    device_authority(&state, &auth, &headers, "delivery-key", &device_id, &delivery_key).await?;
    let updated = sqlx::query("UPDATE user_devices SET delivery_key = $1 WHERE user_id = $2 AND device_id = $3")
        .bind(&delivery_key)
        .bind(&auth.user_id)
        .bind(&device_id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if updated == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "success": true })))
}

async fn list_devices(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(String, Option<Vec<u8>>, i64, i64, i64, Vec<u8>, Option<String>, Option<Vec<u8>>, i64)> = sqlx::query_as(
        "SELECT device_id, device_name_ciphertext, attested, created_at, last_active_at, identity_key, linked_by, link_sig, generation
         FROM user_devices WHERE user_id = $1 ORDER BY created_at",
    )
    .bind(&auth.user_id)
    .fetch_all(&state.db)
    .await?;
    let devices: Vec<Value> = rows
        .into_iter()
        .map(|(device_id, name, attested, created_at, last_active_at, identity_key, linked_by, link_sig, generation)| {
            json!({
                // "This device": the session speaks for it AT ITS CURRENT GENERATION. An
                // install that was superseded by a restore is not the device any more.
                "current": auth.device_id.as_deref() == Some(device_id.as_str()) && auth.device_generation == Some(generation),
                "generation": generation,
                "device_id": device_id,
                "device_name_ciphertext": name.map(|n| B64.encode(n)),
                "attested": attested == 1,
                "created_at": created_at,
                "last_active_at": last_active_at,
                "identity_key": B64.encode(identity_key),
                "linked_by": linked_by,
                "link_sig": link_sig.map(|s| B64.encode(s)),
            })
        })
        .collect();
    let reset_requested_at: Option<Option<i64>> =
        sqlx::query_scalar("SELECT reset_requested_at FROM e2ee_accounts WHERE user_id = $1").bind(&auth.user_id).fetch_optional(&state.db).await?;
    let reset_completes_at = reset_requested_at.flatten().map(|t| t + RESET_DELAY_MS);
    let recoveries: Vec<(String, i64, Option<String>, String, Vec<u8>)> =
        sqlx::query_as("SELECT device_id, requested_at, approved_by, nonce, install_hash FROM device_recoveries WHERE user_id = $1").bind(&auth.user_id).fetch_all(&state.db).await?;
    let recoveries: Vec<Value> = recoveries
        .into_iter()
        .map(|(device_id, requested_at, approved_by, nonce, install_hash)| {
            // `request_id` is what an approving / refusing device signs. The requesting
            // install's hash is NOT here (nor anywhere else): see rule 4. `fingerprint` is a
            // short one-way code of it that the requesting install shows too, so the person
            // approving can see it is the request they started.
            json!({
                "device_id": device_id,
                "completes_at": requested_at + RESET_DELAY_MS,
                "requested_at": requested_at,
                "approved": approved_by.is_some(),
                "request_id": nonce,
                "fingerprint": skwod_crypto::backup::recovery_fingerprint(&install_hash),
            })
        })
        .collect();
    let now = now_ms();
    let verifier_set_at: Option<i64> =
        sqlx::query_scalar("SELECT set_at FROM backup_keys WHERE user_id = $1 AND retired_at IS NULL ORDER BY set_at DESC LIMIT 1").bind(&auth.user_id).fetch_optional(&state.db).await?;
    // The last change or removal of the recovery key, for as long as it matters (one hold).
    let had_recovery_key: bool =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_keys WHERE user_id = $1").bind(&auth.user_id).fetch_one(&state.db).await? > 0;
    let erased: Vec<(String, Vec<u8>, i64)> =
        sqlx::query_as("SELECT device_id, identity_key, created_at FROM device_tombstones WHERE user_id = $1 AND reason = 'self_erased' ORDER BY created_at").bind(&auth.user_id).fetch_all(&state.db).await?;
    let erased: Vec<Value> = erased.into_iter().map(|(device_id, identity_key, at)| json!({ "device_id": device_id, "identity_key": B64.encode(identity_key), "erased_at": at })).collect();
    let changed_at: Option<i64> = sqlx::query_scalar("SELECT max(replaced_at) FROM backup_keys WHERE user_id = $1 AND replaced_at > $2")
        .bind(&auth.user_id)
        .bind(now - RESET_DELAY_MS)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(json!({
        "user_id": auth.user_id,
        // When a restore with the recovery key IN FORCE becomes instant (null: none on record),
        // and when the recovery key was last changed or removed (reported for one hold period:
        // the key it replaced still restores at once until then).
        "recovery_key_instant_from": verifier_set_at.map(|t| t + RESET_DELAY_MS),
        "recovery_key_changed_at": changed_at,
        // The account had a recovery key and none is in force now (it was retired, or used up
        // by an overlap restore): prompt for a new one.
        "recovery_key_needed": verifier_set_at.is_none() && had_recovery_key,
        // Devices that erased themselves (a current device may report one as lost/stolen).
        "erased": erased,
        "devices": devices,
        "reset_completes_at": reset_completes_at,
        "recoveries": recoveries,
        "max_devices": MAX_DEVICES_PER_USER,
    })))
}

// ---- device linking ----

pub(crate) const LINK_REQUEST_TTL_MS: i64 = 10 * 60 * 1000;

#[derive(Deserialize)]
pub struct LinkRequestCreate {
    pub identity_key: String,
    /// HMAC(link code, account ‖ identity key). The code itself never reaches the server.
    pub proof: String,
}

/// A not-yet-registered device asks to be linked. Stores only public values.
async fn create_link_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<LinkRequestCreate>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_link:{}", auth.user_id), 10, crate::limiter::HOUR)?;
    let identity_key = b64_decode(&req.identity_key)?;
    let proof = b64_decode(&req.proof)?;
    if !certs::is_valid_identity_key(&identity_key) || proof.len() != 32 {
        return Err(ApiError::BadRequest("bad link request"));
    }
    let now = now_ms();
    sqlx::query("DELETE FROM device_link_requests WHERE user_id = $1 AND (created_at < $2 OR identity_key = $3)")
        .bind(&auth.user_id)
        .bind(now - LINK_REQUEST_TTL_MS)
        .bind(&identity_key)
        .execute(&state.db)
        .await?;
    let id = new_id();
    sqlx::query("INSERT INTO device_link_requests (id, user_id, identity_key, proof, created_at) VALUES ($1, $2, $3, $4, $5)")
        .bind(&id)
        .bind(&auth.user_id)
        .bind(&identity_key)
        .bind(&proof)
        .bind(now)
        .execute(&state.db)
        .await?;
    state.rt.publish(&crate::rt::user_topic(&auth.user_id), "link_request", json!({}));
    Ok(Json(json!({ "request_id": id, "expires_at": now + LINK_REQUEST_TTL_MS })))
}

/// The account's pending (unapproved, unexpired) link requests, for its existing devices.
async fn list_link_requests(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Value>, ApiError> {
    let rows: Vec<(String, Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT id, identity_key, proof, created_at FROM device_link_requests
         WHERE user_id = $1 AND link_sig IS NULL AND created_at >= $2 ORDER BY created_at",
    )
    .bind(&auth.user_id)
    .bind(now_ms() - LINK_REQUEST_TTL_MS)
    .fetch_all(&state.db)
    .await?;
    let requests: Vec<Value> = rows
        .into_iter()
        .map(|(id, identity_key, proof, created_at)| {
            json!({ "request_id": id, "identity_key": B64.encode(identity_key), "proof": B64.encode(proof), "created_at": created_at })
        })
        .collect();
    Ok(Json(json!({ "requests": requests })))
}

#[derive(Deserialize)]
pub struct LinkApproval {
    pub device_id: String,
    pub signature: String,
    pub approval_mac: String,
    /// What the approver hands the new device (sibling set, account key, space keys, owner
    /// pins), sealed under a key derived from the link code. Opaque to the server.
    pub bundle: Option<String>,
}

pub(crate) const MAX_LINK_BUNDLE: usize = 256 * 1024;

/// An existing device approves a link request. The server checks the signature really is that
/// device's vouching for the requested identity (it cannot check the MAC — it has no code).
async fn approve_link_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(request_id): Path<String>,
    Json(req): Json<LinkApproval>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_link:{}", auth.user_id), 10, crate::limiter::HOUR)?;
    require_bound_device_session(&state, &auth, &req.device_id).await?;
    let approver_identity = own_device_identity(&state, &auth.user_id, &req.device_id).await?;
    let signature = b64_decode(&req.signature)?;
    let approval_mac = b64_decode(&req.approval_mac)?;
    let identity_key: Vec<u8> = sqlx::query_scalar(
        "SELECT identity_key FROM device_link_requests WHERE id = $1 AND user_id = $2 AND created_at >= $3",
    )
    .bind(&request_id)
    .bind(&auth.user_id)
    .bind(now_ms() - LINK_REQUEST_TTL_MS)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    if approval_mac.len() != 32 || !skwod_crypto::link::verify_link(&approver_identity, &auth.user_id, &identity_key, &signature) {
        return Err(ApiError::BadRequest("bad link approval"));
    }
    let bundle = req.bundle.as_deref().map(b64_decode).transpose()?;
    if bundle.as_ref().is_some_and(|b| b.len() > MAX_LINK_BUNDLE) {
        return Err(ApiError::BadRequest("link bundle too large"));
    }
    sqlx::query(
        "UPDATE device_link_requests SET approver_device_id = $1, approver_identity_key = $2, link_sig = $3, approval_mac = $4,
             approval_bundle = $7
         WHERE id = $5 AND user_id = $6",
    )
    .bind(&req.device_id)
    .bind(&approver_identity)
    .bind(&signature)
    .bind(&approval_mac)
    .bind(&request_id)
    .bind(&auth.user_id)
    .bind(bundle)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "success": true })))
}

/// The requesting device polls its own request for an approval.
async fn get_link_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(request_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let row: Option<(Option<String>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT approver_device_id, approver_identity_key, link_sig, approval_mac, approval_bundle FROM device_link_requests
         WHERE id = $1 AND user_id = $2 AND created_at >= $3",
    )
    .bind(&request_id)
    .bind(&auth.user_id)
    .bind(now_ms() - LINK_REQUEST_TTL_MS)
    .fetch_optional(&state.db)
    .await?;
    let (device_id, identity, sig, mac, bundle) = row.ok_or(ApiError::NotFound)?;
    Ok(Json(match (device_id, identity, sig, mac) {
        (Some(device_id), Some(identity), Some(sig), Some(mac)) => json!({
            "approved": true,
            "bundle": bundle.map(|b| B64.encode(b)),
            "device_id": device_id,
            "identity_key": B64.encode(identity),
            "signature": B64.encode(sig),
            "approval_mac": B64.encode(mac),
        }),
        _ => json!({ "approved": false }),
    }))
}

/// Every registered device of `user_id` (id, delivery key, identity key) — what a sender needs to reach ALL of a peer's
/// devices rather than whichever one a lookup happened to return. Same authorization as a bundle.
async fn user_devices(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // A client re-reads the device list before every send (never encrypt to a removed
    // member), so this allowance has to keep step with the send allowance (`messages.rs`).
    state.limiter.check(&format!("e2ee_devices:{}", auth.user_id), 600, crate::limiter::MINUTE)?;
    let devices = directory_devices(&state, &auth.user_id, &user_id).await?.ok_or(ApiError::Forbidden)?;
    // Identities of this user's devices that ERASED THEMSELVES and are not registered now. A
    // contact corroborates a device's "I am erasing myself" against this before it will take
    // that identity back under a new device row (it never does for a removed device).
    let erased: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT t.identity_key FROM device_tombstones t WHERE t.user_id = $1 AND t.reason = 'self_erased'
           AND NOT EXISTS (SELECT 1 FROM user_devices d WHERE d.user_id = t.user_id AND d.identity_key = t.identity_key)",
    )
    .bind(&user_id)
    .fetch_all(&state.db)
    .await?;
    let erased: Vec<String> = erased.iter().map(|k| B64.encode(k)).collect();
    Ok(Json(json!({ "user_id": user_id, "devices": devices, "erased": erased })))
}

#[derive(Deserialize)]
pub struct MemberDevicesQuery {
    pub server_id: String,
}

/// Every device of every member of a server the caller belongs to, in one round trip — the
/// recipient list for a channel sender-key distribution.
async fn member_devices(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<MemberDevicesQuery>,
) -> Result<Json<Value>, ApiError> {
    // A client re-reads the device list before every send (never encrypt to a removed
    // member), so this allowance has to keep step with the send allowance (`messages.rs`).
    state.limiter.check(&format!("e2ee_devices:{}", auth.user_id), 600, crate::limiter::MINUTE)?;
    let member: Option<String> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1 AND user_id = $2")
        .bind(&q.server_id)
        .bind(&auth.user_id)
        .fetch_optional(&state.db)
        .await?;
    if member.is_none() {
        return Err(ApiError::Forbidden);
    }
    let members: Vec<String> = sqlx::query_scalar("SELECT user_id FROM server_members WHERE server_id = $1 ORDER BY user_id")
        .bind(&q.server_id)
        .fetch_all(&state.db)
        .await?;
    // Sharing a server is not enough: each member goes through the same gate as a direct lookup,
    // so a member the caller blocked (or who blocked the caller) is simply absent from the list.
    let mut devices = Vec::new();
    for member in members {
        if let Some(entries) = directory_devices(&state, &auth.user_id, &member).await? {
            devices.extend(entries);
        }
    }
    Ok(Json(json!({ "devices": devices })))
}

#[derive(Deserialize)]
pub struct DeleteDeviceQuery {
    /// A device erasing itself because it was LOST: treated as a removal (its identity never
    /// comes back by itself; the recovery key is retired as compromised).
    pub lost: Option<u8>,
}

/// Delete ONE of the caller's own devices plus its dependent key material and mailbox.
///
/// A session token alone is NOT enough (it would let a token thief strip the account of its
/// devices). The request must carry a fresh signature over ("delete", account, device id) by the
/// identity key of a device currently on the account — the device itself or a sibling.
async fn delete_device(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Path(device_id): Path<String>,
    Query(q): Query<DeleteDeviceQuery>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_devdel:{}", auth.user_id), 20, crate::limiter::HOUR)?;
    let identity_key = own_device_identity(&state, &auth.user_id, &device_id).await?;
    // Proof AND a session of the signing device's current install (rule 3): a copied identity
    // key cannot strip the account of its devices, its own or a sibling's. `?lost=1` ("I am
    // erasing this because it was lost") is under the signature.
    let lost = q.lost.unwrap_or(0) != 0;
    let signer = device_authority(&state, &auth, &headers, "delete", &device_id, if lost { b"lost" } else { b"" }).await?;
    // WHY it leaves decides whether its identity may ever come back by itself: a device that
    // erased itself may (a later restore); one that another device removed — or that said it
    // was lost — may not.
    let removed_by_sibling = signer != device_id || lost;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    if purge_device(&mut tx, &auth.user_id, &device_id).await? == 0 {
        return Err(ApiError::NotFound);
    }
    // `removed` is permanent: a later self-erase of the same identity does not soften it.
    sqlx::query(
        "INSERT INTO device_tombstones (user_id, identity_key, device_id, reason, created_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id, identity_key) DO UPDATE SET
             reason = CASE WHEN device_tombstones.reason = 'removed' THEN 'removed' ELSE excluded.reason END,
             device_id = excluded.device_id, created_at = excluded.created_at",
    )
    .bind(&auth.user_id)
    .bind(&identity_key)
    .bind(&device_id)
    .bind(if removed_by_sibling { "removed" } else { "self_erased" })
    .bind(now)
    .execute(&mut *tx)
    .await?;
    // A device that was REMOVED may have known the recovery key (and could restore a sibling's
    // identity with it). The key in force is retired AT ONCE as compromised — no overlap, never
    // served or accepted again — and every remaining device is told to save a new one.
    let key_retired = removed_by_sibling && replace_verifier(&mut tx, &auth.user_id, None, now, Retire::Compromised).await?;
    tx.commit().await?;
    announce_device_removed(&state, &auth.user_id, &device_id).await;
    if key_retired {
        announce_recovery_key_change(&state, &auth.user_id, now).await;
    }
    Ok(Json(json!({ "success": true, "recovery_key_retired": key_retired })))
}

/// Tell the account's devices, the members of every server it is in and its DM partners that
/// a device moved to another install (a restore): `device_rekeyed`, with the new generation.
/// The same audience as a removal, for the same reason — the install that was left behind
/// still holds every key the device held. Best-effort.
async fn announce_device_rekeyed(state: &AppState, user_id: &str, device_id: &str, generation: i64) {
    let payload = json!({ "user_id": user_id, "device_id": device_id, "generation": generation });
    for topic in device_audience(state, user_id).await {
        state.rt.publish(&topic, "device_rekeyed", payload.clone());
    }
}

/// The topics of everyone who may hold keys for (or from) a device of `user_id`: the account
/// itself, the servers it is in, its DM partners.
async fn device_audience(state: &AppState, user_id: &str) -> Vec<String> {
    let mut topics = vec![crate::rt::user_topic(user_id)];
    let servers: Vec<String> =
        sqlx::query_scalar("SELECT server_id FROM server_members WHERE user_id = $1").bind(user_id).fetch_all(&state.db).await.unwrap_or_default();
    topics.extend(servers.iter().map(|s| crate::rt::server_topic(s)));
    let partners: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT b.user_id FROM dm_participants a JOIN dm_participants b ON a.conversation_id = b.conversation_id
         WHERE a.user_id = $1 AND b.user_id <> $2 LIMIT 500",
    )
    .bind(user_id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    topics.extend(partners.iter().map(|p| crate::rt::user_topic(p)));
    topics
}

/// Tell everyone who may hold keys for (or from) a removed device that it is gone: the account's
/// own devices, the members of every server the account is in, and its DM partners. They drop
/// the device's receive keys, rotate what it held and stop sending to it — and they check the
/// directory themselves rather than take this event's word for it. Best-effort.
async fn announce_device_removed(state: &AppState, user_id: &str, device_id: &str) {
    let payload = json!({ "user_id": user_id, "device_id": device_id });
    for topic in device_audience(state, user_id).await {
        state.rt.publish(&topic, "device_removed", payload.clone());
    }
    crate::messages::wake_user(state, user_id).await;
}

#[derive(Deserialize)]
pub struct CancelReset {
    pub device_id: String,
}

/// An existing device vetoes a pending account reset. Needs that device's signature — the party
/// who requested the reset holds a session token too, and must not be able to "cancel the cancel".
async fn cancel_reset(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<CancelReset>,
) -> Result<Json<Value>, ApiError> {
    device_authority(&state, &auth, &headers, "cancel-reset", &req.device_id, b"").await?;
    sqlx::query("UPDATE e2ee_accounts SET reset_requested_at = NULL, reset_identity_key = NULL WHERE user_id = $1")
        .bind(&auth.user_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "success": true })))
}

// ---- prekey bundle fetch ----

#[derive(Deserialize)]
pub struct BundleRequest {
    pub protocol_version: Option<u32>,
    pub user_id: String,
    pub device_id: String,
}

/// Atomically claim one unused one-time prekey of `kind` for a device.
async fn claim_one_time(state: &AppState, user_id: &str, device_id: &str, kind: &str) -> Result<Option<(i64, Vec<u8>, Option<Vec<u8>>)>, ApiError> {
    Ok(sqlx::query_as(
        "UPDATE one_time_prekeys SET used = 1
         WHERE id = (SELECT id FROM one_time_prekeys
                     WHERE user_id = $1 AND device_id = $2 AND kind = $3 AND used = 0
                     ORDER BY created_at, key_id LIMIT 1)
         RETURNING key_id, public_key, signature",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(kind)
    .fetch_optional(&state.db)
    .await?)
}

async fn prekey_bundle(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<BundleRequest>,
) -> Result<Json<Value>, ApiError> {
    require_protocol(req.protocol_version)?;
    // Authorization first: a bundle (and the one-time keys it burns) is only for accounts that
    // legitimately talk to the target.
    require_contact(&state, &auth.user_id, &req.user_id).await?;
    // Each fetch consumes one-time prekeys, so bound it three ways: per caller overall, per
    // (caller, target account) per minute, and per (caller, target account) per hour — the last
    // one is what stops a patient member from draining a specific victim's one-time keys.
    state.limiter.check(&format!("e2ee_bundle:{}", auth.user_id), 120, crate::limiter::MINUTE)?;
    state.limiter.check(&format!("e2ee_bundle_target:{}:{}", auth.user_id, req.user_id), 15, crate::limiter::MINUTE)?;
    state.limiter.check(&format!("e2ee_bundle_target_h:{}:{}", auth.user_id, req.user_id), 60, crate::limiter::HOUR)?;

    let row: Option<(i64, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT registration_id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_sig,
                kyber_last_resort_id, kyber_last_resort, kyber_last_resort_sig, delivery_key, spk_timestamp
         FROM user_devices WHERE user_id = $1 AND device_id = $2",
    )
    .bind(&req.user_id)
    .bind(&req.device_id)
    .fetch_optional(&state.db)
    .await?;
    let (registration_id, identity_key, spk_id, spk, spk_sig, lr_id, lr, lr_sig, delivery_key, spk_ts) = row.ok_or(ApiError::NotFound)?;

    let ec = claim_one_time(&state, &req.user_id, &req.device_id, "ec").await?;
    // One-time Kyber key if any remain; otherwise the last-resort key. Never no KEM key.
    let (kyber_id, kyber_pub, kyber_sig, kyber_last_resort) = match claim_one_time(&state, &req.user_id, &req.device_id, "kyber").await? {
        Some((id, public, Some(sig))) => (id, public, sig, false),
        _ => (lr_id, lr, lr_sig, true),
    };

    Ok(Json(json!({
        "protocol_version": PROTOCOL_VERSION,
        "user_id": req.user_id,
        "device_id": req.device_id,
        "registration_id": registration_id,
        "identity_key": B64.encode(identity_key),
        "signed_prekey": { "id": spk_id, "public": B64.encode(spk), "signature": B64.encode(spk_sig) },
        "kyber_prekey": { "id": kyber_id, "public": B64.encode(kyber_pub), "signature": B64.encode(kyber_sig) },
        "kyber_last_resort": kyber_last_resort,
        "one_time_prekey": ec.map(|(id, public, _)| json!({ "id": id, "public": B64.encode(public) })),
        "delivery_key": B64.encode(delivery_key),
        "spk_timestamp": spk_ts,
    })))
}

// ---- prekey replenish / rotation ----

#[derive(Deserialize)]
pub struct ReplenishRequest {
    pub device_id: String,
    #[serde(default)]
    pub one_time_prekeys: Vec<PrekeyUpload>,
    #[serde(default)]
    pub one_time_kyber_prekeys: Vec<SignedKeyUpload>,
}

async fn remaining_counts(db: impl sqlx::Executor<'_, Database = sqlx::Any> + Copy, user_id: &str, device_id: &str) -> Result<(i64, i64), ApiError> {
    let count = |kind: &'static str| {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM one_time_prekeys WHERE user_id = $1 AND device_id = $2 AND kind = $3 AND used = 0")
            .bind(user_id.to_string())
            .bind(device_id.to_string())
            .bind(kind)
    };
    Ok((count("ec").fetch_one(db).await?, count("kyber").fetch_one(db).await?))
}

async fn replenish_prekeys(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<ReplenishRequest>,
) -> Result<Json<Value>, ApiError> {
    require_device_session(&state, &auth, &req.device_id).await?;
    state.limiter.check(&format!("e2ee_replenish:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    let identity_key = own_device_identity(&state, &auth.user_id, &req.device_id).await?;
    if req.one_time_prekeys.is_empty() && req.one_time_kyber_prekeys.is_empty() {
        return Err(ApiError::BadRequest("no prekeys supplied"));
    }
    let keys = verified_one_time_keys(&identity_key, &req.one_time_prekeys, &req.one_time_kyber_prekeys)?;
    // A session token alone must not be able to feed prekeys into a device's stock (EC one-time
    // prekeys carry no signature at all): device proof over exactly the uploaded keys.
    let payload = skwod_crypto::link::op_payload(&[
        &keys_digest_input(keys.ec.iter().map(|k| k.1.as_slice())),
        &keys_digest_input(keys.kyber.iter().map(|k| k.public.as_slice())),
    ]);
    device_authority(&state, &auth, &headers, "replenish", &req.device_id, &payload).await?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM one_time_prekeys WHERE user_id = $1 AND device_id = $2 AND used = 1")
        .bind(&auth.user_id)
        .bind(&req.device_id)
        .execute(&mut *tx)
        .await?;
    // Replaying an existing key id is a client bug; the UNIQUE constraint surfaces it as 409.
    insert_one_time_keys(&mut tx, &auth.user_id, &req.device_id, &keys, now).await?;
    tx.commit().await?;
    let (ec, kyber) = remaining_counts(&state.db, &auth.user_id, &req.device_id).await?;
    Ok(Json(json!({ "uploaded": keys.ec.len(), "kyber_uploaded": keys.kyber.len(), "remaining": ec, "kyber_remaining": kyber })))
}

#[derive(Deserialize)]
pub struct DeviceQuery {
    pub device_id: String,
}

/// How many unused one-time prekeys the server still holds for one of the caller's devices, so the
/// client knows when to replenish.
async fn prekey_count(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<Value>, ApiError> {
    require_device_session(&state, &auth, &q.device_id).await?;
    own_device_identity(&state, &auth.user_id, &q.device_id).await?;
    let (ec, kyber) = remaining_counts(&state.db, &auth.user_id, &q.device_id).await?;
    let spk_ts: i64 = sqlx::query_scalar("SELECT spk_timestamp FROM user_devices WHERE user_id = $1 AND device_id = $2")
        .bind(&auth.user_id)
        .bind(&q.device_id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(json!({ "remaining": ec, "kyber_remaining": kyber, "spk_timestamp": spk_ts })))
}

#[derive(Deserialize)]
pub struct RotateSpkRequest {
    pub device_id: String,
    pub signed_prekey: SignedKeyUpload,
    pub last_resort_kyber_prekey: Option<SignedKeyUpload>,
}

/// Rotate the signed EC prekey (and optionally the last-resort Kyber key). Signatures must verify
/// under the device's stored identity key.
async fn rotate_spk(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<RotateSpkRequest>,
) -> Result<Json<Value>, ApiError> {
    require_device_session(&state, &auth, &req.device_id).await?;
    state.limiter.check(&format!("e2ee_rotate:{}", auth.user_id), 10, crate::limiter::HOUR)?;
    let identity_key = own_device_identity(&state, &auth.user_id, &req.device_id).await?;
    let signed = verified_signed_key(&identity_key, &req.signed_prekey, false)?;
    let last_resort = req.last_resort_kyber_prekey.as_ref().map(|k| verified_signed_key(&identity_key, k, true)).transpose()?;
    // Signed prekeys are public: a token holder could otherwise roll a device BACK to an old
    // (possibly compromised) signed prekey by replaying its signature. Device proof, bound to
    // exactly these keys, single use.
    let payload = skwod_crypto::link::op_payload(&[&signed.public, last_resort.as_ref().map(|k| k.public.as_slice()).unwrap_or_default()]);
    device_authority(&state, &auth, &headers, "spk-rotate", &req.device_id, &payload).await?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE user_devices SET signed_prekey_id = $1, signed_prekey = $2, signed_prekey_sig = $3,
             spk_timestamp = $4, last_active_at = $5 WHERE user_id = $6 AND device_id = $7",
    )
    .bind(signed.id as i64)
    .bind(&signed.public)
    .bind(&signed.signature)
    .bind(now)
    .bind(now)
    .bind(&auth.user_id)
    .bind(&req.device_id)
    .execute(&mut *tx)
    .await?;
    if let Some(lr) = last_resort {
        sqlx::query(
            "UPDATE user_devices SET kyber_last_resort_id = $1, kyber_last_resort = $2, kyber_last_resort_sig = $3
             WHERE user_id = $4 AND device_id = $5",
        )
        .bind(lr.id as i64)
        .bind(&lr.public)
        .bind(&lr.signature)
        .bind(&auth.user_id)
        .bind(&req.device_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(json!({ "success": true })))
}

// ---- instance identity + sealed-sender certificate authority ----

async fn load_or_create_secret(state: &AppState, name: &str, make: impl FnOnce() -> Result<Vec<u8>, ApiError>) -> Result<Vec<u8>, ApiError> {
    let existing: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = $1").bind(name).fetch_optional(&state.db).await?;
    if let Some(v) = existing {
        return Ok(v);
    }
    let value = make()?;
    // Racing first-users: exactly one INSERT wins; everyone re-reads the winner.
    sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(name)
        .bind(&value)
        .bind(now_ms())
        .execute(&state.db)
        .await?;
    Ok(sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = $1").bind(name).fetch_one(&state.db).await?)
}

/// Load (or create on first use) this instance's Ed25519 identity key: `(secret, public)`. The
/// public half is the instance's pinnable identity (see `structure::instance_identity`).
pub(crate) async fn server_signing_key(state: &AppState) -> Result<(Vec<u8>, Vec<u8>), ApiError> {
    let v = load_or_create_secret(state, SERVER_SIGNING_SECRET_NAME, || {
        let (secret, public) = skwod_crypto::instance::generate();
        let mut value = secret.to_vec();
        value.extend_from_slice(&public);
        Ok(value)
    })
    .await?;
    if v.len() != 64 {
        return Err(ApiError::Internal);
    }
    Ok((v[..32].to_vec(), v[32..].to_vec()))
}

fn encode_fields(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

fn decode_fields(mut bytes: &[u8], n: usize) -> Option<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let (len, rest) = bytes.split_at_checked(4)?;
        let len = u32::from_be_bytes(len.try_into().ok()?) as usize;
        let (field, rest) = rest.split_at_checked(len)?;
        out.push(field.to_vec());
        bytes = rest;
    }
    bytes.is_empty().then_some(out)
}

/// Load (or create on first use) the libsignal certificate authority for this instance.
async fn cert_authority(state: &AppState) -> Result<CertAuthority, ApiError> {
    let v = load_or_create_secret(state, CERT_AUTHORITY_SECRET_NAME, || {
        let ca = CertAuthority::generate().map_err(|_| ApiError::Internal)?;
        Ok(encode_fields(&[&ca.trust_root_public, &ca.trust_root_private, &ca.server_certificate, &ca.server_private]))
    })
    .await?;
    let mut f = decode_fields(&v, 4).ok_or(ApiError::Internal)?.into_iter();
    let mut next = || f.next().ok_or(ApiError::Internal);
    Ok(CertAuthority {
        trust_root_public: next()?,
        trust_root_private: next()?,
        server_certificate: next()?,
        server_private: next()?,
    })
}

/// The sealed-sender trust root, vouched for by the instance identity key. UNAUTHENTICATED: a
/// client verifies the signature against the instance key its invite pinned, so it does not have
/// to trust this response.
async fn trust_root(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let ca = cert_authority(&state).await?;
    let (secret, public) = server_signing_key(&state).await?;
    let signature = skwod_crypto::instance::sign(&secret, &certs::root_binding_message(&ca.trust_root_public)).ok_or(ApiError::Internal)?;
    Ok(Json(json!({
        "protocol_version": PROTOCOL_VERSION,
        "trust_root_public": B64.encode(&ca.trust_root_public),
        "signature": B64.encode(signature),
        "server_public": B64.encode(public),
    })))
}

#[derive(Deserialize)]
pub struct CertificateRequest {
    pub device_id: String,
}

/// Issue a 24 h libsignal sender certificate binding the caller's `user:device` address to that
/// device's registered identity key. The certificate travels INSIDE sealed envelopes; presenting it
/// to the server is never required again.
async fn issue_cert(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CertificateRequest>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_cert:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    require_device_session(&state, &auth, &req.device_id).await?;
    let identity_key = own_device_identity(&state, &auth.user_id, &req.device_id).await?;
    let ca = cert_authority(&state).await?;
    let expires = now_ms() as u64 + CERTIFICATE_TTL_MS;
    let cert = ca
        .issue(&DeviceAddress::new(auth.user_id.clone(), req.device_id.clone()), &identity_key, expires)
        .map_err(|_| ApiError::Internal)?;
    sqlx::query("UPDATE user_devices SET last_active_at = $1 WHERE user_id = $2 AND device_id = $3")
        .bind(now_ms())
        .bind(&auth.user_id)
        .bind(&req.device_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "certificate": B64.encode(cert), "expires": expires })))
}

// ---- sealed mailbox ----

#[derive(Deserialize)]
pub struct SealedDeposit {
    pub user_id: String,
    pub device_id: String,
    /// The recipient device's delivery key (base64), obtained with its prekey bundle.
    pub delivery_key: String,
    pub envelope: String,
}

#[derive(Deserialize)]
pub struct SealedSendRequest {
    pub messages: Vec<SealedDeposit>,
}

/// Arrival sequence for mailbox ordering: millisecond time with a counter in the low bits, strictly
/// increasing within this process (single-binary deployment) even for same-millisecond deposits.
fn next_seq(now: i64) -> i64 {
    use std::sync::atomic::{AtomicI64, Ordering};
    static LAST: AtomicI64 = AtomicI64::new(0);
    let floor = now.saturating_mul(4096);
    let mut prev = LAST.load(Ordering::Relaxed);
    loop {
        let next = floor.max(prev + 1);
        match LAST.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(actual) => prev = actual,
        }
    }
}

/// Deposit sealed-sender envelopes. **Takes no credentials** — the handler does not extract
/// `AuthUser` and ignores any Authorization header — so the server never links an envelope to an
/// account. Authorization is the recipient's delivery key. Flooding is bounded per recipient
/// device and by a mailbox cap rather than per sender (there is no sender to count against).
const MAX_SEALED_MISSES: usize = 16;
/// Backup downloads a day by sessions that are not a current device of the account.
/// Enough for a restore that is retried a few times on a few devices; small enough that the
/// blob is not a download anyone with the password repeats at will. (Per account, so someone
/// who has the password can use it up and delay the owner's restore until the next day —
/// they are told each time, and a current device changes the password.)
pub(crate) const BACKUP_FETCHES_WITHOUT_A_DEVICE_PER_DAY: u32 = 24;
/// Backup contents kept per recovery key (the newest), and bytes of backup history per account.
const MAX_BACKUP_BLOBS_PER_KEY: i64 = 8;
const MAX_BACKUP_HISTORY_BYTES: i64 = 24 * 1024 * 1024;

async fn sealed_send(State(state): State<AppState>, source: crate::client_key::ClientKey, Json(req): Json<SealedSendRequest>) -> Result<Json<Value>, ApiError> {
    if req.messages.is_empty() || req.messages.len() > MAX_ENVELOPES_PER_SEND {
        return Err(ApiError::BadRequest("1-256 envelopes per request"));
    }
    // Per source (network address / p2p node), never per account: the route stays credential-free.
    source.limit(&state, "sealed_send", SEALED_REQUESTS_PER_MINUTE)?;
    let now = now_ms();
    // Below the free-space floor nothing is queued: the answer is "busy", which senders retry.
    let disk_full = crate::blobs::free_space(&state.blob_dir).is_some_and(|free| free < state.blob_free_floor_bytes);
    let mut results = Vec::with_capacity(req.messages.len());
    let mut notify: Vec<String> = Vec::new();
    let mut misses = 0usize;
    for m in &req.messages {
        let envelope = b64_decode(&m.envelope)?;
        if envelope.is_empty() || envelope.len() > MAX_ENVELOPE {
            return Err(ApiError::BadRequest("envelope size"));
        }
        // A real sender has a stale device or two in a batch, not dozens. After that many
        // misses the rest of the request is answered "gone" without a lookup (audit M-2: an
        // unauthenticated request cost up to 256 database lookups whatever it carried).
        if misses >= MAX_SEALED_MISSES {
            results.push(json!({ "user_id": m.user_id, "device_id": m.device_id, "status": "gone" }));
            continue;
        }
        let presented = b64_decode(&m.delivery_key)?;
        let stored: Option<Vec<u8>> = sqlx::query_scalar("SELECT delivery_key FROM user_devices WHERE user_id = $1 AND device_id = $2")
            .bind(&m.user_id)
            .bind(&m.device_id)
            .fetch_optional(&state.db)
            .await?;
        // Unknown device and wrong key are indistinguishable to the caller ("gone"): the sender
        // should refresh the device list either way, and probing reveals nothing.
        let ok = stored.as_ref().is_some_and(|s| bool::from(s.as_slice().ct_eq(&presented)));
        if !ok {
            misses += 1;
            results.push(json!({ "user_id": m.user_id, "device_id": m.device_id, "status": "gone" }));
            continue;
        }
        if state.limiter.check(&format!("sealed_rx:{}:{}", m.user_id, m.device_id), 600, crate::limiter::MINUTE).is_err() {
            results.push(json!({ "user_id": m.user_id, "device_id": m.device_id, "status": "busy" }));
            continue;
        }
        let (queued, queued_bytes): (i64, i64) = sqlx::query_as("SELECT CAST(count(*) AS BIGINT), CAST(COALESCE(SUM(length(envelope)), 0) AS BIGINT) FROM sealed_envelopes WHERE user_id = $1 AND device_id = $2")
            .bind(&m.user_id)
            .bind(&m.device_id)
            .fetch_one(&state.db)
            .await?;
        let crowded_out = queued >= MAILBOX_CROWDED
            && state.limiter.check(&format!("sealed_src:{}:{}:{}", source.key, m.user_id, m.device_id), CROWDED_PER_SOURCE_PER_DAY, 24 * crate::limiter::HOUR).is_err();
        if disk_full || queued >= MAX_MAILBOX || queued_bytes + envelope.len() as i64 > MAX_MAILBOX_BYTES || crowded_out {
            results.push(json!({ "user_id": m.user_id, "device_id": m.device_id, "status": "busy" }));
            continue;
        }
        sqlx::query("INSERT INTO sealed_envelopes (id, user_id, device_id, envelope, seq, created_at) VALUES ($1, $2, $3, $4, $5, $6)")
            .bind(new_id())
            .bind(&m.user_id)
            .bind(&m.device_id)
            .bind(&envelope)
            .bind(next_seq(now))
            .bind(now)
            .execute(&state.db)
            .await?;
        results.push(json!({ "user_id": m.user_id, "device_id": m.device_id, "status": "ok" }));
        if !notify.contains(&m.user_id) {
            notify.push(m.user_id.clone());
        }
    }
    // Nudge recipients (realtime + data-only push). The event names the RECIPIENT only, and
    // every envelope is treated alike: the server is not told (and must not be able to tell) a
    // message from a sender key or a call key. Wakes are coalesced and jittered (gateway.rs);
    // the device decides what, if anything, to show.
    for user_id in notify {
        state.rt.publish(&crate::rt::user_topic(&user_id), "sealed", json!({}));
        crate::messages::wake_user(&state, &user_id).await;
    }
    Ok(Json(json!({ "results": results })))
}

/// Fetch (without removing) the oldest queued envelopes for one of the caller's devices.
async fn sealed_inbox(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Query(q): Query<DeviceQuery>,
) -> Result<Json<Value>, ApiError> {
    // The device must be the caller's, on a session bound to it at its current generation. One
    // exception in the order of the answers: a build ≤ 42 polls this every few seconds and a 426
    // is what it shows the user (`oldbuilds.rs`), so an old build on a device that IS the
    // caller's is told to update rather than given an error it cannot read.
    let gate = require_device_session(&state, &auth, &q.device_id).await;
    if !matches!(gate, Err(ApiError::DeviceRemoved | ApiError::Forbidden))
        && crate::oldbuilds::is_old(&state, &auth.user_id, &q.device_id, crate::oldbuilds::build_of(&headers))
    {
        return Err(ApiError::UpgradeRequired(crate::oldbuilds::UPDATE_REQUIRED));
    }
    gate?;
    let now = now_ms();
    sqlx::query("DELETE FROM sealed_envelopes WHERE user_id = $1 AND device_id = $2 AND created_at < $3")
        .bind(&auth.user_id)
        .bind(&q.device_id)
        .bind(now - MAILBOX_RETENTION_MS)
        .execute(&state.db)
        .await?;
    let rows: Vec<(String, Vec<u8>, i64)> = sqlx::query_as(
        "SELECT id, envelope, created_at FROM sealed_envelopes WHERE user_id = $1 AND device_id = $2
         ORDER BY seq LIMIT $3",
    )
    .bind(&auth.user_id)
    .bind(&q.device_id)
    .bind(INBOX_PAGE)
    .fetch_all(&state.db)
    .await?;
    sqlx::query("UPDATE user_devices SET last_active_at = $1 WHERE user_id = $2 AND device_id = $3")
        .bind(now)
        .bind(&auth.user_id)
        .bind(&q.device_id)
        .execute(&state.db)
        .await?;
    let more = rows.len() as i64 == INBOX_PAGE;
    let envelopes: Vec<Value> =
        rows.into_iter().map(|(id, env, created_at)| json!({ "id": id, "envelope": B64.encode(env), "created_at": created_at })).collect();
    Ok(Json(json!({ "envelopes": envelopes, "more": more })))
}

#[derive(Deserialize)]
pub struct SealedAck {
    pub device_id: String,
    pub ids: Vec<String>,
}

/// Remove envelopes the device has processed.
async fn sealed_ack(State(state): State<AppState>, auth: AuthUser, Json(req): Json<SealedAck>) -> Result<Json<Value>, ApiError> {
    if req.ids.len() > 1000 {
        return Err(ApiError::BadRequest("too many ids"));
    }
    require_device_session(&state, &auth, &req.device_id).await?;
    let mut removed = 0u64;
    for id in &req.ids {
        removed += sqlx::query("DELETE FROM sealed_envelopes WHERE id = $1 AND user_id = $2 AND device_id = $3")
            .bind(id)
            .bind(&auth.user_id)
            .bind(&req.device_id)
            .execute(&state.db)
            .await?
            .rows_affected();
    }
    Ok(Json(json!({ "removed": removed })))
}

// ---- passphrase key backup (opaque to the server) ----

#[derive(Deserialize)]
pub struct BackupPut {
    pub encrypted_blob: String, // b64
    pub salt: String,           // b64, >= 8 bytes
    pub version: i64,
    pub kdf_params: Value, // JSON: argon2id parameters used by the client
    /// Public half of the recovery proof key (33 bytes, base64). Covered by the device proof.
    pub auth_verifier: Option<String>,
}

/// What a `backup-put` device proof signs: blob, salt, version and the Argon2id cost parameters.
pub(crate) fn backup_payload(blob: &[u8], salt: &[u8], version: i64, kdf_params: &Value) -> Vec<u8> {
    let n = |k: &str| kdf_params[k].as_u64().unwrap_or(0).to_be_bytes();
    skwod_crypto::link::op_payload(&[blob, salt, &version.to_be_bytes(), &n("m_kib"), &n("t"), &n("p")])
}

async fn put_backup(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<BackupPut>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_backup:{}", auth.user_id), 60, crate::limiter::HOUR)?;
    // Replacing the backup is an account-security mutation: a token thief must not be able to
    // destroy it or swap in a blob of their own. Only a device on the account may write it.
    // The signature covers the blob, salt, version and KDF parameters, so a captured proof cannot
    // carry a different backup.
    let blob = b64_decode(&req.encrypted_blob)?;
    let salt = b64_decode(&req.salt)?;
    // The verifier decides who may restore at once, so it is under the signature too: only a
    // current install of a device can set it.
    let verifier = req.auth_verifier.as_deref().map(b64_decode).transpose()?;
    if verifier.as_ref().is_some_and(|v| v.len() != 33) {
        return Err(ApiError::BadRequest("bad auth_verifier"));
    }
    let base = backup_payload(&blob, &salt, req.version, &req.kdf_params);
    let payload = match &verifier {
        Some(v) => skwod_crypto::link::op_payload(&[&base, v]),
        None => base,
    };
    let writer = device_authority(&state, &auth, &headers, "backup-put", "backup", &payload).await?;
    if salt.len() < 16 {
        return Err(ApiError::BadRequest("salt too short"));
    }
    if blob.len() > 1024 * 1024 || salt.len() > 64 {
        return Err(ApiError::BadRequest("backup too large"));
    }
    let now = now_ms();
    let kdf_params = req.kdf_params.to_string();
    if kdf_params.len() > 1024 {
        return Err(ApiError::BadRequest("kdf_params too large"));
    }
    // The history is bounded and counted (audit M-2: every changed upload appended up to
    // 1 MB, 60 an hour, kept until the key was retired plus the hold). Below the free-space
    // floor nothing is added; and an account's backup history never holds more than
    // `MAX_BACKUP_HISTORY_BYTES` — past that an upload is REFUSED, never made room for by
    // dropping an older key's blobs: those are what the owner restores from after a key was
    // planted.
    if crate::blobs::free_space(&state.blob_dir).is_some_and(|free| free < state.blob_free_floor_bytes.saturating_add(blob.len() as u64)) {
        return Err(ApiError::InsufficientStorage("this skwod's host is almost out of disk space, so it cannot store a backup right now"));
    }
    let held: i64 = sqlx::query_scalar("SELECT CAST(COALESCE(SUM(length(encrypted_blob)), 0) AS BIGINT) FROM backup_blobs WHERE user_id = $1").bind(&auth.user_id).fetch_one(&state.db).await?;
    if held.saturating_add(blob.len() as i64) > MAX_BACKUP_HISTORY_BYTES {
        return Err(ApiError::PayloadTooLarge("this account's backup history is full; it empties as old recovery keys expire (7 days)"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO e2ee_key_backups (user_id, encrypted_blob, salt, version, kdf, kdf_params, created_at, updated_at, device_id)
         VALUES ($1, $2, $3, $4, 'argon2id', $5, $6, $7, $8)
         ON CONFLICT (user_id) DO UPDATE SET encrypted_blob = excluded.encrypted_blob, salt = excluded.salt,
             version = excluded.version, kdf_params = excluded.kdf_params, updated_at = excluded.updated_at,
             device_id = excluded.device_id",
    )
    .bind(&auth.user_id)
    .bind(&blob)
    .bind(&salt)
    .bind(req.version)
    .bind(&kdf_params)
    .bind(now)
    .bind(now)
    // The device this backup restores (see `request_backup`).
    .bind(&writer)
    .execute(&mut *tx)
    .await?;
    // The recovery key is what the verifier stands for. The same one (a routine re-upload):
    // its history row just takes the new blob — its age carries on. Anything else — another
    // verifier, or none — is a CHANGE of recovery key (see `replace_verifier`).
    let changed = replace_verifier(&mut tx, &auth.user_id, verifier.as_deref(), now, Retire::Replaced).await?;
    let mut instant_from = None;
    let mut contents_replaced = false;
    if let Some(v) = &verifier {
        let in_force: Option<(String, i64)> = sqlx::query_as("SELECT id, set_at FROM backup_keys WHERE user_id = $1 AND retired_at IS NULL AND verifier = $2")
            .bind(&auth.user_id)
            .bind(v)
            .fetch_optional(&mut *tx)
            .await?;
        // A new key seasons from now — also one that was used before: a key coming back by a
        // WRITE is as new as any other. The same key keeps its row, and so its age.
        let (key_id, set_at) = match in_force {
            Some(key) => key,
            None => {
                let id = new_id();
                sqlx::query("INSERT INTO backup_keys (id, user_id, verifier, set_at) VALUES ($1, $2, $3, $4)").bind(&id).bind(&auth.user_id).bind(v).bind(now).execute(&mut *tx).await?;
                (id, now)
            }
        };
        instant_from = Some(set_at + RESET_DELAY_MS);
        // The contents: a blob is never rewritten. New contents are a new blob under the key;
        // the same contents again record nothing.
        let latest: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT encrypted_blob, salt FROM backup_blobs WHERE key_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1")
            .bind(&key_id)
            .fetch_optional(&mut *tx)
            .await?;
        if latest.as_ref() != Some(&(blob.clone(), salt.clone())) {
            contents_replaced = latest.is_some();
            sqlx::query("INSERT INTO backup_blobs (id, key_id, user_id, encrypted_blob, salt, version, kdf_params, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
                .bind(new_id())
                .bind(&key_id)
                .bind(&auth.user_id)
                .bind(&blob)
                .bind(&salt)
                .bind(req.version)
                .bind(&kdf_params)
                .bind(now)
                .execute(&mut *tx)
                .await?;
        }
    }
    // Under ONE key, only the newest contents matter for a restore (older ones of the same
    // key are superseded states of the same devices): keep the newest few. So "the previous
    // contents stay restorable for the hold period" holds for the last
    // `MAX_BACKUP_BLOBS_PER_KEY - 1` uploads under a key, not for every one ever made; a
    // current device that wants to bury an older state needs that many uploads, and each is
    // announced. Blobs of OTHER keys are never touched here.
    let keys: Vec<String> = sqlx::query_scalar("SELECT id FROM backup_keys WHERE user_id = $1").bind(&auth.user_id).fetch_all(&mut *tx).await?;
    for key_id in keys {
        let keep: Vec<String> = sqlx::query_scalar("SELECT id FROM backup_blobs WHERE key_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2")
            .bind(&key_id)
            .bind(MAX_BACKUP_BLOBS_PER_KEY)
            .fetch_all(&mut *tx)
            .await?;
        if keep.len() as i64 == MAX_BACKUP_BLOBS_PER_KEY {
            let all: Vec<String> = sqlx::query_scalar("SELECT id FROM backup_blobs WHERE key_id = $1").bind(&key_id).fetch_all(&mut *tx).await?;
            for id in all.into_iter().filter(|id| !keep.contains(id)) {
                sqlx::query("DELETE FROM backup_blobs WHERE id = $1").bind(&id).execute(&mut *tx).await?;
            }
        }
    }
    // The sweep: a blob goes only when its KEY is retired and the hold has passed since.
    sqlx::query("DELETE FROM backup_blobs WHERE user_id = $1 AND key_id IN (SELECT id FROM backup_keys WHERE user_id = $2 AND retired_at IS NOT NULL AND retired_at + $3 < $4)")
        .bind(&auth.user_id)
        .bind(&auth.user_id)
        .bind(RESET_DELAY_MS)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    if changed {
        // A changed key voids every outstanding challenge.
        sqlx::query("DELETE FROM backup_auth_nonces WHERE user_id = $1").bind(&auth.user_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    if changed {
        announce_recovery_key_change(&state, &auth.user_id, now).await;
    } else if contents_replaced {
        // Announced too — as what it is: the backup's contents were replaced under the SAME
        // recovery key (devices refresh it as their state changes). The previous contents
        // stay restorable for the hold period.
        state.rt.publish(&crate::rt::user_topic(&auth.user_id), "backup_updated", json!({ "at": now }));
    }
    Ok(Json(json!({ "success": true, "recovery_key_instant_from": instant_from })))
}

/// One backup as `get_backup` serves it.
fn backup_json(blob: &[u8], salt: &[u8], version: i64, kdf_params: &str) -> Value {
    json!({
        "encrypted_blob": B64.encode(blob),
        "salt": B64.encode(salt),
        "version": version,
        "kdf": "argon2id",
        "kdf_params": serde_json::from_str::<Value>(kdf_params).unwrap_or(Value::Null),
    })
}

const BACKUP_WITHHELD: &str = "this account's recovery key was set less than 7 days ago; its backup can be restored once the key is 7 days old";
/// Carries the requesting install's secret on `GET /key-backup` (base64, 32 bytes): the
/// preimage of the hash its restore request was filed with.
const INSTALL_SECRET_HEADER: &str = "x-skwod-install-secret";

/// The device the account's backup restores: the one that wrote it. A backup from before that
/// was recorded belongs, unambiguously, to an account's only device; otherwise unknown.
async fn backup_device(state: &AppState, user_id: &str) -> Result<Option<String>, ApiError> {
    let recorded: Option<Option<String>> = sqlx::query_scalar("SELECT device_id FROM e2ee_key_backups WHERE user_id = $1").bind(user_id).fetch_optional(&state.db).await?;
    let Some(recorded) = recorded else { return Err(ApiError::NotFound) };
    let devices: Vec<String> = sqlx::query_scalar("SELECT device_id FROM user_devices WHERE user_id = $1").bind(user_id).fetch_all(&state.db).await?;
    Ok(match recorded {
        Some(device) if devices.contains(&device) => Some(device),
        Some(_) => None,
        None if devices.len() == 1 => devices.into_iter().next(),
        None => None,
    })
}

/// Has the install presenting its secret been GRANTED the withheld backup? Only if a restore
/// request for the backup's device was filed with the hash of exactly that secret, and a
/// current device approved it (or the registration PIN did) or the hold has run out on it.
async fn backup_request_granted(state: &AppState, user_id: &str, headers: &axum::http::HeaderMap, now: i64) -> Result<bool, ApiError> {
    use sha2::{Digest, Sha256};
    let Some(secret) = headers.get(INSTALL_SECRET_HEADER).and_then(|v| v.to_str().ok()).and_then(|v| b64_decode(v).ok()).filter(|s| s.len() == 32) else { return Ok(false) };
    let Some(device_id) = backup_device(state, user_id).await? else { return Ok(false) };
    let pending: Option<(i64, Option<String>, Option<i64>)> = sqlx::query_as("SELECT requested_at, approved_by, contested_at FROM device_recoveries WHERE user_id = $1 AND device_id = $2 AND install_hash = $3")
        .bind(user_id)
        .bind(&device_id)
        .bind(Sha256::digest(&secret).to_vec())
        .fetch_optional(&state.db)
        .await?;
    Ok(pending.is_some_and(|(requested_at, approved_by, contested_at)| recovery_granted(requested_at, approved_by.as_deref(), contested_at, now)))
}

#[derive(Deserialize)]
pub struct BackupRequest {
    /// SHA-256 of the requesting install's secret (as in a re-key).
    pub install_hash: String,
    pub pin: Option<String>,
}

/// A sign-in that is not one of the account's devices asks to restore the account's backup
/// while its recovery key is too young for the backup to be handed over (`get_backup`).
///
/// Restoring by approval used to start with the backup: the new install opened it and asked,
/// with the restored identity, to be made the device (`rekey_device` → `authorize_recovery`).
/// With the backup withheld it cannot ask that way. So it asks HERE, and this is the same
/// request, in the same table, under the same rules — filed against the device the backup
/// restores, for this install's secret hash: every device of the account is told, any of them
/// approves or refuses exactly this request (`approve_recovery` / `cancel_recovery`,
/// device-signed), the seasoned registration PIN grants it, and un-cancelled it completes
/// after the hold. Once granted, `get_backup` serves the backup to the install holding the
/// secret, and the re-key that follows finds the request already granted.
///
/// What this does NOT do: it hands nothing over. A request by itself opens no route — not the
/// backup, not the key directory, not anything else; and one made without the recovery key
/// gets, even when someone approves it, a ciphertext it cannot open and a re-key it cannot sign.
async fn request_backup(State(state): State<AppState>, auth: AuthUser, Json(req): Json<BackupRequest>) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_recovery:{}", auth.user_id), 30, crate::limiter::HOUR)?;
    let install_hash = install_hash_of(Some(&req.install_hash))?.ok_or(ApiError::BadRequest("install_hash required"))?;
    // Which device it is about is the server's record, never the caller's word. Unknown (a
    // backup from before that was recorded, on an account with several devices): as before.
    let device_id = backup_device(&state, &auth.user_id).await?.ok_or(ApiError::Conflict(BACKUP_WITHHELD))?;
    authorize_recovery(&state, &auth, &device_id, &install_hash, req.pin.as_deref()).await?;
    // Granted. By an approval or the hold there is a row saying so; the PIN leaves none, so
    // record the grant for this install (the backup fetch and the re-key both look for it).
    let now = now_ms();
    let row: Option<(i64, Option<String>, Option<i64>)> = sqlx::query_as("SELECT requested_at, approved_by, contested_at FROM device_recoveries WHERE user_id = $1 AND device_id = $2 AND install_hash = $3")
        .bind(&auth.user_id)
        .bind(&device_id)
        .bind(&install_hash)
        .fetch_optional(&state.db)
        .await?;
    let on_record = row.is_some_and(|(requested_at, approved_by, contested_at)| recovery_granted(requested_at, approved_by.as_deref(), contested_at, now));
    if !on_record {
        // Granted by the PIN — outside every filing limit and cap, like the recovery key. It
        // is an approval: every other request for this device is over, in the same step.
        let mut tx = state.db.begin().await?;
        lock_recoveries(&mut tx, &auth.user_id, &device_id).await?;
        sqlx::query("DELETE FROM device_recoveries WHERE user_id = $1 AND device_id = $2").bind(&auth.user_id).bind(&device_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO device_recoveries (user_id, device_id, install_hash, requested_at, approved_by, nonce) VALUES ($1, $2, $3, $4, 'pin', $5)")
            .bind(&auth.user_id)
            .bind(&device_id)
            .bind(&install_hash)
            .bind(now)
            .bind(new_id())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(Json(json!({ "success": true, "device_id": device_id })))
}

/// The account's backup — and, in `alternates`, the backups sealed under recovery keys that
/// were replaced but are still in their overlap. A restore tries its recovery key against each:
/// the owner's key opens the owner's backup even after someone put another in its place or
/// deleted it. (All of it is ciphertext under a recovery key; none of it is new to the server.)
async fn get_backup(State(state): State<AppState>, auth: AuthUser, headers: axum::http::HeaderMap) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_backup:{}", auth.user_id), 60, crate::limiter::HOUR)?;
    let now = now_ms();
    let mut current: Option<(Vec<u8>, Vec<u8>, i64, String)> =
        sqlx::query_as("SELECT encrypted_blob, salt, version, kdf_params FROM e2ee_key_backups WHERE user_id = $1").bind(&auth.user_id).fetch_optional(&state.db).await?;
    // The backup in force is sealed under the recovery key in force. While that key is younger
    // than the hold period it is served only to a session that IS one of the account's current
    // devices (which holds the identity anyway). Anyone else — a password-only login from
    // another machine — waits until the key has seasoned, like every other use of a new
    // recovery key: otherwise "set a recovery key on a borrowed phone, then fetch the backup
    // from home" hands over the identity key at once.
    let unseasoned_until: Option<i64> = sqlx::query_scalar("SELECT set_at FROM backup_keys WHERE user_id = $1 AND retired_at IS NULL AND set_at + $2 > $3 ORDER BY set_at DESC LIMIT 1")
        .bind(&auth.user_id)
        .bind(RESET_DELAY_MS)
        .bind(now)
        .fetch_optional(&state.db)
        .await?
        .map(|set_at: i64| set_at + RESET_DELAY_MS);
    let mut withheld = false;
    if current.is_some() && unseasoned_until.is_some() {
        let bound = match auth.device_id.as_deref() {
            Some(device) => require_bound_device_session(&state, &auth, device).await.is_ok(),
            None => false,
        };
        // …or to the install whose request to restore it was APPROVED by a current device
        // (or sat out the hold un-cancelled, every device having been told): `request_backup`.
        if !bound && !backup_request_granted(&state, &auth.user_id, &headers, now).await? {
            current = None;
            withheld = true;
        }
    }
    // Every blob whose KEY is valid right now — the key in force (its earlier contents too,
    // for the hold period) and seasoned keys in their overlap. A blob under a key that is not
    // valid is never served, whatever the blob's own age.
    let overlap: Vec<(Vec<u8>, Vec<u8>, i64, String)> = sqlx::query_as(
        "SELECT b.encrypted_blob, b.salt, b.version, b.kdf_params FROM backup_blobs b JOIN backup_keys k ON k.id = b.key_id
         WHERE k.user_id = $1 AND (k.retired_at IS NULL OR (k.retired_at > $2 AND k.retire_reason = 'replaced'))
           AND k.set_at + $3 <= $2
         ORDER BY CASE WHEN k.retired_at IS NULL THEN 0 ELSE 1 END, b.created_at DESC, b.id DESC
         LIMIT 16",
    )
    .bind(&auth.user_id)
    .bind(now)
    .bind(RESET_DELAY_MS)
    .fetch_all(&state.db)
    .await?;
    let overlap: Vec<(Vec<u8>, Vec<u8>, i64, String)> = overlap.into_iter().filter(|b| current.as_ref() != Some(b)).collect();
    let mut all: Vec<Value> = current.iter().chain(overlap.iter()).map(|(blob, salt, version, kdf)| backup_json(blob, salt, *version, kdf)).collect();
    if all.is_empty() {
        if withheld {
            return Err(ApiError::Conflict(BACKUP_WITHHELD));
        }
        return Err(ApiError::NotFound);
    }
    // Who is asking (audit M-4)? A session that IS a current install of one of the account's
    // devices holds the identity already. Anyone else — a sign-in with the password alone, on
    // the way to a restore, or someone who only has the password — is handed material that can
    // be attacked offline when the backup is protected by a passphrase rather than a generated
    // key. The proof of the recovery key cannot be asked for FIRST: the key that makes it is
    // sealed inside this blob. So such a fetch is rare (a handful a day per account, not 60 an
    // hour), and never silent: every device of the account is told at once, and woken.
    let current_device = match auth.device_id.as_deref() {
        Some(device) => require_bound_device_session(&state, &auth, device).await.is_ok(),
        None => false,
    };
    if !current_device {
        state.limiter.check(&format!("e2ee_backup_fetch_unbound:{}", auth.user_id), BACKUP_FETCHES_WITHOUT_A_DEVICE_PER_DAY, 24 * crate::limiter::HOUR)?;
        state.rt.publish(&crate::rt::user_topic(&auth.user_id), "backup_fetched", json!({ "at": now }));
        crate::messages::wake_user(&state, &auth.user_id).await;
    }
    let mut first = all.remove(0);
    first["alternates"] = json!(all);
    Ok(Json(first))
}

/// Delete the account's key backup (the user turned backup off). The recovery key in force is
/// thereby REMOVED — which is a change like any other: announced to every device, and the key
/// (if seasoned) keeps restoring at once for one more hold period, from the history that this
/// does not touch. So deleting the backup is not a way to lock the owner out.
async fn delete_backup(State(state): State<AppState>, auth: AuthUser, headers: axum::http::HeaderMap) -> Result<Json<Value>, ApiError> {
    device_authority(&state, &auth, &headers, "backup-delete", "backup", b"").await?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM e2ee_key_backups WHERE user_id = $1").bind(&auth.user_id).execute(&mut *tx).await?;
    let changed = replace_verifier(&mut tx, &auth.user_id, None, now, Retire::Replaced).await?;
    sqlx::query("DELETE FROM backup_auth_nonces WHERE user_id = $1").bind(&auth.user_id).execute(&mut *tx).await?;
    tx.commit().await?;
    if changed {
        announce_recovery_key_change(&state, &auth.user_id, now).await;
    }
    Ok(Json(json!({ "success": true })))
}

// ---- registration PIN ----

#[derive(Deserialize)]
pub struct RegistrationPinRequest {
    pub enable: bool,
    pub pin: Option<String>,
    /// Required when a PIN is already set (to change or disable it).
    pub current_pin: Option<String>,
}

/// Enable, change or disable the registration lock.
///
/// The PIN is what lets an account reset skip the waiting period, so setting it is itself an
/// account-security mutation and a session token is not enough:
/// - the request must be signed by a device currently on the account, over the new PIN, and the
///   signature is accepted once;
/// - if a PIN is already set, the current PIN is required too (wrong tries count toward lockout);
/// - and a PIN only waives the reset hold once it has been in place for the length of that hold.
///
/// The PIN protects no key material; it is stored as an Argon2id hash.
async fn set_registration_pin(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegistrationPinRequest>,
) -> Result<Json<Value>, ApiError> {
    state.limiter.check(&format!("e2ee_pin:{}", auth.user_id), 20, crate::limiter::HOUR)?;
    // The proof covers the new PIN itself: a captured "set-pin" signature cannot set another PIN.
    let signed_pin = req.pin.as_deref().unwrap_or("");
    device_authority(&state, &auth, &headers, "set-pin", if req.enable { "enable" } else { "disable" }, signed_pin.as_bytes()).await?;
    // Changing or removing an existing PIN needs the PIN (no-op when no lock is enabled).
    verify_registration_pin(&state, &auth.user_id, req.current_pin.as_deref()).await?;
    let pin_hash = if req.enable {
        let pin = req.pin.ok_or(ApiError::BadRequest("pin required to enable"))?;
        if pin.chars().count() < 6 || pin.len() > 128 {
            return Err(ApiError::BadRequest("pin must be 6-128 characters"));
        }
        Some(crate::auth::hash_secret(&pin)?)
    } else {
        None
    };
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE profiles SET registration_pin_hash = $1, registration_lock_enabled = $2,
             pin_attempt_count = 0, pin_locked_until = NULL WHERE id = $3",
    )
    .bind(&pin_hash)
    .bind(req.enable as i64)
    .bind(&auth.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE e2ee_accounts SET pin_set_at = $1 WHERE user_id = $2")
        .bind(req.enable.then(now_ms))
        .bind(&auth.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(json!({ "success": true, "waives_reset_hold_from": req.enable.then(|| now_ms() + RESET_DELAY_MS) })))
}

// The unauthenticated "key transparency" log and the device-attestation routes that used to be
// here are gone (audit L2): they accepted any session token, verified nothing they stored, and
// no client ever called them — an `attested` flag anyone could set is worse than none. Real key
// transparency is on the roadmap (docs/SECURITY.md); it will not be built on those tables.
