//! Join-code gating — the server-side "may this person create an account here?" check.
//!
//! skwod hosts nothing centrally: every server is self-hosted by an operator who runs `skwod init`
//! (which sets an `admin_setup_code`). Security model:
//!
//! - The `admin_setup_code` is a **one-time bootstrap** key: it authorizes exactly the FIRST signup,
//!   which claims instance ownership (`owner_user_id`). Once ownership is claimed the bootstrap code
//!   is permanently dead — a leaked/old init code can never mint another account. This is the fix
//!   for the "forever skeleton key" problem.
//! - Everyone after the owner must present a **server invite**: expiring, use-limited, and
//!   revocable (see the `invites` table). Invites default to a 7-day expiry when the host doesn't
//!   set one, so a code that leaks doesn't work indefinitely.
//! - A never-initialized (dev/test) instance allows open signup.

use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::state::{now_ms, AppState};

/// Default lifetime for a server invite when the host doesn't specify one (7 days).
pub const DEFAULT_INVITE_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// How a join code validated — signup uses this to know whether to claim instance ownership.
#[derive(Debug, PartialEq, Eq)]
pub enum JoinAuth {
    /// The one-time bootstrap code, and ownership is not yet claimed → this signup becomes owner.
    Bootstrap,
    /// A valid, unexpired, non-exhausted server invite.
    Invite,
    /// Not valid.
    Invalid,
}

/// Whether instance ownership has been claimed (the first account exists).
async fn owner_claimed(state: &AppState) -> Result<bool, ApiError> {
    let has: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM instance_secrets WHERE name = 'owner_user_id') THEN 1 ELSE 0 END AS BIGINT)")
        .fetch_one(&state.db)
        .await?;
    Ok(has == 1)
}

/// Validate a join code, reporting HOW it validated so signup can claim ownership on bootstrap.
pub async fn authorize_join(state: &AppState, code: &str) -> Result<JoinAuth, ApiError> {
    // Bootstrap: the admin_setup_code works only until ownership is claimed, then it's dead forever.
    if !owner_claimed(state).await? {
        let admin_hash: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT value FROM instance_secrets WHERE name = 'admin_setup_code'")
                .fetch_optional(&state.db)
                .await?;
        if let Some(hash) = admin_hash {
            // Constant-time compare of the SHA-256 digests.
            let given = Sha256::digest(code.as_bytes());
            if given.as_slice().ct_eq(&hash) {
                return Ok(JoinAuth::Bootstrap);
            }
        }
    }

    // An active, unexpired, non-exhausted server invite.
    let now = now_ms();
    let ok: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM invites WHERE code = $1 AND status = 'active'
             AND (expires_at IS NULL OR expires_at > $2)
             AND (max_uses IS NULL OR use_count < max_uses)) THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(code)
    .bind(now)
    .fetch_one(&state.db)
    .await?;
    Ok(if ok == 1 { JoinAuth::Invite } else { JoinAuth::Invalid })
}

/// Claim instance ownership for `user_id` as part of an in-progress signup transaction. Returns
/// `true` iff this INSERT actually created the `owner_user_id` row — i.e. this signup is the one
/// that won ownership. A concurrent second bootstrap signup hits `ON CONFLICT DO NOTHING`, gets
/// `false`, and must be rejected by the caller (rolling its transaction back). Doing the claim in
/// the same transaction as the account insert closes the race where two admin-code signups both
/// read `!owner_claimed()` and both create an account.
pub async fn claim_ownership_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    user_id: &str,
) -> Result<bool, ApiError> {
    let res = sqlx::query(
        "INSERT INTO instance_secrets (name, value, created_at) VALUES ('owner_user_id', $1, $2)
         ON CONFLICT(name) DO NOTHING",
    )
    .bind(user_id.as_bytes())
    .bind(now_ms())
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Default for `SKWOD_INVITE_PENDING_SIGNUPS`: how many accounts created with one invite may
/// sit in the waiting room (admitted to no server) at the same time.
pub const DEFAULT_INVITE_PENDING_SIGNUPS: i64 = 10;

/// Count a signup against the invite `code`, inside the signup transaction. Returns `false`
/// (and the caller rolls the account back) when the invite
/// - stopped being valid since it was checked,
/// - has already created as many accounts as it has uses (`max_uses`) — a one-time link makes
///   one account, not one account per attempt until someone redeems it, or
/// - already has `pending_cap` accounts that nobody has admitted. That is the bound for an
///   invite with unlimited uses: a forwarded or screenshotted code cannot be turned into an
///   unbounded number of accounts while the host is not looking. The host frees a place by
///   approving the request, or by deleting the account.
///
/// Kept apart from `use_count`, which counts memberships (`accept_invite`): the account that
/// signs up with a one-time link must still be able to redeem that same link.
pub async fn consume_signup_tx(tx: &mut sqlx::Transaction<'_, sqlx::Any>, code: &str, user_id: &str, pending_cap: i64, now: i64) -> Result<SignupClaim, ApiError> {
    // ONE conditional UPDATE claims the use: validity and `max_uses` are checked and the count
    // is raised in the same statement, so two signups racing for the last use cannot both get
    // it. It also takes the invite's row lock (Postgres) / the write lock (SQLite) until this
    // transaction ends, so the count of unadmitted accounts below is not raced either: the next
    // signup on this invite waits here and then sees this one. A refusal rolls everything back.
    let claimed: Option<String> = sqlx::query_scalar(
        "UPDATE invites SET signup_count = signup_count + 1
          WHERE code = $1 AND status = 'active'
            AND (expires_at IS NULL OR expires_at > $2)
            AND (max_uses IS NULL OR (use_count < max_uses AND signup_count < max_uses))
         RETURNING id",
    )
    .bind(code)
    .bind(now)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(invite_id) = claimed else { return Ok(SignupClaim::Invalid) };
    // Unadmitted accounts of this invite, counted from the rows themselves (not a second
    // counter that every membership change would have to keep in step): admitted the moment a
    // server has them, back in the count if they are removed from everywhere, gone when deleted.
    let pending: i64 = sqlx::query_scalar(
        "SELECT CAST(count(*) AS BIGINT) FROM invite_signups s
          WHERE s.invite_id = $1 AND NOT EXISTS(SELECT 1 FROM server_members m WHERE m.user_id = s.user_id)",
    )
    .bind(&invite_id)
    .fetch_one(&mut **tx)
    .await?;
    if pending >= pending_cap {
        return Ok(SignupClaim::Full { invite_id, waiting: pending });
    }
    sqlx::query("INSERT INTO invite_signups (user_id, invite_id, created_at) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(&invite_id)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    Ok(SignupClaim::Claimed)
}

/// What [`consume_signup_tx`] decided. Anything but `Claimed`: the caller rolls the account back.
pub enum SignupClaim {
    Claimed,
    /// Not valid (any more), or out of uses. The joining app is told only "forbidden".
    Invalid,
    /// Valid, but `waiting` accounts created with it are admitted nowhere — the cap. Said out
    /// loud on both sides: the joiner gets [`INVITE_FULL`], the host [`notify_invite_full`].
    Full { invite_id: String, waiting: i64 },
}

/// The answer to a signup refused because the invite's waiting places are taken. Says nothing
/// the holder of a valid invite could not work out (signing up was refused, the code checks out).
pub const INVITE_FULL: &str = "invite full: too many people who used this invite are waiting for the host to let them in";

/// How many accounts created with each of `server_id`'s invites are admitted to no server:
/// `(invite id, waiting)`, only invites that have any.
pub async fn invite_waiting(db: &crate::state::Db, server_id: &str) -> Result<Vec<(String, i64)>, ApiError> {
    Ok(sqlx::query_as(
        "SELECT i.id, CAST(count(*) AS BIGINT) FROM invites i JOIN invite_signups s ON s.invite_id = i.id
          WHERE i.server_id = $1 AND NOT EXISTS(SELECT 1 FROM server_members m WHERE m.user_id = s.user_id)
          GROUP BY i.id",
    )
    .bind(server_id)
    .fetch_all(db)
    .await?)
}

/// Whether this instance requires a join code at signup. The signal is that the operator ran
/// `skwod init` (which sets `admin_setup_code`) — that's a deployed instance where invitation
/// should be enforced. A dev/test instance that was never initialized allows open signup.
pub async fn signup_requires_code(state: &AppState) -> Result<bool, ApiError> {
    let has_admin: i64 =
        sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM instance_secrets WHERE name = 'admin_setup_code') THEN 1 ELSE 0 END AS BIGINT)")
            .fetch_one(&state.db)
            .await?;
    Ok(has_admin == 1)
}

/// Constant-time byte comparison, so join-code checks don't leak via timing.
trait CtEq {
    fn ct_eq(&self, other: &[u8]) -> bool;
}
impl CtEq for [u8] {
    fn ct_eq(&self, other: &[u8]) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}
