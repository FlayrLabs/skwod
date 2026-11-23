//! The waiting room: what an account that nobody has admitted may do.
//!
//! Signing up needs only an invite code, and a "code" invite admits nobody by itself — the host
//! approves each join request. Until then the account is a stranger holding a session token.
//! It gets exactly what it needs to wait and to be let in: its own account and devices, its own
//! mailbox, redeeming an invite, and the instance's public identity. Everything else — looking
//! people up, opening conversations, the key directory, sender certificates, push registration,
//! storage — is refused HERE, in the one place every authenticated request passes through
//! ([`crate::auth::AuthUser`]), so a new route is closed to the waiting room unless it is added
//! to [`waiting_room_allows`] on purpose.
//!
//! An account is **admitted** when it is a member of at least one server, is the instance owner,
//! or was granted server creation by the owner. An instance nobody owns yet (never initialised:
//! development and tests) has no gate to be on the wrong side of.

use axum::http::Method;

use crate::error::ApiError;
use crate::state::AppState;

/// Is `user_id` past the waiting room?
pub(crate) async fn is_admitted(state: &AppState, user_id: &str) -> Result<bool, ApiError> {
    let admitted: i64 = sqlx::query_scalar(
        "SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_members WHERE user_id = $1)
              OR NOT EXISTS(SELECT 1 FROM instance_secrets WHERE name = 'owner_user_id')
              OR EXISTS(SELECT 1 FROM instance_secrets WHERE name = 'owner_user_id' AND value = $2)
              OR EXISTS(SELECT 1 FROM server_creators WHERE user_id = $3)
         THEN 1 ELSE 0 END AS BIGINT)",
    )
    .bind(user_id)
    .bind(user_id.as_bytes())
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(admitted == 1)
}

/// The routes open to an account that has not been admitted. `path` is the full request path.
/// Deny by default: anything not named here needs admission.
pub(crate) fn waiting_room_allows(method: &Method, path: &str, user_id: &str) -> bool {
    let path = path.trim_end_matches('/');
    let get = method == Method::GET;
    // Its own account: session, password, deleting itself.
    if path.starts_with("/api/auth/") {
        return true;
    }
    // Redeeming (or checking) an invite is how it gets out of here.
    if path.starts_with("/api/invites/") && (path.ends_with("/accept") || path.ends_with("/check")) {
        return true;
    }
    // Its own devices, keys, backup and mailbox. NOT other accounts' devices or prekeys
    // (`users/:id/devices`, `member-devices`, `prekey-bundle`), and not a sender certificate.
    const OWN_E2EE: &[&str] = &[
        "/api/e2ee/devices",
        "/api/e2ee/link-requests",
        "/api/e2ee/prekeys/replenish",
        "/api/e2ee/prekeys/count",
        "/api/e2ee/spk/rotate",
        "/api/e2ee/trust-root",
        "/api/e2ee/sealed/inbox",
        "/api/e2ee/sealed/ack",
        "/api/e2ee/key-backup",
        "/api/e2ee/registration-pin",
    ];
    if OWN_E2EE.iter().any(|p| path == *p || path.strip_prefix(p).is_some_and(|rest| rest.starts_with('/'))) {
        return true;
    }
    if path.strip_prefix("/api/e2ee/users/").and_then(|rest| rest.strip_suffix("/devices")) == Some(user_id) {
        return true;
    }
    // Read-only, and about the caller or the instance only: has it been let in yet, which
    // instance is this, what the app needs to draw an (empty) home screen without errors.
    // The instance routes are named one by one: `/api/instance/p2p` (the LAN-discovery key)
    // and the server-creator list are for members.
    const INSTANCE: &[&str] = &["identity", "address-record", "owner-attestation", "can-create-servers", "limits", "local-proof"];
    get && (path == "/api/servers"
        || path == "/api/dms"
        || path == "/api/blocks"
        || path == "/api/rings"
        || path.strip_prefix("/api/instance/").is_some_and(|name| INSTANCE.contains(&name))
        || path.starts_with("/api/updates/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_waiting_room_is_deny_by_default() {
        let me = "u1";
        for (method, path) in [
            (Method::GET, "/api/auth/me"),
            (Method::POST, "/api/invites/ABCDEFGH/accept"),
            (Method::GET, "/api/invites/ABCDEFGH/check"),
            (Method::POST, "/api/e2ee/devices/register"),
            (Method::GET, "/api/e2ee/devices"),
            (Method::GET, "/api/e2ee/sealed/inbox"),
            (Method::POST, "/api/e2ee/sealed/ack"),
            (Method::GET, "/api/e2ee/users/u1/devices"),
            (Method::GET, "/api/servers"),
            (Method::GET, "/api/instance/can-create-servers"),
        ] {
            assert!(waiting_room_allows(&method, path, me), "{method} {path} should be open");
        }
        for (method, path) in [
            (Method::GET, "/api/users/lookup"),
            (Method::POST, "/api/dms"),
            (Method::POST, "/api/dms/c1/messages"),
            (Method::GET, "/api/e2ee/users/u2/devices"),
            (Method::GET, "/api/e2ee/member-devices"),
            (Method::POST, "/api/e2ee/prekey-bundle"),
            (Method::POST, "/api/e2ee/certificates"),
            (Method::POST, "/api/e2ee/transparency"),
            (Method::POST, "/api/push/register"),
            (Method::POST, "/api/blobs"),
            (Method::POST, "/api/servers"),
            (Method::DELETE, "/api/invites/ABCDEFGH"),
            (Method::POST, "/api/e2ee/devicesx"),
            (Method::PUT, "/api/blocks/u2"),
            (Method::POST, "/api/some/route/added/later"),
            (Method::GET, "/api/instance/p2p"),
            (Method::GET, "/api/instance/server-creators"),
            (Method::GET, "/api/instance/added-later"),
        ] {
            assert!(!waiting_room_allows(&method, path, me), "{method} {path} should be closed");
        }
    }
}
