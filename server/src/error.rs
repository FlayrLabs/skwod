//! API error type. Coarse on purpose: auth failures never say *why* (no user-enumeration or
//! oracle surface), and internal errors never leak SQL/state to the client.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    /// Missing/invalid credentials or token.
    Unauthorized,
    /// Authenticated but not allowed to do this.
    Forbidden,
    /// The account exists but nobody has admitted it to a server yet (`admission.rs`): it may
    /// wait, and nothing else. 403, typed so an app can show the waiting room instead of an error.
    NotAdmitted,
    /// A signup with a valid invite that already has as many accounts waiting for the host as
    /// it may (`join.rs`). 403, typed and worded so the joining app can say what to do: the
    /// invite is fine, the host has to let people in (or share a fresh one).
    InviteFull,
    /// Referenced entity doesn't exist (or the caller may not know it exists).
    NotFound,
    /// Malformed or semantically invalid request. The message is safe for clients.
    BadRequest(&'static str),
    /// Uniqueness conflict (e.g. username taken).
    Conflict(&'static str),
    /// The client speaks an E2EE protocol generation this server no longer (or does not yet)
    /// accept. The message is shown to the user verbatim.
    UpgradeRequired(&'static str),
    /// The account already has a device: a new one must be linked by an existing device.
    LinkRequired,
    /// An account reset was recorded and can complete at this unix-ms time unless a device of
    /// the account cancels it first.
    ResetPending(i64),
    /// An account reset needs the registration-lock PIN and none was sent. Typed, so the apps
    /// can route to the PIN screen (or offer the 7-day hold for a forgotten PIN).
    PinRequired,
    /// The registration-lock PIN was wrong: tries left before the lockout, or when it ends.
    PinIncorrect { attempts_left: i64, locked_until: Option<i64> },
    /// This install holds an older generation of the device than the server: the device was
    /// restored from a key backup somewhere else, and this copy must stop.
    DeviceSuperseded,
    /// The request names (or is bound to) a device that is not registered on the account — it
    /// was removed.
    DeviceRemoved,
    /// The session has not proved which install of the device it is (`devices/:id/bind`).
    BindRequired,
    /// A re-key by an install without the device's current install secret was recorded as a
    /// recovery request. It completes at this unix-ms time unless a current device cancels it —
    /// or at once when one approves it or the registration PIN is given. The second field is
    /// when the request was CONTESTED (another install asked to restore the same device): a
    /// contested request never completes by the hold, only by an approval or the PIN.
    RecoveryPending(i64, Option<i64>),
    /// Over a quota (413). The message is shown to the user verbatim.
    PayloadTooLarge(&'static str),
    /// One file larger than the host allows (413, `limits.rs`). Carries the limit so the answer
    /// can say it — and so an app holding a stale number learns the real one.
    FileTooLarge { max_upload_bytes: u64 },
    /// The host is out of room (507). The message is shown to the user verbatim.
    InsufficientStorage(&'static str),
    /// No call server is running right now (503): `starting` = one is on its way. Typed, so an
    /// app can say "voice is off" instead of "check your connection". `reason` is a short code.
    VoiceOff { starting: bool, reason: &'static str },
    /// Too many requests in the window.
    RateLimited,
    /// An unauthenticated p2p request arrived without a valid proof-of-work stamp
    /// (`client_key.rs`). Carries the host's current stamp window so a client whose clock is off
    /// can redo the work for the right one.
    PowRequired(u64),
    /// The same, while the host is being flooded: it wants this many bits of work, more than
    /// the base (`skwod_net::pow::required_bits`). Current members redo the work at that
    /// difficulty; a build that cannot is refused only for as long as the flood lasts.
    PowRequiredBits(u64, u32),
    /// Anything internal. Logged server-side, opaque to the client.
    Internal,
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &e {
            if db.is_unique_violation() {
                return ApiError::Conflict("already exists");
            }
        }
        tracing::error!(error = %e, "database error");
        ApiError::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::VoiceOff { starting, reason } = self {
            let (error, code) = if starting { ("voice is starting on this skwod", "voice_starting") } else { ("voice is off on this skwod", "voice_off") };
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": error, "code": code, "reason": reason }))).into_response();
        }
        if let ApiError::ResetPending(completes_at) = self {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": "device reset pending", "completes_at": completes_at }))).into_response();
        }
        if let ApiError::RecoveryPending(completes_at, contested_at) = self {
            return (StatusCode::FORBIDDEN, Json(json!({ "error": "device recovery pending", "completes_at": completes_at, "contested_at": contested_at }))).into_response();
        }
        if let ApiError::PinIncorrect { attempts_left, locked_until } = self {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "registration pin incorrect", "attempts_left": attempts_left, "locked_until": locked_until })),
            )
                .into_response();
        }
        if let ApiError::FileTooLarge { max_upload_bytes } = self {
            let mb = max_upload_bytes / (1024 * 1024);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({ "error": format!("that file is too large for this skwod: the host allows up to {mb} MB per file"), "max_upload_bytes": max_upload_bytes })),
            )
                .into_response();
        }
        if let ApiError::PowRequiredBits(window, bits) = self {
            let mut res = ApiError::PowRequired(window).into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&bits.to_string()) {
                res.headers_mut().insert(skwod_net::pow::POW_BITS_HEADER, v);
            }
            return res;
        }
        if let ApiError::PowRequired(window) = self {
            return (
                StatusCode::PRECONDITION_REQUIRED,
                [(skwod_net::pow::POW_WINDOW_HEADER, window.to_string())],
                Json(json!({ "error": "proof of work required" })),
            )
                .into_response();
        }
        let (status, message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            ApiError::NotAdmitted => (StatusCode::FORBIDDEN, "waiting for approval"),
            ApiError::InviteFull => (StatusCode::FORBIDDEN, crate::join::INVITE_FULL),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not found"),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::UpgradeRequired(m) => (StatusCode::UPGRADE_REQUIRED, m),
            ApiError::LinkRequired => (StatusCode::FORBIDDEN, "device link required"),
            ApiError::VoiceOff { .. } | ApiError::ResetPending(_) | ApiError::RecoveryPending(..) | ApiError::PinIncorrect { .. } | ApiError::FileTooLarge { .. } => unreachable!("handled above"),
            ApiError::PinRequired => (StatusCode::FORBIDDEN, "registration pin required"),
            ApiError::DeviceSuperseded => (StatusCode::CONFLICT, "device superseded"),
            ApiError::DeviceRemoved => (StatusCode::FORBIDDEN, "device removed"),
            ApiError::BindRequired => (StatusCode::FORBIDDEN, "device bind required"),
            ApiError::PayloadTooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, m),
            ApiError::InsufficientStorage(m) => (StatusCode::INSUFFICIENT_STORAGE, m),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            ApiError::PowRequired(_) | ApiError::PowRequiredBits(..) => (StatusCode::PRECONDITION_REQUIRED, "proof of work required"),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
