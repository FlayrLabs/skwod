//! Router assembly. Everything under `/api/*` except `/health`.

use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

#[derive(Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok", service: "skwod-server", version: env!("CARGO_PKG_VERSION") })
}

/// While the host has the server stopped (admin page), the API refuses everyone. `/health`
/// stays up so a container healthcheck does not restart a server that is off on purpose.
async fn serving_gate(
    axum::extract::State(state): axum::extract::State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    if req.uri().path() != "/health" && !state.serving.load(std::sync::atomic::Ordering::SeqCst) {
        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "error": "this skwod is stopped" }))).into_response();
    }
    next.run(req).await
}

#[derive(serde::Deserialize)]
struct LocalProofQuery {
    nonce: String,
}

/// "Are you the server I just started?" — for a host app that supervises this process and is
/// about to send its owner's password to `127.0.0.1:<port>`. A local port proves nothing: any
/// program on the machine can listen on it once the real server is gone. So the supervisor
/// hands its child a random per-launch secret — on its standard input (`run
/// --local-proof-stdin`: a pipe only the child reads), or in `SKWOD_LOCAL_PROOF_SECRET` (an
/// environment other processes of the same user can read on macOS; kept for supervisors that
/// have not moved) — never on the command line, never on disk — and asks this route for `HMAC-SHA256(secret, "skwod-local-proof\0" ||
/// nonce)` over a fresh nonce; only the process it spawned can answer. Without the variable the
/// route does not exist (404). Answers nothing about the instance and is safe unauthenticated:
/// the caller must already know the secret to check the reply, and learns nothing otherwise.
async fn local_proof(axum::extract::Query(q): axum::extract::Query<LocalProofQuery>) -> Result<Json<serde_json::Value>, crate::error::ApiError> {
    use crate::error::ApiError;
    let secret = LOCAL_PROOF_SECRET
        .get()
        .cloned()
        .or_else(|| std::env::var("SKWOD_LOCAL_PROOF_SECRET").ok())
        .filter(|s| s.len() >= 32)
        .ok_or(ApiError::NotFound)?;
    let nonce = hex::decode(&q.nonce).ok().filter(|n| (16..=64).contains(&n.len())).ok_or(ApiError::BadRequest("nonce must be 16-64 bytes of hex"))?;
    Ok(Json(serde_json::json!({ "proof": local_proof_for(secret.as_bytes(), &nonce) })))
}

/// The local-proof secret read from standard input at start (`run --local-proof-stdin`).
pub(crate) static LOCAL_PROOF_SECRET: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub(crate) fn local_proof_for(secret: &[u8], nonce: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(b"skwod-local-proof\0");
    mac.update(nonce);
    hex::encode(mac.finalize().into_bytes())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/instance/local-proof", get(local_proof))
        .route("/api/ws", get(crate::ws::ws_handler))
        .nest("/api/auth", crate::auth::routes())
        .nest("/api/e2ee", crate::keydir::routes())
        .nest(
            "/api",
            crate::structure::routes()
                .merge(crate::messages::routes())
                .merge(crate::blobs::routes())
                .merge(crate::limits::routes())
                .merge(crate::music::routes())
                .merge(crate::voice::routes())
                .merge(crate::push::routes())
                .merge(crate::safety::routes())
                .merge(crate::updates::routes())
                .merge(crate::p2p::routes()),
        )
        .layer(axum::middleware::from_fn_with_state(state.clone(), serving_gate))
        .with_state(state)
}
