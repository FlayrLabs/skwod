//! Native app self-update: serves a version manifest + the release artifacts so clients
//! (macOS / Android / iOS) can check for and install newer builds without an app store.
//!
//! Everything here is PUBLIC and unauthenticated by design: the manifest advertises only build
//! numbers + filenames, and the artifacts are the same signed binaries anyone can download. It
//! never leaks anything about accounts or ciphertext. Content is served from `<data>/releases/`,
//! which `package-release.sh` populates on the host (a `manifest.json` + the `.zip` / `.apk`).
//!
//! Manifest shape (written by package-release.sh; missing keys just mean "no update for that OS"):
//! ```json
//! { "macos":   { "build": 26, "version": "0.1.0", "file": "Skwod-26-macos.zip", "sha256": "…", "notes": "…" },
//!   "android": { "build": 26, "version": "0.1.0", "file": "skwod-26.apk",       "sha256": "…", "notes": "…" },
//!   "ios":     { "build": 26, "version": "0.1.0", "testflight": "https://testflight.apple.com/join/XXXX" } }
//! ```
//! Clients build the download URL themselves as `<their server base>/api/updates/download/<file>`,
//! so it always points at whatever public host the client already reached (proxy-safe).

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use tokio_util::io::ReaderStream;

use crate::client_key::ClientKey;
use crate::state::AppState;

/// Reject the request with 429 if this IP has exceeded `limit` hits/minute on the update endpoints.
/// Update traffic is unauthenticated, so it's rate-limited per source IP (like signup/login).
fn rate_ok(state: &AppState, client: &ClientKey, bucket: &str, limit: u32) -> bool {
    client.limit(state, bucket, limit).is_ok()
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/updates/manifest", get(manifest))
        .route("/updates/appcast.xml", get(appcast))
        .route("/updates/download/:file", get(download))
}

/// GET /api/updates/appcast.xml — Sparkle's feed for macOS. Served here (not via /download) so its
/// URL is `<server>/api/updates/appcast.xml`; the enclosure URLs inside are RELATIVE (`download/…`),
/// which Sparkle resolves against this URL's directory. That keeps the appcast host-independent — the
/// same file works for every self-hosted server without baking in a public hostname at release time.
async fn appcast(State(state): State<AppState>, client: ClientKey) -> Response {
    if !rate_ok(&state, &client, "update_meta", 300) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let path = state.releases_dir.join("appcast.xml");
    match tokio::fs::read(&path).await {
        Ok(bytes) => (
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
            bytes,
        )
            .into_response(),
        // No release published yet: an empty, valid feed reads as "no updates" to Sparkle.
        Err(_) => (
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
            "<?xml version=\"1.0\"?>\n<rss version=\"2.0\"><channel></channel></rss>".to_string(),
        )
            .into_response(),
    }
}

/// GET /api/updates/manifest — the current release manifest, or `{}` if the host has published no
/// releases yet. Deliberately never errors: a missing or malformed file reads as "no update", so a
/// client version-check can't be broken by an operator who hasn't set releases up.
async fn manifest(State(state): State<AppState>, client: ClientKey) -> Response {
    if !rate_ok(&state, &client, "update_meta", 300) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let path = state.releases_dir.join("manifest.json");
    let body = tokio::fs::read(&path)
        .await
        .ok()
        // Validate it parses so a corrupt file reads as "no update" rather than erroring the client.
        .filter(|b| serde_json::from_slice::<serde_json::Value>(b).is_ok())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_else(|| "{}".to_string());
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// GET /api/updates/download/:file — stream a published artifact back to a client.
///
/// The filename is validated to a strict, bare-basename charset (no `/`, no `..`, no leading dot)
/// so a crafted id can never escape `releases_dir` — defense-in-depth on top of the join.
///
/// The body is STREAMED off disk (constant memory), so a busy server serving a 45 MB apk to many
/// clients at once can't be pushed into an OOM. Downloads are also rate-limited per source IP.
async fn download(State(state): State<AppState>, client: ClientKey, Path(file): Path<String>) -> Response {
    if !rate_ok(&state, &client, "update_dl", 60) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let safe = !file.is_empty()
        && file.len() <= 128
        && !file.starts_with('.')
        && !file.contains("..")
        && file
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !safe {
        return (StatusCode::BAD_REQUEST, "bad filename").into_response();
    }
    let path = state.releases_dir.join(&file);
    // Require a regular file (a symlink pointing outside the dir, or a directory, is rejected).
    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) if m.is_file() => m,
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let handle = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let ctype = if file.ends_with(".apk") {
        "application/vnd.android.package-archive"
    } else if file.ends_with(".zip") {
        "application/zip"
    } else if file.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    };
    let body = Body::from_stream(ReaderStream::new(handle));
    (
        [
            (header::CONTENT_TYPE, ctype.to_string()),
            (header::CONTENT_LENGTH, meta.len().to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{file}\""),
            ),
        ],
        body,
    )
        .into_response()
}
