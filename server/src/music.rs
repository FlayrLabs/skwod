//! Story music, fetched for the viewer by their own host.
//!
//! A story can carry a song from Apple's catalogue; what plays is its ~30 second preview, a
//! small audio file on Apple's CDN. If every viewer's app fetched that file itself, Apple would
//! see the IP address of everyone who opens the story. So the app asks ITS HOST for it:
//!
//! `POST /api/music/preview` `{ "url": "https://audio-ssl.itunes.apple.com/itunes-assets/….m4a" }`
//! → the audio bytes. Members only.
//!
//! What this trades. Apple now sees the host's address and nobody else's. The HOST learns that
//! this session asked for this preview, now — which song, when, by which account. It does not
//! learn which story it was for or who posted it (that stays inside the encrypted message), and
//! it keeps no record: nothing about the request is logged, and the URL travels in the request
//! BODY, so it is in no access log either (a reverse proxy logs paths and query strings).
//!
//! This is the one place the server fetches something a member named, so it is narrow on
//! purpose — not a proxy:
//!
//! - `https` only, no credentials, default port, and the host must be EXACTLY Apple's preview
//!   host with a preview path ([`validate`]), checked on the parsed URL;
//! - the name is resolved here and every address must be public ([`ip_refused`]); the request
//!   then goes to one of exactly those addresses (no second lookup to race);
//! - a redirect is followed at most twice, and only to a URL that passes all of the above;
//! - the answer must say it is audio, and is cut off at 4 MB and 15 seconds;
//! - per account: 120 an hour;
//! - a small in-memory cache (10 minutes), so the friends who open the same story cause one
//!   request to Apple between them.
//!
//! A song card's ARTWORK goes the same way, for the same reason (`POST /api/music/artwork`):
//! the same guards with its own, equally exact rules ([`ARTWORK`]) — Apple's image hosts, an
//! image path, `image/jpeg|png|webp` only, 300 kB, 600 an hour.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;
use sha2::Digest;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::{now_ms, AppState};

/// What one of the two endpoints will fetch: everything about it is fixed here.
pub struct Rules {
    /// Exact host names — never a suffix match.
    pub hosts: &'static [&'static str],
    pub path_prefix: &'static str,
    pub extensions: &'static [&'static str],
    /// Exact content types (lowercase, parameters stripped), or a `type/` prefix.
    pub content_types: &'static [&'static str],
    pub max_bytes: usize,
    pub per_hour: u32,
    limiter_key: &'static str,
    /// Which of the two caches (and allowances) this is.
    artwork: bool,
    cache_entries: usize,
    not_this: &'static str,
}

/// A preview is about 1 MB; nothing larger than this is relayed.
pub const MAX_PREVIEW_BYTES: usize = 4 * 1024 * 1024;
/// Artwork at the 200 px the apps ask for is about 20 kB.
pub const MAX_ARTWORK_BYTES: usize = 300 * 1024;

/// Apple's preview CDN, as handed out by both MusicKit (`previewAssets`) and the iTunes Search
/// API (`previewUrl`).
pub const PREVIEW: Rules = Rules {
    hosts: &["audio-ssl.itunes.apple.com"],
    path_prefix: "/itunes-assets/",
    extensions: &[".m4a", ".mp3", ".aac"],
    content_types: &["audio/"],
    max_bytes: MAX_PREVIEW_BYTES,
    per_hour: PER_HOUR,
    limiter_key: "music_preview",
    artwork: false,
    cache_entries: CACHE_ENTRIES,
    not_this: NOT_A_PREVIEW,
};

/// Apple's artwork CDN (`artworkUrl100` of the iTunes Search API, MusicKit's `artwork.url`):
/// `https://is1-ssl.mzstatic.com/image/thumb/…/200x200bb.jpg`. The numbered shards, by name.
/// Raster images only — never SVG, which is a document that can carry script.
pub const ARTWORK: Rules = Rules {
    hosts: &["is1-ssl.mzstatic.com", "is2-ssl.mzstatic.com", "is3-ssl.mzstatic.com", "is4-ssl.mzstatic.com", "is5-ssl.mzstatic.com"],
    path_prefix: "/image/thumb/",
    extensions: &[".jpg", ".jpeg", ".png", ".webp"],
    content_types: &["image/jpeg", "image/png", "image/webp"],
    max_bytes: MAX_ARTWORK_BYTES,
    per_hour: 600,
    limiter_key: "music_artwork",
    artwork: true,
    cache_entries: 128,
    not_this: "that is not Apple Music artwork",
};
const MAX_URL_LEN: usize = 600;
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_REDIRECTS: usize = 2;
/// Previews one account may ask for per hour (a cache hit counts too).
pub const PER_HOUR: u32 = 120;
const CACHE_TTL_MS: i64 = 10 * 60 * 1000;
const CACHE_ENTRIES: usize = 24;

const NOT_A_PREVIEW: &str = "that is not an Apple Music preview";
const UNAVAILABLE: &str = "that could not be fetched from Apple";

/// The cache, and (tests only) where "Apple" really is.
#[derive(Clone, Default)]
pub struct Previews {
    cache: Arc<Mutex<HashMap<[u8; 32], Cached>>>,
    /// Artwork, kept apart so a screen of song cards cannot push the audio out (128 × 300 kB at most).
    art: Arc<Mutex<HashMap<[u8; 32], Cached>>>,
    /// Tests: a local stand-in for the preview host, reached over plain HTTP. The URL rules
    /// are the real ones either way; only the connection is redirected. Never set in a build
    /// that serves anyone.
    #[cfg(test)]
    pub test_origin: Option<SocketAddr>,
}

#[derive(Clone)]
struct Cached {
    at: i64,
    content_type: String,
    body: Bytes,
}

impl Previews {
    fn map(&self, rules: &Rules) -> &Mutex<HashMap<[u8; 32], Cached>> {
        if rules.artwork { &self.art } else { &self.cache }
    }

    fn get(&self, rules: &Rules, key: &[u8; 32]) -> Option<Cached> {
        let mut map = self.map(rules).lock().expect("preview cache lock");
        map.retain(|_, c| now_ms() - c.at < CACHE_TTL_MS);
        map.get(key).cloned()
    }

    fn put(&self, rules: &Rules, key: [u8; 32], value: Cached) {
        let mut map = self.map(rules).lock().expect("preview cache lock");
        if map.len() >= rules.cache_entries {
            // Full: the oldest goes (24 × 4 MB bounds the memory this can ever hold).
            if let Some(oldest) = map.iter().min_by_key(|(_, c)| c.at).map(|(k, _)| *k) {
                map.remove(&oldest);
            }
        }
        map.insert(key, value);
    }
}

/// Is `raw` a URL this server will fetch? Decided on the PARSED url, so nothing about how it
/// is spelled (userinfo, an `@`, a trailing dot, a port) can make another host look like Apple's.
pub fn validate(rules: &Rules, raw: &str) -> Result<reqwest::Url, ApiError> {
    let bad = || ApiError::BadRequest(rules.not_this);
    if raw.len() > MAX_URL_LEN || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(bad());
    }
    let url = reqwest::Url::parse(raw).map_err(|_| bad())?;
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(bad());
    }
    if !matches!(url.port(), None | Some(443)) {
        return Err(bad());
    }
    match url.host() {
        Some(url::Host::Domain(host)) if rules.hosts.contains(&host) => {}
        _ => return Err(bad()),
    }
    let path = url.path();
    if !path.starts_with(rules.path_prefix) || path.contains("..") || !rules.extensions.iter().any(|e| path.ends_with(e)) {
        return Err(bad());
    }
    Ok(url)
}

/// An address this server never connects to on a member's say-so: itself, the host's own
/// network, link-local (cloud metadata lives there), carrier NAT, multicast, documentation and
/// other reserved ranges — in IPv4, IPv6, and IPv4 written as IPv6.
pub fn ip_refused(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10, carrier NAT (and Tailscale)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15, benchmarking
                || o[0] >= 240 // reserved
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_refused(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7, unique local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10, link-local
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
                || (s[0] == 0x64 && s[1] == 0xff9b) // NAT64: an IPv4 address in disguise
                || s[0] == 0x2002 // 6to4: likewise
                || s[..6] == [0, 0, 0, 0, 0, 0] // IPv4-compatible and friends
        }
    }
}

/// The addresses a name resolved to, if ALL of them may be connected to. One private address
/// among public ones refuses the lot: which one a connection picks must not matter.
pub fn screen(addrs: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, ApiError> {
    if addrs.is_empty() || addrs.iter().any(|a| ip_refused(a.ip())) {
        return Err(ApiError::BadRequest(UNAVAILABLE));
    }
    Ok(addrs)
}

fn type_allowed(rules: &Rules, content_type: &str) -> bool {
    let kind = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let listed = rules.content_types.iter().any(|t| if t.ends_with('/') { kind.starts_with(t) && kind.len() > t.len() } else { kind == *t });
    listed && kind.len() <= 40 && kind.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'+'))
}

#[cfg(test)]
fn is_audio(content_type: &str) -> bool {
    type_allowed(&PREVIEW, content_type)
}

/// One request to one validated URL, connected only to addresses that passed [`screen`].
async fn fetch_once(previews: &Previews, url: &reqwest::Url) -> Result<reqwest::Response, ApiError> {
    let host = url.host_str().ok_or(ApiError::BadRequest(UNAVAILABLE))?;
    let builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(FETCH_TIMEOUT)
        .connect_timeout(Duration::from_secs(8))
        .no_proxy();
    #[cfg(test)]
    if let Some(origin) = previews.test_origin {
        let mut local = reqwest::Url::parse(&format!("http://{origin}/")).map_err(|_| ApiError::Internal)?;
        local.set_path(url.path());
        local.set_query(url.query());
        let client = builder.build().map_err(|_| ApiError::Internal)?;
        return client.get(local).header(header::HOST, host).send().await.map_err(|_| ApiError::BadRequest(UNAVAILABLE));
    }
    let _ = previews;
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host, 443)).await.map_err(|_| ApiError::BadRequest(UNAVAILABLE))?.collect();
    let addrs = screen(resolved)?;
    // Pinned: the connection goes to the addresses that were just checked, not to whatever a
    // second lookup would say.
    let client = builder.https_only(true).resolve_to_addrs(host, &addrs).build().map_err(|_| ApiError::Internal)?;
    client.get(url.clone()).send().await.map_err(|_| ApiError::BadRequest(UNAVAILABLE))
}

/// Fetch a preview (tests).
#[cfg(test)]
pub async fn fetch(previews: &Previews, raw: &str) -> Result<(String, Bytes), ApiError> {
    fetch_as(&PREVIEW, previews, raw).await
}

/// Fetch what `rules` allow: validated, redirects re-validated, its content types only, bounded.
pub async fn fetch_as(rules: &Rules, previews: &Previews, raw: &str) -> Result<(String, Bytes), ApiError> {
    let mut url = validate(rules, raw)?;
    let mut hops = 0;
    let mut res = loop {
        let res = fetch_once(previews, &url).await?;
        if !res.status().is_redirection() {
            break res;
        }
        hops += 1;
        if hops > MAX_REDIRECTS {
            return Err(ApiError::BadRequest(UNAVAILABLE));
        }
        // Wherever it points, it is judged like a URL a member typed: Apple's preview host, or nothing.
        let location = res.headers().get(header::LOCATION).and_then(|v| v.to_str().ok()).ok_or(ApiError::BadRequest(UNAVAILABLE))?;
        let next = url.join(location).map_err(|_| ApiError::BadRequest(UNAVAILABLE))?;
        url = validate(rules, next.as_str()).map_err(|_| ApiError::BadRequest(UNAVAILABLE))?;
    };
    if res.status() != reqwest::StatusCode::OK {
        return Err(ApiError::BadRequest(UNAVAILABLE));
    }
    let content_type = res.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if !type_allowed(rules, &content_type) {
        return Err(ApiError::BadRequest(UNAVAILABLE));
    }
    if res.content_length().is_some_and(|n| n > rules.max_bytes as u64) {
        return Err(ApiError::BadRequest(UNAVAILABLE));
    }
    // Whatever the length header said (or did not): stop one byte past the cap.
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|_| ApiError::BadRequest(UNAVAILABLE))? {
        if body.len() + chunk.len() > rules.max_bytes {
            return Err(ApiError::BadRequest(UNAVAILABLE));
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return Err(ApiError::BadRequest(UNAVAILABLE));
    }
    let kind = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    Ok((kind, Bytes::from(body)))
}

pub fn routes() -> Router<AppState> {
    use axum::routing::post;
    Router::new().route("/music/preview", post(preview)).route("/music/artwork", post(artwork))
}

#[derive(Deserialize)]
struct PreviewReq {
    url: String,
}

/// Members only. Nothing here is logged: which preview an account asked for is a song choice.
async fn preview(State(state): State<AppState>, auth: AuthUser, Json(req): Json<PreviewReq>) -> Result<Response, ApiError> {
    serve(&PREVIEW, state, auth, req).await
}

/// A song card's artwork, the same way and for the same reason. Not logged either.
async fn artwork(State(state): State<AppState>, auth: AuthUser, Json(req): Json<PreviewReq>) -> Result<Response, ApiError> {
    serve(&ARTWORK, state, auth, req).await
}

async fn serve(rules: &'static Rules, state: AppState, auth: AuthUser, req: PreviewReq) -> Result<Response, ApiError> {
    // Refused before anything else is spent on it — and before it counts against the hour.
    let url = validate(rules, &req.url)?;
    state.limiter.check(&format!("{}:{}", rules.limiter_key, auth.user_id), rules.per_hour, crate::limiter::HOUR)?;
    // Like storage: for the people of this skwod, not for an account that merely exists.
    let member: i64 = sqlx::query_scalar("SELECT CAST(CASE WHEN EXISTS(SELECT 1 FROM server_members WHERE user_id = $1) THEN 1 ELSE 0 END AS BIGINT)")
        .bind(&auth.user_id)
        .fetch_one(&state.db)
        .await?;
    if member == 0 {
        return Err(ApiError::Forbidden);
    }
    let key: [u8; 32] = sha2::Sha256::digest(url.as_str().as_bytes()).into();
    let hit = match state.music.get(rules, &key) {
        Some(hit) => hit,
        None => {
            let (content_type, body) = fetch_as(rules, &state.music, url.as_str()).await?;
            let fresh = Cached { at: now_ms(), content_type, body };
            state.music.put(rules, key, fresh.clone());
            fresh
        }
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, hit.content_type),
            // The app keeps it for the story it is looking at; nothing in between may.
            (header::CACHE_CONTROL, "private, no-store".to_string()),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
        ],
        hit.body,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{send, signup, test_state};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const GOOD: &str = "https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview211/v4/cd/7d/83/x/mzaf_1.plus.aac.p.m4a";

    #[test]
    fn only_apples_preview_host_over_https_is_ever_fetched() {
        assert!(validate(&PREVIEW, GOOD).is_ok());
        assert!(validate(&PREVIEW, "https://audio-ssl.itunes.apple.com:443/itunes-assets/a.m4a").is_ok());
        for bad in [
            "http://audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "https://evil.example/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com.evil.example/itunes-assets/a.m4a",
            "https://evil.example/audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com@evil.example/itunes-assets/a.m4a",
            "https://user:pw@audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com:8443/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com./itunes-assets/a.m4a",
            "https://xaudio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "https://itunes.apple.com/itunes-assets/a.m4a",
            "https://is1-ssl.mzstatic.com/itunes-assets/a.m4a",
            "https://127.0.0.1/itunes-assets/a.m4a",
            "https://[::1]/itunes-assets/a.m4a",
            "https://169.254.169.254/itunes-assets/a.m4a",
            "https://localhost/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com/",
            "https://audio-ssl.itunes.apple.com/other/a.m4a",
            "https://audio-ssl.itunes.apple.com/itunes-assets/../a.m4a",
            "https://audio-ssl.itunes.apple.com/itunes-assets/a.html",
            "https://audio-ssl.itunes.apple.com/itunes-assets/a.m4a#x",
            "https://audio-ssl.itunes.apple.com/itunes-assets/a .m4a",
            "https://audio-ssl.itunes.apple.com/itunes-assets/a\n.m4a",
            "file:///etc/passwd",
            "ftp://audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "//audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "",
        ] {
            assert!(validate(&PREVIEW, bad).is_err(), "{bad}");
        }
        assert!(validate(&PREVIEW, &format!("https://audio-ssl.itunes.apple.com/itunes-assets/{}.m4a", "a".repeat(700))).is_err());
        // Spelled differently, the same host: accepted because the PARSED host is Apple's.
        assert!(validate(&PREVIEW, "https://AUDIO-SSL.itunes.apple.com/itunes-assets/a.m4a").is_ok());
    }

    #[test]
    fn private_loopback_and_link_local_addresses_are_refused() {
        for bad in [
            "127.0.0.1", "127.8.8.8", "10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "0.0.0.0", "0.1.2.3",
            "100.64.0.1", "100.127.255.255", "192.0.0.1", "198.18.0.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "192.0.2.1",
            "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
            "64:ff9b::7f00:1", "2002:7f00:1::", "2001:db8::1", "::7f00:1",
        ] {
            assert!(ip_refused(bad.parse().unwrap()), "{bad}");
        }
        for good in ["17.253.144.10", "23.45.67.89", "8.8.8.8", "100.63.0.1", "100.128.0.1", "2620:149:a44::10", "2a02:26f0::1", "::ffff:17.1.2.3"] {
            assert!(!ip_refused(good.parse().unwrap()), "{good}");
        }
        let public: SocketAddr = "17.253.144.10:443".parse().unwrap();
        let private: SocketAddr = "10.0.0.5:443".parse().unwrap();
        assert!(screen(vec![public]).is_ok());
        // One private address among public ones refuses the lot; so does no address at all.
        assert!(screen(vec![public, private]).is_err());
        assert!(screen(vec![private]).is_err());
        assert!(screen(vec![]).is_err());
    }

    #[test]
    fn only_audio_content_types_pass() {
        for ok in ["audio/x-m4p", "audio/mp4", "audio/mpeg", "audio/x-m4a; charset=binary", "Audio/AAC"] {
            assert!(is_audio(ok), "{ok}");
        }
        for bad in ["text/html", "application/octet-stream", "application/json", "", "audio", "video/mp4", "image/png", "audio/x\r\nset-cookie: a"] {
            assert!(!is_audio(bad), "{bad}");
        }
    }

    /// A stand-in for Apple's preview host: answers by path, counts what it was asked.
    async fn fake_apple() -> (SocketAddr, Arc<AtomicUsize>) {
        use axum::extract::Path;
        use axum::routing::get;
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = Router::new().route(
            "/itunes-assets/:name",
            get(move |Path(name): Path<String>, headers: axum::http::HeaderMap| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    // The request names Apple's host, as it would on the real connection.
                    assert_eq!(headers.get(header::HOST).and_then(|h| h.to_str().ok()), Some("audio-ssl.itunes.apple.com"));
                    let audio = |body: Vec<u8>| (StatusCode::OK, [(header::CONTENT_TYPE, "audio/x-m4p")], body).into_response();
                    let to = |location: &str| (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response();
                    match name.as_str() {
                        "song.m4a" => audio(b"preview-bytes".to_vec()),
                        "big.m4a" => audio(vec![7u8; MAX_PREVIEW_BYTES + 1]),
                        "max.m4a" => audio(vec![7u8; MAX_PREVIEW_BYTES]),
                        "empty.m4a" => audio(vec![]),
                        "page.m4a" => (StatusCode::OK, [(header::CONTENT_TYPE, "text/html")], "<html>").into_response(),
                        "untyped.m4a" => (StatusCode::OK, "bytes").into_response(),
                        "missing.m4a" => StatusCode::NOT_FOUND.into_response(),
                        "moved.m4a" => to("https://audio-ssl.itunes.apple.com/itunes-assets/song.m4a"),
                        "relative.m4a" => to("song.m4a"),
                        "offhost.m4a" => to("https://evil.example/itunes-assets/song.m4a"),
                        "metadata.m4a" => to("http://169.254.169.254/latest/meta-data/"),
                        "local.m4a" => to("https://127.0.0.1/itunes-assets/song.m4a"),
                        "downgrade.m4a" => to("http://audio-ssl.itunes.apple.com/itunes-assets/song.m4a"),
                        "offpath.m4a" => to("/somewhere/else.m4a"),
                        "loop.m4a" => to("https://audio-ssl.itunes.apple.com/itunes-assets/loop.m4a"),
                        // On Apple's own CDN, but the image host: not where a PREVIEW may come from.
                        "toart.m4a" => to("https://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg"),
                        _ => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr, hits)
    }

    fn at(name: &str) -> String {
        format!("https://audio-ssl.itunes.apple.com/itunes-assets/{name}")
    }

    #[tokio::test]
    async fn redirects_oversize_and_non_audio_answers_are_refused() {
        let (addr, hits) = fake_apple().await;
        let previews = Previews { test_origin: Some(addr), ..Default::default() };

        let (kind, body) = fetch(&previews, &at("song.m4a")).await.unwrap();
        assert_eq!((kind.as_str(), &body[..]), ("audio/x-m4p", &b"preview-bytes"[..]));
        // A redirect that stays on Apple's preview host (absolute or relative) is followed…
        assert_eq!(&fetch(&previews, &at("moved.m4a")).await.unwrap().1[..], b"preview-bytes");
        assert_eq!(&fetch(&previews, &at("relative.m4a")).await.unwrap().1[..], b"preview-bytes");
        // …one that leaves it is not: no request is made to where it points.
        for name in ["offhost.m4a", "metadata.m4a", "local.m4a", "downgrade.m4a", "offpath.m4a", "toart.m4a"] {
            let before = hits.load(Ordering::SeqCst);
            assert!(fetch(&previews, &at(name)).await.is_err(), "{name}");
            assert_eq!(hits.load(Ordering::SeqCst), before + 1, "{name}: only the first hop was requested");
        }
        // A redirect loop ends after two hops.
        let before = hits.load(Ordering::SeqCst);
        assert!(fetch(&previews, &at("loop.m4a")).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), before + 1 + MAX_REDIRECTS);
        // Size: exactly the cap passes, one byte more does not; nothing empty either.
        assert_eq!(fetch(&previews, &at("max.m4a")).await.unwrap().1.len(), MAX_PREVIEW_BYTES);
        assert!(fetch(&previews, &at("big.m4a")).await.is_err());
        assert!(fetch(&previews, &at("empty.m4a")).await.is_err());
        // Only audio, and only a 200.
        for name in ["page.m4a", "untyped.m4a", "missing.m4a"] {
            assert!(fetch(&previews, &at(name)).await.is_err(), "{name}");
        }
    }

    async fn post_raw(app: &Router, token: Option<&str>, body: serde_json::Value) -> (StatusCode, Option<String>, Vec<u8>) {
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let mut req = axum::http::Request::builder().method("POST").uri("/api/music/preview").header(header::CONTENT_TYPE, "application/json");
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let res = app.clone().oneshot(req.body(axum::body::Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = res.status();
        let kind = res.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
        (status, kind, res.into_body().collect().await.unwrap().to_bytes().to_vec())
    }

    async fn join_a_space(app: &Router, token: &str) {
        use base64::Engine;
        let name = base64::engine::general_purpose::STANDARD.encode(b"s");
        assert_eq!(send(app, "POST", "/api/servers", Some(token), Some(json!({ "name_ciphertext": name }))).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_endpoint_is_for_members_serves_audio_and_asks_apple_once() {
        let (addr, hits) = fake_apple().await;
        let mut state = test_state().await;
        state.music = Previews { test_origin: Some(addr), ..Default::default() };
        let app = crate::api::router(state.clone());
        let (_, alice) = signup(&app, "alice").await;
        let (_, bob) = signup(&app, "bobby").await;
        let (_, stray) = signup(&app, "stray").await;
        join_a_space(&app, &alice).await;
        join_a_space(&app, &bob).await;

        // Signed out: nothing. An account in no space: nothing. Neither reaches Apple.
        assert_eq!(post_raw(&app, None, json!({ "url": at("song.m4a") })).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(post_raw(&app, Some("not-a-token"), json!({ "url": at("song.m4a") })).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(post_raw(&app, Some(&stray), json!({ "url": at("song.m4a") })).await.0, StatusCode::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        let (st, kind, body) = post_raw(&app, Some(&alice), json!({ "url": at("song.m4a") })).await;
        assert_eq!((st, kind.as_deref(), &body[..]), (StatusCode::OK, Some("audio/x-m4p"), &b"preview-bytes"[..]));
        // Another viewer of the same story, and the first one again: served from memory.
        assert_eq!(post_raw(&app, Some(&bob), json!({ "url": at("song.m4a") })).await.2, b"preview-bytes");
        assert_eq!(post_raw(&app, Some(&alice), json!({ "url": at("song.m4a") })).await.0, StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "one upstream fetch between them");

        // Not a proxy: anything else is refused before any request is made.
        for bad in ["https://evil.example/itunes-assets/a.m4a", "http://127.0.0.1:8080/", "https://169.254.169.254/itunes-assets/a.m4a", "file:///etc/passwd"] {
            let (st, kind, _) = post_raw(&app, Some(&alice), json!({ "url": bad })).await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
            assert_eq!(kind.as_deref(), Some("application/json"));
        }
        assert_eq!(post_raw(&app, Some(&alice), json!({ "url": at("offhost.m4a") })).await.0, StatusCode::BAD_REQUEST);
        assert!(post_raw(&app, Some(&alice), json!({ "nope": 1 })).await.0.is_client_error());
        // The URL is only ever in the body: a GET with it in the query string does not exist.
        let (st, _) = send(&app, "GET", &format!("/api/music/preview?u={}", at("song.m4a")), Some(&alice), None).await;
        assert_eq!(st, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn previews_are_rate_limited_per_account() {
        let (addr, _) = fake_apple().await;
        let mut state = test_state().await;
        state.music = Previews { test_origin: Some(addr), ..Default::default() };
        let app = crate::api::router(state.clone());
        let (_, alice) = signup(&app, "alice").await;
        let (_, bob) = signup(&app, "bobby").await;
        join_a_space(&app, &alice).await;
        join_a_space(&app, &bob).await;
        for i in 0..PER_HOUR {
            assert_eq!(post_raw(&app, Some(&alice), json!({ "url": at("song.m4a") })).await.0, StatusCode::OK, "request {i}");
        }
        assert_eq!(post_raw(&app, Some(&alice), json!({ "url": at("song.m4a") })).await.0, StatusCode::TOO_MANY_REQUESTS);
        // Refused URLs do not use up the hour, and one account's limit is not another's.
        assert_eq!(post_raw(&app, Some(&bob), json!({ "url": "https://evil.example/a.m4a" })).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(post_raw(&app, Some(&bob), json!({ "url": at("song.m4a") })).await.0, StatusCode::OK);
    }

    #[test]
    fn the_cache_is_bounded() {
        let previews = Previews::default();
        for i in 0..(CACHE_ENTRIES as u8 + 10) {
            previews.put(&PREVIEW, [i; 32], Cached { at: now_ms() + i as i64, content_type: "audio/mp4".into(), body: Bytes::from_static(b"x") });
        }
        assert_eq!(previews.cache.lock().unwrap().len(), CACHE_ENTRIES);
        assert!(previews.get(&PREVIEW, &[0; 32]).is_none(), "the oldest went first");
        assert!(previews.get(&PREVIEW, &[CACHE_ENTRIES as u8 + 9; 32]).is_some());
        // An entry past its ten minutes is gone.
        previews.put(&PREVIEW, [200; 32], Cached { at: now_ms() - CACHE_TTL_MS - 1, content_type: "audio/mp4".into(), body: Bytes::from_static(b"x") });
        assert!(previews.get(&PREVIEW, &[200; 32]).is_none());
    }

    // ---- artwork ----

    const ART: &str = "https://is1-ssl.mzstatic.com/image/thumb/Music112/v4/df/db/61/x/18UMGIM31076.rgb.jpg/200x200bb.jpg";

    #[test]
    fn only_apples_image_hosts_and_image_paths_are_fetched_as_artwork() {
        assert!(validate(&ARTWORK, ART).is_ok());
        for n in 1..=5 {
            assert!(validate(&ARTWORK, &format!("https://is{n}-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg")).is_ok());
        }
        for bad in [
            "http://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg",
            "https://mzstatic.com/image/thumb/a/200x200bb.jpg",
            "https://evil.mzstatic.com/image/thumb/a/200x200bb.jpg",
            "https://is6-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg",
            "https://is1-ssl.mzstatic.com.evil.example/image/thumb/a/200x200bb.jpg",
            "https://is1-ssl.mzstatic.com@evil.example/image/thumb/a/200x200bb.jpg",
            "https://u:p@is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg",
            "https://is1-ssl.mzstatic.com:8443/image/thumb/a/200x200bb.jpg",
            "https://is1-ssl.mzstatic.com./image/thumb/a/200x200bb.jpg",
            "https://evil.example/image/thumb/a/200x200bb.jpg",
            "https://127.0.0.1/image/thumb/a/200x200bb.jpg",
            "https://169.254.169.254/image/thumb/a/200x200bb.jpg",
            "https://[::1]/image/thumb/a/200x200bb.jpg",
            "https://is1-ssl.mzstatic.com/other/a.jpg",
            "https://is1-ssl.mzstatic.com/image/thumb/../../a.jpg",
            "https://is1-ssl.mzstatic.com/image/thumb/a/x.svg",
            "https://is1-ssl.mzstatic.com/image/thumb/a/x.html",
            "https://is1-ssl.mzstatic.com/image/thumb/a/x.jpg#f",
            // Each endpoint has its own host: neither fetches the other's.
            "https://audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com/image/thumb/a/200x200bb.jpg",
            "file:///etc/passwd",
            "",
        ] {
            assert!(validate(&ARTWORK, bad).is_err(), "{bad}");
        }
        assert!(validate(&PREVIEW, ART).is_err());
        // Raster images only: an SVG is a document, and "image/" alone is not a type.
        for ok in ["image/jpeg", "image/png", "image/webp", "IMAGE/JPEG; q=1"] {
            assert!(type_allowed(&ARTWORK, ok), "{ok}");
        }
        for bad in ["image/svg+xml", "image/", "image/gif", "text/html", "application/octet-stream", "audio/mp4", "", "image/jpeg\r\nx: y"] {
            assert!(!type_allowed(&ARTWORK, bad), "{bad}");
        }
        assert!(!type_allowed(&PREVIEW, "audio/"));
    }

    /// A stand-in for Apple's image host.
    async fn fake_image_host() -> (SocketAddr, Arc<AtomicUsize>) {
        use axum::extract::Path;
        use axum::routing::get;
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = Router::new().route(
            "/image/thumb/:name",
            get(move |Path(name): Path<String>| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let image = |kind: &'static str, body: Vec<u8>| (StatusCode::OK, [(header::CONTENT_TYPE, kind)], body).into_response();
                    let to = |location: &str| (StatusCode::FOUND, [(header::LOCATION, location.to_string())]).into_response();
                    match name.as_str() {
                        "cover.jpg" => image("image/jpeg", b"jpeg-bytes".to_vec()),
                        "max.jpg" => image("image/jpeg", vec![1u8; MAX_ARTWORK_BYTES]),
                        "big.jpg" => image("image/jpeg", vec![1u8; MAX_ARTWORK_BYTES + 1]),
                        "vector.jpg" => image("image/svg+xml", b"<svg onload=alert(1)>".to_vec()),
                        "page.jpg" => image("text/html", b"<html>".to_vec()),
                        "audio.jpg" => image("audio/mp4", b"sound".to_vec()),
                        "moved.jpg" => to("https://is3-ssl.mzstatic.com/image/thumb/cover.jpg"),
                        "offhost.jpg" => to("https://evil.example/image/thumb/cover.jpg"),
                        "metadata.jpg" => to("http://169.254.169.254/latest/meta-data/"),
                        "local.jpg" => to("https://127.0.0.1/image/thumb/cover.jpg"),
                        "toaudio.jpg" => to("https://audio-ssl.itunes.apple.com/itunes-assets/song.m4a"),
                        _ => StatusCode::NOT_FOUND.into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr, hits)
    }

    fn art(name: &str) -> String {
        format!("https://is1-ssl.mzstatic.com/image/thumb/{name}")
    }

    #[tokio::test]
    async fn artwork_redirects_oversize_and_non_images_are_refused() {
        let (addr, hits) = fake_image_host().await;
        let previews = Previews { test_origin: Some(addr), ..Default::default() };
        let (kind, body) = fetch_as(&ARTWORK, &previews, &art("cover.jpg")).await.unwrap();
        assert_eq!((kind.as_str(), &body[..]), ("image/jpeg", &b"jpeg-bytes"[..]));
        // A redirect to another of Apple's image shards is followed; anything else is not requested.
        assert_eq!(&fetch_as(&ARTWORK, &previews, &art("moved.jpg")).await.unwrap().1[..], b"jpeg-bytes");
        for name in ["offhost.jpg", "metadata.jpg", "local.jpg", "toaudio.jpg"] {
            let before = hits.load(Ordering::SeqCst);
            assert!(fetch_as(&ARTWORK, &previews, &art(name)).await.is_err(), "{name}");
            assert_eq!(hits.load(Ordering::SeqCst), before + 1, "{name}: only the first hop was requested");
        }
        assert_eq!(fetch_as(&ARTWORK, &previews, &art("max.jpg")).await.unwrap().1.len(), MAX_ARTWORK_BYTES);
        for name in ["big.jpg", "vector.jpg", "page.jpg", "audio.jpg", "missing.jpg"] {
            assert!(fetch_as(&ARTWORK, &previews, &art(name)).await.is_err(), "{name}");
        }
    }

    #[tokio::test]
    async fn the_artwork_endpoint_is_for_members_cached_and_rate_limited() {
        use http_body_util::BodyExt;
        use tower::ServiceExt;
        let (addr, hits) = fake_image_host().await;
        let mut state = test_state().await;
        state.music = Previews { test_origin: Some(addr), ..Default::default() };
        let app = crate::api::router(state.clone());
        let (_, alice) = signup(&app, "alice").await;
        let (_, bob) = signup(&app, "bobby").await;
        let (_, stray) = signup(&app, "stray").await;
        join_a_space(&app, &alice).await;
        join_a_space(&app, &bob).await;
        let post = |token: Option<String>, url: String| {
            let app = app.clone();
            async move {
                let mut req = axum::http::Request::builder().method("POST").uri("/api/music/artwork").header(header::CONTENT_TYPE, "application/json");
                if let Some(t) = token {
                    req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
                }
                let res = app.oneshot(req.body(axum::body::Body::from(json!({ "url": url }).to_string())).unwrap()).await.unwrap();
                let status = res.status();
                let kind = res.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
                (status, kind, res.into_body().collect().await.unwrap().to_bytes().to_vec())
            }
        };
        assert_eq!(post(None, art("cover.jpg")).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(post(Some(stray.clone()), art("cover.jpg")).await.0, StatusCode::FORBIDDEN);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        let (st, kind, body) = post(Some(alice.clone()), art("cover.jpg")).await;
        assert_eq!((st, kind.as_deref(), &body[..]), (StatusCode::OK, Some("image/jpeg"), &b"jpeg-bytes"[..]));
        assert_eq!(post(Some(bob.clone()), art("cover.jpg")).await.0, StatusCode::OK);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "one upstream fetch between them");
        // Not a proxy, and not the preview endpoint's allowlist either.
        for bad in ["https://evil.example/image/thumb/a.jpg", "https://169.254.169.254/image/thumb/a.jpg", "http://127.0.0.1/", &at("song.m4a")] {
            assert_eq!(post(Some(alice.clone()), bad.to_string()).await.0, StatusCode::BAD_REQUEST, "{bad}");
        }
        assert_eq!(post_raw(&app, Some(&alice), json!({ "url": art("cover.jpg") })).await.0, StatusCode::BAD_REQUEST, "the preview endpoint does not fetch images");
        // Its own hourly allowance (refused URLs above did not use it up).
        for i in 2..ARTWORK.per_hour {
            assert_eq!(post(Some(alice.clone()), art("cover.jpg")).await.0, StatusCode::OK, "request {i}");
        }
        assert_eq!(post(Some(alice.clone()), art("cover.jpg")).await.0, StatusCode::OK);
        assert_eq!(post(Some(alice.clone()), art("cover.jpg")).await.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(post(Some(bob.clone()), art("cover.jpg")).await.0, StatusCode::OK);
        // The two caches are apart: artwork never evicts audio.
        assert!(state.music.cache.lock().unwrap().is_empty());
        assert_eq!(state.music.art.lock().unwrap().len(), 1);
    }
}
