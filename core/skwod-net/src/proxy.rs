//! The loopback proxy: how the apps' EXISTING HTTP/WebSocket clients reach the host.
//!
//! The Swift/Kotlin apps talk to the server from many places (URLSession, OkHttp, the LiveKit
//! SDK) besides the Rust core. Rather than port all of them, the core runs this tiny HTTP/1.1
//! reverse proxy inside the app process and hands the app a base URL:
//!
//! ```text
//! http://127.0.0.1:<random port>/<128-bit secret>            → skwod API   (KIND_HTTP stream)
//! ws://127.0.0.1:<random port>/<128-bit secret>/lk           → LiveKit     (KIND_LIVEKIT stream)
//! ```
//!
//! - Bound to 127.0.0.1 only, OS-assigned port.
//! - **Authenticated by the secret path prefix**: another local app (or a web page doing DNS
//!   rebinding) that finds the port gets `404` for anything not under the secret. The prefix is
//!   stripped before the request leaves the device; the host never sees it.
//! - One QUIC stream per request; upgrades (WebSocket) become a raw byte pipe on that stream.
//!
//! [`Upstream`] is the seam for other transports: a Tor onion upstream (stage 4) implements the
//! same two methods and everything above keeps working.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONNECTION, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::{BoxFuture, Member, NetError};

pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// Something that can open byte streams to the host's HTTP API and to its LiveKit.
pub trait Upstream: Send + Sync + 'static {
    fn open_http(self: Arc<Self>) -> BoxFuture<Result<Box<dyn Io>, NetError>>;
    fn open_livekit(self: Arc<Self>) -> BoxFuture<Result<Box<dyn Io>, NetError>>;
    /// `(host id, own id)` when the upstream wants proof-of-work stamps on unauthenticated
    /// first-contact requests (see [`crate::pow`]); `None` for transports that don't.
    fn pow_identity(&self) -> Option<([u8; 32], [u8; 32])> {
        None
    }
}

impl Upstream for Member {
    fn open_http(self: Arc<Self>) -> BoxFuture<Result<Box<dyn Io>, NetError>> {
        Box::pin(async move { Ok(Box::new(Member::open_http(&self).await?) as Box<dyn Io>) })
    }
    fn open_livekit(self: Arc<Self>) -> BoxFuture<Result<Box<dyn Io>, NetError>> {
        Box::pin(async move { Ok(Box::new(Member::open_livekit(&self).await?) as Box<dyn Io>) })
    }
    fn pow_identity(&self) -> Option<([u8; 32], [u8; 32])> {
        Some((*self.host_id().as_bytes(), *self.id().as_bytes()))
    }
}

/// Requests that test a credential without a session — the ones the host wants a stamp on.
fn needs_pow(method: &hyper::Method, path: &str) -> bool {
    method == hyper::Method::POST && matches!(path, "/api/auth/signup" | "/api/auth/login")
}

/// Bodies of stamped requests are buffered (so a clock-skew retry can resend them); they are
/// small JSON credentials, never uploads.
const MAX_POW_BODY: usize = 64 * 1024;

type Body = BoxBody<Bytes, hyper::Error>;

pub struct LocalProxy {
    port: u16,
    secret: String,
    task: tokio::task::JoinHandle<()>,
}

impl LocalProxy {
    pub async fn start(upstream: Arc<dyn Upstream>) -> Result<Self, NetError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| NetError::Io(e.to_string()))?;
        let port = listener.local_addr().map_err(|e| NetError::Io(e.to_string()))?.port();
        let secret = hex::encode(rand::random::<[u8; 16]>());
        let prefix: Arc<str> = format!("/{secret}").into();
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, peer)) = listener.accept().await else { continue };
                if !peer.ip().is_loopback() {
                    continue;
                }
                let (upstream, prefix) = (upstream.clone(), prefix.clone());
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req| handle(upstream.clone(), prefix.clone(), req));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        Ok(Self { port, secret, task })
    }

    /// Base URL for the skwod API — a drop-in for the `https://…` server URL.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/{}", self.port, self.secret)
    }

    /// URL to give the LiveKit SDK (it appends `/rtc?...` itself).
    pub fn livekit_url(&self) -> String {
        format!("ws://127.0.0.1:{}/{}/lk", self.port, self.secret)
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn status(code: StatusCode) -> Response<Body> {
    let mut res = Response::new(Empty::<Bytes>::new().map_err(|never| match never {}).boxed());
    *res.status_mut() = code;
    res
}

/// Constant-time-ish prefix check (the secret is 128 random bits; this just avoids a trivially
/// measurable early exit).
fn strip_secret<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let (head, rest) = path.split_at_checked(prefix.len())?;
    let diff = head.bytes().zip(prefix.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b));
    (diff == 0 && (rest.is_empty() || rest.starts_with('/'))).then_some(rest)
}

/// What the HOST may make the app's HTTP stack do (audit P5). The apps reach every skwod
/// through a proxy on `127.0.0.1`, and their HTTP stack scopes cookies to a HOST, not a port:
/// a `Set-Cookie` from one skwod's host was sent back to every other skwod's proxy (and on to
/// that skwod's host) and to anything else on loopback — two hosts could link one person's
/// accounts across skwods. And a redirect was followed wherever it pointed: the member's
/// router, another loopback service, any site. The API uses neither cookies nor redirects, so:
///
/// - `Set-Cookie` never reaches the app, and a `Cookie` the app sends never reaches a host;
/// - a `Location` survives only as a path on the SAME skwod (`/…`, not `//…`), re-anchored
///   under this proxy's secret prefix; anything else is removed, which leaves the app with a
///   redirect status and nowhere to go.
fn sanitize_response_headers(headers: &mut hyper::HeaderMap, prefix: &str) {
    headers.remove(hyper::header::SET_COOKIE);
    headers.remove("set-cookie2");
    for name in [hyper::header::LOCATION, hyper::header::CONTENT_LOCATION, hyper::header::REFRESH] {
        let same_skwod = headers
            .get(&name)
            .and_then(|v| v.to_str().ok())
            .filter(|_| name == hyper::header::LOCATION)
            .filter(|v| v.starts_with('/') && !v.starts_with("//") && !v.contains('\\'))
            .and_then(|v| HeaderValue::from_str(&format!("{prefix}{v}")).ok());
        match same_skwod {
            Some(local) => {
                headers.insert(name, local);
            }
            None => {
                headers.remove(name);
            }
        }
    }
}

fn sanitize_request_headers(headers: &mut hyper::HeaderMap) {
    headers.remove(hyper::header::COOKIE);
    headers.remove("cookie2");
}

/// Send one request upstream on a fresh stream.
async fn forward(upstream: &Arc<dyn Upstream>, livekit: bool, req: Request<Body>) -> Option<Response<Incoming>> {
    let opened = if livekit { upstream.clone().open_livekit().await } else { upstream.clone().open_http().await };
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(opened.ok()?)).await.ok()?;
    tokio::spawn(conn.with_upgrades());
    sender.send_request(req).await.ok()
}

async fn stamp(ids: ([u8; 32], [u8; 32]), window: u64, bits: u32) -> Option<HeaderValue> {
    let stamp = tokio::task::spawn_blocking(move || crate::pow::solve_for(crate::pow::Purpose::Request, &ids.0, &ids.1, window, bits)).await.ok()?;
    HeaderValue::from_str(&stamp).ok()
}

async fn handle(upstream: Arc<dyn Upstream>, prefix: Arc<str>, mut req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
    let Some(rest) = strip_secret(req.uri().path(), &prefix) else {
        return Ok(status(StatusCode::NOT_FOUND));
    };
    let (livekit, rest) = match rest.strip_prefix("/lk") {
        Some(r) if r.is_empty() || r.starts_with('/') => (true, r),
        _ => (false, rest),
    };
    let path = if rest.is_empty() { "/".to_string() } else { rest.to_string() };
    let mut target = path.clone();
    if let Some(q) = req.uri().query() {
        target.push('?');
        target.push_str(q);
    }
    let Ok(uri) = target.parse() else { return Ok(status(StatusCode::BAD_REQUEST)) };
    *req.uri_mut() = uri;

    sanitize_request_headers(req.headers_mut());
    let wants_upgrade = req.headers().contains_key(UPGRADE);
    let downstream = wants_upgrade.then(|| hyper::upgrade::on(&mut req));
    if !wants_upgrade {
        // One request per stream: tell the far side not to wait for another.
        req.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
    }

    // Unauthenticated first contact (signup/login): attach a proof-of-work stamp. The app never
    // sees this; a stamp sent by the app itself is discarded.
    let pow = upstream.pow_identity().filter(|_| !livekit && needs_pow(req.method(), &path));
    let res = match pow {
        None => forward(&upstream, livekit, req.map(|b| b.boxed())).await,
        Some(ids) => {
            let (mut parts, body) = req.into_parts();
            let Ok(body) = http_body_util::Limited::new(body, MAX_POW_BODY).collect().await.map(|b| b.to_bytes()) else {
                return Ok(status(StatusCode::PAYLOAD_TOO_LARGE));
            };
            parts.headers.remove(crate::pow::POW_HEADER);
            let build = |stamp: HeaderValue| {
                let mut r = Request::new(http_body_util::Full::new(body.clone()).map_err(|never| match never {}).boxed());
                *r.method_mut() = parts.method.clone();
                *r.uri_mut() = parts.uri.clone();
                *r.headers_mut() = parts.headers.clone();
                r.headers_mut().insert(crate::pow::POW_HEADER, stamp);
                r
            };
            let Some(first) = stamp(ids, crate::pow::current_window(), crate::pow::POW_BITS).await else { return Ok(status(StatusCode::BAD_GATEWAY)) };
            let mut res = forward(&upstream, false, build(first)).await;
            // 428 + a window: our clock disagrees with the host's, or the host — being flooded
            // — wants more work than the base (`x-skwod-pow-bits`, audit P6). Redo the work
            // for ITS window at ITS difficulty, once. The difficulty is capped on this side
            // (`pow::MAX_POW_BITS`): a host cannot make a phone grind for minutes.
            let header = |name: &str| {
                res.as_ref()
                    .filter(|r| r.status() == StatusCode::PRECONDITION_REQUIRED)
                    .and_then(|r| r.headers().get(name))
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
            };
            let host_window = header(crate::pow::POW_WINDOW_HEADER);
            let host_bits = header(crate::pow::POW_BITS_HEADER).map(|b| b.clamp(crate::pow::POW_BITS as u64, crate::pow::MAX_POW_BITS as u64) as u32);
            if let Some(window) = host_window {
                if let Some(again) = stamp(ids, window, host_bits.unwrap_or(crate::pow::POW_BITS)).await {
                    res = forward(&upstream, false, build(again)).await;
                }
            }
            res
        }
    };
    let Some(mut res) = res else { return Ok(status(StatusCode::BAD_GATEWAY)) };
    sanitize_response_headers(res.headers_mut(), &prefix);
    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(downstream) = downstream {
            let upstream_upgrade = hyper::upgrade::on(&mut res);
            tokio::spawn(async move {
                if let (Ok(down), Ok(up)) = (downstream.await, upstream_upgrade.await) {
                    let (mut down, mut up) = (TokioIo::new(down), TokioIo::new(up));
                    let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                }
            });
        }
    } else if !wants_upgrade {
        // The upstream leg is per-request; don't let its `close` end the app's keep-alive socket.
        res.headers_mut().remove(CONNECTION);
    }
    Ok(res.map(|b| b.boxed()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_prefix_gate() {
        let p = "/0123456789abcdef";
        assert_eq!(strip_secret("/0123456789abcdef/api/x", p), Some("/api/x"));
        assert_eq!(strip_secret("/0123456789abcdef", p), Some(""));
        assert_eq!(strip_secret("/0123456789abcdeX/api/x", p), None);
        assert_eq!(strip_secret("/0123456789abcdefg/api", p), None, "prefix must end at a segment boundary");
        assert_eq!(strip_secret("/api/x", p), None);
        assert_eq!(strip_secret("/", p), None);
    }

    /// Audit P5: a host plants no cookie and sends the app nowhere but itself.
    #[test]
    fn a_host_cannot_plant_cookies_or_redirect_the_app_elsewhere() {
        use hyper::header::{COOKIE, LOCATION, SET_COOKIE};
        let prefix = "/0123456789abcdef";
        let filtered = |location: &str| {
            let mut h = hyper::HeaderMap::new();
            h.append(SET_COOKIE, HeaderValue::from_static("id=tracker; Path=/; Max-Age=31536000"));
            h.append(SET_COOKIE, HeaderValue::from_static("second=1"));
            h.insert(LOCATION, HeaderValue::from_str(location).unwrap());
            h.insert(hyper::header::REFRESH, HeaderValue::from_static("0; url=http://192.168.1.1/"));
            h.insert(hyper::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            sanitize_response_headers(&mut h, prefix);
            assert!(!h.contains_key(SET_COOKIE) && !h.contains_key(hyper::header::REFRESH));
            assert!(h.contains_key(hyper::header::CONTENT_TYPE), "everything else passes");
            h.get(LOCATION).map(|v| v.to_str().unwrap().to_string())
        };
        for elsewhere in ["http://192.168.1.1/admin", "https://evil.example/x", "//evil.example/x", "http://127.0.0.1:3477/", "skwod://join", "relative/path", "/\\evil.example"] {
            assert_eq!(filtered(elsewhere), None, "{elsewhere}");
        }
        assert_eq!(filtered("/api/blobs/b1").as_deref(), Some("/0123456789abcdef/api/blobs/b1"), "a path on the same skwod stays under this proxy");
        let mut req = hyper::HeaderMap::new();
        req.insert(COOKIE, HeaderValue::from_static("id=from-another-skwod"));
        req.insert(hyper::header::AUTHORIZATION, HeaderValue::from_static("Bearer t"));
        sanitize_request_headers(&mut req);
        assert!(!req.contains_key(COOKIE) && req.contains_key(hyper::header::AUTHORIZATION));
    }

    #[test]
    fn only_credential_testing_requests_are_stamped() {
        use hyper::Method;
        assert!(needs_pow(&Method::POST, "/api/auth/signup") && needs_pow(&Method::POST, "/api/auth/login"));
        assert!(!needs_pow(&Method::GET, "/api/auth/login"));
        assert!(!needs_pow(&Method::POST, "/api/auth/logout"), "authenticated requests are exempt");
        assert!(!needs_pow(&Method::POST, "/api/channels/x/messages"));
    }
}
