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
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, CONNECTION, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;

use crate::{BoxFuture, Member, NetError};

pub trait Io: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> Io for T {}

/// What an [`Upstream`] hands back: a future of a byte stream (public, for upstreams outside
/// this crate).
pub type UpstreamFuture<T> = BoxFuture<Result<T, NetError>>;

/// Something that can open byte streams to the host's HTTP API and to its LiveKit.
pub trait Upstream: Send + Sync + 'static {
    fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>>;
    fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>>;
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

/// Build 51: clients of a front send `Authorization: Bearer front-<credential>` (handed out by
/// an explicit sign-in in the core) instead of the session token. The front swaps a credential
/// it knows for the token; a request with any other Authorization is refused here
/// ([`STALE_CREDENTIAL`]) — never forwarded without one: the host's 401 would read as "your
/// session ended"; a request without one gets none (sealed-sender deposits stay anonymous).
pub const FRONT_CREDENTIAL_PREFIX: &str = "front-";

/// Where the front gets the token to inject — called with (the front's secret, the credential
/// the client sent) on every forward, so it is always the session's current one, or nothing.
pub type TokenSource = Arc<dyn Fn(&str, &str) -> Option<String> + Send + Sync>;

/// The header (on a 503) that says the front itself refused a credential.
pub const FRONT_REFUSAL_HEADER: &str = "x-skwod-front";
pub const STALE_CREDENTIAL: &str = "stale-credential";

/// The Authorization rule of the front (pure, tested). `token(credential)`. False: one was
/// presented that stands for nothing — refuse the request.
#[must_use]
pub(crate) fn authorize(headers: &mut hyper::HeaderMap, token: impl FnOnce(&str) -> Option<String>) -> bool {
    if !headers.contains_key(hyper::header::AUTHORIZATION) { return true }
    let credential = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().strip_prefix("Bearer "))
        .filter(|c| c.starts_with(FRONT_CREDENTIAL_PREFIX))
        .map(str::to_string);
    while headers.remove(hyper::header::AUTHORIZATION).is_some() {}
    if let Some(t) = credential.and_then(|c| token(&c)).filter(|t| !t.is_empty()) {
        if let Ok(v) = HeaderValue::from_str(&format!("Bearer {t}")) {
            headers.insert(hyper::header::AUTHORIZATION, v);
            return true;
        }
    }
    false
}

/// Requests that test a credential without a session — the ones the host wants a stamp on.
fn needs_pow(method: &hyper::Method, path: &str) -> bool {
    // Plus the session-less QR pair request (first contact, it stores a row). Its claim is not
    // stamped: it is polled, and the host asks no work for it.
    method == hyper::Method::POST && matches!(path, "/api/auth/signup" | "/api/auth/login" | "/api/e2ee/pair-requests")
}

/// Bodies of stamped requests are buffered (so a clock-skew retry can resend them); they are
/// small JSON credentials, never uploads.
const MAX_POW_BODY: usize = 64 * 1024;

type Body = BoxBody<Bytes, hyper::Error>;

pub struct LocalProxy {
    /// Where the front is and what proves it — one immutable snapshot, swapped as a whole.
    cell: Arc<std::sync::RwLock<Arc<Snapshot>>>,
    /// What every connection is served with (never swapped).
    shared: Arc<Shared>,
    task: std::sync::Mutex<tokio::task::JoinHandle<()>>,
    /// `shutdown` ran: never listen again.
    shut: std::sync::atomic::AtomicBool,
}

/// Build 51: the front's identity at one moment — port, secret and whether it is proved ours —
/// read and replaced together, never in pieces. Every URL and every check derives from ONE
/// snapshot.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    port: u16,
    secret: Arc<str>,
    prefix: Arc<str>,
    /// A challenge proved the port ours. While not, nothing is forwarded or injected.
    verified: bool,
    /// Sticky distrust: the port answered as NOT ours (or a re-listen failed). No later challenge
    /// can make this snapshot trusted again — only a successful re-listen (a new snapshot) can.
    must_rekey: bool,
    /// Which listener/secret this is; a verdict reached for another generation is not applied.
    generation: u64,
}

static GENERATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Snapshot {
    fn fresh(port: u16) -> Self {
        let secret = hex::encode(rand::random::<[u8; 16]>());
        Self {
            port,
            prefix: format!("/{secret}").into(),
            secret: secret.into(),
            verified: true,
            must_rekey: false,
            generation: GENERATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        }
    }
    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/{}", self.port, self.secret)
    }
}

/// What every connection of a front is served with.
struct Shared {
    upstream: Arc<dyn Upstream>,
    tokens: TokenSource,
    /// Set when the listener failed for good (or the front was shut down).
    closed: tokio::sync::watch::Sender<bool>,
    /// Nonces of liveness challenges that reached THIS front's handler (`challenge`).
    seen: Nonces,
    permits: Arc<tokio::sync::Semaphore>,
    /// LiveKit signaling sockets the host's LiveKit accepted (a count, for telling "never reached
    /// the call server" from "reached it, but no media" — local only).
    livekit_accepted: std::sync::atomic::AtomicU64,
    /// Connections that have not named the secret yet (bounded).
    preauth: PreAuth,
    /// Tests: the handler stops proving challenges (a silent impostor's effect, from inside).
    mute_challenges: std::sync::atomic::AtomicBool,
    /// Tests: every bind fails (to reach `FrontState::Failed`).
    fail_binds: std::sync::atomic::AtomicBool,
    /// Which accept loop is THE front's (`spawn_loop`); every other one is parked.
    current_loop: tokio::sync::watch::Sender<u64>,
    /// Tests: no room to park.
    no_park: std::sync::atomic::AtomicBool,
}

/// Build 51 (M1): listeners a front moved away from. A port the front held is never released
/// while the process lives (a squatter could otherwise take it and receive what a stale client
/// still sends there): its loop keeps ONLY the listener (`parked_loop`), answering every
/// connection with the same refusal. Bounded: past `MAX_PARKED` a front that would have to move
/// stays distrusted ([`FrontState::Failed`]) instead.
struct Parked {
    loops: Vec<(u16, tokio::task::JoinHandle<()>)>,
    reserved: usize,
}
static PARKED: std::sync::Mutex<Parked> = std::sync::Mutex::new(Parked { loops: Vec::new(), reserved: 0 });
const MAX_PARKED: usize = 16;
/// Connections to parked ports being answered at any moment (all of them together).
static PARKED_PERMITS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

/// Room to park one more listener, taken BEFORE a front moves; given back if unused.
struct ParkSlot { lot: &'static std::sync::Mutex<Parked>, used: bool }

impl ParkSlot {
    fn reserve(lot: &'static std::sync::Mutex<Parked>) -> Option<Self> {
        let mut p = lot.lock().unwrap_or_else(|e| e.into_inner());
        if p.loops.len() + p.reserved >= MAX_PARKED {
            // One whose port can be bound again holds nothing any more (the OS took its socket).
            p.loops.retain(|(port, h)| {
                let dead = h.is_finished() || listen_on(*port).is_ok();
                if dead { h.abort(); }
                !dead
            });
        }
        if p.loops.len() + p.reserved >= MAX_PARKED { return None; }
        p.reserved += 1;
        Some(Self { lot, used: false })
    }

    fn park(mut self, port: u16, handle: tokio::task::JoinHandle<()>) {
        self.used = true;
        let mut p = self.lot.lock().unwrap_or_else(|e| e.into_inner());
        p.reserved -= 1;
        p.loops.push((port, handle));
    }
}

impl Drop for ParkSlot {
    fn drop(&mut self) {
        if !self.used { self.lot.lock().unwrap_or_else(|e| e.into_inner()).reserved -= 1; }
    }
}

/// What is left of a loop whose front moved away: the listener, and nothing of the front.
async fn parked_loop(listener: TcpListener) {
    let mut failures = 0u32;
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => { failures = 0; refuse_parked(tcp); }
            Err(e) => match classify_accept_error(&e) {
                AcceptFailure::Transient => {
                    failures = failures.saturating_add(1);
                    tokio::time::sleep(accept_backoff(failures)).await;
                }
                AcceptFailure::Fatal => { let _hold = listener; return std::future::pending().await; }
            },
        }
    }
}

/// Dropped at once when too many are being answered; nothing is ever read or waited for.
fn refuse_parked(mut tcp: tokio::net::TcpStream) {
    let Ok(permit) = PARKED_PERMITS.try_acquire() else { return };
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _permit = permit;
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            let _ = tcp.write_all(REFUSED).await;
            let _ = tcp.shutdown().await;
        }).await;
    });
}

/// Start `listener`'s accept loop as the front's current one (any earlier loop is parked from now on).
fn spawn_loop(listener: TcpListener, cell: Arc<std::sync::RwLock<Arc<Snapshot>>>, shared: Arc<Shared>) -> tokio::task::JoinHandle<()> {
    let mut id = 0;
    shared.current_loop.send_modify(|c| { *c += 1; id = *c; });
    tokio::spawn(accept_loop(listener, cell, shared, id))
}

/// Build 51 (M1): this process's own liveness challenges in flight: (the challenge's own socket
/// address, the front address it goes to). The socket is bound BEFORE it connects, so the front
/// knows its challenge by the exact pair and lets it skip the pre-auth queue — a flood can
/// neither evict nor delay it. Single-use: the first match takes it out.
type ChallengePair = (std::net::SocketAddr, std::net::SocketAddr);
static CHALLENGERS: std::sync::Mutex<std::collections::BTreeSet<ChallengePair>> = std::sync::Mutex::new(std::collections::BTreeSet::new());

fn take_challenger(peer: std::net::SocketAddr, local: std::net::SocketAddr) -> bool {
    CHALLENGERS.lock().unwrap_or_else(|e| e.into_inner()).remove(&(peer, local))
}

/// Registers a challenge; unregisters it when the challenge ends, however it ends.
struct ChallengerTag(ChallengePair);
impl ChallengerTag {
    fn new(peer: std::net::SocketAddr, front: std::net::SocketAddr) -> Self {
        CHALLENGERS.lock().unwrap_or_else(|e| e.into_inner()).insert((peer, front));
        Self((peer, front))
    }
}
impl Drop for ChallengerTag {
    fn drop(&mut self) { CHALLENGERS.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0); }
}

/// Build 51 (pre-auth flood): at most `MAX_PREAUTH` connections may be waiting to name the
/// secret. A newcomer always gets in: it evicts the oldest one that has sent NOTHING yet, else the
/// oldest still incomplete. (This process's own challenges do not wait here.)
#[derive(Default)]
struct PreAuth {
    waiting: std::sync::Mutex<std::collections::VecDeque<(u64, tokio::task::AbortHandle, Arc<std::sync::atomic::AtomicBool>)>>,
    next: std::sync::atomic::AtomicU64,
}

const MAX_PREAUTH: usize = 64;

impl PreAuth {
    /// Admit a connection (its task, and the flag it sets while its bytes are a valid prefix of
    /// `METHOD /<secret>`). When full: the oldest idle one is evicted, else the oldest of those
    /// still sending (all of them incomplete) — the newcomer always gets in. (The in-process
    /// liveness challenge never waits here at all: `CHALLENGERS`.)
    fn admit(&self, abort: tokio::task::AbortHandle, sending: Arc<std::sync::atomic::AtomicBool>) -> Option<u64> {
        use std::sync::atomic::Ordering::SeqCst;
        let id = self.next.fetch_add(1, SeqCst);
        let mut q = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= MAX_PREAUTH {
            let i = q.iter().position(|(_, _, sending)| !sending.load(SeqCst)).unwrap_or(0);
            if let Some((_, evicted, _)) = q.remove(i) { evicted.abort(); }
        }
        q.push_back((id, abort, sending));
        Some(id)
    }

    /// Under pressure (the queue three-quarters full) a newcomer gets a shorter deadline.
    fn deadline(&self) -> Duration {
        let len = self.waiting.lock().unwrap_or_else(|e| e.into_inner()).len();
        if len * 4 >= MAX_PREAUTH * 3 { Duration::from_secs(1) } else { FIRST_REQUEST_DEADLINE }
    }
    fn done(&self, id: u64) {
        self.waiting.lock().unwrap_or_else(|e| e.into_inner()).retain(|(i, _, _)| *i != id);
    }
}

/// Nonces of liveness challenges that reached THIS front's handler. A set (bounded), so
/// challenges that overlap never overwrite each other's proof (no false negatives).
#[derive(Default)]
pub(crate) struct Nonces(std::sync::Mutex<std::collections::VecDeque<String>>);

impl Nonces {
    const KEEP: usize = 64;
    fn note(&self, nonce: &str) {
        let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() >= Self::KEEP { q.pop_front(); }
        q.push_back(nonce.to_string());
    }
    fn take(&self, nonce: &str) -> bool {
        let mut q = self.0.lock().unwrap_or_else(|e| e.into_inner());
        match q.iter().position(|n| n == nonce) {
            Some(i) => { q.remove(i); true }
            None => false,
        }
    }
}

/// What a liveness challenge found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Challenge {
    /// The nonce reached this front's handler.
    Ours,
    /// Something answered (or the port refused) and the nonce did NOT reach us: the listener is
    /// gone or the port is someone else's.
    NotOurs,
    /// No answer in time — the front may just be busy (it is not judged gone for that).
    Slow,
}

/// What [`LocalProxy::ensure_listening`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontState {
    /// Listening and proved ours, as it was.
    Alive,
    /// It listens again — under a NEW secret (a port not held continuously is never trusted
    /// with the old one), on the same port when it could be had. The old URL is dead in every
    /// part. Carries the old secret and the new base URL.
    Relistened { old_secret: String, base_url: String },
    /// It had to listen again and could not (no port at all): the front forwards nothing until
    /// the next attempt. `old_secret`: Some when the secret had already been changed (the
    /// session must be carried over to the current one even so).
    Failed { old_secret: Option<String> },
}

/// Connections served at once (each is one HTTP/1.1 keep-alive socket of this process).
const MAX_CONNECTIONS: usize = 256;
/// A connection that has not sent a complete request head by then is closed.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// The path (under the secret) a liveness challenge is sent to; answered here, never forwarded.
const CHALLENGE_PATH: &str = "/.skwod-proxy-alive/";

/// Build 51 (M2): how long a new connection has to send the first line of its first request.
const FIRST_REQUEST_DEADLINE: Duration = Duration::from_secs(3);

/// Read up to the end of the first line (at most 4 KiB) within `deadline`; None if it did not come.
async fn first_line(tcp: &mut tokio::net::TcpStream, deadline: Duration, sending: &std::sync::atomic::AtomicBool, secret_len: usize) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let read = async {
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        loop {
            let n = tcp.read(&mut chunk).await.ok()?;
            if n == 0 { return None; }
            buf.extend_from_slice(&chunk[..n]);
            // Protected only while what came is still SYNTACTICALLY a request line for a secret
            // (secret-independent); closed at the first byte that cannot be.
            if !valid_prefix(&buf, secret_len) { return None; }
            sending.store(true, std::sync::atomic::Ordering::SeqCst);
            if buf.windows(2).any(|w| w == b"\r\n") { return Some(buf); }
            if buf.len() >= MAX_FIRST_LINE {
                use tokio::io::AsyncWriteExt;
                let _ = tcp.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
                return None;
            }
        }
    };
    tokio::time::timeout(deadline, read).await.ok().flatten()
}

/// What every refused connection gets — wrong secret, bad syntax, too slow — the same bytes.
const REFUSED: &[u8] = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";

/// The longest first request line a front reads.
const MAX_FIRST_LINE: usize = 4096;

/// Is what a new connection sent so far still SYNTACTICALLY a possible start of
/// `METHOD /<32 hex chars>…`? It depends only on the method's characters, a leading '/', the
/// secret's CHARSET and length so far, and no line end before the secret is complete — never on
/// the secret's value: an early close cannot tell anyone which bytes of the secret were right.
/// (The secret itself is compared once, whole, in constant time, after the line is complete.)
/// `secret_len`: the secret's length (32). Pure, tested.
fn valid_prefix(bytes: &[u8], secret_len: usize) -> bool {
    let cut = bytes.windows(2).position(|w| w == b"\r\n");
    let line = &bytes[..cut.unwrap_or(bytes.len())];
    let Some(space) = line.iter().position(|b| *b == b' ') else {
        return cut.is_none() && line.len() <= 16 && line.iter().all(|b| b.is_ascii_uppercase());
    };
    if space == 0 || space > 16 || !line[..space].iter().all(|b| b.is_ascii_uppercase()) { return false; }
    let target = &line[space + 1..];
    if target.is_empty() { return cut.is_none(); }
    if target[0] != b'/' { return false; }
    let seg = &target[1..];
    let n = seg.len().min(secret_len);
    if !seg[..n].iter().all(|b| b.is_ascii_hexdigit()) { return false; }
    // A line end before the secret is complete cannot be a request for it.
    if seg.len() < secret_len { return cut.is_none(); }
    seg.len() == secret_len || matches!(seg[secret_len], b'/' | b' ' | b'?' | b'#')
}

/// Does `METHOD /<secret>[/…] HTTP/1.1` name this front's secret? (Pure, tested.)
fn first_line_names_secret(head: &[u8], prefix: &str) -> bool {
    let line_end = head.windows(2).position(|w| w == b"\r\n").unwrap_or(head.len());
    let Ok(line) = std::str::from_utf8(&head[..line_end]) else { return false };
    let mut parts = line.split(' ');
    let (_method, Some(target)) = (parts.next(), parts.next()) else { return false };
    let path = target.split(['?', '#']).next().unwrap_or("");
    strip_secret(path, prefix).is_some()
}

/// A stream whose first bytes were already read (the first line): they are served again first.
struct Prefixed<T> {
    prefix: Vec<u8>,
    pos: usize,
    inner: T,
}

impl<T> Prefixed<T> {
    fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self { prefix, pos: 0, inner }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Prefixed<T> {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Prefixed<T> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, data: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// What a failed `accept` means for the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AcceptFailure {
    /// Out of descriptors or buffers, or one peer that gave up: back off and accept again.
    Transient,
    /// The listening socket itself is gone (iOS reclaims the sockets of a suspended app).
    Fatal,
}

pub(crate) fn classify_accept_error(e: &std::io::Error) -> AcceptFailure {
    use std::io::ErrorKind::*;
    if matches!(e.kind(), ConnectionAborted | ConnectionReset | Interrupted | WouldBlock | TimedOut | OutOfMemory) {
        return AcceptFailure::Transient;
    }
    // EMFILE, ENFILE, ENOBUFS, ENOMEM, ECONNABORTED, EPROTO, EPERM (a firewall refusing one
    // connection on Linux) — the same numbers on Linux, macOS, iOS and Android, except ENOBUFS.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const TRANSIENT: &[i32] = &[24, 23, 105, 12, 103, 71, 1];
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const TRANSIENT: &[i32] = &[24, 23, 55, 12, 53, 100, 1];
    match e.raw_os_error() {
        Some(code) if TRANSIENT.contains(&code) => AcceptFailure::Transient,
        _ => AcceptFailure::Fatal,
    }
}

/// Back-off after the `n`th failed accept in a row: 10 ms doubling to 1 s.
fn accept_backoff(n: u32) -> Duration {
    Duration::from_millis(10u64.saturating_mul(1u64 << n.min(7)).min(1_000))
}

impl LocalProxy {
    pub async fn start(upstream: Arc<dyn Upstream>) -> Result<Self, NetError> {
        Self::start_with_tokens(upstream, Arc::new(|_: &str, _: &str| None)).await
    }

    /// [`Self::start`] with the source of the token this front injects (credentials).
    pub async fn start_with_tokens(upstream: Arc<dyn Upstream>, tokens: TokenSource) -> Result<Self, NetError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| NetError::Io(e.to_string()))?;
        let port = listener.local_addr().map_err(|e| NetError::Io(e.to_string()))?.port();
        let shared = Arc::new(Shared {
            upstream,
            tokens,
            closed: tokio::sync::watch::channel(false).0,
            seen: Nonces::default(),
            permits: Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS)),
            livekit_accepted: Default::default(),
            preauth: PreAuth::default(),
            mute_challenges: Default::default(),
            fail_binds: Default::default(),
            current_loop: tokio::sync::watch::channel(0).0,
            no_park: Default::default(),
        });
        // A listener this process just bound is ours: verified from the start.
        let cell = Arc::new(std::sync::RwLock::new(Arc::new(Snapshot::fresh(port))));
        let task = spawn_loop(listener, cell.clone(), shared.clone());
        Ok(Self { cell, shared, task: std::sync::Mutex::new(task), shut: Default::default() })
    }

    fn snap(&self) -> Arc<Snapshot> {
        self.cell.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Apply a verdict reached for snapshot `generation` — only if that snapshot is still the
    /// current one and the front is not shut. Trust is never restored to a snapshot marked
    /// `must_rekey`; `distrust` marks it so.
    fn apply_verdict(&self, generation: u64, verified: bool, distrust: bool) {
        if self.shut.load(std::sync::atomic::Ordering::SeqCst) { return }
        let mut cell = self.cell.write().unwrap_or_else(|e| e.into_inner());
        if cell.generation != generation { return }
        let verified = verified && !cell.must_rekey && !distrust;
        if cell.verified != verified || (distrust && !cell.must_rekey) {
            let mut next = (**cell).clone();
            next.verified = verified;
            next.must_rekey |= distrust;
            *cell = Arc::new(next);
        }
    }

    fn set_verified(&self, verified: bool) {
        let generation = self.snap().generation;
        self.apply_verdict(generation, verified, false);
    }

    /// Mark the current snapshot not ours for good (until a re-listen).
    fn distrust(&self) {
        let generation = self.snap().generation;
        self.apply_verdict(generation, false, true);
    }

    /// Must the front re-key before it can be trusted again?
    pub fn must_rekey(&self) -> bool {
        self.snap().must_rekey
    }

    /// Build 51 (iOS listener reclaim): is the listener still there and PROVED ours — checked in
    /// process (accept-loop state, and a one-time nonce that must reach this front's handler)?
    /// If not, listen again, always under a NEW secret: on the same port only when our old
    /// listener is really gone, otherwise on a new port bound FIRST. If no port can be had the
    /// front stays unverified (forwards nothing) and says [`FrontState::Failed`].
    pub async fn ensure_listening(&self) -> FrontState {
        use std::sync::atomic::Ordering::SeqCst;
        if self.shut.load(SeqCst) {
            return FrontState::Failed { old_secret: None };
        }
        let verdict = if self.is_closed() { Challenge::NotOurs } else { self.verify(&[Duration::from_secs(2), Duration::from_secs(4)]).await };
        if verdict == Challenge::Ours {
            return FrontState::Alive;
        }
        self.relisten(verdict == Challenge::Slow).await
    }

    /// Re-key, unconditionally (the caller has decided the front is not proved ours, and retired
    /// its URL first). Always a NEW secret. `in_place`: the challenge was merely unanswered (a
    /// busy or flooded front) and our listener is still alive — it is KEPT (a port we hold is
    /// never released) and only the secret changes. Otherwise (refused: the listener is gone) the
    /// same port is bound again if it can be had, else a new one. No port at all: distrusted
    /// (forwards nothing) and [`FrontState::Failed`].
    pub async fn relisten(&self, in_place: bool) -> FrontState {
        use std::sync::atomic::Ordering::SeqCst;
        if self.shut.load(SeqCst) {
            return FrontState::Failed { old_secret: None };
        }
        let old = self.snap();
        if in_place && !self.is_closed() {
            // The new secret is installed UNVERIFIED (forwarding nothing) and published only once
            // a challenge on THIS generation proves the port ours.
            let mut next = Snapshot::fresh(old.port);
            next.verified = false;
            *self.cell.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(next);
            let budgets = [Duration::from_secs(2), Duration::from_secs(4)];
            if self.verify(&budgets).await == Challenge::Ours {
                return FrontState::Relistened { old_secret: old.secret.to_string(), base_url: self.base_url() };
            }
            // Still not proved: a fresh port, bound FIRST, and the front moves there — if the
            // port it leaves can be kept held (parked).
            let Some(slot) = self.park_slot() else {
                self.distrust();
                return FrontState::Failed { old_secret: Some(old.secret.to_string()) };
            };
            let bind = if self.shared.fail_binds.load(SeqCst) { Err(std::io::Error::other("test")) } else { listen_on(0) };
            let Some((listener, addr)) = bind.ok().and_then(|l| l.local_addr().ok().map(|a| (l, a))) else {
                self.distrust();
                return FrontState::Failed { old_secret: Some(old.secret.to_string()) };
            };
            // The port we held is NOT let go: its loop is parked (refusing everything) for the
            // life of the process.
            *self.cell.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(Snapshot::fresh(addr.port()));
            self.shared.closed.send_replace(false);
            let previous = std::mem::replace(&mut *self.task.lock().unwrap_or_else(|e| e.into_inner()),
                                             spawn_loop(listener, self.cell.clone(), self.shared.clone()));
            slot.park(old.port, previous);
            return FrontState::Relistened { old_secret: old.secret.to_string(), base_url: self.base_url() };
        }
        self.set_verified(false);
        // Our listener is gone, or looks it (refused, or its accept loop ended). A loop that ended
        // holds nothing: let go of what is left. Otherwise the same port is tried while the old
        // loop is still there: binding it proves the OS took our socket (nothing is held any
        // more); not being able to means it IS held — the old listener is kept (parked) and the
        // front moves, or fails when no more can be parked.
        let ended = self.is_closed() || self.task.lock().unwrap_or_else(|e| e.into_inner()).is_finished();
        if ended {
            self.task.lock().unwrap_or_else(|e| e.into_inner()).abort();
            tokio::task::yield_now().await;
        }
        let bind = |port: u16| if self.shared.fail_binds.load(SeqCst) { Err(std::io::Error::other("test")) } else { listen_on(port) };
        let mut slot = None;
        let listener = match bind(old.port) {
            Ok(l) => Ok(l),
            Err(e) if ended => { let _ = e; bind(0) }
            Err(e) => match self.park_slot() {
                Some(r) => { slot = Some(r); bind(0) }
                None => Err(e),
            },
        };
        let Some(addr) = listener.as_ref().ok().and_then(|l| l.local_addr().ok()) else {
            self.distrust();
            return FrontState::Failed { old_secret: None };
        };
        let Ok(listener) = listener else { unreachable!() };
        *self.cell.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(Snapshot::fresh(addr.port()));
        self.shared.closed.send_replace(false);
        let previous = std::mem::replace(&mut *self.task.lock().unwrap_or_else(|e| e.into_inner()),
                                         spawn_loop(listener, self.cell.clone(), self.shared.clone()));
        match slot {
            Some(slot) => slot.park(old.port, previous),
            None => previous.abort(),
        }
        FrontState::Relistened { old_secret: old.secret.to_string(), base_url: self.base_url() }
    }

    fn park_slot(&self) -> Option<ParkSlot> {
        if self.shared.no_park.load(std::sync::atomic::Ordering::SeqCst) { return None; }
        ParkSlot::reserve(&PARKED)
    }

    /// Challenge the port with growing budgets until it proves ours. Ours: verified (the front
    /// forwards). NotOurs at any try: that. Slow every time: Slow — and from the first slow try
    /// until a later Ours the front is UNVERIFIED: it forwards nothing and injects nothing.
    pub async fn verify(&self, budgets: &[Duration]) -> Challenge {
        if self.must_rekey() { return Challenge::NotOurs; }
        for budget in budgets {
            let (verdict, generation) = self.challenge_gen(*budget).await;
            match verdict {
                Challenge::Ours => {
                    self.apply_verdict(generation, true, false);
                    return if self.is_verified() { Challenge::Ours } else { Challenge::NotOurs };
                }
                Challenge::NotOurs => { self.apply_verdict(generation, false, true); return Challenge::NotOurs; }
                Challenge::Slow => self.apply_verdict(generation, false, false),
            }
        }
        Challenge::Slow
    }

    /// Like [`Self::verify`] but changes nothing: what a health check may ask concurrently with
    /// a re-listen without racing it.
    pub async fn probe(&self, budgets: &[Duration]) -> Challenge {
        if self.must_rekey() || !self.is_verified() { return Challenge::NotOurs; }
        for budget in budgets {
            match self.challenge(*budget).await {
                Challenge::Slow => continue,
                other => return other,
            }
        }
        Challenge::Slow
    }

    /// Is the front verified (forwarding)?
    pub fn is_verified(&self) -> bool {
        self.snap().verified
    }

    /// Tests: the handler stops proving challenges (and answers them late).
    #[doc(hidden)]
    pub fn no_park_for_test(&self) {
        self.shared.no_park.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    #[doc(hidden)]
    pub fn mute_challenges_for_test(&self, mute: bool) {
        self.shared.mute_challenges.store(mute, std::sync::atomic::Ordering::SeqCst);
    }

    /// Tests: every bind fails.
    #[doc(hidden)]
    pub fn fail_binds_for_test(&self, fail: bool) {
        self.shared.fail_binds.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Tests: take the listener away the way the OS does on a suspended iOS app.
    #[doc(hidden)]
    pub fn drop_listener_for_test(&self) {
        self.task.lock().unwrap_or_else(|e| e.into_inner()).abort();
    }

    /// The listener failed for good (or its task ended).
    pub fn is_closed(&self) -> bool {
        *self.shared.closed.borrow() || self.task.lock().unwrap_or_else(|e| e.into_inner()).is_finished()
    }

    /// Stop serving: the listener goes (and with it the port) and everyone waiting in
    /// [`Self::closed`] is woken. Called when the session is let go.
    pub fn shutdown(&self) {
        self.shut.store(true, std::sync::atomic::Ordering::SeqCst);
        self.set_verified(false);
        self.shared.closed.send_replace(true);
        self.task.lock().unwrap_or_else(|e| e.into_inner()).abort();
    }

    /// A receiver that turns `true` when the listener failed for good or the front was shut down.
    pub fn closed_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shared.closed.subscribe()
    }

    /// Resolves when the listener has failed for good (at once if it already has).
    pub async fn closed(&self) {
        let mut rx = self.shared.closed.subscribe();
        let _ = rx.wait_for(|closed| *closed).await;
    }

    /// Does a request sent to this front's port reach THIS front? (One snapshot: port + secret.)
    pub async fn challenge(&self, timeout: Duration) -> Challenge {
        self.challenge_gen(timeout).await.0
    }

    /// The verdict, and the snapshot generation it is about.
    async fn challenge_gen(&self, timeout: Duration) -> (Challenge, u64) {
        let snap = self.snap();
        if self.is_closed() {
            return (Challenge::NotOurs, snap.generation);
        }
        (challenge_port(snap.port, &snap.secret, &self.shared.seen, timeout).await, snap.generation)
    }

    /// Base URL for the skwod API — a drop-in for the `https://…` server URL.
    pub fn base_url(&self) -> String {
        self.snap().base_url()
    }

    /// URL to give the LiveKit SDK (it appends `/rtc?...` itself).
    pub fn livekit_url(&self) -> String {
        let snap = self.snap();
        format!("ws://127.0.0.1:{}/{}/lk", snap.port, snap.secret)
    }

    /// How many signaling sockets the host's LiveKit has accepted through this front.
    pub fn livekit_accepted(&self) -> u64 {
        self.shared.livekit_accepted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The front's secret (the last path segment of its base URL).
    pub fn secret(&self) -> String {
        self.snap().secret.to_string()
    }

    /// Reads the CURRENT secret later (a re-key changes it) without holding the front.
    pub fn secret_reader(&self) -> impl Fn() -> String + Send + Sync + 'static {
        let cell = Arc::downgrade(&self.cell);
        move || cell.upgrade().map(|c| c.read().unwrap_or_else(|e| e.into_inner()).secret.to_string()).unwrap_or_default()
    }

    pub fn port(&self) -> u16 {
        self.snap().port
    }

    /// (Port, secret) of one snapshot.
    pub fn identity(&self) -> (u16, String) {
        let snap = self.snap();
        (snap.port, snap.secret.to_string())
    }
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.task.lock().unwrap_or_else(|e| e.into_inner()).abort();
    }
}

/// Listen on `127.0.0.1:port` (0: any), with SO_REUSEADDR so the port a reclaimed listener held
/// can be bound again at once.
fn listen_on(port: u16) -> std::io::Result<TcpListener> {
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    socket.bind(std::net::SocketAddr::from(([127, 0, 0, 1], port)))?;
    socket.listen(1024)
}

/// The accept loop of a front's listener. Every connection and every request is checked
/// against the snapshot current AT THAT MOMENT (a re-key cuts off the old secret at once).
async fn accept_loop(listener: TcpListener, cell: Arc<std::sync::RwLock<Arc<Snapshot>>>, shared: Arc<Shared>, loop_id: u64) {
    let mut failures = 0u32;
    let mut current = shared.current_loop.subscribe();
    loop {
        if *current.borrow_and_update() != loop_id {
            // The front moved away: from here on only the listener is kept.
            drop((cell, shared, current));
            return parked_loop(listener).await;
        }
        let accepted = tokio::select! {
            a = listener.accept() => a,
            _ = current.changed() => continue,
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => {
                failures = 0;
                accepted
            }
            Err(e) => match classify_accept_error(&e) {
                AcceptFailure::Transient => {
                    failures = failures.saturating_add(1);
                    tokio::time::sleep(accept_backoff(failures)).await;
                    continue;
                }
                AcceptFailure::Fatal => {
                    // Say so at once (`closed`): the app has the front listen again
                    // (`ensure_listening`). The dead listener is held until then.
                    if *shared.current_loop.borrow() == loop_id { shared.closed.send_replace(true); }
                    let _hold = listener;
                    std::future::pending::<()>().await;
                    return;
                }
            },
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        // Parked (the front moved away): the port stays held, every connection refused and closed.
        if *current.borrow() != loop_id {
            refuse_parked(tcp);
            continue;
        }
        let own_challenge = tcp.local_addr().is_ok_and(|local| take_challenger(peer, local));
        let (cell, shared2) = (cell.clone(), shared.clone());
        let sending = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = sending.clone();
        let (go, ready) = tokio::sync::oneshot::channel::<u64>();
        let task = tokio::spawn(async move {
            let shared = shared2;
            // Build 51 (M2): a connection must name the secret in its first request line within
            // FIRST_REQUEST_DEADLINE, or it is closed — and only one that did counts against
            // the cap. While it has not, it is one of at most MAX_PREAUTH; once its first line
            // is in, it is never evicted.
            let mut tcp = tcp;
            let Ok(id) = ready.await else { return };
            let secret_len = cell.read().unwrap_or_else(|e| e.into_inner()).secret.len();
            // (This process's own challenge always has the full time: cut short under pressure it
            // would read as a port that is not ours.)
            let deadline = if own_challenge { FIRST_REQUEST_DEADLINE } else { shared.preauth.deadline() };
            let head = first_line(&mut tcp, deadline, &flag, secret_len).await;
            shared.preauth.done(id);
            // The whole secret, once, in constant time; every failure answered the same way.
            let prefix = cell.read().unwrap_or_else(|e| e.into_inner()).prefix.clone();
            let Some(head) = head.filter(|h| first_line_names_secret(h, &prefix)) else {
                use tokio::io::AsyncWriteExt;
                let _ = tcp.write_all(REFUSED).await;
                return;
            };
            let Ok(permit) = shared.permits.clone().acquire_owned().await else { return };
            let _permit = permit;
            let tcp = Prefixed::new(head, tcp);
            let svc = hyper::service::service_fn(move |req| {
                let snap = cell.read().unwrap_or_else(|e| e.into_inner()).clone();
                let shared = shared.clone();
                let sec = snap.secret.clone();
                let tokens = shared.tokens.clone();
                let token = move |credential: &str| tokens(&sec, credential);
                handle(shared.upstream.clone(), snap, shared, token, req)
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(tcp), svc)
                .with_upgrades()
                .await;
        });
        if own_challenge {
            // This process's own liveness challenge: never queued, never evicted.
            let _ = go.send(u64::MAX);
        } else if let Some(id) = shared.preauth.admit(task.abort_handle(), sending) {
            let _ = go.send(id);
        }
    }
}

/// Build 51 (bearer and passwords off loopback): one request of the core's own API client,
/// straight over a fresh upstream stream — never through the loopback port. Stamped with proof
/// of work exactly like the front stamps first-contact requests. Returns (status, body) with the
/// body capped at `max_body`; None when there was no answer within `timeout`.
pub async fn direct_request(upstream: Arc<dyn Upstream>, method: &str, path: &str, headers: Vec<(String, String)>,
                            body: Option<Vec<u8>>, max_body: usize, timeout: Duration) -> Option<(u16, Vec<u8>)> {
    let method = hyper::Method::from_bytes(method.as_bytes()).ok()?;
    let ask = async {
        let body = Bytes::from(body.unwrap_or_default());
        let mut base = Request::new(());
        *base.method_mut() = method.clone();
        *base.uri_mut() = path.parse().ok()?;
        let h = base.headers_mut();
        h.insert(hyper::header::HOST, HeaderValue::from_static("skwod"));
        h.insert(CONNECTION, HeaderValue::from_static("close"));
        for (k, v) in &headers {
            if let (Ok(k), Ok(v)) = (hyper::header::HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) { h.append(k, v); }
        }
        h.remove(crate::pow::POW_HEADER);
        let build = |stamp: Option<HeaderValue>| {
            let mut r = Request::new(http_body_util::Full::new(body.clone()).map_err(|never| match never {}).boxed());
            *r.method_mut() = base.method().clone();
            *r.uri_mut() = base.uri().clone();
            *r.headers_mut() = base.headers().clone();
            if let Some(s) = stamp { r.headers_mut().insert(crate::pow::POW_HEADER, s); }
            r
        };
        let pow = upstream.pow_identity().filter(|_| needs_pow(&method, path));
        let mut res = match pow {
            None => forward(&upstream, false, build(None)).await?,
            Some(ids) => {
                let first = stamp(ids, crate::pow::current_window(), crate::pow::POW_BITS).await?;
                let res = forward(&upstream, false, build(Some(first))).await?;
                let header = |name: &str| (res.status() == StatusCode::PRECONDITION_REQUIRED)
                    .then(|| res.headers().get(name).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok())).flatten();
                match header(crate::pow::POW_WINDOW_HEADER) {
                    Some(window) => {
                        let bits = header(crate::pow::POW_BITS_HEADER).map(|b| b.clamp(crate::pow::POW_BITS as u64, crate::pow::MAX_POW_BITS as u64) as u32);
                        let again = stamp(ids, window, bits.unwrap_or(crate::pow::POW_BITS)).await?;
                        forward(&upstream, false, build(Some(again))).await?
                    }
                    None => res,
                }
            }
        };
        let status = res.status().as_u16();
        let collected = http_body_util::Limited::new(res.body_mut(), max_body).collect().await.ok()?.to_bytes();
        Some((status, collected.to_vec()))
    };
    tokio::time::timeout(timeout, ask).await.ok().flatten()
}

/// Build 51: one request with the session `token`, straight over a fresh upstream stream — never
/// through the loopback port (logout, push unregister: what must reach the host even while the
/// app is tearing its clients down). Returns the status, or 0 when it did not get one in time.
pub async fn upstream_request(upstream: Arc<dyn Upstream>, method: &str, path: &str, token: &str, body: Option<String>, timeout: Duration) -> u16 {
    let Ok(method) = hyper::Method::from_bytes(method.as_bytes()) else { return 0 };
    let ask = async {
        let io = upstream.open_http().await.ok()?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(io)).await.ok()?;
        tokio::spawn(conn);
        let has_body = body.is_some();
        let mut req = Request::new(http_body_util::Full::new(Bytes::from(body.unwrap_or_default())).map_err(|never| match never {}).boxed());
        *req.method_mut() = method;
        *req.uri_mut() = path.parse().ok()?;
        let h = req.headers_mut();
        h.insert(hyper::header::HOST, HeaderValue::from_static("skwod"));
        h.insert(CONNECTION, HeaderValue::from_static("close"));
        h.insert(hyper::header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}")).ok()?);
        if has_body { h.insert(hyper::header::CONTENT_TYPE, HeaderValue::from_static("application/json")); }
        Some(sender.send_request(req).await.ok()?.status().as_u16())
    };
    tokio::time::timeout(timeout, ask).await.ok().flatten().unwrap_or(0)
}

/// `GET /health` straight over a fresh upstream stream (not through any loopback port): does the
/// HOST answer, within `timeout`? Nothing but a 200 counts.
pub async fn upstream_answers(upstream: Arc<dyn Upstream>, timeout: Duration) -> bool {
    let ask = async {
        let io = upstream.open_http().await.ok()?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Body>(TokioIo::new(io)).await.ok()?;
        tokio::spawn(conn);
        let mut req = Request::new(Empty::<Bytes>::new().map_err(|never| match never {}).boxed());
        *req.uri_mut() = "/health".parse().ok()?;
        req.headers_mut().insert(hyper::header::HOST, HeaderValue::from_static("skwod"));
        req.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
        Some(sender.send_request(req).await.ok()?.status() == StatusCode::OK)
    };
    tokio::time::timeout(timeout, ask).await.ok().flatten().unwrap_or(false)
}

/// Send a liveness challenge to `port` and check, in process, that `seen` recorded it.
pub(crate) async fn challenge_port(port: u16, secret: &str, seen: &Nonces, timeout: Duration) -> Challenge {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    // NotOurs only on a refused connection or a REAL answer without our nonce; anything a local
    // process can cause cheaply (an EOF, a reset, an empty answer, no answer) is Slow — retried,
    // never a verdict on its own.
    let ask = async {
        // Our local port first, registered, THEN the connection (`CHALLENGERS`).
        let socket = tokio::net::TcpSocket::new_v4().ok()?;
        socket.bind(([127, 0, 0, 1], 0).into()).ok()?;
        let _tag = ChallengerTag::new(socket.local_addr().ok()?, ([127, 0, 0, 1], port).into());
        let mut tcp = match socket.connect(([127, 0, 0, 1], port).into()).await {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Some(false),
            Err(_) => return None,
        };
        let req = format!("GET /{secret}{CHALLENGE_PATH}{nonce} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n");
        if tcp.write_all(req.as_bytes()).await.is_err() { return None }
        // Only the first bytes of the answer are waited for (the handler records the nonce
        // before it answers), and never more than 4 KiB are read: whatever listens there
        // cannot make this read grow or last.
        let mut first = [0u8; 4096];
        match (&mut tcp).take(4096).read(&mut first).await {
            Ok(n) if n > 0 => Some(true),
            _ => None,
        }
    };
    match tokio::time::timeout(timeout, ask).await {
        Err(_) | Ok(None) => if seen.take(&nonce) { Challenge::Ours } else { Challenge::Slow },
        Ok(Some(false)) => Challenge::NotOurs,
        Ok(Some(true)) => if seen.take(&nonce) { Challenge::Ours } else { Challenge::NotOurs },
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
    // The front's own word (`STALE_CREDENTIAL`): never a host's.
    while headers.remove(FRONT_REFUSAL_HEADER).is_some() {}
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

async fn handle(
    upstream: Arc<dyn Upstream>,
    snap: Arc<Snapshot>,
    shared: Arc<Shared>,
    token: impl FnOnce(&str) -> Option<String>,
    mut req: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    let Some(rest) = strip_secret(req.uri().path(), &snap.prefix) else {
        // Not under the secret: refused, and the connection is closed (never kept alive for
        // whoever is guessing).
        let mut res = status(StatusCode::NOT_FOUND);
        res.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
        return Ok(res);
    };
    // A liveness challenge from this process (`LocalProxy::challenge`): noted, never forwarded.
    if let Some(nonce) = rest.strip_prefix(CHALLENGE_PATH) {
        if nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            if shared.mute_challenges.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return Ok(status(StatusCode::NO_CONTENT));
            }
            shared.seen.note(nonce);
            return Ok(status(StatusCode::NO_CONTENT));
        }
        return Ok(status(StatusCode::NOT_FOUND));
    }
    // Not proved ours (yet): nothing is forwarded and no token is injected.
    if !snap.verified {
        let mut res = status(StatusCode::SERVICE_UNAVAILABLE);
        res.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
        return Ok(res);
    }
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
    // The token is the core's, put in here and only here (never by the app, never on loopback).
    if !livekit {
        if !authorize(req.headers_mut(), token) {
            let mut res = status(StatusCode::SERVICE_UNAVAILABLE);
            res.headers_mut().insert(FRONT_REFUSAL_HEADER, HeaderValue::from_static(STALE_CREDENTIAL));
            return Ok(res);
        }
    } else {
        while req.headers_mut().remove(hyper::header::AUTHORIZATION).is_some() {}
    }
    let wants_upgrade = req.headers().contains_key(UPGRADE);
    let downstream = wants_upgrade.then(|| hyper::upgrade::on(&mut req));
    if !wants_upgrade {
        // One request per stream: tell the far side not to wait for another.
        req.headers_mut().insert(CONNECTION, HeaderValue::from_static("close"));
    }

    // Unauthenticated first contact (signup/login/QR pair request): attach a proof-of-work stamp. The app never
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
    sanitize_response_headers(res.headers_mut(), &snap.prefix);
    if res.status() == StatusCode::SWITCHING_PROTOCOLS {
        if livekit {
            shared.livekit_accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Build 51 (B): the placeholder becomes the session token; anything else a client sends as
    /// Authorization is dropped; no Authorization stays none (sealed-sender deposits).
    #[test]
    fn the_front_injects_the_token_only_for_the_placeholder() {
        use hyper::header::AUTHORIZATION;
        let cred = format!("front-{}", "a".repeat(32));
        let run = |sent: Option<&str>| {
            let mut h = hyper::HeaderMap::new();
            if let Some(s) = sent { h.insert(AUTHORIZATION, HeaderValue::from_str(s).unwrap()); }
            let c = cred.clone();
            authorize(&mut h, move |got: &str| (got == c).then(|| "t0k".to_string()))
                .then(|| h.get(AUTHORIZATION).map(|v| v.to_str().unwrap().to_string()))
        };
        assert_eq!(run(Some(&format!("Bearer {cred}"))), Some(Some("Bearer t0k".into())));
        assert_eq!(run(None), Some(None), "sealed sender: forwarded, nothing is ever added");
        assert_eq!(run(Some("Bearer someone-elses-token")), None, "a client's own token: refused");
        assert_eq!(run(Some(&format!("Bearer front-{}", "b".repeat(32)))), None, "an unknown credential: refused");
        assert_eq!(run(Some("Basic Zm9vOmJhcg==")), None);
    }

    #[test]
    fn running_out_of_descriptors_is_survived_not_fatal() {
        for code in [24 /* EMFILE */, 23 /* ENFILE */, 12 /* ENOMEM */] {
            assert_eq!(classify_accept_error(&std::io::Error::from_raw_os_error(code)), AcceptFailure::Transient, "{code}");
        }
        assert_eq!(classify_accept_error(&std::io::Error::from(std::io::ErrorKind::ConnectionAborted)), AcceptFailure::Transient);
        // EBADF / ENOTSOCK / EINVAL: the listening socket itself is gone.
        for code in [9, 38, 22] {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            let code = if code == 38 { 88 } else { code };
            assert_eq!(classify_accept_error(&std::io::Error::from_raw_os_error(code)), AcceptFailure::Fatal, "{code}");
        }
        assert!(accept_backoff(1) < accept_backoff(5));
        assert_eq!(accept_backoff(40), Duration::from_secs(1), "backs off, bounded, forever");
    }

    /// Something else on a port answering "204 No Content" to anything is not our proxy.
    #[tokio::test]
    async fn the_liveness_check_rejects_an_impostor_listener() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let impostor = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = impostor.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = impostor.accept().await {
                let mut buf = [0u8; 1024];
                let _ = tcp.read(&mut buf).await;
                let _ = tcp.write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n").await;
            }
        });
        let seen = Nonces::default();
        assert_eq!(challenge_port(port, &"0".repeat(32), &seen, Duration::from_secs(2)).await, Challenge::NotOurs);
        // An impostor that never stops talking neither grows the read nor holds it open.
        let talker = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let talker_port = talker.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = talker.accept().await {
                tokio::spawn(async move {
                    let chunk = vec![b'x'; 64 * 1024];
                    while tcp.write_all(&chunk).await.is_ok() {}
                });
            }
        });
        let started = std::time::Instant::now();
        assert_eq!(challenge_port(talker_port, &"0".repeat(32), &seen, Duration::from_secs(2)).await, Challenge::NotOurs);
        assert!(started.elapsed() < Duration::from_secs(1), "one capped read, not the whole stream: {:?}", started.elapsed());
        // A port nobody listens on is not alive either.
        let free = TcpListener::bind(("127.0.0.1", 0)).await.unwrap().local_addr().unwrap().port();
        assert_eq!(challenge_port(free, &"0".repeat(32), &seen, Duration::from_secs(2)).await, Challenge::NotOurs);
        // One that accepts and closes at once (EOF) is SLOW too: cheap to cause, no verdict.
        let closer = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let closer_port = closer.local_addr().unwrap().port();
        tokio::spawn(async move { while let Ok((tcp, _)) = closer.accept().await { drop(tcp); } });
        assert_eq!(challenge_port(closer_port, &"0".repeat(32), &seen, Duration::from_millis(500)).await, Challenge::Slow);
        // A listener that accepts and never answers is SLOW, not "not ours".
        let mute = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let mute_port = mute.local_addr().unwrap().port();
        tokio::spawn(async move { let mut held = Vec::new(); while let Ok((tcp, _)) = mute.accept().await { held.push(tcp); } });
        assert_eq!(challenge_port(mute_port, &"0".repeat(32), &seen, Duration::from_millis(500)).await, Challenge::Slow);
    }

    /// Review: a connection that is already sending its first line is never evicted by a flood
    /// of idle ones, and is served when it finishes.
    #[tokio::test]
    async fn a_connection_that_is_sending_is_not_evicted() {
        struct Never;
        impl Upstream for Never {
            fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
            fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
        }
        let front = LocalProxy::start(Arc::new(Never)).await.unwrap();
        let port = front.port();
        let mut app = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        app.write_all(format!("GET /{}/api/x HTTP/1.1", front.secret()).as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut idle = Vec::new();
        for _ in 0..(MAX_PREAUTH * 2) { idle.push(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap()); }
        tokio::time::sleep(Duration::from_millis(200)).await;
        app.write_all(b"\r\nhost: x\r\nconnection: close\r\n\r\n").await.unwrap();
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), app.read_to_string(&mut out)).await;
        assert!(out.starts_with("HTTP/1.1 502"), "served (forward attempted): {out}");
    }

    /// Review: what protects a connection (and when it is closed early) depends only on syntax,
    /// never on the secret's value — a right and a wrong prefix behave the same until the line
    /// is complete.
    #[test]
    fn early_rules_never_depend_on_the_secret() {
        assert!(valid_prefix(b"GE", 32));
        assert!(valid_prefix(b"GET /0123", 32));
        assert!(valid_prefix(b"GET /ffff", 32), "any hex is as good as the right hex");
        assert!(valid_prefix(format!("POST /{}/api", "a".repeat(32)).as_bytes(), 32));
        assert!(!valid_prefix(b"GET /x", 32), "not the charset");
        assert!(!valid_prefix(b"get /0123", 32));
        assert!(!valid_prefix(b"GET /0123\r\n", 32), "a line end before the secret is complete");
        assert!(!valid_prefix(format!("GET /{}X", "a".repeat(32)).as_bytes(), 32));
        assert!(!valid_prefix(b"\x16\x03\x01", 32));
    }

    /// Review: a connection with the right first bytes of the secret and one with wrong ones are
    /// indistinguishable until their lines are complete — both still open — and both refused
    /// identically if the rest is wrong.
    #[tokio::test]
    async fn a_right_and_a_wrong_prefix_look_the_same() {
        struct Never;
        impl Upstream for Never {
            fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
            fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
        }
        let front = LocalProxy::start(Arc::new(Never)).await.unwrap();
        let secret = front.secret();
        let wrong_first = if secret.starts_with('0') { "1" } else { "0" };
        let mut right = tokio::net::TcpStream::connect(("127.0.0.1", front.port())).await.unwrap();
        let mut wrong = tokio::net::TcpStream::connect(("127.0.0.1", front.port())).await.unwrap();
        right.write_all(format!("GET /{}", &secret[..8]).as_bytes()).await.unwrap();
        wrong.write_all(format!("GET /{wrong_first}{}", &secret[1..8]).as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut b = [0u8; 1];
        for c in [&mut right, &mut wrong] {
            assert!(tokio::time::timeout(Duration::from_millis(100), c.read(&mut b)).await.is_err(), "both still open, nothing answered");
        }
        let finish = format!("{} HTTP/1.1\r\nhost: x\r\n\r\n", "f".repeat(24));
        let (mut out_r, mut out_w) = (String::new(), String::new());
        right.write_all(finish.as_bytes()).await.unwrap();
        wrong.write_all(finish.as_bytes()).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), right.read_to_string(&mut out_r)).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), wrong.read_to_string(&mut out_w)).await;
        assert_eq!(out_r, out_w, "the same refusal for both");
        assert!(out_r.starts_with("HTTP/1.1 404"));
    }

    /// Review: when full, idle ones go first, then the oldest still-incomplete sender; a
    /// newcomer always gets in.
    #[tokio::test]
    async fn eviction_takes_idle_first_then_the_oldest_sender() {
        let q = PreAuth::default();
        let mut handles = Vec::new();
        let mut flags = Vec::new();
        for i in 0..MAX_PREAUTH {
            let t = tokio::spawn(std::future::pending::<()>());
            let f = Arc::new(std::sync::atomic::AtomicBool::new(i % 2 == 0));
            q.admit(t.abort_handle(), f.clone()).unwrap();
            handles.push(t); flags.push(f);
        }
        let t = tokio::spawn(std::future::pending::<()>());
        let newcomer = Arc::new(std::sync::atomic::AtomicBool::new(false));
        assert!(q.admit(t.abort_handle(), newcomer.clone()).is_some(), "the newcomer gets in");
        flags.push(newcomer);
        tokio::task::yield_now().await;
        assert!(handles[1].is_finished(), "the oldest IDLE one was evicted");
        assert!(!handles[0].is_finished(), "a sender is kept while an idle one can go");
        assert!(q.deadline() < FIRST_REQUEST_DEADLINE, "under pressure: a shorter deadline");
        for f in &flags { f.store(true, std::sync::atomic::Ordering::SeqCst); }
        let t2 = tokio::spawn(std::future::pending::<()>());
        assert!(q.admit(t2.abort_handle(), Arc::new(Default::default())).is_some());
        tokio::task::yield_now().await;
        assert!(handles[0].is_finished(), "all sending: the oldest incomplete sender goes");
    }

    /// Review: the exemption is the exact (peer, front) pair, once.
    #[test]
    fn a_challenge_is_matched_exactly_and_once() {
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let front: std::net::SocketAddr = "127.0.0.1:2".parse().unwrap();
        let other: std::net::SocketAddr = "127.0.0.1:3".parse().unwrap();
        let tag = ChallengerTag::new(peer, front);
        assert!(!take_challenger(peer, other), "another front's port");
        assert!(!take_challenger(other, front), "another peer");
        assert!(!take_challenger("127.0.0.2:1".parse().unwrap(), front), "the same port, another address");
        assert!(take_challenger(peer, front));
        assert!(!take_challenger(peer, front), "single use");
        drop(tag);
        let tag = ChallengerTag::new(peer, front);
        drop(tag);
        assert!(!take_challenger(peer, front), "gone when the challenge ends");
    }

    /// Review (M1): a flood of idle connections never pushes out the in-process challenge.
    #[tokio::test]
    async fn the_challenge_proves_the_front_under_a_flood() {
        struct Never;
        impl Upstream for Never {
            fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
            fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
        }
        let front = LocalProxy::start(Arc::new(Never)).await.unwrap();
        let port = front.port();
        let flood = tokio::spawn(async move {
            let mut held = Vec::new();
            for _ in 0..(MAX_PREAUTH * 4) {
                if let Ok(c) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await { held.push(c); }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(held);
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(front.probe(&[Duration::from_millis(1_500), Duration::from_secs(3)]).await, Challenge::Ours);
        flood.abort();
    }

    /// Tests that use the process-wide parking state run one at a time.
    static PARK_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Review: what may be parked is bounded; an unused reservation is given back; a parked loop
    /// whose port nothing holds any more (the OS took its socket) makes room, a held one never does.
    #[tokio::test]
    async fn parking_is_bounded() {
        let lot: &'static _ = Box::leak(Box::new(std::sync::Mutex::new(Parked { loops: Vec::new(), reserved: 0 })));
        let mut held_ports = Vec::new();
        for _ in 0..MAX_PARKED - 1 {
            let l = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = l.local_addr().unwrap().port();
            held_ports.push(port);
            ParkSlot::reserve(lot).expect("room").park(port, tokio::spawn(parked_loop(l)));
        }
        let last = ParkSlot::reserve(lot).expect("room for one more");
        assert!(ParkSlot::reserve(lot).is_none(), "full: live listeners are never let go to make room");
        for port in &held_ports { assert!(std::net::TcpListener::bind(("127.0.0.1", *port)).is_err(), "still held"); }
        drop(last);
        let dead_port = { let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap(); l.local_addr().unwrap().port() };
        ParkSlot::reserve(lot).expect("given back").park(dead_port, tokio::spawn(std::future::pending()));
        assert!(ParkSlot::reserve(lot).is_some(), "the one that holds nothing was reaped");
    }

    /// Review: no room to park: a front that is not proved ours does NOT move (its listener would
    /// have to be let go); it stays where it is, distrusted, forwarding nothing.
    #[tokio::test]
    async fn without_room_to_park_the_front_fails_instead_of_moving() {
        struct Never;
        impl Upstream for Never {
            fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
            fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
        }
        let front = LocalProxy::start(Arc::new(Never)).await.unwrap();
        front.no_park_for_test();
        let port = front.port();
        front.mute_challenges_for_test(true);
        assert!(matches!(front.relisten(true).await, FrontState::Failed { old_secret: Some(_) }));
        assert_eq!(front.port(), port, "not moved");
        assert!(!front.is_verified(), "distrusted");
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err(), "still held");
    }

    /// Review: a flood of a parked port is dropped at once past the shared bound.
    #[tokio::test]
    async fn a_parked_port_holds_nothing_for_a_flood() {
        let _one = PARK_TESTS.lock().await;
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let parked = tokio::spawn(parked_loop(listener));
        let _all = PARKED_PERMITS.acquire_many(8).await.unwrap();
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), c.read_to_end(&mut out)).await.expect("closed at once");
        assert!(out.is_empty(), "no permit: dropped without an answer");
        parked.abort();
    }

    /// Review (M1): a port the front moves away from is never let go: it stays held for the life
    /// of the process and refuses every connection the same way (it cannot be bound by anyone).
    #[tokio::test]
    async fn a_port_moved_away_from_stays_held_and_refuses() {
        let _one = PARK_TESTS.lock().await;
        struct Never;
        impl Upstream for Never {
            fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
            fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
        }
        let front = LocalProxy::start(Arc::new(Never)).await.unwrap();
        let old_port = front.port();
        let old_secret = front.secret();
        front.mute_challenges_for_test(true);
        assert!(matches!(front.relisten(true).await, FrontState::Relistened { .. }));
        front.mute_challenges_for_test(false);
        assert_ne!(front.port(), old_port, "not proved in place: moved to a fresh port");
        assert!(std::net::TcpListener::bind(("127.0.0.1", old_port)).is_err(), "the old port is still held");
        let _ = old_secret;
        // Nothing is sent: a parked port answers without reading or waiting.
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", old_port)).await.expect("held: it accepts");
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), c.read_to_string(&mut out)).await;
        assert!(out.starts_with("HTTP/1.1 404"), "parked: refused like any wrong guess: {out}");
        assert!(!front.is_closed(), "the parked loop never speaks for the front");
        assert_eq!(front.probe(&[Duration::from_millis(1_500), Duration::from_secs(3)]).await, Challenge::Ours);
    }

    /// Review: a verdict for an older snapshot is not applied; a probe changes nothing; once
    /// distrusted, no challenge restores trust — only a re-listen does.
    #[tokio::test]
    async fn verdicts_apply_only_to_their_snapshot_and_distrust_sticks() {
        struct Never;
        impl Upstream for Never {
            fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
            fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
        }
        let front = LocalProxy::start(Arc::new(Never)).await.unwrap();
        let stale = front.snap().generation;
        assert!(matches!(front.relisten(true).await, FrontState::Relistened { .. }));
        front.apply_verdict(stale, false, true);
        assert!(front.is_verified() && !front.must_rekey(), "a verdict about the old snapshot changed nothing");
        front.mute_challenges_for_test(true);
        assert_eq!(front.probe(&[Duration::from_millis(300)]).await, Challenge::Slow);
        assert!(front.is_verified(), "a probe changes nothing");
        front.mute_challenges_for_test(false);
        front.distrust();
        assert!(front.must_rekey() && !front.is_verified());
        assert_eq!(front.verify(&[Duration::from_secs(2)]).await, Challenge::NotOurs, "no challenge restores trust");
        assert!(!front.is_verified());
        assert!(matches!(front.relisten(true).await, FrontState::Relistened { .. }));
        assert!(front.is_verified() && !front.must_rekey(), "a successful re-listen does");
    }

    /// E: overlapping challenges never overwrite each other's proof.
    #[test]
    fn overlapping_nonces_are_all_kept() {
        let n = Nonces::default();
        n.note("a"); n.note("b");
        assert!(n.take("a") && n.take("b"));
        assert!(!n.take("a"), "each proves one challenge");
    }

    /// D: only a first line under the secret gets in.
    #[test]
    fn the_first_line_must_name_the_secret() {
        let p = "/0123456789abcdef";
        assert!(first_line_names_secret(b"GET /0123456789abcdef/api/x HTTP/1.1\r\n", p));
        assert!(first_line_names_secret(b"POST /0123456789abcdef?x=1 HTTP/1.1\r\nhost", p));
        assert!(!first_line_names_secret(b"GET /api/x HTTP/1.1\r\n", p));
        assert!(!first_line_names_secret(b"GET /0123456789abcdefX HTTP/1.1\r\n", p));
        assert!(!first_line_names_secret(b"garbage\r\n", p));
    }

    /// D (M2): idle and guessing connections are closed and never take the slots of the app's.
    #[tokio::test]
    async fn idle_and_guessing_connections_cannot_starve_the_front() {
        struct Never;
        impl Upstream for Never {
            fn open_http(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
            fn open_livekit(self: Arc<Self>) -> UpstreamFuture<Box<dyn Io>> { Box::pin(async { Err(NetError::Unreachable("test".into())) }) }
        }
        let front = LocalProxy::start(Arc::new(Never)).await.unwrap();
        let port = front.port();
        // Far more idle connections than the cap, and a guesser.
        let mut idle = Vec::new();
        for _ in 0..(MAX_CONNECTIONS + 50) { idle.push(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap()); }
        let mut guess = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        guess.write_all(b"GET /api/x HTTP/1.1\r\nhost: x\r\n\r\n").await.unwrap();
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), guess.read_to_string(&mut out)).await;
        assert!(out.starts_with("HTTP/1.1 404") && out.to_lowercase().contains("connection: close"), "every refusal the same: {out}");
        // The app still gets through at once (its liveness challenge reaches the handler).
        assert_eq!(front.challenge(Duration::from_secs(2)).await, Challenge::Ours);
        // And an authenticated request still gets served (a 503 from the stub upstream path is a
        // FORWARD attempt: it got past the gate, through the pre-auth flood).
        let mut app = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        app.write_all(format!("GET /{}/api/x HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n", front.secret()).as_bytes()).await.unwrap();
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), app.read_to_string(&mut out)).await;
        assert!(out.starts_with("HTTP/1.1 502"), "forwarded (upstream refused): {out}");
        // And the idle ones are closed after the first-request deadline.
        let mut one = idle.pop().unwrap();
        let mut rest = Vec::new();
        let closed = tokio::time::timeout(FIRST_REQUEST_DEADLINE + Duration::from_secs(2), one.read_to_end(&mut rest)).await;
        assert!(closed.is_ok(), "an idle connection is ended (refused, then closed)");
        assert!(rest.is_empty() || rest.starts_with(REFUSED), "with the same refusal as any other: {:?}", String::from_utf8_lossy(&rest));
    }

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
        assert!(needs_pow(&Method::POST, "/api/e2ee/pair-requests"), "the QR pair request is first contact");
        assert!(!needs_pow(&Method::POST, "/api/e2ee/pair-requests/r1/claim"), "the polled claim asks no work");
    }
}
