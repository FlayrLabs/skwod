//! Host + member in one process, no discovery, no relay, loopback only.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use skwod_net::{BiStream, Discovery, EndpointId, Host, HostBackend, LiveKitTarget, LocalProxy, Member, NetConfig, PathKind, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

type Fut<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

/// A backend whose "API" answers every request with the peer's node id, and whose "LiveKit" is a
/// fake TCP + UDP service on loopback.
struct FakeBackend {
    host_id: [u8; 32],
    livekit: Option<LiveKitTarget>,
    /// Flipped to simulate logout / session expiry / ban of the "good-token" holder.
    revoked: Arc<std::sync::atomic::AtomicBool>,
    /// Set to simulate being kicked/banned from the space that owns ONE room.
    kicked_from_room: Arc<std::sync::Mutex<Option<String>>>,
}

type Kicked = Arc<std::sync::Mutex<Option<String>>>;

/// A LiveKit-shaped access token (unsigned — the fake LiveKit doesn't verify).
fn lk_token(room: &str, identity: &str) -> String {
    use base64::Engine;
    let claims = serde_json::json!({ "sub": identity, "video": { "room": room, "roomJoin": true } });
    format!("hdr.{}.sig", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string()))
}

impl HostBackend for FakeBackend {
    fn serve_http(&self, peer: EndpointId, _relayed: bool, mut io: BiStream) -> Fut<()> {
        let host_id = self.host_id;
        Box::pin(async move {
            let mut buf = vec![0u8; 4096];
            let mut head = Vec::new();
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = io.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                head.extend_from_slice(&buf[..n]);
            }
            let text = String::from_utf8_lossy(&head).to_string();
            let line = text.lines().next().unwrap_or_default().to_string();
            // Does the request carry a VALID proof-of-work stamp for (this host, this peer)?
            let stamp = text.lines().find_map(|l| l.strip_prefix("x-skwod-pow: ")).unwrap_or_default();
            let pow_ok = skwod_net::pow::verify(&host_id, peer.as_bytes(), stamp, skwod_net::pow::current_window()).is_ok();
            let body = format!("{line}|{}|pow={pow_ok}", peer.to_z32());
            let res = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
            let _ = io.write_all(res.as_bytes()).await;
            let _ = io.shutdown().await;
        })
    }
    fn authorize_voice(&self, bearer: String) -> Fut<bool> {
        let revoked = self.revoked.clone();
        Box::pin(async move { bearer == "good-token" && !revoked.load(std::sync::atomic::Ordering::SeqCst) })
    }
    fn authorize_room(&self, bearer: String, room: String, identity: String) -> Fut<bool> {
        let kicked = self.kicked_from_room.clone();
        Box::pin(async move {
            bearer == "good-token" && identity == "me" && room.starts_with("room-") && *kicked.lock().unwrap() != Some(room)
        })
    }
    fn voice_recheck_interval(&self) -> Duration {
        Duration::from_millis(100)
    }
    fn livekit(&self) -> Fut<Option<LiveKitTarget>> {
        let t = self.livekit;
        Box::pin(async move { t })
    }
}

fn local_only(mut cfg: NetConfig) -> NetConfig {
    cfg.public_fallback = false;
    cfg.discovery = Discovery::None;
    cfg.portmapper = false;
    cfg
}

async fn world(livekit: Option<LiveKitTarget>) -> (Host, Arc<Member>, SecretKey) {
    let (host, member, key, _, _) = world_revocable(livekit).await;
    (host, member, key)
}

async fn world_revocable(livekit: Option<LiveKitTarget>) -> (Host, Arc<Member>, SecretKey, Arc<std::sync::atomic::AtomicBool>, Kicked) {
    let key = SecretKey::generate();
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let kicked: Kicked = Arc::default();
    let backend = Arc::new(FakeBackend { host_id: *key.public().as_bytes(), livekit, revoked: revoked.clone(), kicked_from_room: kicked.clone() });
    let host = Host::start(&local_only(NetConfig::host(key.clone())), backend).await.unwrap();
    let member = Member::connect(&local_only(NetConfig::member()), host.loopback_addr()).await.unwrap();
    (host, member, key, revoked, kicked)
}

async fn http_get(port: u16, path: &str) -> String {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    tcp.write_all(format!("GET {path} HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    tcp.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test]
async fn proxy_requires_the_secret_and_strips_it() {
    let (host, member, key) = world(None).await;
    let proxy = LocalProxy::start(member.clone()).await.unwrap();
    let base = proxy.base_url();
    let secret = base.rsplit('/').next().unwrap().to_string();
    assert_eq!(secret.len(), 32);

    let ok = http_get(proxy.port(), &format!("/{secret}/api/thing?x=1")).await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    // The host saw the path WITHOUT the secret, and an authenticated (non-host) peer id.
    let body = ok.rsplit("\r\n\r\n").next().unwrap();
    let mut fields = body.split('|');
    let (line, peer, pow) = (fields.next().unwrap(), fields.next().unwrap(), fields.next().unwrap());
    assert_eq!(line, "GET /api/thing?x=1 HTTP/1.1");
    assert_eq!(pow, "pow=false", "ordinary requests carry no stamp (and pay no work)");
    assert_eq!(peer.len(), 52);
    assert_ne!(peer, key.public().to_z32());

    // Another local process that only knows the port gets nothing.
    for path in ["/api/thing", "/", &format!("/{}/api/thing", "0".repeat(32)), &format!("/{secret}x/api")] {
        assert!(http_get(proxy.port(), path).await.starts_with("HTTP/1.1 404"), "{path}");
    }
    // LiveKit route without a voice session → refused upstream.
    assert!(http_get(proxy.port(), &format!("/{secret}/lk/rtc")).await.starts_with("HTTP/1.1 502"));

    assert_eq!(member.path().await.kind, PathKind::Direct);
    member.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn member_reconnects_after_the_connection_dies() {
    let (host, member, _) = world(None).await;
    // Audit P1: the member's dial was made to validate its source address first (a QUIC
    // Retry) — and still connected.
    assert!(host.address_validations() >= 1, "the first dial was admitted without address validation");
    let proxy = LocalProxy::start(member.clone()).await.unwrap();
    let url = format!("/{}/a", proxy.base_url().rsplit('/').next().unwrap());
    assert!(http_get(proxy.port(), &url).await.starts_with("HTTP/1.1 200"));
    member.connection().await.unwrap().close(0u32.into(), b"test");
    assert!(http_get(proxy.port(), &url).await.starts_with("HTTP/1.1 200"), "transparent re-dial");
    host.shutdown().await;
}

#[tokio::test]
async fn independent_mode_never_touches_a_relay() {
    let (host, member, _) = world(None).await;
    use skwod_net::iroh_api::Watcher;
    // Give any (non-existent) relay machinery a moment to show itself.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for ep in [host.endpoint(), member.endpoint()] {
        assert_eq!(ep.addr().relay_urls().count(), 0, "no relay address is ever advertised");
        assert!(ep.home_relay_status().get().is_empty(), "no relay is configured or dialed");
    }
    assert_eq!(member.path().await.kind, PathKind::Direct);
    host.shutdown().await;
}

async fn recv(s: &UdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), s.recv_from(buf)).await.expect("media within 5s").unwrap()
}

/// Everything the fake LiveKit's TCP port has ever received.
static LIVEKIT_SAW: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// Fake LiveKit: a TCP port that answers HTTP (101 + echo for `ws=1`, else 200), recording every
/// byte it is sent; and a UDP port that echoes with a prefix.
async fn fake_livekit() -> (SocketAddr, SocketAddr) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signal = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = tcp.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                LIVEKIT_SAW.lock().unwrap().extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                let line = text.lines().next().unwrap_or_default().to_string();
                if line.contains("ws=1") {
                    let _ = s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").await;
                } else {
                    let body = format!("livekit saw: {line}");
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}", body.len()).as_bytes()).await;
                    if text.to_ascii_lowercase().contains("connection: close") {
                        return;
                    }
                }
                // Stay open (like a socket would), recording + echoing whatever else arrives.
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    LIVEKIT_SAW.lock().unwrap().extend_from_slice(&buf[..n]);
                    let _ = s.write_all(&buf[..n]).await;
                }
            });
        }
    });
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let media = udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let udp = Arc::new(udp);
        while let Ok((n, from)) = udp.recv_from(&mut buf).await {
            if &buf[..n] == b"stream" {
                // Like an SFU forwarding someone else's video: keeps sending, unprompted, forever.
                let udp = udp.clone();
                tokio::spawn(async move {
                    loop {
                        let _ = udp.send_to(b"media-frame", from).await;
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                });
                continue;
            }
            let mut out = b"echo:".to_vec();
            out.extend_from_slice(&buf[..n]);
            let _ = udp.send_to(&out, from).await;
        }
    });
    (signal, media)
}

const WS_HEADERS: &str = "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

#[tokio::test]
async fn livekit_stream_cannot_smuggle_a_second_request_or_a_second_token() {
    let (signal, media) = fake_livekit().await;
    let advertised = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (host, member, _) = world(Some(LiveKitTarget { signal, udp: media, advertised_udp_port: advertised })).await;
    member.voice_start("good-token").await.unwrap();
    let (allowed, forbidden) = (lk_token("room-1", "me"), lk_token("other-space", "me"));
    let mut buf = vec![0u8; 2048];
    let saw = |needle: &str| String::from_utf8_lossy(&LIVEKIT_SAW.lock().unwrap()).contains(needle);

    // (a) Authorized token in the query + a different one in the header → refused, nothing forwarded.
    let mut s = member.open_livekit().await.unwrap();
    s.write_all(format!("GET /rtc?marker=dual&access_token={allowed} HTTP/1.1\r\nAuthorization: Bearer {forbidden}\r\n{WS_HEADERS}").as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await.expect("refused and closed").unwrap();
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 400"), "{}", String::from_utf8_lossy(&out));
    assert!(!saw("marker=dual"));

    // (a2) Raw control bytes — the header-injection attempts. hyper's strict parser refuses the
    // request; nothing is forwarded, in particular not the injected header.
    let injections = [
        format!("GET /rtc?marker=inj1&access_token={allowed} HTTP/1.1\r\nX-A: 1\rX-Injected: yes\r\n{WS_HEADERS}"),
        format!("GET /rtc?marker=inj2&access_token={allowed} HTTP/1.1\r\nX-A: 1\0X-Injected: yes\r\n{WS_HEADERS}"),
        format!("GET /rtc?marker=inj3&access_token={allowed}\tHTTP/1.1\r\nX-Injected: yes\r\n{WS_HEADERS}"),
        format!("GET /rtc?marker=inj4&access_token={allowed} HTTP/1.1\r\nX-A: 1\r\n X-Injected: yes\r\n{WS_HEADERS}"),
        format!("GET /rtc?marker=inj5&access_token={allowed} HTTP/1.1\r\nX Bad Name: 1\r\nX-Injected: yes\r\n{WS_HEADERS}"),
    ];
    for raw in injections {
        let mut s = member.open_livekit().await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await.expect("closed").unwrap();
        assert!(!String::from_utf8_lossy(&out).contains("101"), "{raw:?}");
    }
    assert!(!saw("X-Injected") && !saw("x-injected"), "no injected header ever reached LiveKit");
    for marker in ["inj1", "inj2", "inj3", "inj5"] {
        assert!(!saw(&format!("marker={marker}")), "{marker} must not be forwarded at all");
    }

    // (b) A fake "upgrade" (not WebSocket) with a pipelined second request for another room:
    // forwarded as ONE request with Connection: close; the second never reaches LiveKit.
    let mut s = member.open_livekit().await.unwrap();
    s.write_all(
        format!("GET /rtc?marker=h2c&access_token={allowed} HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\nGET /rtc?marker=smuggled&access_token={forbidden} HTTP/1.1\r\n{WS_HEADERS}").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await.expect("one response, then closed").unwrap();
    assert!(String::from_utf8_lossy(&out).contains("livekit saw: GET /rtc?marker=h2c"));
    assert!(saw("marker=h2c") && !saw("marker=smuggled"));

    // (c) A genuine WebSocket handshake that LiveKit does NOT accept (200, not 101), with bytes
    // already queued behind it: the answer is relayed, the queued bytes are not.
    let mut s = member.open_livekit().await.unwrap();
    s.write_all(format!("GET /rtc?marker=refused&access_token={allowed} HTTP/1.1\r\n{WS_HEADERS}GET /rtc?marker=after-refusal HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    s.write_all(b"GET /rtc?marker=late HTTP/1.1\r\n\r\n").await.ok();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(saw("marker=refused") && !saw("marker=after-refusal") && !saw("marker=late"));

    // (d) A real upgrade (101): now, and only now, the stream is a raw pipe.
    let mut s = member.open_livekit().await.unwrap();
    s.write_all(format!("GET /rtc?ws=1&access_token={allowed} HTTP/1.1\r\n{WS_HEADERS}frame-1").as_bytes()).await.unwrap();
    let mut got = Vec::new();
    while !got.ends_with(b"frame-1") {
        let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.expect("101 + echo").unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
    assert!(got.starts_with(b"HTTP/1.1 101 "));
    // The handshake reply must still say `Connection: Upgrade` (a real WebSocket client — e.g.
    // LiveKit's Go SDK — rejects the handshake otherwise).
    let head = String::from_utf8_lossy(&got).to_ascii_lowercase();
    assert!(head.contains("connection: upgrade") && head.contains("upgrade: websocket"), "{head}");

    member.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn proxy_stamps_signup_and_login_with_proof_of_work() {
    let (host, member, _) = world(None).await;
    let proxy = LocalProxy::start(member.clone()).await.unwrap();
    let secret = proxy.base_url().rsplit('/').next().unwrap().to_string();
    for path in ["/api/auth/login", "/api/auth/signup"] {
        let mut tcp = TcpStream::connect(("127.0.0.1", proxy.port())).await.unwrap();
        // The app sends an ordinary request (plus a bogus stamp of its own, which must be replaced).
        tcp.write_all(format!("POST /{secret}{path} HTTP/1.1\r\nhost: x\r\nx-skwod-pow: 1.1\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
        let mut out = String::new();
        tcp.read_to_string(&mut out).await.unwrap();
        assert!(out.ends_with("pow=true"), "{path}: the host received a valid stamp bound to this member: {out}");
    }
    host.shutdown().await;
}

#[tokio::test]
async fn voice_signaling_and_media_ride_the_tunnel() {
    let (signal, media) = fake_livekit().await;
    // The port LiveKit would advertise in its 127.0.0.1 candidate: free on this machine, and
    // different from where the fake actually listens (i.e. "LiveKit behind a port mapping").
    let advertised = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (host, member, _) = world(Some(LiveKitTarget { signal, udp: media, advertised_udp_port: advertised })).await;
    let proxy = LocalProxy::start(member.clone()).await.unwrap();
    let token = lk_token("room-1", "me");
    let lk_path = format!("/{}/lk/rtc?access_token={token}", proxy.base_url().rsplit('/').next().unwrap());

    // No session token → no LiveKit, no media.
    assert!(http_get(proxy.port(), &lk_path).await.starts_with("HTTP/1.1 502"));
    assert!(member.voice_start("bad-token").await.is_err());
    assert!(http_get(proxy.port(), &lk_path).await.starts_with("HTTP/1.1 502"));

    let port = member.voice_start("good-token").await.unwrap();
    assert_eq!(port, advertised);
    let res = http_get(proxy.port(), &lk_path).await;
    assert!(res.ends_with(&format!("livekit saw: GET /rtc?access_token={token} HTTP/1.1")), "{res}");
    // The tunnel is not a blanket pass to the SFU: a stream must carry a LiveKit token, for a
    // room this session may be in, under its own identity.
    let secret = proxy.base_url().rsplit('/').next().unwrap().to_string();
    for bad in [
        format!("/{secret}/lk/rtc"),
        format!("/{secret}/lk/rtc?access_token={}", lk_token("other-space", "me")),
        format!("/{secret}/lk/rtc?access_token={}", lk_token("room-1", "someone-else")),
    ] {
        assert!(!http_get(proxy.port(), &bad).await.contains("livekit saw"), "{bad}");
    }

    // Media: two local "WebRTC sockets" (flows) talk to 127.0.0.1:<advertised>; each gets only its
    // own answers, including a packet far larger than one QUIC datagram.
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let big: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
    a.send_to(b"ping-a", ("127.0.0.1", port)).await.unwrap();
    b.send_to(&big, ("127.0.0.1", port)).await.unwrap();
    let mut buf = vec![0u8; 65536];
    let (n, from) = recv(&a, &mut buf).await;
    assert_eq!(&buf[..n], b"echo:ping-a");
    assert_eq!(from, SocketAddr::from(([127, 0, 0, 1], port)), "answers come from the advertised candidate");
    let (n, _) = recv(&b, &mut buf).await;
    assert_eq!(n, big.len() + 5);
    assert_eq!(&buf[5..n], &big[..]);

    // After a reconnect the proxy re-authorizes voice on the new connection by itself.
    member.connection().await.unwrap().close(0u32.into(), b"test");
    assert!(http_get(proxy.port(), &lk_path).await.ends_with("HTTP/1.1"), "voice survives a re-dial");
    a.send_to(b"again", ("127.0.0.1", port)).await.unwrap();
    let (n, _) = recv(&a, &mut buf).await;
    assert_eq!(&buf[..n], b"echo:again");

    member.close().await;
    host.shutdown().await;
}

/// Open a long-lived LiveKit signaling stream (stands in for the WebSocket) and read its response head.
async fn open_signaling(member: &Member, room: &str) -> skwod_net::BiStream {
    let mut s = member.open_livekit().await.unwrap();
    s.write_all(format!("GET /rtc?ws=1&access_token={} HTTP/1.1\r\n{WS_HEADERS}", lk_token(room, "me")).as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.expect("livekit answers").unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 101"), "admitted to {room}");
    s
}

async fn assert_cut(mut stream: skwod_net::BiStream) {
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut rest)).await;
    assert!(closed.is_ok(), "the live LiveKit stream must be torn down");
}

#[tokio::test]
async fn revoking_the_session_cuts_voice_on_a_live_connection() {
    let (signal, media) = fake_livekit().await;
    let advertised = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (host, member, _, revoked, _) = world_revocable(Some(LiveKitTarget { signal, udp: media, advertised_udp_port: advertised })).await;
    let proxy = LocalProxy::start(member.clone()).await.unwrap();
    let lk_path = format!("/{}/lk/rtc?access_token={}", proxy.base_url().rsplit('/').next().unwrap(), lk_token("room-1", "me"));
    let port = member.voice_start("good-token").await.unwrap();
    let conn_before = member.connection().await.unwrap().stable_id();

    let signaling = open_signaling(&member, "room-1").await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0u8; 2048];
    sock.send_to(b"before", ("127.0.0.1", port)).await.unwrap();
    assert_eq!(recv(&sock, &mut buf).await.0, 11);

    // The user logs out / the session expires. Same iroh connection, nothing reconnects.
    revoked.store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(400)).await; // > recheck interval

    // Media is no longer forwarded…
    sock.send_to(b"after", ("127.0.0.1", port)).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await.is_err(), "media must stop");
    // …the open signaling stream was cut by the host…
    assert_cut(signaling).await;
    // …and new LiveKit streams are refused, even though the connection itself is the same one.
    assert!(http_get(proxy.port(), &lk_path).await.starts_with("HTTP/1.1 403"));
    assert_eq!(member.connection().await.unwrap().stable_id(), conn_before);
    // The API itself is unaffected.
    assert!(http_get(proxy.port(), &format!("/{}/api/x", proxy.base_url().rsplit('/').next().unwrap())).await.starts_with("HTTP/1.1 200"));

    member.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn being_removed_from_one_space_cuts_that_room_even_with_a_valid_session() {
    let (signal, media) = fake_livekit().await;
    let advertised = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (host, member, _, _, kicked) = world_revocable(Some(LiveKitTarget { signal, udp: media, advertised_udp_port: advertised })).await;
    let proxy = LocalProxy::start(member.clone()).await.unwrap();
    let secret = proxy.base_url().rsplit('/').next().unwrap().to_string();
    let port = member.voice_start("good-token").await.unwrap();
    let in_a = open_signaling(&member, "room-a").await;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = vec![0u8; 2048];
    sock.send_to(b"x", ("127.0.0.1", port)).await.unwrap();
    recv(&sock, &mut buf).await;

    // Kicked/banned from the space owning room-a. The session is still valid and the user is
    // still a member of the space owning room-b.
    *kicked.lock().unwrap() = Some("room-a".to_string());
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_cut(in_a).await;
    sock.send_to(b"y", ("127.0.0.1", port)).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await.is_err(), "media into the old room stops");
    // Even after re-authorizing voice (the session IS valid), room-a stays closed — its still-
    // unexpired LiveKit token is useless through the tunnel — while room-b works.
    member.voice_start("good-token").await.unwrap();
    let a = http_get(proxy.port(), &format!("/{secret}/lk/rtc?access_token={}", lk_token("room-a", "me"))).await;
    assert!(!a.contains("livekit saw"), "{a}");
    let b = http_get(proxy.port(), &format!("/{secret}/lk/rtc?access_token={}", lk_token("room-b", "me"))).await;
    assert!(b.contains("livekit saw"), "{b}");

    member.close().await;
    host.shutdown().await;
}

#[tokio::test]
async fn revocation_stops_inbound_media_and_ends_the_reader_tasks() {
    let (signal, media) = fake_livekit().await;
    let advertised = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (host, member, _, revoked, _) = world_revocable(Some(LiveKitTarget { signal, udp: media, advertised_udp_port: advertised })).await;
    let port = member.voice_start("good-token").await.unwrap();
    let mut buf = vec![0u8; 2048];

    // Two flows; LiveKit streams media DOWN one of them continuously (a subscribed video track).
    let (a, b) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
    a.send_to(b"stream", ("127.0.0.1", port)).await.unwrap();
    b.send_to(b"ping", ("127.0.0.1", port)).await.unwrap();
    let n = recv(&a, &mut buf).await.0;
    assert_eq!(&buf[..n], b"media-frame");
    recv(&b, &mut buf).await;
    assert_eq!(skwod_net::voice::active_host_readers(media), 2, "one reader per flow while the call is live");
    let before = member.voice_stats().2;

    // Revoke mid-call. The forwarder is aborted (not allowed to finish normally) while LiveKit
    // is still sending.
    revoked.store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(500)).await; // > recheck interval

    // The reader tasks are gone with it…
    assert_eq!(skwod_net::voice::active_host_readers(media), 0, "readers must not outlive the forwarder");
    // …so nothing LiveKit sends reaches the member any more: drain what was in flight, then silence.
    while tokio::time::timeout(Duration::from_millis(100), a.recv_from(&mut buf)).await.is_ok() {}
    let settled = member.voice_stats().2;
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(member.voice_stats().2, settled, "no further datagrams arrive from the host (had {before} before revocation)");
    assert!(tokio::time::timeout(Duration::from_millis(300), a.recv_from(&mut buf)).await.is_err());

    // Closing the connection (no revocation) ends readers too.
    let (host2, member2, _) = world(Some(LiveKitTarget { signal, udp: media, advertised_udp_port: advertised })).await;
    drop(member); // releases 127.0.0.1:<advertised> … once its tasks are gone
    host.shutdown().await;
    let mut port2 = None;
    for _ in 0..20 {
        match member2.voice_start("good-token").await {
            Ok(p) => {
                port2 = Some(p);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let port2 = port2.expect("forwarder port free again");
    a.send_to(b"stream", ("127.0.0.1", port2)).await.unwrap();
    recv(&a, &mut buf).await;
    assert_eq!(skwod_net::voice::active_host_readers(media), 1);
    member2.close().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(skwod_net::voice::active_host_readers(media), 0, "readers stop when the connection closes");
    host2.shutdown().await;
}
