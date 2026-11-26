//! Remembered direct routes over real endpoints, on this machine's own private address (a loopback
//! address is never remembered). Discovery and relays are off: nothing else can find the host.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use skwod_net::{BiStream, BoxFuture, Discovery, EndpointAddr, EndpointId, Host, HostBackend, LiveKitTarget, Member, NetConfig, RelayGate, Routes, SecretKey};

struct Nothing;
impl HostBackend for Nothing {
    fn serve_http(&self, _: EndpointId, _: bool, _: BiStream) -> BoxFuture<()> { Box::pin(async {}) }
    fn authorize_voice(&self, _: String) -> BoxFuture<bool> { Box::pin(async { false }) }
    fn authorize_room(&self, _: String, _: String, _: String) -> BoxFuture<bool> { Box::pin(async { false }) }
    fn livekit(&self) -> BoxFuture<Option<LiveKitTarget>> { Box::pin(async { None }) }
}

/// The private IPv4 address of this machine (nothing is sent), if it is on such a network.
fn lan() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    matches!(ip, IpAddr::V4(v4) if v4.is_private()).then_some(ip)
}

fn local(mut cfg: NetConfig) -> NetConfig {
    cfg.public_fallback = false;
    cfg.discovery = Discovery::None;
    cfg.portmapper = false;
    cfg
}

fn member(host: EndpointId, blob: Option<&str>) -> NetConfig {
    NetConfig { routes: Routes::load(host, blob), ..local(NetConfig::member()) }
}

const SOON: Duration = Duration::from_secs(8);

#[tokio::test(flavor = "multi_thread")]
async fn a_host_is_found_again_where_it_was_reached_and_only_itself() {
    let Some(ip) = lan() else { eprintln!("SKIP: not on a private IPv4 network"); return };
    let key = SecretKey::generate();
    let host = Host::start(&local(NetConfig::host(key.clone())), Arc::new(Nothing)).await.unwrap();
    let id = host.node_id();
    let port = host.endpoint().bound_sockets().iter().find(|s| s.is_ipv4()).unwrap().port();
    let at = SocketAddr::new(ip, port);

    let cfg = member(id, None);
    assert!(Member::connect_within(&cfg, EndpointAddr::new(id), Duration::from_secs(2)).await.is_err(), "nothing knows where it is");
    let m = Member::connect_within(&cfg, EndpointAddr::new(id).with_ip_addr(at), SOON).await.unwrap();
    let blob = tokio::time::timeout(SOON, async {
        loop {
            if let Some(b) = cfg.routes.take_blob() { return b }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("the direct path is remembered");
    assert!(blob.contains(&at.to_string()));
    m.close().await;
    // Another process later, with nothing but that: the bare node id is enough.
    let m = Member::connect_within(&member(id, Some(&blob)), EndpointAddr::new(id), SOON).await.unwrap();
    m.close().await;
    host.shutdown().await;

    // Somebody else at that address now: refused before our certificate goes out — they never learn
    // which key knocked.
    let mut other = local(NetConfig::host(SecretKey::generate()));
    other.bind_port = Some(port);
    let impostor = skwod_net::bind(&other).await.unwrap();
    let listening = impostor.clone();
    let learnt = tokio::spawn(async move {
        let mut knocked = 0;
        while let Ok(Some(incoming)) = tokio::time::timeout(Duration::from_secs(6), listening.accept()).await {
            knocked += 1;
            if let Ok(accepting) = incoming.accept() {
                if accepting.await.is_ok() { return (knocked, true) }
            }
        }
        (knocked, false)
    });
    assert!(Member::connect_within(&member(id, Some(&blob)), EndpointAddr::new(id), Duration::from_secs(4)).await.is_err());
    impostor.close().await;
    let (knocked, identified) = learnt.await.unwrap();
    assert!(knocked > 0 && !identified, "{knocked} {identified}");
}

/// Turning relays off: the gate is first, and neither it nor reading the routes waits for a dial.
#[tokio::test(flavor = "multi_thread")]
async fn nothing_waits_before_relays_are_revoked() {
    let gate = RelayGate::new(true);
    let nobody = SecretKey::generate().public();
    let mut cfg = NetConfig { relay_gate: gate.clone(), ..member(nobody, None) };
    cfg.public_fallback = true;
    cfg.custom_relays = Some(skwod_net::iroh_api::RelayMap::empty());
    let routes = cfg.routes.clone();
    let dial = tokio::spawn(async move {
        Member::connect_within(&cfg, EndpointAddr::new(nobody).with_ip_addr("127.0.0.1:9".parse().unwrap()), Duration::from_secs(20)).await.is_err()
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(gate.live(), 1, "the dial holds the connection lock and its lease");
    let started = Instant::now();
    gate.revoke();
    assert_eq!(routes.take_blob(), None);
    assert!(started.elapsed() < Duration::from_millis(100), "{:?}", started.elapsed());
    assert!(tokio::time::timeout(Duration::from_secs(5), dial).await.unwrap().unwrap());
    assert!(gate.off(Duration::from_secs(5)).await);
}
