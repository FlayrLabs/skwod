//! Build 51: what iOS does to a suspended app — every network socket of the process is taken away —
//! on the runtime the apps really use (`async_compat`'s single thread, as every exported async fn),
//! with the DHT client the member's endpoint runs. The front and the connection must come back.
//!
//! macOS only: the sockets are taken with the kernel call iOS uses (`pid_shutdown_sockets`), on this
//! test process itself. A private call, in this test only: nothing shipped makes it. The host is a
//! child process (this test binary again), so its sockets stay.
#![cfg(target_os = "macos")]

use std::io::{BufRead, Read, Write};
use std::sync::Arc;
use std::time::Duration;

const CHILD: &str = "SKWOD_TEST_DEAD_SOCKETS_HOST";

struct Ok200;
impl skwod_net::HostBackend for Ok200 {
    fn serve_http(&self, _peer: skwod_net::EndpointId, _relayed: bool, mut io: skwod_net::BiStream) -> skwod_net::BoxFuture<()> {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") { if io.read(&mut b).await.unwrap_or(0) == 0 { return } head.push(b[0]); }
            let _ = io.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok").await;
            let _ = io.shutdown().await;
        })
    }
    fn authorize_voice(&self, _bearer: String) -> skwod_net::BoxFuture<bool> { Box::pin(async { false }) }
    fn authorize_room(&self, _b: String, _r: String, _i: String) -> skwod_net::BoxFuture<bool> { Box::pin(async { false }) }
    fn livekit(&self) -> skwod_net::BoxFuture<Option<skwod_net::LiveKitTarget>> { Box::pin(async { None }) }
}

/// Not a test of its own: the host, when this binary is started as the child.
#[test]
fn host_child() {
    if std::env::var_os(CHILD).is_none() { return }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let mut cfg = skwod_net::NetConfig::host(skwod_net::SecretKey::generate());
        cfg.public_fallback = false;
        cfg.discovery = skwod_net::Discovery::None;
        cfg.portmapper = false;
        let host = skwod_net::Host::start(&cfg, Arc::new(Ok200)).await.unwrap();
        let addr = host.loopback_addr();
        println!("\nHOST {} {}", addr.id, addr.ip_addrs().next().unwrap());
        std::io::stdout().flush().unwrap();
        let _ = tokio::task::spawn_blocking(|| std::io::stdin().read(&mut [0u8; 1])).await;
    });
}

/// Every network socket of this process, taken as iOS takes them (SYS_pid_shutdown_sockets = 436, level
/// DISCONNECT_ALL = 2). From a helper process: this crate forbids the unsafe it would need here.
fn take_all_sockets() {
    let done = std::process::Command::new("/usr/bin/perl")
        .args(["-e", "exit(syscall(436, $ARGV[0] + 0, 2) == 0 ? 0 : 1)", &std::process::id().to_string()])
        .status().unwrap();
    assert!(done.success(), "the sockets were not taken");
}

#[test]
fn a_member_whose_sockets_were_all_taken_comes_back() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "host_child", "--nocapture"]).env(CHILD, "1")
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    let line = std::io::BufReader::new(child.stdout.take().unwrap()).lines().map_while(Result::ok)
        .find(|l| l.starts_with("HOST ")).expect("the host is up");
    let mut parts = line.split(' ').skip(1);
    let id: skwod_net::EndpointId = parts.next().unwrap().parse().unwrap();
    let at: std::net::SocketAddr = parts.next().unwrap().parse().unwrap();

    // All of it on a thread of its own, waited for with a plain timer: if the runtime's thread is
    // taken, its own timers stop with it.
    let (done, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        futures::executor::block_on(async_compat::Compat::new(async move {
            let mut cfg = skwod_net::NetConfig::member();
            cfg.public_fallback = false;
            cfg.discovery = skwod_net::Discovery::None;
            let session = skwod_core::p2p::connect_with(&cfg, skwod_net::EndpointAddr::new(id).with_ip_addr(at)).await.unwrap();
            // The DHT client of a real member's endpoint (no bootstrap: a test contacts nobody).
            let dht = n0_mainline::Dht::builder().no_bootstrap().build().unwrap();
            let before = session.base_url();
            assert!(session.check(5_000).await.proxy_ok);

            for round in 0..2 {
                // (Replacements are paced, 10 s apart after one that worked.)
                if round > 0 { tokio::time::sleep(Duration::from_secs(11)).await; }
                session.suspend();
                take_all_sockets();
                tokio::time::sleep(Duration::from_millis(500)).await;
                let state = session.clone().ensure_front().await;
                assert!(state.relistened && !state.failed, "round {round}: the front listens again");
                session.reconnect(None).await.unwrap_or_else(|e| panic!("round {round}: reconnects: {e}"));
                let health = session.check(10_000).await;
                assert!(health.proxy_ok && health.upstream_ok, "round {round}: {health:?}");
            }
            assert_ne!(session.base_url(), before, "re-keyed");
            drop(dht);
            session.disconnect().await;
        }));
        let _ = done.send(());
    });
    let outcome = result.recv_timeout(Duration::from_secs(60));
    let _ = child.kill();
    let _ = child.wait();
    assert!(outcome.is_ok(), "the core's runtime never came back: {outcome:?}");
}
