//! The host's side of `dead_sockets.rs`: the server's own runtime (multi-threaded, as many workers as it
//! takes) must not freeze either when its DHT client's socket dies. A file, and so a process, of its own:
//! the sockets of the whole process are taken.
#![cfg(target_os = "macos")]

use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn a_hosts_runtime_goes_on_when_its_dht_socket_dies() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    let ticks = Arc::new(AtomicUsize::new(0));
    let dht = rt.block_on(async {
        for n in 0..20 {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(50 + n)).await;
                    ticks.fetch_add(1, SeqCst);
                }
            });
        }
        n0_mainline::Dht::builder().no_bootstrap().build().unwrap()
    });
    let port = rt.block_on(dht.info()).unwrap().local_addr().port();
    std::thread::sleep(Duration::from_secs(1));
    let taken = std::process::Command::new("/usr/bin/perl")
        .args(["-e", "exit(syscall(436, $ARGV[0] + 0, 2) == 0 ? 0 : 1)", &std::process::id().to_string()])
        .status().unwrap();
    assert!(taken.success());
    std::thread::sleep(Duration::from_secs(2));
    let before = ticks.load(SeqCst);
    std::thread::sleep(Duration::from_secs(2));
    let in_two_seconds = ticks.load(SeqCst) - before;
    // (Asked from outside: a frozen runtime would not time out either.)
    let (done, answer) = std::sync::mpsc::channel();
    let asked = dht.clone();
    rt.spawn(async move { let _ = done.send(asked.info().await.map(|i| i.local_addr().port())); });
    let answer = answer.recv_timeout(Duration::from_secs(5));
    rt.shutdown_background();
    assert!(in_two_seconds > 400, "{in_two_seconds} ticks (about 650 expected)");
    assert_eq!(answer.expect("the client answers").unwrap(), port, "bound again on its port");
}
