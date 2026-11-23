//! Headless p2p member — the demo / measurement tool for `docs/P2P.md`.
//!
//! Uses ONLY the FFI surface the apps get (`p2p_parse_invite`, `p2p_connect`, `signup`/`login`,
//! `SkwodClient`) plus the realtime client, against a real `skwod run` reached by its invite:
//!
//! ```text
//! cargo run -p skwod-core --example p2p_member -- 'skwod://join/<node id>#<join code>' \
//!     [--no-fallback] [--addr IP:PORT] [--user NAME] [--password PW] [--messages N] [--voice] [--hold SECS]
//! ```
//!
//! It connects (DHT lookup → QUIC), signs up (or logs in), creates an E2EE space, sends N
//! encrypted messages and waits for each to come back on the WebSocket, then reads them back and
//! decrypts them. `--voice` additionally opens the voice tunnel and prints the loopback LiveKit
//! URL + a room token, then holds the session open so a LiveKit client can use it.

use std::time::{Duration, Instant};

use skwod_core::{login, p2p_connect, p2p_parse_invite, signup, SkwodClient};
use skwod_sync::{RealtimeClient, RtEvent};

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() {
    // Silent by default; `RUST_LOG=iroh=debug,iroh_mainline_address_lookup=debug` shows the transport.
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).init();
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(link) = args.first().filter(|a| a.starts_with("skwod://")) else {
        eprintln!("usage: p2p_member 'skwod://join/<node id>#<code>' [--no-fallback] [--user NAME] [--password PW] [--messages N] [--voice] [--hold SECS]");
        std::process::exit(2);
    };
    let fallback = !flag(&args, "--no-fallback");
    let user = opt(&args, "--user").unwrap_or_else(|| "demo".into());
    let password = opt(&args, "--password").unwrap_or_else(|| "demo-password-1".into());
    let n: usize = opt(&args, "--messages").and_then(|v| v.parse().ok()).unwrap_or(20);

    let invite = p2p_parse_invite(link.clone()).expect("invite");
    println!("host node id     : {}", invite.node_id);
    println!("public fallback  : {fallback}");

    let t = Instant::now();
    // `--addr ip:port`: skip discovery and dial the host at a known address (same-machine / LAN tests).
    let dial = match opt(&args, "--addr") {
        Some(addr) => {
            let mut cfg = skwod_net::NetConfig::member();
            cfg.public_fallback = fallback;
            cfg.discovery = skwod_net::Discovery::None;
            let node = skwod_net::invite::parse_node_id(&invite.node_id).expect("node id");
            let host = skwod_net::EndpointAddr::new(node).with_ip_addr(addr.parse().expect("--addr ip:port"));
            println!("discovery        : none (dialing {addr})");
            skwod_core::p2p::connect_with(&cfg, host).await
        }
        None => p2p_connect(invite.node_id.clone(), fallback).await,
    };
    let session = match dial {
        Ok(s) => s,
        Err(e) => {
            eprintln!("connect failed after {:?}: {e}", t.elapsed());
            std::process::exit(1);
        }
    };
    let connect = t.elapsed();
    let path = session.path().await;
    println!("connected in     : {connect:?}  (path: {}, rtt {} ms)", path.kind, path.rtt_ms);
    let base = session.base_url();

    let t = Instant::now();
    let auth = match signup(base.clone(), user.clone(), password.clone(), invite.join_code.clone().unwrap_or_default()).await {
        Ok(a) => a,
        Err(_) => login(base.clone(), user.clone(), password).await.expect("signup or login"),
    };
    println!("signed in        : {:?} as {user} ({})", t.elapsed(), auth.user_id);

    let client = SkwodClient::new(base.clone(), auth.token.clone());
    // A throwaway encrypted cache, so sent messages are stored and can be read back from history.
    let cache_dir = tempfile::tempdir().expect("temp dir");
    let cache_key: [u8; 32] = std::array::from_fn(|i| i as u8 ^ 0x5a);
    let cache_path = cache_dir.path().join("cache.db").to_string_lossy().into_owned();
    client.attach_cache(cache_path, cache_key.iter().map(|b| format!("{b:02x}")).collect()).await.expect("cache");
    client.register_device().await.expect("register device");
    let space = client.create_space("p2p demo".into(), "general".into()).await.expect("create space");
    println!("space            : server {} channel {}", space.server_id, space.channel_id);

    // Realtime over the tunnel.
    let ws_url = format!("{}/api/ws", base.replacen("http://", "ws://", 1));
    let (rt, mut events) = RealtimeClient::connect(ws_url, auth.token.clone());
    rt.subscribe(format!("channel:{}", space.channel_id));
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut rpc = Vec::with_capacity(n);
    let mut echo = Vec::with_capacity(n);
    for i in 0..n {
        let t = Instant::now();
        client.send_channel_message(space.channel_id.clone(), format!("hello over p2p #{i}")).await.expect("send");
        rpc.push(t.elapsed());
        loop {
            match tokio::time::timeout(Duration::from_secs(10), events.recv()).await {
                Ok(Some(RtEvent::Message { event, .. })) if event == "message" => break,
                Ok(Some(_)) => continue,
                _ => panic!("no realtime event for message {i}"),
            }
        }
        echo.push(t.elapsed());
    }
    let stats = |v: &mut Vec<Duration>| {
        v.sort();
        (v[v.len() / 2], v[(v.len() * 95 / 100).min(v.len() - 1)], v[v.len() - 1])
    };
    if n > 0 {
        let (p50, p95, max) = stats(&mut rpc);
        println!("send (HTTP POST) : p50 {p50:?}  p95 {p95:?}  max {max:?}   [{n} E2EE messages]");
        let (p50, p95, max) = stats(&mut echo);
        println!("send → WS event  : p50 {p50:?}  p95 {p95:?}  max {max:?}");
        let history = client.fetch_channel_messages(space.channel_id.clone(), auth.user_id.clone()).await.expect("fetch");
        let ok = history.iter().filter(|m| m.content.as_deref().is_some_and(|c| c.starts_with("hello over p2p #"))).count();
        println!("read back        : {ok}/{n} messages decrypted");
        assert_eq!(ok, n, "every message must round-trip");
    }
    let path = session.path().await;
    println!("path now         : {} (rtt {} ms)", path.kind, path.rtt_ms);

    if flag(&args, "--voice") {
        let channel = client.ensure_voice_channel(space.server_id.clone(), "voice".into()).await.expect("voice channel");
        match client.voice_token(channel).await {
            Ok(v) => {
                println!("voice room       : {}", v.room);
                println!("LIVEKIT_URL={}", v.url.unwrap_or_default());
                println!("LIVEKIT_TOKEN={}", v.token);
            }
            Err(e) => println!("voice            : unavailable ({e})"),
        }
    }
    let hold: u64 = opt(&args, "--hold").and_then(|v| v.parse().ok()).unwrap_or(0);
    if hold > 0 {
        println!("holding the session for {hold}s…");
        let end = Instant::now() + Duration::from_secs(hold);
        while Instant::now() < end {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let p = session.path().await;
            let v = session.voice_stats();
            println!(
                "path             : {} (rtt {} ms)   voice tunnel: up {} pkts / {} kB, down {} pkts / {} kB",
                p.kind, p.rtt_ms, v.packets_up, v.bytes_up / 1000, v.packets_down, v.bytes_down / 1000
            );
        }
    }
    drop(rt);
    session.disconnect().await;
}
