//! Read-only reachability probe: from a clean member endpoint (fresh key, no cache), resolve and
//! dial a host by node id and report how long it took and whether the path is direct or relayed.
//! Opens no stream and sends no request. Usage:
//!   cargo run -p skwod-net --example probe -- <node id> [MODE]
//! MODE: `fallback` (the app's default config), `dht-only` (public fallback off), `dht-relay`
//! (DHT lookup only, relays on), `relay-only` (n0 lookup, no UDP at all), `hint:<relay url>`
//! (the app's config plus a relay hint, e.g. a stale one).
use std::time::Instant;

use skwod_net::{EndpointAddr, NetConfig};

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let id = args.next().expect("node id");
    let mode = args.next().unwrap_or_else(|| "fallback".into());
    let node = skwod_net::invite::parse_node_id(&id).expect("node id");
    let mut cfg = NetConfig::member();
    if mode == "dht-only" {
        cfg.public_fallback = false;
    }
    println!("plan: {:?}", cfg.plan());
    use skwod_net::iroh_api::address_lookup::PkarrResolver;
    use skwod_net::iroh_api::endpoint::presets;
    let ep = match mode.as_str() {
        // The DHT alone decides the lookup; relays allowed so a relay-only record still dials.
        "dht-relay" => skwod_net::Endpoint::builder(presets::Minimal)
            .relay_mode(skwod_net::iroh_api::endpoint::default_relay_mode())
            .address_lookup(iroh_mainline_address_lookup::DhtAddressLookup::builder().no_publish())
            .bind().await.expect("bind"),
        // n0 lookup, no UDP at all: what a phone on a UDP-hostile network gets.
        "relay-only" => skwod_net::Endpoint::builder(presets::Minimal)
            .relay_mode(skwod_net::iroh_api::endpoint::default_relay_mode())
            .clear_ip_transports()
            .address_lookup(PkarrResolver::n0_dns())
            .bind().await.expect("bind"),
        _ => skwod_net::bind(&cfg).await.expect("bind"),
    };
    let t = Instant::now();
    // `hint:<relay url>`: the app's own config plus a relay hint (e.g. a stale one).
    let target = match mode.strip_prefix("hint:") {
        Some(relay) => skwod_net::invite::dial_addr(node, Some(relay), true),
        None => EndpointAddr::new(node),
    };
    let r = tokio::time::timeout(std::time::Duration::from_secs(40), ep.connect(target, skwod_net::ALPN)).await;
    match r {
        Ok(Ok(conn)) => {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let relay = conn.paths().iter().find(|p| p.is_selected()).map(|p| p.is_relay());
            println!("{mode}: CONNECTED in {:?}, selected path relay={relay:?}", t.elapsed());
            conn.close(0u32.into(), b"probe");
        }
        Ok(Err(e)) => println!("{mode}: FAILED after {:?}: {e}", t.elapsed()),
        Err(_) => println!("{mode}: TIMEOUT after {:?}", t.elapsed()),
    }
    ep.close().await;
}
