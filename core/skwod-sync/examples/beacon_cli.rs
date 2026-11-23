//! Manual beacon driver for live end-to-end testing (not shipped).
//!
//! Subcommands:
//!   gen                                     → prints a fresh identity (secret/pubkey/contentKey)
//!   publish <secret> <ckey> <address>       → publish over Tor (production path)
//!   publish-direct <secret> <ckey> <addr>   → publish without Tor (faster, for debugging)
//!   resolve <pubkey> <ckey> [min_ts]        → resolve directly (verify what relays serve)
//!   resolve-tor <pubkey> <ckey> [min_ts]    → resolve over Tor (member production path)

use rand::RngCore;
use skwod_sync::beacon;

fn default_relays() -> Vec<String> {
    beacon::DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => {
            let kp = beacon::generate_beacon_key();
            let mut ck = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut ck);
            println!("secret={}", kp.secret_hex);
            println!("pubkey={}", kp.pubkey_hex);
            println!("contentKey={}", hex::encode(ck));
        }
        Some("publish") | Some("publish-direct") => {
            let (secret, ckey, addr) = (&args[2], &args[3], &args[4]);
            let res = if args[1] == "publish" {
                beacon::publish_address_private(secret, ckey, addr, &default_relays()).await
            } else {
                beacon::publish_address(secret, ckey, addr, &default_relays()).await
            };
            match res {
                Ok(()) => println!("published {addr}"),
                Err(e) => {
                    eprintln!("publish failed: {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("resolve") | Some("resolve-tor") => {
            let (pubkey, ckey) = (&args[2], &args[3]);
            let min_ts: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
            let res = if args[1] == "resolve" {
                beacon::resolve_address(pubkey, ckey, &default_relays(), min_ts).await
            } else {
                beacon::resolve_address_private(pubkey, ckey, &default_relays(), min_ts).await
            };
            match res {
                Some((ts, addr)) => println!("created_at={ts} address={addr}"),
                None => {
                    eprintln!("nothing resolved");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("usage: beacon_cli gen | publish <secret> <ckey> <addr> | resolve <pubkey> <ckey> [min_ts]");
            std::process::exit(1);
        }
    }
}
