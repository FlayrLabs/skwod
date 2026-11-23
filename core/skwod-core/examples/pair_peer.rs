//! Headless EXISTING device for the "Add a device" by QR end-to-end check (build 48).
//!
//! Signs up (or in) on a local `skwod run` (loopback; the host must run with `SKWOD_QR_PAIRING=1`
//! and p2p on), registers its device, creates a space, then makes a pairing offer exactly as the
//! app's "Add a device" sheet does and writes the QR text for the device under test. Uses only
//! the FFI surface the apps get.
//!
//! ```text
//! cargo run -p skwod-core --example pair_peer -- --base http://127.0.0.1:PORT --out DIR \
//!     [--code <owner join code>] [--user NAME] [--mode approve|wrong|deny|expired] [--hold SECS] \
//!     [--pick-from <new device's pair.json>]
//! ```
//!
//! Writes `<out>/qr.txt` (the QR text) and `<out>/peer.json` (what it saw: the four sets offered,
//! the one it picked, what it did, what it sent). The existing device is shown four sets and must
//! pick the one the NEW device shows, as a person would read it off that screen: with
//! `--pick-from` it waits for the new device's `pair.json` to reach `confirm` and picks the set
//! named there. `approve`: picks that set, then keys the channel and sends `PAIRED-<ts>` so the
//! new device can show a message sent after linking. `wrong`: picks a decoy (the request must be
//! denied). `deny`: "None of these". `expired`: writes a QR whose offer expired 400 s ago (never
//! registered).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use skwod_core::pairing::{pairing_new_offer, pairing_qr_encode};
use skwod_core::{login, signup, SkwodClient};

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(base), Some(out)) = (opt(&args, "--base"), opt(&args, "--out")) else {
        eprintln!("usage: pair_peer --base http://127.0.0.1:PORT --out DIR [--code CODE] [--user NAME] [--mode approve|wrong|deny|expired] [--hold SECS] [--pick-from PAIR_JSON]");
        std::process::exit(2);
    };
    let out = std::path::PathBuf::from(out);
    std::fs::create_dir_all(&out).unwrap();
    let user = opt(&args, "--user").unwrap_or_else(|| "pairowner".into());
    let mode = opt(&args, "--mode").unwrap_or_else(|| "approve".into());
    let hold: u64 = opt(&args, "--hold").and_then(|v| v.parse().ok()).unwrap_or(300);
    let password = "e2e-pair-password-1".to_string();
    let mut report = json!({ "mode": mode });
    let write = |r: &serde_json::Value| std::fs::write(out.join("peer.json"), serde_json::to_vec_pretty(r).unwrap()).unwrap();

    let auth = match signup(base.clone(), user.clone(), password.clone(), opt(&args, "--code").unwrap_or_default()).await {
        Ok(a) => a,
        Err(_) => login(base.clone(), user.clone(), password).await.expect("signup or login"),
    };
    let me = auth.user_id.clone();
    let client = SkwodClient::new(base.clone(), auth.token.clone());
    let cache_dir = tempfile::tempdir().unwrap();
    let cache = cache_dir.path().join("cache.db").to_string_lossy().into_owned();
    client.attach_cache(cache, "5a".repeat(32)).await.expect("cache");
    client.register_device().await.expect("register device");
    let space = client.create_space("Pair check".into(), "general".into()).await.expect("space");
    client.send_channel_message(space.channel_id.clone(), "BEFORE-LINKING".into()).await.expect("send");

    let info = client.instance_p2p().await.expect("instance p2p").expect("the host must run with p2p on");
    assert!(info.qr_pairing, "the host must run with SKWOD_QR_PAIRING=1");
    let made = if mode == "expired" { now() - 400 } else { now() };
    let offer = pairing_new_offer(info.node_id.clone(), info.relay_url.clone(), user.clone(), me.clone(), made).expect("offer");
    if mode != "expired" {
        client.register_pairing_offer(offer.clone()).await.expect("register offer");
    }
    std::fs::write(out.join("qr.txt"), pairing_qr_encode(offer.clone()).expect("qr")).unwrap();
    report["node_id"] = json!(info.node_id);
    write(&report);
    println!("QR written");
    if mode == "expired" {
        return;
    }

    let end = Instant::now() + Duration::from_secs(hold);
    let candidate = loop {
        if Instant::now() > end {
            report["result"] = json!("nobody asked");
            write(&report);
            return;
        }
        match client.pairing_candidate(offer.clone(), now()).await {
            Ok(Some(c)) => break c,
            Ok(None) => tokio::time::sleep(Duration::from_secs(2)).await,
            Err(e) => {
                report["result"] = json!(format!("refused: {e}"));
                write(&report);
                return;
            }
        }
    };
    report["choices"] = json!(candidate.choices);
    println!("CHOICES {:?}", candidate.choices);
    if mode == "deny" {
        client.deny_pairing(offer, candidate).await.expect("deny");
        report["result"] = json!("denied");
        write(&report);
        return;
    }
    // What the new device shows, read off its screen (its pair.json); without one, the first set.
    let shown = match opt(&args, "--pick-from") {
        Some(path) => loop {
            if Instant::now() > end {
                report["result"] = json!("the new device never showed emoji");
                write(&report);
                return;
            }
            let v: serde_json::Value = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
            if v["phase"] == "confirm" {
                if let Some(e) = v["emoji"].as_str() {
                    break e.to_string();
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        },
        None => candidate.choices[0].clone(),
    };
    report["shown"] = json!(shown);
    let picked = if mode == "wrong" {
        candidate.choices.iter().find(|c| **c != shown).cloned().unwrap()
    } else {
        candidate.choices.iter().find(|c| **c == shown).cloned().unwrap_or_else(|| {
            report["result"] = json!("the new device's emoji were not among the choices");
            write(&report);
            std::process::exit(1);
        })
    };
    report["picked"] = json!(picked);
    println!("PICKED {picked}");
    let ok = match client.approve_pairing(offer, candidate, picked, now()).await {
        Ok(ok) => ok,
        Err(e) => {
            report["result"] = json!(format!("refused: {e}"));
            write(&report);
            return;
        }
    };
    report["result"] = json!(if ok { "approved" } else { "not approved" });
    write(&report);

    // Key the new device for the channel and speak once it is registered.
    let text = format!("PAIRED-{}", now());
    let mut sent = false;
    while Instant::now() < end {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let _ = client.process_control_inbox(me.clone()).await;
        let _ = client.sync_channel_membership(space.channel_id.clone(), space.server_id.clone(), me.clone()).await;
        let devices = client.list_devices().await.map(|d| d.devices.len()).unwrap_or(0);
        if !sent && devices >= 2 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let _ = client.sync_channel_membership(space.channel_id.clone(), space.server_id.clone(), me.clone()).await;
            if client.send_channel_message(space.channel_id.clone(), text.clone()).await.is_ok() {
                sent = true;
                report["sent"] = json!(text);
                write(&report);
                println!("SENT {text}");
            }
        }
    }
}
