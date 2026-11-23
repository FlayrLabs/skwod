//! Headless second participant for the app end-to-end checks (docs/APPLE.md "Proving it", and
//! the Android emulator run).
//!
//! Plays the HOST's own client: it talks to a local `skwod run` on its loopback address (the
//! path a host's own app uses), owns the instance, creates one E2EE space, mints an invite for
//! the app under test, then keeps the space keyed and prints every message it could DECRYPT.
//! Uses only the FFI surface the apps get.
//!
//! ```text
//! cargo run --release -p skwod-core --example e2e_peer -- \
//!     --base http://127.0.0.1:38411 --code <owner join code> --node <host node id> \
//!     [--user owner] [--password PW] [--hold SECS] [--say-file PATH] [--voice]
//! ```
//!
//! - prints `INVITE=skwod://join/<node>#<code>` (a one-time, auto-joining invite);
//! - prints `RECV <username>: <text>` for each message from someone else, after decrypting it;
//! - `--say-file PATH`: whenever that file's contents change, they are sent as a channel message
//!   (lets a test script make the peer speak at a chosen moment);
//! - `--voice`: prints `LIVEKIT_URL=` / `LIVEKIT_TOKEN=` / `VOICE_ROOM=` for the space's voice
//!   room, so a LiveKit client can join as this account.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use skwod_core::{login, p2p_format_invite, signup, SkwodClient};

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}
fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(base), Some(node)) = (opt(&args, "--base"), opt(&args, "--node")) else {
        eprintln!("usage: e2e_peer --base http://127.0.0.1:PORT --node <node id> [--code <owner join code>] [--user NAME] [--password PW] [--hold SECS] [--say-file PATH] [--voice]");
        std::process::exit(2);
    };
    let code = opt(&args, "--code").unwrap_or_default();
    let user = opt(&args, "--user").unwrap_or_else(|| "owner".into());
    let password = opt(&args, "--password").unwrap_or_else(|| "e2e-owner-password-1".into());
    let hold: u64 = opt(&args, "--hold").and_then(|v| v.parse().ok()).unwrap_or(600);
    let say_file = opt(&args, "--say-file");

    let auth = match signup(base.clone(), user.clone(), password.clone(), code).await {
        Ok(a) => a,
        Err(_) => login(base.clone(), user.clone(), password).await.expect("signup or login"),
    };
    let me = auth.user_id.clone();
    println!("signed in as {user}");

    let client = SkwodClient::new(base.clone(), auth.token.clone());
    let cache_dir = tempfile::tempdir().expect("temp dir");
    let cache_key: [u8; 32] = std::array::from_fn(|i| i as u8 ^ 0x3c);
    let cache_path = cache_dir.path().join("cache.db").to_string_lossy().into_owned();
    client.attach_cache(cache_path, cache_key.iter().map(|b| format!("{b:02x}")).collect()).await.expect("cache");
    client.register_device().await.expect("register device");

    let space = client.create_space("skwod e2e".into(), "general".into()).await.expect("create space");
    let invite_code = client.invite_to_space(space.server_id.clone(), "token".into(), None).await.expect("mint invite");
    let link = p2p_format_invite(node, Some(invite_code)).expect("format invite");
    println!("INVITE={link}");

    if flag(&args, "--voice") {
        let channel = client.ensure_voice_channel(space.server_id.clone(), "General".into()).await.expect("voice channel");
        match client.voice_token(channel).await {
            Ok(v) => {
                println!("VOICE_ROOM={}", v.room);
                println!("LIVEKIT_URL={}", v.url.unwrap_or_default());
                println!("LIVEKIT_TOKEN={}", v.token);
                println!("LIVEKIT_IDENTITY={me}");
            }
            Err(e) => println!("voice unavailable: {e}"),
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut names: HashMap<String, String> = HashMap::new();
    let mut last_said = String::new();
    let mut members = 1usize;
    let end = Instant::now() + Duration::from_secs(hold);
    while Instant::now() < end {
        tokio::time::sleep(Duration::from_secs(2)).await;
        // Fulfil provision requests (a joining member asks the host for the space + channel keys).
        let _ = client.process_control_inbox(me.clone()).await;
        // Code invites: approve, then provision ONLY the exact account that was approved.
        if let Ok(pending) = client.list_join_requests(space.server_id.clone()).await {
            for req in pending {
                if client.approve_join_request(space.server_id.clone(), req.user_id.clone()).await.is_ok() {
                    if let Ok(found) = client.find_user(req.username.clone()).await {
                        if found.user_id == req.user_id {
                            let _ = client.provision_member(space.server_id.clone(), found.user_id, found.device_id).await;
                        }
                    }
                }
            }
        }
        if let Ok(list) = client.list_members(space.server_id.clone()).await {
            if list.len() != members {
                members = list.len();
                println!("MEMBERS={members}");
            }
            for m in list {
                names.insert(m.user_id, m.username);
            }
        }
        // Keys for whoever is in the channel now (what opening the channel in an app does).
        let _ = client.sync_channel_membership(space.channel_id.clone(), space.server_id.clone(), me.clone()).await;

        if let Some(path) = &say_file {
            if let Ok(text) = std::fs::read_to_string(path) {
                let text = text.trim().to_string();
                if !text.is_empty() && text != last_said && members > 1 && client.send_channel_message(space.channel_id.clone(), text.clone()).await.is_ok() {
                    println!("SENT {text}");
                    last_said = text;
                }
            }
        }
        if let Ok(rows) = client.fetch_channel_messages(space.channel_id.clone(), me.clone()).await {
            for m in rows {
                let Some(text) = m.content else { continue };
                let mine = m.author_id.as_deref() == Some(me.as_str()) || m.author_id.as_deref() == Some("__me__");
                if mine || text.starts_with('\u{2}') || !seen.insert(m.message_id) {
                    continue;
                }
                let who = m.author_id.as_ref().and_then(|id| names.get(id)).cloned().unwrap_or_else(|| "member".into());
                println!("RECV {who}: {text}");
            }
        }
    }
}
