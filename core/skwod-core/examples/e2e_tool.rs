//! Headless helpers for the trust end-to-end checks (docs/APPLE.md "Proving it"). Uses only the
//! FFI surface the apps get, against a local `skwod run`.
//!
//! ```text
//! # A second device for an existing account. Prints LINK_CODE=<code>; approve it on one of the
//! # account's devices (app hook `approvelink:<code>`); then prints LINKED=<device id> and stays
//! # registered for --hold seconds.
//! cargo run --release -p skwod-core --example e2e_tool -- link \
//!     --base http://127.0.0.1:38411 --user member --password PW [--hold 600]
//!
//! # A "ghost": an account with a real device that was never invited. Prints GHOST_USER=<id>
//! # and GHOST_DEVICE=<id>, then waits for --server/--channel ids on stdin-free flags: once the
//! # test has inserted the ghost into the server's database it asks every member for keys
//! # exactly as a joining client does, and reports what it can read:
//! #   GHOST members=<n> channels_named=<n> messages=<n> decrypted=<n>
//! cargo run --release -p skwod-core --example e2e_tool -- ghost \
//!     --base http://127.0.0.1:38411 --user ghost --password PW \
//!     --ids-file /path/ids.txt [--code <invite>] [--hold 600]
//! ```
//!
//! `--ids-file` holds `<server id> <channel id>` (written by the test once it knows them).
//!
//! `device2` is `link` that then takes part as the account's second device — see the comment
//! on that mode below (`--ids-file`, `--cmd-file`).

use std::time::{Duration, Instant};

use skwod_core::{login, signup, SkwodClient};

fn opt(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

async fn client_for(base: &str, token: &str, dir: &tempfile::TempDir) -> std::sync::Arc<SkwodClient> {
    let client = SkwodClient::new(base.to_string(), token.to_string());
    let key: [u8; 32] = std::array::from_fn(|i| i as u8 ^ 0x5a);
    let path = dir.path().join("cache.db").to_string_lossy().into_owned();
    client.attach_cache(path, key.iter().map(|b| format!("{b:02x}")).collect()).await.expect("cache");
    client
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().cloned().unwrap_or_default();
    let (Some(base), Some(user)) = (opt(&args, "--base"), opt(&args, "--user")) else {
        eprintln!("usage: e2e_tool <link|ghost> --base URL --user NAME [--password PW] [--hold SECS] [--ids-file PATH] [--code INVITE]");
        std::process::exit(2);
    };
    let password = opt(&args, "--password").unwrap_or_else(|| "e2e-password-1".into());
    let hold: u64 = opt(&args, "--hold").and_then(|v| v.parse().ok()).unwrap_or(600);
    let end = Instant::now() + Duration::from_secs(hold);
    let dir = tempfile::tempdir().expect("temp dir");

    match mode.as_str() {
        "link" => {
            let auth = login(base.clone(), user.clone(), password).await.expect("login");
            let client = client_for(&base, &auth.token, &dir).await;
            let code = client.begin_device_link().await.expect("begin device link");
            println!("LINK_CODE={code}");
            let device = loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                match client.complete_device_link().await {
                    Ok(Some(device)) => break device,
                    Ok(None) if Instant::now() < end => continue,
                    Ok(None) => panic!("link was not approved in time"),
                    Err(e) => panic!("link failed: {e}"),
                }
            };
            println!("LINKED={device}");
            while Instant::now() < end {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let _ = client.process_control_inbox(auth.user_id.clone()).await;
            }
        }
        // A SECOND DEVICE of an existing account that also takes part: once linked it asks
        // the account's other devices for the server's keys, then follows --cmd-file (consumed
        // on read), one command per line:
        //   edit:<text>   edit this ACCOUNT's newest chat message in the channel (sealed by THIS device)
        //   say:<text>    send a channel message from this device
        // and prints what it sees: `DM from_self=<bool> peer=<user id> text=<text>` for each direct
        // message that reaches this device (from_self = a copy of one the account sent from
        // another device), `DMS <n>: <peer usernames>` when the conversation list changes, and
        // `CHANNEL messages=<n> decrypted=<n>`.
        "device2" => {
            let auth = login(base.clone(), user.clone(), password).await.expect("login");
            let me = auth.user_id.clone();
            let client = client_for(&base, &auth.token, &dir).await;
            let code = client.begin_device_link().await.expect("begin device link");
            println!("LINK_CODE={code}");
            let device = loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                match client.complete_device_link().await {
                    Ok(Some(device)) => break device,
                    Ok(None) if Instant::now() < end => continue,
                    Ok(None) => panic!("link was not approved in time"),
                    Err(e) => panic!("link failed: {e}"),
                }
            };
            println!("LINKED={device}");
            let ids_file = opt(&args, "--ids-file").expect("--ids-file");
            let cmd_file = opt(&args, "--cmd-file").expect("--cmd-file");
            let (mut last_dms, mut last_channel) = (String::new(), String::new());
            let mut asked = 0u32;
            while Instant::now() < end {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let Ok(ids) = std::fs::read_to_string(&ids_file) else { continue };
                let mut it = ids.split_whitespace();
                let (Some(server), Some(channel)) = (it.next().map(str::to_string), it.next().map(str::to_string)) else { continue };
                // The server's keys come from this account's own other device(s).
                let named = client.list_channels(server.clone()).await.map(|c| c.iter().filter(|c| c.name.is_some()).count()).unwrap_or(0);
                if named == 0 && asked < 20 {
                    asked += 1;
                    for other in client.list_own_devices().await.unwrap_or_default() {
                        if other != device {
                            let _ = client.request_provision(server.clone(), me.clone(), other).await;
                        }
                    }
                }
                match client.sync_dms().await {
                    Ok(events) => {
                        for e in events {
                            println!("DM from_self={} peer={} text={}", e.from_self, e.peer_user_id, e.text.chars().take(80).collect::<String>());
                        }
                    }
                    Err(e) => eprintln!("sync_dms: {e}"),
                }
                let _ = client.process_control_inbox(me.clone()).await;
                let _ = client.sync_channel_membership(channel.clone(), server.clone(), me.clone()).await;
                if let Ok(dms) = client.list_dms().await {
                    let line = format!("DMS {}: {}", dms.len(), dms.iter().map(|d| d.peer_username.clone()).collect::<Vec<_>>().join(","));
                    if line != last_dms {
                        println!("{line}");
                        last_dms = line;
                    }
                }
                let rows = client.fetch_channel_messages(channel.clone(), me.clone()).await.unwrap_or_default();
                let line = format!("CHANNEL messages={} decrypted={} keys={}", rows.len(), rows.iter().filter(|m| m.content.is_some()).count(), named > 0);
                if line != last_channel {
                    println!("{line}");
                    last_channel = line;
                }
                let Ok(cmds) = std::fs::read_to_string(&cmd_file) else { continue };
                let _ = std::fs::remove_file(&cmd_file);
                for cmd in cmds.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    if let Some(text) = cmd.strip_prefix("edit:") {
                        // The account's newest chat message — typically written on its OTHER device.
                        let mine = rows.iter().rev().find(|m| {
                            let author = m.author_id.as_deref();
                            (author == Some(me.as_str()) || author == Some("__me__")) && !m.is_deleted
                                && !m.content.as_deref().unwrap_or("").starts_with('\u{2}')
                        });
                        match mine {
                            Some(m) => match client.edit_channel_message(channel.clone(), m.message_id.clone(), text.to_string()).await {
                                Ok(()) => println!("EDITED {} was={:?}", m.message_id, m.content),
                                Err(e) => println!("EDIT_FAILED {e}"),
                            },
                            None => println!("EDIT_FAILED nothing of this account's to edit"),
                        }
                    } else if let Some(text) = cmd.strip_prefix("say:") {
                        match client.send_channel_message(channel.clone(), text.to_string()).await {
                            Ok(id) => println!("SAID {id}"),
                            Err(e) => println!("SAY_FAILED {e}"),
                        }
                    }
                }
            }
        }
        "ghost" => {
            let code = opt(&args, "--code").unwrap_or_default();
            let auth = match signup(base.clone(), user.clone(), password.clone(), code).await {
                Ok(a) => a,
                Err(_) => login(base.clone(), user.clone(), password).await.expect("signup or login"),
            };
            let me = auth.user_id.clone();
            let client = client_for(&base, &auth.token, &dir).await;
            let device = client.register_device().await.expect("register device");
            println!("GHOST_USER={me}");
            println!("GHOST_DEVICE={device}");
            let ids_file = opt(&args, "--ids-file").expect("--ids-file");
            let mut last = String::new();
            while Instant::now() < end {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let Ok(ids) = std::fs::read_to_string(&ids_file) else { continue };
                let mut it = ids.split_whitespace();
                let (Some(server), Some(channel)) = (it.next().map(str::to_string), it.next().map(str::to_string)) else { continue };
                // Ask every member the server lists for the keys, as a joining client would.
                let members = client.list_members(server.clone()).await.unwrap_or_default();
                for m in &members {
                    if m.user_id == me {
                        continue;
                    }
                    if let Ok(found) = client.find_user(m.username.clone()).await {
                        let _ = client.request_provision(server.clone(), found.user_id, found.device_id).await;
                    }
                }
                let _ = client.process_control_inbox(me.clone()).await;
                let _ = client.sync_channel_membership(channel.clone(), server.clone(), me.clone()).await;
                let named = client.list_channels(server.clone()).await.map(|c| c.iter().filter(|c| c.name.is_some()).count()).unwrap_or(0);
                let rows = client.fetch_channel_messages(channel.clone(), me.clone()).await.unwrap_or_default();
                let decrypted = rows.iter().filter(|m| m.content.is_some() && m.author_id.as_deref() != Some("__system__")).count();
                let line = format!("GHOST members={} channels_named={named} messages={} decrypted={decrypted}", members.len(), rows.len());
                if line != last {
                    println!("{line}");
                    last = line;
                }
            }
        }
        _ => {
            eprintln!("unknown mode {mode:?}: link | device2 | ghost");
            std::process::exit(2);
        }
    }
}
