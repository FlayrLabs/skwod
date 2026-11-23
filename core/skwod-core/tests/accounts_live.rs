//! Build 44a — accounts, devices and recovery — through the `SkwodClient` surface the apps use,
//! against a REAL skwod-server:
//!
//! - a second device is linked, named and listed; removed from the first, it is signed out,
//!   cannot post even after signing in again, and the rest of the space moves on without it;
//! - signing out and back in on the same install is the same device — no re-link;
//! - a password change needs the old password and ends every other session;
//! - a reset on an account with a PIN is a typed `PinRequired`; a forgotten PIN is the 7-day hold;
//! - a restore (here with the PIN) supersedes the install it was restored from, which stops with
//!   a clear error; the restored device asks for what it cannot read and its peers send it again
//!   — channel history and a direct message that was sealed for the lost session;
//! - a cache that does not open under its key is set aside, not looped on.
//!
//! Skips gracefully if the server can't build.

use std::process::{Child, Command};
use std::sync::Once;
use std::time::Duration;

use skwod_core::{CoreError, DeviceState, SkwodClient};
use skwod_sync::ApiClient;

static BUILD: Once = Once::new();

fn server_manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/Cargo.toml")
}
fn build_server() -> bool {
    // `SKWOD_TEST_SERVER_BIN=<path>` runs the tests against an already-built server binary
    // (e.g. the release one) instead of building a debug one here.
    if std::env::var_os("SKWOD_TEST_SERVER_BIN").is_some() {
        return true;
    }
    let mut ok = true;
    BUILD.call_once(|| {
        let status = Command::new("cargo").args(["build", "--quiet", "--bin", "skwod", "--manifest-path"]).arg(server_manifest()).status();
        ok = matches!(status, Ok(s) if s.success());
    });
    ok
}
fn server_bin() -> std::path::PathBuf {
    if let Some(bin) = std::env::var_os("SKWOD_TEST_SERVER_BIN") {
        return bin.into();
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/target/debug/skwod")
}

struct ServerGuard {
    child: Child,
    _dir: tempfile::TempDir,
    base: String,
}
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn start() -> Option<ServerGuard> {
    if !build_server() {
        eprintln!("SKIP: could not build skwod-server");
        return None;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(server_bin())
        .args(["run", "--listen", &format!("127.0.0.1:{port}"), "--data"])
        .arg(dir.path())
        .env("SKWOD_OPEN_SIGNUP", "1")
        .env("SKWOD_NO_P2P", "true")
        // The machine running the tests may itself be short of disk; that floor is tested in
        // the server's own suite.
        .env("SKWOD_BLOB_FREE_FLOOR_MB", "0")
        .spawn()
        .ok()?;
    let guard = ServerGuard { child, _dir: dir, base: format!("http://127.0.0.1:{port}") };
    let http = reqwest::Client::new();
    for _ in 0..600 {
        if http.get(format!("{}/health", guard.base)).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            return Some(guard);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server never became healthy");
}

fn key(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

/// A session of its own for each install: a session speaks for one device (the one it
/// registered or bound), so two clients must never share a token.
async fn fresh_token(base: &str, username: &str, password: &str) -> String {
    ApiClient::new(base).login(username, password).await.expect("login").token
}


const PASSWORD: &str = "password123";
/// Let the account's recovery key age past the 7-day hold (only then does a restore with it
/// complete at once). Done on the server's database, as time would.
fn season_recovery_key(server: &ServerGuard) {
    let status = Command::new("sqlite3")
        .arg(server._dir.path().join("skwod.db"))
        .arg("UPDATE backup_keys SET set_at = 1 WHERE retired_at IS NULL")
        .status()
        .expect("sqlite3 (to age the recovery key)");
    assert!(status.success());
}


/// One install: its own session, its own cache, a name.
async fn install(server: &ServerGuard, caches: &tempfile::TempDir, user: &str, file: &str, k: char, label: &str) -> std::sync::Arc<SkwodClient> {
    let client = SkwodClient::new(server.base.clone(), fresh_token(&server.base, user, PASSWORD).await);
    client.attach_cache(caches.path().join(file).to_string_lossy().to_string(), key(k)).await.expect("attach");
    client.set_device_label(label.into()).await;
    client
}

struct Pair {
    server: ServerGuard,
    caches: tempfile::TempDir,
    alice: String,
    bob: String,
    phone: std::sync::Arc<SkwodClient>,
    phone_dev: String,
    bobs: std::sync::Arc<SkwodClient>,
    server_id: String,
    channel: String,
}

/// Alice (one phone) owns a space; Bob is in it; both hold each other's channel keys.
async fn pair() -> Option<Pair> {
    let server = start().await?;
    let caches = tempfile::tempdir().unwrap();
    let a = ApiClient::new(&server.base).signup("alice", PASSWORD).await.expect("signup alice");
    let b = ApiClient::new(&server.base).signup("bobby", PASSWORD).await.expect("signup bob");
    let phone = install(&server, &caches, "alice", "phone.sqlite3", 'a', "Alice's phone").await;
    let phone_dev = phone.register_device().await.expect("register phone");
    let space = phone.create_space("Crew".into(), "general".into()).await.expect("space");
    let bobs = install(&server, &caches, "bobby", "bob.sqlite3", 'c', "Bob's phone").await;
    bobs.register_device().await.expect("register bob");
    let invite = phone.invite_to_space(space.server_id.clone(), "code".into(), None).await.unwrap();
    assert!(bobs.join_by_code(invite).await.unwrap().pending);
    phone.approve_join_request(space.server_id.clone(), b.user_id.clone()).await.unwrap();
    phone.approve_member(space.server_id.clone(), b.user_id.clone()).await.unwrap();
    let p = Pair { server, caches, alice: a.user_id, bob: b.user_id, phone, phone_dev, bobs, server_id: space.server_id, channel: space.channel_id };
    settle(&[(&p.phone, &p.alice), (&p.bobs, &p.bob)]).await;
    for (c, me) in [(&p.phone, &p.alice), (&p.bobs, &p.bob)] {
        c.sync_channel_membership(p.channel.clone(), p.server_id.clone(), me.clone()).await.expect("share channel key");
    }
    settle(&[(&p.phone, &p.alice), (&p.bobs, &p.bob)]).await;
    Some(p)
}

/// Let sealed mail (keys, resets, retry requests and their answers) settle.
async fn settle(clients: &[(&std::sync::Arc<SkwodClient>, &String)]) {
    for _ in 0..3 {
        for (c, me) in clients {
            let _ = c.process_control_inbox((*me).clone()).await;
        }
    }
}

async fn texts(c: &SkwodClient, channel: &str, me: &str) -> Vec<String> {
    let _ = c.fetch_channel_messages(channel.into(), me.into()).await;
    c.history(format!("channel:{channel}")).await.into_iter().filter_map(|m| m.content).collect()
}

fn is_placeholder(t: &str) -> bool {
    t.starts_with("\u{2}skwod/undecryptable|")
}

async fn link(p: &Pair, file: &str, k: char, label: &str) -> (std::sync::Arc<SkwodClient>, String) {
    let mac = install(&p.server, &p.caches, "alice", file, k, label).await;
    assert!(matches!(mac.register_device().await, Err(CoreError::LinkRequired { .. })));
    let code = mac.begin_device_link().await.expect("begin link");
    assert!(p.phone.approve_device_link(code).await.expect("approve link"));
    let dev = mac.complete_device_link().await.expect("complete").expect("approved");
    settle(&[(&p.phone, &p.alice), (&mac, &p.alice)]).await;
    (mac, dev)
}

#[tokio::test]
async fn a_linked_device_is_listed_named_and_once_removed_cannot_post() {
    let Some(p) = pair().await else { return };
    p.bobs.send_channel_message(p.channel.clone(), "said before the mac existed".into()).await.expect("bob posts early");
    let (mac, mac_dev) = link(&p, "mac.sqlite3", 'b', "Alice's Mac").await;

    // The new device got the space key WITH the approval (it reads names before anything
    // sealed could have reached it), and its sibling set — nobody had to provision it.
    assert_eq!(mac.server_name(p.server_id.clone()).await.unwrap().as_deref(), Some("Crew"));
    // (Bob's app re-reads Alice's devices when it hears of the new one.)
    p.bobs.refresh_devices_of(p.alice.clone()).await.expect("bob learns of the mac");
    mac.sync_channel_membership(p.channel.clone(), p.server_id.clone(), p.alice.clone()).await.expect("mac shares its key");
    settle(&[(&p.phone, &p.alice), (&mac, &p.alice), (&p.bobs, &p.bob)]).await;
    mac.send_channel_message(p.channel.clone(), "from the mac".into()).await.expect("mac posts");
    assert!(texts(&p.bobs, &p.channel, &p.bob).await.contains(&"from the mac".to_string()));
    // What was said before the Mac was let in was never the Mac's to read: it is neither
    // shown as a failure nor asked for again (a retry request is not a way into old history).
    p.bobs.send_channel_message(p.channel.clone(), "said after".into()).await.unwrap();
    settle(&[(&mac, &p.alice), (&p.bobs, &p.bob)]).await;
    let mac_sees = texts(&mac, &p.channel, &p.alice).await;
    settle(&[(&mac, &p.alice), (&p.bobs, &p.bob)]).await;
    let mac_sees_later = texts(&mac, &p.channel, &p.alice).await;
    assert!(mac_sees.contains(&"said after".to_string()), "{mac_sees:?}");
    assert!(!mac_sees_later.iter().any(|t| t == "said before the mac existed" || is_placeholder(t)), "{mac_sees_later:?}");

    // The devices screen: both, with the names only this account can read, "this device", 5 max.
    let list = p.phone.list_devices().await.expect("list");
    assert_eq!(list.max_devices, 5);
    let mut rows: Vec<(Option<String>, bool, bool)> = list.devices.iter().map(|d| (d.name.clone(), d.is_this_device, d.verified)).collect();
    rows.sort();
    assert_eq!(rows, [(Some("Alice's Mac".to_string()), false, true), (Some("Alice's phone".to_string()), true, true)]);
    assert!(list.devices.iter().all(|d| d.created_at > 0 && d.last_active_at > 0));
    let from_mac = mac.list_devices().await.expect("list on mac");
    assert!(from_mac.devices.iter().any(|d| d.is_this_device && d.device_id == mac_dev && d.name.as_deref() == Some("Alice's Mac")));
    mac.rename_device("Studio Mac".into()).await.expect("rename");
    assert!(p.phone.list_devices().await.unwrap().devices.iter().any(|d| d.name.as_deref() == Some("Studio Mac")));

    // Remove it from the phone.
    p.phone.unregister_device(mac_dev.clone()).await.expect("remove the mac");
    assert_eq!(p.phone.list_devices().await.unwrap().devices.len(), 1);
    // Its session is over…
    assert_eq!(mac.session_state().await, skwod_core::SessionState::SignedOut);
    assert!(mac.send_channel_message(p.channel.clone(), "still here?".into()).await.is_err());
    // …and signing in again on that install does not bring the device back: it still holds
    // its keys, and the server will have none of it.
    let again = install(&p.server, &p.caches, "alice", "mac.sqlite3", 'b', "Alice's Mac").await;
    assert_eq!(again.current_device_id().await.as_deref(), Some(mac_dev.as_str()), "(same cache, same identity)");
    assert!(matches!(again.sync_dms().await, Err(CoreError::DeviceRemoved { .. })));
    assert!(matches!(again.send_channel_message(p.channel.clone(), "sneaking back".into()).await, Err(CoreError::DeviceRemoved { .. })));
    assert_eq!(again.device_state().await, DeviceState::Removed);

    // Everyone else moves on: Bob re-reads Alice's devices (the `device_removed` event), the
    // phone's key for the channel rotates, and what is said next the removed Mac never gets.
    p.bobs.refresh_devices_of(p.alice.clone()).await.expect("bob refreshes");
    p.phone.send_channel_message(p.channel.clone(), "after the mac left".into()).await.expect("phone posts");
    settle(&[(&p.phone, &p.alice), (&p.bobs, &p.bob)]).await;
    let seen = texts(&p.bobs, &p.channel, &p.bob).await;
    assert!(seen.contains(&"after the mac left".to_string()), "{seen:?}");
    assert!(!seen.iter().any(|t| t == "still here?" || t == "sneaking back"));
    p.bobs.send_channel_message(p.channel.clone(), "bob after".into()).await.expect("bob posts");
    settle(&[(&p.phone, &p.alice), (&p.bobs, &p.bob)]).await;
    assert!(texts(&p.phone, &p.channel, &p.alice).await.contains(&"bob after".to_string()));
}

#[tokio::test]
async fn signing_out_and_back_in_is_the_same_device() {
    let Some(p) = pair().await else { return };
    p.phone.send_channel_message(p.channel.clone(), "before".into()).await.unwrap();
    let before = texts(&p.phone, &p.channel, &p.alice).await;

    // "Sign out": the session ends. Nothing on the device is touched.
    let old = ApiClient::new(&p.server.base).login("alice", PASSWORD).await.unwrap();
    ApiClient::new(&p.server.base).with_token(old.token).post("/api/auth/logout", serde_json::json!({})).await.unwrap();
    drop(p.phone.clone());

    // "Sign back in": a new session on the same cache. The identity is restored from it, the
    // session is bound to the same device by that device's own key — no link, no new device row.
    let back = SkwodClient::new(p.server.base.clone(), fresh_token(&p.server.base, "alice", PASSWORD).await);
    let restored = back.attach_cache(p.caches.path().join("phone.sqlite3").to_string_lossy().to_string(), key('a')).await.expect("attach");
    assert!(restored, "the identity is still there");
    assert_eq!(back.current_device_id().await.as_deref(), Some(p.phone_dev.as_str()));
    assert_eq!(back.device_state().await, DeviceState::Active);
    back.process_control_inbox(p.alice.clone()).await.expect("mailbox works at once");
    let list = back.list_devices().await.unwrap();
    assert_eq!(list.devices.len(), 1, "no second device appeared");
    assert!(list.devices[0].is_this_device);
    assert_eq!(texts(&back, &p.channel, &p.alice).await, before, "history is still on the device");
    back.send_channel_message(p.channel.clone(), "after signing back in".into()).await.expect("and it can post");
    settle(&[(&back, &p.alice), (&p.bobs, &p.bob)]).await;
    assert!(texts(&p.bobs, &p.channel, &p.bob).await.contains(&"after signing back in".to_string()));
}

#[tokio::test]
async fn a_password_change_ends_other_sessions_and_a_reset_with_a_pin_is_typed() {
    let Some(p) = pair().await else { return };
    let other = ApiClient::new(&p.server.base).login("alice", PASSWORD).await.unwrap();
    let other_api = ApiClient::new(&p.server.base).with_token(other.token);
    assert!(other_api.get("/api/auth/me").await.is_ok());

    assert!(p.phone.change_password("not the password".into(), "a much better one".into()).await.is_err());
    assert!(other_api.get("/api/auth/me").await.is_ok(), "a failed change ends nothing");
    p.phone.change_password(PASSWORD.into(), "a much better one".into()).await.expect("change");
    assert!(matches!(other_api.get("/api/auth/me").await, Err(skwod_sync::ClientError::Status { status: 401, .. })), "every other session is over");
    assert_eq!(p.phone.session_state().await, skwod_core::SessionState::Valid, "this device carries on");
    assert!(ApiClient::new(&p.server.base).login("alice", PASSWORD).await.is_err(), "the old password is dead");

    // A PIN on the account; then someone who has lost everything signs in and asks to reset.
    p.phone.set_registration_pin(Some("482913".into()), None).await.expect("set pin");
    let lost = SkwodClient::new(p.server.base.clone(), ApiClient::new(&p.server.base).login("alice", "a much better one").await.unwrap().token);
    lost.attach_cache(p.caches.path().join("lost.sqlite3").to_string_lossy().to_string(), key('d')).await.unwrap();
    assert!(matches!(lost.register_device().await, Err(CoreError::LinkRequired { .. })));
    assert!(matches!(lost.reset_devices(None).await, Err(CoreError::PinRequired { .. })), "typed: the app shows the PIN screen");
    match lost.reset_devices(Some("000000".into())).await {
        Err(CoreError::PinIncorrect { attempts_left, .. }) => assert_eq!(attempts_left, 4),
        other => panic!("expected PinIncorrect, got {other:?}"),
    }
    // Forgotten: the same 7-day hold as an account without a PIN — and the live device vetoes it.
    assert!(matches!(lost.reset_devices_forgot_pin().await, Err(CoreError::ResetPending { .. })));
    assert_eq!(lost.device_state().await, DeviceState::Unregistered);
    p.phone.refresh_own_devices().await.unwrap();
    assert!(p.phone.take_security_notices().await.iter().any(|n| n.kind == "reset_blocked"));
    assert_eq!(p.phone.list_devices().await.unwrap().devices.len(), 1, "nothing was removed");
}

#[tokio::test]
async fn a_restore_stops_the_old_install_and_peers_send_again_what_it_cannot_read() {
    let Some(p) = pair().await else { return };
    p.phone.send_channel_message(p.channel.clone(), "alice one".into()).await.unwrap();
    p.bobs.send_channel_message(p.channel.clone(), "bob one".into()).await.unwrap();
    p.bobs.send_channel_message(p.channel.clone(), "bob two".into()).await.unwrap();
    let dm = p.bobs.open_dm(p.alice.clone()).await.unwrap();
    p.bobs.send_dm(dm.clone(), p.alice.clone(), p.phone_dev.clone(), "hi alice".into()).await.unwrap();
    settle(&[(&p.phone, &p.alice), (&p.bobs, &p.bob)]).await;
    assert!(texts(&p.phone, &p.channel, &p.alice).await.contains(&"bob two".to_string()));
    p.phone.verify_contact(p.bob.clone(), p.phone.safety_number(p.alice.clone(), p.bob.clone(), String::new()).await.unwrap()).await.expect("alice verifies bob");
    let recovery_key = skwod_core::generate_recovery_key();
    p.phone.enable_key_backup(recovery_key.clone()).await.expect("backup");

    // (The recovery key has been in place for a week: only a seasoned key skips the wait.)
    season_recovery_key(&p.server);
    // The phone is "lost". A new install restores from the recovery key: proving the key to the
    // server is enough — it completes at once (no PIN, no approval, no 7-day wait).
    let restored = install(&p.server, &p.caches, "alice", "restored.sqlite3", 'e', "Alice's new phone").await;
    assert!(restored.restore_key_backup(recovery_key.clone()).await.expect("restore with the recovery key"));
    assert_eq!(restored.current_device_id().await.as_deref(), Some(p.phone_dev.as_str()), "same device, same safety number");
    assert!(restored.key_backup_enabled().await);
    // Trust state came back with it: the space (and its owner pin), and Bob still verified.
    assert_eq!(restored.server_name(p.server_id.clone()).await.unwrap().as_deref(), Some("Crew"));
    assert_eq!(restored.space_owner(p.server_id.clone()).await.as_deref(), Some(p.alice.as_str()));
    assert!(restored.contact_status(p.bob.clone()).await.verified, "the verified mark survived the restore");

    // The original is still running. It stops, with a reason — it is not a second copy of the device.
    let stopped = p.phone.process_control_inbox(p.alice.clone()).await;
    assert!(matches!(stopped, Err(CoreError::DeviceSuperseded { .. })), "{stopped:?}");
    assert!(matches!(p.phone.send_channel_message(p.channel.clone(), "from the old install".into()).await, Err(CoreError::DeviceSuperseded { .. })));
    assert_eq!(p.phone.device_state().await, DeviceState::Superseded);

    // Bob does not know yet and seals a DM for the session the lost phone had.
    p.bobs.send_dm(dm.clone(), p.alice.clone(), p.phone_dev.clone(), "are you back?".into()).await.expect("bob sends on the old session");
    let _ = restored.sync_dms().await;
    let shown = restored.history(format!("dm:{dm}")).await;
    assert!(shown.iter().any(|m| m.content.as_deref().is_some_and(is_placeholder)), "a visible placeholder, not silence: {shown:?}");
    // The channel: Bob's earlier messages cannot be read with keys that are gone — placeholders.
    let first = texts(&restored, &p.channel, &p.alice).await;
    assert!(first.iter().filter(|t| is_placeholder(t)).count() >= 2, "{first:?}");

    // Bob's device answers the reset and the retry requests…
    settle(&[(&p.bobs, &p.bob), (&restored, &p.alice)]).await;
    // …and everything is readable again.
    let dms: Vec<String> = restored.history(format!("dm:{dm}")).await.into_iter().filter_map(|m| m.content).collect();
    assert!(dms.contains(&"are you back?".to_string()) && !dms.iter().any(|t| is_placeholder(t)), "the DM was sent again and replaced its placeholder: {dms:?}");
    let now = texts(&restored, &p.channel, &p.alice).await;
    assert!(now.contains(&"bob one".to_string()) && now.contains(&"bob two".to_string()), "channel history was sent again: {now:?}");
    // What Alice herself wrote from the lost phone was sealed under this device id with keys
    // that are gone: nobody can send it again, so it stays — as a FINAL placeholder, not as a
    // hole. Nothing else is a placeholder any more.
    let left: Vec<&String> = now.iter().filter(|t| is_placeholder(t)).collect();
    assert_eq!(left.len(), 1, "{now:?}");
    assert!(left[0].contains("\"final\":true") && left[0].contains(p.alice.as_str()), "{left:?}");
    // New traffic flows both ways on fresh keys.
    restored.sync_channel_membership(p.channel.clone(), p.server_id.clone(), p.alice.clone()).await.expect("restored shares a new key");
    restored.send_channel_message(p.channel.clone(), "alice is back".into()).await.expect("restored posts");
    p.bobs.send_channel_message(p.channel.clone(), "welcome back".into()).await.expect("bob posts");
    settle(&[(&p.bobs, &p.bob), (&restored, &p.alice)]).await;
    assert!(texts(&p.bobs, &p.channel, &p.bob).await.contains(&"alice is back".to_string()));
    assert!(texts(&restored, &p.channel, &p.alice).await.contains(&"welcome back".to_string()));
    assert_eq!(p.bobs.retry_deliveries().await, 0, "nothing is still owed to a device");
}

#[tokio::test]
async fn a_cache_that_will_not_open_is_set_aside_and_nothing_registers_without_one() {
    let Some(p) = pair().await else { return };
    let path = p.caches.path().join("phone.sqlite3").to_string_lossy().to_string();
    // The key is gone (a new one was minted): the cache does not open under it.
    let client = SkwodClient::new(p.server.base.clone(), fresh_token(&p.server.base, "alice", PASSWORD).await);
    let restored = client.attach_cache(path.clone(), key('f')).await.expect("attach does not fail on every launch");
    assert!(!restored, "no device was restored from it");
    assert!(client.cache_was_reset().await.is_some(), "and the app can say what happened");
    assert!(std::path::Path::new(&format!("{path}.unreadable")).exists(), "the old file is kept, aside");
    // A second launch is quiet: the fresh cache opens.
    let again = SkwodClient::new(p.server.base.clone(), fresh_token(&p.server.base, "alice", PASSWORD).await);
    drop(client);
    assert!(!again.attach_cache(path, key('f')).await.unwrap());
    // The account has a device, so this install must link / restore / reset — never a silent new one.
    assert!(matches!(again.register_device().await, Err(CoreError::LinkRequired { .. })));

    // And with no cache at all, nothing that creates a device goes ahead.
    let bare = SkwodClient::new(p.server.base.clone(), fresh_token(&p.server.base, "bobby", PASSWORD).await);
    assert!(matches!(bare.register_device().await, Err(CoreError::Cache { .. })));
    assert!(matches!(bare.begin_device_link().await, Err(CoreError::Cache { .. })));
    assert!(matches!(bare.reset_devices(None).await, Err(CoreError::Cache { .. })));
}

#[tokio::test]
async fn erase_then_restore_brings_the_device_back_and_an_erase_says_when_it_is_unsafe() {
    let Some(p) = pair().await else { return };
    p.bobs.send_channel_message(p.channel.clone(), "bob before the erase".into()).await.unwrap();
    settle(&[(&p.phone, &p.alice), (&p.bobs, &p.bob)]).await;
    let _ = texts(&p.phone, &p.channel, &p.alice).await;

    // No backup, no other device: erasing would leave only the 7-day reset. The gate says so.
    let check = p.phone.erase_check().await.expect("check");
    assert!(!check.safe && !check.has_key_backup && check.other_devices == 0);
    let recovery_key = skwod_core::generate_recovery_key();
    p.phone.enable_key_backup(recovery_key.clone()).await.expect("backup");
    assert!(p.phone.erase_check().await.unwrap().safe, "with a recovery key saved it is safe");
    // The app can say when the key becomes instant: a week after it was saved — straight
    // after saving it, with no refresh in between (the "Recovery key saved" screen).
    let instant_from = p.phone.recovery_key_instant_from().await.expect("a recovery key is on record");
    assert!(instant_from > (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64) + 6 * 24 * 3_600_000);
    season_recovery_key(&p.server);

    // "Erase this device": unregistered on the server, nothing left on disk.
    let path = p.caches.path().join("phone.sqlite3");
    p.phone.erase_device(false).await.expect("erase");
    // Bob's app hears `device_removed` and re-reads Alice's devices. The phone had TOLD him it
    // was erasing itself; that only counts now that the server's record agrees (the device is
    // gone and recorded as self-erased) — a claim from a device still listed is ignored.
    settle(&[(&p.bobs, &p.bob)]).await;
    p.bobs.refresh_devices_of(p.alice.clone()).await.expect("bob re-reads alice's devices after the erase");
    assert!(!path.exists(), "the cache is gone");
    let fresh = install(&p.server, &p.caches, "alice", "phone.sqlite3", 'a', "Alice's phone").await;
    assert_eq!(fresh.device_state().await, DeviceState::Unregistered);
    assert!(matches!(fresh.register_device().await, Err(CoreError::LinkRequired { .. })), "the account has had a device: no silent new one");

    // Restore with the recovery key: the erased device's row is gone, so the restored identity
    // comes back as a device of its own — at once.
    assert!(matches!(fresh.restore_key_backup("not the recovery key at all".into()).await, Err(CoreError::Invalid { .. })));
    assert!(fresh.restore_key_backup(recovery_key).await.expect("restore after erase"));
    assert_eq!(fresh.device_state().await, DeviceState::Active);
    let new_dev = fresh.current_device_id().await.expect("registered");
    assert_ne!(new_dev, p.phone_dev, "a fresh device row");
    assert_eq!(fresh.server_name(p.server_id.clone()).await.unwrap().as_deref(), Some("Crew"), "space keys came back");
    let list = fresh.list_devices().await.unwrap();
    assert_eq!((list.devices.len(), list.devices[0].is_this_device), (1, true));

    // Bob accepts it as Alice's device: the same identity key he already trusted, and the phone
    // TOLD him it was erasing itself before it went (a device Alice had removed would not be
    // taken back like this). He is shown that she is on a new device.
    settle(&[(&p.bobs, &p.bob)]).await;
    let _ = p.bobs.take_security_notices().await;
    p.bobs.refresh_devices_of(p.alice.clone()).await.expect("bob re-reads alice's devices");
    assert!(p.bobs.take_security_notices().await.iter().any(|n| n.kind == "new_device" && n.user_id == p.alice && n.device_id == new_dev), "a visible notice");
    assert_eq!(p.bobs.contact_status(p.alice.clone()).await.unvouched_devices, 0, "not a stranger's device");
    fresh.sync_channel_membership(p.channel.clone(), p.server_id.clone(), p.alice.clone()).await.expect("alice shares a key");
    settle(&[(&fresh, &p.alice), (&p.bobs, &p.bob)]).await;
    fresh.send_channel_message(p.channel.clone(), "alice after the restore".into()).await.expect("alice posts");
    p.bobs.send_channel_message(p.channel.clone(), "bob after the restore".into()).await.expect("bob posts");
    settle(&[(&fresh, &p.alice), (&p.bobs, &p.bob)]).await;
    assert!(texts(&p.bobs, &p.channel, &p.bob).await.contains(&"alice after the restore".to_string()));
    let _ = texts(&fresh, &p.channel, &p.alice).await;
    settle(&[(&fresh, &p.alice), (&p.bobs, &p.bob)]).await;
    let seen = texts(&fresh, &p.channel, &p.alice).await;
    assert!(seen.contains(&"bob after the restore".to_string()), "{seen:?}");
}

/// Restore by approval, end to end, on a build-45 server. The recovery key is minutes old, so
/// the server does not hand its backup to a new sign-in; the new install ASKS to restore it
/// (`POST /key-backup/request`), the account's other device is shown that request — the device
/// it is about and the same short code — and its approval is for exactly the request shown.
/// A request another install files beside it is a separate request with its own code; once the
/// owner's request is approved the others are over, the backup is handed over and the restore
/// completes.
#[tokio::test]
async fn a_restore_without_the_recovery_key_waits_and_an_approval_is_for_the_request_shown() {
    let Some(p) = pair().await else { return };
    let (mac, _mac_dev) = link(&p, "mac.sqlite3", 'b', "Alice's Mac").await;
    let recovery_key = skwod_core::generate_recovery_key();
    p.phone.enable_key_backup(recovery_key.clone()).await.expect("backup");
    // The recovery key was saved a moment ago. It opens the backup and proves itself — but a
    // key that young does not skip the wait (it could have been planted): approval it is.
    let restorer = install(&p.server, &p.caches, "alice", "restorer.sqlite3", 'e', "Alice's new phone").await;
    assert!(matches!(restorer.restore_key_backup(recovery_key.clone()).await, Err(CoreError::RecoveryPending { .. })));
    assert_eq!(restorer.device_state().await, DeviceState::RecoveryPending);
    // Alone, it may complete by the hold: the waiting screen shows the countdown.
    assert!(!restorer.recovery_contested().await);
    assert!(restorer.recovery_completes_at().await.is_some(), "uncontested: a countdown");
    let code = restorer.recovery_fingerprint().await;

    // The Mac is shown the request: which device, its id, and the same short code.
    mac.refresh_own_devices().await.unwrap();
    let notice = mac.take_security_notices().await.into_iter().find(|n| n.kind == "recovery_requested").expect("the mac is told");
    assert_eq!((notice.device_id.as_str(), notice.fingerprint.as_deref()), (p.phone_dev.as_str(), Some(code.as_str())));
    let shown = notice.request_id.clone().expect("request id");

    // Before the user taps "approve", another install asks too (server audit L1): its request is
    // filed BESIDE the owner's, with its own id and code, and is a notice of its own.
    let attacker = install(&p.server, &p.caches, "alice", "attacker.sqlite3", 'f', "?").await;
    let filed = attacker.restore_key_backup(recovery_key.clone()).await;
    assert!(matches!(&filed, Err(CoreError::RecoveryPending { detail }) if detail.contains("waiting for approval")), "{filed:?}");
    // Both requests are contested now: neither promises the hold, both wait for an approval.
    assert!(attacker.recovery_contested().await && attacker.recovery_completes_at().await.is_none());
    assert!(matches!(restorer.retry_restore(None).await, Err(CoreError::RecoveryPending { .. })));
    assert!(restorer.recovery_contested().await, "the first request is contested too");
    assert_eq!(restorer.recovery_completes_at().await, None, "no countdown for a contested request");
    mac.refresh_own_devices().await.unwrap();
    let other = mac.take_security_notices().await.into_iter().find(|n| n.kind == "recovery_requested").expect("a notice for the second request");
    assert_ne!(other.request_id.as_deref(), Some(shown.as_str()));
    assert_eq!(other.fingerprint.as_deref(), Some(attacker.recovery_fingerprint().await.as_str()));
    assert_ne!(other.fingerprint.as_deref(), Some(code.as_str()), "each request shows its own install's code");
    // The app is relaunched while it waits (the key given earlier is gone with the process):
    // it promises no countdown before the server has answered, and asking again says the
    // request is still contested.
    drop(restorer);
    let restorer = install(&p.server, &p.caches, "alice", "restorer.sqlite3", 'e', "Alice's new phone").await;
    assert_eq!(restorer.device_state().await, DeviceState::RecoveryPending);
    assert_eq!(restorer.recovery_completes_at().await, None, "not known yet after a relaunch");
    assert!(matches!(restorer.retry_restore(None).await, Err(CoreError::RecoveryPending { .. })), "still waiting after a relaunch");
    assert!(restorer.recovery_contested().await && restorer.recovery_completes_at().await.is_none(), "contested after a relaunch too");
    // The tap is for what was shown — the owner's — and it lands; the other request is over.
    mac.approve_recovery(p.phone_dev.clone(), shown.clone()).await.expect("approve what is shown");
    assert!(mac.approve_recovery(p.phone_dev.clone(), other.request_id.clone().unwrap()).await.is_err(), "the other request is gone");
    // The other install gets nothing — and is told why, in the server's words.
    let refused = attacker.retry_restore(None).await;
    assert!(matches!(&refused, Err(CoreError::Invalid { detail }) if detail.contains("already approved")), "{refused:?}");
    // Relaunched since, the approved install is asked for its key again, then completes.
    let again = restorer.retry_restore(None).await;
    assert!(matches!(&again, Err(CoreError::Invalid { detail }) if detail == skwod_core::RESTORE_APPROVED_KEY_AGAIN), "{again:?}");
    assert!(restorer.restore_key_backup(recovery_key.clone()).await.expect("completes once approved"));
    assert!(matches!(p.phone.process_control_inbox(p.alice.clone()).await, Err(CoreError::DeviceSuperseded { .. })));
    mac.refresh_own_devices().await.unwrap();
    assert!(mac.take_security_notices().await.iter().any(|n| n.kind == "account_restored" && n.device_id == p.phone_dev), "the other devices are told");
}

/// The same request with nobody answering: every device was told, none refused, and when the
/// 7-day hold has run out the restore completes by itself — not before.
#[tokio::test]
async fn a_restore_nobody_answers_completes_when_the_hold_has_run_out() {
    let Some(p) = pair().await else { return };
    let recovery_key = skwod_core::generate_recovery_key();
    p.phone.enable_key_backup(recovery_key.clone()).await.expect("backup");
    let restorer = install(&p.server, &p.caches, "alice", "restorer.sqlite3", 'e', "Alice's new phone").await;
    assert!(matches!(restorer.restore_key_backup(recovery_key.clone()).await, Err(CoreError::RecoveryPending { .. })));
    assert_eq!(restorer.device_state().await, DeviceState::RecoveryPending);
    // The phone is told, and goes on working meanwhile.
    p.phone.refresh_own_devices().await.unwrap();
    assert!(p.phone.take_security_notices().await.iter().any(|n| n.kind == "recovery_requested" && n.device_id == p.phone_dev));
    assert!(matches!(restorer.retry_restore(None).await, Err(CoreError::RecoveryPending { .. })), "still waiting");
    p.phone.process_control_inbox(p.alice.clone()).await.expect("the phone is untouched while it waits");
    // Seven days later (the request is aged in the server's database; the key stays young).
    let aged = std::process::Command::new("sqlite3").arg(p.server._dir.path().join("skwod.db")).arg("UPDATE device_recoveries SET requested_at = 1").status().expect("sqlite3");
    assert!(aged.success());
    assert!(restorer.retry_restore(None).await.expect("completes once the hold has run out"));
    assert_eq!(restorer.device_state().await, DeviceState::Active);
    assert_eq!(restorer.current_device_id().await.as_deref(), Some(p.phone_dev.as_str()));
    assert!(matches!(p.phone.process_control_inbox(p.alice.clone()).await, Err(CoreError::DeviceSuperseded { .. })));
}

/// A device that is moved to another install and then moved BACK (restore on a new phone, then
/// restore on the old one again) has a gap: what was written while the device lived elsewhere.
/// None of it may be silently absent on the first install — a contact's messages are asked for
/// again, and what the account itself wrote from the other install (same device id, keys that
/// are gone) is shown as a placeholder.
#[tokio::test]
async fn messages_written_while_the_device_lived_on_another_install_are_never_silently_missing() {
    let Some(p) = pair().await else { return };
    p.phone.send_channel_message(p.channel.clone(), "alice before".into()).await.unwrap();
    p.bobs.send_channel_message(p.channel.clone(), "bob before".into()).await.unwrap();
    settle(&[(&p.phone, &p.alice), (&p.bobs, &p.bob)]).await;
    assert!(texts(&p.phone, &p.channel, &p.alice).await.contains(&"bob before".to_string()));
    let recovery_key = skwod_core::generate_recovery_key();
    p.phone.enable_key_backup(recovery_key.clone()).await.expect("backup");
    season_recovery_key(&p.server);

    // The device moves to a second install, which takes part for a while.
    let other = install(&p.server, &p.caches, "alice", "other.sqlite3", 'e', "Alice's other phone").await;
    assert!(other.restore_key_backup(recovery_key.clone()).await.expect("restore on the other install"));
    assert!(matches!(p.phone.process_control_inbox(p.alice.clone()).await, Err(CoreError::DeviceSuperseded { .. })));
    settle(&[(&p.bobs, &p.bob), (&other, &p.alice)]).await;
    other.sync_channel_membership(p.channel.clone(), p.server_id.clone(), p.alice.clone()).await.expect("the other install shares a key");
    settle(&[(&p.bobs, &p.bob), (&other, &p.alice)]).await;
    let from_other = other.send_channel_message(p.channel.clone(), "alice from the other install".into()).await.expect("the other install posts");
    let from_bob = p.bobs.send_channel_message(p.channel.clone(), "bob while alice was moved".into()).await.expect("bob posts");
    settle(&[(&p.bobs, &p.bob), (&other, &p.alice)]).await;
    assert!(texts(&other, &p.channel, &p.alice).await.contains(&"bob while alice was moved".to_string()));
    // The stopped install keeps looking (the app's timers do not know yet).
    let _ = texts(&p.phone, &p.channel, &p.alice).await;

    // The device moves back: the first install sets up again and restores with the same key.
    // Its old session is bound to the superseded install and fetches nothing (not even the
    // backup), so — as in the apps — it signs in again first, on the same cache.
    p.phone.forget_registration().await;
    let phone = install(&p.server, &p.caches, "alice", "phone.sqlite3", 'a', "Alice's phone").await;
    assert!(phone.restore_key_backup(recovery_key.clone()).await.expect("restore back on the first install"));
    assert_eq!(phone.device_state().await, DeviceState::Active);
    let _ = texts(&phone, &p.channel, &p.alice).await;
    settle(&[(&p.bobs, &p.bob), (&phone, &p.alice)]).await;
    let _ = phone.fetch_channel_messages(p.channel.clone(), p.alice.clone()).await;
    let rows = phone.history(format!("channel:{}", p.channel)).await;
    let row = |id: &str| rows.iter().find(|m| m.message_id == id);
    let summary: Vec<(String, Option<String>)> = rows.iter().map(|m| (m.message_id.clone(), m.content.clone())).collect();
    // Bob's message: there — read (sent again) or as a placeholder still waiting for that.
    assert!(row(&from_bob).is_some(), "bob's message from the gap is missing altogether: {summary:?}");
    // The account's own message from the other install: a placeholder, marked as one.
    let own = row(&from_other).unwrap_or_else(|| panic!("the account's own message from the gap is missing altogether: {summary:?}"));
    assert!(own.is_undecryptable && own.content.as_deref().is_some_and(|t| is_placeholder(t) && t.contains("\"final\":true")), "{own:?}");
    // What this install wrote itself before all that is still its own readable row, not a placeholder.
    assert!(rows.iter().any(|m| m.content.as_deref() == Some("alice before") && !m.is_undecryptable), "{summary:?}");
}

/// Build 46: the instance owner names the skwod on the host (device-signed); a member reads it,
/// cannot set it, and a cleared name reads as none.
#[tokio::test(flavor = "multi_thread")]
async fn the_owner_names_the_skwod_and_members_read_it() {
    let Some(p) = pair().await else { return };
    // An open-signup test server has no instance owner: make Alice the one `skwod init` would.
    let status = Command::new("sqlite3")
        .arg(p.server._dir.path().join("skwod.db"))
        .arg(format!("INSERT INTO instance_secrets (name, value, created_at) VALUES ('owner_user_id', CAST('{}' AS BLOB), 0)", p.alice))
        .status()
        .expect("sqlite3 (to name the instance owner)");
    assert!(status.success());
    assert_eq!(p.bobs.instance_name().await.expect("read before"), None);
    assert_eq!(p.phone.set_instance_name("  Weekend Crew \u{1F3D5}\u{FE0F} ".into()).await.expect("owner sets").as_deref(), Some("Weekend Crew \u{1F3D5}\u{FE0F}"));
    assert_eq!(p.bobs.instance_name().await.expect("member reads").as_deref(), Some("Weekend Crew \u{1F3D5}\u{FE0F}"));
    assert!(p.bobs.set_instance_name("Bob's".into()).await.is_err(), "only the instance owner names the skwod");
    assert!(p.phone.set_instance_name("a\u{202E}b".into()).await.is_err(), "bidi controls are refused");
    assert_eq!(p.bobs.instance_name().await.unwrap().as_deref(), Some("Weekend Crew \u{1F3D5}\u{FE0F}"));
    assert_eq!(p.phone.set_instance_name(String::new()).await.expect("owner clears"), None);
    assert_eq!(p.bobs.instance_name().await.unwrap(), None);
}
