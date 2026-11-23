//! One account, two devices, against a REAL skwod-server: device A creates a solo server, device B
//! (a distinct identity on the same account) links itself by asking A to provision it, then both
//! devices exchange channel messages and each sees the other's. This is the exact "signed in on my
//! phone and my Mac, messages don't cross" scenario. Skips gracefully if the server can't build.

use std::process::{Child, Command};
use std::sync::Once;
use std::time::Duration;

use skwod_core::SkwodClient;
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
        let status = Command::new("cargo")
            .args(["build", "--quiet", "--bin", "skwod", "--manifest-path"])
            .arg(server_manifest())
            .status();
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
/// A session of its own for each install: a session speaks for one device (the one it
/// registered or bound), so two clients must never share a token.
async fn fresh_token(base: &str, username: &str, password: &str) -> String {
    ApiClient::new(base).login(username, password).await.expect("login").token
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}
/// Pick the port up front so we can build both the listen arg and the base URL.
async fn start() -> Option<ServerGuard> {
    if !build_server() {
        eprintln!("SKIP: could not build skwod-server");
        return None;
    }
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(server_bin())
        .args(["run", "--listen", &format!("127.0.0.1:{port}"), "--data"])
        .arg(dir.path())
        // A throwaway test instance: open signup is asked for explicitly (`skwod run` otherwise
        // auto-initializes a fresh volume behind a join code), and no p2p endpoint is needed.
        .env("SKWOD_OPEN_SIGNUP", "1")
        .env("SKWOD_NO_P2P", "true")
        .env("SKWOD_QR_PAIRING", "1")
        .spawn()
        .ok()?;
    let guard = ServerGuard { child, _dir: dir, base: format!("http://127.0.0.1:{port}") };
    let http = reqwest::Client::new();
    for _ in 0..600 { // up to 60 s: cold start under a parallel test load
        if http.get(format!("{}/health", guard.base)).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            return Some(guard);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("server never became healthy");
}

fn cache_path(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string()
}
const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Link device `b` to the account through device `a`: b shows a code, the user types it into a.
async fn link(a: &SkwodClient, b: &SkwodClient, me: &str) -> String {
    assert!(matches!(b.register_device().await, Err(skwod_core::CoreError::LinkRequired { .. })), "a token alone cannot add a device");
    let code = b.begin_device_link().await.expect("begin link");
    assert_eq!(a.pending_device_links().await.unwrap(), 1);
    assert!(a.approve_device_link(code).await.expect("approve"));
    let dev = b.complete_device_link().await.expect("complete").expect("approved");
    a.process_control_inbox(me.into()).await.unwrap();
    b.process_control_inbox(me.into()).await.unwrap();
    dev
}

async fn texts(client: &SkwodClient, channel: &str, me: &str) -> Vec<String> {
    let _ = client.fetch_channel_messages(channel.into(), me.into()).await;
    client.history(format!("channel:{channel}")).await.into_iter().filter_map(|m| m.content).collect()
}

async fn history(client: &SkwodClient, channel: &str, me: &str) -> Vec<skwod_core::Message> {
    let _ = client.fetch_channel_messages(channel.into(), me.into()).await;
    client.history(format!("channel:{channel}")).await
}

#[tokio::test]
async fn two_devices_one_account_exchange_channel_messages() {
    let Some(server) = start().await else { return };
    let caches = tempfile::tempdir().unwrap();
    let sess = ApiClient::new(&server.base).signup("dualdevice", "password123").await.expect("signup");
    let me = sess.user_id.clone();

    // Device A: register, create a solo server + channel, hold the space key.
    let a = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "dualdevice", "password123").await);
    assert!(!a.attach_cache(cache_path(&caches, "a.sqlite3"), KEY_A.into()).await.unwrap());
    let dev_a = a.register_device().await.expect("register A");
    let space = a.create_space("Dual Crew".into(), "general".into()).await.expect("space");
    let channel = space.channel_id.clone();

    // Device B: a DISTINCT identity on the SAME account (fresh cache key). No space key yet.
    let b = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "dualdevice", "password123").await);
    assert!(!b.attach_cache(cache_path(&caches, "b.sqlite3"), KEY_B.into()).await.unwrap());
    let dev_b = link(&a, &b, &me).await;
    assert_ne!(dev_a, dev_b, "the two devices must have distinct identities");

    // --- Link B: B asks its sibling A to provision it (the solo-owner-second-device path) ---
    b.request_provision(space.server_id.clone(), me.clone(), dev_a.clone()).await.expect("B requests provision");
    // A's inbox: sees B's request (different device → not skipped), provisions B over a self-DM.
    let provisioned = a.process_control_inbox(me.clone()).await.expect("A inbox");
    assert_eq!(provisioned, 1, "A must provision its sibling device B");
    // B's inbox: accepts the space key (from its own account) + A's channel sender key.
    b.process_control_inbox(me.clone()).await.expect("B inbox");

    // B can now decrypt channel metadata — proof the space key crossed.
    let b_channels = b.list_channels(space.server_id.clone()).await.expect("B channels");
    assert!(b_channels.iter().any(|c| c.name.as_deref() == Some("general")), "B decrypts the channel name");

    // Reciprocal sender key: B hands A its channel key so A can read B's messages too.
    b.share_group_key(channel.clone(), me.clone(), dev_a.clone()).await.expect("B shares key to A");
    a.process_control_inbox(me.clone()).await.expect("A inbox 2");

    // --- Bidirectional messaging (after keys are exchanged both ways) ---
    a.send_channel_message(channel.clone(), "hello from the Mac".into()).await.expect("A sends");
    b.send_channel_message(channel.clone(), "hi from the phone".into()).await.expect("B sends");

    let a_sees = texts(&a, &channel, &me).await;
    let b_sees = texts(&b, &channel, &me).await;

    assert!(a_sees.iter().any(|t| t == "hello from the Mac"), "A sees its own send (cache)");
    assert!(a_sees.iter().any(|t| t == "hi from the phone"), "A sees B's message — THE BUG");
    assert!(b_sees.iter().any(|t| t == "hi from the phone"), "B sees its own send (cache)");
    assert!(b_sees.iter().any(|t| t == "hello from the Mac"), "B sees A's message — THE BUG");
}

#[tokio::test]
async fn message_context_menu_ops_reply_edit_delete_react() {
    let Some(server) = start().await else { return };
    let caches = tempfile::tempdir().unwrap();
    let sess = ApiClient::new(&server.base).signup("opsuser", "password123").await.expect("signup");
    let me = sess.user_id.clone();

    // Two devices of one account, linked (reuses the provisioning + sender-key path).
    let a = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "opsuser", "password123").await);
    assert!(!a.attach_cache(cache_path(&caches, "a.sqlite3"), KEY_A.into()).await.unwrap());
    let dev_a = a.register_device().await.expect("register A");
    let space = a.create_space("Ops".into(), "general".into()).await.expect("space");
    let channel = space.channel_id.clone();

    let b = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "opsuser", "password123").await);
    assert!(!b.attach_cache(cache_path(&caches, "b.sqlite3"), KEY_B.into()).await.unwrap());
    let _dev_b = link(&a, &b, &me).await;
    b.request_provision(space.server_id.clone(), me.clone(), dev_a.clone()).await.unwrap();
    a.process_control_inbox(me.clone()).await.unwrap();
    b.process_control_inbox(me.clone()).await.unwrap();
    b.share_group_key(channel.clone(), me.clone(), dev_a.clone()).await.unwrap();
    a.process_control_inbox(me.clone()).await.unwrap();

    // A sends a message; B sees it.
    let mid = a.send_channel_message(channel.clone(), "original text".into()).await.expect("send");
    let b_hist = history(&b, &channel, &me).await;
    assert!(b_hist.iter().any(|m| m.content.as_deref() == Some("original text")), "B sees A's message");

    // REPLY: B replies to A's message; A sees the reply with the reply link.
    let reply_id = b.reply_channel_message(channel.clone(), "a reply".into(), mid.clone()).await.expect("reply");
    let a_hist = history(&a, &channel, &me).await;
    let reply = a_hist.iter().find(|m| m.content.as_deref() == Some("a reply")).expect("A sees the reply");
    assert_eq!(reply.reply_to_id.as_deref(), Some(mid.as_str()), "reply carries the parent id");
    let _ = reply_id;

    // EDIT: A edits its message; B re-decrypts the new text and sees it flagged edited.
    a.edit_channel_message(channel.clone(), mid.clone(), "edited text".into()).await.expect("edit");
    let b_after_edit = history(&b, &channel, &me).await;
    let edited = b_after_edit.iter().find(|m| m.message_id == mid).expect("B still has the message");
    assert_eq!(edited.content.as_deref(), Some("edited text"), "B sees the edited text — sender-key re-decrypt");
    assert!(edited.is_edited, "B sees it flagged edited");

    // REACT: B reacts 🔥; A lists reactions and sees it.
    b.add_reaction(channel.clone(), mid.clone(), "🔥".into()).await.expect("react");
    let reactions = a.list_reactions(channel.clone(), mid.clone()).await.expect("list reactions");
    assert!(reactions.iter().any(|r| r.emoji.as_deref() == Some("🔥") && r.emoji_hash != "🔥" && r.user_id == me), "A sees B's 🔥 reaction; the server only its tag");

    // DELETE: A deletes its message; B sees the tombstone (content gone, is_deleted true).
    a.delete_channel_message(channel.clone(), mid.clone()).await.expect("delete");
    let b_after_delete = history(&b, &channel, &me).await;
    let tomb = b_after_delete.iter().find(|m| m.message_id == mid).expect("B still has the row");
    assert!(tomb.is_deleted, "B sees the tombstone");
    assert!(tomb.content.is_none(), "deleted content is gone on B");
}

/// Build 48, "Add a device" by QR, with NO password on the new device. The existing device's QR
/// carries the address, username, user id and a one-time code. The new device opens a
/// session-less pair request; both screens show the same emoji; the existing device approves
/// exactly that device, and only then does the server hand the new device a session. Someone who
/// photographed the QR makes a second request with the same code: then NOBODY is approved.
#[tokio::test]
async fn a_new_device_pairs_by_qr_without_a_password() {
    use skwod_core::pairing::{pairing_new_offer, pairing_qr_decode, pairing_qr_encode};
    use skwod_core::PairProgress;
    let Some(server) = start().await else { return };
    let caches = tempfile::tempdir().unwrap();
    let sess = ApiClient::new(&server.base).signup("qrpair", "password123").await.expect("signup");
    let me = sess.user_id.clone();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let node = || skwod_net::SecretKey::generate().public().to_z32();

    let a = SkwodClient::new(server.base.clone(), fresh_token(&server.base, "qrpair", "password123").await);
    assert!(!a.attach_cache(cache_path(&caches, "a.sqlite3"), KEY_A.into()).await.unwrap());
    a.register_device().await.expect("register A");

    // A shows the QR; B scans it. B has NO session and never types the password.
    let offer = pairing_new_offer(node(), None, "qrpair".into(), me.clone(), now).unwrap();
    let scanned = pairing_qr_decode(pairing_qr_encode(offer.clone()).unwrap(), now).unwrap();
    assert_eq!(scanned, offer);
    a.register_pairing_offer(offer.clone()).await.expect("register the offer");
    assert!(a.pairing_candidate(offer.clone(), now).await.unwrap().is_none(), "nobody asked yet");

    let b = SkwodClient::new(server.base.clone(), String::new());
    assert!(!b.attach_cache(cache_path(&caches, "b.sqlite3"), KEY_B.into()).await.unwrap());
    b.pair_begin(scanned.clone(), now).await.expect("B begins without a session");
    assert!(matches!(b.pair_poll(scanned.clone()).await.expect("poll"), PairProgress::Waiting), "no emoji before A has seen B");

    // A sees B's key, pins it, and only then releases its nonce: now B can show the emoji.
    let cand = a.pairing_candidate(offer.clone(), now).await.unwrap().expect("B's request");
    assert_eq!(cand.choices.len(), 4);
    let PairProgress::Confirm { emoji: confirm_b } = b.pair_poll(scanned.clone()).await.expect("poll") else { panic!("B shows its emoji now") };
    assert_eq!(confirm_b.split(' ').count(), 5);
    assert_eq!(cand.choices.iter().filter(|c| **c == confirm_b).count(), 1, "B's set is one of the four");
    assert_eq!(a.pairing_candidate(offer.clone(), now).await.unwrap().unwrap().choices, cand.choices, "asking again does not reshuffle");
    assert!(a.approve_pairing(offer.clone(), cand.clone(), confirm_b.clone(), now).await.expect("approve"));

    let PairProgress::Paired { device: paired } = b.pair_poll(scanned.clone()).await.expect("poll") else { panic!("approved") };
    assert_eq!(paired.session.user_id, me);
    assert!(!paired.session.token.is_empty() && !paired.device_id.is_empty());
    // The session is real, and handed out once.
    let me_check = reqwest::Client::new().get(format!("{}/api/auth/me", server.base)).bearer_auth(&paired.session.token).send().await.unwrap();
    assert!(me_check.status().is_success());
    a.process_control_inbox(me.clone()).await.unwrap();

    // Single use and short-lived.
    assert!(a.approve_pairing(offer.clone(), cand.clone(), confirm_b.clone(), now).await.is_err());
    assert!(a.pairing_candidate(offer.clone(), now).await.is_err());
    let old = pairing_new_offer(node(), None, "qrpair".into(), me.clone(), now - 400).unwrap();
    assert!(a.pairing_candidate(old.clone(), now).await.is_err());
    assert!(pairing_qr_decode(pairing_qr_encode(offer).unwrap(), now + 400).is_err(), "the new device refuses it too");

    // Someone photographed the next QR: a second device presenting its code contests the offer
    // (it does not replace the first request) — nobody is approved and nobody gets a session.
    let offer2 = pairing_new_offer(node(), None, "qrpair".into(), me.clone(), now).unwrap();
    let c = SkwodClient::new(server.base.clone(), String::new());
    assert!(!c.attach_cache(cache_path(&caches, "c.sqlite3"), "cc".repeat(32)).await.unwrap());
    let d = SkwodClient::new(server.base.clone(), String::new());
    assert!(!d.attach_cache(cache_path(&caches, "d.sqlite3"), "dd".repeat(32)).await.unwrap());
    a.register_pairing_offer(offer2.clone()).await.unwrap();
    c.pair_begin(offer2.clone(), now).await.unwrap();
    d.pair_begin(offer2.clone(), now).await.expect("looks accepted from outside");
    let err = a.pairing_candidate(offer2.clone(), now).await.expect_err("contested: refused");
    assert!(format!("{err:?}").contains("Someone else also scanned"), "{err:?}");
    assert!(c.pair_poll(offer2.clone()).await.is_err(), "the first gets no session either");
    assert!(matches!(d.pair_poll(offer2.clone()).await.unwrap(), PairProgress::Waiting), "and the second's request never completes");

    // Denied: the new device is told, and has no session.
    let offer3 = pairing_new_offer(node(), None, "qrpair".into(), me.clone(), now).unwrap();
    let e = SkwodClient::new(server.base.clone(), String::new());
    assert!(!e.attach_cache(cache_path(&caches, "e.sqlite3"), "ee".repeat(32)).await.unwrap());
    a.register_pairing_offer(offer3.clone()).await.unwrap();
    e.pair_begin(offer3.clone(), now).await.unwrap();
    let cand3 = a.pairing_candidate(offer3.clone(), now).await.unwrap().expect("E's request");
    a.deny_pairing(offer3.clone(), cand3).await.unwrap();
    assert!(e.pair_poll(offer3).await.is_err(), "denied: no session");

    // A careless tap: picking a set the new device does not show denies it and burns the offer.
    let offer4 = pairing_new_offer(node(), None, "qrpair".into(), me.clone(), now).unwrap();
    let f = SkwodClient::new(server.base.clone(), String::new());
    assert!(!f.attach_cache(cache_path(&caches, "f.sqlite3"), "ff".repeat(32)).await.unwrap());
    a.register_pairing_offer(offer4.clone()).await.unwrap();
    f.pair_begin(offer4.clone(), now).await.unwrap();
    let cand4 = a.pairing_candidate(offer4.clone(), now).await.unwrap().expect("F's request");
    let PairProgress::Confirm { emoji: shown } = f.pair_poll(offer4.clone()).await.unwrap() else { panic!("F shows emoji") };
    let decoy = cand4.choices.iter().find(|c| **c != shown).unwrap().clone();
    let err = a.approve_pairing(offer4.clone(), cand4.clone(), decoy, now).await.expect_err("a wrong pick is refused");
    assert!(format!("{err:?}").contains("aren't the emoji"), "{err:?}");
    assert!(a.approve_pairing(offer4.clone(), cand4, shown, now).await.is_err(), "one try only");
    assert!(f.pair_poll(offer4).await.is_err(), "and the new device is told it was denied");

    // A QR whose commitment is not the one A made (forged, or swapped in transit): the nonce A
    // reveals does not open it, so the new device stops — it never shows emoji or gets in.
    let offer5 = pairing_new_offer(node(), None, "qrpair".into(), me.clone(), now).unwrap();
    let mut forged = offer5.clone();
    forged.commitment = "00".repeat(16);
    let g = SkwodClient::new(server.base.clone(), String::new());
    assert!(!g.attach_cache(cache_path(&caches, "g.sqlite3"), "99".repeat(32)).await.unwrap());
    a.register_pairing_offer(offer5.clone()).await.unwrap();
    g.pair_begin(forged.clone(), now).await.unwrap();
    a.pairing_candidate(offer5.clone(), now).await.unwrap().expect("G's request");
    let Err(err) = g.pair_poll(forged).await else { panic!("the nonce does not match the QR") };
    assert!(format!("{err:?}").contains("did not match"), "{err:?}");

}
