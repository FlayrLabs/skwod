//! The "broken basics", through the same `SkwodClient` surface the apps use, against a REAL
//! skwod-server: two accounts (Alice with a phone and a Mac, Bob with one device).
//!
//! - a photo Alice attaches opens for Bob, in a channel and in a DM;
//! - Bob gets a DM without ever having opened the conversation, and it shows on Alice's Mac;
//! - an edit made on Alice's Mac reaches Bob and Alice's phone;
//! - Bob, offline for 150 messages, catches up — including an edit and a delete;
//! - the feed has one home that every device agrees on;
//! - game traffic stays out of chat, reactions come with the list, oversize sends fail loudly;
//! - a dead session reads as "signed out", an expired invite is known before signup.
//!
//! Skips gracefully if the server can't build.

use std::process::{Child, Command};
use std::sync::Once;
use std::time::Duration;

use skwod_core::{SessionState, SkwodClient};
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

struct World {
    server: ServerGuard,
    _caches: tempfile::TempDir,
    alice: String,
    alice_token: String,
    bob: String,
    bob_token: String,
    /// Alice's phone (the owner's first device), her Mac (linked), Bob's phone.
    phone: std::sync::Arc<SkwodClient>,
    mac: std::sync::Arc<SkwodClient>,
    bobs: std::sync::Arc<SkwodClient>,
    server_id: String,
    channel: String,
}

/// Let sealed mail (keys, provisioning, DMs) settle on every device.
async fn pump(w: &World) {
    for _ in 0..3 {
        let _ = w.phone.process_control_inbox(w.alice.clone()).await;
        let _ = w.mac.process_control_inbox(w.alice.clone()).await;
        let _ = w.bobs.process_control_inbox(w.bob.clone()).await;
    }
}

/// A session of its own for each install: a session speaks for one device (the one it
/// registered or bound), so two clients must never share a token.
async fn fresh_token(base: &str, username: &str, password: &str) -> String {
    ApiClient::new(base).login(username, password).await.expect("login").token
}

async fn world() -> Option<World> {
    let server = start().await?;
    let caches = tempfile::tempdir().unwrap();
    let path = |n: &str| caches.path().join(n).to_string_lossy().to_string();
    let a = ApiClient::new(&server.base).signup("alice", "password123").await.expect("signup alice");
    let b = ApiClient::new(&server.base).signup("bobby", "password123").await.expect("signup bob");

    // The phone's own session: the one its device binds (a session bound to no device is
    // refused once the account has one), and the one the raw uploads below go out on.
    let phone_token = fresh_token(&server.base.clone(), "alice", "password123").await;
    let phone = SkwodClient::new(server.base.clone(), phone_token.clone());
    phone.attach_cache(path("phone.sqlite3"), key('a')).await.unwrap();
    let phone_dev = phone.register_device().await.expect("register phone");
    let space = phone.create_space("Crew".into(), "general".into()).await.expect("space");

    // Alice's Mac: linked through the phone, then provisioned by it.
    let mac = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "alice", "password123").await);
    mac.attach_cache(path("mac.sqlite3"), key('b')).await.unwrap();
    assert!(mac.register_device().await.is_err());
    let code = mac.begin_device_link().await.expect("begin link");
    assert!(phone.approve_device_link(code).await.expect("approve link"));
    mac.complete_device_link().await.expect("complete").expect("approved");
    phone.process_control_inbox(a.user_id.clone()).await.unwrap();
    mac.process_control_inbox(a.user_id.clone()).await.unwrap();
    mac.request_provision(space.server_id.clone(), a.user_id.clone(), phone_dev.clone()).await.expect("mac asks");
    phone.process_control_inbox(a.user_id.clone()).await.unwrap();
    mac.process_control_inbox(a.user_id.clone()).await.unwrap();

    // Bob: joins with an approval-required code, Alice lets him in.
    let bob_token = fresh_token(&server.base.clone(), "bobby", "password123").await;
    let bobs = SkwodClient::new(server.base.clone(), bob_token.clone());
    bobs.attach_cache(path("bob.sqlite3"), key('c')).await.unwrap();
    bobs.register_device().await.expect("register bob");
    let invite = phone.invite_to_space(space.server_id.clone(), "code".into(), None).await.unwrap();
    assert!(bobs.join_by_code(invite).await.unwrap().pending);
    phone.approve_join_request(space.server_id.clone(), b.user_id.clone()).await.unwrap();
    phone.approve_member(space.server_id.clone(), b.user_id.clone()).await.unwrap();

    let w = World {
        server,
        _caches: caches,
        alice: a.user_id,
        alice_token: phone_token,
        bob: b.user_id,
        bob_token,
        phone,
        mac,
        bobs,
        server_id: space.server_id,
        channel: space.channel_id,
    };
    pump(&w).await;
    // Everyone hands out their channel key.
    for (c, me) in [(&w.phone, &w.alice), (&w.mac, &w.alice), (&w.bobs, &w.bob)] {
        c.sync_channel_membership(w.channel.clone(), w.server_id.clone(), me.clone()).await.expect("share channel key");
    }
    pump(&w).await;
    Some(w)
}

async fn chat(c: &SkwodClient, channel: &str, me: &str) -> Vec<skwod_core::Message> {
    c.fetch_channel_messages(channel.into(), me.into()).await.expect("fetch")
}

fn texts(rows: &[skwod_core::Message]) -> Vec<String> {
    rows.iter().filter(|m| !m.is_deleted).filter_map(|m| m.content.clone()).collect()
}

async fn upload(base: &str, token: &str, bytes: &[u8], token_hash: Option<&str>) -> String {
    let http = reqwest::Client::new();
    let mut body = serde_json::json!({ "total_size": bytes.len() });
    if let Some(h) = token_hash {
        body["download_token_hash"] = serde_json::json!(h);
    }
    let v: serde_json::Value = http.post(format!("{base}/api/blobs")).bearer_auth(token).json(&body).send().await.unwrap().json().await.unwrap();
    let id = v["blob_id"].as_str().unwrap_or_else(|| panic!("no blob id: {v}")).to_string();
    let r = http.patch(format!("{base}/api/blobs/{id}")).bearer_auth(token).header("upload-offset", "0").body(bytes.to_vec()).send().await.unwrap();
    assert!(r.status().is_success());
    id
}

#[tokio::test(flavor = "multi_thread")]
async fn a_photo_from_alice_opens_for_bob_in_a_channel_and_in_a_dm() {
    let Some(w) = world().await else { return };
    let http = reqwest::Client::new();
    let photo = b"pretend this is a photo".to_vec();
    let sealed = skwod_core::encrypt_attachment(photo.clone()).unwrap();

    // ---- channel ----
    let blob = upload(&w.server.base, &w.alice_token, &sealed.ciphertext, None).await;
    let descriptor = format!("\u{2}skwod/attach|{{\"blobId\":\"{blob}\"}}");
    w.phone.send_channel_message_with(w.channel.clone(), descriptor.clone(), None, vec![blob.clone()]).await.expect("send with attachment");
    let seen = chat(&w.bobs, &w.channel, &w.bob).await;
    assert!(texts(&seen).contains(&descriptor), "Bob reads the descriptor");
    let got = http.get(format!("{}/api/blobs/{blob}", w.server.base)).bearer_auth(&w.bob_token).send().await.unwrap();
    assert_eq!(got.status(), 200, "Bob — a different account — downloads Alice's attachment");
    let opened = skwod_core::decrypt_attachment(got.bytes().await.unwrap().to_vec(), sealed.key.clone(), sealed.digest.clone(), photo.len() as u64).unwrap();
    assert_eq!(opened, photo);

    // A message sent WITHOUT naming its blob is what build 42 did: nobody else can open it.
    let orphan = upload(&w.server.base, &w.alice_token, &sealed.ciphertext, None).await;
    w.phone.send_channel_message(w.channel.clone(), format!("\u{2}skwod/attach|{{\"blobId\":\"{orphan}\"}}")).await.unwrap();
    assert_eq!(http.get(format!("{}/api/blobs/{orphan}", w.server.base)).bearer_auth(&w.bob_token).send().await.unwrap().status(), 404);

    // ---- DM ----
    let cap = skwod_core::new_blob_download_token();
    let dm_blob = upload(&w.server.base, &w.alice_token, &sealed.ciphertext, Some(&cap.hash_hex)).await;
    let convo = w.phone.open_dm(w.bob.clone()).await.unwrap();
    let body = format!("\u{2}skwod/attach|{{\"blobId\":\"{dm_blob}\",\"token\":\"{}\"}}", cap.token);
    w.phone.send_dm(convo.clone(), w.bob.clone(), String::new(), body.clone()).await.expect("dm with attachment");
    let events = w.bobs.sync_dms().await.unwrap();
    let token_from_dm = events.iter().find(|e| e.text == body).map(|_| cap.token.clone()).expect("Bob received the descriptor");
    // Bob presents ONLY the token — no session — so the server cannot tell who fetched it.
    let got = http.get(format!("{}/api/blobs/{dm_blob}", w.server.base)).header("x-skwod-blob-token", &token_from_dm).send().await.unwrap();
    assert_eq!(got.status(), 200);
    let opened = skwod_core::decrypt_attachment(got.bytes().await.unwrap().to_vec(), sealed.key, sealed.digest, photo.len() as u64).unwrap();
    assert_eq!(opened, photo);
    // His session alone does not open it, and a wrong token does not either.
    assert_eq!(http.get(format!("{}/api/blobs/{dm_blob}", w.server.base)).bearer_auth(&w.bob_token).send().await.unwrap().status(), 404);
    assert_eq!(http.get(format!("{}/api/blobs/{dm_blob}", w.server.base)).header("x-skwod-blob-token", "nope").send().await.unwrap().status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dm_arrives_unasked_and_shows_on_the_senders_other_device() {
    let Some(w) = world().await else { return };
    // Nothing yet, anywhere.
    assert!(w.bobs.sync_dms().await.unwrap().is_empty());
    assert!(w.bobs.list_dms().await.unwrap().is_empty());

    // Alice writes from her phone. Bob has never opened a conversation with her.
    let convo = w.phone.open_dm(w.bob.clone()).await.unwrap();
    let id = w.phone.send_dm(convo.clone(), w.bob.clone(), String::new(), "are you coming tonight?".into()).await.unwrap();

    // Bob's device: one inbox sync reports WHICH conversation was touched and by whom…
    let events = w.bobs.sync_dms().await.unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    let e = &events[0];
    assert_eq!((e.conversation_id.as_str(), e.peer_user_id.as_str(), e.message_id.as_str(), e.from_self), (convo.as_str(), w.alice.as_str(), id.as_str(), false));
    assert_eq!(e.text, "are you coming tonight?");
    // …the message is in his cache under that conversation…
    let history = w.bobs.history(format!("dm:{convo}")).await;
    assert_eq!(history.iter().filter_map(|m| m.content.clone()).collect::<Vec<_>>(), vec!["are you coming tonight?"]);
    // …and the server's list names the conversation and the person, for the sidebar.
    let listed = w.bobs.list_dms().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].conversation_id.as_str(), listed[0].peer_user_id.as_str(), listed[0].peer_username.as_str()), (convo.as_str(), w.alice.as_str(), "alice"));
    // Reported once.
    assert!(w.bobs.sync_dms().await.unwrap().is_empty());
    assert!(w.bobs.take_dm_events().await.is_empty());

    // Alice's Mac never opened it either: it gets her own message as a synced copy (list it,
    // do not notify), and the conversation is in its list.
    let events = w.mac.sync_dms().await.unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!((events[0].conversation_id.as_str(), events[0].peer_user_id.as_str(), events[0].from_self), (convo.as_str(), w.bob.as_str(), true));
    let listed = w.mac.list_dms().await.unwrap();
    assert!(listed.iter().any(|c| c.conversation_id == convo && c.peer_user_id == w.bob && c.peer_username == "bobby"));

    // Bob answers; it reaches both of Alice's devices. A DM drained by SOME OTHER call (here a
    // channel fetch on the phone) is still reported by `take_dm_events`.
    w.bobs.send_dm(convo.clone(), w.alice.clone(), String::new(), "yes!".into()).await.unwrap();
    let _ = chat(&w.phone, &w.channel, &w.alice).await;
    let events = w.phone.take_dm_events().await;
    assert!(events.iter().any(|e| e.text == "yes!" && e.peer_user_id == w.bob && !e.from_self), "{events:?}");
    let events = w.mac.sync_dms().await.unwrap();
    assert!(events.iter().any(|e| e.text == "yes!" && !e.from_self), "{events:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_edit_made_on_another_device_reaches_everyone() {
    let Some(w) = world().await else { return };
    // Sent from the phone…
    let id = w.phone.send_channel_message(w.channel.clone(), "meet at 7".into()).await.unwrap();
    assert!(texts(&chat(&w.bobs, &w.channel, &w.bob).await).contains(&"meet at 7".to_string()));
    assert!(texts(&chat(&w.mac, &w.channel, &w.alice).await).contains(&"meet at 7".to_string()));

    // …edited on the Mac. It is sealed under the MAC's sender key.
    w.mac.edit_channel_message(w.channel.clone(), id.clone(), "meet at 8".into()).await.expect("edit on the other device");

    // Bob sees the edit (he decrypts the row as the Mac, which the server now names).
    let bob_view = chat(&w.bobs, &w.channel, &w.bob).await;
    let row = bob_view.iter().find(|m| m.message_id == id).expect("the message");
    assert_eq!((row.content.as_deref(), row.is_edited), (Some("meet at 8"), true), "Bob sees the edited text");
    // The phone — the ORIGINAL sender — sees it too: an own row is no longer skipped just
    // because this account wrote it; only what THIS device sealed is.
    let phone_view = chat(&w.phone, &w.channel, &w.alice).await;
    let row = phone_view.iter().find(|m| m.message_id == id).unwrap();
    assert_eq!((row.content.as_deref(), row.is_edited), (Some("meet at 8"), true), "the sending device sees its sibling's edit");
    // And back: the phone edits again; the Mac and Bob follow.
    w.phone.edit_channel_message(w.channel.clone(), id.clone(), "meet at 9".into()).await.unwrap();
    for (c, me) in [(&w.mac, &w.alice), (&w.bobs, &w.bob)] {
        let view = chat(c, &w.channel, me).await;
        assert_eq!(view.iter().find(|m| m.message_id == id).unwrap().content.as_deref(), Some("meet at 9"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bob_offline_for_150_messages_catches_up_including_an_edit_and_a_delete() {
    let Some(w) = world().await else { return };
    let keep = w.phone.send_channel_message(w.channel.clone(), "before".into()).await.unwrap();
    let to_edit = w.phone.send_channel_message(w.channel.clone(), "typo".into()).await.unwrap();
    let to_delete = w.phone.send_channel_message(w.channel.clone(), "oops".into()).await.unwrap();
    assert_eq!(texts(&chat(&w.bobs, &w.channel, &w.bob).await), vec!["before", "typo", "oops"]);

    // Bob goes offline. 150 messages (from both of Alice's devices), whiteboard strokes in
    // between — which the server cannot tell from chat — an edit and a delete.
    for i in 0..150 {
        let c = if i % 2 == 0 { &w.phone } else { &w.mac };
        loop {
            match c.send_channel_message(w.channel.clone(), format!("m{i:03}")).await {
                Ok(_) => break,
                Err(e) if e.to_string().contains("429") => tokio::time::sleep(Duration::from_secs(2)).await,
                Err(e) => panic!("send {i}: {e}"),
            }
        }
        if i % 10 == 0 {
            w.mac.send_channel_message(w.channel.clone(), format!("\u{2}skwod/game|{{\"stroke\":{i}}}")).await.unwrap();
        }
    }
    w.phone.edit_channel_message(w.channel.clone(), to_edit.clone(), "fixed".into()).await.unwrap();
    w.phone.delete_channel_message(w.channel.clone(), to_delete.clone()).await.unwrap();

    // Back online: ONE fetch brings all of it (it pages by itself — the old code took the last 100).
    let view = chat(&w.bobs, &w.channel, &w.bob).await;
    let got = texts(&view);
    for i in 0..150 {
        assert!(got.contains(&format!("m{i:03}")), "m{i:03} is missing after catch-up ({} messages present)", got.len());
    }
    assert_eq!(view.iter().find(|m| m.message_id == to_edit).unwrap().content.as_deref(), Some("fixed"), "the edit made while he was away");
    assert!(view.iter().find(|m| m.message_id == to_delete).unwrap().is_deleted, "the delete made while he was away");
    assert_eq!(view.iter().find(|m| m.message_id == keep).unwrap().content.as_deref(), Some("before"));
    assert!(!got.iter().any(|t| t.contains("skwod/game")), "whiteboard traffic is not in the chat history");
    // In order.
    let ms: Vec<&String> = got.iter().filter(|t| t.starts_with('m') && t.len() == 4).collect();
    let mut sorted = ms.clone();
    sorted.sort();
    assert_eq!(ms, sorted, "catch-up keeps the order");

    // Game state was sorted out on the device, after decryption, into its own cache scope.
    let aux = w.bobs.fetch_aux_messages(w.channel.clone(), w.bob.clone()).await.unwrap();
    assert_eq!(aux.len(), 15);
    assert!(aux.iter().all(|m| m.content.as_deref().is_some_and(|c| c.starts_with("\u{2}skwod/game|"))));
    // …also for the device that sent it (its own strokes are cached there, not in chat).
    assert!(!texts(&w.mac.history(format!("channel:{}", w.channel)).await).iter().any(|t| t.contains("skwod/game")));
    assert_eq!(w.mac.fetch_aux_messages(w.channel.clone(), w.alice.clone()).await.unwrap().len(), 15);

    // A second fetch with nothing new changes nothing.
    assert_eq!(texts(&chat(&w.bobs, &w.channel, &w.bob).await).len(), got.len());

    // "Load older": the window the UI shows is the newest part; older pages come from the cache.
    let newest = w.bobs.history_page(format!("channel:{}", w.channel), i64::MAX, 50).await;
    assert_eq!(newest.len(), 50);
    let older = w.bobs.history_page(format!("channel:{}", w.channel), newest[0].created_at, 50).await;
    assert_eq!(older.len(), 50);
    assert!(older.last().unwrap().created_at <= newest[0].created_at);
    // And when the cache runs out, the server is asked — here there is nothing older.
    assert_eq!(w.bobs.load_older_channel_messages(w.channel.clone(), w.bob.clone()).await.unwrap(), 0);

    // What notifies is decided here too, from the decrypted body.
    assert!(skwod_core::message_notifies("see you at 8".into()));
    assert!(skwod_core::message_notifies("\u{2}skwod/attach|{}".into()) && skwod_core::message_notifies("\u{2}skwod/feed|{}".into()));
    for quiet in ["game", "like", "comment", "avatar", "addr", "sys"] {
        assert!(!skwod_core::message_notifies(format!("\u{2}skwod/{quiet}|{{}}")), "{quiet} must not notify");
    }
    assert!(skwod_core::message_is_hidden("\u{2}skwod/game|{}".into()) && !skwod_core::message_is_hidden("\u{2}skwod/like|{}".into()));
}

/// A channel whose recent traffic is mostly a whiteboard must still open with its chat: the
/// server serves one undifferentiated history, so the device keeps paging back until it holds
/// enough chat, and "load older" counts chat, not rows.
#[tokio::test(flavor = "multi_thread")]
async fn game_traffic_cannot_push_chat_out_of_the_window() {
    let Some(w) = world().await else { return };
    // 30 chat lines, then 260 whiteboard strokes on top of them (more than two server pages).
    for i in 0..30 {
        w.phone.send_channel_message(w.channel.clone(), format!("chat{i:02}")).await.unwrap();
    }
    for i in 0..260 {
        let c = if i % 2 == 0 { &w.phone } else { &w.mac };
        c.send_channel_message(w.channel.clone(), format!("\u{2}skwod/game|{{\"stroke\":{i}}}")).await.unwrap();
    }
    // Bob's FIRST sync of this channel (a single page of 100 would be strokes only).
    let view = chat(&w.bobs, &w.channel, &w.bob).await;
    let got = texts(&view);
    assert_eq!(got.len(), 30, "all the chat is there: {got:?}");
    assert!(got.iter().all(|t| t.starts_with("chat")), "and nothing but chat");
    assert_eq!(w.bobs.fetch_aux_messages(w.channel.clone(), w.bob.clone()).await.unwrap().len(), 260, "the strokes are in their own scope");
    // The sender's own devices keep them out of chat as well.
    assert!(!texts(&chat(&w.mac, &w.channel, &w.alice).await).iter().any(|t| t.contains("skwod/game")));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_feed_has_one_home_and_a_post_with_a_photo_appears_for_bob() {
    let Some(w) = world().await else { return };
    // Every device of every member resolves the SAME channel…
    let feed = w.phone.feed_channel(w.server_id.clone()).await.unwrap();
    assert_eq!(w.mac.feed_channel(w.server_id.clone()).await.unwrap(), feed);
    assert_eq!(w.bobs.feed_channel(w.server_id.clone()).await.unwrap(), feed);
    assert_ne!(feed, w.channel, "it is not the chat channel");
    // …and it is not a place in the channel list.
    for c in [&w.phone, &w.bobs] {
        let listed = c.list_channels(w.server_id.clone()).await.unwrap();
        assert!(listed.iter().all(|ch| ch.channel_id != feed), "the feed channel is hidden");
        assert!(listed.iter().any(|ch| ch.channel_id == w.channel));
    }
    // More channels do not change the answer (the old code used "the first channel on this device").
    w.phone.create_channel(w.server_id.clone(), "aaa-first-alphabetically".into()).await.unwrap();
    assert_eq!(w.bobs.feed_channel(w.server_id.clone()).await.unwrap(), feed);

    // A post with a photo: the media is an attachment, the body carries a descriptor.
    let sealed = skwod_core::encrypt_attachment(vec![7u8; 200_000]).unwrap();
    let blob = upload(&w.server.base, &w.alice_token, &sealed.ciphertext, None).await;
    let post = format!("\u{2}skwod/feed|{{\"caption\":\"sunset\",\"blobId\":\"{blob}\"}}");
    for (c, me) in [(&w.phone, &w.alice), (&w.mac, &w.alice), (&w.bobs, &w.bob)] {
        c.sync_channel_membership(feed.clone(), w.server_id.clone(), me.clone()).await.unwrap();
    }
    pump(&w).await;
    w.phone.send_channel_message_with(feed.clone(), post.clone(), None, vec![blob.clone()]).await.expect("post");
    assert!(texts(&chat(&w.bobs, &feed, &w.bob).await).contains(&post), "the post appears for Bob");
    let got = reqwest::Client::new().get(format!("{}/api/blobs/{blob}", w.server.base)).bearer_auth(&w.bob_token).send().await.unwrap();
    assert_eq!(got.status(), 200, "and its photo opens");
    assert!(!texts(&chat(&w.bobs, &w.channel, &w.bob).await).contains(&post), "it is not in the chat channel");

    // Bob likes it: a reaction that comes back with the channel sync, in one call.
    let post_id = chat(&w.bobs, &feed, &w.bob).await.into_iter().find(|m| m.content.as_deref() == Some(post.as_str())).unwrap().message_id;
    w.bobs.add_reaction(feed.clone(), post_id.clone(), "❤️".into()).await.unwrap();
    chat(&w.phone, &feed, &w.alice).await;
    let reactions = w.phone.channel_reactions(feed.clone()).await;
    assert_eq!(reactions.len(), 1, "{reactions:?}");
    assert_eq!((reactions[0].message_id.as_str(), reactions[0].user_id.as_str(), reactions[0].emoji.as_deref()), (post_id.as_str(), w.bob.as_str(), Some("❤️")));
    w.bobs.remove_reaction(feed.clone(), post_id.clone(), "❤️".into()).await.unwrap();
    chat(&w.phone, &feed, &w.alice).await;
    assert!(w.phone.channel_reactions(feed.clone()).await.is_empty());

    // A body that could never be delivered (the old inline-photo posts) fails HERE, in words.
    let huge = format!("\u{2}skwod/feed|{}", "x".repeat(400 * 1024));
    let err = w.phone.send_channel_message(feed.clone(), huge.clone()).await.unwrap_err();
    assert!(matches!(&err, skwod_core::CoreError::Invalid { detail } if detail.contains("too big")), "{err}");
    let convo = w.phone.open_dm(w.bob.clone()).await.unwrap();
    assert!(matches!(w.phone.send_dm(convo, w.bob.clone(), String::new(), huge).await, Err(skwod_core::CoreError::Invalid { .. })));
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_invites_and_fingerprints_tell_the_truth() {
    let Some(w) = world().await else { return };

    // ---- an expired invite is known before signup ----
    let good = w.phone.invite_to_space(w.server_id.clone(), "code".into(), None).await.unwrap();
    let check = skwod_core::check_invite(w.server.base.clone(), good.clone()).await.unwrap();
    assert_eq!((check.valid, check.requires_approval), (true, true));
    w.phone.revoke_invite(good.clone()).await.unwrap();
    let check = skwod_core::check_invite(w.server.base.clone(), good).await.unwrap();
    assert_eq!((check.valid, check.reason.as_deref()), (false, Some("used")));
    let check = skwod_core::check_invite(w.server.base.clone(), "SKWD-NOPE-NOPE".into()).await.unwrap();
    assert_eq!((check.valid, check.reason.as_deref()), (false, Some("unknown")));
    // A host that cannot be reached is an error, not "invalid".
    assert!(skwod_core::check_invite("http://127.0.0.1:1".into(), "SKWD-AAAA-BBBB".into()).await.is_err());

    // ---- the waiting list shows a fingerprint without trusting anyone ----
    let c = ApiClient::new(&w.server.base).signup("carol", "password123").await.unwrap();
    let carol = SkwodClient::new(w.server.base.clone(), fresh_token(&w.server.base.clone(), "carol", "password123").await);
    carol.allow_without_cache();
    carol.register_device().await.unwrap();
    let invite = w.phone.invite_to_space(w.server_id.clone(), "code".into(), None).await.unwrap();
    assert!(carol.join_by_code(invite).await.unwrap().pending);
    let before = w.phone.contact_status(c.user_id.clone()).await;
    assert_eq!(before.devices, 0, "nothing known about Carol yet");
    let peek = w.phone.peek_account_fingerprint(c.user_id.clone()).await.expect("a fingerprint to show");
    assert!(!peek.pinned, "first sight is labelled unverified");
    assert!(!peek.fingerprint.is_empty());
    // Looking — any number of times — pinned nothing.
    for _ in 0..3 {
        w.phone.peek_account_fingerprint(c.user_id.clone()).await.unwrap();
    }
    assert_eq!(w.phone.contact_status(c.user_id.clone()).await, before, "listing someone must not pin their keys");
    // The explicit action does, and the pinned fingerprint is the one that was shown.
    w.phone.approve_join_request(w.server_id.clone(), c.user_id.clone()).await.unwrap();
    w.phone.approve_member(w.server_id.clone(), c.user_id.clone()).await.unwrap();
    assert!(w.phone.contact_status(c.user_id.clone()).await.devices >= 1, "Let in pins");
    let after = w.phone.peek_account_fingerprint(c.user_id.clone()).await.unwrap();
    assert!(after.pinned);
    assert_eq!(after.fingerprint, peek.fingerprint);
    assert_eq!(w.phone.account_fingerprint(c.user_id.clone()).await.unwrap(), peek.fingerprint);

    // ---- a call that is ringing is found by asking ----
    assert!(w.bobs.pending_rings().await.unwrap().is_empty());

    // ---- rotation keeps the sign-in; a dead session reads as signed out, not unreachable ----
    assert_eq!(w.bobs.session_state().await, SessionState::Valid);
    let rotated = skwod_core::rotate_session(w.server.base.clone(), w.bob_token.clone()).await.expect("rotate");
    assert_ne!(rotated.token, w.bob_token);
    assert_eq!(rotated.user_id, w.bob);
    let fresh = SkwodClient::new(w.server.base.clone(), rotated.token.clone());
    assert_eq!(fresh.session_state().await, SessionState::Valid);
    ApiClient::new(&w.server.base).with_token(rotated.token.clone()).post("/api/auth/logout", serde_json::json!({})).await.unwrap();
    assert_eq!(fresh.session_state().await, SessionState::SignedOut);
    let nowhere = SkwodClient::new("http://127.0.0.1:1".into(), rotated.token);
    assert_eq!(nowhere.session_state().await, SessionState::Unreachable);
}
