//! Build 44 "content", end to end through the `SkwodClient` surface the apps use, against a REAL
//! skwod-server process: Alice (phone + Mac, owner of the skwod), Bob (phone + tablet), Carol.
//!
//! - block someone: their messages, reactions and stories disappear, they cannot DM you;
//! - report from a message: metadata to the server, the quote sealed to the owner;
//! - go offline, queue three messages and a post, come back: each is delivered once;
//! - DM reply / edit / delete / react land on both people's two devices;
//! - clear a channel: it empties on a member who was away;
//! - a story ends for everyone, by the server's clock;
//! - a big attachment is streamed, half-uploaded, and finished after an "app restart";
//! - a group DM of three;
//! - a build-42 style send is told to update;
//! - `skwod backup` → `skwod restore` into a fresh folder: same skwod, members carry on.
//!
//! Skips gracefully if the server can't build.

use std::process::{Child, Command};
use std::sync::{Arc, Once};
use std::time::Duration;

use skwod_core::{Message, SkwodClient};
use skwod_sync::ApiClient;

static BUILD: Once = Once::new();

fn server_manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/Cargo.toml")
}
fn build_server() -> bool {
    // `SKWOD_TEST_SERVER_BIN=<path>`: use that server binary (e.g. a release build that is
    // already there) instead of building a debug one.
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

/// A server process that can be stopped ("the network went away") and started again on the
/// same address — and pointed at another data folder (a restored backup).
struct Server {
    /// The owner's join code, printed once by a fresh instance.
    join_code: Option<String>,
    child: Option<Child>,
    data: std::path::PathBuf,
    port: u16,
    base: String,
    _dir: tempfile::TempDir,
}

impl Server {
    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    async fn start(&mut self) {
        assert!(self.child.is_none());
        // A real, OWNED instance (no open signup): the first account, signing up with the join
        // code the server prints once, owns it — which is who abuse reports are sealed to.
        let mut child = Command::new(server_bin())
            .args(["run", "--listen", &format!("127.0.0.1:{}", self.port), "--admin-listen", "off", "--data"])
            .arg(&self.data)
            .env_remove("SKWOD_OPEN_SIGNUP")
            .env("SKWOD_NO_P2P", "true")
            .env("SKWOD_BLOB_FREE_FLOOR_MB", "0")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("spawn server");
        let (tx, rx) = std::sync::mpsc::channel();
        let out = child.stdout.take().expect("stdout");
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in std::io::BufReader::new(out).lines().map_while(Result::ok) {
                if let Some(code) = line.strip_prefix("Join code: ") {
                    let _ = tx.send(code.trim().to_string());
                }
            }
        });
        self.child = Some(child);
        if self.join_code.is_none() {
            self.join_code = rx.recv_timeout(Duration::from_secs(60)).ok();
        }
        let http = reqwest::Client::new();
        for _ in 0..600 {
            if http.get(format!("{}/health", self.base)).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("server never became healthy");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn start() -> Option<Server> {
    if !build_server() {
        eprintln!("SKIP: could not build skwod-server");
        return None;
    }
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let mut server = Server { join_code: None, child: None, data: dir.path().join("data"), port, base: format!("http://127.0.0.1:{port}"), _dir: dir };
    server.start().await;
    Some(server)
}

fn key(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

const STORY: &str = "\u{2}skwod/story|";

struct World {
    server: Server,
    caches: tempfile::TempDir,
    alice: String,
    alice_token: String,
    /// The Mac's own session (build 44a: a session speaks for ONE device).
    mac_token: String,
    bob: String,
    bob_token: String,
    carol: String,
    /// Alice's phone (owner's first device) and Mac; Bob's phone and tablet; Carol's phone.
    phone: Arc<SkwodClient>,
    mac: Arc<SkwodClient>,
    bobs: Arc<SkwodClient>,
    tablet: Arc<SkwodClient>,
    carols: Arc<SkwodClient>,
    server_id: String,
    channel: String,
}

impl World {
    fn everyone(&self) -> [(&Arc<SkwodClient>, &String); 5] {
        [(&self.phone, &self.alice), (&self.mac, &self.alice), (&self.bobs, &self.bob), (&self.tablet, &self.bob), (&self.carols, &self.carol)]
    }

    /// Let sealed mail (keys, provisioning, DMs, DM operations, reports) settle everywhere.
    async fn pump(&self) {
        for _ in 0..3 {
            for (c, me) in self.everyone() {
                let _ = c.process_control_inbox(me.clone()).await;
            }
        }
    }

    /// Hand out everyone's sender key for `channel`.
    async fn key_channel(&self, channel: &str) {
        for (c, me) in self.everyone() {
            c.sync_channel_membership(channel.to_string(), self.server_id.clone(), me.clone()).await.expect("share channel key");
        }
        self.pump().await;
    }
}

/// Link `new` (a second device of the account behind `first`) and give it the space key.
async fn link(first: &SkwodClient, new: &SkwodClient, me: &str, w_host: &SkwodClient, host: &str, host_dev: &str, server_id: &str) {
    assert!(new.register_device().await.is_err(), "a second device must be linked");
    let code = new.begin_device_link().await.expect("begin link");
    assert!(first.approve_device_link(code).await.expect("approve link"));
    new.complete_device_link().await.expect("complete").expect("approved");
    first.process_control_inbox(me.to_string()).await.unwrap();
    new.process_control_inbox(me.to_string()).await.unwrap();
    new.request_provision(server_id.to_string(), host.to_string(), host_dev.to_string()).await.expect("ask for the space key");
    for _ in 0..2 {
        let _ = w_host.process_control_inbox(host.to_string()).await;
        let _ = first.process_control_inbox(me.to_string()).await;
        let _ = new.process_control_inbox(me.to_string()).await;
    }
}

async fn world() -> Option<World> {
    let server = start().await?;
    let caches = tempfile::tempdir().unwrap();
    let path = |n: &str| caches.path().join(n).to_string_lossy().to_string();
    let signup = |name: &'static str, code: String| {
        let base = server.base.clone();
        async move { ApiClient::new(&base).signup_with_code(name, "password123", Some(&code)).await.unwrap_or_else(|e| panic!("signup {name}: {e}")) }
    };
    // Alice signs up with the host's join code: she owns the instance.
    let a = signup("alice", server.join_code.clone().expect("a fresh instance prints its join code")).await;
    let pinned = skwod_core::fetch_server_identity(server.base.clone()).await.expect("identity").server_public;
    let client = |token: &str, file: &str, k: char| {
        let (base, token, file, pinned) = (server.base.clone(), token.to_string(), path(file), pinned.clone());
        async move {
            let c = SkwodClient::new(base, token);
            c.attach_cache(file, key(k)).await.unwrap();
            c.set_pinned_server_key(pinned).await.expect("pin the instance key");
            c
        }
    };

    let phone = client(&a.token, "phone.sqlite3", 'a').await;
    let phone_dev = phone.register_device().await.expect("register phone");
    let space = phone.create_space("Crew".into(), "general".into()).await.expect("space");
    // Everyone else gets in with an invite of hers.
    let invite = || async { phone.invite_to_space(space.server_id.clone(), "code".into(), None).await.expect("invite") };
    let b = signup("bobby", invite().await).await;
    let c = signup("carol", invite().await).await;
    // A second device signs in for itself: a session speaks for the one device it registered
    // or bound, so two installs never share a token.
    let login = |name: &'static str| {
        let base = server.base.clone();
        async move { ApiClient::new(&base).login(name, "password123").await.unwrap_or_else(|e| panic!("login {name}: {e}")).token }
    };
    let mac_token = login("alice").await;
    let mac = client(&mac_token, "mac.sqlite3", 'b').await;
    link(&phone, &mac, &a.user_id, &phone, &a.user_id, &phone_dev, &space.server_id).await;

    let join = |who: Arc<SkwodClient>, user_id: String| {
        let (phone, server_id) = (phone.clone(), space.server_id.clone());
        async move {
            who.register_device().await.expect("register");
            let invite = phone.invite_to_space(server_id.clone(), "code".into(), None).await.unwrap();
            assert!(who.join_by_code(invite).await.unwrap().pending);
            phone.approve_join_request(server_id.clone(), user_id.clone()).await.unwrap();
            phone.approve_member(server_id, user_id).await.unwrap();
        }
    };
    let bobs = client(&b.token, "bob.sqlite3", 'c').await;
    join(bobs.clone(), b.user_id.clone()).await;
    let carols = client(&c.token, "carol.sqlite3", 'e').await;
    join(carols.clone(), c.user_id.clone()).await;
    for _ in 0..2 {
        let _ = phone.process_control_inbox(a.user_id.clone()).await;
        let _ = bobs.process_control_inbox(b.user_id.clone()).await;
        let _ = carols.process_control_inbox(c.user_id.clone()).await;
    }
    let tablet_token = login("bobby").await;
    let tablet = client(&tablet_token, "tablet.sqlite3", 'd').await;
    link(&bobs, &tablet, &b.user_id, &phone, &a.user_id, &phone_dev, &space.server_id).await;

    let w = World {
        server,
        caches,
        alice: a.user_id,
        alice_token: a.token,
        mac_token,
        bob: b.user_id,
        bob_token: b.token,
        carol: c.user_id,
        phone,
        mac,
        bobs,
        tablet,
        carols,
        server_id: space.server_id,
        channel: space.channel_id,
    };
    w.pump().await;
    w.key_channel(&w.channel.clone()).await;
    // Everyone has OPENED the channel in this server's list (build 45: that is what confirms
    // where it belongs on a device, and what the owner's clears and deletions are checked
    // against — a placement the server merely listed authorises nothing).
    for (c, _) in w.everyone() {
        assert!(c.channel_opened(w.server_id.clone(), w.channel.clone()).await);
    }
    Some(w)
}

async fn chat(c: &SkwodClient, channel: &str, me: &str) -> Vec<Message> {
    c.fetch_channel_messages(channel.into(), me.into()).await.expect("fetch")
}

/// What people wrote (membership notices — "X joined" — are rows too; they are not counted).
fn texts(rows: &[Message]) -> Vec<String> {
    rows.iter().filter(|m| !m.is_deleted && m.author_id.as_deref() != Some("__system__")).filter_map(|m| m.content.clone()).collect()
}

async fn dm_texts(c: &SkwodClient, convo: &str) -> Vec<String> {
    texts(&c.history(format!("dm:{convo}")).await)
}

/// Row `id` of a DM conversation: (text, edited, deleted, reply target).
async fn dm_row(c: &SkwodClient, convo: &str, id: &str) -> (Option<String>, bool, bool, Option<String>) {
    let m = c.history(format!("dm:{convo}")).await.into_iter().find(|m| m.message_id == id).unwrap_or_else(|| panic!("no row {id}"));
    (m.content, m.is_edited, m.is_deleted, m.reply_to_id)
}

// ---- 1. block and report ----

#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_person_disappears_everywhere_and_cannot_dm_you() {
    let Some(w) = world().await else { return };
    let feed = w.phone.feed_channel(w.server_id.clone()).await.unwrap();
    w.key_channel(&feed).await;

    // Bob chats, posts a story, and reacts to something Alice said.
    let hello = w.phone.send_channel_message(w.channel.clone(), "hello all".into()).await.unwrap();
    w.bobs.send_channel_message(w.channel.clone(), "bob says hi".into()).await.unwrap();
    w.carols.send_channel_message(w.channel.clone(), "carol says hi".into()).await.unwrap();
    w.bobs.send_channel_message(feed.clone(), format!("{STORY}{{\"text\":\"bob's story\"}}")).await.unwrap();
    w.bobs.add_reaction(w.channel.clone(), hello.clone(), "👍".into()).await.unwrap();
    w.carols.add_reaction(w.channel.clone(), hello.clone(), "🎉".into()).await.unwrap();
    let convo = w.bobs.open_dm(w.alice.clone()).await.unwrap();
    w.bobs.send_dm(convo.clone(), w.alice.clone(), String::new(), "before the block".into()).await.unwrap();
    assert_eq!(w.phone.sync_dms().await.unwrap().len(), 1);

    let before = texts(&chat(&w.phone, &w.channel, &w.alice).await);
    assert!(before.contains(&"bob says hi".to_string()) && before.contains(&"carol says hi".to_string()));
    assert_eq!(texts(&chat(&w.phone, &feed, &w.alice).await).len(), 1);
    assert_eq!(w.phone.channel_reactions(w.channel.clone()).await.len(), 2);
    assert!(w.phone.blocked_user_ids().is_empty());

    // Alice blocks Bob, on her phone.
    w.phone.block_user(w.bob.clone()).await.expect("block");
    assert_eq!(w.phone.blocked_user_ids(), vec![w.bob.clone()]);
    assert!(w.phone.is_blocked(w.bob.clone()) && !w.phone.is_blocked(w.carol.clone()));

    // His chat lines, his story and his reaction are gone from what she reads — Carol's stay.
    let after = texts(&chat(&w.phone, &w.channel, &w.alice).await);
    assert!(!after.contains(&"bob says hi".to_string()), "{after:?}");
    assert!(after.contains(&"carol says hi".to_string()) && after.contains(&"hello all".to_string()));
    assert!(texts(&chat(&w.phone, &feed, &w.alice).await).is_empty(), "his story is gone");
    assert!(w.phone.history_page(format!("channel:{}", w.channel), i64::MAX, 100).await.iter().all(|m| m.author_id.as_deref() != Some(w.bob.as_str())));
    let reactions = w.phone.channel_reactions(w.channel.clone()).await;
    assert_eq!(reactions.iter().map(|r| r.user_id.as_str()).collect::<Vec<_>>(), vec![w.carol.as_str()], "only Carol's reaction is left");
    assert!(dm_texts(&w.phone, &convo).await.is_empty(), "the DM he sent earlier is hidden too");
    assert!(w.phone.list_dms().await.unwrap().iter().all(|c| c.peer_user_id != w.bob), "and the conversation is not listed");

    // What he writes from now on never shows, and nothing of his is a DM event.
    w.bobs.send_channel_message(w.channel.clone(), "can you hear me?".into()).await.unwrap();
    assert!(!texts(&chat(&w.phone, &w.channel, &w.alice).await).contains(&"can you hear me?".to_string()));
    let dm = w.bobs.send_dm(convo.clone(), w.alice.clone(), String::new(), "after the block".into()).await;
    assert!(dm.is_err(), "the server no longer hands him her devices: {dm:?}");
    assert!(w.bobs.open_dm(w.alice.clone()).await.is_err(), "nor opens a conversation");
    assert!(w.phone.sync_dms().await.unwrap().is_empty());

    // Her Mac learns of the block at launch (`refresh_blocks`) and hides him too.
    assert!(texts(&chat(&w.mac, &w.channel, &w.alice).await).contains(&"bob says hi".to_string()), "not yet known on the Mac");
    let listed = w.mac.refresh_blocks().await.expect("refresh");
    assert_eq!(listed.iter().map(|b| (b.user_id.as_str(), b.username.as_str())).collect::<Vec<_>>(), vec![(w.bob.as_str(), "bobby")]);
    assert!(!texts(&chat(&w.mac, &w.channel, &w.alice).await).iter().any(|t| t.contains("bob") || t.contains("hear me")));
    // …and it survives a restart of the app (the list is in the device's state).
    drop(listed);
    let mac_again = SkwodClient::new(w.server.base.clone(), w.mac_token.clone());
    assert!(mac_again.attach_cache(w.caches.path().join("mac.sqlite3").to_string_lossy().to_string(), key('b')).await.unwrap());
    assert_eq!(mac_again.blocked_user_ids(), vec![w.bob.clone()], "known before any network call");
    assert!(!texts(&mac_again.history(format!("channel:{}", w.channel)).await).contains(&"bob says hi".to_string()));

    // Unblock: nothing of hers was destroyed — what he wrote before is readable again. What he
    // wrote WHILE blocked never reached her: the server hid her devices from him, so his device
    // stopped keying her in (to him she had left the channel).
    w.phone.unblock_user(w.bob.clone()).await.unwrap();
    let back = texts(&chat(&w.phone, &w.channel, &w.alice).await);
    assert!(back.contains(&"bob says hi".to_string()), "{back:?}");
    assert!(!back.contains(&"can you hear me?".to_string()), "{back:?}");
    assert_eq!(w.phone.channel_reactions(w.channel.clone()).await.len(), 2);
    assert_eq!(dm_texts(&w.phone, &convo).await, ["before the block"]);
    // And he can reach her again: his next message arrives once his device re-keys her.
    w.bobs.send_channel_message(w.channel.clone(), "friends again".into()).await.unwrap();
    assert!(texts(&chat(&w.phone, &w.channel, &w.alice).await).contains(&"friends again".to_string()), "nobody had to be let in again");
    // …and she him.
    w.phone.send_channel_message(w.channel.clone(), "truce".into()).await.unwrap();
    assert!(texts(&chat(&w.bobs, &w.channel, &w.bob).await).contains(&"truce".to_string()));
    assert!(texts(&chat(&w.tablet, &w.channel, &w.bob).await).contains(&"truce".to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_report_from_a_message_reaches_the_owner_sealed_and_the_server_gets_no_text() {
    let Some(w) = world().await else { return };
    assert_eq!(w.bobs.instance_owner().await.as_deref(), Some(w.alice.as_str()), "Bob knows who owns the skwod (attested under the pinned key)");
    w.carols.send_channel_message(w.channel.clone(), "something nasty".into()).await.unwrap();
    let seen = chat(&w.bobs, &w.channel, &w.bob).await;
    let nasty = seen.iter().find(|m| m.content.as_deref() == Some("something nasty")).expect("Bob sees it");

    // Bob reports it from the message menu and chooses to include what was said.
    let receipt = w
        .bobs
        .report_message_at(
            "harassment".into(),
            Some("she keeps doing this".into()),
            nasty.content.clone(),
            nasty.author_id.clone(),
            Some(w.server_id.clone()),
            Some(w.channel.clone()),
            Some(nasty.message_id.clone()),
        )
        .await
        .expect("the report is filed");
    assert!(!receipt.report_id.is_empty(), "there is an id to confirm with");
    assert!(receipt.sealed_to_owner);

    // The server's queue (the owner's admin view) has the metadata — and not one word of text.
    let http = reqwest::Client::new();
    let queue: serde_json::Value = http.get(format!("{}/api/reports", w.server.base)).bearer_auth(&w.alice_token).send().await.unwrap().json().await.unwrap();
    let row = queue["reports"].as_array().unwrap().iter().find(|r| r["report_id"] == receipt.report_id.as_str()).expect("queued");
    assert_eq!((row["reporter_id"].as_str(), row["subject_user_id"].as_str(), row["category"].as_str()), (Some(w.bob.as_str()), Some(w.carol.as_str()), Some("harassment")));
    assert!(row["body"].is_null(), "no plaintext on the server: {row}");
    assert!(!queue.to_string().contains("nasty") && !queue.to_string().contains("keeps doing"));
    assert!(!queue.to_string().contains(&nasty.message_id) && !queue.to_string().contains(&w.channel), "nor where the message is");

    // Alice — the owner — receives the sealed part on her devices.
    assert!(w.carols.received_reports().await.is_empty());
    w.phone.sync_dms().await.unwrap();
    let got = w.phone.received_reports().await;
    assert_eq!(got.len(), 1, "{got:?}");
    let r = &got[0];
    assert_eq!((r.report_id.as_str(), r.reporter_user_id.as_str(), r.subject_user_id.as_deref()), (receipt.report_id.as_str(), w.bob.as_str(), Some(w.carol.as_str())));
    assert_eq!((r.category.as_str(), r.note.as_deref(), r.excerpt.as_deref()), ("harassment", Some("she keeps doing this"), Some("something nasty")));
    assert_eq!(r.server_id.as_deref(), Some(w.server_id.as_str()));
    // …and where the message is, so her reports inbox can find it — in her OWN copy of the
    // channel — and remove it.
    assert_eq!((r.channel_id.as_deref(), r.message_id.as_deref()), (Some(w.channel.as_str()), Some(nasty.message_id.as_str())));
    let hers = w.phone.fetch_channel_messages(w.channel.clone(), w.alice.clone()).await.unwrap();
    assert_eq!(hers.iter().find(|m| Some(&m.message_id) == r.message_id.as_ref()).and_then(|m| m.content.as_deref()), r.excerpt.as_deref(), "the quote matches what her device decrypted");
    w.phone.delete_channel_message(w.channel.clone(), nasty.message_id.clone()).await.expect("the owner may remove a member's message");
    assert!(chat(&w.bobs, &w.channel, &w.bob).await.iter().all(|m| m.content.as_deref() != Some("something nasty")), "gone for the reporter too");
    // It is not a DM: no conversation appears, nobody is notified as if it were a message.
    assert!(w.phone.take_dm_events().await.is_empty());
    // A redelivery does not duplicate it, and dismissing removes it.
    w.phone.sync_dms().await.unwrap();
    assert_eq!(w.phone.received_reports().await.len(), 1);
    w.phone.dismiss_report(r.report_id.clone(), r.reporter_user_id.clone()).await;
    assert!(w.phone.received_reports().await.is_empty());

    // Reporting WITHOUT the message (and with a blank note): the owner gets neither.
    let receipt = w.bobs.report_message("spam".into(), Some("  ".into()), None, Some(w.carol.clone()), None).await.unwrap();
    assert!(receipt.sealed_to_owner);
    w.mac.sync_dms().await.unwrap();
    let got = w.mac.received_reports().await;
    let r = got.iter().find(|r| r.report_id == receipt.report_id).expect("on the Mac too");
    assert_eq!((r.note.as_deref(), r.excerpt.as_deref()), (None, None));
    assert_eq!((r.channel_id.as_deref(), r.message_id.as_deref()), (None, None));

    // The owner reporting has nobody to seal to: the note goes to her own server's queue and a
    // quoted message is never sent in plaintext.
    let own = w.phone.report_message("abuse".into(), Some("note to self".into()), Some("quoted".into()), Some(w.carol.clone()), None).await.unwrap();
    assert!(!own.sealed_to_owner);
    let queue: serde_json::Value = http.get(format!("{}/api/reports", w.server.base)).bearer_auth(&w.alice_token).send().await.unwrap().json().await.unwrap();
    assert!(queue.to_string().contains("note to self") && !queue.to_string().contains("quoted"));
}

/// Security review: a member sends a channel message and a DM whose bodies are, byte for byte,
/// the core's "couldn't decrypt — asking Alice to resend" stand-in and a system notice. On the
/// receiving device they are messages: not flagged, shown as plain text, notified like any
/// other — while a REAL placeholder and a real notice keep their flags.
#[tokio::test(flavor = "multi_thread")]
async fn a_message_that_looks_like_a_placeholder_or_a_notice_is_shown_as_plain_text() {
    let Some(w) = world().await else { return };
    let forged = format!("\u{2}skwod/undecryptable|{}", serde_json::json!({ "from": w.alice, "final": false }));
    let notice = format!("\u{2}skwod/sys|{}", serde_json::json!({ "kind": "identity_changed", "user_id": w.alice, "device_id": "x", "was_verified": true }));
    let a = w.carols.send_channel_message(w.channel.clone(), forged.clone()).await.unwrap();
    let b = w.carols.send_channel_message(w.channel.clone(), notice.clone()).await.unwrap();
    let seen = chat(&w.bobs, &w.channel, &w.bob).await;
    for id in [&a, &b] {
        let m = seen.iter().find(|m| &m.message_id == id).expect("Bob has it");
        assert!(!m.is_undecryptable && !m.is_system, "a message, not one of the core's rows");
        assert_eq!(m.author_id.as_deref(), Some(w.carol.as_str()), "under its real author");
        let text = m.content.clone().unwrap();
        assert!(text.starts_with("skwod/"), "plain text: {text:?}");
        assert!(skwod_core::message_notifies(text));
    }
    let fake = seen.into_iter().find(|m| m.message_id == a).unwrap();
    assert_eq!(skwod_core::undecryptable_placeholder(fake), None);

    // The same by direct message (and its event is plain text too, so the notification is).
    let conv = w.carols.open_dm(w.bob.clone()).await.unwrap();
    let bob_device = w.bobs.current_device_id().await.unwrap();
    let dm = w.carols.send_dm(conv.clone(), w.bob.clone(), bob_device, forged.clone()).await.unwrap();
    let events = w.bobs.sync_dms().await.unwrap();
    let event = events.iter().find(|e| e.message_id == dm).expect("the DM arrived");
    assert!(event.text.starts_with("skwod/") && skwod_core::message_notifies(event.text.clone()));
    let row = w.bobs.history(format!("dm:{conv}")).await.into_iter().find(|m| m.message_id == dm).unwrap();
    assert!(!row.is_undecryptable && !row.is_system && row.content.as_deref().is_some_and(|t| t.starts_with("skwod/")));
    // The real notices of this world (people joining) are still notices.
    assert!(chat(&w.phone, &w.channel, &w.alice).await.iter().any(|m| m.is_system), "the core's own rows keep their flag");
}

// ---- 2. outbox ----

#[tokio::test(flavor = "multi_thread")]
async fn messages_queued_offline_are_delivered_once_each_when_the_network_returns() {
    let Some(mut w) = world().await else { return };
    let feed = w.phone.feed_channel(w.server_id.clone()).await.unwrap();
    w.key_channel(&feed).await;
    let first = w.phone.send_channel_message(w.channel.clone(), "sent while online".into()).await.unwrap();

    // The server's time, not the phone's clock, is what an own message is filed under.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/api/channels/{}/messages", w.server.base, w.channel))
        .bearer_auth(&w.alice_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let server_time = listed["messages"].as_array().unwrap().iter().find(|m| m["message_id"] == first.as_str()).unwrap()["created_at"].as_i64().unwrap();
    let own = w.phone.cached_message(format!("channel:{}", w.channel), first.clone()).await.unwrap();
    assert_eq!(own.created_at, server_time, "own copy carries the server's created_at");
    assert_eq!(chat(&w.bobs, &w.channel, &w.bob).await.iter().find(|m| m.message_id == first).unwrap().created_at, server_time, "the same time Bob has");

    // The network goes away.
    w.server.stop();
    let direct = w.phone.send_channel_message(w.channel.clone(), "this would have vanished".into()).await;
    assert!(direct.is_err(), "a direct send fails offline");

    let mut queued = Vec::new();
    for text in ["one", "two", "three"] {
        queued.push(w.phone.queue_channel_message(w.channel.clone(), text.into(), None, vec![], vec![]).await.expect("queue"));
    }
    let post = w.phone.queue_channel_message(feed.clone(), "\u{2}skwod/feed|{\"text\":\"posted offline\"}".into(), None, vec![], vec![]).await.unwrap();
    let scope = format!("channel:{}", w.channel);
    // They are in history at once, as hers, in order…
    let local = w.phone.history(scope.clone()).await;
    assert_eq!(texts(&local)[texts(&local).len() - 3..], ["one", "two", "three"]);
    assert!(local.iter().rev().take(3).all(|m| m.author_id.as_deref() == Some("__me__")));
    // …marked as sending.
    let pending = w.phone.pending_sends(Some(scope.clone())).await;
    assert_eq!(pending.iter().map(|p| (p.message_id.as_str(), p.kind.as_str(), p.state.as_str())).collect::<Vec<_>>(), queued.iter().map(|id| (id.as_str(), "send", "sending")).collect::<Vec<_>>());
    assert_eq!(w.phone.pending_sends(None).await.len(), 4);

    // Flushing with no network changes nothing, however often it is tried.
    for _ in 0..3 {
        let r = w.phone.flush_outbox().await;
        assert_eq!((r.sent, r.pending, r.failed), (0, 4, 0), "{r:?}");
    }

    // The app is killed and started again while still offline: the queue is on disk.
    let phone = SkwodClient::new(w.server.base.clone(), w.alice_token.clone());
    assert!(phone.attach_cache(w.caches.path().join("phone.sqlite3").to_string_lossy().to_string(), key('a')).await.unwrap());
    assert_eq!(phone.pending_sends(None).await.len(), 4, "the outbox survives a restart");

    // The network returns.
    w.server.start().await;
    let r = phone.flush_outbox().await;
    assert_eq!((r.sent, r.pending, r.failed), (4, 0, 0), "{r:?}");
    assert!(phone.pending_sends(None).await.is_empty());
    // A second flush (two triggers racing: reconnect and a timer) sends nothing again.
    let (a, b) = tokio::join!(phone.flush_outbox(), phone.flush_outbox());
    assert_eq!(a.sent + b.sent, 0);

    // Bob has each exactly once, in the order she wrote them, under the ids she chose.
    let bob_view = chat(&w.bobs, &w.channel, &w.bob).await;
    let tail: Vec<(&str, &str)> = bob_view.iter().rev().take(3).rev().map(|m| (m.message_id.as_str(), m.content.as_deref().unwrap_or_default())).collect();
    assert_eq!(tail, vec![(queued[0].as_str(), "one"), (queued[1].as_str(), "two"), (queued[2].as_str(), "three")]);
    for text in ["one", "two", "three"] {
        assert_eq!(bob_view.iter().filter(|m| m.content.as_deref() == Some(text)).count(), 1, "{text} delivered once");
    }
    let bob_feed = chat(&w.bobs, &feed, &w.bob).await;
    assert_eq!(bob_feed.iter().filter(|m| m.message_id == post).count(), 1, "the post too");
    // Her own rows now carry the server's time (the same as Bob's copies).
    for id in &queued {
        let mine = phone.cached_message(scope.clone(), id.clone()).await.unwrap();
        assert_eq!(mine.created_at, bob_view.iter().find(|m| &m.message_id == id).unwrap().created_at);
    }
    // Her Mac shows them as HERS (`__me__`), although another device sent them.
    let mac_view = chat(&w.mac, &w.channel, &w.alice).await;
    assert!(mac_view.iter().filter(|m| queued.contains(&m.message_id)).all(|m| m.author_id.as_deref() == Some("__me__")), "own messages from another device are mine");
    assert_eq!(mac_view.iter().filter(|m| queued.contains(&m.message_id)).count(), 3);

    // Lost answer: the request arrived, the reply did not. The retry is not a duplicate.
    let again = phone.queue_channel_message(w.channel.clone(), "once only".into(), None, vec![], vec![]).await.unwrap();
    assert_eq!(phone.flush_outbox().await.sent, 1);
    let http = reqwest::Client::new();
    let resend = http
        .post(format!("{}/api/channels/{}/messages", w.server.base, w.channel))
        .bearer_auth(&w.alice_token)
        // (Build 44a: a post names the device that makes it — the one this session is bound to.)
        .json(&serde_json::json!({ "message_id": again, "ciphertext": "cmV0cnk=", "author_device_id": phone.current_device_id().await }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resend.json().await.unwrap();
    assert_eq!(body["duplicate"], true, "{body}");
    assert_eq!(chat(&w.bobs, &w.channel, &w.bob).await.iter().filter(|m| m.content.as_deref() == Some("once only")).count(), 1);

    // Edit, reaction and delete queue the same way; a delete of something never sent just
    // takes it back.
    w.server.stop();
    phone.queue_channel_edit(w.channel.clone(), queued[0].clone(), "one (edited)".into()).await.unwrap();
    phone.queue_reaction(w.channel.clone(), queued[1].clone(), "🔥".into(), false).await.unwrap();
    phone.queue_channel_delete(w.channel.clone(), queued[2].clone()).await.unwrap();
    let never = phone.queue_channel_message(w.channel.clone(), "typed and regretted".into(), None, vec![], vec![]).await.unwrap();
    phone.queue_channel_delete(w.channel.clone(), never.clone()).await.unwrap();
    assert!(phone.cached_message(scope.clone(), never.clone()).await.is_none(), "taken back before it ever left");
    assert_eq!(phone.pending_sends(None).await.iter().map(|p| p.kind.clone()).collect::<Vec<_>>(), ["edit", "reaction", "delete"]);
    w.server.start().await;
    assert_eq!(phone.flush_outbox().await.sent, 3);
    let bob_view = chat(&w.bobs, &w.channel, &w.bob).await;
    let row = |id: &str| bob_view.iter().find(|m| m.message_id == id).unwrap();
    assert_eq!((row(&queued[0]).content.as_deref(), row(&queued[0]).is_edited), (Some("one (edited)"), true));
    assert!(row(&queued[2]).is_deleted);
    assert!(bob_view.iter().all(|m| m.message_id != never));
    assert!(w.bobs.channel_reactions(w.channel.clone()).await.iter().any(|r| r.message_id == queued[1] && r.emoji.as_deref() == Some("🔥")));

    // Something the server REFUSES is not retried forever: it is marked failed with a
    // sentence, it does not hold up what is queued behind it, and it can be discarded.
    let big = phone.queue_channel_message(w.channel.clone(), "x".repeat(10), None, vec!["00000000-0000-4000-8000-000000000000".into()], vec![]).await.unwrap();
    let after = phone.queue_channel_message(w.channel.clone(), "behind the failure".into(), None, vec![], vec![]).await.unwrap();
    let r = phone.flush_outbox().await;
    assert_eq!((r.sent, r.failed), (1, 1), "{r:?}");
    let failed = phone.pending_sends(None).await;
    assert_eq!(failed.len(), 1);
    assert_eq!((failed[0].message_id.as_str(), failed[0].state.as_str()), (big.as_str(), "failed"));
    assert!(failed[0].error.as_deref().is_some_and(|e| !e.is_empty()), "there is a sentence to show");
    assert!(texts(&chat(&w.bobs, &w.channel, &w.bob).await).contains(&"behind the failure".to_string()));
    let _ = after;
    phone.discard_send(failed[0].local_id.clone()).await;
    assert!(phone.pending_sends(None).await.is_empty());
    assert!(phone.cached_message(scope, big).await.is_none(), "a discarded send leaves no ghost row");
}

// ---- 3. DM parity ----

#[tokio::test(flavor = "multi_thread")]
async fn dm_reply_edit_delete_and_reactions_show_on_both_peoples_two_devices() {
    let Some(w) = world().await else { return };
    let convo = w.phone.open_dm(w.bob.clone()).await.unwrap();
    let to_bob = vec![w.bob.clone()];
    let to_alice = vec![w.alice.clone()];
    let all = [&w.phone, &w.mac, &w.bobs, &w.tablet];
    let settle = || async {
        for c in all {
            let _ = c.sync_dms().await;
        }
    };

    let first = w.phone.send_dm(convo.clone(), w.bob.clone(), String::new(), "dinner at 7?".into()).await.unwrap();
    settle().await;
    for c in all {
        assert_eq!(dm_texts(c, &convo).await, ["dinner at 7?"]);
    }

    // Reply — from Bob's TABLET (a second device).
    let reply = w.tablet.reply_dm(convo.clone(), to_alice.clone(), "make it 8".into(), first.clone()).await.expect("reply");
    let events = w.phone.sync_dms().await.unwrap();
    assert!(events.iter().any(|e| e.kind == "message" && e.message_id == reply && !e.from_self && e.peer_user_id == w.bob), "a reply notifies like a message: {events:?}");
    settle().await;
    for c in all {
        assert_eq!(dm_row(c, &convo, &reply).await, (Some("make it 8".into()), false, false, Some(first.clone())), "the quote link is there");
    }
    assert_eq!(w.bobs.history(format!("dm:{convo}")).await.iter().find(|m| m.message_id == reply).unwrap().author_id.as_deref(), Some("__me__"), "Bob's phone shows his tablet's reply as his");

    // Edit — Alice edits her message on her MAC; it changes on all four devices.
    w.mac.sync_dms().await.unwrap();
    w.mac.edit_dm(convo.clone(), to_bob.clone(), first.clone(), "dinner at 8 then".into()).await.expect("edit");
    let events = w.bobs.sync_dms().await.unwrap();
    assert!(events.iter().any(|e| e.kind == "edit" && e.message_id == first), "an edit is an event that does not notify: {events:?}");
    settle().await;
    for c in all {
        assert_eq!(dm_row(c, &convo, &first).await, (Some("dinner at 8 then".into()), true, false, None));
    }

    // React — Bob on his phone, Alice on her phone; everyone sees both.
    w.bobs.react_dm(convo.clone(), to_alice.clone(), first.clone(), "👍".into(), false).await.expect("react");
    w.phone.react_dm(convo.clone(), to_bob.clone(), reply.clone(), "❤️".into(), false).await.expect("react");
    settle().await;
    for c in all {
        let mut r: Vec<(String, String, String)> = c.dm_reactions(convo.clone()).await.into_iter().map(|r| (r.message_id, r.user_id, r.emoji.unwrap_or_default())).collect();
        r.sort();
        let mut want = vec![(first.clone(), w.bob.clone(), "👍".to_string()), (reply.clone(), w.alice.clone(), "❤️".to_string())];
        want.sort();
        assert_eq!(r, want);
    }
    // …and taking one off.
    w.tablet.react_dm(convo.clone(), to_alice.clone(), first.clone(), "👍".into(), true).await.unwrap();
    settle().await;
    for c in all {
        assert_eq!(c.dm_reactions(convo.clone()).await.len(), 1);
    }

    // Nobody edits or deletes someone else's message: not through the API…
    let err = w.bobs.edit_dm(convo.clone(), to_alice.clone(), first.clone(), "hijacked".into()).await.unwrap_err();
    assert!(matches!(err, skwod_core::CoreError::Invalid { .. }), "{err}");
    assert!(w.bobs.delete_dm(convo.clone(), to_alice.clone(), first.clone()).await.is_err());
    settle().await;
    assert_eq!(dm_row(&w.phone, &convo, &first).await.0.as_deref(), Some("dinner at 8 then"));

    // Delete for everyone — Bob deletes his reply from his phone (the tablet sent it).
    w.bobs.delete_dm(convo.clone(), to_alice.clone(), reply.clone()).await.expect("delete");
    settle().await;
    for c in all {
        assert_eq!(dm_row(c, &convo, &reply).await, (None, false, true, Some(first.clone())), "shown as removed, text gone");
        assert!(c.dm_reactions(convo.clone()).await.iter().all(|r| r.message_id != reply), "its reactions went with it");
    }

    // Queued while offline-ish (the outbox path): a DM, an edit of it and a reaction.
    let queued = w.phone.queue_dm(convo.clone(), to_bob.clone(), "see you there".into(), None, vec![]).await.unwrap();
    assert_eq!(w.phone.pending_sends(Some(format!("dm:{convo}"))).await.len(), 1);
    w.phone.queue_dm_reaction(convo.clone(), to_bob.clone(), first.clone(), "🍝".into(), false).await.unwrap();
    assert_eq!(w.phone.flush_outbox().await.sent, 2);
    settle().await;
    for c in all {
        assert!(dm_texts(c, &convo).await.contains(&"see you there".to_string()));
        assert!(c.dm_reactions(convo.clone()).await.iter().any(|r| r.emoji.as_deref() == Some("🍝")));
    }
    let _ = queued;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_group_dm_of_three_reaches_every_device_of_every_member() {
    let Some(w) = world().await else { return };
    assert!(w.phone.open_group_dm(vec![w.bob.clone()]).await.is_err(), "two people is a DM, not a group");
    let group = w.phone.open_group_dm(vec![w.bob.clone(), w.carol.clone()]).await.expect("open group");
    let others_of = |me: &str| [&w.alice, &w.bob, &w.carol].into_iter().filter(|u| u.as_str() != me).cloned().collect::<Vec<String>>();

    let hello = w.phone.send_group_dm(group.clone(), others_of(&w.alice), "trip this weekend?".into()).await.expect("send to the group");
    for (c, _) in w.everyone() {
        let _ = c.sync_dms().await;
    }
    for (c, _) in w.everyone() {
        assert_eq!(dm_texts(c, &group).await, ["trip this weekend?"], "every device of every member");
    }
    // It is listed as a group (and not among the 1:1 conversations).
    let listed = w.carols.list_group_dms().await.unwrap();
    assert_eq!(listed.len(), 1);
    let mut members = listed[0].member_user_ids.clone();
    members.sort();
    let mut want = others_of(&w.carol);
    want.sort();
    assert_eq!((listed[0].conversation_id.as_str(), members), (group.as_str(), want));
    assert!(w.carols.list_dms().await.unwrap().is_empty());

    // Carol answers with a reply and a reaction; Bob edits nothing of hers.
    let answer = w.carols.reply_dm(group.clone(), others_of(&w.carol), "yes!".into(), hello.clone()).await.unwrap();
    w.carols.react_dm(group.clone(), others_of(&w.carol), hello.clone(), "🏕️".into(), false).await.unwrap();
    for (c, _) in w.everyone() {
        let _ = c.sync_dms().await;
    }
    for (c, _) in w.everyone() {
        assert_eq!(dm_texts(c, &group).await, ["trip this weekend?", "yes!"]);
        assert_eq!(c.dm_reactions(group.clone()).await.len(), 1);
    }
    assert!(w.bobs.edit_dm(group.clone(), others_of(&w.bob), answer, "no!".into()).await.is_err());
    // A message addressed to fewer people than the group has reaches only them: the sender
    // decides who it is sealed to, not the server's member list.
    w.bobs.send_group_dm(group.clone(), vec![w.carol.clone()], "just for carol".into()).await.unwrap();
    for (c, _) in w.everyone() {
        let _ = c.sync_dms().await;
    }
    assert!(dm_texts(&w.carols, &group).await.contains(&"just for carol".to_string()));
    assert!(!dm_texts(&w.phone, &group).await.contains(&"just for carol".to_string()));
}

// ---- 4. channel clear ----

#[tokio::test(flavor = "multi_thread")]
async fn clearing_a_channel_empties_it_on_a_member_who_was_away() {
    let Some(w) = world().await else { return };
    for i in 0..5 {
        w.bobs.send_channel_message(w.channel.clone(), format!("old {i}")).await.unwrap();
    }
    w.phone.send_channel_message(w.channel.clone(), "\u{2}skwod/game|{\"stroke\":1}".into()).await.unwrap();
    let hello = w.phone.send_channel_message(w.channel.clone(), "old from alice".into()).await.unwrap();
    w.bobs.add_reaction(w.channel.clone(), hello, "👍".into()).await.unwrap();
    // Everyone has it cached — Bob's tablet and Carol then go away. Each of them OPENED the
    // channel in this server's list, which is what lets the owner's clear reach their cache
    // (build 45: a placement the server merely listed authorises nothing).
    for (c, me) in w.everyone() {
        assert!(c.channel_opened(w.server_id.clone(), w.channel.clone()).await);
        assert_eq!(texts(&chat(c, &w.channel, me).await).len(), 6);
    }
    assert_eq!(w.tablet.fetch_aux_messages(w.channel.clone(), w.bob.clone()).await.unwrap().len(), 1);
    assert_eq!(w.tablet.channel_reactions(w.channel.clone()).await.len(), 1);

    // A plain member cannot clear; the owner can.
    assert!(w.bobs.clear_channel_messages(w.channel.clone()).await.is_err());
    w.phone.clear_channel_messages(w.channel.clone()).await.expect("clear");
    w.phone.send_channel_message(w.channel.clone(), "fresh start".into()).await.unwrap();

    // The Mac was online: it gets the realtime event and empties at once, without a fetch.
    w.mac.channel_cleared(w.channel.clone(), None).await;
    assert!(w.mac.history(format!("channel:{}", w.channel)).await.is_empty(), "emptied on the event alone");

    // The tablet and Carol never saw the event. Their caches still hold the old messages…
    assert_eq!(texts(&w.tablet.history(format!("channel:{}", w.channel)).await).len(), 6);
    // …until their next sync: everything from before the clear is purged — chat, game state,
    // reactions, and their OWN messages too — and what came after is there.
    for (c, me) in [(&w.tablet, &w.bob), (&w.carols, &w.carol), (&w.bobs, &w.bob), (&w.mac, &w.alice), (&w.phone, &w.alice)] {
        assert_eq!(texts(&chat(c, &w.channel, me).await), ["fresh start"], "only what was written after the clear");
        assert!(c.fetch_aux_messages(w.channel.clone(), me.clone()).await.unwrap().is_empty(), "the whiteboard went too");
        assert!(c.channel_reactions(w.channel.clone()).await.is_empty());
        // Nothing a person wrote before the clear is left; the rows the core wrote about who
        // joined and whose keys changed are not messages and are not the clearer's to erase.
        assert!(c.history_page(format!("channel:{}", w.channel), i64::MAX, 500).await.iter().all(|m| m.is_system || m.content.as_deref() == Some("fresh start")));
    }
    // A second sync does not purge again (a message sent after the clear survives).
    w.bobs.send_channel_message(w.channel.clone(), "second".into()).await.unwrap();
    assert_eq!(texts(&chat(&w.tablet, &w.channel, &w.bob).await), ["fresh start", "second"]);
}

// ---- 6. stories ----

#[tokio::test(flavor = "multi_thread")]
async fn a_story_ends_for_everyone_by_the_servers_clock_and_can_be_deleted() {
    let Some(w) = world().await else { return };
    let feed = w.phone.feed_channel(w.server_id.clone()).await.unwrap();
    w.key_channel(&feed).await;
    // The sender's own idea of the time is inside the body and is a lie (a year in the future).
    let lie = 4_102_444_800_000i64;
    let bobs_story = w.bobs.send_channel_message(feed.clone(), format!("{STORY}{{\"text\":\"bob\",\"ts\":{lie}}}")).await.unwrap();
    let alices_story = w.phone.send_channel_message(feed.clone(), format!("{STORY}{{\"text\":\"alice\",\"ts\":{lie}}}")).await.unwrap();
    let post = w.phone.send_channel_message(feed.clone(), "\u{2}skwod/feed|{\"text\":\"a post is not a story\"}".into()).await.unwrap();
    let comment = w.bobs.send_channel_message(feed.clone(), format!("\u{2}skwod/comment|{{\"postId\":\"{post}\",\"text\":\"nice\"}}")).await.unwrap();
    for (c, me) in w.everyone() {
        assert_eq!(texts(&chat(c, &feed, me).await).len(), 4);
    }
    // Long TTL: nothing ends, whatever the bodies claim.
    assert_eq!(w.phone.expire_stories(feed.clone(), STORY.into(), 24 * 3600 * 1000).await, 0);
    // The device clock is close to the server's (same machine), and known from the send.
    assert!((w.phone.server_now_ms().await - std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64).abs() < 5_000);

    // Time passes (a TTL of 1.5 s stands in for 24 h).
    tokio::time::sleep(Duration::from_millis(1_700)).await;
    let ttl = 1_500;
    // Alice's phone: Bob's story is purged from her cache; her own is deleted for everyone.
    assert_eq!(w.phone.expire_stories(feed.clone(), STORY.into(), ttl).await, 2);
    let mine = chat(&w.phone, &feed, &w.alice).await;
    assert!(mine.iter().all(|m| m.message_id != bobs_story), "someone else's expired story is gone from this device");
    assert!(mine.iter().find(|m| m.message_id == alices_story).is_some_and(|m| m.is_deleted), "her own is tombstoned");
    assert!(texts(&mine).iter().all(|t| !t.starts_with(STORY)));
    assert_eq!(texts(&mine).len(), 2, "the post and the comment are untouched");
    // Everyone else sees Alice's story end on their next sync — no matter what their clock says
    // (Carol never runs the expiry at all here).
    for (c, me) in [(&w.carols, &w.carol), (&w.tablet, &w.bob), (&w.mac, &w.alice)] {
        let view = chat(c, &feed, me).await;
        assert!(view.iter().find(|m| m.message_id == alices_story).unwrap().is_deleted, "the author's tombstone reached everyone");
    }
    // Its media went with it: the server holds no ciphertext for a tombstoned story.
    let listed: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/api/channels/{feed}/messages", w.server.base))
        .bearer_auth(&w.bob_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = listed["messages"].as_array().unwrap().iter().find(|m| m["message_id"] == alices_story.as_str()).unwrap();
    assert!(row["deleted_at"].as_i64().is_some() && row["ciphertext"].as_str() == Some(""), "{row}");
    // Bob's phone ends his own.
    chat(&w.bobs, &feed, &w.bob).await;
    assert_eq!(w.bobs.expire_stories(feed.clone(), STORY.into(), ttl).await, 1, "his own; Alice's is already a tombstone");
    assert!(chat(&w.carols, &feed, &w.carol).await.iter().find(|m| m.message_id == bobs_story).unwrap().is_deleted);
    // Running it again ends nothing more.
    assert_eq!(w.phone.expire_stories(feed.clone(), STORY.into(), ttl).await, 0);

    // Delete for posts and comments: by their author, from any of their devices.
    w.tablet.queue_channel_delete(feed.clone(), comment.clone()).await.expect("Bob deletes his comment from the tablet");
    w.mac.queue_channel_delete(feed.clone(), post.clone()).await.expect("Alice deletes her post from the Mac");
    assert_eq!(w.tablet.flush_outbox().await.sent, 1);
    assert_eq!(w.mac.flush_outbox().await.sent, 1);
    for (c, me) in w.everyone() {
        assert!(texts(&chat(c, &feed, me).await).is_empty(), "post and comment are gone for everyone");
    }
    // Carol cannot delete Bob's comment… there is nothing left to try on, so: Alice's post id.
    w.carols.queue_channel_delete(feed.clone(), alices_story.clone()).await.unwrap();
    let r = w.carols.flush_outbox().await;
    assert_eq!(r.sent, 1, "deleting what is already gone counts as done: {r:?}");
}

// ---- 8. uploads ----

#[tokio::test(flavor = "multi_thread")]
async fn a_large_attachment_is_streamed_and_its_upload_resumes_after_a_restart() {
    let Some(mut w) = world().await else { return };
    let work = w.caches.path().join("uploads");
    let source = w.caches.path().join("holiday.mov");
    // 3.5 MiB of something recognizable (four chunks).
    let plain: Vec<u8> = (0..3_670_016u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &plain).unwrap();

    // Prepared OFFLINE: encryption needs no network.
    w.server.stop();
    let up = w.phone.prepare_upload(source.to_string_lossy().into(), work.to_string_lossy().into(), false).await.expect("prepare");
    assert_eq!((up.plaintext_len, up.key.len(), up.digest.len()), (plain.len() as u64, 64, 32));
    assert!(up.blob_len > up.plaintext_len && up.download_token.is_none());
    let sealed_file = work.join(format!("{}.blob", up.upload_id));
    let sealed = std::fs::read(&sealed_file).unwrap();
    assert_eq!(sealed.len() as u64, up.blob_len);
    assert!(!sealed.windows(64).any(|w| w == &plain[..64]), "what is on disk is ciphertext");
    // The source can go away now (a share-sheet temp file would).
    std::fs::remove_file(&source).unwrap();

    // The message is queued with the attachment still to upload.
    let descriptor = format!("\u{2}skwod/attach|{{\"blobId\":\"{}\",\"name\":\"holiday.mov\"}}", up.placeholder_blob_id);
    let message = w.phone.queue_channel_message(w.channel.clone(), descriptor.clone(), None, vec![], vec![up.upload_id.clone()]).await.unwrap();
    assert_eq!(w.phone.flush_outbox().await.pending, 1);
    assert_eq!(w.phone.pending_uploads().await.iter().map(|p| (p.sent, p.total, p.done)).collect::<Vec<_>>(), [(0, up.blob_len, false)]);

    // Online: two chunks go up, then the connection drops and the app is killed.
    w.server.start().await;
    assert_eq!(w.phone.upload_some(&up.upload_id, 2).await.unwrap(), None, "interrupted part-way");
    let progress = w.phone.pending_uploads().await;
    assert_eq!((progress[0].sent, progress[0].done), (2 * 1024 * 1024, false));
    let blob_id = progress[0].blob_id.clone().expect("the blob exists on the server");
    let http = reqwest::Client::new();
    let offset = |r: &reqwest::Response| r.headers()["upload-offset"].to_str().unwrap().parse::<u64>().unwrap();
    let r = http.get(format!("{}/api/blobs/{blob_id}/offset", w.server.base)).bearer_auth(&w.alice_token).send().await.unwrap();
    assert_eq!(offset(&r), 2 * 1024 * 1024);

    // A chunk whose answer was lost: the server is AHEAD of what the device recorded. (Sent
    // here behind the client's back.)
    let third = sealed[2 * 1024 * 1024..3 * 1024 * 1024].to_vec();
    let r = http.patch(format!("{}/api/blobs/{blob_id}", w.server.base)).bearer_auth(&w.alice_token).header("upload-offset", 2 * 1024 * 1024).body(third).send().await.unwrap();
    assert_eq!(offset(&r), 3 * 1024 * 1024);

    // Restart: a new client on the same cache knows the upload and the queued message.
    let phone = SkwodClient::new(w.server.base.clone(), w.alice_token.clone());
    assert!(phone.attach_cache(w.caches.path().join("phone.sqlite3").to_string_lossy().to_string(), key('a')).await.unwrap());
    assert_eq!(phone.pending_uploads().await.len(), 1, "the upload is remembered across the restart");
    let report = phone.flush_outbox().await;
    assert_eq!((report.sent, report.pending, report.failed), (1, 0, 0), "{report:?}");
    // It continued the SAME blob from where the server stood — nothing was re-sent or duplicated.
    let r = http.get(format!("{}/api/blobs/{blob_id}/offset", w.server.base)).bearer_auth(&w.alice_token).send().await.unwrap();
    assert_eq!((offset(&r), r.headers()["upload-complete"].to_str().unwrap()), (up.blob_len, "1"));
    assert!(phone.pending_uploads().await.is_empty());
    assert!(!sealed_file.exists(), "the local ciphertext is removed once the message is out");

    // Bob gets the message with the REAL blob id, downloads it, and opens it file to file.
    let want = descriptor.replace(&up.placeholder_blob_id, &blob_id);
    assert_eq!(phone.cached_message(format!("channel:{}", w.channel), message.clone()).await.unwrap().content.as_deref(), Some(want.as_str()), "her own row names the real blob too");
    let seen = chat(&w.bobs, &w.channel, &w.bob).await;
    assert_eq!(seen.iter().find(|m| m.message_id == message).unwrap().content.as_deref(), Some(want.as_str()));
    let got = http.get(format!("{}/api/blobs/{blob_id}", w.server.base)).bearer_auth(&w.bob_token).send().await.unwrap();
    assert_eq!(got.status(), 200, "linked to the message, so Bob may fetch it");
    let (downloaded, opened) = (w.caches.path().join("dl.blob"), w.caches.path().join("dl.mov"));
    std::fs::write(&downloaded, got.bytes().await.unwrap()).unwrap();
    skwod_core::decrypt_attachment_file(downloaded.to_string_lossy().into(), opened.to_string_lossy().into(), up.key.clone(), up.digest.clone(), up.plaintext_len).expect("opens");
    assert_eq!(std::fs::read(&opened).unwrap(), plain);
    // A tampered download writes nothing.
    let mut bad = std::fs::read(&downloaded).unwrap();
    bad[1000] ^= 1;
    std::fs::write(&downloaded, bad).unwrap();
    let out = w.caches.path().join("bad.mov");
    assert!(skwod_core::decrypt_attachment_file(downloaded.to_string_lossy().into(), out.to_string_lossy().into(), up.key.clone(), up.digest.clone(), up.plaintext_len).is_err());
    assert!(!out.exists());

    // A DM attachment carries a download token; a discarded message drops its upload.
    std::fs::write(&source, b"small").unwrap();
    let dm = phone.prepare_upload(source.to_string_lossy().into(), work.to_string_lossy().into(), true).await.unwrap();
    assert!(dm.download_token.as_deref().is_some_and(|t| t.len() >= 32));
    let convo = phone.open_dm(w.bob.clone()).await.unwrap();
    w.server.stop();
    phone.queue_dm(convo.clone(), vec![w.bob.clone()], format!("\u{2}skwod/attach|{{\"blobId\":\"{}\"}}", dm.placeholder_blob_id), None, vec![dm.upload_id.clone()]).await.unwrap();
    let pending = phone.pending_sends(None).await;
    phone.discard_send(pending[0].local_id.clone()).await;
    assert!(phone.pending_uploads().await.is_empty() && !work.join(format!("{}.blob", dm.upload_id)).exists());
    assert!(dm_texts(&phone, &convo).await.is_empty());
}

// ---- 9 & 10. the host: old builds, backup and move ----

#[tokio::test(flavor = "multi_thread")]
async fn a_build_42_send_is_told_to_update_and_current_builds_name_themselves() {
    let Some(w) = world().await else { return };
    let http = reqwest::Client::new();
    // What build 42 posted: a ciphertext and its device, no message id.
    let devices = w.bobs.list_own_devices().await.unwrap();
    let res = http
        .post(format!("{}/api/channels/{}/messages", w.server.base, w.channel))
        .bearer_auth(&w.bob_token)
        .json(&serde_json::json!({ "ciphertext": "djI=", "author_device_id": devices[0] }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 426);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("https://skwod.io/download"), "{body}");
    // Its sync loop polls the mailbox: same answer, which builds 41/42 show as an alert.
    let inbox = format!("{}/api/e2ee/sealed/inbox?device_id={}", w.server.base, devices[0]);
    assert_eq!(http.get(&inbox).bearer_auth(&w.bob_token).send().await.unwrap().status(), 426);
    // The same device on a current build names its build with every request and is let in:
    // the core's own sync works, and clears the mark.
    w.bobs.sync_dms().await.expect("a build-44 client is not refused");
    w.tablet.sync_dms().await.expect("nor the account's other device");
    assert_eq!(http.get(&inbox).bearer_auth(&w.bob_token).send().await.unwrap().status(), 200, "the mark is gone once the device showed it was updated");
    assert_eq!(skwod_sync::CLIENT_BUILD, 44);
}

fn cli(args: &[&str], passphrase: &str) -> std::process::Output {
    Command::new(server_bin()).args(args).env("SKWOD_BACKUP_PASSPHRASE", passphrase).output().expect("run skwod")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_host_is_exported_and_imported_into_a_fresh_folder_and_members_carry_on() {
    let Some(mut w) = world().await else { return };
    let pass = "correct horse battery staple";
    for i in 0..3 {
        w.bobs.send_channel_message(w.channel.clone(), format!("history {i}")).await.unwrap();
    }
    let identity = skwod_core::fetch_server_identity(w.server.base.clone()).await.unwrap();
    let invite = w.phone.invite_to_space(w.server_id.clone(), "code".into(), None).await.unwrap();
    let old_data = w.server.data.clone();
    let scratch = w.caches.path().to_path_buf();
    let file = scratch.join("crew.skwodbackup");
    let s = |p: &std::path::Path| p.to_string_lossy().to_string();

    // Export, with the server running (a consistent copy is taken). A weak passphrase is refused.
    let weak = cli(&["backup", "--data", &s(&old_data), "--out", &s(&file)], "123456");
    assert!(!weak.status.success() && String::from_utf8_lossy(&weak.stderr).contains("too weak"), "{weak:?}");
    let made = Command::new(server_bin())
        .args(["backup", "--data", &s(&old_data), "--out", &s(&file)])
        .env("SKWOD_BACKUP_PASSPHRASE", pass)
        .env("SKWOD_BACKUP_OWNER_LOGIN", r#"{"username":"alice","password":"password123"}"#)
        .output()
        .unwrap();
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    let raw = std::fs::read(&file).unwrap();
    assert!(!raw.windows(15).any(|w| w == b"SQLite format 3") && !raw.windows(11).any(|w| w == b"password123"), "the export is encrypted");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // Something written AFTER the export is, of course, not in it.
    w.bobs.send_channel_message(w.channel.clone(), "after the export".into()).await.unwrap();

    // The old Mac is gone.
    w.server.stop();

    // Import on "the new Mac": a fresh folder. Wrong passphrase: nothing happens.
    let new_data = scratch.join("new-mac").join("skwod-host-data");
    let login_out = scratch.join("owner-login.json");
    let wrong = cli(&["restore", "--in", &s(&file), "--data", &s(&new_data)], "not the passphrase at all");
    assert!(!wrong.status.success() && !new_data.exists(), "{wrong:?}");
    let checked = cli(&["restore", "--in", &s(&file), "--data", &s(&new_data), "--verify-only"], pass);
    assert!(checked.status.success() && !new_data.exists(), "verify restores nothing: {checked:?}");
    let restored = cli(&["restore", "--in", &s(&file), "--data", &s(&new_data), "--owner-login-out", &s(&login_out)], pass);
    assert!(restored.status.success(), "{}", String::from_utf8_lossy(&restored.stderr));
    assert_eq!(std::fs::read_to_string(&login_out).unwrap(), r#"{"username":"alice","password":"password123"}"#, "the owner's login came along");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [new_data.clone(), new_data.join("skwod.db"), new_data.join("blobs"), login_out.clone()] {
            let meta = std::fs::metadata(&p).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, if meta.is_dir() { 0o700 } else { 0o600 }, "{}", p.display());
        }
    }
    // Importing over a folder that holds a skwod is refused.
    let again = cli(&["restore", "--in", &s(&file), "--data", &s(&new_data)], pass);
    assert!(!again.status.success() && String::from_utf8_lossy(&again.stderr).contains("already holds a skwod"));

    // "Change storage folder" MOVES the skwod.
    let moved = scratch.join("external-disk").join("skwod-host-data");
    let mv = cli(&["move-data", "--from", &s(&new_data), "--to", &s(&moved)], pass);
    assert!(mv.status.success(), "{}", String::from_utf8_lossy(&mv.stderr));
    assert!(!new_data.join("skwod.db").exists() && moved.join("skwod.db").exists());

    // The server starts on the restored, moved folder — at the same address.
    w.server.data = moved.clone();
    w.server.start().await;
    let now = skwod_core::fetch_server_identity(w.server.base.clone()).await.unwrap();
    assert_eq!((now.instance_id, now.server_public), (identity.instance_id, identity.server_public), "the same instance: its key is what invites pin");
    // (The p2p key — the node id an invite addresses — is part of the folder; p2p is off in
    // this test, so the old folder has none to compare. `hostbackup.rs` tests cover it.)

    // A restore signs everyone out (server M-6, SELF-HOSTING.md): every session ends. Members
    // sign in again — each install on the cache and keys it already had — bind the new
    // session to their device, and see the history.
    for (c, _) in w.everyone() {
        assert_eq!(c.session_state().await, skwod_core::SessionState::SignedOut, "a restore ends every session");
    }
    let pinned = skwod_core::fetch_server_identity(w.server.base.clone()).await.unwrap().server_public;
    for (name, file, k, slot) in [("alice", "phone.sqlite3", 'a', 0), ("alice", "mac.sqlite3", 'b', 1), ("bobby", "bob.sqlite3", 'c', 2), ("bobby", "tablet.sqlite3", 'd', 3), ("carol", "carol.sqlite3", 'e', 4)] {
        let token = ApiClient::new(&w.server.base).login(name, "password123").await.unwrap_or_else(|e| panic!("login {name}: {e}")).token;
        let c = SkwodClient::new(w.server.base.clone(), token);
        c.attach_cache(w.caches.path().join(file).to_string_lossy().to_string(), key(k)).await.unwrap();
        c.set_pinned_server_key(pinned.clone()).await.expect("pin the instance key");
        assert!(c.bind_session().await.expect("bind the new session"), "{name}: the install is still the account's device");
        match slot { 0 => w.phone = c, 1 => w.mac = c, 2 => w.bobs = c, 3 => w.tablet = c, _ => w.carols = c }
    }
    for (c, me) in w.everyone() {
        assert_eq!(c.session_state().await, skwod_core::SessionState::Valid, "signed in again");
        let view = texts(&chat(c, &w.channel, me).await);
        for i in 0..3 {
            assert!(view.contains(&format!("history {i}")), "{view:?}");
        }
    }
    // …and keep talking: new messages flow both ways on the restored server.
    w.phone.send_channel_message(w.channel.clone(), "we moved house".into()).await.expect("send on the restored server");
    assert!(texts(&chat(&w.carols, &w.channel, &w.carol).await).contains(&"we moved house".to_string()));
    w.carols.send_channel_message(w.channel.clone(), "works here".into()).await.unwrap();
    assert!(texts(&chat(&w.tablet, &w.channel, &w.bob).await).contains(&"works here".to_string()));
    // The invite handed out before the move still lets someone in.
    assert!(skwod_core::check_invite(w.server.base.clone(), invite.clone()).await.unwrap().valid, "the invite handed out before the move is still good");
    let dave = ApiClient::new(&w.server.base).signup_with_code("david", "password123", Some(&invite)).await.expect("signup on the restored server");
    let daves = SkwodClient::new(w.server.base.clone(), dave.token.clone());
    daves.attach_cache(scratch.join("dave.sqlite3").to_string_lossy().to_string(), key('f')).await.unwrap();
    daves.register_device().await.unwrap();
    let joined = daves.join_by_code(invite).await.expect("the old invite still works");
    assert!(joined.pending, "and still asks the owner");

    // The daily snapshot of the new folder was taken at start; the pre-export folder still
    // has its own.
    let snaps = |d: &std::path::Path| std::fs::read_dir(d.join("snapshots")).map(|r| r.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("daily-")).count()).unwrap_or(0);
    assert_eq!((snaps(&old_data), snaps(&moved)), (1, 1), "one local snapshot per day in each data folder");
}

// ---- a hostile server and the attachment descriptor (security review) ----

/// A server that answers `POST /api/blobs` with whatever "blob id" it likes (and accepts every
/// chunk). Returns its base URL and the paths it was asked for.
fn hostile_blob_server(blob_id: &'static str) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let log = log.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                // Read the head, then as much body as Content-Length says.
                let (head_end, length) = loop {
                    let Ok(n) = stream.read(&mut chunk) else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..at]).to_lowercase();
                        let length = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                        break (at + 4, length);
                    }
                };
                while buf.len() < head_end + length {
                    let Ok(n) = stream.read(&mut chunk) else { return };
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let request_line = String::from_utf8_lossy(&buf).lines().next().unwrap_or_default().to_string();
                log.lock().unwrap().push(request_line.clone());
                let body = if request_line.starts_with("POST /api/blobs ") {
                    serde_json::json!({ "blob_id": blob_id, "max_chunk": 16777216 }).to_string()
                } else {
                    "{}".to_string()
                };
                let extra = if request_line.starts_with("PATCH ") || request_line.contains("/offset") { "upload-offset: 999999999\r\nupload-complete: 1\r\n" } else { "" };
                let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n{extra}content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).as_bytes());
            });
        }
    });
    (base, seen)
}

/// The server chooses a blob's id. One that is not a plain UUID — here: text that would close
/// the descriptor's string and add an attacker's key, and a path that would climb out of
/// `/api/blobs/` — fails the upload. It is never stored, never requested as a path, and never
/// reaches the message a recipient would trust as the sender's.
#[tokio::test(flavor = "multi_thread")]
async fn a_server_that_returns_a_hostile_blob_id_fails_the_send_and_cannot_alter_the_descriptor() {
    for hostile in [
        "x\",\"key\":\"ATTACKERKEY\",\"digest\":\"ATTACKERDIGEST",
        "../../api/auth/logout",
        "3f2b8c1e-9a4d-4e6f-8b7a-0c1d2e3f4a5b\",\"key\":\"ATTACKERKEY",
        "3F2B8C1E-9A4D-4E6F-8B7A-0C1D2E3F4A5B",
    ] {
        let (base, seen) = hostile_blob_server(hostile);
        let dir = tempfile::tempdir().unwrap();
        let client = SkwodClient::new(base, "token".into());
        client.attach_cache(dir.path().join("c.sqlite3").to_string_lossy().to_string(), key('a')).await.unwrap();
        let source = dir.path().join("photo.jpg");
        std::fs::write(&source, vec![7u8; 5000]).unwrap();
        let up = client.prepare_upload(source.to_string_lossy().into(), dir.path().join("work").to_string_lossy().into(), false).await.unwrap();

        // Uploading directly: refused, with nothing recorded.
        let err = client.finish_upload(up.upload_id.clone()).await.unwrap_err();
        assert!(err.to_string().contains("attachment id"), "{hostile:?}: {err}");
        let progress = client.pending_uploads().await;
        assert_eq!((progress.len(), progress[0].blob_id.clone(), progress[0].sent), (1, None, 0), "{hostile:?}: the id was not kept");

        // Through the outbox: the message is not sent, and its body is exactly what was queued.
        let channel = "11111111-1111-4111-8111-111111111111".to_string();
        let body = format!("\u{2}skwod/attach|{{\"blobId\":\"{}\",\"key\":\"SENDERKEY\"}}", up.placeholder_blob_id);
        let id = client.queue_channel_message(channel.clone(), body.clone(), None, vec![], vec![up.upload_id.clone()]).await.unwrap();
        for _ in 0..4 {
            let r = client.flush_outbox().await;
            assert_eq!(r.sent, 0, "{hostile:?}: nothing may go out");
            // (Backoff between soft failures: make every pass an attempt.)
            for p in client.pending_sends(None).await {
                if p.state == "failed" {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let row = client.cached_message(format!("channel:{channel}"), id).await.expect("still queued locally");
        assert_eq!(row.content.as_deref(), Some(body.as_str()), "{hostile:?}: the descriptor is untouched");
        assert!(!row.content.unwrap().contains("ATTACKER"));

        // The server was asked to create a blob — and for nothing derived from its answer:
        // no chunk upload, no offset query, no message, no path built from the hostile id.
        let asked = seen.lock().unwrap().clone();
        assert!(asked.iter().any(|l| l.starts_with("POST /api/blobs ")), "{asked:?}");
        assert!(asked.iter().all(|l| l.starts_with("POST /api/blobs ")), "{hostile:?}: only blob creation was ever requested: {asked:?}");

        // Dropping the upload does not turn the id into a DELETE path either.
        client.release_upload(up.upload_id.clone(), true).await;
        assert!(seen.lock().unwrap().iter().all(|l| !l.starts_with("DELETE")), "{hostile:?}");
    }
}
