//! Integration tests against a REAL skwod-server process.
//!
//! Builds the server binary once, launches it on an ephemeral data dir + port, and drives the
//! sync client's REST and WebSocket paths end to end. Skips gracefully (with a printed notice)
//! if the server binary can't be built in this environment.

use std::process::{Child, Command};
use std::sync::Once;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use skwod_sync::{ApiClient, Engine, PeerId, RealtimeClient, RtEvent, Session};

static BUILD: Once = Once::new();

fn server_manifest() -> std::path::PathBuf {
    // core/skwod-sync/tests → ../../../server
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

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Launch a server on `port` against `data_dir`; wait for /health.
async fn launch(port: u16, data_dir: &std::path::Path) -> Option<Child> {
    let child = Command::new(server_bin())
        .args(["run", "--listen", &format!("127.0.0.1:{port}"), "--data"])
        .arg(data_dir)
        // A throwaway test instance: open signup is asked for explicitly (`skwod run` otherwise
        // auto-initializes a fresh volume behind a join code), and no p2p endpoint is needed.
        .env("SKWOD_OPEN_SIGNUP", "1")
        .env("SKWOD_NO_P2P", "true")
        .spawn()
        .ok()?;
    let http = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    for _ in 0..50 {
        if http.get(format!("{base}/health")).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            return Some(child);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Launch a server on a free port; return None if the build isn't possible here.
async fn start_server() -> Option<ServerGuard> {
    if !build_server() {
        eprintln!("SKIP: could not build skwod-server in this environment");
        return None;
    }
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let child = launch(port, dir.path()).await?;
    Some(ServerGuard { child, _dir: dir, base: format!("http://127.0.0.1:{port}") })
}

#[tokio::test]
async fn rest_signup_and_message_roundtrip() {
    let Some(server) = start_server().await else { return };
    let api = ApiClient::new(&server.base);

    let session = api.signup("syncuser", "password123").await.expect("signup");
    let api = api.with_token(&session.token);

    // Create a server + channel via the generic helpers.
    let srv = api.post("/api/servers", serde_json::json!({ "name_ciphertext": "ZW5j" })).await.unwrap();
    let server_id = srv["server_id"].as_str().unwrap();
    let ch = api
        .post(&format!("/api/servers/{server_id}/channels"), serde_json::json!({ "name_ciphertext": "ZW5j" }))
        .await
        .unwrap();
    let channel_id = ch["channel_id"].as_str().unwrap().to_string();

    // Send an opaque ciphertext and read it back.
    let (msg_id, _) = api.send_channel_message(&channel_id, "b3BhcXVl").await.expect("send");
    let msgs = api.channel_messages(&channel_id, i64::MAX, 50).await.expect("list");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0]["message_id"].as_str().unwrap(), msg_id);
    assert_eq!(msgs[0]["ciphertext"].as_str().unwrap(), "b3BhcXVl");
}

#[tokio::test]
async fn realtime_delivers_live_message() {
    let Some(server) = start_server().await else { return };
    let api = ApiClient::new(&server.base);
    let session = api.signup("rtuser", "password123").await.expect("signup");
    let api = api.with_token(&session.token);

    let srv = api.post("/api/servers", serde_json::json!({ "name_ciphertext": "ZW5j" })).await.unwrap();
    let server_id = srv["server_id"].as_str().unwrap();
    let ch = api
        .post(&format!("/api/servers/{server_id}/channels"), serde_json::json!({ "name_ciphertext": "ZW5j" }))
        .await
        .unwrap();
    let channel_id = ch["channel_id"].as_str().unwrap().to_string();

    let ws_url = format!("{}/api/ws", server.base.replacen("http", "ws", 1));
    let (rt, mut events) = RealtimeClient::connect(ws_url, session.token.clone());
    rt.subscribe(format!("channel:{channel_id}"));
    // Give the subscribe a beat to register before publishing.
    tokio::time::sleep(Duration::from_millis(200)).await;

    api.send_channel_message(&channel_id, "bGl2ZQ==").await.expect("send");

    // Await the fan-out event.
    let ev = tokio::time::timeout(Duration::from_secs(5), events.recv()).await.expect("event within 5s").expect("event");
    match ev {
        RtEvent::Message { topic, event, payload } => {
            assert_eq!(topic, format!("channel:{channel_id}"));
            assert_eq!(event, "message");
            assert_eq!(payload["ciphertext"].as_str().unwrap(), "bGl2ZQ==");
        }
        other => panic!("expected a message event, got {other:?}"),
    }
}

#[tokio::test]
async fn realtime_reconnects_resubscribes_and_signals_backfill() {
    if !build_server() {
        eprintln!("SKIP: could not build skwod-server");
        return;
    }
    // Fixed port + persistent data dir so we can kill and restart the same instance.
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let base = format!("http://127.0.0.1:{port}");

    let mut child = launch(port, dir.path()).await.expect("first launch");
    let api = ApiClient::new(&base);
    let session = api.signup("reconuser", "password123").await.expect("signup");
    let api = api.with_token(&session.token);
    let srv = api.post("/api/servers", serde_json::json!({ "name_ciphertext": "ZW5j" })).await.unwrap();
    let server_id = srv["server_id"].as_str().unwrap();
    let ch = api
        .post(&format!("/api/servers/{server_id}/channels"), serde_json::json!({ "name_ciphertext": "ZW5j" }))
        .await
        .unwrap();
    let channel_id = ch["channel_id"].as_str().unwrap().to_string();

    let ws_url = format!("ws://127.0.0.1:{port}/api/ws");
    let (rt, mut events) = RealtimeClient::connect(&ws_url, session.token.clone());
    rt.subscribe(format!("channel:{channel_id}"));
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Kill the server out from under the live socket.
    child.kill().unwrap();
    child.wait().unwrap();

    // Bring it back on the same port + data dir; the client must reconnect and re-subscribe
    // on its own, then signal that a backfill is due.
    let mut child2 = launch(port, dir.path()).await.expect("relaunch");

    let reconnected = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match events.recv().await {
                Some(RtEvent::Reconnected) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .expect("reconnect within 20s");
    assert!(reconnected, "client should emit Reconnected after the server returns");

    // Prove the resubscription actually took: a fresh send now reaches the socket.
    let (_, _) = api.send_channel_message(&channel_id, "YWZ0ZXI=").await.expect("send after reconnect");
    let ev = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Some(RtEvent::Message { payload, .. }) => return payload,
                Some(_) => continue,
                None => panic!("stream closed"),
            }
        }
    })
    .await
    .expect("message after reconnect");
    assert_eq!(ev["ciphertext"].as_str().unwrap(), "YWZ0ZXI=");

    child2.kill().unwrap();
    child2.wait().unwrap();
}

/// Sign up `name` and register its first device. Returns (session, engine, its address).
async fn user(base: &str, name: &str) -> (Session, Engine, PeerId) {
    let api = ApiClient::new(base);
    let session = api.signup(name, "password123").await.unwrap();
    let mut engine = Engine::new(ApiClient::new(base).with_token(&session.token));
    let device = engine.register().await.expect("register first device");
    let peer = PeerId { user_id: session.user_id.clone(), device_id: device };
    (session, engine, peer)
}

/// Put two accounts in one server. Since build 45 that (or a conversation both have written
/// in) is what lets one account look the other up, open a conversation with it and fetch its
/// keys: to a stranger the server answers 404.
async fn meet(host: &mut Engine, guest: &mut Engine) {
    let space = host.create_space("Shared", "general").await.expect("space");
    let code = host.invite_to_space(&space.server_id, "token", None).await.expect("invite");
    assert!(!guest.join_space(&code, &space.space_key_hex, &space.channel_id).await.expect("join").pending);
}

/// Add a device to an existing account the only way there is: linked by one of its devices.
/// The new device shows a code, the user types it into `existing`, the new device completes.
async fn device(base: &str, session: &Session, existing: &mut Engine) -> (Engine, PeerId) {
    // A session of its own: a session speaks for one device (the one it registered), so the
    // new install signs in rather than borrowing the first device's token.
    let me = ApiClient::new(base).with_token(&session.token).get("/api/auth/me").await.expect("me");
    let own = ApiClient::new(base).login(me["username"].as_str().unwrap(), "password123").await.expect("login");
    let mut engine = Engine::new(ApiClient::new(base).with_token(&own.token));
    assert!(matches!(engine.register().await, Err(skwod_sync::EngineError::LinkRequired)), "a token alone cannot add a device");
    let code = engine.begin_link().await.expect("begin link");
    assert_eq!(engine.complete_link().await.unwrap(), None, "not approved yet");
    assert!(existing.approve_link(&code).await.expect("approve link"));
    let device = engine.complete_link().await.expect("complete link").expect("approved");
    // The existing device verifies the newcomer's link signature and tells it about its siblings.
    existing.poll_inbox().await.unwrap();
    engine.poll_inbox().await.unwrap();
    assert!(existing.is_sibling(&device));
    let peer = PeerId { user_id: session.user_id.clone(), device_id: device };
    (engine, peer)
}

fn texts(v: Vec<skwod_sync::InboundMessage>) -> Vec<String> {
    v.into_iter().map(|m| m.text).collect()
}

/// The headline test: accounts with SEVERAL devices register libsignal identities on a real
/// server, fetch each other's PQXDH bundles through the real key directory, and exchange
/// sealed-sender DMs. Every device of the recipient gets the message, the sender's other device
/// gets a synced copy, and the server's DM relay never holds a byte of content.
#[tokio::test]
async fn two_clients_exchange_e2ee_dms_through_real_server() {
    let Some(server) = start_server().await else { return };
    let (a_session, mut alice, alice_peer) = user(&server.base, "alicee2ee").await;
    let (mut alice_mac, _) = device(&server.base, &a_session, &mut alice).await;
    let (b_session, mut bob, bob_peer) = user(&server.base, "bobe2ee").await;
    meet(&mut alice, &mut bob).await;
    let (mut bob_tablet, _) = device(&server.base, &b_session, &mut bob).await;

    let convo = alice.open_dm(&b_session.user_id).await.unwrap();
    assert_eq!(convo, bob.open_dm(&a_session.user_id).await.unwrap());

    // Alice → Bob: one send reaches BOTH of bob's devices, and alice's other device.
    let id1 = alice.send_dm(&convo, &bob_peer, "hello bob, this is E2EE").await.expect("alice send");
    for (who, engine) in [("bob phone", &mut bob), ("bob tablet", &mut bob_tablet)] {
        let got = engine.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.expect("fetch");
        engine.ack_inbox().await.unwrap();
        assert_eq!(got.len(), 1, "{who}");
        assert_eq!(got[0].text, "hello bob, this is E2EE", "{who}");
        assert_eq!(got[0].author_id, a_session.user_id, "{who}: author comes from the sealed-sender certificate");
        assert_eq!(got[0].message_id, id1, "{who}");
    }
    let synced = alice_mac.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap();
    alice_mac.ack_inbox().await.unwrap();
    assert_eq!(synced.len(), 1, "sender's sibling device gets a synced copy");
    assert_eq!((synced[0].text.as_str(), synced[0].author_id.as_str()), ("hello bob, this is E2EE", skwod_sync::SELF_AUTHOR));

    // Replies ride the established sessions; several rounds step the ratchets both ways.
    for i in 0..4 {
        let msg = format!("bob tablet msg {i}");
        bob_tablet.send_dm(&convo, &alice_peer, &msg).await.unwrap();
        let got = texts(alice.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap());
        alice.ack_inbox().await.unwrap();
        assert_eq!(got, [msg]);
        let reply = format!("alice msg {i}");
        alice.send_dm(&convo, &bob_peer, &reply).await.unwrap();
        let got = texts(bob_tablet.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap());
        bob_tablet.ack_inbox().await.unwrap();
        assert_eq!(got, [reply]);
    }

    // Acked mail is gone: a second sync returns nothing new (and a redelivery would be a rejected
    // duplicate, not a second copy).
    assert!(bob_tablet.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap().is_empty());

    // The server's DM relay holds no message at all — content only ever sat in sealed mailboxes.
    let raw = ApiClient::new(&server.base).with_token(&a_session.token);
    let relay = raw.get(&format!("/api/dms/{convo}/messages?limit=100")).await.unwrap();
    assert!(relay["messages"].as_array().unwrap().is_empty(), "no DM content on the authenticated relay");

    // Both sides see the same Signal safety number for a device pair.
    let sn_a = alice.safety_number(&a_session.user_id, &bob_peer).await.unwrap();
    let sn_b = bob.safety_number(&b_session.user_id, &alice_peer).await.unwrap();
    assert_eq!(sn_a, sn_b);
    assert_eq!(sn_a.len(), 60);

    // A message filed under a conversation the sender is not part of is dropped by the recipient.
    let (c_session, mut carol, _) = user(&server.base, "carole2ee").await;
    meet(&mut bob, &mut carol).await;
    let _carol_convo = carol.open_dm(&b_session.user_id).await.unwrap();
    // (Bob's phone first catches up: alice's four replies, which went to both of his devices, and
    // the synced copies of the four messages his tablet sent.)
    let caught_up = bob.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap();
    bob.ack_inbox().await.unwrap();
    assert_eq!(caught_up.iter().filter(|m| m.author_id == a_session.user_id).count(), 4);
    assert_eq!(caught_up.iter().filter(|m| m.author_id == skwod_sync::SELF_AUTHOR).count(), 4);
    assert_eq!(caught_up.len(), 8);
    carol.send_dm(&convo, &bob_peer, "injected into alice's thread").await.unwrap();
    assert!(bob.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap().is_empty());
    bob.ack_inbox().await.unwrap();
    assert!(bob.take_dms().is_empty(), "not filed anywhere");
    let _ = c_session;
}

/// Simultaneous initiation: both peers send their first message before either has received the
/// other's. libsignal keeps both sessions and converges; no message is lost in either direction.
#[tokio::test]
async fn simultaneous_first_messages_converge() {
    let Some(server) = start_server().await else { return };
    let (a_session, mut alice, alice_peer) = user(&server.base, "collidea").await;
    let (b_session, mut bob, bob_peer) = user(&server.base, "collideb").await;
    meet(&mut alice, &mut bob).await;
    let convo = alice.open_dm(&b_session.user_id).await.unwrap();

    alice.send_dm(&convo, &bob_peer, "from alice").await.unwrap();
    bob.send_dm(&convo, &alice_peer, "from bob").await.unwrap();
    assert_eq!(texts(alice.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap()), ["from bob"]);
    assert_eq!(texts(bob.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap()), ["from alice"]);
    alice.ack_inbox().await.unwrap();
    bob.ack_inbox().await.unwrap();

    alice.send_dm(&convo, &bob_peer, "alice second").await.unwrap();
    bob.send_dm(&convo, &alice_peer, "bob second").await.unwrap();
    assert_eq!(texts(alice.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap()), ["bob second"]);
    assert_eq!(texts(bob.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap()), ["alice second"]);
}

/// A device that reinstalls (same account, brand-new identity) is noticed: peers get a "safety
/// number changed" notice; a peer who had VERIFIED the old device is blocked from sending until
/// they accept the change.
#[tokio::test]
async fn reinstall_raises_safety_number_change_and_blocks_verified_peers() {
    let Some(server) = start_server().await else { return };
    let (a_session, mut alice, alice_peer) = user(&server.base, "snalice").await;
    let (b_session, mut bob, bob_peer) = user(&server.base, "snbob").await;
    meet(&mut alice, &mut bob).await;
    let convo = alice.open_dm(&b_session.user_id).await.unwrap();
    alice.send_dm(&convo, &bob_peer, "hi").await.unwrap();
    bob.poll_inbox().await.unwrap();
    bob.send_dm(&convo, &alice_peer, "hi back").await.unwrap();
    alice.poll_inbox().await.unwrap();
    let before = alice.safety_number(&a_session.user_id, &bob_peer).await.unwrap();
    // Verification is bound to the number the user compared: anything else is refused.
    let wrong = "0".repeat(60);
    assert!(matches!(alice.verify_contact(&b_session.user_id, &wrong).await, Err(skwod_sync::EngineError::IdentityChanged(_))));
    assert!(!alice.is_verified(&bob_peer));
    alice.verify_contact(&b_session.user_id, &before).await.unwrap();
    assert!(alice.is_verified(&bob_peer));
    // The QR code is directional: bob's code matches on alice's side, her own does not.
    let on_alice = alice.safety_qr(&b_session.user_id).await.unwrap();
    let on_bob = bob.safety_qr(&a_session.user_id).await.unwrap();
    assert_ne!(on_alice, on_bob);
    assert_eq!(alice.check_safety_qr(&b_session.user_id, &on_bob).await.unwrap().as_deref(), Some(before.as_str()));
    assert!(matches!(alice.check_safety_qr(&b_session.user_id, &on_alice).await, Err(skwod_sync::EngineError::IdentityChanged(_))), "own code must not match");
    assert_eq!(alice.check_safety_qr(&b_session.user_id, "skwod://join/x").await.unwrap(), None);
    assert!(alice.take_security_notices().is_empty());

    // Bob moves to a new phone: the old device links it, then removes itself (signed). The new
    // device has its own identity.
    let (mut bob2, bob2_peer) = device(&server.base, &b_session, &mut bob).await;
    bob2.delete_device(&bob_peer.device_id).await.expect("signed removal of the old device");
    assert_ne!(bob2_peer.device_id, bob_peer.device_id);
    // (A reset, by contrast, is not instant without a long-standing PIN: it is put on hold.)
    // (Signed in afresh: the session that registered the old device ended when it was removed.)
    let lost_session = ApiClient::new(&server.base).login("snbob", "password123").await.unwrap();
    let mut lost = Engine::new(ApiClient::new(&server.base).with_token(&lost_session.token));
    assert!(matches!(lost.register_reset(None).await, Err(skwod_sync::EngineError::ResetPending(_))));
    bob2.set_registration_pin(Some("824613"), None).await.expect("device sets a PIN");
    assert!(matches!(lost.register_reset(None).await, Err(skwod_sync::EngineError::PinRequired)), "with a PIN set, a reset without it is a typed error");
    assert!(matches!(lost.register_reset(Some("824613")).await, Err(skwod_sync::EngineError::ResetPending(_))), "a fresh PIN does not skip the hold");
    bob2.refresh_own_devices().await.unwrap(); // vetoes the pending reset
    assert!(bob2.take_security_notices().iter().any(|n| n.kind == "reset_blocked"));

    // Alice only looks now, AFTER the old phone is gone. Its link signature on the new one is
    // genuine — but a device that is absent from the listing vouches for nobody (M5: a host
    // working with whoever holds a discarded device's key could serve exactly this). So the new
    // phone is held and flagged, and nothing is sent to bob until alice decides.
    let err = alice.send_dm(&convo, &bob2_peer, "to the new phone").await.unwrap_err();
    assert!(matches!(err, skwod_sync::EngineError::IdentityChanged(_)), "{err:?}");
    let notices = alice.take_security_notices();
    assert!(notices.iter().any(|n| n.kind == "unverified_contact_device" && n.user_id == b_session.user_id && n.device_id == bob2_peer.device_id), "{notices:?}");
    assert!(!notices.iter().any(|n| n.kind == "new_device"), "{notices:?}");
    assert!(notices.iter().any(|n| n.kind == "identity_changed" && n.user_id == b_session.user_id && n.was_verified), "{notices:?}");
    assert!(!alice.is_verified(&bob2_peer));
    assert_eq!(alice.contact_status(&b_session.user_id), (false, true, 0, 1), "held: no live device, one unvouched");
    // She chooses to continue (and then compares the number again).
    { let shown = alice.accept_fingerprint(&bob2_peer.user_id); alice.accept_identity_change(&bob2_peer, &shown).await.unwrap(); }
    assert_eq!(alice.contact_status(&b_session.user_id), (false, false, 1, 0));
    assert_ne!(alice.safety_number(&a_session.user_id, &bob2_peer).await.unwrap(), before, "one number per account, over its device set");
    // Both sides compute the same account safety number.
    assert_eq!(
        alice.safety_number(&a_session.user_id, &bob2_peer).await.unwrap(),
        bob2.safety_number(&b_session.user_id, &alice_peer).await.unwrap()
    );
    // THE RACE: alice was looking at the OLD number when bob's device set changed. Confirming
    // that number must not mark the new set verified.
    assert!(matches!(alice.verify_contact(&b_session.user_id, &before).await, Err(skwod_sync::EngineError::IdentityChanged(_))));
    assert!(!alice.is_verified(&bob2_peer), "a stale number verified the new device set");
    let after = alice.safety_number(&a_session.user_id, &bob2_peer).await.unwrap();
    alice.verify_contact(&b_session.user_id, &after).await.unwrap();
    assert!(alice.is_verified(&bob2_peer));
    alice.send_dm(&convo, &bob2_peer, "to the new phone").await.unwrap();
    assert_eq!(texts(bob2.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap()), ["to the new phone"]);
    bob2.ack_inbox().await.unwrap();

    // The directory serves a key for bob's device that is NOT the one alice holds for it (a
    // substitution needs a malicious server; here alice's pin is pointed at another key instead).
    let stranger = skwod_crypto::SignalStore::generate();
    alice.test_force_contact_identity(&bob2_peer, &stranger.identity_key());
    alice.test_drop_session(&bob2_peer);
    let err = alice.send_dm(&convo, &bob2_peer, "should not go out").await.unwrap_err();
    assert!(matches!(err, skwod_sync::EngineError::IdentityChanged(_)), "{err:?}");
    assert!(bob2.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap().is_empty());
    { let shown = alice.accept_fingerprint(&bob2_peer.user_id); alice.accept_identity_change(&bob2_peer, &shown).await.unwrap(); }
    assert!(!alice.is_verified(&bob2_peer), "verification must be redone");
    alice.send_dm(&convo, &bob2_peer, "after accepting").await.unwrap();
    assert_eq!(texts(bob2.fetch_inbound_dm(&convo, &alice_peer, &b_session.user_id).await.unwrap()), ["after accepting"]);
}

/// M5 without silent loss, for a contact who was never verified: alice links a new phone and
/// removes the old one; bob, who only looks afterwards, sends to her. The new phone's link is
/// signed by a device that is gone, so it is held — and bob's send is REFUSED with the reason
/// (never `Ok` with nobody reached). He is shown the unvouched device; when he continues,
/// the message goes to the new phone and what it had sent him meanwhile is delivered.
#[tokio::test]
async fn a_message_to_someone_who_replaced_their_phone_is_never_silently_dropped() {
    let Some(server) = start_server().await else { return };
    let (a_session, mut alice, alice_peer) = user(&server.base, "movera").await;
    let (b_session, mut bob, bob_peer) = user(&server.base, "moverb").await;
    meet(&mut alice, &mut bob).await;
    let convo = bob.open_dm(&a_session.user_id).await.unwrap();
    bob.send_dm(&convo, &alice_peer, "before").await.unwrap();
    assert_eq!(texts(alice.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap()), ["before"]);
    alice.ack_inbox().await.unwrap();
    assert!(!bob.is_verified(&alice_peer), "bob never compared a safety number with alice");
    bob.take_security_notices();

    // Alice moves to a new phone: the old one links it, then it removes the old one.
    let (mut alice2, alice2_peer) = device(&server.base, &a_session, &mut alice).await;
    alice2.delete_device(&alice_peer.device_id).await.expect("signed removal of the old phone");

    // Bob sends. Not delivered to nobody with a smile: refused, and he is told why.
    let err = bob.send_dm(&convo, &alice2_peer, "after the move").await.unwrap_err();
    assert!(matches!(&err, skwod_sync::EngineError::IdentityChanged(user) if user == &a_session.user_id), "{err:?}");
    let notices = bob.take_security_notices();
    assert!(notices.iter().any(|n| n.kind == "unverified_contact_device" && n.user_id == a_session.user_id && n.device_id == alice2_peer.device_id), "{notices:?}");
    let status = bob.contact_status(&a_session.user_id);
    assert_eq!((status.2, status.3), (0, 1), "no live device, the new phone held");
    assert!(alice2.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap().is_empty(), "nothing went out");
    alice2.ack_inbox().await.unwrap();
    // Asking again changes nothing by itself.
    assert!(bob.send_dm(&convo, &alice2_peer, "after the move").await.is_err());

    // He continues ("her devices changed — accept"): now it is delivered, to the new phone.
    { let shown = bob.accept_fingerprint(&alice2_peer.user_id); bob.accept_identity_change(&alice2_peer, &shown).await.unwrap(); }
    bob.send_dm(&convo, &alice2_peer, "after the move").await.expect("delivered once accepted");
    assert_eq!(texts(alice2.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap()), ["after the move"]);
    alice2.ack_inbox().await.unwrap();
    // And the other way round.
    alice2.send_dm(&convo, &bob_peer, "new phone, who dis").await.unwrap();
    assert_eq!(texts(bob.fetch_inbound_dm(&convo, &alice2_peer, &b_session.user_id).await.unwrap()), ["new phone, who dis"]);
}

/// The stolen-session-token attack: an attacker who holds a valid token (but none of the
/// account's devices) tries to enrol a device so it receives the victim's synced DMs and is
/// treated as "one of mine". The server refuses to register it; and even a device the server
/// DOES list under the account (a malicious server) is ignored by the victim's real devices
/// because no device of theirs vouched for it.
#[tokio::test]
async fn stolen_token_cannot_enrol_a_device() {
    let Some(server) = start_server().await else { return };
    let (a_session, mut alice, alice_peer) = user(&server.base, "victim").await;
    let (b_session, mut bob, bob_peer) = user(&server.base, "victimfriend").await;
    meet(&mut alice, &mut bob).await;
    let convo = alice.open_dm(&b_session.user_id).await.unwrap();

    // 1. Plain registration with the stolen token: refused.
    let mut attacker = Engine::new(ApiClient::new(&server.base).with_token(&a_session.token));
    assert!(matches!(attacker.register().await, Err(skwod_sync::EngineError::LinkRequired)));
    // 2. The attacker files a link request. Alice's device only approves a request matching a
    //    code SHE types from a device SHE holds — the attacker's request never matches.
    let attacker_code = attacker.begin_link().await.unwrap();
    assert_eq!(alice.pending_link_requests().await.unwrap(), 1, "the real device can see something is asking");
    assert!(!alice.approve_link("AAAA-BBBB-CCCC-DDDD").await.unwrap(), "a guessed code matches nothing");
    assert_eq!(attacker.complete_link().await.unwrap(), None);
    // 3. Alice links a REAL second device while the attacker's request is pending: her code picks
    //    out her own device's request, not the attacker's.
    let (mut alice_mac, mac_peer) = device(&server.base, &a_session, &mut alice).await;
    assert_ne!(attacker_code, "", "attacker still waiting");
    assert_eq!(attacker.complete_link().await.unwrap(), None, "attacker was never approved");
    let api = ApiClient::new(&server.base).with_token(&a_session.token);
    let listed = api.get("/api/e2ee/devices").await.unwrap();
    assert_eq!(listed["devices"].as_array().unwrap().len(), 2, "only alice's two real devices exist");

    // 4. DMs: bob → alice reaches both real devices; alice's own sends sync to her mac only.
    bob.send_dm(&convo, &alice_peer, "for alice's eyes").await.unwrap();
    assert_eq!(texts(alice.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap()), ["for alice's eyes"]);
    assert_eq!(texts(alice_mac.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap()), ["for alice's eyes"]);
    alice.send_dm(&convo, &bob_peer, "reply").await.unwrap();
    let synced = alice_mac.fetch_inbound_dm(&convo, &bob_peer, &a_session.user_id).await.unwrap();
    assert_eq!(synced.len(), 1);
    assert_eq!(synced[0].author_id, skwod_sync::SELF_AUTHOR);
    assert!(alice.is_sibling(&mac_peer.device_id) && alice_mac.is_sibling(&alice_peer.device_id));
    // Alice's first device was told a device was linked.
    assert!(alice.take_security_notices().iter().any(|n| n.kind == "device_linked" && n.device_id == mac_peer.device_id));

    // 5. The attacker tries the other doors a token used to open.
    //    a) Delete the victim's devices: the server wants a signature from a device on the account.
    assert!(api.delete(&format!("/api/e2ee/devices/{}", alice_peer.device_id)).await.is_err());
    assert!(attacker.delete_device(&alice_peer.device_id).await.is_err(), "attacker's key is not on the account");
    //    b) Force a reset: without the PIN it is only a request, on hold for 7 days...
    let err = attacker.register_reset(None).await.unwrap_err();
    assert!(matches!(err, skwod_sync::EngineError::ResetPending(_)), "{err:?}");
    assert_eq!(api.get("/api/e2ee/devices").await.unwrap()["devices"].as_array().unwrap().len(), 2, "nothing was wiped");
    //    ...and the victim's device, on its next sync, vetoes it and tells the user.
    alice.refresh_own_devices().await.unwrap();
    assert!(alice.take_security_notices().iter().any(|n| n.kind == "reset_blocked"));
    assert!(api.get("/api/e2ee/devices").await.unwrap()["reset_completes_at"].is_null(), "request cancelled");
    //    Alice keeps working, and can remove a device of her own with a signed request.
    alice.send_dm(&convo, &bob_peer, "still here").await.unwrap();
    alice.delete_device(&mac_peer.device_id).await.expect("signed delete");
    assert_eq!(api.get("/api/e2ee/devices").await.unwrap()["devices"].as_array().unwrap().len(), 1);
}

/// A third device learns about the device that was linked BEFORE its own linker (whose row
/// carries no signature it could check on its own) from its linker, and all three fan out to
/// each other.
#[tokio::test]
async fn three_devices_form_one_verified_sibling_set() {
    let Some(server) = start_server().await else { return };
    let (session, mut phone, phone_peer) = user(&server.base, "triple").await;
    let (mut mac, mac_peer) = device(&server.base, &session, &mut phone).await;
    // The tablet is linked by the MAC, not by the phone.
    let (mut tablet, tablet_peer) = device(&server.base, &session, &mut mac).await;
    phone.poll_inbox().await.unwrap();
    mac.poll_inbox().await.unwrap();
    tablet.poll_inbox().await.unwrap();
    for (name, engine, others) in [
        ("phone", &phone, [&mac_peer, &tablet_peer]),
        ("mac", &mac, [&phone_peer, &tablet_peer]),
        ("tablet", &tablet, [&phone_peer, &mac_peer]),
    ] {
        for o in others {
            assert!(engine.is_sibling(&o.device_id), "{name} should have verified {}", o.device_id);
        }
    }
    // A solo server created on the phone becomes readable on the tablet via sibling provisioning.
    let space = phone.create_space("Mine", "general").await.unwrap();
    tablet.request_provision(&space.server_id, &phone_peer).await.unwrap();
    assert_eq!(phone.process_control_inbox(&session.user_id).await.unwrap(), 1);
    phone.ack_inbox().await.unwrap();
    tablet.poll_inbox().await.unwrap();
    let channels = tablet.list_channels(&space.server_id).await.unwrap();
    // (Not `channels[0]`: the space's channels are created in the same millisecond and tie.)
    assert!(channels.iter().any(|c| c.name.as_deref() == Some("general")), "the tablet reads channel names");
    phone.send_channel_message(&space.channel_id, "note to self").await.unwrap();
    assert_eq!(texts(tablet.fetch_channel_messages(&space.channel_id, &session.user_id).await.unwrap()), ["note to self"]);
    assert_eq!(texts(mac.fetch_channel_messages(&space.channel_id, &session.user_id).await.unwrap()), ["note to self"]);
}

/// Channels over a real server: the owner's sender key reaches every device of every member in
/// one membership sync, and members read each other.
#[tokio::test]
async fn group_sender_key_exchange() {
    let Some(server) = start_server().await else { return };
    let (a_session, mut alice, _) = user(&server.base, "groupa").await;
    let (b_session, mut bob, _) = user(&server.base, "groupb").await;
    let (mut bob_mac, _) = device(&server.base, &b_session, &mut bob).await;

    let space = alice.create_space("space", "general").await.unwrap();
    let channel = space.channel_id.clone();
    assert!(!bob.join_space(&space.invite_code, &space.space_key_hex, &channel).await.unwrap().pending);
    // The server listing bob is not enough: alice (the owner) lets him in, which signs it.
    alice.approve_member(&space.server_id, &b_session.user_id).await.unwrap();

    // ONE sync hands alice's key to both of bob's devices (the old code reached one per user).
    assert!(!alice.sync_channel_membership(&channel, &space.server_id, &a_session.user_id).await.unwrap());
    alice.send_channel_message(&channel, "gm everyone").await.unwrap();
    alice.send_channel_message(&channel, "second").await.unwrap();
    for (who, engine) in [("bob phone", &mut bob), ("bob mac", &mut bob_mac)] {
        engine.sync_channel_membership(&channel, &space.server_id, &b_session.user_id).await.unwrap();
        let got = texts(engine.fetch_channel_messages(&channel, &b_session.user_id).await.unwrap());
        engine.ack_inbox().await.unwrap();
        assert_eq!(got, ["gm everyone", "second"], "{who}");
    }
    // Bob's phone posts; alice AND bob's own other device read it.
    bob.send_channel_message(&channel, "hi from the phone").await.unwrap();
    assert_eq!(texts(alice.fetch_channel_messages(&channel, &a_session.user_id).await.unwrap()), ["hi from the phone"]);
    let mac_sees = texts(bob_mac.fetch_channel_messages(&channel, &b_session.user_id).await.unwrap());
    assert_eq!(mac_sees, ["hi from the phone"], "sibling device reads its own account's message");
    // Re-fetching yields nothing new (already-consumed sender-key messages are rejected as replays).
    alice.ack_inbox().await.unwrap();
    assert!(alice.fetch_channel_messages(&channel, &a_session.user_id).await.unwrap().is_empty());
}

/// Membership removal rotates the channel sender key: after the owner kicks Bob, the next send
/// mints a fresh key that reaches EVERY device of every remaining member — and no device of Bob's.
/// Bob keeps his old key but cannot decrypt anything sent after the kick, and the owner refuses to
/// hand him the new one.
#[tokio::test]
async fn kicked_member_cannot_decrypt_after_sender_key_rotation() {
    let Some(server) = start_server().await else { return };
    let (a_session, mut alice, alice_peer) = user(&server.base, "rotalice").await;
    let (b_session, mut bob, bob_peer) = user(&server.base, "rotbob").await;
    let (mut bob_mac, _) = device(&server.base, &b_session, &mut bob).await;
    let (c_session, mut carol, carol_peer) = user(&server.base, "rotcarol").await;
    let (mut carol_mac, _) = device(&server.base, &c_session, &mut carol).await;

    let space = alice.create_space("space", "general").await.unwrap();
    let channel = space.channel_id.clone();
    let scope = format!("channel:{channel}");
    assert!(!bob.join_space(&space.invite_code, &space.space_key_hex, &channel).await.unwrap().pending);
    let carol_code = alice.invite_to_space(&space.server_id, "token", None).await.unwrap();
    assert!(!carol.join_space(&carol_code, &space.space_key_hex, &channel).await.unwrap().pending);
    for joiner in [&b_session.user_id, &c_session.user_id] {
        alice.approve_member(&space.server_id, joiner).await.unwrap();
    }

    // The device id passed to share_group_key is only a hint: every device of the member is keyed.
    alice.share_group_key(&channel, &bob_peer).await.unwrap();
    alice.share_group_key(&channel, &carol_peer).await.unwrap();
    alice.send_channel_message(&channel, "before kick").await.unwrap();
    for (who, engine, me) in [
        ("bob", &mut bob, &b_session.user_id),
        ("bob mac", &mut bob_mac, &b_session.user_id),
        ("carol", &mut carol, &c_session.user_id),
        ("carol mac", &mut carol_mac, &c_session.user_id),
    ] {
        assert_eq!(texts(engine.fetch_channel_messages(&channel, me).await.unwrap()), ["before kick"], "{who}");
        engine.ack_inbox().await.unwrap();
    }

    // Kick Bob through the REST API (as the owner).
    let owner_api = ApiClient::new(&server.base).with_token(&a_session.token);
    owner_api.delete(&format!("/api/servers/{}/members/{}", space.server_id, b_session.user_id)).await.unwrap();

    // Alice's next send notices Bob's devices are gone, rotates, and redistributes — to BOTH of
    // Carol's devices (the pre-libsignal code re-keyed only one device per user).
    let after_id = alice.send_channel_message(&channel, "after kick").await.unwrap();
    assert!(!alice.group_key_stale(&scope));
    for (who, engine) in [("carol", &mut carol), ("carol mac", &mut carol_mac)] {
        assert_eq!(texts(engine.fetch_channel_messages(&channel, &c_session.user_id).await.unwrap()), ["after kick"], "{who}");
        engine.ack_inbox().await.unwrap();
    }

    // Neither of Bob's devices got a replacement key, and their retained old key cannot open the
    // new message.
    let msgs = owner_api.channel_messages(&channel, i64::MAX, 50).await.unwrap();
    let after = msgs.iter().find(|m| m["message_id"].as_str() == Some(after_id.as_str())).unwrap();
    let ct = B64.decode(after["ciphertext"].as_str().unwrap()).unwrap();
    for (who, engine) in [("bob", &mut bob), ("bob mac", &mut bob_mac)] {
        engine.poll_inbox().await.unwrap();
        assert!(engine.group_decrypt(&scope, &alice_peer, &ct).is_err(), "{who}: removed member decrypted post-removal ciphertext");
    }
    // Carol decrypting the same bytes again is a rejected replay.
    assert!(carol.group_decrypt(&scope, &alice_peer, &ct).is_err());

    // And the owner refuses to share the current key with a non-member.
    assert!(alice.share_group_key(&channel, &bob_peer).await.is_err());
}

/// The code-only auto-discover flow: a friend joins with ONLY an invite code (no copied space
/// key, no channel id). After the host approves, the host provisions them over sealed sessions,
/// and the friend can then see every channel name and read the host's messages.
#[tokio::test]
async fn join_by_code_then_auto_provision_reveals_all_channels() {
    let Some(server) = start_server().await else { return };
    let (_host_session, mut host, _) = user(&server.base, "provhost").await;
    let space = host.create_space("Weekend Crew", "general").await.unwrap();
    // Host mints an approval-gated code invite (our secure default).
    let code = host.invite_to_space(&space.server_id, "code", None).await.unwrap();

    // Friend joins with ONLY the code — no space key, no channel id.
    let (friend_session, mut friend, friend_peer) = user(&server.base, "provfriend").await;
    let outcome = friend.join_by_code(&code).await.unwrap();
    assert!(outcome.pending, "a code invite lands in the approval queue");
    assert_eq!(outcome.server_id, space.server_id);

    // Host approves, then provisions the friend (space key + channel sender keys, sealed).
    host.approve_join_request(&space.server_id, &friend_session.user_id).await.unwrap();
    host.provision_member(&space.server_id, &friend_peer).await.unwrap();

    // The friend's inbox sync silently installs the space key and the channel sender key.
    friend.poll_inbox().await.unwrap();
    assert!(friend.take_dms().is_empty(), "control traffic is never surfaced as chat");

    // Now the friend discovers the whole server: channel list with the DECRYPTED name.
    let channels = friend.list_channels(&space.server_id).await.unwrap();
    let general = channels.iter().find(|c| c.channel_id == space.channel_id).expect("general present");
    assert_eq!(general.name.as_deref(), Some("general"), "channel name decrypted with the relayed key");

    // And the friend can read a message the host posts to that channel.
    host.send_channel_message(&space.channel_id, "welcome to the crew!").await.unwrap();
    let msgs = friend.fetch_channel_messages(&space.channel_id, &friend_session.user_id).await.unwrap();
    assert!(msgs.iter().any(|m| m.text == "welcome to the crew!"), "friend reads the host's channel message");
}

/// Token/username auto-join has no approval step, so the member asks to be provisioned and the host
/// fulfills it on its next inbox sync — then the member auto-discovers the server just the same.
#[tokio::test]
async fn token_join_requests_provision_and_host_inbox_sync_fulfills() {
    let Some(server) = start_server().await else { return };
    let (host_session, mut host, host_peer) = user(&server.base, "tokhost").await;
    let space = host.create_space("Token Crew", "general").await.unwrap();
    // A one-time auto-join token (host pre-vouches).
    let token = host.invite_to_space(&space.server_id, "token", None).await.unwrap();

    let (friend_session, mut friend, _) = user(&server.base, "tokfriend").await;
    // Friend joins by code — auto-approved (not pending) — and learns the host identity.
    let outcome = friend.join_by_code(&token).await.unwrap();
    assert!(!outcome.pending, "a token invite auto-joins");
    assert_eq!(outcome.host_user_id.as_deref(), Some(host_session.user_id.as_str()));
    assert_eq!(outcome.host_device_id.as_deref(), Some(host_peer.device_id.as_str()));

    // With no approval step, the friend asks the host to provision them.
    friend.request_provision(&space.server_id, &host_peer).await.unwrap();

    // The host's inbox sync sees the request — but a request is not an approval: nothing is signed
    // or sent on the server's say-so. It surfaces as a join request for the owner.
    let provisioned = host.process_control_inbox(&host_session.user_id).await.unwrap();
    host.ack_inbox().await.unwrap();
    assert_eq!(provisioned, 0, "a provision request alone provisions nobody");
    let notices = host.take_security_notices();
    assert!(notices.iter().any(|n| n.kind == "join_request" && n.user_id == friend_session.user_id && n.device_id == space.server_id), "{notices:?}");
    assert_eq!(host.held_members(&space.server_id), std::slice::from_ref(&friend_session.user_id));
    // The owner taps "Let in": that signs the approval, and provisioning follows.
    host.approve_member(&space.server_id, &friend_session.user_id).await.unwrap();
    host.provision_member(&space.server_id, &PeerId { user_id: friend_session.user_id.clone(), device_id: String::new() }).await.unwrap();
    assert!(host.held_members(&space.server_id).is_empty());

    // Friend receives the bundle and discovers the server, no key pasted.
    friend.poll_inbox().await.unwrap();
    let channels = friend.list_channels(&space.server_id).await.unwrap();
    let general = channels.iter().find(|c| c.channel_id == space.channel_id).expect("general present");
    assert_eq!(general.name.as_deref(), Some("general"), "token-joiner sees the decrypted channel name");
}

/// Security guard: a still-pending (unapproved) code-joiner who asks to be provisioned is NOT handed
/// the keys by the host's inbox sync — the approval gate holds even against a forged provision request.
#[tokio::test]
async fn pending_requester_is_not_provisioned_by_inbox_sync() {
    let Some(server) = start_server().await else { return };
    let (host_session, mut host, _) = user(&server.base, "guardhost").await;
    let space = host.create_space("Guarded", "general").await.unwrap();
    let code = host.invite_to_space(&space.server_id, "code", None).await.unwrap();

    let (_s, mut intruder, _) = user(&server.base, "guardintruder").await;
    // Intruder joins via a code (goes pending), then tries to force provisioning by requesting it.
    let outcome = intruder.join_by_code(&code).await.unwrap();
    assert!(outcome.pending, "code join is pending approval");
    let host_peer = PeerId { user_id: outcome.host_user_id.unwrap(), device_id: outcome.host_device_id.unwrap() };
    // Build 45: the server no longer hands a pending account the host's devices at all, so
    // the request cannot even be addressed. (That a request which DOES arrive from someone
    // not yet accepted is held is covered by the engine's own tests.)
    assert!(intruder.request_provision(&space.server_id, &host_peer).await.is_err(), "a pending account cannot reach the host's key directory");

    // The host processes its inbox — but must NOT provision a non-member.
    let provisioned = host.process_control_inbox(&host_session.user_id).await.unwrap();
    assert_eq!(provisioned, 0, "a pending (unapproved) requester is never provisioned");
    // Nothing reached the intruder: no space key, so the server's name stays opaque to them.
    intruder.poll_inbox().await.unwrap();
    assert!(matches!(intruder.server_name(&space.server_id).await, Ok(None) | Err(_)));
}

/// A total stranger (no shared server, no DM, no pending join) cannot obtain another account's
/// prekey bundle or device list through the engine at all.
#[tokio::test]
async fn strangers_cannot_start_sessions() {
    let Some(server) = start_server().await else { return };
    let (_a, mut alice, _) = user(&server.base, "strangera").await;
    let (_b, _bob, bob_peer) = user(&server.base, "strangerb").await;
    let err = alice.send_dm("no-such-conversation", &bob_peer, "hello?").await.unwrap_err();
    assert!(format!("{err}").contains("403"), "{err}");
    assert!(alice.safety_number("x", &bob_peer).await.is_err());
}

/// User-safety tooling end to end: a ban survives fresh invites (unlike a kick) until lifted, and
/// a block makes the server refuse DM traffic between the pair — all through the engine's client
/// API, against a real server, with content staying E2EE throughout.
#[tokio::test]
async fn bans_and_blocks_enforced_end_to_end() {
    let Some(server) = start_server().await else { return };

    // Host creates a space; Mallory joins via the auto-join token invite.
    let host_api = ApiClient::new(&server.base);
    let host_session = host_api.signup("safetyhost", "password123").await.unwrap();
    let mut host = Engine::new(host_api.with_token(&host_session.token));
    let host_device = host.register().await.unwrap();
    let space = host.create_space("Moderated Crew", "general").await.unwrap();

    let mal_api = ApiClient::new(&server.base);
    let mal_session = mal_api.signup("safetymallory", "password123").await.unwrap();
    let mut mallory = Engine::new(mal_api.with_token(&mal_session.token));
    let mal_device = mallory.register().await.unwrap();
    let outcome = mallory.join_space(&space.invite_code, &space.space_key_hex, &space.channel_id).await.unwrap();
    assert!(!outcome.pending, "token invite auto-joins");

    // Ban: Mallory is evicted AND a brand-new, valid invite no longer readmits them.
    host.ban_member(&space.server_id, &mal_session.user_id, Some("spam")).await.unwrap();
    let fresh = host.invite_to_space(&space.server_id, "token", None).await.unwrap();
    assert!(
        mallory.join_space(&fresh, &space.space_key_hex, &space.channel_id).await.is_err(),
        "banned user can't rejoin with any invite"
    );
    let bans = host.list_bans(&space.server_id).await.unwrap();
    assert!(bans.iter().any(|(uid, _, reason)| uid == &mal_session.user_id && reason.as_deref() == Some("spam")));

    // Unban → a fresh invite works again.
    host.unban_member(&space.server_id, &mal_session.user_id).await.unwrap();
    let fresh = host.invite_to_space(&space.server_id, "token", None).await.unwrap();
    assert!(!mallory.join_space(&fresh, &space.space_key_hex, &space.channel_id).await.unwrap().pending);

    // Blocks: an established E2EE DM goes quiet at the relay once the host blocks Mallory.
    let host_peer = PeerId { user_id: host_session.user_id.clone(), device_id: host_device };
    let mal_peer = PeerId { user_id: mal_session.user_id.clone(), device_id: mal_device };
    let convo = mallory.open_dm(&host_session.user_id).await.unwrap();
    mallory.send_dm(&convo, &host_peer, "hello before the block").await.unwrap();

    host.block_user(&mal_session.user_id).await.unwrap();
    assert!(
        mallory.send_dm(&convo, &host_peer, "are you ignoring me").await.is_err(),
        "server refuses a blocked sender's DM"
    );
    let blocks = host.list_blocks().await.unwrap();
    assert!(blocks.iter().any(|(uid, name)| uid == &mal_session.user_id && name == "safetymallory"));

    // Unblock → the pair can talk again (host replies to prove both directions flow).
    host.unblock_user(&mal_session.user_id).await.unwrap();
    mallory.send_dm(&convo, &host_peer, "back on speaking terms").await.unwrap();
    host.send_dm(&convo, &mal_peer, "welcome back").await.unwrap();
}

/// Clearing a channel (and a whole server) hard-deletes the content but leaves the server, its
/// channels, and every membership intact — and a plain member can't do it.
#[tokio::test]
async fn clear_channel_and_server_keep_members_and_channels() {
    let Some(server) = start_server().await else { return };

    // Host creates a space + a second channel and posts to both.
    let host_api = ApiClient::new(&server.base);
    let host_session = host_api.signup("clearhost", "password123").await.unwrap();
    let mut host = Engine::new(host_api.with_token(&host_session.token));
    host.register().await.unwrap();
    let space = host.create_space("Clear Crew", "general").await.unwrap();
    let off_topic = host.create_channel(&space.server_id, "off-topic").await.unwrap();

    // A friend token-joins so we can assert membership survives the clears.
    let friend_api = ApiClient::new(&server.base);
    let friend_session = friend_api.signup("clearfriend", "password123").await.unwrap();
    let mut friend = Engine::new(friend_api.with_token(&friend_session.token));
    friend.register().await.unwrap();
    let token = host.invite_to_space(&space.server_id, "token", None).await.unwrap();
    assert!(!friend.join_by_code(&token).await.unwrap().pending, "token invite auto-joins");

    for i in 0..5 {
        host.send_channel_message(&space.channel_id, &format!("general {i}")).await.unwrap();
    }
    for i in 0..3 {
        host.send_channel_message(&off_topic, &format!("off {i}")).await.unwrap();
    }
    let raw = ApiClient::new(&server.base).with_token(&host_session.token);
    assert_eq!(raw.channel_messages(&space.channel_id, i64::MAX, 50).await.unwrap().len(), 5);

    // A plain member (only @everyone perms) must NOT be able to clear.
    assert!(friend.clear_channel(&space.channel_id).await.is_err(), "non-moderator cannot clear a channel");
    assert_eq!(raw.channel_messages(&space.channel_id, i64::MAX, 50).await.unwrap().len(), 5, "rejected clear left messages");

    // Owner clears just #general.
    host.clear_channel(&space.channel_id).await.unwrap();
    assert!(raw.channel_messages(&space.channel_id, i64::MAX, 50).await.unwrap().is_empty(), "#general cleared");
    assert_eq!(raw.channel_messages(&off_topic, i64::MAX, 50).await.unwrap().len(), 3, "#off-topic untouched");
    assert_eq!(host.list_members(&space.server_id).await.unwrap().len(), 2, "members kept after channel clear");
    assert_eq!(host.list_channels(&space.server_id).await.unwrap().iter().filter(|c| c.purpose.as_deref() != Some("feed")).count(), 2, "channels kept after channel clear");

    // Owner clears the ENTIRE server's content.
    host.clear_server_content(&space.server_id).await.unwrap();
    assert!(raw.channel_messages(&off_topic, i64::MAX, 50).await.unwrap().is_empty(), "server clear emptied #off-topic");
    assert_eq!(host.list_members(&space.server_id).await.unwrap().len(), 2, "members kept after server clear");
    assert_eq!(host.list_channels(&space.server_id).await.unwrap().iter().filter(|c| c.purpose.as_deref() != Some("feed")).count(), 2, "channels kept after server clear");
}
