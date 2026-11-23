//! Engine unit tests that need no server: state persistence, the v1 → libsignal migration, the
//! sender-key membership boundary, scope binding of channel messages, and control-message policy.
//! The networked paths are covered by `tests/live_server.rs` against a real server process.

use super::*;

fn engine(user: &str, device: &str) -> Engine {
    let mut e = Engine::new(ApiClient::new("http://localhost".to_string()));
    e.user_id = Some(user.to_string());
    e.device_id = Some(device.to_string());
    e
}

fn addr(user: &str, device: &str) -> DeviceAddress {
    DeviceAddress::new(user, device)
}

/// Make `peer` a pinned contact device of `e`, with a session under `identity` — what a first
/// directory fetch plus a sealed session would have established.
fn pin(e: &mut Engine, peer: &DeviceAddress, identity: &[u8]) {
    let c = e.contacts.entry(peer.user_id.clone()).or_default();
    c.vouched.insert(peer.device_id.clone(), identity.to_vec());
    c.live.insert(peer.device_id.clone());
    e.store.accept_identity(peer, identity).unwrap();
    e.take_security_notices();
}

fn pin_fresh(e: &mut Engine, user: &str, device: &str) -> DeviceAddress {
    let a = addr(user, device);
    pin(e, &a, &SignalStore::generate().identity_key());
    a
}

/// Hand `from`'s sender key for `channel` to `to`, the way a sealed `SenderKey` message would.
async fn hand_key(from: &mut Engine, to: &mut Engine, channel: &str) {
    pin(to, &from.local().unwrap(), &from.store.identity_key());
    // The channel belongs to a server whose roster (on the receiving device) has the sender.
    let server = to.channel_servers.entry(channel.to_string()).or_insert_with(|| "srv".to_string()).clone();
    to.rosters.entry(server).or_default().members.insert(from.user_id.clone().unwrap());
    let scope = format!("channel:{channel}");
    let id = from.ensure_send_key(&scope).unwrap();
    let skdm = from.store.create_distribution(&from.local().unwrap(), id).unwrap();
    let payload = Content::SenderKey { channel_id: channel.to_string(), skdm }.encode().unwrap();
    let local = to.local().unwrap();
    to.handle_content(&local, from.local().unwrap(), &payload, 0).await;
}

fn wire(e: &mut Engine, channel: &str, text: &str) -> Vec<u8> {
    B64.decode(e.channel_ciphertext(channel, "mid", None, false, text).unwrap()).unwrap()
}

/// A build-42 (wire v2) channel message from `e`: the sender-key plaintext is the bare text.
fn wire_v2(e: &mut Engine, channel: &str, text: &str) -> Vec<u8> {
    let id = e.ensure_send_key(&format!("channel:{channel}")).unwrap();
    let local = e.local().unwrap();
    let mut out = vec![CHANNEL_WIRE_V2];
    out.extend(e.store.group_encrypt(&local, id, text.as_bytes()).unwrap());
    out
}

/// A recording stand-in for the server: answers every request with what `answer(method, path)`
/// returns and keeps the `(method, path)` of each. Enough to see WHICH requests a code path makes.
struct Mock {
    base: String,
    seen: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl Mock {
    fn start(answer: impl Fn(&str, &str) -> (u16, serde_json::Value) + Send + 'static) -> Self {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                    request.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&request).to_string();
                let length = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                let mut body = vec![0u8; length];
                let _ = stream.read_exact(&mut body);
                let mut words = head.split_whitespace();
                let (method, path) = (words.next().unwrap_or_default().to_string(), words.next().unwrap_or_default().to_string());
                log.lock().unwrap().push((method.clone(), path.clone()));
                let (status, json) = answer(&method, &path);
                let json = json.to_string();
                let _ = write!(stream, "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{json}", json.len());
            }
        });
        Self { base, seen }
    }

    fn engine(&self, user: &str, device: &str) -> Engine {
        let mut e = Engine::new(ApiClient::new(self.base.clone()));
        e.user_id = Some(user.to_string());
        e.device_id = Some(device.to_string());
        e
    }

    /// The requests made so far, and forget them.
    fn take(&self) -> Vec<(String, String)> {
        std::mem::take(&mut self.seen.lock().unwrap())
    }
}

const V1_STATE: &[u8] = include_bytes!("../../tests/fixtures/engine-state-v1.bin");

/// The upgrade path, against a GENUINE protocol-v1 snapshot: space keys and provisioner pins are
/// carried over, the v1 identity/sessions are discarded for a fresh libsignal identity, the device
/// must re-register, and both the "upgraded" notice and per-peer "safety number changed" notices
/// are produced.
#[test]
fn v1_engine_state_migrates_to_libsignal() {
    let mut e = Engine::new(ApiClient::new("http://localhost".to_string()));
    let fresh_identity = e.store.identity_key();
    assert_eq!(e.load_state(V1_STATE), LoadOutcome::Migrated);

    assert_eq!(e.spaces.get("server-1"), Some(&[0x5a; 32]));
    assert_eq!(e.spaces.get("server-2"), Some(&[0xa5; 32]));
    assert_eq!(e.expected_provisioner.get("server-2").map(String::as_str), Some("host-user"));
    assert!(e.device_id().is_none(), "the v1 device is gone; the app registers a new one");
    assert!(e.local().is_err());
    assert_ne!(e.store.identity_key(), fresh_identity, "a brand-new identity, not a reused object");
    assert_eq!(e.store.identity_key().len(), 33, "libsignal identity key");
    assert!(e.send_keys.is_empty() && e.recv_keys.is_empty(), "no v1 sender key survives");
    let peers: Vec<&str> = e.legacy_peers.iter().map(String::as_str).collect();
    assert_eq!(peers, ["bob-user", "carol-user", "erin-user"]);

    // The device learns it was upgraded...
    let notices = e.take_security_notices();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].kind, "protocol_upgraded");
    assert_eq!(notices[0].device_id, "11111111-2222-3333-4444-555555555555");
    // ...and the first libsignal contact with each v1 peer raises "safety number changed", once.
    e.note_legacy_peer(&addr("bob-user", "new-device"));
    e.note_legacy_peer(&addr("bob-user", "another-device"));
    e.note_legacy_peer(&addr("stranger", "d"));
    let notices = e.take_security_notices();
    assert_eq!(notices.len(), 1);
    assert_eq!((notices[0].kind.as_str(), notices[0].user_id.as_str()), ("identity_changed", "bob-user"));

    // The migrated state persists in the v2 format and no longer contains v1 material.
    let v2 = e.export_state();
    assert!(v2.starts_with(STATE_MAGIC));
    let mut again = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(again.load_state(&v2), LoadOutcome::Restored);
    assert_eq!(again.store.identity_key(), e.store.identity_key());
    assert_eq!(again.spaces.len(), 2);
    assert_eq!(again.legacy_peers.len(), 2, "remaining v1 peers still owed a notice");
    // A v1 blob from the oldest layout (no trailing group_dist) is the same bytes minus a suffix;
    // truncating mid-structure must be rejected, not half-loaded.
    let mut junk = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(junk.load_state(&V1_STATE[..V1_STATE.len() / 2]), LoadOutcome::Unreadable);
    assert_eq!(junk.load_state(b"definitely not a state"), LoadOutcome::Unreadable);
    assert_eq!(junk.load_state(&[]), LoadOutcome::Unreadable);
    // The state ends with build 44's two tagged sections (accounts, then content). Cut inside
    // either, or inside the build-43 tail before them: unreadable. Cut exactly before the
    // sections: that IS a build-43 state, and it loads. Cut between the two: a state with the
    // accounts section only (as the accounts batch alone would have written), and it loads.
    let content_len = 5 + postcard::to_stdvec(&super::content::ContentExt::default()).unwrap().len();
    let sections_len = content_len + 5 + postcard::to_stdvec(&e.acct).unwrap().len();
    for cut in [1, 2, content_len - 1, content_len + 1, content_len + 4, sections_len - 1, sections_len + 1, sections_len + 6] {
        assert_eq!(junk.load_state(&v2[..v2.len() - cut]), LoadOutcome::Unreadable, "cut {cut}");
    }
    let mut accounts_only = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(accounts_only.load_state(&v2[..v2.len() - content_len]), LoadOutcome::Restored, "the accounts section alone");
    let mut older = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(older.load_state(&v2[..v2.len() - sections_len]), LoadOutcome::Restored, "a state written by build 43");
    assert_eq!(older.store.identity_key(), e.store.identity_key());
}

/// Build 44's additions ride in their own tagged section: they survive a restart, a build-43
/// state loads without them, and a state from a build NEWER than this one (a section this one
/// does not know) still loads.
#[tokio::test]
async fn dm_operations_and_reports_survive_a_restart_and_older_states_still_load() {
    let mut alice = engine("alice", "a1");
    alice.dm_ops.push(DmOp {
        conversation_id: "c".into(),
        message_id: "m".into(),
        author_id: "bob".into(),
        peer_user_id: "bob".into(),
        kind: DmOpKind::Edit { text: "edited".into() },
        received_at: 5,
    });
    alice.reports.push(InboundReport {
        report_id: "r".into(),
        reporter_user_id: "bob".into(),
        subject_user_id: Some("carol".into()),
        server_id: None,
        category: "abuse".into(),
        note: Some("note".into()),
        excerpt: Some("what was said".into()),
        received_at: 6,
        channel_id: Some("ch".into()),
        message_id: Some("m".into()),
    });
    let snapshot = alice.export_state();
    let mut restored = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(restored.load_state(&snapshot), LoadOutcome::Restored);
    assert_eq!(restored.take_dm_ops(), alice.dm_ops);
    assert_eq!(restored.take_reports(), alice.reports);

    // A later build appends a tail this one does not know: identity and sessions still load.
    let mut newer = engine("alice", "a1").export_state();
    super::accounts::write_section(&mut newer, 0x7E, &[1, 2, 3, 4]);
    let mut e = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(e.load_state(&newer), LoadOutcome::Restored);
    assert!(e.take_dm_ops().is_empty());
}

/// A DM operation is accepted only for a conversation its sender is really in, and never from
/// someone this account blocked; a report names its reporter by who SEALED it.
#[tokio::test]
async fn dm_operations_are_policy_checked() {
    let mut alice = engine("alice", "a1");
    let bob = pin_fresh(&mut alice, "bob", "b1");
    let mallory = pin_fresh(&mut alice, "mallory", "m1");
    let local = alice.local().unwrap();
    alice.dm_participants.insert("conv".into(), vec!["alice".into(), "bob".into()]);
    let edit = |conversation: &str| Content::DmEdit { conversation_id: conversation.into(), message_id: "m1".into(), text: "new".into(), sync_peer: None }.encode().unwrap();

    alice.handle_content(&local, bob.clone(), &edit("conv"), 10).await;
    let ops = alice.take_dm_ops();
    assert_eq!(ops.len(), 1);
    assert_eq!((ops[0].author_id.as_str(), ops[0].peer_user_id.as_str(), &ops[0].kind), ("bob", "bob", &DmOpKind::Edit { text: "new".into() }));

    // Mallory is not in that conversation: her "edit" of a message there goes nowhere.
    alice.handle_content(&local, mallory.clone(), &edit("conv"), 10).await;
    assert!(alice.take_dm_ops().is_empty(), "an outsider cannot touch the conversation");
    // (The engine re-read the conversation from the server before refusing; there is none here.)
    alice.dm_participants.insert("conv".into(), vec!["alice".into(), "bob".into()]);
    // Oversized or empty fields are dropped.
    for bad in [
        Content::DmReaction { conversation_id: "conv".into(), message_id: "m1".into(), emoji: "x".repeat(65), remove: false, sync_peer: None },
        Content::DmReaction { conversation_id: "conv".into(), message_id: "m1".into(), emoji: String::new(), remove: false, sync_peer: None },
        Content::DmDelete { conversation_id: "conv".into(), message_id: String::new(), sync_peer: None },
        Content::DmReply { conversation_id: "conv".into(), message_id: "m2".into(), text: "t".into(), sent_at: 1, reply_to: String::new(), sync_peer: None },
    ] {
        alice.handle_content(&local, bob.clone(), &bad.encode().unwrap(), 10).await;
    }
    assert!(alice.take_dm_ops().is_empty());
    // A reply's time is the sender's claim, clamped to "not in the future".
    let reply = Content::DmReply { conversation_id: "conv".into(), message_id: "m2".into(), text: "t".into(), sent_at: i64::MAX, reply_to: "m1".into(), sync_peer: None };
    alice.handle_content(&local, bob.clone(), &reply.encode().unwrap(), 10).await;
    assert!(matches!(&alice.take_dm_ops()[0].kind, DmOpKind::Reply { sent_at, .. } if *sent_at <= now_ms() as i64 + 1));

    // A report: whatever it says about its reporter, the reporter is whoever sealed it.
    let report = InboundReport {
        report_id: "r1".into(),
        reporter_user_id: "someone-else".into(),
        subject_user_id: Some("mallory".into()),
        server_id: None,
        category: "abuse".into(),
        note: None,
        excerpt: Some("quote".into()),
        received_at: 0,
        channel_id: None,
        message_id: None,
    };
    alice.handle_content(&local, bob.clone(), &Content::Report { report: report.clone() }.encode().unwrap(), 42).await;
    let got = alice.take_reports();
    assert_eq!((got[0].reporter_user_id.as_str(), got[0].received_at, got[0].excerpt.as_deref()), ("bob", 42, Some("quote")));

    // Blocked: nothing Bob sends is acted on — not an edit, not a reaction, not a report.
    alice.blocked.insert("bob".into());
    alice.handle_content(&local, bob.clone(), &edit("conv"), 10).await;
    alice.handle_content(&local, bob, &Content::Report { report }.encode().unwrap(), 42).await;
    assert!(alice.take_dm_ops().is_empty() && alice.take_reports().is_empty());
    assert_eq!(alice.blocked_users(), ["bob"]);
}

/// Engine state survives a persistence round trip: identity, sender keys, bindings, notices.
#[tokio::test]
async fn engine_state_survives_serialization() {
    let mut alice = engine("alice", "a1");
    let mut bob = engine("bob", "b1");
    hand_key(&mut alice, &mut bob, "x").await;
    alice.send_keys.get_mut("channel:x").unwrap().holders.insert(addr("bob", "b1"));
    alice.spaces.insert("s".into(), [3; 32]);
    alice.pending_acks.push("env-1".into());
    let first = wire(&mut alice, "x", "before restart");

    let snapshot = alice.export_state();
    let mut restored = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(restored.load_state(&snapshot), LoadOutcome::Restored);
    assert_eq!(restored.local().unwrap(), addr("alice", "a1"));
    assert_eq!(restored.send_key_id("channel:x"), alice.send_key_id("channel:x"));
    assert!(restored.send_keys["channel:x"].holders.contains(&addr("bob", "b1")));
    assert_eq!(restored.pending_acks, ["env-1"]);
    assert_eq!(restored.spaces.get("s"), Some(&[3; 32]));

    // The restored engine keeps sending on the same sender key; bob reads both messages.
    let second = wire(&mut restored, "x", "after restart");
    assert_eq!(bob.group_decrypt("channel:x", &addr("alice", "a1"), &first).unwrap(), b"before restart");
    assert_eq!(bob.group_decrypt("channel:x", &addr("alice", "a1"), &second).unwrap(), b"after restart");
    // Bob's receiving state survives too.
    let bob_snapshot = bob.export_state();
    let mut bob2 = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(bob2.load_state(&bob_snapshot), LoadOutcome::Restored);
    let third = wire(&mut restored, "x", "third");
    assert_eq!(bob2.group_decrypt("channel:x", &addr("alice", "a1"), &third).unwrap(), b"third");
}

/// A channel message only decrypts in the scope its sender key was announced for, from the device
/// that announced it; replays and pre-libsignal ciphertext are rejected.
#[tokio::test]
async fn channel_messages_are_bound_to_scope_and_sender() {
    let mut alice = engine("alice", "a1");
    let mut bob = engine("bob", "b1");
    hand_key(&mut alice, &mut bob, "general").await;
    let a = addr("alice", "a1");

    let m = wire(&mut alice, "general", "hello");
    // A malicious server replays the ciphertext into another channel, or attributes it to
    // another device: refused before any key is touched.
    assert!(matches!(bob.group_decrypt("channel:random", &a, &m), Err(EngineError::NoSession(_))));
    assert!(matches!(bob.group_decrypt("channel:general", &addr("alice", "a2"), &m), Err(EngineError::NoSession(_))));
    assert!(matches!(bob.group_decrypt("channel:general", &addr("mallory", "m1"), &m), Err(EngineError::NoSession(_))));
    assert_eq!(bob.group_decrypt("channel:general", &a, &m).unwrap(), b"hello");
    assert!(bob.group_decrypt("channel:general", &a, &m).is_err(), "replay rejected");

    // Out of order within the chain.
    let m1 = wire(&mut alice, "general", "one");
    let m2 = wire(&mut alice, "general", "two");
    assert_eq!(bob.group_decrypt("channel:general", &a, &m2).unwrap(), b"two");
    assert_eq!(bob.group_decrypt("channel:general", &a, &m1).unwrap(), b"one");

    // A distribution id cannot be re-pointed at another channel by re-announcing it.
    let id = alice.send_key_id("channel:general").unwrap();
    let skdm = alice.store.create_distribution(&a, id).unwrap();
    let payload = Content::SenderKey { channel_id: "random".into(), skdm }.encode().unwrap();
    let bob_local = bob.local().unwrap();
    let keys_before = bob.recv_keys.len();
    bob.handle_content(&bob_local, a.clone(), &payload, 0).await;
    let m3 = wire(&mut alice, "general", "three");
    assert!(bob.group_decrypt("channel:random", &a, &m3).is_err());
    assert_eq!(bob.group_decrypt("channel:general", &a, &m3).unwrap(), b"three");
    assert_eq!(bob.recv_keys.len(), keys_before);

    // Protocol-v1 ciphertext (a bare postcard blob) and oversized input are refused cleanly.
    assert!(matches!(bob.group_decrypt("channel:general", &a, &[0x00, 0x01, 0x02]), Err(EngineError::Protocol(_))));
    assert!(matches!(bob.group_decrypt("channel:general", &a, &[]), Err(EngineError::Protocol(_))));
    let mut huge = vec![CHANNEL_WIRE_V3];
    huge.resize(MAX_WIRE_ENVELOPE + 2, 0);
    assert!(matches!(bob.group_decrypt("channel:general", &a, &huge), Err(EngineError::Protocol(_))));
}

/// Kick/ban/leave revocation at DEVICE granularity: the key rotates when any device holding it is
/// no longer a member device; an unchanged list does not rotate; a rotated key is a new
/// distribution the removed member never receives.
#[tokio::test]
async fn membership_shrink_rotates_sender_key() {
    let mut alice = engine("alice", "a1");
    let mut eve = engine("eve", "e1");
    let mut bob = engine("bob", "phone");
    let scope = "channel:c";
    hand_key(&mut alice, &mut eve, "c").await;
    hand_key(&mut alice, &mut bob, "c").await;
    let holders = [addr("bob", "phone"), addr("bob", "mac"), addr("eve", "e1")];
    alice.send_keys.get_mut(scope).unwrap().holders.extend(holders.iter().cloned());
    let old_id = alice.send_key_id(scope).unwrap();
    let a = addr("alice", "a1");

    let full: BTreeSet<DeviceAddress> = holders.iter().cloned().collect();
    assert!(!alice.membership_rotation_needed(scope, &full), "no shrink ⇒ no rotation");
    // A NEW device appearing (a member added a device) does not rotate either.
    let mut grown = full.clone();
    grown.insert(addr("dan", "d1"));
    assert!(!alice.membership_rotation_needed(scope, &grown));

    // Eve is kicked: her device leaves the member-device list.
    let without_eve: BTreeSet<DeviceAddress> = [addr("bob", "phone"), addr("bob", "mac")].into_iter().collect();
    assert!(alice.membership_rotation_needed(scope, &without_eve));
    // One of bob's devices is removed from his account: also a rotation (it still holds the key).
    let without_bob_mac: BTreeSet<DeviceAddress> = [addr("bob", "phone"), addr("eve", "e1")].into_iter().collect();
    assert!(alice.membership_rotation_needed(scope, &without_bob_mac));

    let before = wire(&mut alice, "c", "before the kick");
    alice.create_group_session(scope).unwrap();
    let new_id = alice.send_key_id(scope).unwrap();
    assert_ne!(new_id, old_id, "rotation mints a new distribution");
    assert!(alice.send_keys[scope].holders.is_empty(), "fresh key handed to nobody yet");
    assert!(!alice.membership_rotation_needed(scope, &without_eve));
    // The old key is deleted on the sender: it cannot be used to send again.
    assert!(alice.store.group_encrypt(&a, old_id, b"x").is_err());

    // Remaining member gets the fresh key; the removed one does not.
    hand_key(&mut alice, &mut bob, "c").await;
    let after = wire(&mut alice, "c", "post-kick secret");
    assert_eq!(bob.group_decrypt(scope, &a, &after).unwrap(), b"post-kick secret");
    assert!(matches!(eve.group_decrypt(scope, &a, &after), Err(EngineError::NoSession(_))), "removed member locked out");
    // Both still read what was sent before the rotation (late delivery).
    assert_eq!(bob.group_decrypt(scope, &a, &before).unwrap(), b"before the kick");
    assert_eq!(eve.group_decrypt(scope, &a, &before).unwrap(), b"before the kick");

    // No key at all ⇒ nothing to protect.
    assert!(!alice.membership_rotation_needed("channel:never-opened", &full));
}

/// `member_removed` marks exactly the scopes whose current key one of the removed user's devices
/// holds, stops accepting their sender keys for that server's channels, and a fresh key clears the
/// mark.
#[tokio::test]
async fn member_removal_marks_holding_scopes_stale() {
    let mut e = engine("me", "m1");
    let mut bob = engine("bob", "bob-dev");
    e.channel_servers.insert("c1".into(), "s1".into());
    e.channel_servers.insert("c2".into(), "s2".into());
    for ch in ["c1", "c2"] {
        let scope = format!("channel:{ch}");
        e.ensure_send_key(&scope).unwrap();
        e.send_keys.get_mut(&scope).unwrap().holders.extend([addr("bob", "bob-dev"), addr("carol", "c")]);
        hand_key(&mut bob, &mut e, ch).await;
    }
    let everyone: BTreeSet<DeviceAddress> = [addr("bob", "bob-dev"), addr("carol", "c")].into_iter().collect();
    let b = addr("bob", "bob-dev");

    e.member_removed("s1", "bob");
    assert!(e.group_key_stale("channel:c1"));
    assert!(!e.group_key_stale("channel:c2"), "bob is still in s2");
    // Stale forces a rotation even if bob has been re-admitted by the time we look.
    assert!(e.membership_rotation_needed("channel:c1", &everyone));
    assert!(!e.membership_rotation_needed("channel:c2", &everyone));
    // His sender key is no longer accepted in s1's channel, but still is in s2's.
    let m1 = wire(&mut bob, "c1", "x");
    let m2 = wire(&mut bob, "c2", "y");
    assert!(matches!(e.group_decrypt("channel:c1", &b, &m1), Err(EngineError::NoSession(_))));
    assert_eq!(e.group_decrypt("channel:c2", &b, &m2).unwrap(), b"y");
    // Someone who never held the key does not force a rotation.
    e.member_removed("s2", "dave");
    assert!(!e.group_key_stale("channel:c2"));

    e.create_group_session("channel:c1").unwrap();
    assert!(!e.group_key_stale("channel:c1"));
    assert!(e.send_keys["channel:c1"].holders.is_empty());
}

/// Control-message policy: a space key is accepted only from the recorded host or one of our own
/// devices, never overwrites one we hold; malformed voice keys are ignored; a session reset makes
/// us re-send our sender keys to that device.
#[tokio::test]
async fn control_messages_are_policy_checked() {
    let mut e = engine("me", "m1");
    let me = e.local().unwrap();
    e.pin_owner("s1", "host", trust::OwnerSource::Invite);
    let space = |server: &str, key: u8| Content::SpaceKey { server_id: server.into(), key: [key; 32] }.encode().unwrap();
    for (user, device) in [("mallory", "x"), ("host", "h1"), ("newbie", "n1"), ("newbie", "n2"), ("bob", "b1")] {
        pin_fresh(&mut e, user, device);
    }

    e.handle_content(&me, addr("mallory", "x"), &space("s1", 1), 0).await;
    assert!(!e.spaces.contains_key("s1"), "a random peer cannot seed a space key");
    e.handle_content(&me, addr("host", "h1"), &space("s1", 2), 0).await;
    assert_eq!(e.spaces["s1"], [2; 32]);
    e.handle_content(&me, addr("host", "h1"), &space("s1", 3), 0).await;
    assert_eq!(e.spaces["s1"], [2; 32], "never overwritten");
    // "Own device" privileges are for VERIFIED siblings only. A device the server merely lists
    // under our account (e.g. enrolled with a stolen session token) gets none of them...
    e.last_sibling_check = Some(Instant::now());
    let rogue_sync = Content::Chat { conversation_id: "c".into(), message_id: "m".into(), text: "planted".into(), sent_at: 1, sync_peer: Some("bob".into()) }
        .encode()
        .unwrap();
    e.dm_participants.insert("c".into(), vec!["me".into(), "bob".into()]);
    e.handle_content(&me, addr("me", "rogue"), &space("s9", 4), 0).await;
    e.handle_content(&me, addr("me", "rogue"), &rogue_sync, 0).await;
    e.handle_content(&me, addr("me", "rogue"), &Content::Siblings { devices: vec![("rogue2".into(), vec![1; 33])] }.encode().unwrap(), 0).await;
    assert!(!e.spaces.contains_key("s9"), "an unlinked device on our account cannot seed a space key");
    assert!(e.inbox_dms.is_empty(), "nor plant 'sent by me' messages");
    assert!(e.siblings.is_empty(), "nor vouch for further devices");
    // ...a verified sibling does — but only over a session with the identity key that was
    // vouched for (the server issues sender certificates, so the address alone proves nothing).
    let sibling_key = SignalStore::generate().identity_key();
    e.siblings.insert("m2".into(), sibling_key.clone());
    e.store.accept_identity(&addr("me", "m2"), &SignalStore::generate().identity_key()).unwrap();
    e.handle_content(&me, addr("me", "m2"), &space("s9", 4), 0).await;
    assert!(!e.spaces.contains_key("s9"), "right device id, wrong identity key");
    e.store.accept_identity(&addr("me", "m2"), &sibling_key).unwrap();
    e.take_security_notices();
    e.handle_content(&me, addr("me", "m2"), &space("s9", 4), 0).await;
    assert_eq!(e.spaces["s9"], [4; 32], "a verified sibling device may link us in");
    e.handle_content(&me, addr("me", "m2"), &rogue_sync, 0).await;
    assert_eq!(e.inbox_dms.len(), 1);
    assert_eq!(e.inbox_dms[0].author_id, SELF_AUTHOR);

    // Provision requests queue once per (server, user) and are dropped once provisioned.
    let prov = Content::ProvisionRequest { server_id: "s1".into() }.encode().unwrap();
    e.handle_content(&me, addr("newbie", "n1"), &prov, 0).await;
    assert_eq!(e.prov_queue.len(), 1);
    e.provisioned.insert("s1|newbie".into());
    e.handle_content(&me, addr("newbie", "n2"), &prov, 0).await;
    assert_eq!(e.prov_queue.len(), 1);

    // Voice keys: wrong length / out-of-range index ignored; a good one for a call we are in is
    // stored per sender user.
    let vk = |index: u32, len: usize| Content::VoiceKey { channel_id: "v".into(), call_id: "RM_1".into(), index, key: vec![7; len] }.encode().unwrap();
    e.voice_call("v", "RM_1");
    e.handle_content(&me, addr("bob", "b1"), &vk(0, 16), 0).await;
    e.handle_content(&me, addr("bob", "b1"), &vk(99, 32), 0).await;
    assert!(e.voice.iter().all(|c| c.peers.is_empty()) && e.pending_voice.is_empty());
    e.handle_content(&me, addr("bob", "b1"), &vk(1, 32), 0).await;
    assert_eq!(e.voice_call("v", "RM_1").peers["bob"][&1], vec![7; 32]);

    // SessionReset from a holder: forget that it holds our keys, so the next sync re-sends them.
    e.ensure_send_key("channel:c").unwrap();
    e.send_keys.get_mut("channel:c").unwrap().holders.extend([addr("bob", "b1"), addr("bob", "b2")]);
    e.handle_content(&me, addr("bob", "b1"), &Content::SessionReset.encode().unwrap(), 0).await;
    assert_eq!(e.send_keys["channel:c"].holders.iter().cloned().collect::<Vec<_>>(), [addr("bob", "b2")]);

    // Garbage and unknown content versions are ignored without effect.
    e.handle_content(&me, addr("bob", "b1"), b"", 0).await;
    e.handle_content(&me, addr("bob", "b1"), &[9, 1, 2, 3], 0).await;
    assert!(Content::decode(&[CONTENT_V1, 0xff, 0xff, 0xff]).is_none());
}

/// A backup carries the identity and space keys but no session state, and loads into a store
/// that still has the same identity (so safety numbers survive a restore).
#[tokio::test]
async fn backup_export_excludes_sessions() {
    let mut alice = engine("alice", "a1");
    let mut bob = engine("bob", "b1");
    hand_key(&mut alice, &mut bob, "c").await;
    alice.spaces.insert("s".into(), [1; 32]);
    let backup = alice.export_backup();
    let b: BackupState = postcard::from_bytes(&backup).unwrap();
    assert_eq!(b.spaces["s"], [1; 32]);
    assert_eq!(b.device_id.as_deref(), Some("a1"));
    let restored = SignalStore::from_bytes(&b.identity).unwrap();
    assert_eq!(restored.identity_key(), alice.store.identity_key());
    let id = alice.send_key_id("channel:c").unwrap();
    assert!(!restored.has_sender_key(&addr("alice", "a1"), id), "sender keys are not backed up");
    assert_eq!(restored.one_time_prekey_counts(), (0, 0));
}

/// The 426 "update required" response surfaces as a dedicated, user-facing error.
#[test]
fn update_required_is_a_distinct_error() {
    let e: EngineError = ClientError::Status { status: 426, body: r#"{"error":"update required: new app needed"}"#.into() }.into();
    assert!(matches!(&e, EngineError::UpdateRequired(m) if m == "update required: new app needed"));
    let e: EngineError = ClientError::Status { status: 403, body: "{}".into() }.into();
    assert!(matches!(e, EngineError::Client(_)));
}

// ---- contact device trust (H1 + M2) ----

fn dir_row(user: &str, device: &str, identity: &[u8], link: Option<(&str, &[u8])>) -> serde_json::Value {
    serde_json::json!({
        "user_id": user,
        "device_id": device,
        "delivery_key": B64.encode([9u8; 32]),
        "identity_key": B64.encode(identity),
        "linked_by": link.map(|(d, _)| d),
        "link_sig": link.map(|(_, s)| B64.encode(s)),
    })
}

fn kinds(e: &mut Engine) -> Vec<(String, String, String, bool)> {
    e.take_security_notices().into_iter().map(|n| (n.kind, n.user_id, n.device_id, n.was_verified)).collect()
}

/// THE ATTACK (H1 + M2): the server mints a "new device" for a contact — no link signature, or a
/// forged one — hoping DMs fan out to it and its messages are taken as the contact's. Build 42
/// returned every listed device from `ingest_devices` (so it received DMs and every key) and
/// accepted its inbound messages, with at most one droppable "new device" notice.
#[tokio::test]
async fn server_minted_contact_device_is_held_and_blocks_a_verified_contact() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    let bob1 = SignalStore::generate();
    let bob2 = SignalStore::generate();
    let ghost = SignalStore::generate();
    let (b1, b2, g) = (addr("bob", "b1"), addr("bob", "b2"), addr("bob", "ghost"));
    me.dm_participants.insert("conv".into(), vec!["me".into(), "bob".into()]);
    me.dir_refreshed.insert("bob".into(), Instant::now()); // no directory re-check in this test
    let devices = |e: &mut Engine, rows: Vec<serde_json::Value>| -> Vec<DeviceAddress> {
        e.ingest_devices(Some("bob"), &serde_json::Value::Array(rows)).into_iter().map(|(d, _)| d).collect()
    };

    // First sight of bob: his one device is pinned (the account root). No notice.
    assert_eq!(devices(&mut me, vec![dir_row("bob", "b1", &bob1.identity_key(), None)]), std::slice::from_ref(&b1));
    assert!(kinds(&mut me).is_empty());
    me.store.accept_identity(&b1, &bob1.identity_key()).unwrap();
    me.set_verified(&b1, true).unwrap();
    assert!(me.is_verified(&b1));

    // The server adds a device with NO link signature.
    let listed = vec![dir_row("bob", "b1", &bob1.identity_key(), None), dir_row("bob", "ghost", &ghost.identity_key(), None)];
    assert_eq!(devices(&mut me, listed.clone()), std::slice::from_ref(&b1), "an unvouched device must never be a send target");
    assert_eq!(
        kinds(&mut me),
        [("unverified_contact_device".into(), "bob".into(), "ghost".into(), true), ("identity_changed".into(), "bob".into(), "".into(), true)],
        "named, and flagged as blocking a verified contact"
    );
    // Seeing the same listing again does not repeat the notices.
    devices(&mut me, listed);
    assert!(kinds(&mut me).is_empty());
    // A forged link: signed by the ghost itself / by a stranger, "linked by b1".
    for forger in [&ghost, &SignalStore::generate()] {
        let sig = forger.sign_link("bob", &ghost.identity_key()).unwrap();
        let rows = vec![dir_row("bob", "b1", &bob1.identity_key(), None), dir_row("bob", "ghost", &ghost.identity_key(), Some(("b1", &sig)))];
        assert_eq!(devices(&mut me, rows), std::slice::from_ref(&b1));
    }
    // ...or bob's real signature, but over ANOTHER key / for another account.
    let wrong_key = bob1.sign_link("bob", &bob2.identity_key()).unwrap();
    let wrong_user = bob1.sign_link("carol", &ghost.identity_key()).unwrap();
    for sig in [&wrong_key, &wrong_user] {
        let rows = vec![dir_row("bob", "b1", &bob1.identity_key(), None), dir_row("bob", "ghost", &ghost.identity_key(), Some(("b1", sig)))];
        assert_eq!(devices(&mut me, rows), std::slice::from_ref(&b1));
    }

    // Bob is VERIFIED and has an unvouched device: the whole send is blocked — even to b1.
    assert!(me.contact_blocked("bob") && !me.is_verified(&b1));
    let chat = Content::Chat { conversation_id: "conv".into(), message_id: "x".into(), text: "secret".into(), sent_at: 1, sync_peer: None };
    assert!(matches!(me.send_content(&[b1.clone(), g.clone()], &chat).await, Err(EngineError::IdentityChanged(u)) if u == "bob"));
    assert!(matches!(me.set_verified(&b1, true), Err(EngineError::IdentityChanged(_))), "cannot be waved through by re-marking");

    // Inbound from the ghost (the server issued it a sender certificate) is not delivered as
    // bob's message; it is held. From b1 it is delivered.
    me.store.accept_identity(&g, &ghost.identity_key()).unwrap();
    let forged = Content::Chat { conversation_id: "conv".into(), message_id: "f1".into(), text: "wire me money".into(), sent_at: 1, sync_peer: None }.encode().unwrap();
    me.handle_content(&local, g.clone(), &forged, 5).await;
    assert!(me.inbox_dms.is_empty(), "a message from an unvouched device was accepted as the contact's");
    assert_eq!(me.held_inbound.len(), 1);
    me.handle_content(&local, b1.clone(), &chat.encode().unwrap(), 5).await;
    assert_eq!(me.inbox_dms.len(), 1);
    // A device the directory does not list at all (removed, or made up): dropped outright.
    me.handle_content(&local, addr("bob", "nobody"), &forged, 5).await;
    assert_eq!((me.inbox_dms.len(), me.held_inbound.len()), (1, 1));
    // Right device id, but the session is under another identity key: not that device.
    me.store.accept_identity(&b1, &ghost.identity_key()).unwrap();
    me.handle_content(&local, b1.clone(), &forged, 5).await;
    assert_eq!(me.inbox_dms.len(), 1);
    me.store.accept_identity(&b1, &bob1.identity_key()).unwrap();
    me.take_security_notices();

    // The server withdraws the ghost: bob is as verified as before.
    assert_eq!(devices(&mut me, vec![dir_row("bob", "b1", &bob1.identity_key(), None)]), std::slice::from_ref(&b1));
    assert!(me.is_verified(&b1) && !me.contact_blocked("bob"));

    // Bob REALLY links a device (b1 signs b2's identity key): it is chain-verified and becomes a
    // send target — and, because bob was verified for exactly {b1}, sends stay blocked until
    // the user has compared the (changed) account safety number.
    let link = bob1.sign_link("bob", &bob2.identity_key()).unwrap();
    let rows = vec![dir_row("bob", "b1", &bob1.identity_key(), None), dir_row("bob", "b2", &bob2.identity_key(), Some(("b1", &link)))];
    assert_eq!(devices(&mut me, rows.clone()), [b1.clone(), b2.clone()]);
    assert_eq!(kinds(&mut me), [("new_device".into(), "bob".into(), "b2".into(), false), ("identity_changed".into(), "bob".into(), "".into(), true)]);
    assert!(me.contact_blocked("bob"));
    me.set_verified(&b1, true).unwrap();
    assert!(me.is_verified(&b2) && !me.contact_blocked("bob"));
    // A third device linked BY the second: the chain goes b3 → b2 → b1 (the pinned root).
    let bob3 = SignalStore::generate();
    let link3 = bob2.sign_link("bob", &bob3.identity_key()).unwrap();
    let mut rows3 = rows.clone();
    rows3.push(dir_row("bob", "b3", &bob3.identity_key(), Some(("b2", &link3))));
    assert_eq!(devices(&mut me, rows3).len(), 3);
    // b1 is removed from the account; b3's chain still verifies through the remembered b2.
    let rows_no_root = vec![
        dir_row("bob", "b2", &bob2.identity_key(), Some(("b1", &link))),
        dir_row("bob", "b3", &bob3.identity_key(), Some(("b2", &link3))),
    ];
    assert_eq!(devices(&mut me, rows_no_root), [b2.clone(), addr("bob", "b3")]);

    // The ghost is no longer listed: what was held from it went with the key it was read
    // under (held text never outlives the listing it was read against).
    assert!(me.held_inbound.is_empty());
    // State (pins, verified set) survives a restart.
    let mut again = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert_eq!(again.contacts["bob"].vouched.len(), 3);
}

/// An unverified contact with an unvouched device: sends to the trusted devices go ahead, the
/// unvouched one is held and named. A state written by build 42 (no trust extension) loads.
#[tokio::test]
async fn unverified_contact_holds_only_the_unvouched_device() {
    let mut me = engine("me", "m1");
    let bob1 = SignalStore::generate();
    let ghost = SignalStore::generate();
    let rows = |with_ghost: bool| {
        let mut v = vec![dir_row("bob", "b1", &bob1.identity_key(), None)];
        if with_ghost {
            v.push(dir_row("bob", "ghost", &ghost.identity_key(), None));
        }
        serde_json::Value::Array(v)
    };
    me.ingest_devices(Some("bob"), &rows(false));
    let out = me.ingest_devices(Some("bob"), &rows(true));
    assert_eq!(out.len(), 1);
    assert!(!me.contact_blocked("bob"), "not verified ⇒ the trusted device keeps working");
    assert_eq!(kinds(&mut me), [("unverified_contact_device".into(), "bob".into(), "ghost".into(), false)]);
    assert!(!me.contact_device_trusted(&addr("bob", "ghost")));

    // Build-42 state: the original struct with nothing after it.
    let full = me.export_state();
    let mut old = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(old.load_state(&full), LoadOutcome::Restored);
    let state = EngineState {
        store: me.store.to_bytes(),
        user_id: me.user_id.clone(),
        device_id: me.device_id.clone(),
        delivery_key: me.delivery_key,
        spaces: HashMap::new(),
        expected_provisioner: HashMap::new(),
        pinned_instance_key: None,
        trust_root: None,
        cert: None,
        peer_delivery: HashMap::new(),
        send_keys: HashMap::new(),
        recv_keys: HashMap::new(),
        legacy_peers: BTreeSet::new(),
        notices: Vec::new(),
        pending_acks: Vec::new(),
        inbox_dms: Vec::new(),
        blocked: BTreeSet::new(),
        siblings: BTreeMap::new(),
        pending_link: None,
        known_devices: HashMap::new(),
    };
    let mut build42 = STATE_MAGIC.to_vec();
    build42.extend(postcard::to_stdvec(&state).unwrap());
    let mut upgraded = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(upgraded.load_state(&build42), LoadOutcome::Restored);
    assert!(upgraded.contacts.is_empty() && upgraded.rosters.is_empty());
    // A corrupt extension is not half-loaded.
    let mut bad = build42.clone();
    bad.extend([trust::EXT_VERSION, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(Engine::new(ApiClient::new("http://localhost".to_string())).load_state(&bad), LoadOutcome::Unreadable);
}

// ---- membership (C1 interim) ----

fn approval(signer: &SignalStore, server: &str, user: &str, approver: &str, device: &str, ts: i64) -> serde_json::Value {
    serde_json::json!({
        "user_id": user,
        "approver_user_id": approver,
        "approver_device_id": device,
        "ts": ts,
        "signature": B64.encode(signer.sign_member_approval(server, user, approver, ts).unwrap()),
    })
}

/// THE ATTACK (C1): a malicious host inserts a ghost member (or, with a colluding account, a
/// device) and waits for every client to hand it sender keys, space keys and voice keys. Build
/// 42 keyed every device the member list returned, and a first-sight user raised no notice.
#[tokio::test]
async fn server_inserted_member_gets_no_keys_without_a_verifiable_approval() {
    let mut me = engine("me", "m1");
    let host = SignalStore::generate();
    let bob = SignalStore::generate();
    let (h1, b1) = (addr("host", "h1"), addr("bob", "b1"));
    pin(&mut me, &h1, &host.identity_key());
    pin(&mut me, &b1, &bob.identity_key());
    let ghost = pin_fresh(&mut me, "ghost", "g1"); // the server lists it; its device is "pinned" like any first-sight user
    me.pin_owner("s", "host", trust::OwnerSource::Invite);
    let scope = "channel:c";

    // Our first look at the server: the members listed then are the baseline. No events.
    assert_eq!(me.admit("s", scope, vec![h1.clone(), b1.clone()]).await, [h1.clone(), b1.clone()]);
    assert!(me.take_system_events().is_empty());

    // The server now lists a ghost. It gets nothing, and the channel says so — once.
    let listed = vec![h1.clone(), b1.clone(), ghost.clone()];
    assert_eq!(me.clear_devices("s", scope, listed.clone()), [h1.clone(), b1.clone()], "a server-inserted member was cleared for keys");
    let events = me.take_system_events();
    assert_eq!(events.len(), 1);
    assert_eq!((events[0].kind.as_str(), events[0].user_id.as_str(), events[0].scope.as_str()), ("member_held", "ghost", scope));
    assert_eq!(me.clear_devices("s", scope, listed.clone()).len(), 2);
    assert!(me.take_system_events().is_empty());
    assert_eq!(me.held_members("s"), ["ghost"]);

    // Approvals the server can fabricate or replay do not admit it:
    let now = now_ms() as i64;
    let stranger = SignalStore::generate();
    let forged = serde_json::json!([
        approval(&stranger, "s", "ghost", "host", "h1", now),          // not the host's key
        approval(&stranger, "s", "ghost", "ghost", "g1", now),         // self-approval
        approval(&host, "other-server", "ghost", "host", "h1", now),   // the host's signature for another server
        approval(&host, "s", "someone-else", "host", "h1", now),       // ...or for another user
        approval(&host, "s", "ghost", "host", "h1", now + 3_600_000),  // post-dated
        approval(&stranger, "s", "ghost", "stranger", "x", now),       // approver is nobody here
        approval(&host, "s", "ghost", "host", "h-unknown", now),       // a device of the host we do not trust
    ]);
    // (rows 3 and 4 carry valid signatures over DIFFERENT statements; re-label them as ghost@s)
    let mut relabelled = forged.clone();
    relabelled[2]["user_id"] = "ghost".into();
    relabelled[3]["user_id"] = "ghost".into();
    me.apply_approvals("s", &forged);
    me.apply_approvals("s", &relabelled);
    assert_eq!(me.clear_devices("s", scope, listed.clone()).len(), 2, "a forged approval admitted the ghost");

    // The host's device really approves a newcomer: accepted, and the join is SHOWN (with who
    // approved) before the key goes out.
    let newbie = pin_fresh(&mut me, "newbie", "n1");
    me.apply_approvals("s", &serde_json::json!([approval(&host, "s", "newbie", "host", "h1", now)]));
    let with_newbie = vec![h1.clone(), b1.clone(), newbie.clone()];
    // No visible event ⇒ no key (a sink that cannot write the row).
    me.set_event_sink(Box::new(|_| false));
    assert_eq!(me.clear_devices("s", scope, with_newbie.clone()).len(), 2, "keys went out before the join was shown");
    let shown = std::sync::Arc::new(std::sync::Mutex::new(Vec::<SystemEvent>::new()));
    let sink = shown.clone();
    me.set_event_sink(Box::new(move |e| {
        sink.lock().unwrap().push(e.clone());
        true
    }));
    assert_eq!(me.clear_devices("s", scope, with_newbie.clone()), with_newbie);
    {
        let shown = shown.lock().unwrap();
        assert_eq!(shown.len(), 1);
        assert_eq!((shown[0].kind.as_str(), shown[0].user_id.as_str(), shown[0].by_user_id.as_deref()), ("member_joined", "newbie", Some("host")));
    }
    // A member already accepted (bob) may approve too; an approved member's NEW device is shown
    // as "added a device" before it is keyed.
    let carol = pin_fresh(&mut me, "carol", "c1");
    me.apply_approvals("s", &serde_json::json!([approval(&bob, "s", "carol", "bob", "b1", now)]));
    let n2 = pin_fresh(&mut me, "newbie", "n2");
    let all = vec![h1.clone(), b1.clone(), newbie.clone(), n2.clone(), carol.clone()];
    assert_eq!(me.clear_devices("s", scope, all.clone()), all);
    {
        let shown = shown.lock().unwrap();
        let tail: Vec<(&str, &str, &str)> = shown[1..].iter().map(|e| (e.kind.as_str(), e.user_id.as_str(), e.device_id.as_str())).collect();
        assert_eq!(tail, [("device_added", "newbie", "n2"), ("member_joined", "carol", "")]);
    }

    // Kick, then the server re-inserts the user and REPLAYS the old approval: refused. Only an
    // approval made after the removal re-admits them.
    me.member_removed("s", "newbie");
    me.apply_approvals("s", &serde_json::json!([approval(&host, "s", "newbie", "host", "h1", now)]));
    assert!(!me.clear_devices("s", scope, all.clone()).contains(&newbie), "a replayed approval re-admitted a removed member");
    me.apply_approvals("s", &serde_json::json!([approval(&host, "s", "newbie", "host", "h1", now_ms() as i64 + 1000)]));
    assert!(me.clear_devices("s", scope, all.clone()).contains(&newbie));

    // An approver whose own devices are in doubt (verified contact, changed device set) is not
    // believed until the user has re-verified them.
    me.contacts.get_mut("host").unwrap().verified = Some(vec![vec![0; 33]]);
    let dave = pin_fresh(&mut me, "dave", "d1");
    me.apply_approvals("s", &serde_json::json!([approval(&host, "s", "dave", "host", "h1", now)]));
    let mut with_dave = all.clone();
    with_dave.push(dave.clone());
    assert!(!me.clear_devices("s", scope, with_dave).contains(&dave));

    // Rosters survive a restart.
    let mut again = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert!(again.rosters["s"].members.contains("carol") && !again.rosters["s"].members.contains("ghost"));
}

/// THE ATTACK (C1, owner side): the server inserts a ghost user and has it send the owner a
/// provision request. The owner's device must not turn that into a signed approval or a key —
/// with a roster, and (fail-closed) without one.
#[tokio::test]
async fn provision_request_from_an_unapproved_user_signs_nothing_and_sends_nothing() {
    for with_roster in [true, false] {
        let mut owner = engine("owner", "o1");
        let me = owner.local().unwrap();
        owner.spaces.insert("s".into(), [7; 32]);
        owner.pin_owner("s", "owner", trust::OwnerSource::Created);
        if with_roster {
            owner.rosters.entry("s".into()).or_default().members.extend(["owner".to_string(), "bob".to_string()]);
        }
        let ghost = pin_fresh(&mut owner, "ghost", "g1");
        let prov = Content::ProvisionRequest { server_id: "s".into() }.encode().unwrap();
        owner.handle_content(&me, ghost.clone(), &prov, 0).await;
        assert_eq!(owner.prov_queue.len(), 1);

        assert_eq!(owner.fulfill_provisions().await, 0, "an unapproved requester was provisioned");
        assert!(owner.provisioned.is_empty());
        assert!(owner.rosters.get("s").is_none_or(|r| !r.members.contains("ghost") && r.approved_by.is_empty()), "an approval was recorded");
        assert!(owner.send_keys.is_empty(), "a sender key was minted for distribution");
        // It surfaces as a join request for the owner — once.
        assert_eq!(kinds(&mut owner), [("join_request".into(), "ghost".into(), "s".into(), false)]);
        owner.handle_content(&me, ghost.clone(), &prov, 0).await;
        assert_eq!(owner.fulfill_provisions().await, 0);
        assert!(kinds(&mut owner).is_empty());
        // The explicit provisioning call refuses too: approval is a separate, deliberate step.
        assert!(matches!(owner.provision_member("s", &ghost).await, Err(EngineError::Protocol(_))));
        // And when the baseline is taken later, the requester is NOT grandfathered in.
        let listed = vec![addr("bob", "b1"), ghost.clone()];
        pin_fresh(&mut owner, "bob", "b1");
        let admitted = if with_roster { owner.clear_devices("s", "channel:c", listed) } else { owner.admit("s", "channel:c", listed).await };
        assert!(!admitted.contains(&ghost), "with_roster={with_roster}");
        assert_eq!(owner.held_members("s"), ["ghost"]);
    }
}

/// A server that lies about `owner_id` gains nothing: what it lists is kept for display only and
/// never becomes the trust anchor, so a "ghost owner" can neither seed a space key nor approve
/// members. A device with no pinned owner gets one only from a verified sibling of its own.
#[tokio::test]
async fn server_claimed_owner_is_never_a_trust_anchor() {
    let mut me = engine("me", "m2"); // e.g. a freshly linked device: no owner pinned yet
    let local = me.local().unwrap();
    let ghost_store = SignalStore::generate();
    let ghost = addr("ghost", "g1");
    pin(&mut me, &ghost, &ghost_store.identity_key());
    let bob = pin_fresh(&mut me, "bob", "b1");

    // The server's listing names the ghost as owner of "s".
    me.note_claimed_owners(&serde_json::json!([{ "server_id": "s", "owner_id": "ghost" }]));
    assert_eq!(me.trusted_owner("s"), None, "a server-supplied owner was pinned");
    assert!(me.expected_provisioner.is_empty());
    assert_eq!(me.claimed_owners.get("s").map(String::as_str), Some("ghost"), "kept, for display only");

    // The ghost "owner" sends a space key: refused.
    let space = Content::SpaceKey { server_id: "s".into(), key: [9; 32] }.encode().unwrap();
    me.handle_content(&local, ghost.clone(), &space, 0).await;
    assert!(!me.spaces.contains_key("s"), "a space key from the server-named owner was accepted");

    // The ghost "owner" approves an accomplice: refused (the ghost is not in our roster either).
    assert_eq!(me.admit("s", "channel:c", vec![bob.clone()]).await, std::slice::from_ref(&bob));
    let accomplice = pin_fresh(&mut me, "accomplice", "x1");
    me.apply_approvals("s", &serde_json::json!([approval(&ghost_store, "s", "accomplice", "ghost", "g1", now_ms() as i64)]));
    assert!(!me.clear_devices("s", "channel:c", vec![bob.clone(), accomplice.clone()]).contains(&accomplice), "an approval by the server-named owner was accepted");

    // Owner pins: not from another account, not from an unverified device of ours...
    let pins = Content::OwnerPins { pins: vec![("s".into(), "ghost".into())] }.encode().unwrap();
    me.handle_content(&local, ghost.clone(), &pins, 0).await;
    me.last_sibling_check = Some(Instant::now());
    me.handle_content(&local, addr("me", "rogue"), &pins, 0).await;
    assert_eq!(me.trusted_owner("s"), None);
    // ...only from a verified sibling of our own account, and an existing pin is never replaced.
    let sibling_key = SignalStore::generate().identity_key();
    me.siblings.insert("m1".into(), sibling_key.clone());
    me.store.accept_identity(&addr("me", "m1"), &sibling_key).unwrap();
    let real = Content::OwnerPins { pins: vec![("s".into(), "host".into())] }.encode().unwrap();
    me.handle_content(&local, addr("me", "m1"), &real, 0).await;
    assert_eq!(me.trusted_owner("s").map(String::as_str), Some("host"));
    me.handle_content(&local, addr("me", "m1"), &pins, 0).await;
    assert_eq!(me.trusted_owner("s").map(String::as_str), Some("host"), "a pin was replaced");
}

/// Owner pins carry a provenance. A pin from before provenance existed (any build-42 state, a
/// restored backup) is `legacy-unknown`: it authorizes nothing, is not sent to sibling devices,
/// and becomes trusted only when the pinned instance key re-confirms that very owner.
#[tokio::test]
async fn legacy_owner_pins_authorize_nothing_and_are_not_propagated() {
    // A build-42 state: an owner pin with no provenance at all.
    let mut old = engine("me", "m1");
    old.expected_provisioner.insert("s".into(), "host".into());
    old.expected_provisioner.insert("poisoned".into(), "ghost".into());
    let (instance_secret, instance_public) = skwod_crypto::instance::generate();
    old.pinned_instance_key = Some(instance_public.to_vec());
    let mut me = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(me.load_state(&old.export_state()), LoadOutcome::Restored);
    let local = me.local().unwrap();
    assert_eq!(me.expected_provisioner.len(), 2, "the pins are kept...");
    assert!(me.trusted_owner("s").is_none() && me.trusted_owner("poisoned").is_none(), "...but marked legacy-unknown");
    assert!(me.owner_pins_to_share().is_empty(), "a legacy pin was offered to sibling devices");

    // It authorizes neither a space key nor an approval.
    me.owner_rechecked.insert("s".into(), Instant::now()); // no network re-confirmation here
    me.owner_rechecked.insert("poisoned".into(), Instant::now());
    let host_store = SignalStore::generate();
    let host = addr("host", "h1");
    pin(&mut me, &host, &host_store.identity_key());
    let space = Content::SpaceKey { server_id: "s".into(), key: [4; 32] }.encode().unwrap();
    me.handle_content(&local, host.clone(), &space, 0).await;
    assert!(!me.spaces.contains_key("s"), "a legacy-unknown owner seeded a space key");
    let bob = pin_fresh(&mut me, "bob", "b1");
    me.rosters.entry("s".into()).or_default().members.extend(["me".to_string(), "bob".to_string()]);
    let newbie = pin_fresh(&mut me, "newbie", "n1");
    let now = now_ms() as i64;
    me.apply_approvals("s", &serde_json::json!([approval(&host_store, "s", "newbie", "host", "h1", now)]));
    assert!(!me.clear_devices("s", "channel:c", vec![bob.clone(), newbie.clone()]).contains(&newbie), "a legacy-unknown owner's approval was accepted");

    // Re-confirmation: only an attestation by the PINNED instance key, naming the SAME owner.
    let attest = |key: &[u8], server: &str, owner: &str| {
        let msg = skwod_crypto::instance::owner_attestation_message(server, owner).unwrap();
        serde_json::json!({ "owner_id": owner, "signature": B64.encode(skwod_crypto::instance::sign(key, &msg).unwrap()) })
    };
    let other_instance = skwod_crypto::instance::generate().0;
    assert!(!me.apply_owner_attestation("s", &attest(&other_instance, "s", "host")), "not the pinned instance key");
    assert!(!me.apply_owner_attestation("s", &attest(&instance_secret, "other", "host")), "for another server");
    assert!(!me.apply_owner_attestation("s", &attest(&instance_secret, "s", "someone-else")), "names a different owner");
    assert_eq!(me.expected_provisioner["s"], "host", "an attestation never replaces the pinned owner");
    assert!(me.trusted_owner("s").is_none());
    assert!(me.apply_owner_attestation("s", &attest(&instance_secret, "s", "host")));
    assert_eq!(me.trusted_owner("s").map(String::as_str), Some("host"));
    // Now — and only now — it authorizes, and may be shared with siblings; the other pin may not.
    me.apply_approvals("s", &serde_json::json!([approval(&host_store, "s", "newbie", "host", "h1", now)]));
    assert!(me.clear_devices("s", "channel:c", vec![bob.clone(), newbie.clone()]).contains(&newbie));
    me.handle_content(&local, host.clone(), &space, 0).await;
    assert_eq!(me.spaces.get("s"), Some(&[4; 32]));
    assert_eq!(me.owner_pins_to_share(), [("s".to_string(), "host".to_string())]);

    // A sibling's pin replaces a legacy-unknown one, never a trusted one.
    me.accept_sibling_pins(vec![("poisoned".into(), "real-owner".into()), ("s".into(), "ghost".into())]);
    assert_eq!(me.trusted_owner("poisoned").map(String::as_str), Some("real-owner"));
    assert_eq!(me.trusted_owner("s").map(String::as_str), Some("host"));
    // Provenance survives a restart; pins we make ourselves are trusted from the start.
    me.pin_owner("mine", "me", trust::OwnerSource::Created);
    let mut again = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert_eq!(again.owner_pins_to_share().len(), 3);
    // Without a pinned instance key there is nothing to re-confirm against.
    let mut unpinned = engine("me", "m1");
    unpinned.expected_provisioner.insert("s".into(), "host".into());
    assert!(!unpinned.apply_owner_attestation("s", &attest(&instance_secret, "s", "host")));
}

// ---- authenticated message metadata (M3) ----

/// The message id, reply target and edit flag travel inside the sender-key plaintext. A
/// ciphertext the server serves under another message id is dropped, and the server's own
/// `reply_to_id` / `is_edited` are ignored for a v3 message.
#[tokio::test]
async fn message_metadata_is_authenticated_by_the_sender() {
    let mut alice = engine("alice", "a1");
    let mut bob = engine("bob", "b1");
    hand_key(&mut alice, &mut bob, "c").await;
    let a = addr("alice", "a1");
    let seal = |e: &mut Engine, id: &str, reply: Option<&str>, edited: bool, text: &str| B64.decode(e.channel_ciphertext("c", id, reply, edited, text).unwrap()).unwrap();

    let pt = bob.open_channel_message("channel:c", &a, &seal(&mut alice, "m1", Some("m0"), false, "hi")).unwrap();
    assert_eq!(pt.text, "hi");
    // Served under its own id: the sender's reply target and edit flag win over the row's.
    assert_eq!(Engine::row_metadata("m1", pt.meta.clone()), Some((Some("m0".to_string()), false)));
    // Served under ANOTHER message's id (content swapped between rows): dropped.
    assert_eq!(Engine::row_metadata("m2", pt.meta), None);

    // An edit says so itself, and names the message it edits.
    let edit = bob.open_channel_message("channel:c", &a, &seal(&mut alice, "m1", Some("m0"), true, "hi (edited)")).unwrap();
    assert_eq!(Engine::row_metadata("m1", edit.meta.clone()), Some((Some("m0".to_string()), true)));
    assert_eq!(Engine::row_metadata("m9", edit.meta), None, "an edit cannot be applied to another message");

    // A build-42 (v2) body states no metadata: it is shown with no reply link and no edit
    // marker. There is no way to hand the row's own claims in.
    assert_eq!(Engine::row_metadata("m5", None), Some((None, false)));
}

/// M2 (a): the version byte is outside the ciphertext, so it decides nothing. A v3 message the
/// server relabels as v2 is still a v3 message: its sealed id, reply target and edit flag are
/// the ones used, and served under another message's id it is dropped — never shown as text.
#[tokio::test]
async fn a_v3_message_relabelled_as_v2_keeps_its_sealed_metadata() {
    let mut alice = engine("alice", "a1");
    let mut bob = engine("bob", "b1");
    hand_key(&mut alice, &mut bob, "c").await;
    let a = addr("alice", "a1");
    let honest = B64.decode(alice.channel_ciphertext("c", "m1", Some("m0"), true, "short").unwrap()).unwrap();
    assert_eq!(honest[0], CHANNEL_WIRE_V3);
    // Any other version byte is refused, before the key is touched.
    for v in [0u8, 1, 4, 255] {
        let mut other = honest.clone();
        other[0] = v;
        assert!(bob.open_channel_message("channel:c", &a, &other).is_err());
    }
    let mut flipped = honest.clone();
    flipped[0] = CHANNEL_WIRE_V2;
    let pt = bob.open_channel_message("channel:c", &a, &flipped).unwrap();
    assert_eq!(pt.text, "short");
    assert_eq!(pt.meta, Some(("m1".to_string(), Some("m0".to_string()), true)), "the metadata from INSIDE the ciphertext");
    assert_eq!(Engine::row_metadata("m1", pt.meta.clone()), Some((Some("m0".to_string()), true)));
    assert_eq!(Engine::row_metadata("m2", pt.meta), None, "moved to another row: dropped, not shown as text");
    // And it counts as a v3 sighting of that device.
    assert_eq!(bob.b45.v3_seen.len(), 1);

    // A v3-labelled body that is not a `ChannelBody` is malformed, not text.
    let id = alice.ensure_send_key("channel:c").unwrap();
    let mut bare = vec![CHANNEL_WIRE_V3];
    bare.extend(alice.store.group_encrypt(&a, id, b"just text").unwrap());
    assert!(matches!(bob.open_channel_message("channel:c", &a, &bare), Err(EngineError::Protocol(_))));
}

fn channel_row(id: &str, at: i64, wire: &[u8]) -> serde_json::Value {
    // What a lying server adds to every row: a reply target and an edit marker of its own.
    serde_json::json!({
        "message_id": id, "author_id": "alice", "author_device_id": "a1", "ciphertext": B64.encode(wire),
        "created_at": at, "updated_at": at, "reply_to_id": "forged-target", "is_edited": true,
    })
}

/// M2 (b) and "existing history still displays": a channel whose older pages are all build-42
/// (v2) messages. The newest page — already v3 — is read first; then the user scrolls up into
/// pages this device never fetched. Every old message is shown, as plain text, with the
/// server's `reply_to_id` / `is_edited` ignored; the v3 ones carry their sealed metadata.
#[tokio::test]
async fn build_42_history_still_displays_and_takes_no_metadata_from_the_server() {
    let mut alice = engine("alice", "a1");
    // (old page, newest page), filled in once bob holds alice's key.
    let pages = std::sync::Arc::new(std::sync::Mutex::new((Vec::new(), Vec::new())));
    let served = pages.clone();
    let mock = Mock::start(move |_, path| {
        if !path.starts_with("/api/channels/c/messages") {
            return (200, serde_json::json!({}));
        }
        let (old, new) = served.lock().unwrap().clone();
        (200, serde_json::json!({ "messages": if path.contains(&format!("before={}", i64::MAX)) { new } else { old } }))
    });
    let mut bob = mock.engine("bob", "b1");
    hand_key(&mut alice, &mut bob, "c").await;
    let old: Vec<serde_json::Value> = (1..=4).map(|i| channel_row(&format!("m{i}"), i, &wire_v2(&mut alice, "c", &format!("old {i}")))).collect();
    let seal = |e: &mut Engine, id: &str, reply: Option<&str>, text: &str| B64.decode(e.channel_ciphertext("c", id, reply, false, text).unwrap()).unwrap();
    let new = vec![channel_row("m5", 5, &seal(&mut alice, "m5", Some("m4"), "new 5")), channel_row("m6", 6, &seal(&mut alice, "m6", None, "new 6"))];
    *pages.lock().unwrap() = (old, new);

    let newest = bob.channel_page("c", "bob", PageCursor::Before(i64::MAX)).await.unwrap();
    let shown = |page: &ChannelPage| page.messages.iter().map(|m| (m.message_id.clone(), m.text.clone(), m.reply_to_id.clone(), m.is_edited, m.undecryptable)).collect::<Vec<_>>();
    assert_eq!(
        shown(&newest),
        vec![("m5".into(), "new 5".into(), Some("m4".into()), false, false), ("m6".into(), "new 6".into(), None, false, false)],
        "v3: the sender's reply target, not the row's"
    );
    assert_eq!(bob.b45.v3_seen.len(), 1, "alice's device has been seen on v3");

    // Scrolling up, AFTER the v3 messages were seen: the old rows are earlier on alice's own
    // counter, so they are read.
    let older = bob.channel_page("c", "bob", PageCursor::Before(5)).await.unwrap();
    assert_eq!(
        shown(&older),
        (1..=4).map(|i| (format!("m{i}"), format!("old {i}"), None, false, false)).collect::<Vec<_>>(),
        "build-42 history: plain text, no reply link, no edit marker"
    );

    // The mark is part of the persisted state.
    let mut again = mock.engine("bob", "b1");
    assert_eq!(again.load_state(&bob.export_state()), LoadOutcome::Restored);
    assert_eq!(again.b45, bob.b45);
}

/// M2 (c): once a sender device has been seen writing v3 in a channel, a build-42 body that its
/// own signed sender-key counter places AFTER that is refused — for good, with no placeholder
/// and nobody asked to send it again — while its genuinely older v2 messages stay readable.
/// The marker survives a restart, and a state from before it existed loads.
#[tokio::test]
async fn a_build_42_body_sealed_after_its_sender_moved_to_v3_is_refused() {
    let mut alice = engine("alice", "a1");
    let a = addr("alice", "a1");
    let rows = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let served = rows.clone();
    let mock = Mock::start(move |_, path| match path.starts_with("/api/channels/c/messages") {
        true => (200, serde_json::json!({ "messages": served.lock().unwrap().clone() })),
        false => (200, serde_json::json!({})),
    });
    let mut bob = mock.engine("bob", "b1");
    hand_key(&mut alice, &mut bob, "c").await;
    let early = wire_v2(&mut alice, "c", "before the update"); // the first message on the chain
    let v3 = B64.decode(alice.channel_ciphertext("c", "m1", None, false, "after the update").unwrap()).unwrap();
    let late = wire_v2(&mut alice, "c", "sealed after v3"); // a later iteration on the same chain
    *rows.lock().unwrap() = vec![channel_row("x1", 9, &late)];
    bob.acct.first_key_at.insert("channel:c|alice".into(), 0); // (so an unreadable row WOULD get a placeholder)

    assert_eq!(bob.open_channel_message("channel:c", &a, &v3).unwrap().text, "after the update");
    // Through the page fetch: no row, no placeholder, nothing asked for again.
    mock.take();
    let page = bob.channel_page("c", "bob", PageCursor::Before(i64::MAX)).await.unwrap();
    assert_eq!((page.rows, page.messages.len()), (1, 0), "refused, and not replaced by a placeholder");
    assert!(mock.take().iter().all(|(method, _)| method == "GET"), "nobody is asked to send it again");

    // Persisted: after a restart the older v2 is still read, and a later one still refused.
    let later = wire_v2(&mut alice, "c", "another one after v3");
    let mut again = mock.engine("bob", "b1");
    assert_eq!(again.load_state(&bob.export_state()), LoadOutcome::Restored);
    assert!(matches!(again.open_channel_message("channel:c", &a, &later), Err(EngineError::Protocol(why)) if why == V2_AFTER_V3));
    let pt = again.open_channel_message("channel:c", &a, &early).unwrap();
    assert_eq!((pt.text.as_str(), pt.meta), ("before the update", None), "sealed before the first v3: history");

    // A sender key announced AFTER the device was seen on v3 never carries build-42 bodies.
    alice.create_group_session("channel:c").unwrap();
    hand_key(&mut alice, &mut again, "c").await;
    let fresh_chain = wire_v2(&mut alice, "c", "v2 under a new key");
    assert!(matches!(again.open_channel_message("channel:c", &a, &fresh_chain), Err(EngineError::Protocol(why)) if why == V2_AFTER_V3));
    // …and v3 under it is read as ever.
    let ok = B64.decode(alice.channel_ciphertext("c", "m2", None, false, "fine").unwrap()).unwrap();
    assert_eq!(again.open_channel_message("channel:c", &a, &ok).unwrap().text, "fine");

    // Another device of the same person is judged by its own record: one that has only ever
    // written v2 is not held to alice's phone having moved on.
    let mut tablet = engine("alice", "a2");
    hand_key(&mut tablet, &mut again, "c").await;
    let from_tablet = wire_v2(&mut tablet, "c", "old build on the tablet");
    assert_eq!(again.open_channel_message("channel:c", &addr("alice", "a2"), &from_tablet).unwrap().text, "old build on the tablet");

    // A build-44 state has no such section: it loads, with nobody marked.
    let state = again.export_state();
    let section = 5 + postcard::to_stdvec(&again.b45_for_export()).unwrap().len();
    let content = super::content::ContentExt { dm_ops: again.dm_ops.clone(), reports: again.reports.clone() };
    let after = 5 + postcard::to_stdvec(&again.acct).unwrap().len() + 5 + postcard::to_stdvec(&content).unwrap().len();
    let at = state.len() - after - section;
    assert_eq!(state[at], SECTION_BUILD45);
    let mut old = state[..at].to_vec();
    old.extend_from_slice(&state[at + section..]);
    let mut older = engine("bob", "b1");
    assert_eq!(older.load_state(&old), LoadOutcome::Restored);
    assert_eq!(older.b45, Build45Ext::default());
}

/// Reactions: the server sees a keyed tag, not the emoji; equal emoji on ONE message give equal
/// tags (so it can count them), and the same emoji on another message or another server gives
/// an unrelated tag (so it cannot guess the emoji by how often a tag turns up).
#[test]
fn reaction_tags_hide_the_emoji_and_do_not_repeat_across_messages() {
    let (k1, k2) = ([1u8; 32], [2u8; 32]);
    let t = Engine::reaction_tag(&k1, "m1", "🔥");
    assert_eq!(t.len(), 64);
    assert!(!t.contains("🔥"));
    assert_eq!(t, Engine::reaction_tag(&k1, "m1", "🔥"));
    assert_ne!(t, Engine::reaction_tag(&k1, "m1", "👍"));
    assert_ne!(t, Engine::reaction_tag(&k1, "m2", "🔥"), "the same emoji on another message");
    assert_ne!(t, Engine::reaction_tag(&k2, "m1", "🔥"));
    assert_ne!(Engine::reaction_tag(&k1, "a|b", "c"), Engine::reaction_tag(&k1, "a", "b|c"), "the id cannot run into the emoji");
}

/// Engine M3: a reaction is what its author sealed, for that message, under that author's name.
/// The server cannot invent one (a tag that IS the emoji used to be shown as such), attribute a
/// real one to someone else, or move it to another message.
#[test]
fn a_reaction_row_is_shown_only_as_its_author_sealed_it() {
    let key = [5u8; 32];
    let seal = |message: &str, user: &str, emoji: &str| {
        let sealed = skwod_crypto::aead::seal(&key, format!("skwod/reaction-v2|{}|{message}|{user}", message.len()).as_bytes(), emoji.as_bytes());
        (Engine::reaction_tag(&key, message, emoji), B64.encode(sealed))
    };
    let (tag, sealed) = seal("m1", "bob", "🔥");
    assert_eq!(Engine::open_reaction(Some(&key), "m1", "bob", &tag, Some(&sealed)).as_deref(), Some("🔥"));
    // The server's own word: a raw emoji as the "tag", with or without a ciphertext.
    assert_eq!(Engine::open_reaction(Some(&key), "m1", "bob", "💩", None), None);
    assert_eq!(Engine::open_reaction(Some(&key), "m1", "bob", "💩", Some(&sealed)), None);
    assert_eq!(Engine::open_reaction(Some(&key), "m1", "bob", &tag, None), None, "a bare tag is not a reaction");
    // Bob's sealed reaction shown as alice's, or on another message.
    assert_eq!(Engine::open_reaction(Some(&key), "m1", "alice", &tag, Some(&sealed)), None, "re-attributed");
    assert_eq!(Engine::open_reaction(Some(&key), "m2", "bob", &tag, Some(&sealed)), None, "moved");
    assert_eq!(Engine::open_reaction(Some(&key), "m2", "bob", &Engine::reaction_tag(&key, "m2", "🔥"), Some(&sealed)), None);
    // A build-44 reaction (bound to the message only): no longer shown, since anyone's name fits it.
    let old = B64.encode(skwod_crypto::aead::seal(&key, b"skwod/reaction|m1", "🔥".as_bytes()));
    assert_eq!(Engine::open_reaction(Some(&key), "m1", "bob", &tag, Some(&old)), None);
    // Without the space key nothing opens.
    assert_eq!(Engine::open_reaction(None, "m1", "bob", &tag, Some(&sealed)), None);
}

// ---- flood caps (M5) ----

/// 20,000 sender-key distributions used to fill the table for good, after which nobody's new key
/// was accepted. Now one sender can only ever push out their own oldest keys.
#[tokio::test]
async fn sender_key_flood_cannot_lock_out_other_senders() {
    let mut me = engine("me", "m1");
    let mut mallory = engine("mallory", "x");
    let mut bob = engine("bob", "b1");
    hand_key(&mut bob, &mut me, "general").await;
    let bob_key = me.recv_keys.keys().next().unwrap().clone();
    pin(&mut me, &mallory.local().unwrap(), &mallory.store.identity_key());
    let local = me.local().unwrap();
    let m = mallory.local().unwrap();
    let mut first = None;
    for i in 0..(MAX_RECV_KEYS_PER_SENDER + 40) {
        let id = skwod_crypto::new_distribution_id();
        let skdm = mallory.store.create_distribution(&m, id).unwrap();
        // Mallory is a member, and these are channels of that server: the flood is a member's.
        me.channel_servers.insert(format!("flood-{i}"), "srv".into());
        me.rosters.entry("srv".into()).or_default().members.insert("mallory".into());
        let payload = Content::SenderKey { channel_id: format!("flood-{i}"), skdm }.encode().unwrap();
        me.handle_content(&local, m.clone(), &payload, 0).await;
        first.get_or_insert(id.to_string());
    }
    let of_mallory = me.recv_keys.values().filter(|r| r.sender.user_id == "mallory").count();
    assert_eq!(of_mallory, MAX_RECV_KEYS_PER_SENDER, "per-sender cap");
    assert!(!me.recv_keys.contains_key(&first.unwrap()), "the flooder's OLDEST key was evicted");
    assert!(me.recv_keys.contains_key(&bob_key), "someone else's key was evicted by the flood");
    assert_eq!(me.recv_order.len(), me.recv_keys.len());
    // A new key from anyone is still accepted — including the flooder's next (legitimate) one.
    let mut carol = engine("carol", "c1");
    hand_key(&mut carol, &mut me, "general").await;
    let text = wire(&mut carol, "general", "still works");
    assert_eq!(me.group_decrypt("channel:general", &addr("carol", "c1"), &text).unwrap(), b"still works");
    hand_key(&mut mallory, &mut me, "general").await;
    let text = wire(&mut mallory, "general", "latest");
    assert_eq!(me.group_decrypt("channel:general", &m, &text).unwrap(), b"latest");
}

/// Bogus VoiceKey call ids used to create call entries and, at eight, evict the live call's keys.
#[tokio::test]
async fn bogus_voice_keys_cannot_evict_the_live_call() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    let bob = pin_fresh(&mut me, "bob", "b1");
    let mallory = pin_fresh(&mut me, "mallory", "x");
    let vk = |call: &str, index: u32, byte: u8| Content::VoiceKey { channel_id: "v".into(), call_id: call.into(), index, key: vec![byte; 32] }.encode().unwrap();
    // We are in call RM_live with bob.
    let own_key = me.voice_call("v", "RM_live").own_key.clone();
    me.handle_content(&local, bob.clone(), &vk("RM_live", 0, 7), 0).await;
    for i in 0..50 {
        me.handle_content(&local, mallory.clone(), &vk(&format!("RM_bogus_{i}"), 0, 1), 0).await;
    }
    assert_eq!(me.voice.len(), 1, "a key for a call we are not in created a call entry");
    let live = me.voice_call("v", "RM_live");
    assert_eq!((live.own_key.clone(), live.peers["bob"][&0].clone()), (own_key, vec![7; 32]), "the live call's keys were evicted");
    assert_eq!(me.pending_voice.len(), MAX_PENDING_VOICE_PER_SENDER, "bounded per sender");
    // A key that arrives just before we join its call is used once we do.
    me.handle_content(&local, bob.clone(), &vk("RM_next", 2, 9), 0).await;
    assert_eq!(me.voice_call("v", "RM_next").peers["bob"][&2], vec![9; 32]);
    assert!(me.pending_voice.iter().all(|p| p.2 != "RM_next"));
}

/// The instance owner is taken only from an attestation signed by the PINNED instance key, and
/// that signature is not interchangeable with a server-owner attestation.
#[test]
fn instance_owner_needs_the_pinned_instance_key() {
    use super::trust::check_instance_owner;
    let (secret, public) = skwod_crypto::instance::generate();
    let (other_secret, _) = skwod_crypto::instance::generate();
    let sign = |key: &[u8], msg: &[u8]| B64.encode(skwod_crypto::instance::sign(key, msg).unwrap());
    let good = serde_json::json!({ "owner_id": "host", "signature": sign(&secret, &skwod_crypto::instance::instance_owner_message("host")) });
    assert_eq!(check_instance_owner(&public, &good).as_deref(), Some("host"));
    let forged = serde_json::json!({ "owner_id": "host", "signature": sign(&other_secret, &skwod_crypto::instance::instance_owner_message("host")) });
    assert_eq!(check_instance_owner(&public, &forged), None, "signed by another instance");
    let renamed = serde_json::json!({ "owner_id": "mallory", "signature": good["signature"] });
    assert_eq!(check_instance_owner(&public, &renamed), None, "names someone the signature does not cover");
    let server_level = serde_json::json!({ "owner_id": "host", "signature": sign(&secret, &skwod_crypto::instance::owner_attestation_message("", "host").unwrap()) });
    assert_eq!(check_instance_owner(&public, &server_level), None, "a server-owner attestation is not an instance-owner one");
    assert_eq!(check_instance_owner(&public, &serde_json::json!({ "owner_id": "", "signature": "" })), None);
}

/// Why a device left decides whether its identity may come back by itself. A sibling that
/// erased itself — CORROBORATED by the server's record — may; one that one of our devices
/// REMOVED never does, whatever it claims and whenever the tombstone arrives.
#[test]
fn only_a_corroborated_self_erase_is_readmitted_and_a_removed_identity_never_is() {
    let key = || SignalStore::generate().identity_key();
    let b64 = |k: &[u8]| serde_json::json!(B64.encode(k));
    let own_listing = |listed: &[&Vec<u8>], erased: &[&Vec<u8>]| {
        (
            serde_json::Value::Array(listed.iter().map(|k| serde_json::json!({ "identity_key": b64(k) })).collect()),
            serde_json::Value::Array(erased.iter().map(|k| serde_json::json!({ "identity_key": b64(k) })).collect()),
        )
    };
    let mut e = engine("me", "d1");
    let (erased, removed, live, unknown) = (key(), key(), key(), key());
    e.acct.past_siblings.extend([erased.clone(), removed.clone(), live.clone()]);
    assert!(!e.may_readmit_sibling(&erased), "a sibling that merely disappeared is not taken back");

    // A claim alone does nothing…
    e.claim_self_erase("me", erased.clone());
    e.claim_self_erase("me", live.clone());
    assert!(!e.may_readmit_sibling(&erased), "an erase CLAIM is not an erase");
    // …not while the claiming device is still registered (a live device cannot make itself
    // "erased"), and not when the server has no record of the erase.
    let (devices, record) = own_listing(&[&erased, &live], &[&erased, &live]);
    e.confirm_erase_claims("me", &devices, &record, true);
    assert!(!e.may_readmit_sibling(&erased) && !e.may_readmit_sibling(&live), "still listed: ignored");
    let (devices, record) = own_listing(&[&live], &[]);
    e.confirm_erase_claims("me", &devices, &record, true);
    assert!(!e.may_readmit_sibling(&erased), "no erase on record: ignored");
    // Gone from the device list AND recorded as self-erased: now it counts. The live one never.
    let (devices, record) = own_listing(&[&live], &[&erased]);
    e.confirm_erase_claims("me", &devices, &record, true);
    assert!(e.may_readmit_sibling(&erased));
    assert!(!e.may_readmit_sibling(&live));
    assert!(!e.may_readmit_sibling(&unknown), "an identity that was never ours");

    // Removed is permanent: a later claim — even a "corroborated" one — changes nothing.
    e.tombstone(removed.clone());
    e.claim_self_erase("me", removed.clone());
    let (devices, record) = own_listing(&[], &[&removed]);
    e.confirm_erase_claims("me", &devices, &record, true);
    e.note_self_erased(removed.clone());
    assert!(!e.may_readmit_sibling(&removed));
    // A tombstone that arrives later (from the sibling that did the removing) wins too.
    e.tombstone(erased.clone());
    assert!(!e.may_readmit_sibling(&erased));

    // It survives a restart and travels in the backup.
    let mut again = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(again.load_state(&e.export_state()), LoadOutcome::Restored);
    assert!(again.acct.tombstones.contains(&removed) && !again.may_readmit_sibling(&removed));
    let backup = e.export_backup();
    let (_, tail) = postcard::take_from_bytes::<BackupState>(&backup).unwrap();
    let mut restored = engine("me", "d2");
    restored.siblings.insert("stolen".into(), removed.clone());
    restored.apply_backup_ext(tail);
    assert!(restored.acct.tombstones.contains(&removed), "the backup carries the tombstones");
    assert!(!restored.siblings.contains_key("stolen"), "a removed device is not a sibling of the restored one");
}

/// The tombstone list cannot be stuffed. Junk (not an identity key, or not a device of ours)
/// is not recorded at all; a tombstone's security effect applies whatever the state of the
/// list; and at the cap the OLDEST entry gives way — a new removal is never dropped.
#[test]
fn tombstones_cannot_be_crowded_out_and_their_effect_always_applies() {
    let key = || SignalStore::generate().identity_key();
    let mut e = engine("me", "d1");
    // Junk from a (compromised) sibling: wrong shape, and well-formed keys that were never ours.
    for junk in [vec![], vec![7u8; 33], vec![5u8; 64]] {
        e.tombstone(junk);
    }
    for _ in 0..50 {
        e.tombstone(key());
    }
    assert!(e.acct.tombstones.is_empty(), "nothing that was not a device of ours is recorded");

    // Fill the list to its cap with real past siblings.
    let cap = 1024;
    let mut first = Vec::new();
    for i in 0..cap {
        let k = key();
        if i == 0 {
            first = k.clone();
        }
        e.acct.past_siblings.insert(k.clone());
        e.tombstone(k);
    }
    assert_eq!(e.acct.tombstones.len(), cap);
    // One more real removal — of a device that had (corroboratedly) erased itself before.
    let stolen = key();
    e.acct.past_siblings.insert(stolen.clone());
    e.acct.erased_identities.insert(stolen.clone());
    assert!(e.may_readmit_sibling(&stolen));
    e.tombstone(stolen.clone());
    assert!(!e.may_readmit_sibling(&stolen), "the security effect applied with the list full");
    assert_eq!(e.acct.tombstones.len(), cap, "bounded");
    assert!(e.acct.tombstones.contains(&stolen), "the new removal is recorded");
    assert!(!e.acct.tombstones.contains(&first), "the oldest entry made room");
    // Even an identity that cannot be RECORDED loses re-admission.
    let odd = vec![9u8; 33];
    e.acct.erased_identities.insert(odd.clone());
    e.tombstone(odd.clone());
    assert!(!e.acct.erased_identities.contains(&odd));
}

/// The same rule for a CONTACT's devices: an identity we accepted for them, coming back under
/// a new device row with no link signature, is accepted only if that device told us it was
/// erasing itself. Otherwise it is unvouched: nothing is sent to it, and the user is told.
#[test]
fn a_contacts_returning_identity_is_accepted_only_after_a_self_erase() {
    let row = |device: &str, identity: &[u8]| trust::DirRow { device: device.to_string(), identity: identity.to_vec(), link: None };
    let identity = SignalStore::generate().identity_key();

    // Bob's device was removed by Bob (we never heard "I am erasing myself")…
    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("old", &identity)]);
    e.update_contact("bob", &[]);
    e.take_security_notices();
    // …and its identity turns up again under a new row.
    e.update_contact("bob", &[row("new", &identity)]);
    assert!(!e.contact_device_trusted(&addr("bob", "new")), "not trusted");
    assert_eq!(e.contact_status("bob"), (false, false, 0, 1), "held as unvouched");
    assert!(e.take_security_notices().iter().any(|n| n.kind == "unverified_contact_device" && n.device_id == "new"), "and flagged");

    // Bob's device erased ITSELF and said so; later Bob restores it.
    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("old", &identity)]);
    e.note_self_erased(identity.clone());
    e.update_contact("bob", &[]);
    e.take_security_notices();
    e.update_contact("bob", &[row("new", &identity)]);
    assert!(e.contact_device_trusted(&addr("bob", "new")), "the same device, back");
    assert!(e.take_security_notices().iter().any(|n| n.kind == "new_device" && n.device_id == "new"), "with a visible notice");

    // A CLAIM of self-erase from a device that is still listed counts for nothing: Bob then
    // removes that device, and its identity is not taken back.
    let b64 = |k: &[u8]| serde_json::json!(B64.encode(k));
    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("old", &identity)]);
    e.claim_self_erase("bob", identity.clone());
    e.confirm_erase_claims("bob", &serde_json::json!([{ "identity_key": b64(&identity) }]), &serde_json::json!([b64(&identity)]), false);
    assert!(!e.may_readmit_contact_identity("bob", &identity), "still listed: the claim is ignored");
    e.confirm_erase_claims("bob", &serde_json::json!([]), &serde_json::json!([]), false);
    assert!(!e.may_readmit_contact_identity("bob", &identity), "gone, but the server records no self-erase (it was removed)");
    e.update_contact("bob", &[]);
    e.update_contact("bob", &[row("new", &identity)]);
    assert!(!e.contact_device_trusted(&addr("bob", "new")));

    // And a removal Bob's device tells us about beats an erase that WAS corroborated.
    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("old", &identity)]);
    e.claim_self_erase("bob", identity.clone());
    e.confirm_erase_claims("bob", &serde_json::json!([]), &serde_json::json!([b64(&identity)]), false);
    assert!(e.may_readmit_contact_identity("bob", &identity));
    e.tombstone_contact_identity("bob", identity.clone());
    assert!(!e.may_readmit_contact_identity("bob", &identity), "removed by its owner: never re-admitted on its own word");
    e.claim_self_erase("bob", identity.clone());
    e.confirm_erase_claims("bob", &serde_json::json!([]), &serde_json::json!([b64(&identity)]), false);
    assert!(!e.may_readmit_contact_identity("bob", &identity));
    e.update_contact("bob", &[]);
    e.update_contact("bob", &[row("new", &identity)]);
    assert!(!e.contact_device_trusted(&addr("bob", "new")));
}

/// M6: the mailbox delivery key is a bearer capability every contact was handed. It is
/// replaced when someone who holds it should not (a member or a device removed) and at least
/// weekly — but not in a loop, and the bookkeeping survives a reload.
#[test]
fn the_delivery_key_is_rotated_on_membership_change_and_weekly() {
    use super::rest::{DeliveryRotation, DELIVERY_ROTATION_MIN_GAP_MS, DELIVERY_ROTATION_MS};
    let t0 = 1_800_000_000_000u64;
    // A state from a build that never rotated: due at once.
    assert!(DeliveryRotation::default().wanted(t0));
    let fresh = DeliveryRotation { rotated_at: t0, due_since: None };
    assert!(!fresh.wanted(t0 + DELIVERY_ROTATION_MS - 1), "nothing happened: not before a week");
    assert!(fresh.wanted(t0 + DELIVERY_ROTATION_MS), "weekly");
    let exposed = DeliveryRotation { rotated_at: t0, due_since: Some(t0 + 1) };
    assert!(!exposed.wanted(t0 + DELIVERY_ROTATION_MIN_GAP_MS - 1), "never twice in quick succession");
    assert!(exposed.wanted(t0 + DELIVERY_ROTATION_MIN_GAP_MS), "a membership change brings it forward");

    // What marks it: a member removed from a server, a contact's device removed.
    let mut e = engine("me", "d1");
    e.delivery = DeliveryRotation { rotated_at: now_ms(), due_since: None };
    e.member_removed("s1", "mallory");
    assert!(e.delivery.due_since.is_some(), "a removed member still holds the key");
    let first = e.delivery.due_since;
    e.member_removed("s1", "trudy");
    assert_eq!(e.delivery.due_since, first, "the first change since the last rotation is what counts");

    let mut e = engine("me", "d1");
    e.delivery = DeliveryRotation { rotated_at: now_ms(), due_since: None };
    let b1 = SignalStore::generate().identity_key();
    e.update_contact("bob", &[trust::DirRow { device: "b1".into(), identity: b1, link: None }]);
    assert!(e.delivery.due_since.is_none());
    e.update_contact("bob", &[]);
    assert!(e.delivery.due_since.is_some(), "a removed device still holds the key");

    // Persisted: a restart does not forget that a rotation is owed (or when the last one was).
    let mut again = engine("me", "d1");
    assert_eq!(again.load_state(&e.export_state()), LoadOutcome::Restored);
    assert_eq!(again.delivery, e.delivery);
    // A build-44 state (no such section) loads, and counts as never rotated.
    let state = e.export_state();
    let section = 5 + postcard::to_stdvec(&e.delivery).unwrap().len();
    // Layout: … | delivery | build 45 | accounts | content.
    let content = super::content::ContentExt { dm_ops: e.dm_ops.clone(), reports: e.reports.clone() };
    let after = 5 + postcard::to_stdvec(&e.b45_for_export()).unwrap().len() + 5 + postcard::to_stdvec(&e.acct).unwrap().len() + 5 + postcard::to_stdvec(&content).unwrap().len();
    let at = state.len() - after - section;
    assert_eq!(state[at], super::rest::SECTION_DELIVERY);
    let mut old = state[..at].to_vec();
    old.extend_from_slice(&state[at + section..]);
    let mut older = engine("me", "d1");
    assert_eq!(older.load_state(&old), LoadOutcome::Restored);
    assert_eq!(older.delivery, DeliveryRotation::default());
    assert!(older.delivery.wanted(now_ms()));
}

/// M5: a device seen removed is retired. Its key can no longer vouch for a new device (a thief
/// holding it, with the server's help, could otherwise add devices to the account for ever),
/// and the device does not come back by being listed again. That survives a reload. A device
/// linked the ordinary way — by a device that is still listed — still works.
#[test]
fn a_removed_device_no_longer_vouches() {
    let row = |device: &str, store: &SignalStore, link: Option<(&str, Vec<u8>)>| trust::DirRow {
        device: device.to_string(),
        identity: store.identity_key(),
        link: link.map(|(by, sig)| (by.to_string(), sig)),
    };
    let (b1, b2, b3, ghost) = (SignalStore::generate(), SignalStore::generate(), SignalStore::generate(), SignalStore::generate());
    let link = |by: &SignalStore, new: &SignalStore| by.sign_link("bob", &new.identity_key()).unwrap();

    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("b1", &b1, None)]);
    // A legitimately linked device is accepted.
    e.update_contact("bob", &[row("b1", &b1, None), row("b2", &b2, Some(("b1", link(&b1, &b2))))]);
    assert!(e.contact_device_trusted(&addr("bob", "b2")));
    // b1 links b3 while it is still listed, and is removed afterwards: the ordinary order.
    e.update_contact("bob", &[row("b1", &b1, None), row("b2", &b2, None), row("b3", &b3, Some(("b1", link(&b1, &b3))))]);
    assert!(e.contact_device_trusted(&addr("bob", "b3")), "linked by a listed device");
    e.update_contact("bob", &[row("b2", &b2, Some(("b1", link(&b1, &b2)))), row("b3", &b3, Some(("b1", link(&b1, &b3))))]);
    assert!(e.contact_device_trusted(&addr("bob", "b3")) && e.contact_device_trusted(&addr("bob", "b2")), "accepted devices stay accepted when their linker goes");
    assert!(!e.contact_device_trusted(&addr("bob", "b1")));
    e.take_security_notices();

    // From here b1 has been SEEN removed. Its key signs a ghost device; the server lists it.
    let with_ghost = |ghost_row: trust::DirRow| vec![row("b2", &b2, None), row("b3", &b3, None), ghost_row];
    e.update_contact("bob", &with_ghost(row("g", &ghost, Some(("b1", link(&b1, &ghost))))));
    assert!(!e.contact_device_trusted(&addr("bob", "g")), "a retired device vouches for nobody");
    assert_eq!(e.contact_status("bob"), (false, false, 2, 1), "the ghost is held as unvouched");
    assert!(e.take_security_notices().iter().any(|n| n.kind == "unverified_contact_device" && n.device_id == "g"));

    // Across a reload of the persisted state.
    let mut again = engine("me", "d1");
    assert_eq!(again.load_state(&e.export_state()), LoadOutcome::Restored);
    again.update_contact("bob", &[row("b2", &b2, None), row("b3", &b3, None)]);
    again.update_contact("bob", &with_ghost(row("g2", &ghost, Some(("b1", link(&b1, &ghost))))));
    assert!(!again.contact_device_trusted(&addr("bob", "g2")), "still retired after a reload");
    // The removed device itself, listed again under its old row: held, not silently taken back.
    again.update_contact("bob", &with_ghost(row("b1", &b1, None)));
    assert!(!again.contact_device_trusted(&addr("bob", "b1")), "a removed device does not return by being listed");
    assert_eq!(again.contact_status("bob").3, 1);
    // A live device still links new ones.
    again.update_contact("bob", &with_ghost(row("b4", &ghost, Some(("b3", link(&b3, &ghost))))));
    assert!(again.contact_device_trusted(&addr("bob", "b4")));

    // A removal Bob's own device told us about retires the key even while the server goes on
    // listing the device.
    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("b1", &b1, None), row("b2", &b2, Some(("b1", link(&b1, &b2))))]);
    e.tombstone_contact_identity("bob", b1.identity_key());
    e.update_contact("bob", &[row("b1", &b1, None), row("b2", &b2, None), row("g", &ghost, Some(("b1", link(&b1, &ghost))))]);
    assert!(!e.contact_device_trusted(&addr("bob", "g")), "removed by its owner: its links count for nothing");
}

/// M5, the colluding host: a contact's old device vanishes from the listing and, IN THE SAME
/// listing, a new device appears carrying a (genuine) link signature from it — what a server
/// working with whoever holds the old device's key would serve. "Absent from this listing" is
/// "removed": the signature of a device that is gone admits nobody, and the newcomer is held
/// and flagged. A live device's link still works in that same listing.
#[test]
fn a_device_that_vanishes_cannot_vouch_for_one_that_appears_with_it() {
    let row = |device: &str, store: &SignalStore, link: Option<(&str, Vec<u8>)>| trust::DirRow {
        device: device.to_string(),
        identity: store.identity_key(),
        link: link.map(|(by, sig)| (by.to_string(), sig)),
    };
    let (b1, b2, evil, b3) = (SignalStore::generate(), SignalStore::generate(), SignalStore::generate(), SignalStore::generate());
    let link = |by: &SignalStore, new: &SignalStore| by.sign_link("bob", &new.identity_key()).unwrap();

    // The only device vanishes and its "successor" appears.
    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("b1", &b1, None)]);
    e.take_security_notices();
    e.update_contact("bob", &[row("x", &evil, Some(("b1", link(&b1, &evil))))]);
    assert!(!e.contact_device_trusted(&addr("bob", "x")), "signed by a device that is gone: not accepted");
    let status = e.contact_status("bob");
    assert_eq!((status.2, status.3), (0, 1), "nothing of bob's is live; the newcomer is held");
    assert!(e.take_security_notices().iter().any(|n| n.kind == "unverified_contact_device" && n.device_id == "x"));
    // Listing the vanished device again afterwards does not rescue the link either.
    e.update_contact("bob", &[row("b1", &b1, None), row("x", &evil, Some(("b1", link(&b1, &evil))))]);
    assert!(!e.contact_device_trusted(&addr("bob", "x")) && !e.contact_device_trusted(&addr("bob", "b1")));

    // One of two devices vanishes: the other stays, its own links count, the vanished one's do not.
    let mut e = engine("me", "d1");
    e.update_contact("bob", &[row("b1", &b1, None), row("b2", &b2, Some(("b1", link(&b1, &b2))))]);
    e.update_contact("bob", &[row("b2", &b2, None), row("x", &evil, Some(("b1", link(&b1, &evil)))), row("b3", &b3, Some(("b2", link(&b2, &b3))))]);
    assert!(!e.contact_device_trusted(&addr("bob", "x")));
    assert!(e.contact_device_trusted(&addr("bob", "b2")) && e.contact_device_trusted(&addr("bob", "b3")), "a device that is still there links as before");
    // A chain through the held device goes nowhere.
    let mut e2 = engine("me", "d1");
    e2.update_contact("bob", &[row("b1", &b1, None)]);
    e2.update_contact("bob", &[row("x", &evil, Some(("b1", link(&b1, &evil)))), row("y", &b3, Some(("x", link(&evil, &b3))))]);
    assert!(!e2.contact_device_trusted(&addr("bob", "x")) && !e2.contact_device_trusted(&addr("bob", "y")));
}

/// THE INVARIANT under every pairwise send: reaching no recipient device is an error the app
/// sees, never `Ok` with nobody reached. In particular after a contact replaced their phone
/// and the new one is held (M5): the send is refused with `IdentityChanged` — "their devices
/// changed, look" — for a contact the user never verified just as for a verified one.
#[tokio::test]
async fn a_send_that_reaches_no_recipient_device_is_always_an_error() {
    let row = |device: &str, store: &SignalStore, link: Option<(&str, Vec<u8>)>| serde_json::json!({
        "user_id": "bob", "device_id": device, "delivery_key": B64.encode([5u8; 32]), "identity_key": B64.encode(store.identity_key()),
        "linked_by": link.as_ref().map(|(by, _)| by.to_string()), "link_sig": link.as_ref().map(|(_, sig)| B64.encode(sig)),
    });
    let (b1, b2) = (SignalStore::generate(), SignalStore::generate());
    let listing = std::sync::Arc::new(std::sync::Mutex::new(vec![row("b1", &b1, None)]));
    let served = listing.clone();
    let mock = Mock::start(move |_, path| match path {
        "/api/e2ee/users/bob/devices" => (200, serde_json::json!({ "devices": served.lock().unwrap().clone() })),
        "/api/e2ee/users/nobody/devices" => (200, serde_json::json!({ "devices": [] })),
        _ => (200, serde_json::json!({})),
    });
    let mut me = mock.engine("me", "d1");
    let chat = Content::Chat { conversation_id: "c".into(), message_id: "m".into(), text: "hi".into(), sent_at: 1, sync_peer: None };

    // Nobody to send to.
    assert!(matches!(me.send_content(&[], &chat).await, Err(EngineError::Protocol(why)) if why == NO_RECIPIENT));
    // (Its own conversation: a conversation is bound to the people it was first used with.)
    assert!(matches!(me.send_dm_as("c-nobody", &["nobody".to_string()], "m0", "hi", None).await, Err(EngineError::Protocol(_))));
    // (A sync copy to our own devices, none of them a verified sibling yet, is not a send to
    // a recipient: nothing goes out and nothing is claimed.)
    assert!(me.send_content(&[addr("me", "d2")], &chat).await.is_ok_and(|reached| reached.is_empty()));

    // Bob is pinned with one phone. He links a new one and removes the old; we only look now.
    me.fetch_devices("bob").await.unwrap();
    me.take_security_notices();
    *listing.lock().unwrap() = vec![row("b2", &b2, Some(("b1", b1.sign_link("bob", &b2.identity_key()).unwrap())))];
    // Never verified by us — and still not a silent success: refused, with the reason.
    assert!(!me.is_verified(&addr("bob", "b1")));
    let err = me.send_dm_as("c", &["bob".to_string()], "m1", "are you there?", None).await.unwrap_err();
    assert!(matches!(&err, EngineError::IdentityChanged(user) if user == "bob"), "{err:?}");
    assert!(me.take_security_notices().iter().any(|n| n.kind == "unverified_contact_device" && n.device_id == "b2"), "and the user is shown why");
    assert_eq!(me.contact_status("bob").3, 1);
    // The same from the layer below, whatever path gets there: a device that is not vouched
    // for is never a quiet no-op.
    assert!(matches!(me.send_content(&[addr("bob", "b2")], &chat).await, Err(EngineError::IdentityChanged(_))));
    assert!(matches!(me.send_content(&[addr("bob", "b1")], &chat).await, Err(EngineError::IdentityChanged(_))), "the removed phone is no recipient either");
    // Other pairwise paths: a provision for someone whose devices are all held hands over
    // nothing and says so (it used to count as done).
    me.spaces.insert("s1".into(), [9; 32]);
    me.rosters.entry("s1".into()).or_default().members.insert("bob".into());
    assert!(me.provision_member("s1", &addr("bob", "b2")).await.is_err());
}

/// M6: leaving a server, or being removed from one, replaces the delivery key — everyone in
/// that server was handed it. Found from the server's list of our servers (the apps leave
/// over plain REST; a removal happens elsewhere).
#[tokio::test]
async fn the_delivery_key_is_rotated_when_we_leave_or_are_removed_from_a_server() {
    use super::rest::{DeliveryRotation, DELIVERY_ROTATION_MIN_GAP_MS};
    let listed = std::sync::Arc::new(std::sync::Mutex::new(Some(vec!["s1", "s2"])));
    let served = listed.clone();
    let mock = Mock::start(move |_, path| match (path, served.lock().unwrap().clone()) {
        ("/api/servers", Some(ids)) => (200, serde_json::json!({ "servers": ids.iter().map(|id| serde_json::json!({ "server_id": id })).collect::<Vec<_>>() })),
        ("/api/servers", None) => (500, serde_json::json!({ "error": "down" })),
        // Stocked with prekeys: only the delivery key is in play here.
        (p, _) if p.starts_with("/api/e2ee/prekeys/count") => (200, serde_json::json!({ "remaining": 100, "kyber_remaining": 100 })),
        _ => (200, serde_json::json!({})),
    });
    let rotations = |mock: &Mock| mock.take().iter().filter(|(m, p)| m == "PUT" && p.ends_with("/delivery-key")).count();
    let settled = || DeliveryRotation { rotated_at: now_ms() - DELIVERY_ROTATION_MIN_GAP_MS - 1, due_since: None };
    let pass = |e: &mut Engine| {
        e.servers_checked = None;
        e.last_maintenance = Some(Instant::now()); // (prekey upkeep is not what is being looked at)
    };

    // We LEAVE one of two servers.
    let mut e = mock.engine("me", "d1");
    e.delivery = settled();
    let before = e.delivery_key;
    pass(&mut e);
    e.maintain_keys().await.unwrap();
    assert_eq!(rotations(&mock), 0, "the first listing is a baseline");
    assert_eq!(e.b45.servers.as_ref().map(|s| s.len()), Some(2));
    pass(&mut e);
    e.maintain_keys().await.unwrap();
    assert_eq!(rotations(&mock), 0, "nothing changed");
    *listed.lock().unwrap() = None;
    pass(&mut e);
    e.maintain_keys().await.unwrap();
    assert_eq!(rotations(&mock), 0, "a list that cannot be read is not 'left everything'");
    assert_eq!(e.b45.servers.as_ref().map(|s| s.len()), Some(2));
    *listed.lock().unwrap() = Some(vec!["s2"]);
    pass(&mut e);
    e.maintain_keys().await.unwrap();
    assert_eq!(rotations(&mock), 1, "left s1: the key its members hold is replaced");
    assert_ne!(e.delivery_key, before);
    assert!(e.delivery.due_since.is_none());
    // What we remember survives a restart, so a change made while the app was closed counts.
    let mut again = mock.engine("me", "d1");
    assert_eq!(again.load_state(&e.export_state()), LoadOutcome::Restored);
    assert_eq!(again.b45.servers, e.b45.servers);

    // We are REMOVED from the only server we were in (the account is back in the waiting
    // room, where the list is still served — empty — and the rotation is still allowed).
    again.delivery = settled();
    *listed.lock().unwrap() = Some(vec![]);
    let before = again.delivery_key;
    pass(&mut again);
    again.maintain_keys().await.unwrap();
    assert_eq!(rotations(&mock), 1, "removed from our last server");
    assert_ne!(again.delivery_key, before);
    // Joining one is not a reason.
    again.delivery = settled();
    *listed.lock().unwrap() = Some(vec!["s3"]);
    pass(&mut again);
    again.maintain_keys().await.unwrap();
    assert_eq!(rotations(&mock), 0);
    // Too soon after the last replacement: owed, and made when the gap has passed.
    *listed.lock().unwrap() = Some(vec![]);
    again.delivery = DeliveryRotation { rotated_at: now_ms(), due_since: None };
    pass(&mut again);
    again.maintain_keys().await.unwrap();
    assert_eq!(rotations(&mock), 0);
    assert!(again.delivery.due_since.is_some());
}

/// The notification extension never creates, rotates or uploads a key (docs/PUSH.md). With
/// everything due at once — delivery key never rotated, no prekeys on the server, a provision
/// request waiting — the ordinary sync writes keys (the control) and the extension's writes
/// nothing at all: it only reads. The provision request it could not act on is kept for the app.
#[tokio::test]
async fn the_notification_extension_path_writes_no_keys() {
    let mock = Mock::start(|_, path| match path {
        p if p.starts_with("/api/e2ee/sealed/inbox") => (200, serde_json::json!({ "envelopes": [], "more": false })),
        "/api/servers" => (200, serde_json::json!({ "servers": [{ "server_id": "s1" }] })),
        p if p.starts_with("/api/servers/s1/members") => (200, serde_json::json!({ "members": [{ "user_id": "bob", "username": "bob" }] })),
        _ => (200, serde_json::json!({})),
    });
    let due = |mock: &Mock| {
        let mut e = mock.engine("me", "d1");
        e.trust_root = Some(vec![1; 33]); // pinned earlier; no envelope is opened here
        e.acct.install_secret = Some([7; 32]);
        e.spaces.insert("s1".into(), [9; 32]);
        e.rosters.entry("s1".into()).or_default().members.insert("bob".into());
        e.prov_queue.push((addr("bob", "b1"), "s1".into()));
        assert!(e.delivery.wanted(now_ms()) && e.last_maintenance.is_none());
        e
    };
    let key_writes = |seen: &[(String, String)]| seen.iter().filter(|(m, p)| m != "GET" && (p.contains("/delivery-key") || p.contains("/prekeys/") || p.contains("/spk/") || p.contains("/devices/register"))).count();

    // Control: the app's sync, on the same server and state, does write keys.
    let mut app = due(&mock);
    app.process_control_inbox("me").await.unwrap();
    let seen = mock.take();
    assert!(seen.iter().any(|(m, p)| m == "PUT" && p.ends_with("/delivery-key")), "{seen:?}");
    assert!(seen.iter().any(|(m, p)| m == "POST" && p == "/api/e2ee/prekeys/replenish"), "{seen:?}");
    assert!(key_writes(&seen) >= 2);
    assert!(app.prov_queue.is_empty() && app.b45.deferred_provisions.is_empty(), "the app acted on the request");

    // The extension.
    let mut nse = due(&mock);
    let (delivery_key, store) = (nse.delivery_key, nse.store.to_bytes());
    nse.process_inbox_passive().await.unwrap();
    // …and what it calls next: the channel fetch (which syncs the mailbox again) and, were
    // it ever to, the maintenance entry points themselves.
    let _ = nse.fetch_channel_messages("c", "me").await;
    nse.maintain_keys().await.unwrap();
    let _ = nse.process_control_inbox("me").await;
    assert!(!nse.rotate_delivery_key().await);
    assert!(nse.create_group_session("channel:c").is_err() && nse.ensure_send_key("channel:c").is_err(), "no sender key is minted");
    assert!(nse.register().await.is_err());
    let seen = mock.take();
    assert!(seen.iter().any(|(_, p)| p.starts_with("/api/e2ee/sealed/inbox")), "it did sync the mailbox: {seen:?}");
    assert!(seen.iter().all(|(m, _)| m == "GET"), "the extension only reads: {seen:?}");
    assert_eq!(nse.delivery_key, delivery_key);
    assert_eq!(nse.store.to_bytes(), store, "no key was generated locally either");
    assert!(nse.send_keys.is_empty());

    // The provision request is kept — across the hand-over to the app — and fulfilled there.
    assert_eq!(nse.b45.deferred_provisions, vec![(addr("bob", "b1"), "s1".to_string())]);
    let mut back = mock.engine("me", "d1");
    assert_eq!(back.load_state(&nse.export_state()), LoadOutcome::Restored);
    assert_eq!(back.b45.deferred_provisions.len(), 1);
    assert!(!back.passive, "the mode is the process's, not the state's");
    back.trust_root = Some(vec![1; 33]);
    let _ = back.sync_inbox().await;
    assert!(back.b45.deferred_provisions.is_empty(), "taken up by the app");
    assert!(mock.take().iter().any(|(_, p)| p.starts_with("/api/servers/s1/members")), "…which checks membership and provisions");

    // An install the app has not bound yet has no install secret; the extension makes none.
    let mut unbound = Engine::new(ApiClient::new(mock.base.clone()).with_token("t"));
    unbound.user_id = Some("me".into());
    unbound.device_id = Some("d1".into());
    unbound.trust_root = Some(vec![1; 33]);
    assert!(unbound.process_inbox_passive().await.is_err());
    assert!(unbound.acct.install_secret.is_none());
    assert!(mock.take().iter().all(|(m, _)| m == "GET"));
}

/// Security review, build 44: an erase claim belongs to the account that made it. Contact B's
/// server record must not be able to "confirm" a claim about contact A's identity — and our own
/// account's record must not confirm a contact's claim, nor the other way round.
#[test]
fn an_erase_claim_is_confirmed_only_by_the_record_of_the_account_that_made_it() {
    let key = || SignalStore::generate().identity_key();
    let b64 = |k: &[u8]| serde_json::json!(B64.encode(k));
    let none = serde_json::json!([]);
    let alice_key = key();
    let mut e = engine("me", "d1");
    e.claim_self_erase("alice", alice_key.clone());

    // Bob's listing names Alice's identity as self-erased (Bob's server record is whatever
    // Bob — or a server acting for him — makes it): nothing of Alice's is confirmed by it.
    e.confirm_erase_claims("bob", &none, &serde_json::json!([b64(&alice_key)]), false);
    assert!(!e.may_readmit_contact_identity("alice", &alice_key), "another contact's record confirms nothing");
    assert_eq!(e.acct.erase_claims, vec![("alice".to_string(), alice_key.clone())], "the claim is still only a claim");
    // Nor does our OWN account's record.
    e.confirm_erase_claims("me", &none, &serde_json::json!([{ "identity_key": b64(&alice_key) }]), true);
    assert!(!e.may_readmit_contact_identity("alice", &alice_key));
    // Alice's own record does.
    e.confirm_erase_claims("alice", &none, &serde_json::json!([b64(&alice_key)]), false);
    assert!(e.may_readmit_contact_identity("alice", &alice_key));
    assert!(e.acct.erase_claims.is_empty());

    // The same identity claimed under two accounts: each claim stands alone.
    let mut e = engine("me", "d1");
    let shared = key();
    e.claim_self_erase("alice", shared.clone());
    e.claim_self_erase("bob", shared.clone());
    e.claim_self_erase("bob", shared.clone());
    assert_eq!(e.acct.erase_claims.len(), 2, "one claim per (account, identity)");
    // Bob is still listed with it; Alice's record corroborates hers.
    e.confirm_erase_claims("bob", &serde_json::json!([{ "identity_key": b64(&shared) }]), &serde_json::json!([b64(&shared)]), false);
    assert!(!e.may_readmit_contact_identity("bob", &shared));
    assert_eq!(e.acct.erase_claims.len(), 2);

    // One account cannot crowd out another's claims.
    let mut e = engine("me", "d1");
    e.claim_self_erase("alice", alice_key.clone());
    for _ in 0..200 {
        e.claim_self_erase("mallory", key());
    }
    assert!(e.acct.erase_claims.iter().filter(|(u, _)| u == "mallory").count() <= 16);
    assert!(e.acct.erase_claims.contains(&("alice".to_string(), alice_key.clone())));

    // The persisted section round-trips the claimant.
    let bytes = e.export_state();
    let mut again = engine("me", "d1");
    assert_eq!(again.load_state(&bytes), LoadOutcome::Restored);
    assert!(again.acct.erase_claims.contains(&("alice".to_string(), alice_key)));
}

/// Security review, build 44: removal tombstones are kept per contact. One contact flooding
/// its own set cannot evict another contact's removals (which would let a removed device be
/// taken back), and whatever cannot be recorded is denied by default.
#[test]
fn a_contact_cannot_crowd_out_another_contacts_tombstones() {
    let key = || SignalStore::generate().identity_key();
    let b64 = |k: &[u8]| serde_json::json!(B64.encode(k));
    let none = serde_json::json!([]);
    let mut e = engine("me", "d1");

    // Alice removed a device.
    let alice_removed = key();
    e.tombstone_contact_identity("alice", alice_removed.clone());

    // Mallory sends far more "removals" than any account has devices.
    let mut mallory_keys = Vec::new();
    for _ in 0..300 {
        let k = key();
        e.tombstone_contact_identity("mallory", k.clone());
        mallory_keys.push(k);
    }
    assert!(e.acct.contact_tombstones["mallory"].len() <= 64, "each contact's set is capped by itself");
    assert!(e.acct.contact_tombstones["alice"].contains(&alice_removed), "Alice's removal is still on record");

    // Alice's removed device claims an erase, and even a corroborating record does not bring
    // it back.
    e.claim_self_erase("alice", alice_removed.clone());
    e.confirm_erase_claims("alice", &none, &serde_json::json!([b64(&alice_removed)]), false);
    e.note_self_erased(alice_removed.clone());
    assert!(!e.may_readmit_contact_identity("alice", &alice_removed));

    // Mallory's entries past the cap were refused, not recorded — so NOTHING of Mallory's is
    // re-admitted on its own word any more, including an identity that erased itself for real.
    let refused = mallory_keys.last().unwrap().clone();
    assert!(!e.acct.contact_tombstones["mallory"].contains(&refused));
    e.claim_self_erase("mallory", refused.clone());
    e.confirm_erase_claims("mallory", &none, &serde_json::json!([b64(&refused)]), false);
    assert!(!e.may_readmit_contact_identity("mallory", &refused), "a full set denies by default");
    // The first entries are all still there: a full set never evicts.
    assert!(e.acct.contact_tombstones["mallory"].contains(&mallory_keys[0]));

    // An unrelated contact is unaffected: a corroborated erase of Bob's is still accepted.
    let bob_key = key();
    e.claim_self_erase("bob", bob_key.clone());
    e.confirm_erase_claims("bob", &none, &serde_json::json!([b64(&bob_key)]), false);
    assert!(e.may_readmit_contact_identity("bob", &bob_key));

    // A removal always takes effect, whatever the state of the record.
    e.tombstone_contact_identity("bob", bob_key.clone());
    assert!(!e.may_readmit_contact_identity("bob", &bob_key));

    // When no more contacts can be recorded at all, a contact without a record is denied.
    let mut e = engine("me", "d1");
    for i in 0..8192 {
        e.acct.contact_tombstones.insert(format!("u{i}"), BTreeSet::new());
    }
    let (carol_removed, carol_erased) = (key(), key());
    e.tombstone_contact_identity("carol", carol_removed);
    assert!(e.acct.contact_tombstones_full && !e.acct.contact_tombstones.contains_key("carol"));
    e.claim_self_erase("carol", carol_erased.clone());
    e.confirm_erase_claims("carol", &none, &serde_json::json!([b64(&carol_erased)]), false);
    assert!(!e.may_readmit_contact_identity("carol", &carol_erased), "the record is incomplete: denied");

    // The per-contact record survives a save and a load.
    let mut e = engine("me", "d1");
    let k = key();
    e.tombstone_contact_identity("alice", k.clone());
    let bytes = e.export_state();
    let mut again = engine("me", "d1");
    assert_eq!(again.load_state(&bytes), LoadOutcome::Restored);
    assert!(again.acct.contact_tombstones["alice"].contains(&k));
}

/// Both build-44 state sections (accounts, content) are written, load back, and a section a
/// newer build added is skipped rather than failing the load.
#[test]
fn build_44_state_sections_round_trip_together() {
    let mut e = engine("me", "d1");
    e.acct.device_name = Some("Test Mac".into());
    e.dm_ops.push(super::content::DmOp {
        conversation_id: "c".into(),
        message_id: "m".into(),
        author_id: "bob".into(),
        peer_user_id: "bob".into(),
        kind: super::content::DmOpKind::Delete,
        received_at: 1,
    });
    let mut bytes = e.export_state();
    // A section from a build that does not exist yet.
    super::accounts::write_section(&mut bytes, 0x7F, b"from the future");
    let mut again = engine("x", "y");
    assert_eq!(again.load_state(&bytes), LoadOutcome::Restored);
    assert_eq!(again.acct.device_name.as_deref(), Some("Test Mac"));
    assert_eq!(again.dm_ops.len(), 1);
    assert_eq!(again.dm_ops[0].kind, super::content::DmOpKind::Delete);
    // A truncated tail is a damaged state, not a shorter one.
    assert_eq!(engine("x", "y").load_state(&bytes[..bytes.len() - 3]), LoadOutcome::Unreadable);
}

/// The wire tags of the build-44 `Content` variants: 44a's (accounts) follow build 43's, then
/// 44b's (content). Both batches were merged before either shipped; this pins the order so a
/// later reshuffle is caught.
#[test]
fn build_44_content_variants_keep_their_wire_tags() {
    let tag = |c: Content| postcard::to_stdvec(&c).unwrap()[0];
    let pins = tag(Content::OwnerPins { pins: Vec::new() });
    assert_eq!(tag(Content::RetryRequest { channel_id: None, ids: Vec::new() }), pins + 1);
    assert_eq!(tag(Content::ChatResend { retry_id: String::new(), conversation_id: String::new(), message_id: String::new(), text: String::new(), sent_at: 0, sync_peer: None, reply_to: None }), pins + 2);
    assert_eq!(tag(Content::ChannelResend { channel_id: String::new(), messages: Vec::new() }), pins + 3);
    assert_eq!(tag(Content::RetryNone { channel_id: None, ids: Vec::new(), lost: false }), pins + 4);
    assert_eq!(tag(Content::SiblingsAck), pins + 5);
    assert_eq!(tag(Content::AccountSync { account_key: [0; 32] }), pins + 6);
    assert_eq!(tag(Content::SelfErased), pins + 7);
    assert_eq!(tag(Content::Tombstones { identities: Vec::new() }), pins + 8);
    assert_eq!(tag(Content::DmReply { conversation_id: String::new(), message_id: String::new(), text: String::new(), sent_at: 0, reply_to: String::new(), sync_peer: None }), pins + 9);
    assert_eq!(tag(Content::DmEdit { conversation_id: String::new(), message_id: String::new(), text: String::new(), sync_peer: None }), pins + 10);
    assert_eq!(tag(Content::DmDelete { conversation_id: String::new(), message_id: String::new(), sync_peer: None }), pins + 11);
    assert_eq!(tag(Content::DmReaction { conversation_id: String::new(), message_id: String::new(), emoji: String::new(), remove: false, sync_peer: None }), pins + 12);
}

/// Where the two build-44 batches meet: a direct message that was a REPLY (44b) and could not
/// be decrypted is sent again (44a) as a reply — it takes the placeholder's place with its
/// quote intact, and only when it answers a request this device made of that very device.
#[tokio::test]
async fn a_reply_that_is_sent_again_keeps_what_it_quotes() {
    let mut alice = engine("alice", "a1");
    let bob = pin_fresh(&mut alice, "bob", "b1");
    let local = alice.local().unwrap();
    alice.dm_participants.insert("conv".into(), vec!["alice".into(), "bob".into()]);
    let resend = |retry_id: &str, reply_to: Option<&str>| {
        Content::ChatResend {
            retry_id: retry_id.into(),
            conversation_id: "conv".into(),
            message_id: "m2".into(),
            text: "yes, that one".into(),
            sent_at: 5,
            sync_peer: None,
            reply_to: reply_to.map(str::to_string),
        }
        .encode()
        .unwrap()
    };

    // Nobody asked: dropped.
    alice.handle_content(&local, bob.clone(), &resend("e1", Some("m1")), 10).await;
    assert!(alice.take_dm_ops().is_empty() && alice.take_dms().is_empty());

    // Asked of Bob's device: the reply arrives as a reply, and the placeholder is resolved.
    alice.acct.retry_asked.insert("env:e1".into(), super::accounts::RetryAsk { device: bob.clone(), at_ms: 7, scope: Some("dm:conv".into()) });
    alice.handle_content(&local, bob.clone(), &resend("e1", Some("m1")), 10).await;
    let ops = alice.take_dm_ops();
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].message_id, "m2");
    assert_eq!(ops[0].author_id, "bob");
    assert!(matches!(&ops[0].kind, DmOpKind::Reply { text, reply_to, .. } if text == "yes, that one" && reply_to == "m1"));
    assert!(alice.take_retry_events().contains(&RetryEvent::Resolved { scope: "dm:conv".into(), id: "retry:e1".into() }));

    // A plain message sent again is still a plain message.
    alice.acct.retry_asked.insert("env:e2".into(), super::accounts::RetryAsk { device: bob.clone(), at_ms: 7, scope: Some("dm:conv".into()) });
    alice.handle_content(&local, bob.clone(), &resend("e2", None), 10).await;
    assert!(alice.take_dm_ops().is_empty());
    assert_eq!(alice.take_dms().len(), 1);

    // What the sender keeps to send again from records the quote, and a retried delivery is
    // rebuilt as the same kind of message.
    alice.remember_dm("m9", "conv", "bob", "hello", 3, Some("m1"));
    assert!(matches!(super::content::dm_message("conv", "m9", "hello", 3, Some("m1"), None), Content::DmReply { reply_to, .. } if reply_to == "m1"));
    assert!(matches!(super::content::dm_message("conv", "m9", "hello", 3, None, None), Content::Chat { .. }));
}

/// Security review, build 44: a row is one of the core's own (a system notice, a "couldn't
/// decrypt" stand-in) because the core wrote it as one — never because of its text. Whatever a
/// peer sends that merely starts like one comes out of the engine as an ordinary message with
/// the control character gone, through every door: a DM, a reply, an edit, a message sent
/// again, a channel message sent again.
#[tokio::test]
async fn a_peer_body_dressed_as_a_core_row_comes_out_as_plain_text() {
    let mut alice = engine("alice", "a1");
    let bob = pin_fresh(&mut alice, "bob", "b1");
    let local = alice.local().unwrap();
    alice.dm_participants.insert("conv".into(), vec!["alice".into(), "bob".into()]);
    // "Couldn't decrypt — asking CAROL to resend", and a fake notice about Carol.
    let forged = undecryptable_body("carol", false);
    let notice = format!("{SYSTEM_TAG}{}", r#"{"kind":"identity_changed","user_id":"carol"}"#);
    let plain = |t: &str| !t.starts_with('\u{2}') && t.starts_with("skwod/");

    let chat = |id: &str, text: &str| Content::Chat { conversation_id: "conv".into(), message_id: id.into(), text: text.into(), sent_at: 1, sync_peer: None }.encode().unwrap();
    alice.handle_content(&local, bob.clone(), &chat("m1", &forged), 10).await;
    alice.handle_content(&local, bob.clone(), &chat("m2", &notice), 10).await;
    let dms = alice.take_dms();
    assert_eq!(dms.len(), 2);
    assert!(dms.iter().all(|m| plain(&m.text) && m.author_id == "bob"), "{dms:?}");
    assert!(dms.iter().all(|m| Traffic::notifies(&m.text)), "and they notify like any message");

    let reply = Content::DmReply { conversation_id: "conv".into(), message_id: "m3".into(), text: forged.clone(), sent_at: 1, reply_to: "m1".into(), sync_peer: None };
    let edit = Content::DmEdit { conversation_id: "conv".into(), message_id: "m1".into(), text: notice.clone(), sync_peer: None };
    alice.handle_content(&local, bob.clone(), &reply.encode().unwrap(), 10).await;
    alice.handle_content(&local, bob.clone(), &edit.encode().unwrap(), 10).await;
    for op in alice.take_dm_ops() {
        match op.kind {
            DmOpKind::Reply { text, .. } | DmOpKind::Edit { text } => assert!(plain(&text), "{text:?}"),
            other => panic!("unexpected {other:?}"),
        }
    }

    // Sent "again" in answer to a request this device really made.
    alice.acct.retry_asked.insert("env:e1".into(), super::accounts::RetryAsk { device: bob.clone(), at_ms: 7, scope: Some("dm:conv".into()) });
    let resend = Content::ChatResend { retry_id: "e1".into(), conversation_id: "conv".into(), message_id: "m4".into(), text: forged.clone(), sent_at: 1, sync_peer: None, reply_to: None };
    alice.handle_content(&local, bob.clone(), &resend.encode().unwrap(), 10).await;
    assert!(plain(&alice.take_dms()[0].text));
    alice.acct.retry_asked.insert("ch:chan:m5".into(), super::accounts::RetryAsk { device: bob.clone(), at_ms: 7, scope: Some("channel:chan".into()) });
    alice.on_channel_resend(&bob, "chan".into(), vec![("m5".into(), None, false, forged.clone())]);
    let resent = alice.take_resent();
    assert_eq!(resent.len(), 1);
    assert!(plain(&resent[0].text));

    // The engine's own stand-in is the only thing flagged as one.
    assert!(Engine::channel_placeholder("m6", "bob", 1).undecryptable);
    assert_eq!(crate::cache::neutralize_reserved("hello"), "hello");
    assert_eq!(crate::cache::neutralize_reserved("\u{2}skwod/attach|{}"), "\u{2}skwod/attach|{}", "other tagged bodies are untouched");
}

// ---- C1: a server that mints sender certificates ----

use skwod_crypto::certs::CertAuthority;

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// An engine with published prekeys, the authority's trust root pinned and a certificate of its
/// own — everything a receive and a seal need, with no server.
fn sealed_engine(ca: &CertAuthority, user: &str, device: &str) -> Engine {
    let mut e = engine(user, device);
    e.trust_root = Some(ca.trust_root_public.clone());
    let cert = ca.issue(&e.local().unwrap(), &e.store.identity_key(), now_ms() + DAY_MS).unwrap();
    e.cert = Some((cert, now_ms() + DAY_MS));
    e
}

/// What the key directory would serve for `store` (one fresh one-time key of each kind).
fn bundle_of(store: &mut SignalStore) -> PreKeyBundleData {
    PreKeyBundleData {
        registration_id: store.registration_id(),
        identity_key: store.identity_key(),
        signed_pre_key: store.generate_signed_prekey().unwrap(),
        kyber_pre_key: store.generate_one_time_kyber(1).unwrap().remove(0),
        pre_key: store.generate_one_time_prekeys(1).unwrap().pop(),
    }
}

/// `from` (holding `store`, certified under `cert_key`'s certificate by the authority) starts a
/// session to `to` and seals `content`. With `store` = the host's own and `from` = someone
/// else's address, this is the certificate-minting attack.
fn seal_first(ca: &CertAuthority, store: &mut SignalStore, from: &DeviceAddress, to: &mut Engine, content: &Content) -> Vec<u8> {
    let cert = ca.issue(from, &store.identity_key(), now_ms() + DAY_MS).unwrap();
    let to_addr = to.local().unwrap();
    let bundle = bundle_of(&mut to.store);
    store.process_bundle(from, &to_addr, &bundle).unwrap();
    store.sealed_encrypt(&to_addr, &to.store.identity_key(), &cert, &content.encode().unwrap()).unwrap()
}

async fn receive(e: &mut Engine, envelope: &[u8]) -> Option<DeviceAddress> {
    let (local, root) = (e.local().unwrap(), e.trust_root.clone().unwrap());
    e.receive_envelope(&local, &root, now_ms(), envelope, 0).await
}

/// C1, end to end through the engine, against a contact we have a session with — unverified,
/// then verified. The host mints a certificate naming bob's device under its own key and
/// deposits a PreKey message. Nothing is replaced, nothing is re-keyed, bob stays who he was
/// (and stays verified), the user is told once, and the next thing sealed for bob is something
/// the host cannot open and bob can.
#[tokio::test]
async fn a_server_minted_certificate_cannot_take_over_a_contacts_session() {
    for verified in [false, true] {
        let ca = CertAuthority::generate().unwrap();
        let mut me = sealed_engine(&ca, "me", "m1");
        let me_addr = me.local().unwrap();
        let mut bob = SignalStore::generate();
        let b1 = addr("bob", "b1");
        let bob_key = bob.identity_key();
        me.ingest_devices(Some("bob"), &serde_json::json!([dir_row("bob", "b1", &bob_key, None)]));
        me.dir_refreshed.insert("bob".into(), Instant::now()); // no directory re-check in this test
        me.peer_delivery.insert(b1.name().unwrap(), vec![9; 32]);
        // The real bob opens a session; we now have one we can answer on.
        let hello = seal_first(&ca, &mut bob, &b1, &mut me, &Content::SessionReset);
        assert!(receive(&mut me, &hello).await.is_none());
        assert!(me.store.has_session_with(&b1, &bob_key));
        if verified {
            me.set_verified(&b1, true).unwrap();
        }
        // Bob holds our key for a channel and for a call.
        me.ensure_send_key("channel:c").unwrap();
        me.send_keys.get_mut("channel:c").unwrap().holders.insert(b1.clone());
        me.take_security_notices();
        let state_before = (me.store.known_identity(&b1), me.store.session_identity(&b1), me.store.one_time_prekey_counts());

        // THE ATTACK, several times over.
        let mut host = SignalStore::generate();
        let forged = seal_first(&ca, &mut host, &b1, &mut me, &Content::SessionReset);
        let prekeys = me.store.one_time_prekey_counts();
        for _ in 0..3 {
            assert!(receive(&mut me, &forged).await.is_none(), "a forged envelope must never trigger a session repair");
        }
        assert_eq!(me.store.known_identity(&b1), state_before.0, "the identity on record was replaced");
        assert_eq!(me.store.session_identity(&b1), Some(bob_key.clone()), "the session was replaced");
        assert_eq!(me.store.one_time_prekey_counts(), prekeys, "a prekey was consumed");
        assert_eq!(me.contact_identity(&b1), Some(&bob_key));
        assert!(me.send_keys["channel:c"].holders.contains(&b1), "our sender key would have been handed out again");
        assert_eq!(me.is_verified(&b1), verified, "a verified contact stays verified: their key did not change");
        assert!(!me.contact_blocked("bob"), "a forged envelope must not be a mute button for the server");
        // The user is told, once, and whether the contact was verified.
        assert_eq!(kinds(&mut me), [("identity_changed".into(), "bob".into(), "b1".into(), verified)]);

        // The next outbound message.
        let secret = Content::SpaceKey { server_id: "s".into(), key: [7; 32] }.encode().unwrap();
        let (envelope, _) = me.seal_for(&b1, &secret).await.unwrap();
        let me_key = me.store.identity_key();
        assert!(host.sealed_decrypt(&b1, &ca.trust_root_public, now_ms(), &envelope, |_| Some(me_key.clone())).is_err(), "the host read it");
        let opened = bob.sealed_decrypt(&b1, &ca.trust_root_public, now_ms(), &envelope, |_| Some(me_key.clone())).unwrap();
        assert_eq!((opened.sender, opened.plaintext), (me_addr, secret));
    }
}

/// The same attack where there is a pin but nothing in the libsignal store yet (a member we
/// never exchanged a message with), and against one of our OWN sibling devices. No first-use
/// trust on receive: no identity is recorded and no session exists afterwards.
#[tokio::test]
async fn a_server_minted_certificate_cannot_start_a_session_for_a_pinned_device_or_a_sibling() {
    let ca = CertAuthority::generate().unwrap();
    let mut me = sealed_engine(&ca, "me", "m1");
    let bob_key = SignalStore::generate().identity_key();
    let sibling_key = SignalStore::generate().identity_key();
    let (b1, m2) = (addr("bob", "b1"), addr("me", "m2"));
    me.ingest_devices(Some("bob"), &serde_json::json!([dir_row("bob", "b1", &bob_key, None)]));
    me.siblings.insert("m2".into(), sibling_key);
    for user in ["bob", "me"] {
        me.dir_refreshed.insert(user.into(), Instant::now());
    }
    me.take_security_notices();
    for victim in [&b1, &m2] {
        let mut host = SignalStore::generate();
        let chat = Content::AccountSync { account_key: [1; 32] };
        let forged = seal_first(&ca, &mut host, victim, &mut me, &chat);
        assert!(receive(&mut me, &forged).await.is_none());
        assert!(me.store.known_identity(victim).is_none(), "an identity was recorded on first use");
        assert!(!me.store.has_session(victim) && me.store.session_identity(victim).is_none(), "a session was started");
        assert_eq!(kinds(&mut me), [("identity_changed".into(), victim.user_id.clone(), victim.device_id.clone(), false)]);
        // With no session to the pinned key, sealing goes to the directory for a bundle (there
        // is no server here) rather than to anything the host installed.
        assert!(me.seal_for(victim, b"x").await.is_err());
    }
    assert!(me.acct.account_key.is_none(), "content under a forged certificate was acted on");
}

/// An install written BEFORE receives were pinned may already hold the host's key and session
/// for a contact. The pin wins: the first send or receive retires both, nothing is sealed to the
/// host's key, and the real device is heard again.
#[tokio::test]
async fn a_session_planted_before_the_fix_is_retired_not_used() {
    let ca = CertAuthority::generate().unwrap();
    let mut me = sealed_engine(&ca, "me", "m1");
    let mut bob = SignalStore::generate();
    let b1 = addr("bob", "b1");
    let bob_key = bob.identity_key();
    me.ingest_devices(Some("bob"), &serde_json::json!([dir_row("bob", "b1", &bob_key, None)]));
    me.dir_refreshed.insert("bob".into(), Instant::now());
    me.peer_delivery.insert(b1.name().unwrap(), vec![9; 32]);
    // What build 44 would have accepted: the host's session, recorded as bob's.
    let mut host = SignalStore::generate();
    let forged = seal_first(&ca, &mut host, &b1, &mut me, &Content::SessionReset);
    let (local, root, host_key) = (me.local().unwrap(), me.trust_root.clone().unwrap(), host.identity_key());
    me.store.sealed_decrypt(&local, &root, now_ms(), &forged, |_| Some(host_key.clone())).unwrap();
    assert!(me.store.has_session_with(&b1, &host_key), "the planted state");

    // Sending: the planted session is retired; with no server to fetch bob's bundle from, the
    // send fails — it does not go to the host.
    assert!(me.seal_for(&b1, b"secret").await.is_err());
    assert!(!me.store.has_session(&b1));
    assert_eq!(me.store.known_identity(&b1).map(|(k, _)| k), Some(bob_key.clone()));
    assert!(kinds(&mut me).iter().any(|k| k.0 == "identity_changed" && k.1 == "bob"));
    // The host keeps writing on its session: refused. The real bob writes: heard.
    let more = host.sealed_encrypt(&local, &me.store.identity_key(), &ca.issue(&b1, &host_key, now_ms() + DAY_MS).unwrap(), b"x").unwrap();
    assert!(receive(&mut me, &more).await.is_none());
    assert!(!me.store.has_session(&b1));
    let hello = seal_first(&ca, &mut bob, &b1, &mut me, &Content::SessionReset);
    assert!(receive(&mut me, &hello).await.is_none());
    assert!(me.store.has_session_with(&b1, &bob_key));
    let (envelope, _) = me.seal_for(&b1, b"secret").await.unwrap();
    let me_key = me.store.identity_key();
    assert!(host.sealed_decrypt(&b1, &root, now_ms(), &envelope, |_| Some(me_key.clone())).is_err());
    assert!(bob.sealed_decrypt(&b1, &root, now_ms(), &envelope, |_| Some(me_key.clone())).is_ok());
}

/// A device the server lists for a contact but nobody vouched for: what it says is held for the
/// user to decide about, and reading it leaves no session and no identity behind. Once the
/// user accepts the device, the held message is delivered.
#[tokio::test]
async fn an_unvouched_devices_message_is_held_without_keeping_a_session() {
    let ca = CertAuthority::generate().unwrap();
    let mut me = sealed_engine(&ca, "me", "m1");
    let bob_key = SignalStore::generate().identity_key();
    let mut ghost = SignalStore::generate();
    let g = addr("bob", "ghost");
    me.ingest_devices(Some("bob"), &serde_json::json!([dir_row("bob", "b1", &bob_key, None)]));
    me.ingest_devices(Some("bob"), &serde_json::json!([dir_row("bob", "b1", &bob_key, None), dir_row("bob", "ghost", &ghost.identity_key(), None)]));
    me.dir_refreshed.insert("bob".into(), Instant::now());
    let chat = Content::Chat { conversation_id: "conv".into(), message_id: "x".into(), text: "from the ghost".into(), sent_at: 1, sync_peer: None };
    let envelope = seal_first(&ca, &mut ghost, &g, &mut me, &chat);
    let prekeys = me.store.one_time_prekey_counts();
    assert!(receive(&mut me, &envelope).await.is_none());
    assert_eq!(me.held_inbound.len(), 1);
    assert!(me.store.known_identity(&g).is_none() && me.store.session_identity(&g).is_none());
    assert_eq!(me.store.one_time_prekey_counts(), prekeys);
    assert!(me.take_dms().is_empty());
    // The server delivers the very same envelope again (and again): it is held ONCE — reading
    // it kept no session, so nothing in libsignal would have noticed the replay.
    for _ in 0..3 {
        assert!(receive(&mut me, &envelope).await.is_none());
    }
    assert_eq!(me.held_inbound.len(), 1, "a replayed envelope was held again");
    // The record survives a restart...
    let mut restarted = sealed_engine(&ca, "me", "m1");
    assert_eq!(restarted.load_state(&me.export_state()), LoadOutcome::Restored);
    restarted.dir_refreshed.insert("bob".into(), Instant::now());
    assert!(receive(&mut restarted, &envelope).await.is_none());
    assert_eq!(restarted.held_inbound.len(), 1);
    // ...and outlives the hold: once the ghost is accepted and its message delivered, the
    // same envelope does not deliver it a second time through the ordinary path.
    let ghost_key = ghost.identity_key();
    let c = me.contacts.get_mut("bob").unwrap();
    c.unvouched.remove("ghost");
    c.vouched.insert("ghost".into(), ghost_key.clone());
    c.live.insert("ghost".into());
    me.held_inbound.clear();
    assert!(receive(&mut me, &envelope).await.is_none());
    assert!(me.store.known_identity(&g).is_none() && me.held_inbound.is_empty(), "a spent envelope was read again");
    {
        let c = me.contacts.get_mut("bob").unwrap();
        c.live.remove("ghost");
        c.vouched.remove("ghost");
        c.unvouched.insert("ghost".into(), ghost_key);
    }
    // A third key under the ghost's name (not the listed one) is not even read.
    let mut other = SignalStore::generate();
    let envelope = seal_first(&ca, &mut other, &g, &mut me, &chat);
    assert!(receive(&mut me, &envelope).await.is_none());
    assert!(me.held_inbound.is_empty() && me.store.known_identity(&g).is_none());
}

// ---- engine H2: a join response cannot move a trust anchor ----

/// Accepting ANY invite on a malicious host: it answers with the id of a space we are already
/// in and a ghost as its host. The pinned owner and the space key stay, the join is refused and
/// the user is told. A first join pins; the same owner again is fine; only the user's explicit
/// `forget_space` lets a different owner be pinned.
#[test]
fn a_join_response_cannot_replace_a_pinned_owner_or_a_space_key() {
    let mut me = engine("me", "m1");
    let join = |host: &str| JoinOutcome { server_id: "space".into(), pending: false, host_user_id: Some(host.into()), host_device_id: None };
    me.apply_join(&join("owner"), Some([1; 32])).unwrap();
    assert_eq!(me.trusted_owner("space").map(String::as_str), Some("owner"));
    assert_eq!(me.spaces["space"], [1; 32]);

    // The attack.
    assert!(me.apply_join(&join("ghost"), Some([2; 32])).is_err());
    assert_eq!(me.trusted_owner("space").map(String::as_str), Some("owner"), "the owner pin was replaced");
    assert_eq!(me.spaces["space"], [1; 32], "the space key was replaced");
    assert_eq!(kinds(&mut me), [("owner_change_refused".into(), "ghost".into(), "space".into(), false)]);
    // The ghost's approvals authorize nobody.
    let ghost = SignalStore::generate();
    pin(&mut me, &addr("ghost", "g1"), &ghost.identity_key());
    me.rosters.entry("space".into()).or_default().members.insert("me".into());
    me.apply_approvals("space", &serde_json::json!([approval(&ghost, "space", "mallory", "ghost", "g1", now_ms() as i64)]));
    assert!(!me.rosters["space"].members.contains("mallory"));

    // The same owner again (another invite to the same space): fine, and the key still stays.
    me.apply_join(&join("owner"), Some([3; 32])).unwrap();
    assert_eq!(me.spaces["space"], [1; 32]);
    // A pin of unknown origin (a build-42 state) is not replaced by a join either.
    me.expected_provisioner.insert("old".into(), "host".into());
    let old = JoinOutcome { server_id: "old".into(), pending: false, host_user_id: Some("ghost".into()), host_device_id: None };
    assert!(me.apply_join(&old, None).is_err());
    assert_eq!(me.expected_provisioner["old"], "host");
    // A pin handed over by a sibling keeps its source when the join names the same owner.
    me.pin_owner("sib", "owner", trust::OwnerSource::Sibling);
    me.apply_join(&JoinOutcome { server_id: "sib".into(), pending: false, host_user_id: Some("owner".into()), host_device_id: None }, None).unwrap();
    assert_eq!(me.owner_sources["sib"], trust::OwnerSource::Sibling);

    // Only the user's own decision clears the way.
    me.forget_space("space");
    assert!(me.trusted_owner("space").is_none() && !me.spaces.contains_key("space") && !me.rosters.contains_key("space"));
    me.apply_join(&join("ghost"), Some([2; 32])).unwrap();
    assert_eq!(me.trusted_owner("space").map(String::as_str), Some("ghost"));
}

// ---- engine H1: the roster gates who may SPEAK, not only who may read ----

/// The server makes up a ghost account (or keeps a removed member around), has it send every
/// member a sender key for a channel, and serves rows under its name. A sender key is bound
/// only for someone on THIS device's roster for the channel's server, so the ghost's rows can
/// never be decrypted or shown — for a channel of a server we keep a roster for, for a channel
/// we cannot place, and for a member once they are removed.
#[tokio::test]
async fn a_non_member_cannot_speak_in_a_channel() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    me.channel_servers.insert("c".into(), "srv".into());
    me.rosters.entry("srv".into()).or_default().members.extend(["me".to_string(), "bob".to_string()]);
    let key_from = |e: &mut Engine, channel: &str| {
        let id = e.ensure_send_key(&format!("channel:{channel}")).unwrap();
        let skdm = e.store.create_distribution(&e.local().unwrap(), id).unwrap();
        Content::SenderKey { channel_id: channel.to_string(), skdm }.encode().unwrap()
    };

    // The ghost: an account with a valid, pinned device (first sight pins), but on no roster.
    let mut ghost = engine("ghost", "g1");
    pin(&mut me, &ghost.local().unwrap(), &ghost.store.identity_key());
    let payload = key_from(&mut ghost, "c");
    me.handle_content(&local, ghost.local().unwrap(), &payload, 0).await;
    assert!(me.recv_keys.is_empty(), "a sender key from a non-member was bound");
    let row = wire(&mut ghost, "c", "i am a member, honest");
    assert!(me.open_channel_message("channel:c", &ghost.local().unwrap(), &row).is_err());
    assert!(!me.accepted_member("srv", "ghost"));

    // A member: bound, readable.
    let mut bob = engine("bob", "b1");
    pin(&mut me, &bob.local().unwrap(), &bob.store.identity_key());
    let payload = key_from(&mut bob, "c");
    me.handle_content(&local, bob.local().unwrap(), &payload, 0).await;
    assert_eq!(me.recv_keys.len(), 1);
    let row = wire(&mut bob, "c", "hello");
    assert_eq!(me.open_channel_message("channel:c", &bob.local().unwrap(), &row).unwrap().text, "hello");

    // A channel this device cannot place in any server (nothing to look it up with here): refused.
    let payload = key_from(&mut bob, "elsewhere");
    me.handle_content(&local, bob.local().unwrap(), &payload, 0).await;
    assert_eq!(me.recv_keys.len(), 1);

    // Bob is removed: his key goes, a key he sends afterwards is not bound, and a row under
    // his name is not one this device would show.
    me.member_removed("srv", "bob");
    assert!(me.recv_keys.is_empty());
    let mut bob_again = engine("bob", "b1");
    bob_again.store = SignalStore::from_bytes(&bob.store.to_bytes()).unwrap();
    bob_again.send_keys.clear();
    let payload = key_from(&mut bob_again, "c");
    me.handle_content(&local, bob.local().unwrap(), &payload, 0).await;
    assert!(me.recv_keys.is_empty(), "a removed member's new key was bound");
    assert!(!me.accepted_member("srv", "bob") && me.accepted_member("srv", "me"));
}

// ---- engine H3: a removed device stays removed ----

/// One of our own devices was removed. The tombstone is enforced the moment it arrives — the
/// device stops being a sibling even though the server still lists it — and nothing brings it
/// back: not a sibling repeating an old set, not the link bundle of a later link.
#[tokio::test]
async fn a_removed_sibling_is_evicted_and_never_re_admitted() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    let (phone, lost) = (SignalStore::generate().identity_key(), SignalStore::generate().identity_key());
    me.siblings.insert("phone".into(), phone.clone());
    me.siblings.insert("lost".into(), lost.clone());
    for d in ["phone", "lost"] {
        me.store.accept_identity(&addr("me", d), &me.siblings[d].clone()).unwrap();
    }
    me.ensure_send_key("channel:c").unwrap();
    me.send_keys.get_mut("channel:c").unwrap().holders.insert(addr("me", "lost"));
    me.take_security_notices();

    // The phone tells us the lost device was removed.
    let payload = Content::Tombstones { identities: vec![lost.clone()] }.encode().unwrap();
    me.handle_content(&local, addr("me", "phone"), &payload, 0).await;
    assert!(!me.siblings.contains_key("lost"), "a tombstoned device is still a sibling");
    assert!(me.siblings.contains_key("phone"));
    assert!(me.own_tombstoned(&lost));
    assert!(me.stale_scopes.contains("channel:c"), "what it held of ours must rotate");
    assert!(kinds(&mut me).contains(&("device_removed".into(), "me".into(), "lost".into(), false)));
    // Nothing is sealed for it any more (the send gate is the sibling set).
    let chat = Content::AccountSync { account_key: [1; 32] };
    assert!(me.send_content(&[addr("me", "lost")], &chat).await.unwrap().is_empty());

    // A sibling that still lists it (an old set, a replay) does not bring it back...
    let payload = Content::Siblings { devices: vec![("lost".into(), lost.clone()), ("lost-renamed".into(), lost.clone())] }.encode().unwrap();
    me.handle_content(&local, addr("me", "phone"), &payload, 0).await;
    assert!(!me.siblings.contains_key("lost") && !me.siblings.contains_key("lost-renamed"));
    // ...and what it sends is refused like any device nobody vouched for.
    me.dir_refreshed.insert("me".into(), Instant::now());
    assert!(me.pinned_identity(&addr("me", "lost")).is_none());
    // The state survives a restart.
    let mut again = engine("me", "m1");
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert!(again.own_tombstoned(&lost) && !again.siblings.contains_key("lost"));
}

/// A contact told us (from a device we trust) that they removed one of their devices. It is
/// retired at once, and the server listing it again — same row, same key — does not make it a
/// send target or an accepted sender again.
#[tokio::test]
async fn a_contacts_removed_device_is_retired_at_once_and_stays_out() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    let (b1, b2) = (SignalStore::generate().identity_key(), SignalStore::generate());
    let rows = serde_json::json!([dir_row("bob", "b1", &b1, None), dir_row("bob", "b2", &b2.identity_key(), None)]);
    assert_eq!(me.ingest_devices(Some("bob"), &rows).len(), 2);
    me.store.accept_identity(&addr("bob", "b1"), &b1).unwrap();
    me.take_security_notices();

    let payload = Content::Tombstones { identities: vec![b2.identity_key()] }.encode().unwrap();
    me.handle_content(&local, addr("bob", "b1"), &payload, 0).await;
    assert!(!me.contact_device_trusted(&addr("bob", "b2")), "retired the moment its owner said so");
    assert!(me.contact_identity(&addr("bob", "b2")).is_none());
    // The server goes on listing it: held as unvouched, never live.
    let listed: Vec<DeviceAddress> = me.ingest_devices(Some("bob"), &rows).into_iter().map(|(d, _)| d).collect();
    assert_eq!(listed, [addr("bob", "b1")]);
    assert!(!me.contact_device_trusted(&addr("bob", "b2")));
    assert!(me.contacts["bob"].unvouched.contains_key("b2"));
}

// ---- engine M1: the server cannot erase channel history ----

/// A channel clear and a message deletion count only as sealed messages from someone entitled:
/// the pinned owner of the channel's server (clears; anyone's message), the message's own
/// author (their message), or one of our own devices. From anyone else nothing is queued.
#[tokio::test]
async fn clears_and_deletes_are_only_taken_from_the_owner_or_the_author() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    assert!(me.confirm_channel("c", "srv"));
    me.pin_owner("srv", "owner", trust::OwnerSource::Invite);
    me.rosters.entry("srv".into()).or_default().members.extend(["me", "owner", "bob"].map(String::from));
    let (owner, bob, ghost) = (pin_fresh(&mut me, "owner", "o1"), pin_fresh(&mut me, "bob", "b1"), pin_fresh(&mut me, "ghost", "g1"));
    me.siblings.insert("m2".into(), SignalStore::generate().identity_key());
    me.store.accept_identity(&addr("me", "m2"), &me.siblings["m2"].clone()).unwrap();
    let clear = |at: i64| Content::ChannelClear { server_id: "srv".into(), channel_id: "c".into(), cleared_at: at }.encode().unwrap();
    let delete = |id: &str| Content::ChannelDelete { server_id: "srv".into(), channel_id: "c".into(), message_id: id.into() }.encode().unwrap();

    // A member who is not the owner, and a non-member: no clear.
    me.handle_content(&local, bob.clone(), &clear(1_000), 0).await;
    me.handle_content(&local, ghost.clone(), &clear(1_000), 0).await;
    assert!(me.take_channel_clears().is_empty());
    // The owner: taken; a time in the far future is cut down to the present.
    me.handle_content(&local, owner.clone(), &clear(1_000), 0).await;
    me.handle_content(&local, owner.clone(), &clear(i64::MAX), 0).await;
    let clears = me.take_channel_clears();
    assert_eq!(clears.len(), 2);
    assert_eq!(clears[0], ("c".to_string(), 1_000));
    assert!(clears[1].1 <= now_ms() as i64 + 10 * 60 * 1000, "a clear reached into the future");
    // One of our own devices: taken.
    me.handle_content(&local, addr("me", "m2"), &clear(2_000), 0).await;
    assert_eq!(me.take_channel_clears(), [("c".to_string(), 2_000)]);
    // A channel this device has no placement for: nobody's clear counts.
    let stray = Content::ChannelClear { server_id: "srv".into(), channel_id: "elsewhere".into(), cleared_at: 5 }.encode().unwrap();
    me.handle_content(&local, owner.clone(), &stray, 0).await;
    me.handle_content(&local, addr("me", "m2"), &stray, 0).await;
    assert!(me.take_channel_clears().is_empty(), "a channel this device has not placed is nobody's to clear");

    // Deletions: anyone's is theirs to make for their OWN messages (the application checks the
    // author); only the pinned owner's, in a channel confirmed in that server, reaches anyone's.
    me.handle_content(&local, bob.clone(), &delete("x"), 0).await;
    me.handle_content(&local, owner.clone(), &delete("y"), 0).await;
    me.handle_content(&local, ghost.clone(), &delete("z"), 0).await;
    me.handle_content(&local, addr("me", "m2"), &delete("w"), 0).await;
    let deletes = me.take_channel_deletes();
    let seen: Vec<(&str, &str, bool)> = deletes.iter().map(|d| (d.message_id.as_str(), d.by_user_id.as_str(), d.by_owner)).collect();
    // (The ghost's is queued as the ghost's own: it can only ever touch a message the ghost wrote.)
    assert_eq!(seen, [("x", "bob", false), ("y", "owner", true), ("z", "ghost", false), ("w", SELF_AUTHOR, false)]);
    // Pending ones survive a restart.
    me.handle_content(&local, owner, &clear(3_000), 0).await;
    let mut again = engine("me", "m1");
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert_eq!(again.take_channel_clears(), [("c".to_string(), 3_000)]);
}

// ---- engine M4: the server cannot shrink the block list ----

#[test]
fn the_servers_block_list_can_add_but_never_remove() {
    let mut me = engine("me", "m1");
    me.blocked.insert("troll".into());
    // The server answers with an empty list (at launch, say): the troll stays blocked, and is
    // still on the list the user is shown.
    assert_eq!(me.fold_blocks(&serde_json::json!([])), [("troll".to_string(), String::new())]);
    assert!(me.blocked.contains("troll"));
    // A block made on another of our devices is added.
    let shown = me.fold_blocks(&serde_json::json!([{ "user_id": "spammer", "username": "spam" }]));
    assert_eq!(shown, [("spammer".to_string(), "spam".to_string()), ("troll".to_string(), String::new())]);
    assert!(me.blocked.contains("spammer") && me.blocked.contains("troll"));
    assert!(me.fold_blocks(&serde_json::Value::Null).len() == 2 && me.blocked.len() == 2);
}

// ---- engine M5: a conversation is with the people it was first used with ----

/// A member, with the host's help, names the id of our 1:1 with bob and has the server list
/// them as a participant. The conversation was bound to bob when it was first used, so the
/// message is not filed there — as a plain message, a reply, an edit, a delete or a reaction.
#[tokio::test]
async fn a_message_cannot_be_filed_in_someone_elses_conversation() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    let (bob, mallory) = (pin_fresh(&mut me, "bob", "b1"), pin_fresh(&mut me, "mallory", "x1"));
    me.dm_participants.insert("conv".into(), vec!["me".into(), "bob".into()]);
    let chat = |id: &str, text: &str| Content::Chat { conversation_id: "conv".into(), message_id: id.into(), text: text.into(), sent_at: 1, sync_peer: None }.encode().unwrap();
    me.handle_content(&local, bob.clone(), &chat("1", "hi"), 5).await;
    assert_eq!(me.take_dms().len(), 1);

    // The server now lists mallory in that conversation (and only mallory, for good measure).
    for listed in [vec!["me", "bob", "mallory"], vec!["me", "mallory"]] {
        me.dm_participants.insert("conv".into(), listed.into_iter().map(String::from).collect());
        me.handle_content(&local, mallory.clone(), &chat("2", "it's bob, new phone"), 6).await;
        assert!(me.take_dms().is_empty(), "filed in a conversation that is with someone else");
        for op in [
            Content::DmReply { conversation_id: "conv".into(), message_id: "3".into(), text: "x".into(), sent_at: 1, reply_to: "1".into(), sync_peer: None },
            Content::DmEdit { conversation_id: "conv".into(), message_id: "1".into(), text: "x".into(), sync_peer: None },
            Content::DmDelete { conversation_id: "conv".into(), message_id: "1".into(), sync_peer: None },
            Content::DmReaction { conversation_id: "conv".into(), message_id: "1".into(), emoji: "👍".into(), remove: false, sync_peer: None },
        ] {
            me.handle_content(&local, mallory.clone(), &op.encode().unwrap(), 7).await;
        }
        assert!(me.take_dm_ops().is_empty());
        // Bob still writes there.
        me.handle_content(&local, bob.clone(), &chat(&format!("b{}", me.guard.dm_peers.len()), "still me"), 8).await;
        assert_eq!(me.take_dms().len(), 1);
    }
    // Our own sends are held to the same binding, and it survives a restart.
    assert!(matches!(me.send_dm_as("conv", &["mallory".to_string()], "9", "oops", None).await, Err(EngineError::Protocol(_))));
    let mut again = engine("me", "m1");
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert_eq!(again.conversation_binding("conv").map(|b| b.iter().cloned().collect::<Vec<_>>()), Some(vec!["bob".to_string()]));
    // A conversation mallory really has with us is theirs to write in.
    me.dm_participants.insert("other".into(), vec!["me".into(), "mallory".into()]);
    let other = Content::Chat { conversation_id: "other".into(), message_id: "1".into(), text: "hi".into(), sent_at: 1, sync_peer: None }.encode().unwrap();
    me.handle_content(&local, mallory, &other, 9).await;
    assert_eq!(me.take_dms().len(), 1);
}

// ---- engine M6: an older key backup is recognised ----

#[tokio::test]
async fn a_rolled_back_key_backup_is_refused_by_an_install_that_saw_a_newer_one() {
    let mut me = engine("me", "m1");
    let old = me.export_backup();
    me.backup_uploaded();
    let first = me.guard.backup_seq;
    assert!(first > 0);
    let new = me.export_backup();
    me.backup_uploaded();
    assert!(me.guard.backup_seq > first, "sequence numbers only go up");
    // An export that never reached the server does not count as seen.
    let unsent = me.export_backup();
    let tail = |b: &[u8]| postcard::take_from_bytes::<BackupState>(b).unwrap().1.to_vec();
    assert!(Engine::backup_seq_of(&tail(&unsent)) > me.guard.backup_seq);
    assert!(me.check_backup_fresh(&tail(&new)).is_ok(), "the newest backup restores");
    assert!(me.check_backup_fresh(&tail(&unsent)).is_ok());
    assert!(me.check_backup_fresh(&tail(&old)).is_err(), "a stale blob was accepted");
    // A backup written before build 45 (no sequence number) is older than anything seen.
    let (state, _) = postcard::take_from_bytes::<BackupState>(&old).unwrap();
    let mut pre45 = postcard::to_stdvec(&state).unwrap();
    pre45.extend(me.backup_ext());
    assert!(me.restore_backup(&pre45, None, None).await.is_err());
    assert!(me.restore_backup(&old, None, None).await.is_err());
    assert_eq!(me.local().unwrap(), addr("me", "m1"), "a refused restore must leave the engine as it was");
    // ...while an install that has seen none takes it (there is nothing to compare it with).
    assert!(engine("x", "y").check_backup_fresh(&tail(&old)).is_ok());
    // The mark survives a restart.
    let mut again = engine("me", "m1");
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert_eq!(again.guard.backup_seq, me.guard.backup_seq);
}

/// One of our own devices starts over (a restore): it is sent the sibling set, the removals and
/// the owner pins again — whatever it restored may be older than what the account knows now.
#[tokio::test]
async fn a_restored_sibling_is_sent_the_removals_again() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    let phone = SignalStore::generate().identity_key();
    me.siblings.insert("phone".into(), phone.clone());
    me.store.accept_identity(&addr("me", "phone"), &phone).unwrap();
    assert!(me.acct.sibling_sync.is_empty());
    me.handle_content(&local, addr("me", "phone"), &Content::SessionReset.encode().unwrap(), 0).await;
    assert!(me.acct.sibling_sync.contains_key("phone"));
    // A contact's reset schedules nothing of the kind.
    let bob = pin_fresh(&mut me, "bob", "b1");
    me.handle_content(&local, bob, &Content::SessionReset.encode().unwrap(), 0).await;
    assert_eq!(me.acct.sibling_sync.len(), 1);
}

/// Where a channel belongs is fixed the first time this device places it. The server cannot
/// move a channel under a server whose owner it controls to get clears and deletes accepted:
/// the remap is refused (and reported), a clear must name the server it speaks for, and the
/// owner of ANOTHER server — however real — clears nothing in a channel placed elsewhere.
#[tokio::test]
async fn a_channel_cannot_be_moved_to_another_server_to_authorise_a_clear() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    for (server, owner) in [("home", "alice"), ("other", "mallory")] {
        me.pin_owner(server, owner, trust::OwnerSource::Invite);
        me.rosters.entry(server.into()).or_default().members.extend(["me".to_string(), owner.to_string()]);
    }
    let (alice, mallory) = (pin_fresh(&mut me, "alice", "a1"), pin_fresh(&mut me, "mallory", "x1"));
    assert!(me.confirm_channel("c", "home"));
    assert!(me.confirm_channel("theirs", "other"));
    me.take_security_notices();

    // The server lists "c" under mallory's server. The placement does not move; told once.
    assert!(!me.bind_channel("c", "other"));
    assert!(!me.bind_channel("c", "other"));
    assert_eq!(me.channel_servers["c"], "home");
    assert_eq!(kinds(&mut me), [("channel_remap_refused".into(), "home".into(), "c".into(), false)]);
    assert!(me.channels_of("other") == ["theirs"] && me.channels_of("home") == ["c"]);

    let clear = |server: &str, channel: &str| Content::ChannelClear { server_id: server.into(), channel_id: channel.into(), cleared_at: 10 }.encode().unwrap();
    let delete = |server: &str, channel: &str| Content::ChannelDelete { server_id: server.into(), channel_id: channel.into(), message_id: "m".into() }.encode().unwrap();
    // Mallory, the real owner of "other": speaking for her own server about a channel placed
    // in "home", or claiming to speak for "home" — refused either way.
    for server in ["other", "home"] {
        me.handle_content(&local, mallory.clone(), &clear(server, "c"), 0).await;
        me.handle_content(&local, mallory.clone(), &delete(server, "c"), 0).await;
    }
    assert!(me.take_channel_clears().is_empty(), "another server's owner cleared a channel placed elsewhere");
    let deletes = me.take_channel_deletes();
    assert!(!deletes.is_empty() && deletes.iter().all(|d| !d.by_owner && d.by_user_id == "mallory"), "another server's owner was given an owner's right to delete: {deletes:?}");
    // Alice, the owner of "home", naming the wrong server for it: refused. Naming it right: taken.
    me.handle_content(&local, alice.clone(), &clear("other", "c"), 0).await;
    assert!(me.take_channel_clears().is_empty());
    me.handle_content(&local, alice.clone(), &clear("home", "c"), 0).await;
    me.handle_content(&local, alice, &delete("home", "c"), 0).await;
    assert_eq!(me.take_channel_clears(), [("c".to_string(), 10)]);
    assert!(matches!(me.take_channel_deletes().as_slice(), [d] if d.by_owner && d.by_user_id == "alice"));
    // Mallory in her own channel: hers to clear.
    me.handle_content(&local, mallory, &clear("other", "theirs"), 0).await;
    assert_eq!(me.take_channel_clears(), [("theirs".to_string(), 10)]);

    // The placement survives a restart (it is not re-learned from the server's lists)...
    let mut again = engine("me", "m1");
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    assert_eq!(again.channel_servers["c"], "home");
    assert!(!again.bind_channel("c", "other"));
    // ...and our own "clear this server" announces only what is CONFIRMED in it here: with the
    // server listing "c" (and anything else) under "other", clearing "other" touches neither.
    assert!(again.bind_channel("listed-only", "other"));
    assert_eq!(again.channels_of("other"), ["theirs"]);
    // Only the user's explicit decision removes a placement.
    again.forget_space("home");
    assert!(again.bind_channel("c", "other"));
}

/// The two tiers. What a listing says is kept in memory, bounded per server, and authorises
/// nothing; what the user did is confirmed, persisted and immovable. A server listing junk
/// channels by the thousand — under one server or many — never keeps a real channel from being
/// confirmed, never evicts a confirmed one, and never gets a clear accepted.
#[tokio::test]
async fn a_flood_of_listed_channels_cannot_crowd_out_or_stand_in_for_a_confirmed_one() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    me.pin_owner("home", "alice", trust::OwnerSource::Invite);
    me.pin_owner("junk", "mallory", trust::OwnerSource::Invite);
    let (alice, mallory) = (pin_fresh(&mut me, "alice", "a1"), pin_fresh(&mut me, "mallory", "x1"));
    assert!(me.confirm_channel("mine", "home"));
    // The flood: far more than a server may list, under "junk" and under "home" itself, plus
    // the id of a real channel of "home" that this device has not seen yet, squatted under "junk".
    for i in 0..(3 * MAX_SERVER_ARRAY) {
        assert!(me.bind_channel(&format!("junk-{i}"), "junk"));
        assert!(me.bind_channel(&format!("home-junk-{i}"), "home"));
    }
    assert!(me.bind_channel("real", "junk"));
    assert!(me.channels_of("junk").is_empty() && me.listed_channels.len() <= 2 * MAX_SERVER_ARRAY, "listed placements are bounded and confirm nothing");
    assert_eq!(me.guard.channel_servers.len(), 1, "a listing confirmed something");
    assert_eq!(me.channel_servers["mine"], "home", "a confirmed placement was evicted by listings");
    assert!(!me.bind_channel("mine", "junk"), "a listing moved a confirmed channel");

    // A listed placement lets no clear through — not even its own server's owner's.
    let clear = |server: &str, channel: &str| Content::ChannelClear { server_id: server.into(), channel_id: channel.into(), cleared_at: 10 }.encode().unwrap();
    me.handle_content(&local, mallory.clone(), &clear("junk", "real"), 0).await;
    me.handle_content(&local, mallory.clone(), &clear("junk", "junk-2999"), 0).await;
    me.handle_content(&local, alice.clone(), &clear("home", "home-junk-2999"), 0).await;
    assert!(me.take_channel_clears().is_empty(), "a listing-only placement authorised a clear");

    // The real channel is still the user's to confirm, in its real server, after all that —
    // the squatted listing gives way, and from then on it cannot be moved.
    assert!(me.confirm_channel("real", "home"), "junk listings kept a real channel from being bound");
    assert!(!me.bind_channel("real", "junk"));
    me.handle_content(&local, mallory, &clear("junk", "real"), 0).await;
    assert!(me.take_channel_clears().is_empty());
    me.handle_content(&local, alice, &clear("home", "real"), 0).await;
    assert_eq!(me.take_channel_clears(), [("real".to_string(), 10)]);
    // Only the confirmed placements are written to disk.
    let mut again = engine("me", "m1");
    assert_eq!(again.load_state(&me.export_state()), LoadOutcome::Restored);
    let mut kept: Vec<&String> = again.channel_servers.keys().collect();
    kept.sort();
    assert_eq!(kept, ["mine", "real"]);
}

// ---- apple A5: group or 1:1 is the sender's sealed statement, not the server's ----

/// A group message goes out wrapped with the group's members; a 1:1 message goes out bare. The
/// server cannot present one as the other: a bare payload is never filed in a group, a wrapped
/// one never in a 1:1, and a group message only in the group of exactly the members it names.
#[tokio::test]
async fn a_group_message_cannot_be_presented_as_a_direct_one_or_the_reverse() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    let (bob, carol, mallory) = (pin_fresh(&mut me, "bob", "b1"), pin_fresh(&mut me, "carol", "c1"), pin_fresh(&mut me, "mallory", "x1"));
    me.dm_participants.insert("one".into(), vec!["me".into(), "bob".into()]);
    me.dm_participants.insert("grp".into(), vec!["me".into(), "bob".into(), "carol".into()]);
    let chat = |conv: &str, id: &str| Content::Chat { conversation_id: conv.into(), message_id: id.into(), text: "hi".into(), sent_at: 1, sync_peer: None };
    let grouped = |members: &[&str], inner: &Content| Content::Grouped { members: members.iter().map(|m| m.to_string()).collect(), inner: inner.encode().unwrap() }.encode().unwrap();
    let group = ["bob", "carol", "me"];

    // Honest traffic: a bare message in the 1:1, a wrapped one in the group.
    me.handle_content(&local, bob.clone(), &chat("one", "1").encode().unwrap(), 1).await;
    me.handle_content(&local, bob.clone(), &grouped(&group, &chat("grp", "1")), 1).await;
    me.handle_content(&local, carol.clone(), &grouped(&group, &chat("grp", "2")), 1).await;
    assert_eq!(me.take_dms().len(), 3);
    assert_eq!((me.conversation_is_group("one"), me.conversation_is_group("grp"), me.conversation_is_group("never")), (Some(false), Some(true), None));

    // The server re-labels: bob's 1:1 payload served under the group's id, a group payload
    // under the 1:1's id (with the server listing whatever it likes as participants).
    me.dm_participants.insert("one".into(), vec!["me".into(), "bob".into(), "carol".into()]);
    me.dm_participants.insert("grp".into(), vec!["me".into(), "bob".into()]);
    me.handle_content(&local, bob.clone(), &chat("grp", "3").encode().unwrap(), 1).await;
    me.handle_content(&local, bob.clone(), &grouped(&group, &chat("one", "3")), 1).await;
    // A group message naming other members than the group has; one that leaves us, or its own
    // sender, out; a "group" of two; a wrapper around a wrapper or around something that is not
    // a direct message.
    me.handle_content(&local, bob.clone(), &grouped(&["bob", "carol", "mallory", "me"], &chat("grp", "4")), 1).await;
    me.handle_content(&local, mallory.clone(), &grouped(&["bob", "carol", "me"], &chat("grp", "5")), 1).await;
    me.handle_content(&local, bob.clone(), &grouped(&["bob", "carol"], &chat("grp", "6")), 1).await;
    me.handle_content(&local, bob.clone(), &grouped(&["bob", "me"], &chat("one", "7")), 1).await;
    let nested = Content::Grouped { members: group.iter().map(|m| m.to_string()).collect(), inner: chat("grp", "8").encode().unwrap() };
    me.handle_content(&local, bob.clone(), &grouped(&group, &nested), 1).await;
    me.handle_content(&local, bob.clone(), &grouped(&group, &Content::AccountSync { account_key: [9; 32] }), 1).await;
    assert!(me.take_dms().is_empty(), "a relabelled or malformed group message was filed");
    assert!(me.acct.account_key.is_none());

    // A conversation never used here: the server's list and the sealed marker must agree.
    me.dm_participants.insert("new1".into(), vec!["me".into(), "bob".into(), "carol".into()]);
    me.handle_content(&local, bob.clone(), &chat("new1", "1").encode().unwrap(), 1).await;
    me.dm_participants.insert("new2".into(), vec!["me".into(), "bob".into()]);
    me.handle_content(&local, bob.clone(), &grouped(&group, &chat("new2", "1")), 1).await;
    assert!(me.take_dms().is_empty() && me.conversation_is_group("new1").is_none() && me.conversation_is_group("new2").is_none());

    // What WE send: bare to one person, wrapped with the members to a group.
    assert!(me.bind_conversation("mine", &["bob".to_string(), "carol".to_string()].into_iter().collect()));
    let out = me.group_wrapped(&local, &chat("mine", "1")).unwrap();
    assert!(matches!(out, Some(Content::Grouped { ref members, .. }) if members == &["bob", "carol", "me"]));
    assert!(me.group_wrapped(&local, &chat("one", "9")).unwrap().is_none());
    assert!(me.group_wrapped(&local, &Content::SessionReset).unwrap().is_none());
}

/// Acting in a channel does not confirm where the server says it is. The host lists a channel
/// of "home" under "other" (whose owner it controls) before this device has confirmed it; the
/// user then writes, deletes and clears there. The placement stays a listing: the other owner's
/// clear is refused, nothing of ours is announced for it, and the user can still confirm the
/// channel where it really belongs.
#[tokio::test]
async fn writing_deleting_or_clearing_in_a_channel_confirms_nothing() {
    let mut me = engine("me", "m1");
    let local = me.local().unwrap();
    me.pin_owner("home", "alice", trust::OwnerSource::Invite);
    me.pin_owner("other", "mallory", trust::OwnerSource::Invite);
    let (alice, mallory) = (pin_fresh(&mut me, "alice", "a1"), pin_fresh(&mut me, "mallory", "x1"));
    assert!(me.bind_channel("c", "other"), "the server's listing, taken for routing");

    // The user acts in the channel (no server here, so the calls fail at the network — after
    // whatever they would have done to the placement).
    let _ = me.send_channel_message_as("c", "m-1", "hello", None, &[]).await;
    let _ = me.delete_channel_message("c", "m-1").await;
    let _ = me.clear_channel("c").await;
    me.announce_clear("other", "c").await;
    me.announce_delete("c", "m-1").await;
    assert!(me.confirmed_server("c").is_none(), "acting in a channel confirmed the server's placement of it");
    assert!(me.channels_of("other").is_empty());

    let clear = |server: &str| Content::ChannelClear { server_id: server.into(), channel_id: "c".into(), cleared_at: 10 }.encode().unwrap();
    me.handle_content(&local, mallory.clone(), &clear("other"), 0).await;
    assert!(me.take_channel_clears().is_empty(), "the listed server's owner cleared the channel");
    // The user opens it from its real server's list: confirmed there, and that owner's clear counts.
    assert!(me.confirm_channel("c", "home"));
    me.handle_content(&local, mallory, &clear("other"), 0).await;
    assert!(me.take_channel_clears().is_empty());
    me.handle_content(&local, alice, &clear("home"), 0).await;
    assert_eq!(me.take_channel_clears(), [("c".to_string(), 10)]);
}

/// Engine M4, the other half: someone only THIS device blocks (the server has no row for them)
/// can still be unblocked here, whatever the server answers.
#[tokio::test]
async fn a_locally_blocked_user_can_always_be_unblocked() {
    let mut me = engine("me", "m1");
    me.blocked.insert("troll".into());
    // No server at all (the request fails outright): the local entry still goes.
    let _ = me.unblock_user("troll").await;
    assert!(!me.blocked.contains("troll"));
    assert!(me.fold_blocks(&serde_json::json!([])).is_empty());
}

/// What is held from an unvouched device was read under the key the directory listed for it
/// then. The host injects text under its own key, then lists the device's real key so that an
/// "accept" would deliver the host's text as the contact's: the held text goes when the key does.
#[tokio::test]
async fn held_messages_do_not_outlive_the_key_they_were_read_under() {
    let ca = CertAuthority::generate().unwrap();
    let mut me = sealed_engine(&ca, "me", "m1");
    let bob_key = SignalStore::generate().identity_key();
    let real_new_device = SignalStore::generate().identity_key();
    let mut host = SignalStore::generate();
    let g = addr("bob", "b2");
    let rows = |b2: &[u8]| serde_json::json!([dir_row("bob", "b1", &bob_key, None), dir_row("bob", "b2", b2, None)]);
    me.ingest_devices(Some("bob"), &serde_json::json!([dir_row("bob", "b1", &bob_key, None)]));
    me.ingest_devices(Some("bob"), &rows(&host.identity_key()));
    me.dir_refreshed.insert("bob".into(), Instant::now());
    let chat = Content::Chat { conversation_id: "conv".into(), message_id: "x".into(), text: "send me the code".into(), sent_at: 1, sync_peer: None };
    let envelope = seal_first(&ca, &mut host, &g, &mut me, &chat);
    assert!(receive(&mut me, &envelope).await.is_none());
    assert_eq!(me.held_inbound.len(), 1);
    // Listed again under the SAME key: still held.
    me.ingest_devices(Some("bob"), &rows(&host.identity_key()));
    assert_eq!(me.held_inbound.len(), 1);
    // The listing now names another key for that device: what was read under the old one goes.
    me.ingest_devices(Some("bob"), &rows(&real_new_device));
    assert!(me.held_inbound.is_empty(), "text read under one key would be delivered under another");
}

// ---- server H-1, the peers' side: a contact's device restored onto another install ----

/// The directory lists a contact's device at a higher generation (`device_rekeyed`): the
/// install it left still holds what we handed that device, so our delivery key and every
/// sender key it was a holder of rotate. Trust is untouched — it is the same device and key.
/// A first sight, the same generation again, and a device that is gone rotate nothing by this
/// rule (a departed device has its own).
#[tokio::test]
async fn a_contacts_device_restored_elsewhere_makes_what_it_held_rotate() {
    let mut me = engine("me", "m1");
    let bob_key = SignalStore::generate().identity_key();
    let row = |generation: i64| {
        let mut r = dir_row("bob", "b1", &bob_key, None);
        r["generation"] = serde_json::json!(generation);
        serde_json::json!([r])
    };
    me.ingest_devices(Some("bob"), &row(0));
    me.ensure_send_key("channel:c").unwrap();
    me.ensure_send_key("channel:other").unwrap();
    me.send_keys.get_mut("channel:c").unwrap().holders.insert(addr("bob", "b1"));
    me.delivery.due_since = None;
    me.stale_scopes.clear();

    me.ingest_devices(Some("bob"), &row(0));
    assert!(me.stale_scopes.is_empty() && me.delivery.due_since.is_none(), "nothing changed, nothing rotates");

    me.ingest_devices(Some("bob"), &row(1));
    assert!(me.stale_scopes.contains("channel:c"), "the sender key the old install holds must rotate");
    assert!(!me.stale_scopes.contains("channel:other"), "a scope it never held is left alone");
    assert!(me.delivery.due_since.is_some(), "the delivery key it was handed must rotate");
    assert!(me.contact_device_trusted(&addr("bob", "b1")), "a restore is not a change of identity");

    // Once per rise.
    me.stale_scopes.clear();
    me.delivery.due_since = None;
    me.ingest_devices(Some("bob"), &row(1));
    assert!(me.stale_scopes.is_empty() && me.delivery.due_since.is_none());
    // A listing without the field (an older server) is not a rise, and forgets nothing.
    me.ingest_devices(Some("bob"), &serde_json::json!([dir_row("bob", "b1", &bob_key, None)]));
    assert!(me.stale_scopes.is_empty());
    me.ingest_devices(Some("bob"), &row(2));
    assert!(me.stale_scopes.contains("channel:c"));
}

/// Audit M2: a FRESH restore from a stale backup (the host can serve an older blob that still
/// opens under the recovery key) that lists a device removed since. Its siblings come back
/// UNCONFIRMED: nothing goes to them — not even when the host goes on listing the removed
/// device with the link signature it was first admitted with — and nothing they send counts:
/// the stolen device claiming itself and a new device in a sibling set confirms neither.
/// Only the user (one device at a time) or an already-confirmed sibling confirms; that
/// sibling's removals drop the stale one.
#[tokio::test]
async fn a_stale_backup_does_not_bring_back_a_removed_sibling() {
    let (lost, tablet) = (SignalStore::generate(), SignalStore::generate());
    // The account as it was when the stale backup was written: phone + lost + tablet.
    let mut phone = engine("me", "phone");
    phone.siblings.insert("lost".into(), lost.identity_key());
    phone.siblings.insert("tablet".into(), tablet.identity_key());
    let stale = phone.export_backup();
    // The host still lists "lost", under the link signature the phone once gave it — and a
    // device "lost" vouched for.
    let rogue = SignalStore::generate();
    // A device the phone linked AFTER that backup and removed again since: the backup does not
    // know it, but the phone's old link signature for it is still the host's to replay.
    let later = SignalStore::generate();
    let row = |device: &str, store: &SignalStore, linker: &str, by: &SignalStore| serde_json::json!({
        "device_id": device, "delivery_key": B64.encode([5u8; 32]), "identity_key": B64.encode(store.identity_key()),
        "linked_by": linker, "link_sig": B64.encode(by.sign_link("me", &store.identity_key()).unwrap()),
    });
    let own = serde_json::json!({ "user_id": "me", "devices": [
        row("lost", &lost, "phone", &phone.store), row("tablet", &tablet, "phone", &phone.store), row("rogue", &rogue, "lost", &lost),
        // …and "lost" again under a fresh row id, with the same old signature.
        row("lost-again", &lost, "phone", &phone.store), row("later", &later, "phone", &phone.store),
    ] });
    let mock = Mock::start(move |_, path| match path {
        "/api/e2ee/devices" => (200, own.clone()),
        _ => (200, serde_json::json!({})),
    });
    // A new install restores it (as the device "phone", moved here).
    let mut r = mock.engine("me", "interim");
    r.restore_backup(&stale, None, None).await.unwrap();
    assert_eq!(r.device_id(), Some("phone"));
    assert!(r.siblings.is_empty(), "no restored sibling is trusted on the backup's word, nor on an old link signature");
    assert!(!r.is_sibling("lost-again") && !r.is_sibling("later"));
    assert_eq!(r.unconfirmed_siblings(), vec!["later".to_string(), "lost".to_string(), "lost-again".to_string(), "tablet".to_string()],
        "devices vouched for only by this identity's pre-restore signatures are asked about");
    // A device vouched for only by an unconfirmed one is not trusted — and the user IS told.
    assert!(!r.is_sibling("rogue"));
    let notices = r.take_security_notices();
    assert!(notices.iter().any(|n| n.kind == "unverified_device" && n.device_id == "rogue"), "{notices:?}");
    assert!(!notices.iter().any(|n| n.kind == "unverified_device" && (n.device_id == "lost" || n.device_id == "tablet")));
    assert!(notices.iter().any(|n| n.kind == "restored_devices_unconfirmed"), "the user is told to confirm them");
    // It survives a restart.
    let mut again = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(again.load_state(&r.export_state()), LoadOutcome::Restored);
    assert_eq!(again.unconfirmed_siblings(), r.unconfirmed_siblings());

    // No sync copy (nor anything else) goes to an unconfirmed sibling: not even a key fetch.
    mock.take();
    let copy = Content::Chat { conversation_id: "c".into(), message_id: "m".into(), text: "hi".into(), sent_at: 1, sync_peer: Some("bob".into()) };
    let targets = [addr("me", "lost"), addr("me", "tablet"), addr("me", "lost-again"), addr("me", "later")];
    assert!(r.send_content(&targets, &copy).await.is_ok_and(|reached| reached.is_empty()));
    assert!(mock.take().iter().all(|(_, p)| !p.contains("lost") && !p.contains("tablet") && !p.contains("later")), "nothing was even looked up for them");
    // A refresh does not re-admit them by the old link signatures either.
    r.refresh_siblings(true).await.unwrap();
    assert!(r.siblings.is_empty());

    // The stolen device sends a sibling set claiming itself and a new device, and a removal of
    // the tablet: none of it counts.
    let local = r.local().unwrap();
    r.store.accept_identity(&addr("me", "lost"), &lost.identity_key()).unwrap();
    let claim = Content::Siblings { devices: vec![("lost".into(), lost.identity_key()), ("rogue".into(), rogue.identity_key())] }.encode().unwrap();
    r.handle_content(&local, addr("me", "lost"), &claim, 0).await;
    let tomb = Content::Tombstones { identities: vec![tablet.identity_key()] }.encode().unwrap();
    r.handle_content(&local, addr("me", "lost"), &tomb, 0).await;
    assert!(!r.is_sibling("lost") && !r.is_sibling("rogue") && !r.is_sibling("tablet"));
    assert_eq!(r.unconfirmed_siblings().len(), 4, "an unconfirmed device confirms and removes nothing");

    // The user says the tablet is theirs. The tablet, now confirmed, sends the account's
    // current set (the phone only — "lost" was removed) and its removals: "lost" is dropped.
    r.confirm_restored_sibling("tablet").await.unwrap();
    assert!(r.is_sibling("tablet"));
    r.store.accept_identity(&addr("me", "tablet"), &tablet.identity_key()).unwrap();
    let set = Content::Siblings { devices: vec![("phone".into(), phone.store.identity_key())] }.encode().unwrap();
    r.handle_content(&local, addr("me", "tablet"), &set, 0).await;
    assert_eq!(r.unconfirmed_siblings(), vec!["later".to_string(), "lost".to_string(), "lost-again".to_string()], "not listed by the tablet: still unconfirmed");
    let removals = Content::Tombstones { identities: vec![lost.identity_key(), later.identity_key()] }.encode().unwrap();
    r.handle_content(&local, addr("me", "tablet"), &removals, 0).await;
    assert!(r.unconfirmed_siblings().is_empty(), "the removals win, under every row");
    r.refresh_siblings(true).await.unwrap();
    assert!(r.unconfirmed_siblings().is_empty() && !r.is_sibling("lost-again") && !r.is_sibling("later"), "and stay won");
    assert!(!r.is_sibling("lost"));
    mock.take();
    let _ = r.send_content(&[addr("me", "lost")], &copy).await;
    assert!(mock.take().iter().all(|(_, p)| !p.contains("lost")), "no sync copy to the removed device");
    // And a user confirmation cannot bring a removed one back.
    r.unconfirmed_siblings.insert("lost".into(), lost.identity_key());
    assert!(r.confirm_restored_sibling("lost").await.is_err());
    assert!(!r.is_sibling("lost"));
}

/// Audit M2: after a restore, a device THIS install links is its own link and is admitted as
/// usual; one vouched for only by the identity's pre-restore signature is asked about.
#[tokio::test]
async fn a_link_made_after_the_restore_is_trusted_an_older_one_is_asked_about() {
    let phone = engine("me", "phone");
    let backup = phone.export_backup();
    let (fresh, old) = (SignalStore::generate(), SignalStore::generate());
    let row = |device: &str, store: &SignalStore| serde_json::json!({
        "device_id": device, "delivery_key": B64.encode([5u8; 32]), "identity_key": B64.encode(store.identity_key()),
        "linked_by": "phone", "link_sig": B64.encode(phone.store.sign_link("me", &store.identity_key()).unwrap()),
    });
    let own = serde_json::json!({ "user_id": "me", "devices": [row("fresh", &fresh), row("old", &old)] });
    let mock = Mock::start(move |_, path| match path {
        "/api/e2ee/devices" => (200, own.clone()),
        _ => (200, serde_json::json!({})),
    });
    let mut r = mock.engine("me", "interim");
    r.restore_backup(&backup, None, None).await.unwrap();
    assert_eq!(r.unconfirmed_siblings(), vec!["fresh".to_string(), "old".to_string()]);
    // (What `approve_link` records when this install signs a new device's link.)
    r.unconfirmed_siblings.clear();
    r.linked_here.insert(fresh.identity_key());
    r.refresh_siblings(true).await.unwrap();
    assert!(r.is_sibling("fresh"));
    assert!(!r.is_sibling("old") && r.unconfirmed_siblings() == vec!["old".to_string()]);
    // It survives a restart.
    let mut again = Engine::new(ApiClient::new("http://localhost".to_string()));
    assert_eq!(again.load_state(&r.export_state()), LoadOutcome::Restored);
    assert!(again.restored_install && again.linked_here.contains(&fresh.identity_key()));
}

/// Audit M2: an ALREADY-CONFIRMED sibling's set confirms a restored device it lists under the
/// key the backup had for it.
#[tokio::test]
async fn a_confirmed_siblings_set_confirms_a_restored_device() {
    let (tablet, mac) = (SignalStore::generate(), SignalStore::generate());
    let mut phone = engine("me", "phone");
    phone.siblings.insert("tablet".into(), tablet.identity_key());
    phone.siblings.insert("mac".into(), mac.identity_key());
    let backup = phone.export_backup();
    let row = |device: &str, store: &SignalStore| serde_json::json!({
        "device_id": device, "delivery_key": B64.encode([5u8; 32]), "identity_key": B64.encode(store.identity_key()),
        "linked_by": "phone", "link_sig": B64.encode(phone.store.sign_link("me", &store.identity_key()).unwrap()),
    });
    let own = serde_json::json!({ "user_id": "me", "devices": [row("tablet", &tablet), row("mac", &mac)] });
    let mock = Mock::start(move |_, path| match path {
        "/api/e2ee/devices" => (200, own.clone()),
        _ => (200, serde_json::json!({})),
    });
    let mut r = mock.engine("me", "interim");
    r.restore_backup(&backup, None, None).await.unwrap();
    assert!(!r.is_sibling("tablet") && !r.is_sibling("mac"));
    // With no confirmed sibling at all, only the user can start: they confirm the tablet.
    assert!(r.confirm_restored_sibling("nobody").await.is_err());
    r.confirm_restored_sibling("tablet").await.unwrap();
    assert!(r.is_sibling("tablet") && !r.is_sibling("mac"));
    let local = r.local().unwrap();
    r.store.accept_identity(&addr("me", "tablet"), &tablet.identity_key()).unwrap();
    // The tablet lists the mac under a DIFFERENT key first: not the device the backup knew.
    let swapped = SignalStore::generate().identity_key();
    let wrong = Content::Siblings { devices: vec![("mac".into(), swapped)] }.encode().unwrap();
    r.handle_content(&local, addr("me", "tablet"), &wrong, 0).await;
    r.refresh_siblings(true).await.unwrap();
    assert!(!r.is_sibling("mac"), "the directory's key is not the one listed: not trusted");
    // Under the backup's key: confirmed.
    r.siblings.remove("mac");
    r.unconfirmed_siblings.insert("mac".into(), mac.identity_key());
    let set = Content::Siblings { devices: vec![("mac".into(), mac.identity_key())] }.encode().unwrap();
    r.handle_content(&local, addr("me", "tablet"), &set, 0).await;
    assert!(r.is_sibling("mac") && r.unconfirmed_siblings().is_empty());
}

/// Audit M2: the contacts' removed devices travel in the backup — in a section of their own,
/// so a backup written before it existed still restores everything else.
#[test]
fn contact_removals_travel_in_the_backup_and_old_backups_stay_readable() {
    let mut e = engine("me", "d1");
    let alice_old = SignalStore::generate().identity_key();
    e.contacts.entry("alice".into()).or_default().vouched.insert("a1".into(), alice_old.clone());
    e.tombstone_contact_identity("alice", alice_old.clone());
    e.acct.device_name = Some("Phone".into());
    let backup = e.export_backup();
    let (_, tail) = postcard::take_from_bytes::<BackupState>(&backup).unwrap();
    let mut restored = engine("me", "d1");
    restored.apply_backup_ext(tail);
    assert!(restored.acct.contact_tombstones["alice"].contains(&alice_old));
    assert_eq!(restored.acct.device_name.as_deref(), Some("Phone"));
    // A build-44 backup: the accounts section and nothing else.
    let old_tail: Vec<u8> = accounts::read_sections(tail).unwrap().into_iter().filter(|(t, _)| *t == accounts::SECTION_ACCOUNTS).flat_map(|(t, b)| {
        let mut out = Vec::new();
        accounts::write_section(&mut out, t, b);
        out
    }).collect();
    let mut from_old = engine("me", "d1");
    from_old.apply_backup_ext(&old_tail);
    assert_eq!(from_old.acct.device_name.as_deref(), Some("Phone"), "still read");
    assert!(from_old.acct.contact_tombstones.is_empty());
}

/// Audit L2: "Accept" takes on exactly the device set the banner showed. A device the server
/// lists between the banner and the tap is not accepted with it: the accept is refused
/// (`IdentityChanged`) and the banner is shown again for the new set.
#[tokio::test]
async fn accept_takes_only_the_device_set_the_banner_showed() {
    let row = |device: &str, store: &SignalStore| serde_json::json!({
        "user_id": "bob", "device_id": device, "delivery_key": B64.encode([5u8; 32]), "identity_key": B64.encode(store.identity_key()),
    });
    let (b1, b2, b3) = (SignalStore::generate(), SignalStore::generate(), SignalStore::generate());
    let listing = std::sync::Arc::new(std::sync::Mutex::new(vec![row("b1", &b1)]));
    let served = listing.clone();
    let mock = Mock::start(move |_, path| match path {
        "/api/e2ee/users/bob/devices" => (200, serde_json::json!({ "devices": served.lock().unwrap().clone() })),
        _ => (200, serde_json::json!({})),
    });
    let mut me = mock.engine("me", "d1");
    me.fetch_devices("bob").await.unwrap();
    // An unlinked second device appears: held, and the banner shows it.
    *listing.lock().unwrap() = vec![row("b1", &b1), row("b2", &b2)];
    me.fetch_devices("bob").await.unwrap();
    assert_eq!(me.contact_status("bob").3, 1);
    let shown = me.accept_fingerprint("bob");
    // Before the tap, the server lists one more (or swaps a key): what was shown is not what
    // would be accepted now — nothing is accepted.
    *listing.lock().unwrap() = vec![row("b1", &b1), row("b2", &b2), row("b3", &b3)];
    let err = me.accept_identity_change(&addr("bob", ""), &shown).await.unwrap_err();
    assert!(matches!(&err, EngineError::IdentityChanged(u) if u == "bob"), "{err:?}");
    assert_eq!(me.contact_status("bob").3, 2, "both still held");
    assert!(me.contact_identity(&addr("bob", "b2")).is_none() && me.contact_identity(&addr("bob", "b3")).is_none());
    // A made-up or empty fingerprint accepts nothing either.
    assert!(me.accept_identity_change(&addr("bob", ""), "").await.is_err());
    // The banner is shown again for the new set; accepting THAT works.
    let shown = me.accept_fingerprint("bob");
    me.accept_identity_change(&addr("bob", ""), &shown).await.unwrap();
    assert_eq!(me.contact_status("bob").3, 0);
    assert!(me.contact_identity(&addr("bob", "b3")).is_some());
    // The fingerprint covers keys, not just ids: the same ids under another key differ.
    let mut c = trust::ContactTrust::default();
    c.unvouched.insert("x".into(), vec![1; 33]);
    let a = c.accept_fingerprint();
    c.unvouched.insert("x".into(), vec![2; 33]);
    assert_ne!(a, c.accept_fingerprint());
}

/// The server's "waiting" answer maps to `RecoveryPending`, contested or not, and a contested
/// one never promises the hold in what it says.
#[test]
fn a_contested_recovery_answer_waits_for_an_approval_not_the_hold() {
    let answer = |body: serde_json::Value| EngineError::from(ClientError::Status { status: 403, body: body.to_string() });
    let later = now_ms() as i64 + 7 * 86_400_000;
    let plain = answer(serde_json::json!({ "error": "device recovery pending", "completes_at": later, "contested_at": null }));
    assert!(matches!(plain, EngineError::RecoveryPending(at, false) if at == later));
    assert!(plain.to_string().contains("complete in about"), "{plain}");
    // A build-44 server says nothing about a contest: not contested.
    let old = answer(serde_json::json!({ "error": "device recovery pending", "completes_at": later }));
    assert!(matches!(old, EngineError::RecoveryPending(_, false)));
    let contested = answer(serde_json::json!({ "error": "device recovery pending", "completes_at": later, "contested_at": 5 }));
    assert!(matches!(contested, EngineError::RecoveryPending(at, true) if at == later));
    assert!(contested.to_string().contains("waiting for approval on one of your devices"), "{contested}");
    assert!(!contested.to_string().contains("day"), "{contested}");
}
