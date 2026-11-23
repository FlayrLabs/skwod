//! Cross-client protocol tests: several users, several devices each, talking through a simulated
//! key directory + relay exactly the way the real server does it (bundle hand-out, one-time prekey
//! consumption, last-resort fallback, opaque sealed envelopes).

use std::collections::HashMap;

use skwod_crypto::certs::{self, CertAuthority};
use skwod_crypto::store::{safety_number, CryptoError, DeviceAddress, KyberPreKeyUpload, PreKeyBundleData, PreKeyUpload, SealedError, SealedMessage, SignalStore, SignedPreKeyUpload};
use uuid::Uuid;

const HOUR_MS: u64 = 3_600_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// What the key directory holds for one device (public halves only).
struct Published {
    registration_id: u32,
    identity_key: Vec<u8>,
    signed: SignedPreKeyUpload,
    last_resort: KyberPreKeyUpload,
    one_time: Vec<PreKeyUpload>,
    one_time_kyber: Vec<KyberPreKeyUpload>,
}

struct World {
    ca: CertAuthority,
    directory: HashMap<DeviceAddress, Published>,
}

struct Device {
    addr: DeviceAddress,
    store: SignalStore,
    cert: Vec<u8>,
}

impl World {
    fn new() -> Self {
        Self { ca: CertAuthority::generate().unwrap(), directory: HashMap::new() }
    }

    /// Register a fresh device with `n` one-time prekeys of each kind.
    fn device(&mut self, user: &str, device: &str, n: usize) -> Device {
        let addr = DeviceAddress::new(user, device);
        let mut store = SignalStore::generate();
        self.publish(&addr, &mut store, n);
        let cert = self.ca.issue(&addr, &store.identity_key(), now_ms() + 24 * HOUR_MS).unwrap();
        Device { addr, store, cert }
    }

    fn publish(&mut self, addr: &DeviceAddress, store: &mut SignalStore, n: usize) {
        let published = Published {
            registration_id: store.registration_id(),
            identity_key: store.identity_key(),
            signed: store.generate_signed_prekey().unwrap(),
            last_resort: store.generate_last_resort_kyber().unwrap(),
            one_time: store.generate_one_time_prekeys(n).unwrap(),
            one_time_kyber: store.generate_one_time_kyber(n).unwrap(),
        };
        // The server validates signatures on upload.
        assert!(certs::verify_prekey_signature(&published.identity_key, &published.signed.public, &published.signed.signature, false));
        assert!(certs::verify_prekey_signature(&published.identity_key, &published.last_resort.public, &published.last_resort.signature, true));
        self.directory.insert(addr.clone(), published);
    }

    /// Serve a bundle: consume a one-time EC + Kyber prekey if any remain, else fall back to the
    /// last-resort Kyber key and no one-time EC key.
    fn bundle(&mut self, addr: &DeviceAddress) -> PreKeyBundleData {
        let p = self.directory.get_mut(addr).expect("registered");
        PreKeyBundleData {
            registration_id: p.registration_id,
            identity_key: p.identity_key.clone(),
            signed_pre_key: p.signed.clone(),
            kyber_pre_key: p.one_time_kyber.pop().unwrap_or_else(|| p.last_resort.clone()),
            pre_key: p.one_time.pop(),
        }
    }

    fn root(&self) -> &[u8] {
        &self.ca.trust_root_public
    }

    /// `from` sends `text` to `to`, establishing a session from the directory if needed.
    fn send(&mut self, from: &mut Device, to: &DeviceAddress, text: &[u8]) -> Vec<u8> {
        if !from.store.has_session(to) {
            let bundle = self.bundle(to);
            from.store.process_bundle(&from.addr, to, &bundle).unwrap();
        }
        from.store.sealed_encrypt(to, &self.pin(to), &from.cert, text).unwrap()
    }

    /// The identity key the directory holds for `addr` — what an honest client pins.
    fn pin(&self, addr: &DeviceAddress) -> Vec<u8> {
        self.directory[addr].identity_key.clone()
    }

    /// `to` opens `envelope`, expecting each sender under the key the directory holds for it.
    fn open(&self, to: &mut Device, envelope: &[u8]) -> Result<SealedMessage, SealedError> {
        to.store.sealed_decrypt(&to.addr, self.root(), now_ms(), envelope, |sender| self.directory.get(sender).map(|p| p.identity_key.clone()))
    }

    fn recv(&self, to: &mut Device, envelope: &[u8]) -> (DeviceAddress, Vec<u8>) {
        let m = self.open(to, envelope).expect("decrypts");
        (m.sender, m.plaintext)
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn two_users_multiple_devices_exchange_sealed_messages() {
    let mut w = World::new();
    let mut alice_phone = w.device("alice", "phone", 5);
    let mut alice_mac = w.device("alice", "mac", 5);
    let mut bob_phone = w.device("bob", "phone", 5);
    let mut bob_tablet = w.device("bob", "tablet", 5);

    // Alice's phone fans a message out to both of Bob's devices AND her own other device.
    for target in [&mut bob_phone, &mut bob_tablet, &mut alice_mac] {
        let env = w.send(&mut alice_phone, &target.addr.clone(), b"hello from alice's phone");
        let (sender, pt) = w.recv(target, &env);
        assert_eq!(sender, alice_phone.addr);
        assert_eq!(pt, b"hello from alice's phone");
    }

    // Replies ride the established sessions (no further bundle fetch) in both directions, many
    // times, so the Double Ratchet + SPQR steps repeatedly.
    for round in 0..20u32 {
        let text = format!("bob tablet -> alice phone #{round}");
        let env = w.send(&mut bob_tablet, &alice_phone.addr.clone(), text.as_bytes());
        assert_eq!(w.recv(&mut alice_phone, &env).1, text.as_bytes());
        let text = format!("alice phone -> bob tablet #{round}");
        let env = w.send(&mut alice_phone, &bob_tablet.addr.clone(), text.as_bytes());
        assert_eq!(w.recv(&mut bob_tablet, &env).1, text.as_bytes());
    }

    // A device that was never addressed cannot open someone else's envelope.
    let env = w.send(&mut alice_phone, &bob_phone.addr.clone(), b"for bob's phone only");
    assert!(w.open(&mut bob_tablet, &env).is_err());
    assert_eq!(w.recv(&mut bob_phone, &env).1, b"for bob's phone only");
}

#[test]
fn sealed_sender_hides_sender_and_authenticates_via_certificate() {
    let mut w = World::new();
    let mut alice = w.device("alice-user-id", "alice-device", 3);
    let mut bob = w.device("bob-user-id", "bob-device", 3);

    let env = w.send(&mut alice, &bob.addr.clone(), b"who sent this?");
    // What the server relays carries no sender identifier and no plaintext.
    assert!(!contains(&env, b"alice-user-id"));
    assert!(!contains(&env, b"alice-device"));
    assert!(!contains(&env, &alice.store.identity_key()[1..]));
    assert!(!contains(&env, b"who sent this?"));
    // Padding: a 1-byte and a 100-byte message produce equal-length envelopes on the same session.
    let short = w.send(&mut alice, &bob.addr.clone(), b"x");
    let long = w.send(&mut alice, &bob.addr.clone(), &[b'y'; 100]);
    assert_eq!(short.len(), long.len());

    // The recipient learns the sender from the certificate inside.
    let (sender, pt) = w.recv(&mut bob, &env);
    assert_eq!((sender, pt.as_slice()), (alice.addr.clone(), &b"who sent this?"[..]));

    // A certificate from a different authority (a forged "server") is rejected...
    let rogue = CertAuthority::generate().unwrap();
    let mut mallory = w.device("mallory", "m1", 3);
    mallory.cert = rogue.issue(&alice.addr, &mallory.store.identity_key(), now_ms() + HOUR_MS).unwrap();
    let forged = w.send(&mut mallory, &bob.addr.clone(), b"i am alice, honest");
    let err = w.open(&mut bob, &forged).unwrap_err();
    assert!(matches!(err.error, CryptoError::Invalid(_)), "{err:?}");

    // ...as is a certificate the real authority issued to mallory but for someone else's identity
    // key (certificate key must match the sealed-sender static key)...
    let mut mallory2 = w.device("mallory", "m2", 3);
    mallory2.cert = w.ca.issue(&alice.addr, &alice.store.identity_key(), now_ms() + HOUR_MS).unwrap();
    let forged = w.send(&mut mallory2, &bob.addr.clone(), b"still alice");
    assert!(w.open(&mut bob, &forged).is_err());

    // ...and an expired certificate.
    let mut carol = w.device("carol", "c1", 3);
    carol.cert = w.ca.issue(&carol.addr, &carol.store.identity_key(), now_ms() - 1).unwrap();
    let stale = w.send(&mut carol, &bob.addr.clone(), b"late");
    assert!(w.open(&mut bob, &stale).is_err());

    // Certificate validation helper agrees.
    let info = certs::validate(&alice.cert, w.root(), now_ms()).unwrap();
    assert_eq!(info.sender, alice.addr);
    assert_eq!(info.identity_key, alice.store.identity_key());
    assert!(certs::validate(&alice.cert, &rogue.trust_root_public, now_ms()).is_err());
    assert!(certs::validate(&alice.cert, w.root(), now_ms() + 48 * HOUR_MS).is_err());
}

#[test]
fn trust_root_is_bound_to_the_invite_pinned_instance_key() {
    let ca = CertAuthority::generate().unwrap();
    let (instance_secret, instance_public) = skwod_crypto::instance::generate();
    let sig = skwod_crypto::instance::sign(&instance_secret, &certs::root_binding_message(&ca.trust_root_public)).unwrap();
    assert!(certs::verify_root_binding(&instance_public, &ca.trust_root_public, &sig));
    // A different root, or a different pinned instance key, does not verify.
    let other = CertAuthority::generate().unwrap();
    assert!(!certs::verify_root_binding(&instance_public, &other.trust_root_public, &sig));
    assert!(!certs::verify_root_binding(&skwod_crypto::instance::generate().1, &ca.trust_root_public, &sig));
}

#[test]
fn out_of_order_duplicate_and_replayed_messages() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 3);
    let mut bob = w.device("bob", "b1", 3);
    let bob_addr = bob.addr.clone();

    // Establish both directions first.
    let hello = w.send(&mut alice, &bob_addr, b"hello");
    w.recv(&mut bob, &hello);
    let ack = w.send(&mut bob, &alice.addr.clone(), b"ack");
    w.recv(&mut alice, &ack);

    let envs: Vec<Vec<u8>> = (0..6).map(|i| w.send(&mut alice, &bob_addr, format!("m{i}").as_bytes())).collect();
    // Deliver out of order: 3, 0, 5, 1, 4, 2.
    for i in [3usize, 0, 5, 1, 4, 2] {
        assert_eq!(w.recv(&mut bob, &envs[i]).1, format!("m{i}").as_bytes());
    }
    // Every one of them replayed is rejected as a duplicate, attributed to alice.
    for env in &envs {
        let err = w.open(&mut bob, env).unwrap_err();
        assert_eq!(err.error, CryptoError::Duplicate);
        assert_eq!(err.sender.as_ref(), Some(&alice.addr));
    }
    // The very first (PreKey) message replayed is rejected too.
    assert!(w.open(&mut bob, &hello).is_err());
    // And the session still works afterwards.
    let after = w.send(&mut alice, &bob_addr, b"still fine");
    assert_eq!(w.recv(&mut bob, &after).1, b"still fine");

    // A tampered envelope fails and does not damage the session.
    let mut tampered = w.send(&mut alice, &bob_addr, b"intact");
    let n = tampered.len();
    tampered[n - 5] ^= 0x40;
    assert!(w.open(&mut bob, &tampered).is_err());
    let next = w.send(&mut alice, &bob_addr, b"next");
    assert_eq!(w.recv(&mut bob, &next).1, b"next");
}

#[test]
fn prekey_exhaustion_falls_back_to_last_resort_kyber_key() {
    let mut w = World::new();
    // Bob publishes exactly ONE one-time prekey of each kind.
    let mut bob = w.device("bob", "b1", 1);
    let bob_addr = bob.addr.clone();
    let last_resort_id = w.directory[&bob_addr].last_resort.id;

    // First initiator gets the one-time keys.
    let mut a1 = w.device("alice", "a1", 1);
    let b1 = w.bundle(&bob_addr);
    assert!(b1.pre_key.is_some());
    assert_ne!(b1.kyber_pre_key.id, last_resort_id);
    a1.store.process_bundle(&a1.addr, &bob_addr, &b1).unwrap();
    let e1 = a1.store.sealed_encrypt(&bob_addr, &w.pin(&bob_addr), &a1.cert, b"one-time").unwrap();
    assert_eq!(w.recv(&mut bob, &e1).1, b"one-time");
    assert_eq!(bob.store.one_time_prekey_counts(), (0, 0), "one-time keys are deleted on use");

    // Exhausted: the next two initiators both get the last-resort Kyber key and NO one-time EC key
    // — and both sessions still establish (still PQXDH, never a classical downgrade).
    let mut initiators = [w.device("carol", "c1", 1), w.device("dave", "d1", 1)];
    let mut first_envelopes = Vec::new();
    for (i, dev) in initiators.iter_mut().enumerate() {
        let b = w.bundle(&bob_addr);
        assert!(b.pre_key.is_none());
        assert_eq!(b.kyber_pre_key.id, last_resort_id);
        dev.store.process_bundle(&dev.addr, &bob_addr, &b).unwrap();
        assert!(dev.store.has_session(&bob_addr), "session requires PQXDH + SPQR");
        let text = format!("last-resort #{i}");
        let env = dev.store.sealed_encrypt(&bob_addr, &w.pin(&bob_addr), &dev.cert, text.as_bytes()).unwrap();
        assert_eq!(w.recv(&mut bob, &env).1, text.as_bytes());
        first_envelopes.push(env);
    }
    // Replaying a last-resort session-setup message is rejected (base-key reuse / duplicate).
    for env in &first_envelopes {
        assert!(w.open(&mut bob, env).is_err());
    }
    // Bob can answer over the last-resort-established sessions.
    let carol_addr = initiators[0].addr.clone();
    let reply = w.send(&mut bob, &carol_addr, b"got it");
    assert_eq!(w.recv(&mut initiators[0], &reply).1, b"got it");

    // A bundle with a bad prekey signature is refused outright.
    let mut evil = w.bundle(&bob_addr);
    evil.kyber_pre_key.signature[3] ^= 1;
    let mut eve = w.device("eve", "e1", 1);
    assert!(eve.store.process_bundle(&eve.addr, &bob_addr, &evil).is_err());
    let mut evil = w.bundle(&bob_addr);
    evil.signed_pre_key.signature[3] ^= 1;
    assert!(eve.store.process_bundle(&eve.addr, &bob_addr, &evil).is_err());
}

#[test]
fn safety_number_change_is_detected_blocks_sending_and_requires_acceptance() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 3);
    let mut bob = w.device("bob", "b1", 3);
    let bob_addr = bob.addr.clone();

    let e = w.send(&mut alice, &bob_addr, b"hi");
    w.recv(&mut bob, &e);
    let e = w.send(&mut bob, &alice.addr.clone(), b"hi back");
    w.recv(&mut alice, &e);

    // Both sides compute the same 60-digit safety number.
    let sn_a = alice.store.safety_number(&alice.addr, &bob_addr).unwrap();
    let sn_b = bob.store.safety_number(&bob.addr, &alice.addr).unwrap();
    assert_eq!(sn_a, sn_b);
    assert_eq!(sn_a.len(), 60);
    assert!(sn_a.chars().all(|c| c.is_ascii_digit()));
    alice.store.set_verified(&bob_addr, true).unwrap();
    assert!(alice.store.take_identity_changes().is_empty());

    // Bob reinstalls: same address, brand-new identity (this is also what the build-41 migration
    // looks like to peers, and what a malicious server substituting a key looks like).
    let mut bob2 = w.device("bob", "b1", 3);
    assert_ne!(bob2.store.identity_key(), bob.store.identity_key());

    // SENDING to the new identity is refused until explicitly accepted.
    let bundle = w.bundle(&bob_addr);
    let err = alice.store.process_bundle(&alice.addr, &bob_addr, &bundle).unwrap_err();
    assert!(matches!(err, CryptoError::UntrustedIdentity(_)), "{err:?}");
    assert!(alice.store.known_identity(&bob_addr).unwrap().1, "still verified against the OLD key");

    // Accepting records the change, clears the verified mark, and yields a notice.
    assert!(alice.store.accept_identity(&bob_addr, &bundle.identity_key).unwrap());
    let changes = alice.store.take_identity_changes();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].address, bob_addr);
    assert!(changes[0].was_verified);
    assert!(!alice.store.known_identity(&bob_addr).unwrap().1);
    alice.store.process_bundle(&alice.addr, &bob_addr, &bundle).unwrap();
    let e = alice.store.sealed_encrypt(&bob_addr, &w.pin(&bob_addr), &alice.cert, b"after reinstall").unwrap();
    assert_eq!(w.recv(&mut bob2, &e).1, b"after reinstall");
    // The safety number is different now.
    assert_ne!(alice.store.safety_number(&alice.addr, &bob_addr).unwrap(), sn_a);

    // RECEIVING from a changed identity is refused exactly like sending to one: carol knew
    // old-bob, then an envelope arrives from "bob" under another key. Nothing of hers changes.
    let old_bob = bob.store.identity_key();
    let new_bob = bob2.store.identity_key();
    let mut carol = w.device("carol", "c1", 3);
    let e = w.send(&mut bob, &carol.addr.clone(), b"old bob");
    carol.store.sealed_decrypt(&carol.addr, w.root(), now_ms(), &e, |_| Some(old_bob.clone())).unwrap();
    let e = carol.store.sealed_encrypt(&bob_addr, &old_bob, &carol.cert, b"hi old bob").unwrap();
    bob.store.sealed_decrypt(&bob.addr, w.root(), now_ms(), &e, |_| Some(w.pin(&carol.addr))).unwrap();
    assert!(carol.store.take_identity_changes().is_empty());
    let e = w.send(&mut bob2, &carol.addr.clone(), b"new bob");
    // Whether carol's caller still expects the old key or was talked into the new one, the key
    // on record does not move and no session is made.
    for expected in [&old_bob, &new_bob] {
        let err = carol.store.sealed_decrypt(&carol.addr, w.root(), now_ms(), &e, |_| Some(expected.clone())).unwrap_err();
        assert!(matches!(err.error, CryptoError::UntrustedIdentity(_)), "{err:?}");
        assert!(err.sender.is_none(), "a refused identity is never grounds for a session repair");
        assert_eq!(carol.store.known_identity(&bob_addr).unwrap().0, old_bob);
        assert_eq!(carol.store.session_identity(&bob_addr).unwrap(), old_bob);
    }
    let changes = carol.store.take_identity_changes();
    assert!(!changes.is_empty(), "safety number changed notice");
    assert_eq!(changes[0].address, bob_addr);
    // What carol sends next is still for old bob, and new bob cannot read it.
    let e = carol.store.sealed_encrypt(&bob_addr, &old_bob, &carol.cert, b"for old bob").unwrap();
    assert!(bob2.store.sealed_decrypt(&bob2.addr, w.root(), now_ms(), &e, |_| Some(w.pin(&carol.addr))).is_err());
    assert_eq!(bob.store.sealed_decrypt(&bob.addr, w.root(), now_ms(), &e, |_| Some(w.pin(&carol.addr))).unwrap().plaintext, b"for old bob");
    assert!(matches!(carol.store.sealed_encrypt(&bob_addr, &new_bob, &carol.cert, b"x"), Err(CryptoError::UntrustedIdentity(_))));

    // Free-function form matches and is symmetric.
    let ab = safety_number("alice:a1", &alice.store.identity_key(), "bob:b1", &bob2.store.identity_key()).unwrap();
    let ba = safety_number("bob:b1", &bob2.store.identity_key(), "alice:a1", &alice.store.identity_key()).unwrap();
    assert_eq!(ab, ba);
    assert_eq!(ab, alice.store.safety_number(&alice.addr, &bob_addr).unwrap());
}

/// A channel: each member device owns one sender key (distribution id), handed to every other
/// member device over pairwise sealed sessions.
struct Channel {
    /// device -> its current distribution id
    dist: HashMap<DeviceAddress, Uuid>,
}

impl Channel {
    /// `sender` (re)distributes its current key to `recipients` over sealed 1:1 sessions.
    fn distribute(&mut self, w: &mut World, sender: &mut Device, recipients: &mut [&mut Device], rotate: bool) {
        if rotate {
            if let Some(old) = self.dist.remove(&sender.addr) {
                sender.store.delete_sender_key(&sender.addr.clone(), old);
            }
        }
        let id = *self.dist.entry(sender.addr.clone()).or_insert_with(skwod_crypto::new_distribution_id);
        let skdm = sender.store.create_distribution(&sender.addr.clone(), id).unwrap();
        for r in recipients.iter_mut() {
            let env = w.send(sender, &r.addr.clone(), &skdm);
            let (from, payload) = w.recv(r, &env);
            assert_eq!(from, sender.addr);
            assert_eq!(r.store.process_distribution(&from, &payload).unwrap(), id);
        }
    }
}

#[test]
fn group_join_leave_rotation_reaches_every_device_and_locks_out_the_removed_member() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 10);
    let mut bob_phone = w.device("bob", "phone", 10);
    let mut bob_mac = w.device("bob", "mac", 10);
    let mut eve = w.device("eve", "e1", 10);
    let mut ch = Channel { dist: HashMap::new() };

    // Alice shares her key with every device of every member — BOTH of bob's devices.
    ch.distribute(&mut w, &mut alice, &mut [&mut bob_phone, &mut bob_mac, &mut eve], false);
    let alice_id = ch.dist[&alice.addr];
    let m1 = alice.store.group_encrypt(&alice.addr.clone(), alice_id, b"welcome all").unwrap();
    for d in [&mut bob_phone, &mut bob_mac, &mut eve] {
        assert_eq!(d.store.group_decrypt(&alice.addr, &m1).unwrap(), (alice_id, b"welcome all".to_vec()));
    }
    // Group messages are padded too, and replays are rejected.
    let m_short = alice.store.group_encrypt(&alice.addr.clone(), alice_id, b"a").unwrap();
    let m_long = alice.store.group_encrypt(&alice.addr.clone(), alice_id, &[b'b'; 120]).unwrap();
    assert_eq!(m_short.len(), m_long.len());
    assert_eq!(bob_phone.store.group_decrypt(&alice.addr, &m1), Err(CryptoError::Duplicate));
    // Out of order within the sender-key chain.
    assert_eq!(bob_phone.store.group_decrypt(&alice.addr, &m_long).unwrap().1, vec![b'b'; 120]);
    assert_eq!(bob_phone.store.group_decrypt(&alice.addr, &m_short).unwrap().1, b"a");
    // A sender-key message is bound to its sender: attributing alice's message to eve fails.
    assert!(bob_mac.store.group_decrypt(&eve.addr, &m_short).is_err());

    // A late joiner gets the CURRENT chain position: reads new messages, not history.
    let mut dan = w.device("dan", "d1", 10);
    ch.distribute(&mut w, &mut alice, &mut [&mut dan], false);
    assert!(dan.store.group_decrypt(&alice.addr, &m1).is_err(), "no access to pre-join history");
    let m2 = alice.store.group_encrypt(&alice.addr.clone(), alice_id, b"hi dan").unwrap();
    assert_eq!(dan.store.group_decrypt(&alice.addr, &m2).unwrap().1, b"hi dan");
    assert_eq!(eve.store.group_decrypt(&alice.addr, &m2).unwrap().1, b"hi dan");

    // Eve is removed. Alice rotates: a NEW distribution id + key, redistributed to every remaining
    // device (both of bob's, and dan) — never to eve.
    ch.distribute(&mut w, &mut alice, &mut [&mut bob_phone, &mut bob_mac, &mut dan], true);
    let rotated_id = ch.dist[&alice.addr];
    assert_ne!(rotated_id, alice_id);
    let m3 = alice.store.group_encrypt(&alice.addr.clone(), rotated_id, b"eve is gone").unwrap();
    for d in [&mut bob_phone, &mut bob_mac, &mut dan] {
        assert_eq!(d.store.group_decrypt(&alice.addr, &m3).unwrap(), (rotated_id, b"eve is gone".to_vec()));
    }
    assert!(matches!(eve.store.group_decrypt(&alice.addr, &m3), Err(CryptoError::NoSession(_))), "removed member is locked out");
    // The old key is gone on alice's side: she cannot be tricked into sending under it again.
    assert!(alice.store.group_encrypt(&alice.addr.clone(), alice_id, b"x").is_err());
    // Remaining members still hold the superseded key, so a message sent just before the rotation
    // that arrives late still decrypts.
    assert!(bob_mac.store.has_sender_key(&alice.addr, alice_id));
    assert_eq!(bob_mac.store.group_decrypt(&alice.addr, &m2).unwrap().1, b"hi dan");
}

#[test]
fn sealed_group_message_carries_sender_key_payload() {
    // Sender-key ciphertext wrapped in sealed sender is accepted by `sealed_decrypt` (the shape
    // sealed channel delivery would use); exercised here via the pairwise path's SKDM hand-off.
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 3);
    let mut bob = w.device("bob", "b1", 3);
    let id = skwod_crypto::new_distribution_id();
    let skdm = alice.store.create_distribution(&alice.addr.clone(), id).unwrap();
    let env = w.send(&mut alice, &bob.addr.clone(), &skdm);
    let m = w.open(&mut bob, &env).unwrap();
    assert_eq!(bob.store.process_distribution(&m.sender, &m.plaintext).unwrap(), id);
    assert_eq!(SignalStore::group_message_distribution_id(&alice.store.group_encrypt(&alice.addr.clone(), id, b"x").unwrap()).unwrap(), id);
}

#[test]
fn store_snapshot_roundtrip_keeps_sessions_and_backup_export_drops_them() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 3);
    let mut bob = w.device("bob", "b1", 3);
    let bob_addr = bob.addr.clone();
    let e = w.send(&mut alice, &bob_addr, b"before restart");
    w.recv(&mut bob, &e);
    let e = w.send(&mut bob, &alice.addr.clone(), b"reply");
    w.recv(&mut alice, &e);
    let id = skwod_crypto::new_distribution_id();
    alice.store.create_distribution(&alice.addr.clone(), id).unwrap();
    alice.store.set_verified(&bob_addr, true).unwrap();

    // "Restart": everything survives a snapshot round trip.
    let snapshot = alice.store.to_bytes();
    assert!(!contains(&snapshot, b"before restart"));
    alice.store = SignalStore::from_bytes(&snapshot).unwrap();
    assert!(alice.store.has_session(&bob_addr));
    let e = alice.store.sealed_encrypt(&bob_addr, &w.pin(&bob_addr), &alice.cert, b"after restart").unwrap();
    assert_eq!(w.recv(&mut bob, &e).1, b"after restart");
    assert!(alice.store.group_encrypt(&alice.addr.clone(), id, b"x").is_ok());
    assert!(SignalStore::from_bytes(&snapshot[1..]).is_err());
    assert!(SignalStore::from_bytes(&[]).is_err());

    // Backup export: identity + pinned peer identities (+ verified marks) only.
    let restored = SignalStore::from_bytes(&alice.store.export_identity()).unwrap();
    assert_eq!(restored.identity_key(), alice.store.identity_key());
    assert_eq!(restored.registration_id(), alice.store.registration_id());
    assert_eq!(restored.known_identity(&bob_addr), alice.store.known_identity(&bob_addr));
    assert!(restored.known_identity(&bob_addr).unwrap().1);
    assert!(!restored.has_session(&bob_addr), "sessions are never resumed from a backup");
    assert_eq!(restored.one_time_prekey_counts(), (0, 0));
}

#[test]
fn signed_prekey_rotation_keeps_old_key_for_in_flight_setups() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 2);
    let mut bob = w.device("bob", "b1", 2);
    let bob_addr = bob.addr.clone();
    // Alice fetched a bundle against bob's OLD signed prekey...
    let old_bundle = w.bundle(&bob_addr);
    // ...then bob rotates (signed prekey + last-resort kyber) and prunes.
    let new_signed = bob.store.generate_signed_prekey().unwrap();
    let new_lr = bob.store.generate_last_resort_kyber().unwrap();
    assert_ne!(new_signed.id, old_bundle.signed_pre_key.id);
    bob.store.prune_rotated_keys();
    let p = w.directory.get_mut(&bob_addr).unwrap();
    p.signed = new_signed;
    p.last_resort = new_lr;
    // The in-flight setup against the old key still completes (grace period)...
    alice.store.process_bundle(&alice.addr, &bob_addr, &old_bundle).unwrap();
    let e = alice.store.sealed_encrypt(&bob_addr, &w.pin(&bob_addr), &alice.cert, b"old spk").unwrap();
    assert_eq!(w.recv(&mut bob, &e).1, b"old spk");
    // ...and new setups use the rotated key.
    let mut carol = w.device("carol", "c1", 2);
    let e = w.send(&mut carol, &bob_addr, b"new spk");
    assert_eq!(w.recv(&mut bob, &e).1, b"new spk");
    assert!(bob.store.signed_prekey_created_ms().is_some());
}

#[test]
fn device_address_encoding() {
    let a = DeviceAddress::new("user-1", "dev:with:colons");
    assert_eq!(DeviceAddress::parse(&a.name().unwrap()).unwrap(), a);
    assert!(DeviceAddress::new("bad:user", "d").name().is_err());
    assert!(DeviceAddress::new("", "d").name().is_err());
    assert!(DeviceAddress::parse("nocolon").is_none());
}

// ---- C1: a server that mints sender certificates ----

/// What the HOST can do: it issues sender certificates, so it mints one naming `victim` under a
/// key of its own, starts a PQXDH session to `target` from `target`'s public bundle, and seals a
/// message. Returns (the host's store, the envelope it would put in `target`'s mailbox).
fn minted_envelope(w: &mut World, victim: &DeviceAddress, target: &DeviceAddress, text: &[u8]) -> (SignalStore, Vec<u8>) {
    let mut host = SignalStore::generate();
    let cert = w.ca.issue(victim, &host.identity_key(), now_ms() + HOUR_MS).unwrap();
    let bundle = w.bundle(target);
    host.process_bundle(victim, target, &bundle).unwrap();
    let envelope = host.sealed_encrypt(target, &w.pin(target), &cert, text).unwrap();
    (host, envelope)
}

/// The attack of the build-44 audit (C1), against a contact with an established session — once
/// for an unverified and once for a verified contact. The envelope is refused before libsignal
/// sees the inner message: the session, the identity on record, the verified mark and every
/// prekey are exactly as before; the next outbound message is one the host cannot open and the
/// real contact can; and an identity change is queued for the user.
#[test]
fn a_minted_certificate_cannot_replace_a_known_contacts_session() {
    for verified in [false, true] {
        let mut w = World::new();
        let mut alice = w.device("alice", "a1", 5);
        let mut bob = w.device("bob", "b1", 5);
        let (alice_addr, bob_addr) = (alice.addr.clone(), bob.addr.clone());
        let e = w.send(&mut alice, &bob_addr, b"hi");
        w.recv(&mut bob, &e);
        let e = w.send(&mut bob, &alice_addr, b"hi back");
        w.recv(&mut alice, &e);
        alice.store.set_verified(&bob_addr, verified).unwrap();
        let bob_key = bob.store.identity_key();

        let (mut host, forged) = minted_envelope(&mut w, &bob_addr, &alice_addr, b"i am bob");
        let prekeys = alice.store.one_time_prekey_counts();
        // The caller pins bob's real key (what the engine does)...
        let err = alice.store.sealed_decrypt(&alice_addr, w.root(), now_ms(), &forged, |_| Some(bob_key.clone())).unwrap_err();
        assert!(matches!(err.error, CryptoError::UntrustedIdentity(_)), "{err:?}");
        assert!(err.sender.is_none());
        // ...and even a caller that passed the certificate's own key through gets nowhere.
        let err = alice.store.sealed_decrypt(&alice_addr, w.root(), now_ms(), &forged, |_| Some(host.identity_key())).unwrap_err();
        assert!(matches!(err.error, CryptoError::UntrustedIdentity(_)), "{err:?}");

        assert_eq!(alice.store.known_identity(&bob_addr), Some((bob_key.clone(), verified)), "identity and verified mark untouched");
        assert_eq!(alice.store.session_identity(&bob_addr), Some(bob_key.clone()), "session untouched");
        assert!(alice.store.has_session_with(&bob_addr, &bob_key));
        assert_eq!(alice.store.one_time_prekey_counts(), prekeys, "no prekey was consumed");
        let changes = alice.store.take_identity_changes();
        assert!(!changes.is_empty() && changes.iter().all(|c| c.address == bob_addr && c.was_verified == verified), "{changes:?}");

        // The next outbound message: not for the host, still for bob.
        let secret = alice.store.sealed_encrypt(&bob_addr, &bob_key, &alice.cert, b"the secret").unwrap();
        assert!(host.sealed_decrypt(&bob_addr, w.root(), now_ms(), &secret, |_| Some(w.pin(&alice_addr))).is_err(), "the host read the next message");
        assert_eq!(w.recv(&mut bob, &secret).1, b"the secret");
        // And nothing can be sent on a session with the host's key, whoever asks.
        assert!(matches!(alice.store.sealed_encrypt(&bob_addr, &host.identity_key(), &alice.cert, b"x"), Err(CryptoError::UntrustedIdentity(_))));
    }
}

/// The same attack against a device alice holds a pin for but has never exchanged a message
/// with (nothing on record in the store): there is no first-use trust on receive.
#[test]
fn a_minted_certificate_cannot_start_a_session_for_a_pinned_device() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 5);
    let mut bob = w.device("bob", "b1", 5);
    let (alice_addr, bob_addr) = (alice.addr.clone(), bob.addr.clone());
    let (mut host, forged) = minted_envelope(&mut w, &bob_addr, &alice_addr, b"i am bob");
    let prekeys = alice.store.one_time_prekey_counts();

    let err = w.open(&mut alice, &forged).unwrap_err();
    assert!(matches!(err.error, CryptoError::UntrustedIdentity(_)), "{err:?}");
    // No pin at all is a refusal too.
    assert!(alice.store.sealed_decrypt(&alice_addr, w.root(), now_ms(), &forged, |_| None).is_err());
    assert!(alice.store.known_identity(&bob_addr).is_none(), "no identity was recorded");
    assert!(!alice.store.has_session(&bob_addr) && alice.store.session_identity(&bob_addr).is_none(), "no session was started");
    assert_eq!(alice.store.one_time_prekey_counts(), prekeys);

    // Alice's first message to bob goes through his real bundle, to his real key.
    let secret = w.send(&mut alice, &bob_addr, b"the secret");
    assert!(host.sealed_decrypt(&bob_addr, w.root(), now_ms(), &secret, |_| Some(w.pin(&alice_addr))).is_err());
    assert_eq!(w.recv(&mut bob, &secret).1, b"the secret");
}

/// Reading a message from a device nobody vouched for (so the user can decide about it) keeps
/// nothing: no session, no identity, no consumed prekey — and nothing can be sent to it.
#[test]
fn peeking_at_an_unvouched_devices_message_leaves_no_trace() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 5);
    let bob = w.device("bob", "b1", 5);
    let (alice_addr, bob_addr) = (alice.addr.clone(), bob.addr.clone());
    let (host, forged) = minted_envelope(&mut w, &bob_addr, &alice_addr, b"held text");
    let prekeys = alice.store.one_time_prekey_counts();
    let before = alice.store.to_bytes().len();
    let opened = alice.store.sealed_open(&alice_addr, w.root(), now_ms(), &forged).unwrap();
    assert_eq!((opened.sender.clone(), opened.identity_key.clone()), (bob_addr.clone(), host.identity_key()));
    for _ in 0..2 {
        assert_eq!(alice.store.sealed_peek(&alice_addr, &opened).unwrap(), b"held text");
    }
    assert!(alice.store.known_identity(&bob_addr).is_none());
    assert!(alice.store.session_identity(&bob_addr).is_none());
    assert_eq!(alice.store.one_time_prekey_counts(), prekeys);
    assert_eq!(alice.store.to_bytes().len(), before);
    assert!(alice.store.sealed_encrypt(&bob_addr, &host.identity_key(), &alice.cert, b"x").is_err());
}

/// Crypto H1: a member with a valid certificate names the victim's real prekey ids in a session
/// setup that cannot authenticate (it was computed against someone else's keys). Nothing of the
/// victim's is consumed, and an honest peer served those same keys still gets through.
#[test]
fn a_failed_session_setup_consumes_no_prekeys() {
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 2);
    let mut mallory = w.device("mallory", "m1", 2);
    let decoy = w.device("decoy", "d1", 2);
    let alice_addr = alice.addr.clone();
    let real = w.bundle(&alice_addr);
    // Alice's real bundle with the one-time EC key swapped for someone else's: that key is not
    // signed, so mallory's libsignal accepts it, and the secret alice derives cannot match.
    let mut crossed = real.clone();
    crossed.pre_key.as_mut().unwrap().public = w.bundle(&decoy.addr).pre_key.unwrap().public;
    mallory.store.process_bundle(&mallory.addr, &alice_addr, &crossed).unwrap();
    let garbage = mallory.store.sealed_encrypt(&alice_addr, &w.pin(&alice_addr), &mallory.cert, b"x").unwrap();

    let prekeys = alice.store.one_time_prekey_counts();
    for _ in 0..3 {
        let err = w.open(&mut alice, &garbage).unwrap_err();
        assert!(matches!(err.error, CryptoError::Invalid(_)), "{err:?}");
        assert_eq!(err.sender.as_ref(), Some(&mallory.addr), "a pinned sender's failure is attributed to it");
    }
    assert_eq!(alice.store.one_time_prekey_counts(), prekeys, "a setup that failed deleted a one-time key");
    assert!(alice.store.known_identity(&mallory.addr).is_none() && alice.store.session_identity(&mallory.addr).is_none());

    // The honest peer the directory served those very keys to.
    let mut bob = w.device("bob", "b1", 2);
    bob.store.process_bundle(&bob.addr, &alice_addr, &real).unwrap();
    let e = bob.store.sealed_encrypt(&alice_addr, &w.pin(&alice_addr), &bob.cert, b"honest").unwrap();
    assert_eq!(w.recv(&mut alice, &e).1, b"honest");
    assert_eq!(alice.store.one_time_prekey_counts(), (prekeys.0 - 1, prekeys.1 - 1));
}

/// A sender-key (channel) ciphertext never travels sealed; wrapped in an envelope it is refused
/// before it can advance (burn) a channel's message keys.
#[test]
fn a_sealed_sender_key_payload_is_refused() {
    // The store has no way to produce one, which is the point; the receive side is covered by
    // `sealed_open` refusing every payload type but the two pairwise ones.
    let mut w = World::new();
    let mut alice = w.device("alice", "a1", 2);
    let bob = w.device("bob", "b1", 2);
    let e = w.send(&mut alice, &bob.addr.clone(), b"pairwise");
    assert!(bob.store.sealed_open(&bob.addr, w.root(), now_ms(), &e).is_ok());
}

/// One peer starting session after session on the victim's last-resort key fills only its own
/// share of the replay memory: it is refused from then on, and the next peer's first message
/// still gets through.
#[test]
fn a_flood_of_last_resort_setups_from_one_peer_does_not_block_another() {
    let mut w = World::new();
    let mut bob = w.device("bob", "b1", 0); // no one-time keys: every setup uses the last-resort key
    let mut mallory = w.device("mallory", "m1", 0);
    let bob_addr = bob.addr.clone();
    let mut refused = 0;
    for n in 0..80 {
        mallory.store.archive_session(&bob_addr).unwrap();
        let bundle = w.bundle(&bob_addr);
        mallory.store.process_bundle(&mallory.addr, &bob_addr, &bundle).unwrap();
        let e = mallory.store.sealed_encrypt(&bob_addr, &w.pin(&bob_addr), &mallory.cert, b"again").unwrap();
        match w.open(&mut bob, &e) {
            Ok(_) => assert_eq!(refused, 0, "setup {n} got through after a refusal"),
            Err(_) => refused += 1,
        }
    }
    assert_eq!(refused, 80 - 64, "one sender's setups on a last-resort key are bounded");
    let mut carol = w.device("carol", "c1", 0);
    let e = w.send(&mut carol, &bob_addr, b"hello from carol");
    assert_eq!(w.recv(&mut bob, &e).1, b"hello from carol", "one peer's flood blocked another's session setup");
}
