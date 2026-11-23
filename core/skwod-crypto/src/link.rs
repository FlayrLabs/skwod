//! Device linking: how a second (third, …) device joins an account without the server — or
//! anyone holding a stolen session token — being able to add one.
//!
//! The new device shows a one-time **link code** (80 random bits). The user types it into a device
//! that is already on the account. That single code authenticates both directions:
//!
//! - the new device publishes `request_proof = HMAC(code, "skwod-link-request-v1" ‖ user ‖ new_ik)`;
//!   the existing device only approves a request whose proof verifies under the typed code, so it
//!   signs the identity key of the device the user is actually holding, not one the server swapped in;
//! - the existing device answers with a **link signature** (its libsignal identity key over
//!   `"skwod-device-link-v1" ‖ user ‖ new_ik`) and
//!   `approval_mac = HMAC(code, "skwod-link-approval-v1" ‖ user ‖ linker_ik ‖ new_ik)`;
//!   the new device only trusts a linker whose MAC verifies, so the server cannot present a
//!   device of its own as the linker.
//!
//! The server stores the link signature with the new device and refuses to register a non-first
//! device without one; every sibling can verify it. The code never leaves the two devices.
//!
//! Primitives: libsignal identity-key signatures (XEdDSA), HMAC-SHA256 (RustCrypto).

use hmac::{Hmac, Mac};
use rand::TryRngCore as _;
use libsignal_protocol::IdentityKey;
use sha2::{Digest, Sha256};

const LINK_TAG: &[u8] = b"skwod-device-link-v1";
const REQUEST_TAG: &[u8] = b"skwod-link-request-v1";
const APPROVAL_TAG: &[u8] = b"skwod-link-approval-v1";

fn framed(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out = tag.to_vec();
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// The message an existing device signs to vouch for a new device of the same account.
pub fn link_message(user_id: &str, new_identity_key: &[u8]) -> Vec<u8> {
    framed(LINK_TAG, &[user_id.as_bytes(), new_identity_key])
}

/// Order of the Ed25519 group, little-endian.
const GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Is this a 64-byte XEdDSA signature whose scalar `S` is canonical (`S < L`)?
///
/// libsignal's verifier reduces `S` modulo the group order and only rejects `S ≥ 2^253`, so for a
/// valid signature `(R, S)` the encoding `(R, S + L)` verifies too. That malleability is harmless
/// for message authentication, but our signatures are *authorizations*; we refuse any encoding
/// other than the canonical one so a signature has exactly one accepted form.
pub fn is_canonical_signature(signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&signature[32..]);
    s[31] &= 0x7f; // XEdDSA carries the public key's sign bit here
    for i in (0..32).rev() {
        if s[i] != GROUP_ORDER_LE[i] {
            return s[i] < GROUP_ORDER_LE[i];
        }
    }
    false // S == L
}

/// Stable identifier of *what was signed* by a device proof — the server's replay key. Keyed on
/// the signed message, never on the signature bytes, so no re-encoding of a signature (and no
/// second signature over the same request) can be presented as a new proof.
pub fn device_op_id(op: &str, user_id: &str, target: &str, timestamp_ms: u64, payload: &[u8]) -> [u8; 32] {
    Sha256::digest(device_op_message(op, user_id, target, timestamp_ms, payload)).into()
}

/// Verify a link signature: did the device with `linker_identity_key` vouch for `new_identity_key`
/// on account `user_id`?
pub fn verify_link(linker_identity_key: &[u8], user_id: &str, new_identity_key: &[u8], signature: &[u8]) -> bool {
    let Ok(linker) = IdentityKey::decode(linker_identity_key) else { return false };
    is_canonical_signature(signature) && IdentityKey::decode(new_identity_key).is_ok() && linker.public_key().verify_signature(&link_message(user_id, new_identity_key), signature)
}

const MEMBER_APPROVAL_TAG: &[u8] = b"skwod-member-approval-v1";

/// The message an approver's device signs to say "`member_user_id` is a member of `server_id`"
/// (as of `timestamp_ms`). Clients hand channel, space and voice keys to a user they have not
/// seen in that server before only on the strength of such a signature from someone they already
/// trust there — the server listing a member is not enough (docs/DECISIONS.md ADR-012).
pub fn member_approval_message(server_id: &str, member_user_id: &str, approver_user_id: &str, timestamp_ms: i64) -> Vec<u8> {
    framed(MEMBER_APPROVAL_TAG, &[server_id.as_bytes(), member_user_id.as_bytes(), approver_user_id.as_bytes(), &timestamp_ms.to_be_bytes()])
}

/// Verify a member approval under the approver device's identity key.
pub fn verify_member_approval(
    approver_identity_key: &[u8],
    server_id: &str,
    member_user_id: &str,
    approver_user_id: &str,
    timestamp_ms: i64,
    signature: &[u8],
) -> bool {
    let Ok(identity) = IdentityKey::decode(approver_identity_key) else { return false };
    is_canonical_signature(signature)
        && identity.public_key().verify_signature(&member_approval_message(server_id, member_user_id, approver_user_id, timestamp_ms), signature)
}

const ACCOUNT_FP_TAG: &[u8] = b"skwod-account-fingerprint-v1";
const ACCOUNT_FP_ITERATIONS: usize = 5200;

/// One account's half of the account safety number: 30 digits derived from the user id and the
/// SORTED set of that account's device identity keys (iterated SHA-512, the construction of
/// Signal's numeric fingerprint, over a key set instead of a single key).
fn account_fingerprint(user_id: &str, identity_keys: &[Vec<u8>]) -> String {
    use sha2::Sha512;
    let mut keys: Vec<&Vec<u8>> = identity_keys.iter().collect();
    keys.sort();
    keys.dedup();
    let parts: Vec<&[u8]> = std::iter::once(user_id.as_bytes()).chain(keys.iter().map(|k| k.as_slice())).collect();
    let material = framed(ACCOUNT_FP_TAG, &parts);
    let mut hash = Sha512::digest(&material).to_vec();
    for _ in 1..ACCOUNT_FP_ITERATIONS {
        let mut h = Sha512::new();
        h.update(&hash);
        h.update(&material);
        hash = h.finalize().to_vec();
    }
    hash.chunks(5)
        .take(6)
        .map(|c| {
            let n = c.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect()
}

/// The 60-digit **account** safety number between two users: one number per pair of accounts,
/// computed over each side's sorted device-identity set, identical on both sides. It changes
/// whenever either account's device set changes, so "verified" means "verified for exactly these
/// devices". Empty key sets are refused.
pub fn account_safety_number(a_user_id: &str, a_identity_keys: &[Vec<u8>], b_user_id: &str, b_identity_keys: &[Vec<u8>]) -> Option<String> {
    if a_identity_keys.is_empty() || b_identity_keys.is_empty() {
        return None;
    }
    let a = account_fingerprint(a_user_id, a_identity_keys);
    let b = account_fingerprint(b_user_id, b_identity_keys);
    Some(if a <= b { format!("{a}{b}") } else { format!("{b}{a}") })
}

/// The two 30-digit halves of the account safety number, NOT sorted: `(a's fingerprint, b's
/// fingerprint)`. The safety number is these two in sorted order; the QR code needs to know which
/// half is whose (see [`safety_qr_payload`]).
pub fn account_fingerprints(a_user_id: &str, a_identity_keys: &[Vec<u8>], b_user_id: &str, b_identity_keys: &[Vec<u8>]) -> Option<(String, String)> {
    if a_identity_keys.is_empty() || b_identity_keys.is_empty() {
        return None;
    }
    Some((account_fingerprint(a_user_id, a_identity_keys), account_fingerprint(b_user_id, b_identity_keys)))
}

/// Is `displayed` (what the user compared; whitespace ignored) the safety number `current`?
pub fn same_safety_number(displayed: &str, current: &str) -> bool {
    let displayed: String = displayed.chars().filter(|c| !c.is_whitespace()).collect();
    current.len() == 60 && displayed.len() == current.len() && bool::from(subtle::ConstantTimeEq::ct_eq(displayed.as_bytes(), current.as_bytes()))
}

/// Prefix of a safety-number QR payload (version 2: direction-specific).
pub const SAFETY_QR_PREFIX: &str = "skwod-safety:2:";

/// What the safety-number QR code carries: `PREFIX ‖ presenter's fingerprint ‖ the fingerprint
/// the presenter holds for the scanner`. Unlike the 60-digit number (sorted, the same on both
/// sides) this is DIRECTIONAL, as in Signal: the code on my screen is not the code on yours, so
/// scanning my own screen, or a picture of my own code, does not match.
pub fn safety_qr_payload(my_fingerprint: &str, their_fingerprint: &str) -> String {
    format!("{SAFETY_QR_PREFIX}{my_fingerprint}{their_fingerprint}")
}

/// Compare a scanned payload with what the OTHER party's screen must show if nobody is in the
/// middle: their fingerprint as I hold it first, then mine. `None` = not a (current) safety code
/// at all; `Some(false)` = a safety code that does not match — including my own.
pub fn safety_qr_matches(scanned: &str, my_fingerprint: &str, their_fingerprint: &str) -> Option<bool> {
    let digits = scanned.trim().strip_prefix(SAFETY_QR_PREFIX)?;
    if digits.len() != 60 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let expected = format!("{their_fingerprint}{my_fingerprint}");
    // Not secret, but compare in constant time anyway: it costs nothing.
    Some(expected.len() == 60 && bool::from(subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), digits.as_bytes())))
}

const DEVICE_OP_TAG: &[u8] = b"skwod-device-op-v1";

/// The message a device signs to authorize an account-security operation (`op`: `"delete"`,
/// `"cancel-reset"`, `"set-pin"`, `"backup-put"`, `"backup-delete"`, `"delivery-key"`). A session
/// token alone must never be enough for these; the request has to come from a device holding an
/// identity key currently registered on the account.
///
/// The signature covers the operation, the account, the target, a timestamp **and a SHA-256 of
/// the request payload** — so a captured proof cannot be replayed with different contents (a
/// different PIN, a different backup blob). The server additionally accepts each signature once.
pub fn device_op_message(op: &str, user_id: &str, target: &str, timestamp_ms: u64, payload: &[u8]) -> Vec<u8> {
    framed(DEVICE_OP_TAG, &[op.as_bytes(), user_id.as_bytes(), target.as_bytes(), &timestamp_ms.to_be_bytes(), &Sha256::digest(payload)])
}

/// Canonical payload bytes for a multi-field request (length-prefixed concatenation).
pub fn op_payload(parts: &[&[u8]]) -> Vec<u8> {
    framed(b"", parts)
}

/// Verify a device-operation signature under `identity_key`.
pub fn verify_device_op(identity_key: &[u8], op: &str, user_id: &str, target: &str, timestamp_ms: u64, payload: &[u8], signature: &[u8]) -> bool {
    let Ok(identity) = IdentityKey::decode(identity_key) else { return false };
    is_canonical_signature(signature) && identity.public_key().verify_signature(&device_op_message(op, user_id, target, timestamp_ms, payload), signature)
}

/// A fresh link code: 80 random bits as `XXXX-XXXX-XXXX-XXXX` (Crockford base32).
pub fn generate_code() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bytes: [u8; 10] = crate::random_bytes();
    let mut out = String::with_capacity(19);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            if n > 0 && n % 4 == 0 {
                out.push('-');
            }
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
            n += 1;
        }
    }
    out
}

/// Canonical form of a typed code: uppercase, separators dropped, look-alikes folded.
pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

fn mac(code: &str, msg: &[u8]) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(normalize_code(code).as_bytes()).expect("HMAC accepts any key length");
    m.update(msg);
    m.finalize().into_bytes().to_vec()
}

fn mac_ok(code: &str, msg: &[u8], tag: &[u8]) -> bool {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(normalize_code(code).as_bytes()).expect("HMAC accepts any key length");
    m.update(msg);
    m.verify_slice(tag).is_ok()
}

/// New device → existing device: proof that this request was made by whoever shows `code`.
pub fn request_proof(code: &str, user_id: &str, new_identity_key: &[u8]) -> Vec<u8> {
    mac(code, &framed(REQUEST_TAG, &[user_id.as_bytes(), new_identity_key]))
}

pub fn verify_request_proof(code: &str, user_id: &str, new_identity_key: &[u8], proof: &[u8]) -> bool {
    mac_ok(code, &framed(REQUEST_TAG, &[user_id.as_bytes(), new_identity_key]), proof)
}

/// Existing device → new device: proof that the linker is the device the code was typed into.
pub fn approval_mac(code: &str, user_id: &str, linker_identity_key: &[u8], new_identity_key: &[u8]) -> Vec<u8> {
    mac(code, &framed(APPROVAL_TAG, &[user_id.as_bytes(), linker_identity_key, new_identity_key]))
}

pub fn verify_approval_mac(code: &str, user_id: &str, linker_identity_key: &[u8], new_identity_key: &[u8], tag: &[u8]) -> bool {
    mac_ok(code, &framed(APPROVAL_TAG, &[user_id.as_bytes(), linker_identity_key, new_identity_key]), tag)
}

const BUNDLE_TAG: &[u8] = b"skwod-link-bundle-v2";

/// The AEAD key of a link bundle: HKDF-SHA256 over the ECDH secret between the linker's fresh
/// ephemeral key and the NEW device's identity key, salted with a MAC under the link code over
/// the account and all three public keys.
///
/// - The **DH secret** is what keeps it confidential: the server stores the ciphertext, and the
///   link code is shown on a screen (and may be photographed). Code + ciphertext without the new
///   device's identity PRIVATE key decrypts nothing. The linker's half is ephemeral and thrown
///   away, so the linker's long-term key cannot open it later either.
/// - The **code MAC** is what authenticates it: only the device the user typed the code into can
///   make a bundle this device will open — the server cannot substitute one of its own.
fn bundle_key(code: &str, user_id: &str, linker_identity_key: &[u8], new_identity_key: &[u8], ephemeral_public: &[u8], dh: &[u8]) -> [u8; 32] {
    let salt = mac(code, &framed(BUNDLE_TAG, &[user_id.as_bytes(), linker_identity_key, new_identity_key, ephemeral_public]));
    let mut key = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(&salt), dh).expand(BUNDLE_TAG, &mut key).expect("32 bytes is a valid HKDF-SHA256 length");
    key
}

/// Existing device → new device, with the approval: what the new device needs from a sibling it
/// cannot yet be sent a sealed message (it has no device id until it registers) — the sibling
/// set, the account key, space keys, owner pins. Encrypted TO the new device's identity key
/// (see [`bundle_key`]) and authenticated by the link code. Output: `ephemeral public ‖ sealed`.
/// The server relays it and learns nothing; neither does anyone who later sees the code.
pub fn seal_bundle(code: &str, user_id: &str, linker_identity_key: &[u8], new_identity_key: &[u8], bundle: &[u8]) -> Option<Vec<u8>> {
    let recipient = IdentityKey::decode(new_identity_key).ok()?;
    let ephemeral = libsignal_protocol::KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
    let ephemeral_public = ephemeral.public_key.serialize().to_vec();
    let dh = ephemeral.private_key.calculate_agreement(recipient.public_key()).ok()?;
    let key = bundle_key(code, user_id, linker_identity_key, new_identity_key, &ephemeral_public, &dh);
    let mut out = ephemeral_public;
    out.extend(crate::aead::seal(&key, BUNDLE_TAG, bundle));
    Some(out)
}

/// The new device's side of [`seal_bundle`]: `dh` computes the ECDH secret of this device's
/// identity PRIVATE key with the given ephemeral public key (`SignalStore::open_link_bundle`
/// supplies it). `None` unless the bundle was made with this code, for this device, by this
/// linker, for this account.
pub fn open_bundle_with(
    code: &str,
    user_id: &str,
    linker_identity_key: &[u8],
    new_identity_key: &[u8],
    sealed: &[u8],
    dh: impl FnOnce(&libsignal_protocol::PublicKey) -> Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    const PUBLIC_LEN: usize = 33;
    let (ephemeral_public, body) = sealed.split_at_checked(PUBLIC_LEN)?;
    let ephemeral = libsignal_protocol::PublicKey::deserialize(ephemeral_public).ok()?;
    let secret = dh(&ephemeral)?;
    let key = bundle_key(code, user_id, linker_identity_key, new_identity_key, ephemeral_public, &secret);
    crate::aead::open(&key, BUNDLE_TAG, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SignalStore;

    #[test]
    fn link_bundle_needs_the_code_and_the_new_devices_private_key() {
        let (linker, device) = (SignalStore::generate(), SignalStore::generate());
        let (code, a, b) = (generate_code(), linker.identity_key(), device.identity_key());
        let sealed = seal_bundle(&code, "u1", &a, &b, b"space keys").unwrap();
        assert_eq!(device.open_link_bundle(&code.to_lowercase(), "u1", &a, &sealed).as_deref(), Some(&b"space keys"[..]), "the code as typed");

        // What the server (or anyone who later photographs the code) has: the stored ciphertext,
        // the code, and every PUBLIC key. Without the new device's identity private key the
        // bundle does not open — not for a bystander, not for the linker's long-term key, and
        // not by pretending the DH secret is anything derivable from public values.
        let bystander = SignalStore::generate();
        assert!(bystander.open_link_bundle(&code, "u1", &a, &sealed).is_none(), "another key pair");
        assert!(open_bundle_with(&code, "u1", &a, &b, &sealed, |_| bystander_dh(&bystander, &b)).is_none(), "code + ciphertext + public keys only");
        assert!(linker.open_link_bundle(&code, "u1", &a, &sealed).is_none(), "the linker's long-term key (its half was ephemeral)");
        for guess in [vec![0u8; 32], b.clone(), a.clone(), sealed[..33].to_vec()] {
            assert!(open_bundle_with(&code, "u1", &a, &b, &sealed, |_| Some(guess)).is_none(), "a DH secret guessed from public data");
        }

        // And the code is what authenticates it: the right key with the wrong code, account,
        // linker or a bent ciphertext opens nothing.
        assert!(device.open_link_bundle(&generate_code(), "u1", &a, &sealed).is_none(), "another code");
        assert!(device.open_link_bundle(&code, "u2", &a, &sealed).is_none(), "another account");
        assert!(device.open_link_bundle(&code, "u1", &bystander.identity_key(), &sealed).is_none(), "another linker");
        let mut bent = sealed.clone();
        *bent.last_mut().unwrap() ^= 1;
        assert!(device.open_link_bundle(&code, "u1", &a, &bent).is_none(), "tampered in transit");
        // Two bundles for the same pair never share a key (fresh ephemeral each time).
        assert_ne!(sealed[..33], seal_bundle(&code, "u1", &a, &b, b"space keys").unwrap()[..33]);
    }

    /// The best a party WITHOUT `target`'s private key can do: agree with its own.
    fn bystander_dh(bystander: &SignalStore, target_public: &[u8]) -> Option<Vec<u8>> {
        let target = IdentityKey::decode(target_public).ok()?;
        bystander.identity_agreement(target.public_key())
    }

    #[test]
    fn member_approval_binds_server_member_approver_and_time() {
        let approver = SignalStore::generate();
        let sig = approver.sign_member_approval("s1", "newbie", "host", 1000).unwrap();
        let ik = approver.identity_key();
        assert!(verify_member_approval(&ik, "s1", "newbie", "host", 1000, &sig));
        assert!(!verify_member_approval(&ik, "s2", "newbie", "host", 1000, &sig));
        assert!(!verify_member_approval(&ik, "s1", "ghost", "host", 1000, &sig));
        assert!(!verify_member_approval(&ik, "s1", "newbie", "other", 1000, &sig));
        assert!(!verify_member_approval(&ik, "s1", "newbie", "host", 1001, &sig));
        assert!(!verify_member_approval(&SignalStore::generate().identity_key(), "s1", "newbie", "host", 1000, &sig));
        // Not interchangeable with a device link or a device op by the same key.
        assert!(!verify_link(&ik, "s1", &ik, &sig));
    }

    /// The QR code is directional: it matches only when the OTHER party scans it.
    #[test]
    fn safety_qr_matches_only_across_the_two_parties() {
        let k = |n: u8| vec![n; 33];
        let (alice, bob) = account_fingerprints("alice", &[k(1), k(2)], "bob", &[k(3)]).unwrap();
        let number = account_safety_number("alice", &[k(1), k(2)], "bob", &[k(3)]).unwrap();
        assert!(number == format!("{alice}{bob}") || number == format!("{bob}{alice}"));
        let on_alice = safety_qr_payload(&alice, &bob);
        let on_bob = safety_qr_payload(&bob, &alice);
        assert_ne!(on_alice, on_bob, "each side shows a different code");
        // Bob scans alice's screen, alice scans bob's: match.
        assert_eq!(safety_qr_matches(&on_alice, &bob, &alice), Some(true));
        assert_eq!(safety_qr_matches(&on_bob, &alice, &bob), Some(true));
        // Scanning my OWN code (my screen, or a screenshot of it) does not.
        assert_eq!(safety_qr_matches(&on_alice, &alice, &bob), Some(false));
        assert_eq!(safety_qr_matches(&on_bob, &bob, &alice), Some(false));
        // Someone in the middle: bob holds a different fingerprint for alice than her real one.
        let (mallory, _) = account_fingerprints("alice", &[k(7)], "bob", &[k(3)]).unwrap();
        assert_eq!(safety_qr_matches(&on_alice, &bob, &mallory), Some(false));
        // The sorted 60-digit number, a v1 payload, an invite, garbage: not a safety code.
        assert_eq!(safety_qr_matches(&number, &bob, &alice), None);
        assert_eq!(safety_qr_matches(&format!("skwod-safety:1:{number}"), &bob, &alice), None);
        assert_eq!(safety_qr_matches("skwod://join/abc#code", &bob, &alice), None);
        assert_eq!(safety_qr_matches(&format!("{SAFETY_QR_PREFIX}{}", "1".repeat(59)), &bob, &alice), None);
        assert!(account_fingerprints("alice", &[], "bob", &[k(3)]).is_none());
        // Comparing what was displayed: grouping whitespace is ignored, nothing else is.
        let grouped = number.as_bytes().chunks(5).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(" ");
        assert!(same_safety_number(&grouped, &number) && same_safety_number(&number, &number));
        assert!(!same_safety_number(&number[..59], &number) && !same_safety_number("", "") && !same_safety_number(&"0".repeat(60), &number));
    }

    #[test]
    fn account_safety_number_is_symmetric_and_tracks_the_device_set() {
        let k = |n: u8| vec![n; 33];
        let ab = account_safety_number("alice", &[k(1), k(2)], "bob", &[k(3)]).unwrap();
        assert_eq!(ab.len(), 60);
        assert!(ab.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(ab, account_safety_number("bob", &[k(3)], "alice", &[k(2), k(1)]).unwrap(), "symmetric, order-free");
        assert_ne!(ab, account_safety_number("alice", &[k(1), k(2), k(9)], "bob", &[k(3)]).unwrap(), "a new device changes it");
        assert_ne!(ab, account_safety_number("alice", &[k(1)], "bob", &[k(3)]).unwrap(), "a removed device changes it");
        assert_ne!(ab, account_safety_number("alice", &[k(1), k(2)], "carol", &[k(3)]).unwrap());
        assert!(account_safety_number("alice", &[], "bob", &[k(3)]).is_none());
    }

    /// `(R, S)` → `(R, S + L)`: the same signature in the non-canonical encoding libsignal's raw
    /// verifier also accepts. `None` in the rare case `S + L` does not fit below 2^253.
    pub(crate) fn malleate(signature: &[u8]) -> Option<Vec<u8>> {
        let mut out = signature.to_vec();
        let sign_bit = out[63] & 0x80;
        out[63] &= 0x7f;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = out[32 + i] as u16 + GROUP_ORDER_LE[i] as u16 + carry;
            out[32 + i] = v as u8;
            carry = v >> 8;
        }
        if carry != 0 || out[63] & 0xe0 != 0 {
            return None;
        }
        out[63] |= sign_bit;
        Some(out)
    }

    #[test]
    fn non_canonical_signatures_are_refused() {
        let dev = SignalStore::generate();
        let ik = dev.identity_key();
        let identity = IdentityKey::decode(&ik).unwrap();
        let (sig, twin) = loop {
            let sig = dev.sign_device_op("set-pin", "u1", "enable", 7, b"482913").unwrap();
            if let Some(twin) = malleate(&sig) {
                break (sig, twin);
            }
        };
        assert_ne!(sig, twin);
        let msg = device_op_message("set-pin", "u1", "enable", 7, b"482913");
        // The premise: libsignal's own verifier accepts BOTH encodings...
        assert!(identity.public_key().verify_signature(&msg, &sig));
        assert!(identity.public_key().verify_signature(&msg, &twin), "malleable twin verifies at the libsignal layer");
        // ...ours accepts exactly one, for device operations and for link signatures.
        assert!(is_canonical_signature(&sig) && !is_canonical_signature(&twin));
        assert!(verify_device_op(&ik, "set-pin", "u1", "enable", 7, b"482913", &sig));
        assert!(!verify_device_op(&ik, "set-pin", "u1", "enable", 7, b"482913", &twin));
        let new_ik = SignalStore::generate().identity_key();
        let link = dev.sign_link("u1", &new_ik).unwrap();
        assert!(verify_link(&ik, "u1", &new_ik, &link));
        if let Some(twin) = malleate(&link) {
            assert!(!verify_link(&ik, "u1", &new_ik, &twin));
        }
        assert!(!is_canonical_signature(&sig[..63]));
        assert!(!is_canonical_signature(&[&[0u8; 32][..], &GROUP_ORDER_LE[..]].concat()), "S == L");
        // The replay id depends only on what was signed.
        assert_eq!(device_op_id("set-pin", "u1", "enable", 7, b"482913"), device_op_id("set-pin", "u1", "enable", 7, b"482913"));
        assert_ne!(device_op_id("set-pin", "u1", "enable", 7, b"482913"), device_op_id("set-pin", "u1", "enable", 8, b"482913"));
        assert_ne!(device_op_id("set-pin", "u1", "enable", 7, b"482913"), device_op_id("set-pin", "u1", "enable", 7, b"666666"));
    }

    #[test]
    fn link_signature_and_code_bind_both_directions() {
        let old = SignalStore::generate();
        let new = SignalStore::generate();
        let attacker = SignalStore::generate();
        let (old_ik, new_ik, bad_ik) = (old.identity_key(), new.identity_key(), attacker.identity_key());
        let code = generate_code();
        assert_eq!(code.len(), 19);
        assert_ne!(code, generate_code());

        // Request proof: only the identity key of the device showing the code passes.
        let proof = request_proof(&code, "u1", &new_ik);
        assert!(verify_request_proof(&code.to_lowercase().replace('-', " "), "u1", &new_ik, &proof), "typed form is normalized");
        assert!(!verify_request_proof(&code, "u1", &bad_ik, &proof), "server-substituted identity");
        assert!(!verify_request_proof(&code, "u2", &new_ik, &proof));
        assert!(!verify_request_proof(&generate_code(), "u1", &new_ik, &proof));

        // Link signature: verifiable by anyone, bound to account + new identity.
        let sig = old.sign_link("u1", &new_ik).unwrap();
        assert!(verify_link(&old_ik, "u1", &new_ik, &sig));
        assert!(!verify_link(&old_ik, "u1", &bad_ik, &sig));
        assert!(!verify_link(&old_ik, "u2", &new_ik, &sig));
        assert!(!verify_link(&bad_ik, "u1", &new_ik, &sig));
        assert!(!verify_link(&old_ik, "u1", &new_ik, &attacker.sign_link("u1", &new_ik).unwrap()));

        // Device-operation proofs are bound to op, account, target and time.
        let op = old.sign_device_op("set-pin", "u1", "enable", 1000, b"482913").unwrap();
        assert!(verify_device_op(&old_ik, "set-pin", "u1", "enable", 1000, b"482913", &op));
        assert!(!verify_device_op(&old_ik, "set-pin", "u1", "enable", 1000, b"666666", &op), "payload swap");
        assert!(!verify_device_op(&old_ik, "cancel-reset", "u1", "enable", 1000, b"482913", &op));
        assert!(!verify_device_op(&old_ik, "set-pin", "u1", "disable", 1000, b"482913", &op));
        assert!(!verify_device_op(&old_ik, "set-pin", "u1", "enable", 1001, b"482913", &op));
        assert!(!verify_device_op(&bad_ik, "set-pin", "u1", "enable", 1000, b"482913", &op));
        // Multi-field payloads are framed, so field boundaries cannot be shifted.
        assert_ne!(op_payload(&[b"ab", b"c"]), op_payload(&[b"a", b"bc"]));

        // Approval MAC: a linker the code was not typed into is rejected by the new device.
        let tag = approval_mac(&code, "u1", &old_ik, &new_ik);
        assert!(verify_approval_mac(&code, "u1", &old_ik, &new_ik, &tag));
        assert!(!verify_approval_mac(&code, "u1", &bad_ik, &new_ik, &tag), "server-substituted linker");
        assert!(!verify_approval_mac(&code, "u1", &old_ik, &new_ik, &proof), "proof is not an approval");
    }
}
