//! "Add a device" by QR code (build 48).
//!
//! The device that is already signed in shows a QR code; the new device scans it, so nobody types
//! or pastes a link. The QR is a **pairing offer**:
//!
//! ```text
//! skwod-pair:1:<node id>.<relay region | ->.<username>.<user id>.<code>.<expires, unix seconds>.<commitment>
//! ```
//!
//! - `node id` — the skwod's address (52 chars z-base-32), as in an invite.
//! - `relay region` — the host's home relay as its first DNS label (`use1-1` stands for
//!   `https://use1-1.relay.n0.iroh.link/`), or `-`. Only n0 relays can be named this way, so the
//!   QR can never point the new device at an arbitrary server.
//! - `username`, `user id` — which account; the user id binds the link proof (it is not secret:
//!   every member of a shared server sees it).
//! - `code` — a fresh 80-bit device-link code (`skwod_crypto::link::generate_code`, 16 Crockford
//!   base32 characters, no dashes). It is the SAME code the existing link flow uses; only the
//!   direction is reversed: the existing device mints it and the new device presents it.
//! - `expires` — five minutes after it was made ([`PAIRING_TTL_SECS`]).
//! - `commitment` — 32 hex characters: [`skwod_crypto::link::pair_commitment`] of a 32-byte nonce
//!   that stays on the existing device until it has seen the requester's key.
//!
//! **No password, and the QR is not a credential.** Anyone can print a QR, so the new device
//! never asks for a password on the strength of one. Before it dials, it asks "Join <skwod> as
//! <username>?" (the skwod named only by a workspace this device already has, otherwise by the
//! host's short key). It then connects to the node id (the transport proves the host holds that
//! key) and opens a session-less link request with the code (`POST /api/e2ee/pair-requests`).
//!
//! **Commit, then reveal.** The existing device reads the request, pins the requester's identity
//! key, and only then releases the nonce for that key ([`SkwodClient::pairing_candidate`]). The
//! new device checks the nonce against the QR's commitment, and both compute five emoji over
//! (code, account, requester key, nonce) ([`confirm_emoji`]). A key chosen before the nonce was
//! released cannot be ground to match, even by someone holding the code and running the server.
//!
//! **Pick, don't tap.** The existing device shows the real set among three decoys
//! ([`choices`]); the person picks the one the new device shows. A wrong pick denies the request
//! and burns the offer. Two devices with the same code: nobody is approved. The existing device
//! waits about two seconds and checks once more that the request is uncontested before approving.
//!
//! **What a forged QR can still do.** A QR made by someone else can point the new device at
//! THEIR skwod and THEIR account: if they approve it, the new device joins their account, not the
//! person's — it sees only what that account sees, and nothing of the person's. That is why the
//! new device asks before dialling and says "Approved on your other device" with the host's short
//! key before entering. The link bundle stays sealed to the new device's identity key
//! (`skwod_crypto::link`).
//!
//! **Single use, short-lived.** The existing device approves at most one request per offer and
//! refuses any approval after the expiry ([`PairingGuard`]); the new device refuses an expired
//! offer or one claiming to live longer than the TTL. The server consumes the offer on approve,
//! deny, contest and register, and checks its expiry at every step.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use crate::CoreError;

/// Shown when two devices presented the same offer: someone else has the code.
pub const TWO_DEVICES: &str = "Someone else also scanned this code, so no device was added — start again with a new code";

/// The offer's nonce is gone (the app restarted while showing the QR).
pub const OFFER_LOST: &str = "This code can't be used any more — make a new one";
/// The person picked a set the new device does not show.
pub const WRONG_PICK: &str = "Those aren't the emoji on the new device, so it was not added. If it was yours, make a new code and try again";
/// How long the existing device waits before its last uncontested check and the approval.
pub const APPROVE_RECHECK_MS: u64 = 2_000;

/// How long an offer is valid.
pub const PAIRING_TTL_SECS: u64 = 300;
/// Clock skew tolerated between the two devices when checking an offer's expiry.
const SKEW_SECS: u64 = 60;
const PREFIX: &str = "skwod-pair:1:";
const RELAY_SUFFIX: &str = ".relay.n0.iroh.link";
/// Longest payload we will look at (a real one is ~180 chars).
const MAX_LEN: usize = 256;
/// How many sets the existing device offers to pick from (one real, the rest decoys).
pub const CHOICES: usize = 4;

fn invalid(detail: &str) -> CoreError {
    CoreError::Invalid { detail: detail.to_string() }
}

/// A decoded (or freshly made) pairing offer.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PairingOffer {
    /// The host's node id (z-base-32).
    pub node_id: String,
    /// The host's home relay (`https://<region>.relay.n0.iroh.link/`), if known.
    pub relay_url: Option<String>,
    pub username: String,
    /// The account's user id (binds the link proof).
    pub user_id: String,
    /// The device-link code (16 Crockford base32 characters).
    pub code: String,
    /// Unix seconds after which the offer is void.
    pub expires_at: u64,
    /// The commitment to the existing device's nonce (32 lowercase hex characters).
    pub commitment: String,
}

fn valid_username(u: &str) -> bool {
    (3..=32).contains(&u.len()) && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn valid_user_id(u: &str) -> bool {
    (1..=64).contains(&u.len()) && u.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_code(c: &str) -> bool {
    c.len() == 16 && c.bytes().all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
}

fn valid_commitment(c: &str) -> bool {
    c.len() == 32 && c.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The commitment as bytes (only for a valid one).
pub fn commitment_bytes(c: &str) -> Option<[u8; 16]> {
    if !valid_commitment(c) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&c[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn valid_region(r: &str) -> bool {
    (1..=63).contains(&r.len())
        && !r.starts_with('-')
        && !r.ends_with('-')
        && r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The region label of an allow-listed n0 relay URL.
fn relay_region(url: &str) -> Option<String> {
    let canonical = skwod_net::invite::is_allowed_relay(url)?;
    let host = canonical.strip_prefix("https://")?.strip_suffix('/')?;
    let region = host.strip_suffix(RELAY_SUFFIX)?;
    valid_region(region).then(|| region.to_string())
}

/// Make a new offer for `username` on the skwod `node_id`, valid for [`PAIRING_TTL_SECS`] from
/// `now` (unix seconds). Mints a fresh link code. `relay_url` is kept only if it is an n0 relay.
#[uniffi::export]
pub fn pairing_new_offer(node_id: String, relay_url: Option<String>, username: String, user_id: String, now: u64) -> Result<PairingOffer, CoreError> {
    let node = skwod_net::invite::parse_node_id(&node_id).map_err(|_| invalid("malformed node id"))?;
    let username = username.trim().to_ascii_lowercase();
    if !valid_username(&username) {
        return Err(invalid("malformed username"));
    }
    if !valid_user_id(&user_id) {
        return Err(invalid("malformed user id"));
    }
    let code = skwod_crypto::link::normalize_code(&skwod_crypto::link::generate_code());
    let relay_url = relay_url.as_deref().and_then(relay_region).map(|r| format!("https://{r}{RELAY_SUFFIX}/"));
    // The nonce never leaves this process until the requester's key is pinned.
    let nonce = skwod_crypto::random_bytes::<32>();
    let commitment = hex(&skwod_crypto::link::pair_commitment(&code, &nonce));
    secrets().lock().unwrap_or_else(|e| e.into_inner()).insert(code.clone(), OfferSecret { nonce, pinned: None, choices: None });
    Ok(PairingOffer { node_id: node.to_z32(), relay_url, username, user_id, code, expires_at: now + PAIRING_TTL_SECS, commitment })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

/// The QR text for `offer`. Refuses an offer it could not decode again.
#[uniffi::export]
pub fn pairing_qr_encode(offer: PairingOffer) -> Result<String, CoreError> {
    let region = match &offer.relay_url {
        Some(url) => relay_region(url).ok_or_else(|| invalid("relay is not an n0 relay"))?,
        None => "-".to_string(),
    };
    let text = format!("{PREFIX}{}.{region}.{}.{}.{}.{}.{}", offer.node_id, offer.username, offer.user_id, offer.code, offer.expires_at, offer.commitment);
    // Never show a QR we would refuse to read (bad username, code, node id).
    parse(&text)?;
    Ok(text)
}

/// Read a scanned QR. Strict: exactly the versioned grammar above, nothing else; an expired offer,
/// or one claiming to live longer than [`PAIRING_TTL_SECS`] (plus clock skew), is refused.
#[uniffi::export]
pub fn pairing_qr_decode(text: String, now: u64) -> Result<PairingOffer, CoreError> {
    let offer = parse(text.trim())?;
    if now > offer.expires_at + SKEW_SECS {
        return Err(invalid("this code has expired — make a new one on your other device"));
    }
    if offer.expires_at > now + PAIRING_TTL_SECS + SKEW_SECS {
        return Err(invalid("this code claims to be valid for too long"));
    }
    Ok(offer)
}

fn parse(text: &str) -> Result<PairingOffer, CoreError> {
    if text.len() > MAX_LEN {
        return Err(invalid("not a Skwod pairing code"));
    }
    let body = text.strip_prefix(PREFIX).ok_or_else(|| {
        if text.starts_with("skwod-pair:") { invalid("this pairing code needs a newer version of Skwod") } else { invalid("not a Skwod pairing code") }
    })?;
    let parts: Vec<&str> = body.split('.').collect();
    let [node_id, region, username, user_id, code, expires, commitment] = parts.as_slice() else {
        return Err(invalid("malformed pairing code"));
    };
    // `parse_node_id` also takes hex; the QR is z-base-32 only.
    let node = skwod_net::iroh_api::EndpointId::from_z32(node_id).map_err(|_| invalid("malformed node id"))?;
    let relay_url = match *region {
        "-" => None,
        r if valid_region(r) => Some(format!("https://{r}{RELAY_SUFFIX}/")),
        _ => return Err(invalid("malformed relay")),
    };
    if !valid_username(username) {
        return Err(invalid("malformed username"));
    }
    if !valid_user_id(user_id) {
        return Err(invalid("malformed user id"));
    }
    if !valid_code(code) {
        return Err(invalid("malformed code"));
    }
    if expires.is_empty() || expires.len() > 12 || !expires.bytes().all(|b| b.is_ascii_digit()) || expires.starts_with('0') {
        return Err(invalid("malformed expiry"));
    }
    let expires_at: u64 = expires.parse().map_err(|_| invalid("malformed expiry"))?;
    if !valid_commitment(commitment) {
        return Err(invalid("malformed commitment"));
    }
    Ok(PairingOffer {
        node_id: node.to_z32(),
        relay_url,
        username: username.to_string(),
        user_id: user_id.to_string(),
        code: code.to_string(),
        expires_at,
        commitment: commitment.to_string(),
    })
}

/// The share link for the offer's skwod (node id + relay hint), to hand to the normal log-in path.
#[uniffi::export]
pub fn pairing_offer_link(offer: PairingOffer) -> Result<String, CoreError> {
    crate::p2p::p2p_format_share_link(offer.node_id, None, None, offer.relay_url)
}

/// 64 easily told-apart emoji; five of them (30 bits) are the confirmation both screens show.
const EMOJI: [&str; 64] = [
    "🐶", "🐱", "🦊", "🐻", "🐼", "🐨", "🐯", "🦁", "🐮", "🐷", "🐸", "🐵", "🐔", "🐧", "🦉", "🐙",
    "🦋", "🐌", "🐞", "🐢", "🐍", "🦖", "🐳", "🐬", "🦀", "🌵", "🌲", "🍄", "🌻", "🌙", "⭐", "🔥",
    "🌈", "❄️", "🍎", "🍋", "🍌", "🍉", "🍇", "🍓", "🥕", "🌽", "🍕", "🍩", "🎂", "☕", "⚽", "🏀",
    "🎸", "🎺", "🎲", "🎈", "🎁", "🔑", "🔔", "📚", "✏️", "⏰", "🚲", "🚀", "⛵", "🏠", "⚓", "💡",
];

fn emoji_of(indices: &[u8]) -> String {
    indices.iter().map(|i| EMOJI[*i as usize % EMOJI.len()]).collect::<Vec<_>>().join(" ")
}

/// The confirmation both devices show: five emoji derived from the link code, the account, the
/// NEW device's identity key and the existing device's revealed nonce.
pub fn confirm_emoji(code: &str, user_id: &str, new_identity_key: &[u8], nonce: &[u8]) -> String {
    emoji_of(&skwod_crypto::link::pair_confirm_indices(code, user_id, new_identity_key, nonce))
}

/// The sets the existing device offers to pick from: the real one and `CHOICES - 1` random decoys,
/// shuffled. Every decoy differs from the real set in at least two places (a glance at one emoji
/// is not enough to tell them apart), and no two sets are the same.
pub fn choices(real: &str) -> Vec<String> {
    let real_idx: Vec<u8> = real.split(' ').map(|e| EMOJI.iter().position(|x| *x == e).unwrap_or(0) as u8).collect();
    let mut sets = vec![real.to_string()];
    while sets.len() < CHOICES {
        let r = skwod_crypto::random_bytes::<5>();
        let idx: Vec<u8> = r.iter().map(|b| b & 63).collect();
        let differs = idx.iter().zip(&real_idx).filter(|(a, b)| a != b).count();
        let set = emoji_of(&idx);
        if differs >= 2 && !sets.contains(&set) {
            sets.push(set);
        }
    }
    // Fisher-Yates with fresh randomness.
    for i in (1..sets.len()).rev() {
        let j = (u32::from_le_bytes(skwod_crypto::random_bytes::<4>()) as usize) % (i + 1);
        sets.swap(i, j);
    }
    sets
}

/// What the existing device keeps, in this process only, for an offer it made: the nonce, the
/// requester key it was revealed for, and the sets it showed.
struct OfferSecret {
    nonce: [u8; 32],
    pinned: Option<Vec<u8>>,
    choices: Option<Vec<String>>,
}

fn secrets() -> &'static Mutex<HashMap<String, OfferSecret>> {
    static SECRETS: OnceLock<Mutex<HashMap<String, OfferSecret>>> = OnceLock::new();
    SECRETS.get_or_init(Default::default)
}

/// The nonce of an offer this process made, if it still knows it.
pub(crate) fn offer_nonce(code: &str) -> Option<[u8; 32]> {
    secrets().lock().unwrap_or_else(|e| e.into_inner()).get(code).map(|s| s.nonce)
}

/// What pinning `key` for offer `code` means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Pin {
    /// First key seen: reveal the nonce for it.
    New,
    /// The key the nonce was already revealed for.
    Same,
    /// Another key after the reveal: the offer must be burned.
    Other,
    /// This process does not know the offer (made before a restart).
    Unknown,
}

pub(crate) fn pin(code: &str, key: &[u8]) -> Pin {
    let mut map = secrets().lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = map.get_mut(code) else { return Pin::Unknown };
    match &s.pinned {
        None => {
            s.pinned = Some(key.to_vec());
            Pin::New
        }
        Some(k) if k == key => Pin::Same,
        Some(_) => Pin::Other,
    }
}

/// The sets shown for offer `code` — made once, so asking again does not reshuffle them.
pub(crate) fn choices_for(code: &str, real: &str) -> Vec<String> {
    let mut map = secrets().lock().unwrap_or_else(|e| e.into_inner());
    match map.get_mut(code) {
        Some(s) => s.choices.get_or_insert_with(|| choices(real)).clone(),
        None => choices(real),
    }
}

/// Forget an offer's nonce (used, denied, burned).
pub(crate) fn forget(code: &str) {
    secrets().lock().unwrap_or_else(|e| e.into_inner()).remove(code);
}

/// Offers already used to approve a device (by code), for this process. With the expiry this is
/// what makes an offer single-use on the existing device.
pub struct PairingGuard;

fn used() -> &'static Mutex<HashSet<String>> {
    static USED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    USED.get_or_init(Default::default)
}

impl PairingGuard {
    /// May `offer` still approve a device at `now`? Not after its expiry, not a second time.
    pub fn check(code: &str, expires_at: u64, now: u64) -> Result<(), CoreError> {
        if now > expires_at {
            return Err(invalid("this code has expired — make a new one"));
        }
        if used().lock().unwrap_or_else(|e| e.into_inner()).contains(code) {
            return Err(invalid("this code was already used — make a new one"));
        }
        Ok(())
    }

    /// Mark `code` used. False if it already was (lost a race).
    pub fn consume(code: &str) -> bool {
        used().lock().unwrap_or_else(|e| e.into_inner()).insert(code.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;
    const UID: &str = "0b5c6e2a-1f3d-4c8e-9a7b-2d4f6e8a0c1e";

    fn node() -> String {
        skwod_net::SecretKey::generate().public().to_z32()
    }

    fn offer() -> PairingOffer {
        pairing_new_offer(node(), Some("https://use1-1.relay.n0.iroh.link./".into()), "Alice_1".into(), UID.into(), NOW).unwrap()
    }

    #[test]
    fn an_offer_round_trips_through_its_qr_text() {
        let o = offer();
        assert_eq!(o.username, "alice_1");
        assert_eq!(o.relay_url.as_deref(), Some("https://use1-1.relay.n0.iroh.link/"));
        assert_eq!(o.expires_at, NOW + 300);
        assert!(valid_code(&o.code), "{}", o.code);
        assert!(valid_commitment(&o.commitment), "{}", o.commitment);
        let qr = pairing_qr_encode(o.clone()).unwrap();
        assert_eq!(qr, format!("skwod-pair:1:{}.use1-1.alice_1.{UID}.{}.{}.{}", o.node_id, o.code, NOW + 300, o.commitment));
        assert_eq!(pairing_qr_decode(qr.clone(), NOW).unwrap(), o);
        assert_eq!(pairing_qr_decode(format!("  {qr}\n"), NOW + 299).unwrap(), o);
        // Without a relay.
        let mut bare = o.clone();
        bare.relay_url = None;
        let qr = pairing_qr_encode(bare.clone()).unwrap();
        assert!(qr.contains(".-."), "{qr}");
        assert_eq!(pairing_qr_decode(qr, NOW).unwrap(), bare);
    }

    #[test]
    fn the_qr_carries_no_password_token_or_key() {
        let o = offer();
        let qr = pairing_qr_encode(o.clone()).unwrap();
        // Exactly: prefix, node id, relay region, username, user id, code, expiry, commitment.
        let body = qr.strip_prefix("skwod-pair:1:").unwrap();
        assert_eq!(body.split('.').count(), 7);
        assert!(qr.len() < 200, "{}", qr.len());
        // The commitment hides the nonce: it is not in the QR.
        let nonce = offer_nonce(&o.code).unwrap();
        assert!(!qr.contains(&hex(&nonce)));
    }

    #[test]
    fn expired_or_overlong_offers_are_refused() {
        let qr = pairing_qr_encode(offer()).unwrap();
        assert!(pairing_qr_decode(qr.clone(), NOW + 300 + 60).is_ok(), "a minute of clock skew is tolerated");
        assert!(pairing_qr_decode(qr.clone(), NOW + 300 + 61).is_err());
        assert!(pairing_qr_decode(qr.clone(), NOW + 3600).is_err());
        // A QR claiming to live for an hour was not made by Skwod.
        let mut long = offer();
        long.expires_at = NOW + 3600;
        let text = pairing_qr_encode(long).unwrap();
        assert!(pairing_qr_decode(text, NOW).is_err());
    }

    #[test]
    fn the_grammar_is_strict() {
        let o = offer();
        let good = format!("skwod-pair:1:{}.use1-1.alice_1.{UID}.{}.{}.{}", o.node_id, o.code, o.expires_at, o.commitment);
        assert!(pairing_qr_decode(good.clone(), NOW).is_ok());
        let n = &o.node_id;
        let c = &o.code;
        let e = o.expires_at;
        let k = &o.commitment;
        for bad in [
            format!("skwod-pair:2:{n}.use1-1.alice_1.{UID}.{c}.{e}.{k}"),
            format!("skwod-pair:{n}.use1-1.alice_1.{UID}.{c}.{e}.{k}"),
            format!("SKWOD-PAIR:1:{n}.use1-1.alice_1.{UID}.{c}.{e}.{k}"),
            format!("skwod-link:{c}"),
            format!("https://skwod.io/join#{n}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.Not_A_Uid.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.{e}.{k}.x"),
            format!("skwod-pair:1:{n}x.use1-1.alice_1.{UID}.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.evil.example.alice_1.{UID}.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.Use1-1.alice_1.{UID}.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.-use1.alice_1.{UID}.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.Alice.{UID}.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.al.{UID}.{c}.{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{}.{e}.{k}", c.to_lowercase()),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{}.{e}.{k}", &c[..15]),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.ABCD-EFGH-JKMN-PQRS.{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.0{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.-{e}.{k}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.{e}0000000.{k}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.{e}.{k} x"),
            format!("{good}{}", "a".repeat(300)),
            // The commitment: missing, short, upper case, not hex.
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.{e}"),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.{e}.{}", &k[..31]),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.{e}.{}", k.to_uppercase()),
            format!("skwod-pair:1:{n}.use1-1.alice_1.{UID}.{c}.{e}.{}", "g".repeat(32)),
        ] {
            assert!(pairing_qr_decode(bad.clone(), NOW).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_n0_relays_go_into_an_offer() {
        let o = pairing_new_offer(node(), Some("https://evil.example/".into()), "alice".into(), UID.into(), NOW).unwrap();
        assert_eq!(o.relay_url, None);
        let mut forged = offer();
        forged.relay_url = Some("https://evil.example/".into());
        assert!(pairing_qr_encode(forged).is_err());
    }

    #[test]
    fn the_offer_link_dials_the_same_skwod_with_its_relay() {
        let o = offer();
        let link = pairing_offer_link(o.clone()).unwrap();
        let inv = crate::p2p::p2p_parse_invite(link).unwrap();
        assert_eq!(inv.node_id, o.node_id);
        assert_eq!(inv.relay_url, o.relay_url);
        assert_eq!(inv.join_code, None, "a pairing is a log-in, never a join");
    }

    #[test]
    fn an_offer_approves_once_and_never_after_it_expires() {
        let o = offer();
        assert!(PairingGuard::check(&o.code, o.expires_at, NOW).is_ok());
        assert!(PairingGuard::check(&o.code, o.expires_at, o.expires_at + 1).is_err(), "expired");
        assert!(PairingGuard::consume(&o.code));
        assert!(!PairingGuard::consume(&o.code), "second use");
        assert!(PairingGuard::check(&o.code, o.expires_at, NOW).is_err(), "already used");
        // Another offer is unaffected.
        let other = offer();
        assert!(PairingGuard::check(&other.code, other.expires_at, NOW).is_ok());
    }

    #[test]
    fn the_confirmation_depends_on_the_key_and_the_nonce() {
        let n = [9u8; 32];
        let a = confirm_emoji("ABCDEFGHJKMNPQRS", "u1", &[1u8; 33], &n);
        assert_eq!(a, confirm_emoji("ABCDEFGHJKMNPQRS", "u1", &[1u8; 33], &n));
        assert_eq!(a.split(' ').count(), 5, "five emoji, 30 bits");
        assert_ne!(a, confirm_emoji("ABCDEFGHJKMNPQRS", "u1", &[2u8; 33], &n), "another device, other emoji");
        assert_ne!(a, confirm_emoji("ABCDEFGHJKMNPQRT", "u1", &[1u8; 33], &n));
        assert_ne!(a, confirm_emoji("ABCDEFGHJKMNPQRS", "u2", &[1u8; 33], &n));
        assert_ne!(a, confirm_emoji("ABCDEFGHJKMNPQRS", "u1", &[1u8; 33], &[8u8; 32]), "another nonce, other emoji");
    }

    /// M3: someone with the code (a photographed QR) who runs the server used to grind an identity
    /// key whose emoji matched the real device's. Now the key must be fixed before the nonce is
    /// released: a key ground against any nonce the attacker could guess does not match under the
    /// real one. (Ground here on a 12-bit prefix to keep the test fast; the full set is 30 bits.)
    #[test]
    fn a_ground_key_no_longer_matches() {
        let code = "ABCDEFGHJKMNPQRS";
        let real_key = [1u8; 33];
        let guessed = [0u8; 32];
        let target = skwod_crypto::link::pair_confirm_indices(code, UID, &real_key, &guessed);
        let mut ground = None;
        for i in 0u32..1_000_000 {
            let mut k = [2u8; 33];
            k[..4].copy_from_slice(&i.to_le_bytes());
            if skwod_crypto::link::pair_confirm_indices(code, UID, &k, &guessed)[..2] == target[..2] {
                ground = Some(k);
                break;
            }
        }
        let ground = ground.expect("a 12-bit prefix grinds in a few thousand tries");
        // Against the nonce it guessed, the ground key matches where it was ground...
        assert_eq!(skwod_crypto::link::pair_confirm_indices(code, UID, &ground, &guessed)[..2], target[..2]);
        // ...but the existing device reveals a fresh nonce only after it pinned that key.
        let real_nonce = [0x5au8; 32];
        assert_ne!(confirm_emoji(code, UID, &ground, &real_nonce), confirm_emoji(code, UID, &real_key, &real_nonce));
    }

    #[test]
    fn the_commitment_binds_the_nonce_and_the_code() {
        let o = offer();
        let nonce = offer_nonce(&o.code).unwrap();
        let c = commitment_bytes(&o.commitment).unwrap();
        assert_eq!(skwod_crypto::link::pair_commitment(&o.code, &nonce), c);
        assert_ne!(skwod_crypto::link::pair_commitment(&o.code, &[0u8; 32]), c, "another nonce does not open it");
        assert_ne!(skwod_crypto::link::pair_commitment("ABCDEFGHJKMNPQRS", &nonce), c);
        assert_eq!(commitment_bytes("nothex"), None);
    }

    #[test]
    fn the_nonce_is_revealed_for_one_key_only() {
        let o = offer();
        assert_eq!(pin(&o.code, &[1u8; 33]), Pin::New);
        assert_eq!(pin(&o.code, &[1u8; 33]), Pin::Same);
        assert_eq!(pin(&o.code, &[2u8; 33]), Pin::Other, "a swapped key after the reveal burns the offer");
        assert_eq!(pin("ZZZZZZZZZZZZZZZZ", &[1u8; 33]), Pin::Unknown);
        forget(&o.code);
        assert_eq!(offer_nonce(&o.code), None);
    }

    #[test]
    fn the_real_set_hides_among_three_decoys() {
        let real = confirm_emoji("ABCDEFGHJKMNPQRS", UID, &[1u8; 33], &[3u8; 32]);
        let real_parts: Vec<&str> = real.split(' ').collect();
        for _ in 0..200 {
            let c = choices(&real);
            assert_eq!(c.len(), CHOICES);
            assert_eq!(c.iter().filter(|s| **s == real).count(), 1, "exactly one real set");
            let mut uniq = c.clone();
            uniq.sort();
            uniq.dedup();
            assert_eq!(uniq.len(), CHOICES, "no two sets alike");
            for d in c.iter().filter(|s| **s != real) {
                let parts: Vec<&str> = d.split(' ').collect();
                assert_eq!(parts.len(), 5);
                assert!(parts.iter().zip(&real_parts).filter(|(a, b)| a != b).count() >= 2, "{d} vs {real}");
            }
        }
        // Shuffled: the real set is not always in the same place.
        let places: std::collections::HashSet<usize> = (0..200).map(|_| choices(&real).iter().position(|s| *s == real).unwrap()).collect();
        assert!(places.len() > 1);
        // Stable for one offer: asking again does not reshuffle.
        let o = offer();
        assert_eq!(choices_for(&o.code, &real), choices_for(&o.code, &real));
    }
}
