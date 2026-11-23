//! The server **instance identity**: one Ed25519 key per self-hosted server. Its public half is
//! what an invite pins, and what `verify_server_identity` challenges when a skwod moves address.
//! It is not part of the message protocol — it authenticates *the server*, and (via
//! [`crate::certs`]) vouches for the libsignal sealed-sender trust root that server uses.
//!
//! Ed25519 from `ed25519-dalek` (audited).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Generate an instance keypair: `(secret(32), public(32))`.
pub fn generate() -> ([u8; 32], [u8; 32]) {
    let sk = SigningKey::generate(&mut rand_core::OsRng);
    (sk.to_bytes(), sk.verifying_key().to_bytes())
}

/// Sign `msg` with a 32-byte instance secret. `None` if the secret is the wrong length.
pub fn sign(secret: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let sk = SigningKey::from_bytes(secret.try_into().ok()?);
    Some(sk.sign(msg).to_bytes().to_vec())
}

/// Verify `sig` over `msg` against a 32-byte instance public key (strict verification).
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk_bytes) = <[u8; 32]>::try_from(public) else { return false };
    let Ok(pk) = VerifyingKey::from_bytes(&pk_bytes) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    pk.verify_strict(msg, &sig).is_ok()
}

/// Domain tag of the ORIGIN-BOUND proof of possession (`/api/instance/prove` with an `origin`).
/// Distinct from the v1 tag (`skwod-instance-proof-v1:`, nonce only), whose signatures a third
/// party could obtain from the real server and replay from its own address.
pub const PROOF_TAG_V2: &[u8] = b"skwod-instance-proof-v2:";
/// Domain tag of a signed address record.
pub const ADDRESS_RECORD_TAG: &[u8] = b"skwod-address-record-v1:";
/// Scheme of the origin of a host reached by its p2p key: `skwod-p2p:<z-base-32 node id>`.
pub const P2P_ORIGIN_SCHEME: &str = "skwod-p2p:";

/// What an origin-bound proof signs: `TAG ‖ len(nonce) as u16 BE ‖ nonce ‖ origin`. The origin is
/// the address the CLIENT dialed; the server only signs origins it actually serves, so a signature
/// relayed from the real server is useless at any other address.
pub fn proof_message_v2(nonce: &[u8], origin: &str) -> Option<Vec<u8>> {
    let len = u16::try_from(nonce.len()).ok()?;
    let mut msg = Vec::with_capacity(PROOF_TAG_V2.len() + 2 + nonce.len() + origin.len());
    msg.extend_from_slice(PROOF_TAG_V2);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(origin.as_bytes());
    Some(msg)
}

/// The origin for a host dialed by its p2p node id.
pub fn p2p_origin(node_id_z32: &str) -> String {
    format!("{P2P_ORIGIN_SCHEME}{}", node_id_z32.to_ascii_lowercase())
}

/// Canonical origin of an `http(s)` URL: `scheme://host[:port]`, lower-cased, default port and
/// any path/query/fragment dropped. `None` for anything else (userinfo, other schemes, no host).
pub fn normalize_origin(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://").or_else(|| strip_prefix_ci(url, "https://")) {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://").or_else(|| strip_prefix_ci(url, "http://")) {
        ("http", r)
    } else {
        return None;
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() || authority.contains('@') || authority.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let authority = authority.to_ascii_lowercase();
    // Split a trailing `:port` (an IPv6 literal keeps its brackets).
    let (host, port) = match authority.rfind(':') {
        Some(i) if !authority[i..].contains(']') => (&authority[..i], Some(&authority[i + 1..])),
        _ => (authority.as_str(), None),
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        None => None,
        Some(p) => Some(p.parse::<u16>().ok()?),
    };
    let default = if scheme == "https" { 443 } else { 80 };
    Some(match port {
        Some(p) if p != default => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    })
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) && s[..prefix.len()].eq_ignore_ascii_case(prefix)).then(|| &s[prefix.len()..])
}

/// Whether a normalized origin is a loopback address (this machine only).
pub fn is_loopback_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://").or_else(|| origin.strip_prefix("https://")) else { return false };
    let host = match rest.rfind(':') {
        Some(i) if !rest[i..].contains(']') => &rest[..i],
        _ => rest,
    };
    host == "localhost" || host == "[::1]" || host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
}

/// What an address record signs: `TAG ‖ ts (i64 BE, unix ms) ‖ address`. A record says "as of
/// `ts`, this instance is served at `address`"; clients accept one only under the pinned instance
/// key and only with a `ts` newer than the last they accepted.
pub fn address_record_message(address: &str, ts: i64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ADDRESS_RECORD_TAG.len() + 8 + address.len());
    msg.extend_from_slice(ADDRESS_RECORD_TAG);
    msg.extend_from_slice(&ts.to_be_bytes());
    msg.extend_from_slice(address.as_bytes());
    msg
}

/// Domain tag of an owner attestation.
pub const OWNER_ATTESTATION_TAG: &[u8] = b"skwod-owner-attestation-v1:";

/// What an owner attestation signs: `TAG ‖ len(server id) as u16 BE ‖ server id ‖ owner id`.
/// It is the INSTANCE saying "this user owns this server" — the word of the server a client
/// pinned, nothing stronger. Clients use it only to re-confirm an owner they had already pinned
/// before pins carried a provenance; it never introduces or replaces an owner.
pub fn owner_attestation_message(server_id: &str, owner_id: &str) -> Option<Vec<u8>> {
    let len = u16::try_from(server_id.len()).ok()?;
    let mut msg = Vec::with_capacity(OWNER_ATTESTATION_TAG.len() + 2 + server_id.len() + owner_id.len());
    msg.extend_from_slice(OWNER_ATTESTATION_TAG);
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(server_id.as_bytes());
    msg.extend_from_slice(owner_id.as_bytes());
    Some(msg)
}

pub fn verify_owner_attestation(public: &[u8], server_id: &str, owner_id: &str, sig: &[u8]) -> bool {
    owner_attestation_message(server_id, owner_id).is_some_and(|m| verify(public, &m, sig))
}

/// Domain tag of an instance-owner attestation.
pub const INSTANCE_OWNER_TAG: &[u8] = b"skwod-instance-owner-v1:";

/// What an instance-owner attestation signs: `TAG ‖ owner id`. It is the INSTANCE naming the
/// account that owns it (the host). The instance key already identifies the instance, so no
/// instance id is mixed in. Clients pin the first one they verify under the pinned instance key
/// and use it only for instance-level cosmetics (the skwod icon) — never for keys or approvals.
pub fn instance_owner_message(owner_id: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(INSTANCE_OWNER_TAG.len() + owner_id.len());
    msg.extend_from_slice(INSTANCE_OWNER_TAG);
    msg.extend_from_slice(owner_id.as_bytes());
    msg
}

pub fn verify_instance_owner(public: &[u8], owner_id: &str, sig: &[u8]) -> bool {
    !owner_id.is_empty() && verify(public, &instance_owner_message(owner_id), sig)
}

pub fn sign_address_record(secret: &[u8], address: &str, ts: i64) -> Option<Vec<u8>> {
    sign(secret, &address_record_message(address, ts))
}

pub fn verify_address_record(public: &[u8], address: &str, ts: i64, sig: &[u8]) -> bool {
    verify(public, &address_record_message(address, ts), sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_normalize_and_bind() {
        assert_eq!(normalize_origin("HTTPS://Chat.Example.org:443/x?y#z").as_deref(), Some("https://chat.example.org"));
        assert_eq!(normalize_origin("https://chat.example.org:8443").as_deref(), Some("https://chat.example.org:8443"));
        assert_eq!(normalize_origin("http://127.0.0.1:3000/").as_deref(), Some("http://127.0.0.1:3000"));
        assert_eq!(normalize_origin("http://[::1]:3000").as_deref(), Some("http://[::1]:3000"));
        for bad in ["ftp://x", "https://", "https://user@host", "https://host:99999", "host", "https://a b"] {
            assert_eq!(normalize_origin(bad), None, "{bad}");
        }
        assert!(is_loopback_origin("http://127.0.0.1:3000") && is_loopback_origin("http://localhost") && is_loopback_origin("http://[::1]:1"));
        assert!(!is_loopback_origin("https://chat.example.org") && !is_loopback_origin("http://127.0.0.1.evil.com"));

        let (sk, pk) = generate();
        let sig = sign(&sk, &proof_message_v2(b"nonce", "https://real.example").unwrap()).unwrap();
        assert!(verify(&pk, &proof_message_v2(b"nonce", "https://real.example").unwrap(), &sig));
        assert!(!verify(&pk, &proof_message_v2(b"nonce", "https://evil.example").unwrap(), &sig), "bound to the origin");
        // Length-prefixing keeps nonce and origin from sliding into each other.
        assert!(!verify(&pk, &proof_message_v2(b"noncehttps", "://real.example").unwrap(), &sig));
        // And a v2 signature is not a v1 proof of anything.
        let mut v1 = b"skwod-instance-proof-v1:".to_vec();
        v1.extend_from_slice(b"nonce");
        assert!(!verify(&pk, &v1, &sig));
    }

    #[test]
    fn address_records_are_bound_to_address_and_time() {
        let (sk, pk) = generate();
        let sig = sign_address_record(&sk, "https://new.example", 1000).unwrap();
        assert!(verify_address_record(&pk, "https://new.example", 1000, &sig));
        assert!(!verify_address_record(&pk, "https://evil.example", 1000, &sig));
        assert!(!verify_address_record(&pk, "https://new.example", 1001, &sig));
        assert!(!verify_address_record(&generate().1, "https://new.example", 1000, &sig));
    }

    #[test]
    fn sign_verify() {
        let (sk, pk) = generate();
        let sig = sign(&sk, b"msg").unwrap();
        assert!(verify(&pk, b"msg", &sig));
        assert!(!verify(&pk, b"other", &sig));
        assert!(!verify(&generate().1, b"msg", &sig));
        assert!(!verify(&pk[..31], b"msg", &sig));
    }
}
