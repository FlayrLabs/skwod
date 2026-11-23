//! Passphrase key backup.
//!
//! Signal protects PIN-based recovery with SVR: a secure enclave that rate-limits guesses, so a
//! short PIN cannot be brute-forced offline. A self-hosted skwod server has no such enclave, and
//! the server operator is in the threat model — so anything the server stores can be attacked
//! **offline, at the attacker's speed**. A short PIN is therefore never accepted here. Backup is
//! opt-in and requires either a generated 160-bit recovery key ([`generate_recovery_key`]) or a
//! user passphrase that passes [`check_passphrase`]; the passphrase is stretched with Argon2id
//! (parameters travel with the backup so they can be raised later).
//!
//! Layout: a random 32-byte *backup key* seals the payload ([`crate::aead`]); the passphrase-derived
//! key wraps only the backup key. Primitives: RustCrypto `argon2`, `chacha20poly1305`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Argon2id cost parameters, stored next to the salt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// 64 MiB, 3 passes, 1 lane — OWASP's Argon2id guidance with headroom, and what a phone can
    /// run in about a second.
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Floor below which a (possibly server-supplied) parameter set is refused: a malicious server
    /// must not be able to talk a client into deriving with trivial cost and then test guesses
    /// against the result.
    pub const MIN: KdfParams = KdfParams { m_kib: 19 * 1024, t: 2, p: 1 };
    /// Ceiling, so a malicious server cannot make a phone allocate (and grind) without bound:
    /// 256 MiB and 6 passes is several times the default and still something a phone survives.
    const MAX_M_KIB: u32 = 256 * 1024;
    const MAX_T: u32 = 6;

    pub fn acceptable(&self) -> bool {
        self.m_kib >= Self::MIN.m_kib && self.m_kib <= Self::MAX_M_KIB && self.t >= Self::MIN.t && self.t <= Self::MAX_T && (1..=8).contains(&self.p)
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    #[error("passphrase too weak: {0}")]
    WeakPassphrase(&'static str),
    #[error("unacceptable KDF parameters")]
    BadParams,
    #[error("salt too short")]
    BadSalt,
    #[error("wrong passphrase or corrupt backup")]
    Auth,
}

const WRAP_AAD: &[u8] = b"skwod-backup-key-wrap-v3";

/// Minimum passphrase length. With Argon2id at the default cost, 14 characters of real passphrase
/// material is the point where offline guessing stops being practical for a determined attacker.
pub const MIN_PASSPHRASE_CHARS: usize = 14;

/// The least guessing work a passphrase must represent, as estimated by
/// [`passphrase_guess_bits`]. The host holds the salt, the wrapped key and the verifier, so
/// it can test guesses offline at the cost of one Argon2id run each; at the default cost, 2^50
/// guesses is beyond anyone who is not spending millions on it.
pub const MIN_PASSPHRASE_BITS: f64 = 50.0;

/// The most common passwords and the words people build passwords from (lower case). Not a
/// dictionary — the estimator below does the rest — only the stems that turn up at the top of
/// every leaked list, so that "a common word plus digits" is priced as what it is.
const COMMON_STEMS: &[&str] = &[
    "password", "passwort", "passw0rd", "p@ssword", "p@ssw0rd", "pass", "letmein", "welcome", "admin", "administrator", "login", "master", "hello",
    "iloveyou", "loveyou", "love", "monkey", "dragon", "sunshine", "princess", "football", "baseball", "soccer", "hockey", "superman", "batman",
    "trustno1", "shadow", "michael", "jennifer", "jordan", "charlie", "freedom", "whatever", "starwars", "summer", "winter", "spring", "autumn",
    "secret", "google", "apple", "samsung", "iphone", "android", "computer", "internet", "killer", "ninja", "mustang", "access", "flower",
    "skwod", "signal", "recovery", "backup", "passphrase", "changeme", "default", "guest", "test", "qwerty", "qwertz", "azerty", "abc", "abcd",
];

/// Keyboard rows and other runs people type along, forwards.
const SEQUENCES: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "01234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "qwertzuiop",
    "azertyuiop",
    "1q2w3e4r5t6y7u8i9o0p",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm",
    "qazwsxedcrfvtgbyhnujmikolp",
];

/// How long a run starting at `chars[at]` follows one of [`SEQUENCES`], in either direction.
fn sequence_run(chars: &[char], at: usize) -> usize {
    let mut best = 0;
    for seq in SEQUENCES {
        let seq: Vec<char> = seq.chars().collect();
        for (start, _) in seq.iter().enumerate().filter(|(_, c)| **c == chars[at]) {
            for step in [1isize, -1] {
                let mut n = 1;
                while at + n < chars.len() {
                    let next = start as isize + step * n as isize;
                    if next < 0 || next as usize >= seq.len() || seq[next as usize] != chars[at + n] {
                        break;
                    }
                    n += 1;
                }
                best = best.max(n);
            }
        }
    }
    best
}

/// A conservative estimate of how many guesses (as bits) an attacker who knows how people
/// choose passwords needs for `passphrase`. It is the cheapest way of spelling the passphrase
/// out of the pieces a cracker tries first, each priced by how many choices it really was:
///
/// - a common password stem (`password`, `qwerty`, …): about 6 bits, however long;
/// - a run along a keyboard row, the alphabet or the digits (`qwertyuiop`, `123456`, `fedcba`):
///   about 5 bits plus one per extra character;
/// - a repeat of what came just before (`aaaa`, `abcabcabc`): about 2 bits plus one per repeat;
/// - a four-digit year (19xx / 20xx): about 7 bits;
/// - anything else: one character at a time, by the size of its class (26 letters, 10 digits,
///   33 symbols, 64 for anything beyond ASCII), and 1 bit for the choice of that class.
///
/// It under-prices before it over-prices: a passphrase of random words gets less credit than
/// it deserves (each letter as a letter) and still clears the bar at ordinary lengths, while
/// `password123456` and `qwertyuiop1234` come out around 20 bits.
pub fn passphrase_guess_bits(passphrase: &str) -> f64 {
    let original: Vec<char> = passphrase.chars().collect();
    let chars: Vec<char> = passphrase.to_lowercase().chars().collect();
    // Case only counts once per passphrase unless it is mixed throughout.
    let n = chars.len().min(original.len());
    let mut best = vec![f64::INFINITY; n + 1];
    best[0] = 0.0;
    for i in 0..n {
        if !best[i].is_finite() {
            continue;
        }
        let relax = |len: usize, cost: f64, best: &mut Vec<f64>| {
            if len > 0 && i + len <= n && best[i] + cost < best[i + len] {
                best[i + len] = best[i] + cost;
            }
        };
        // One character on its own.
        let c = chars[i];
        let class = if c.is_ascii_lowercase() {
            26.0f64
        } else if c.is_ascii_digit() {
            10.0
        } else if c.is_ascii() {
            33.0
        } else {
            64.0
        };
        relax(1, class.log2() + 1.0, &mut best);
        // A common stem.
        for stem in COMMON_STEMS {
            let stem: Vec<char> = stem.chars().collect();
            if chars[i..n].starts_with(&stem) {
                relax(stem.len(), 6.0, &mut best);
            }
        }
        // A keyboard / alphabet / digit run of three or more.
        let run = sequence_run(&chars[..n], i);
        for len in 3..=run {
            relax(len, 5.0 + (len - 3) as f64, &mut best);
        }
        // A repeat of the block that ends here.
        for block in 1..=i.min(8) {
            let unit = &chars[i - block..i];
            let mut repeats = 0;
            while i + (repeats + 1) * block <= n && &chars[i + repeats * block..i + (repeats + 1) * block] == unit {
                repeats += 1;
                relax(repeats * block, 2.0 + repeats as f64, &mut best);
            }
        }
        // A year.
        if i + 4 <= n && chars[i..i + 4].iter().all(char::is_ascii_digit) && matches!((chars[i], chars[i + 1]), ('1', '9') | ('2', '0')) {
            relax(4, 7.0, &mut best);
        }
    }
    let mixed_case = original.iter().any(|c| c.is_uppercase()) && original.iter().any(|c| c.is_lowercase());
    best[n] + if mixed_case { 2.0 } else { 0.0 }
}

/// Reject passphrases that cannot survive offline guessing: too short, a numeric PIN, too
/// repetitive — or simply guessable ([`passphrase_guess_bits`] under [`MIN_PASSPHRASE_BITS`]):
/// a common password with digits on the end, a walk along the keyboard, a repeated pattern.
/// Length alone is not strength, and the host can run a dictionary against the backup offline.
pub fn check_passphrase(passphrase: &str) -> Result<(), BackupError> {
    let chars: Vec<char> = passphrase.chars().collect();
    if chars.len() < MIN_PASSPHRASE_CHARS {
        return Err(BackupError::WeakPassphrase("use at least 14 characters, or a generated recovery key"));
    }
    if chars.iter().all(|c| c.is_ascii_digit()) {
        return Err(BackupError::WeakPassphrase("a numeric PIN can be brute-forced offline"));
    }
    let mut distinct = chars.clone();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() < 6 {
        return Err(BackupError::WeakPassphrase("too repetitive"));
    }
    if passphrase_guess_bits(passphrase) < MIN_PASSPHRASE_BITS {
        return Err(BackupError::WeakPassphrase("too easy to guess: avoid common passwords, keyboard patterns and repeats, or use a generated recovery key"));
    }
    Ok(())
}

/// A fresh 160-bit recovery key, as 8 dash-separated groups of 4 Crockford-base32 characters
/// (e.g. `7KQ2-M9XA-…`). Meant to be written down or stored in a password manager.
pub fn generate_recovery_key() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bytes: [u8; 20] = crate::random_bytes();
    let mut out = String::with_capacity(39);
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

fn derive(passphrase: &[u8], salt: &[u8], params: KdfParams) -> Result<[u8; 32], BackupError> {
    if salt.len() < 16 {
        return Err(BackupError::BadSalt);
    }
    if !params.acceptable() {
        return Err(BackupError::BadParams);
    }
    let p = argon2::Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| BackupError::BadParams)?;
    let mut out = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, p)
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| BackupError::BadParams)?;
    Ok(out)
}

/// Wrap a 32-byte backup key under a passphrase. Returns the wrapped key (`nonce || ct`).
pub fn wrap_key(backup_key: &[u8; 32], passphrase: &str, salt: &[u8], params: KdfParams) -> Result<Vec<u8>, BackupError> {
    let mut kek = derive(passphrase.as_bytes(), salt, params)?;
    let out = crate::aead::seal(&kek, WRAP_AAD, backup_key);
    kek.zeroize();
    Ok(out)
}

/// Unwrap a backup key. [`BackupError::Auth`] for a wrong passphrase.
pub fn unwrap_key(wrapped: &[u8], passphrase: &str, salt: &[u8], params: KdfParams) -> Result<[u8; 32], BackupError> {
    let mut kek = derive(passphrase.as_bytes(), salt, params)?;
    let pt = crate::aead::open(&kek, WRAP_AAD, wrapped);
    kek.zeroize();
    pt.and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok()).ok_or(BackupError::Auth)
}

// ---- recovery-key proof ----
//
// Restoring from a key backup moves a device to a new install. The server lets that happen at
// once only for someone who proves they hold the RECOVERY KEY — not merely a session, and not
// merely a copy of the device's identity key.
//
// The proof key is derived (HKDF-SHA256) from the 32-byte backup key, which exists only wrapped
// under the recovery key (Argon2id) — so only someone who can unwrap the backup can derive it.
// The server stores the proof key's PUBLIC half (the "verifier") next to the backup and checks a
// signature over a nonce it issued. Neither the recovery key, the backup key nor the proof key
// ever leaves the device.

const RECOVERY_AUTH_INFO: &[u8] = b"skwod-backup-recovery-auth-v1";

fn recovery_auth_key(backup_key: &[u8; 32]) -> Option<libsignal_protocol::PrivateKey> {
    let mut seed = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, backup_key).expand(RECOVERY_AUTH_INFO, &mut seed).ok()?;
    let key = libsignal_protocol::PrivateKey::deserialize(&seed).ok();
    seed.zeroize();
    key
}

/// The verifier the server stores with the backup: the public half of the recovery proof key.
pub fn recovery_verifier(backup_key: &[u8; 32]) -> Option<Vec<u8>> {
    recovery_auth_key(backup_key)?.public_key().ok().map(|k| k.serialize().to_vec())
}

/// What a recovery proof signs: the account, what is being done (`"rekey"` an existing device
/// / `"register"` a fresh one), its target (the device id / the identity key), the server's
/// nonce, and the hash of the restoring install's secret — so a proof cannot be replayed, moved
/// to another device, or used to seat another install.
pub fn recovery_auth_message(user_id: &str, purpose: &str, target: &[u8], nonce: &str, install_hash: &[u8]) -> Vec<u8> {
    let mut out = RECOVERY_AUTH_INFO.to_vec();
    for part in [user_id.as_bytes(), purpose.as_bytes(), target, nonce.as_bytes(), install_hash] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Sign a recovery proof with the key derived from `backup_key`.
pub fn sign_recovery_auth(backup_key: &[u8; 32], message: &[u8]) -> Option<Vec<u8>> {
    use rand::TryRngCore as _;
    recovery_auth_key(backup_key)?.calculate_signature(message, &mut rand::rngs::OsRng.unwrap_err()).ok().map(|s| s.to_vec())
}

/// Server side: does `signature` over `message` verify under the stored `verifier`?
pub fn verify_recovery_auth(verifier: &[u8], message: &[u8], signature: &[u8]) -> bool {
    libsignal_protocol::PublicKey::deserialize(verifier).is_ok_and(|k| crate::link::is_canonical_signature(signature) && k.verify_signature(message, signature))
}

/// The code for one recovery request, derived from the requesting install's secret hash:
/// `XXXX-XXXX-XXXX-XXXX` (16 Crockford-base32 characters, 80 bits). The restoring install shows
/// it; so does the notice on the device asked to approve. If they differ, the request on screen
/// is not the one the user started.
///
/// 80 bits because the code is the only thing the approving user compares, and whoever can file
/// a competing request can also grind install secrets offline until one shows the same code: at
/// the 32 bits this used to be, that took seconds.
pub fn recovery_fingerprint(install_hash: &[u8]) -> String {
    use sha2::Digest;
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let d = sha2::Sha256::new().chain_update(b"skwod-recovery-fingerprint-v2").chain_update(install_hash).finalize();
    // 80 bits = the first ten bytes, five bits at a time.
    let bits = d[..10].iter().fold(0u128, |acc, b| (acc << 8) | u128::from(*b));
    let mut out = String::with_capacity(19);
    for i in 0..16 {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(ALPHABET[((bits >> (75 - 5 * i)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_proof_needs_the_backup_key_and_binds_everything_it_signs() {
        let (key, other) = ([7u8; 32], [8u8; 32]);
        let verifier = recovery_verifier(&key).unwrap();
        assert_eq!(recovery_verifier(&key).unwrap(), verifier, "deterministic: the same recovery key always proves the same way");
        assert_ne!(recovery_verifier(&other).unwrap(), verifier);
        let msg = recovery_auth_message("u1", "rekey", b"dev", "nonce-1", &[1u8; 32]);
        let sig = sign_recovery_auth(&key, &msg).unwrap();
        assert!(verify_recovery_auth(&verifier, &msg, &sig));
        assert!(!verify_recovery_auth(&verifier, &msg, &sign_recovery_auth(&other, &msg).unwrap()), "another backup key");
        for bent in [
            recovery_auth_message("u2", "rekey", b"dev", "nonce-1", &[1u8; 32]),
            recovery_auth_message("u1", "register", b"dev", "nonce-1", &[1u8; 32]),
            recovery_auth_message("u1", "rekey", b"other", "nonce-1", &[1u8; 32]),
            recovery_auth_message("u1", "rekey", b"dev", "nonce-2", &[1u8; 32]),
            recovery_auth_message("u1", "rekey", b"dev", "nonce-1", &[2u8; 32]),
        ] {
            assert!(!verify_recovery_auth(&verifier, &bent, &sig));
        }
        assert!(!verify_recovery_auth(b"junk", &msg, &sig));
    }

    const FAST: KdfParams = KdfParams::MIN;

    #[test]
    fn wrap_unwrap_and_wrong_passphrase() {
        let key = [9u8; 32];
        let salt = [1u8; 16];
        let w = wrap_key(&key, "correct horse battery", &salt, FAST).unwrap();
        assert_eq!(unwrap_key(&w, "correct horse battery", &salt, FAST).unwrap(), key);
        assert_eq!(unwrap_key(&w, "correct horse batterz", &salt, FAST), Err(BackupError::Auth));
        assert_eq!(unwrap_key(&w, "correct horse battery", &[2u8; 16], FAST), Err(BackupError::Auth));
    }

    #[test]
    fn weak_inputs_are_refused() {
        assert!(check_passphrase("123456").is_err());
        assert!(check_passphrase("12345678901234567890").is_err(), "long PIN is still a PIN");
        assert!(check_passphrase("aaaaaaaaaaaaaaaaaaaa").is_err());
        assert!(check_passphrase("short pass").is_err());
        assert!(check_passphrase("correct horse battery staple").is_ok());
        assert!(check_passphrase(&generate_recovery_key()).is_ok());
        // Long enough, varied enough — and at the top of every cracking list (crypto M-2).
        for guessable in [
            "password123456",
            "qwertyuiop1234",
            "Password123456!",
            "iloveyou20242024",
            "abcdefghijklmnop",
            "abcabcabcabcabc1",
            "1q2w3e4r5t6y7u8i",
            "letmein123letmein",
            "zyxwvutsrqponm98",
            "welcome2024summer",
        ] {
            assert!(check_passphrase(guessable).is_err(), "{guessable} ({:.0} bits)", passphrase_guess_bits(guessable));
            assert!(passphrase_guess_bits(guessable) < 40.0, "{guessable} ({:.0} bits)", passphrase_guess_bits(guessable));
        }
        for fine in ["tulip-anvil-crater-moss", "Vx9#mQ2!pLz7@wRt", "my cat naps on the radiator", "größe-ändern-über-straße"] {
            assert!(check_passphrase(fine).is_ok(), "{fine} ({:.0} bits)", passphrase_guess_bits(fine));
        }
        // A KDF cost a hostile server picked to exhaust a phone is refused too (crypto L-6).
        assert!(!KdfParams { m_kib: 1024 * 1024, t: 3, p: 1 }.acceptable());
        assert!(!KdfParams { m_kib: 64 * 1024, t: 16, p: 1 }.acceptable());
        assert!(KdfParams::DEFAULT.acceptable() && KdfParams { m_kib: 256 * 1024, t: 6, p: 1 }.acceptable());
        // Downgraded KDF parameters (as a hostile server might return) are refused.
        let weak = KdfParams { m_kib: 8, t: 1, p: 1 };
        assert_eq!(wrap_key(&[0; 32], "x", &[0u8; 16], weak), Err(BackupError::BadParams));
        assert_eq!(unwrap_key(&[0; 60], "x", &[0u8; 16], KdfParams { m_kib: u32::MAX, t: 3, p: 1 }), Err(BackupError::BadParams));
        assert_eq!(wrap_key(&[0; 32], "x", &[0u8; 8], FAST), Err(BackupError::BadSalt));
    }

    /// The recovery approval code is 80 bits (crypto M-1): four groups of four Crockford
    /// characters, a function of the install hash alone.
    #[test]
    fn recovery_code_is_eighty_bits() {
        let a = recovery_fingerprint(&[1u8; 32]);
        assert_eq!(a.len(), 19);
        assert_eq!(a.split('-').map(str::len).collect::<Vec<_>>(), [4, 4, 4, 4]);
        assert!(a.chars().all(|c| c == '-' || b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&(c as u8))));
        assert_eq!(a, recovery_fingerprint(&[1u8; 32]));
        // Over many inputs every one of the 16 positions takes many values: all 80 bits are used.
        let codes: Vec<String> = (0u32..256).map(|i| recovery_fingerprint(&i.to_le_bytes()).replace('-', "")).collect();
        for pos in 0..16 {
            let mut seen: Vec<u8> = codes.iter().map(|c| c.as_bytes()[pos]).collect();
            seen.sort_unstable();
            seen.dedup();
            assert!(seen.len() >= 24, "position {pos} takes only {} values", seen.len());
        }
    }

    #[test]
    fn recovery_key_shape() {
        let k = generate_recovery_key();
        assert_eq!(k.len(), 39);
        assert_eq!(k.split('-').count(), 8);
        assert_ne!(k, generate_recovery_key());
    }
}
