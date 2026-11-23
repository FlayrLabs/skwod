//! Proof-of-work for UNAUTHENTICATED first contact over p2p (signup / login).
//!
//! A p2p caller's only identity is its node id, and node ids are free. Rate limits keyed on them
//! are therefore either evadable (per key) or a lock-out lever (shared). So every credential-
//! testing request over p2p must carry a stamp that costs CPU to make:
//!
//! ```text
//! stamp  = "<window>.<nonce>"                       (header `x-skwod-pow`)
//! valid  ⇔ SHA-256("skwod-pow-v1" ‖ host id ‖ member id ‖ window ‖ nonce) has ≥ POW_BITS leading zero bits
//! window = unix time / 600 s; the host accepts its current window ± 1, each stamp once
//! ```
//!
//! - Bound to the HOST id: a stamp can't be reused against another skwod.
//! - Bound to the MEMBER id (authenticated by the QUIC handshake): a stamp can't be handed to, or
//!   farmed for, another connection.
//! - Bound to a time window + single use: no stockpiling, no replay.
//!
//! Cost: 2^20 ≈ 1 M hashes per request — a few tenths of a second once per login on a phone,
//! done transparently by the loopback proxy (`proxy.rs`); the apps never see it. For what it buys
//! on the server side see `server/src/client_key.rs`.

use sha2::{Digest, Sha256};

/// Required leading zero bits.
pub const POW_BITS: u32 = 20;
/// Request header carrying the stamp.
pub const POW_HEADER: &str = "x-skwod-pow";
/// Response header (on `428`) telling a client with a skewed clock which window to use.
pub const POW_WINDOW_HEADER: &str = "x-skwod-pow-window";
pub const WINDOW_SECS: u64 = 600;

pub fn current_window() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) / WINDOW_SECS
}

/// Most bits a host may ask for, and a member will work for (64 × the base cost: a second
/// or so on a laptop, several on a phone — only ever asked while the host is being flooded).
pub const MAX_POW_BITS: u32 = 26;
/// Response header (on `428`) telling the client how many bits the host wants right now.
pub const POW_BITS_HEADER: &str = "x-skwod-pow-bits";
/// Bits for a CONNECTION stamp (`host.rs`, admission): sent once per connection by every
/// member, so it is cheap — a few tens of milliseconds on a phone.
pub const CONN_POW_BITS: u32 = 18;

/// What a stamp is for. The label is hashed in, so a stamp made for one purpose is not a
/// stamp for the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// An unauthenticated request (signup / login): header `x-skwod-pow`.
    Request,
    /// Holding a connection slot (`wire::KIND_PROOF`).
    Connection,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::Request => b"skwod-pow-v1",
            Purpose::Connection => b"skwod-pow-conn-v1",
        }
    }
}

fn digest(host: &[u8; 32], member: &[u8; 32], window: u64, nonce: u64) -> [u8; 32] {
    digest_for(Purpose::Request, host, member, window, nonce)
}

fn digest_for(purpose: Purpose, host: &[u8; 32], member: &[u8; 32], window: u64, nonce: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(purpose.label());
    h.update(host);
    h.update(member);
    h.update(window.to_be_bytes());
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

fn leading_zero_bits(d: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for b in d {
        if *b == 0 {
            bits += 8;
        } else {
            return bits + b.leading_zeros();
        }
    }
    bits
}

/// Make a stamp for `window`. CPU-bound (~2^POW_BITS hashes): call from a blocking context.
pub fn solve(host: &[u8; 32], member: &[u8; 32], window: u64) -> String {
    // Random start so two requests in one window never collide on a nonce.
    let mut nonce: u64 = rand::random();
    loop {
        if leading_zero_bits(&digest(host, member, window, nonce)) >= POW_BITS {
            return format!("{window}.{nonce}");
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// [`solve`] for a chosen purpose and difficulty (`bits` is capped at [`MAX_POW_BITS`]: a
/// host cannot make a member burn unbounded CPU).
pub fn solve_for(purpose: Purpose, host: &[u8; 32], member: &[u8; 32], window: u64, bits: u32) -> String {
    let bits = bits.min(MAX_POW_BITS);
    let mut nonce: u64 = rand::random();
    loop {
        if leading_zero_bits(&digest_for(purpose, host, member, window, nonce)) >= bits {
            return format!("{window}.{nonce}");
        }
        nonce = nonce.wrapping_add(1);
    }
}

/// [`verify`] for a chosen purpose and difficulty.
pub fn verify_for(purpose: Purpose, host: &[u8; 32], member: &[u8; 32], stamp: &str, now_window: u64, bits: u32) -> Result<(u64, u64), PowError> {
    let (window, nonce) = stamp.split_once('.').ok_or(PowError::Invalid)?;
    let window: u64 = window.parse().map_err(|_| PowError::Invalid)?;
    let nonce: u64 = nonce.parse().map_err(|_| PowError::Invalid)?;
    if window.abs_diff(now_window) > 1 {
        return Err(PowError::WrongWindow);
    }
    if leading_zero_bits(&digest_for(purpose, host, member, window, nonce)) < bits {
        return Err(PowError::Invalid);
    }
    Ok((window, nonce))
}

/// How many bits a host asks for, given how full its record of spent stamps is (audit P6).
/// The difficulty was fixed, so the cost of filling that record — which locks every new
/// sign-in out — was fixed too, and within reach of one GPU. Now each doubling of the fill
/// beyond 1/64 of capacity costs one more bit: by the time the record is half full a stamp
/// costs 32 × the base, and the flood's price has risen with it. An idle host asks for
/// [`POW_BITS`], which every build can do.
pub fn required_bits(spent: usize, capacity: usize) -> u32 {
    let floor = (capacity / 64).max(1);
    let mut bits = POW_BITS;
    let mut level = floor;
    while spent > level && bits < MAX_POW_BITS {
        bits += 1;
        level = level.saturating_mul(2);
    }
    bits
}

#[derive(Debug, PartialEq, Eq)]
pub enum PowError {
    /// Missing, malformed, or not enough work.
    Invalid,
    /// Well-formed but for a window the host doesn't accept (clock skew / stale).
    WrongWindow,
}

/// Check a stamp against the host's `now_window`. Returns `(window, nonce)` — the caller must
/// additionally make sure each pair is accepted only ONCE per member.
pub fn verify(host: &[u8; 32], member: &[u8; 32], stamp: &str, now_window: u64) -> Result<(u64, u64), PowError> {
    let (window, nonce) = stamp.split_once('.').ok_or(PowError::Invalid)?;
    let window: u64 = window.parse().map_err(|_| PowError::Invalid)?;
    let nonce: u64 = nonce.parse().map_err(|_| PowError::Invalid)?;
    if window.abs_diff(now_window) > 1 {
        return Err(PowError::WrongWindow);
    }
    if leading_zero_bits(&digest(host, member, window, nonce)) < POW_BITS {
        return Err(PowError::Invalid);
    }
    Ok((window, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_verify_and_are_bound_to_host_member_and_window() {
        let (host, member, other) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let stamp = solve(&host, &member, 1000);
        assert_eq!(verify(&host, &member, &stamp, 1000).map(|(w, _)| w), Ok(1000));
        assert!(verify(&host, &member, &stamp, 1001).is_ok(), "±1 window of clock skew is tolerated");
        assert_eq!(verify(&host, &member, &stamp, 1002), Err(PowError::WrongWindow), "stale stamps die");
        assert_eq!(verify(&other, &member, &stamp, 1000), Err(PowError::Invalid), "not valid for another host");
        assert_eq!(verify(&host, &other, &stamp, 1000), Err(PowError::Invalid), "not valid for another member key");
        for junk in ["", "1000", "1000.", "x.y", "1000.1"] {
            assert!(verify(&host, &member, junk, 1000).is_err(), "{junk:?}");
        }
    }

    #[test]
    fn work_is_actually_required() {
        // A random nonce passes with probability 2^-20; 2000 of them must all fail.
        let (host, member) = ([7u8; 32], [8u8; 32]);
        assert!((0..2000u64).all(|n| verify(&host, &member, &format!("5.{n}"), 5).is_err()));
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
        let mut d = [0u8; 32];
        d[2] = 0b0001_0000;
        assert_eq!(leading_zero_bits(&d), 19);
    }

    #[test]
    fn a_connection_stamp_is_not_a_request_stamp_and_difficulty_rises_with_load() {
        let (host, member) = ([1u8; 32], [2u8; 32]);
        let w = current_window();
        let conn = solve_for(Purpose::Connection, &host, &member, w, 12);
        assert!(verify_for(Purpose::Connection, &host, &member, &conn, w, 12).is_ok());
        assert!(verify_for(Purpose::Connection, &host, &[3u8; 32], &conn, w, 12).is_err(), "bound to the member");
        assert!(verify_for(Purpose::Request, &host, &member, &conn, w, 12).is_err(), "bound to its purpose");
        assert!(verify_for(Purpose::Connection, &host, &member, &conn, w + 2, 12).is_err(), "bound to its window");
        // A stamp with more work than asked passes; one with less does not.
        let hard = solve_for(Purpose::Request, &host, &member, w, 14);
        assert!(verify_for(Purpose::Request, &host, &member, &hard, w, 12).is_ok());
        let easy = (0..).map(|_| solve_for(Purpose::Request, &host, &member, w, 4)).find(|s| verify_for(Purpose::Request, &host, &member, s, w, 16).is_err()).unwrap();
        assert!(verify_for(Purpose::Request, &host, &member, &easy, w, 4).is_ok());

        // Idle: the base difficulty. Then one bit per doubling of the spent-stamp record.
        let cap = 200_000;
        assert_eq!(required_bits(0, cap), POW_BITS);
        assert_eq!(required_bits(cap / 64, cap), POW_BITS);
        assert_eq!(required_bits(cap / 64 + 1, cap), POW_BITS + 1);
        assert_eq!(required_bits(cap / 2, cap), POW_BITS + 5);
        assert_eq!(required_bits(cap, cap), MAX_POW_BITS);
        assert!((0..=cap).step_by(997).map(|n| required_bits(n, cap)).is_sorted());
    }
}
