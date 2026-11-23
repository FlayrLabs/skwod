//! In-memory fixed-window rate limiter. Per-process state is correct for the single-binary
//! deployment model (ADR-005); limits mirror the original edge functions' per-user windows.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::ApiError;
use crate::state::now_ms;

/// (window start, hits, THIS entry's window length) — all in ms.
type Window = (i64, u32, i64);

#[derive(Clone, Default)]
pub struct RateLimiter {
    windows: Arc<Mutex<Windows>>,
}

#[derive(Default)]
struct Windows {
    map: HashMap<String, Window>,
    /// When expired windows were last swept out (ms).
    swept_at: i64,
}

/// Entries above which a `check` first sweeps out expired windows…
const GC_THRESHOLD: usize = 10_000;
/// …and how often they are swept whatever the count (audit M-1: with only the count, a few
/// thousand large keys were kept for good — the sweep never ran).
const SWEEP_EVERY_MS: i64 = MINUTE;
/// Longest key kept verbatim. Keys are built from ids and validated names and are far
/// shorter; anything longer is caller-controlled text that got into a key, and is replaced by
/// its SHA-256 so no caller chooses how much memory an entry takes.
const MAX_KEY: usize = 200;

/// `key` as it is stored: itself, or its digest when it is over [`MAX_KEY`].
fn stored_key(key: &str) -> std::borrow::Cow<'_, str> {
    if key.len() <= MAX_KEY {
        return std::borrow::Cow::Borrowed(key);
    }
    use sha2::{Digest, Sha256};
    std::borrow::Cow::Owned(format!("sha256:{}", hex::encode(Sha256::digest(key.as_bytes()))))
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one hit for `key`; error if it exceeds `limit` within `window_ms`.
    pub fn check(&self, key: &str, limit: u32, window_ms: i64) -> Result<(), ApiError> {
        self.check_at(key, limit, window_ms, now_ms())
    }

    fn check_at(&self, key: &str, limit: u32, window_ms: i64, now: i64) -> Result<(), ApiError> {
        let key = stored_key(key);
        let mut windows = self.windows.lock().expect("limiter lock");
        // GC so the map can't grow unboundedly: when it is large, and on a timer regardless.
        // Each entry is judged by ITS OWN window: this used to apply the CURRENT caller's
        // `window_ms` to every entry, so a burst of short-window keys (per-minute) wiped
        // still-running long windows (per-hour) and reset their counts.
        if windows.map.len() > GC_THRESHOLD || now - windows.swept_at >= SWEEP_EVERY_MS {
            windows.map.retain(|_, (start, _, window)| now - *start < *window);
            windows.swept_at = now;
        }
        let map = &mut windows.map;
        let entry = map.entry(key.into_owned()).or_insert((now, 0, window_ms));
        if now - entry.0 >= entry.2 {
            *entry = (now, 0, window_ms);
        }
        entry.2 = window_ms;
        entry.1 += 1;
        if entry.1 > limit {
            Err(ApiError::RateLimited)
        } else {
            Ok(())
        }
    }

    /// Is there room for one more hit for `key`? Counts NOTHING. For an operation that
    /// consumes something on its way (a single-use proof, a recovery key) and must therefore
    /// be refused BEFORE it starts, while only the ones that complete are counted ([`hit`]).
    ///
    /// [`hit`]: RateLimiter::hit
    pub fn has_room(&self, key: &str, limit: u32) -> Result<(), ApiError> {
        let now = now_ms();
        let windows = self.windows.lock().expect("limiter lock");
        match windows.map.get(stored_key(key).as_ref()) {
            Some((start, hits, window)) if now - *start < *window && *hits >= limit => Err(ApiError::RateLimited),
            _ => Ok(()),
        }
    }

    /// Count one completed operation for `key`. Never refuses: by now it has happened.
    pub fn hit(&self, key: &str, window_ms: i64) {
        let _ = self.check(key, u32::MAX, window_ms);
    }

    /// Count one attempt for `key` BEFORE it is judged, to be given back with [`refund`] if
    /// it turns out not to count (a sign-in that succeeded). Taking it first is what makes a
    /// "failures only" window hold against parallel requests: looking (`has_room`), verifying
    /// and then counting let a burst all look before any of it was counted.
    ///
    /// [`refund`]: RateLimiter::refund
    pub fn take(&self, key: &str, limit: u32, window_ms: i64) -> Result<(), ApiError> {
        match self.check(key, limit, window_ms) {
            Ok(()) => Ok(()),
            Err(e) => {
                // The refused attempt itself is not counted: only verified failures are.
                self.refund(key);
                Err(e)
            }
        }
    }

    /// Give back one attempt taken with [`take`](RateLimiter::take).
    pub fn refund(&self, key: &str) {
        let mut windows = self.windows.lock().expect("limiter lock");
        if let Some(entry) = windows.map.get_mut(stored_key(key).as_ref()) {
            entry.1 = entry.1.saturating_sub(1);
        }
    }

    /// Start `key`'s window over (tests: "an hour later").
    #[cfg(test)]
    pub(crate) fn forget(&self, key: &str) {
        self.windows.lock().expect("limiter lock").map.remove(stored_key(key).as_ref());
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.windows.lock().expect("limiter lock").map.len()
    }

    /// Bytes of key text held (tests: what a caller can make the limiter keep).
    #[cfg(test)]
    pub(crate) fn key_bytes(&self) -> usize {
        self.windows.lock().expect("limiter lock").map.keys().map(String::len).sum()
    }
}

/// A set of values that may each be used ONCE until they expire — used proof-of-work stamps.
/// Separate from [`RateLimiter`] on purpose: nothing but an entry's own expiry ever removes it,
/// and when it is full it refuses new entries (fail closed) instead of evicting live ones —
/// either would let a used stamp be replayed.
#[derive(Clone, Default)]
pub struct OnceSet {
    used: Arc<Mutex<HashMap<String, i64>>>,
}

impl OnceSet {
    /// Live entries above which `insert` refuses (after sweeping expired ones). At one stamp per
    /// counted sign-in attempt this is far above what the per-minute ceilings admit in a stamp's
    /// lifetime.
    pub const CAPACITY: usize = 200_000;

    /// Record `value` until `expires_at_ms`. `false` if it is already recorded (a replay) or the
    /// set is full.
    pub fn insert(&self, value: &str, expires_at_ms: i64) -> bool {
        self.insert_at(value, expires_at_ms, now_ms())
    }

    /// Entries held right now (expired ones included until the next sweep): how hard the
    /// spent-stamp record is being pushed, which sets the proof-of-work difficulty.
    pub fn len(&self) -> usize {
        self.live_at(now_ms())
    }

    /// Entries that have not expired at `now`. Expired ones are dropped here: the count
    /// sets the proof-of-work difficulty, which has to come back DOWN when a flood is over —
    /// counting dead entries (they were only swept when the set was full) would have let a
    /// trickle of sign-ins raise it for good.
    fn live_at(&self, now: i64) -> usize {
        let mut used = self.used.lock().expect("once-set lock");
        used.retain(|_, exp| *exp > now);
        used.len()
    }

    fn insert_at(&self, value: &str, expires_at_ms: i64, now: i64) -> bool {
        let mut used = self.used.lock().expect("once-set lock");
        if used.get(value).is_some_and(|exp| *exp > now) {
            return false;
        }
        if used.len() >= Self::CAPACITY {
            used.retain(|_, exp| *exp > now);
            if used.len() >= Self::CAPACITY {
                return false;
            }
        }
        used.insert(value.to_string(), expires_at_ms);
        true
    }
}

/// Common windows.
pub const MINUTE: i64 = 60 * 1000;
pub const HOUR: i64 = 60 * MINUTE;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_limit_within_window() {
        let l = RateLimiter::new();
        assert!(l.check("k", 2, MINUTE).is_ok());
        assert!(l.check("k", 2, MINUTE).is_ok());
        assert!(l.check("k", 2, MINUTE).is_err(), "third hit exceeds limit 2");
        // Independent keys don't interfere.
        assert!(l.check("other", 2, MINUTE).is_ok());
    }

    #[test]
    fn short_window_flood_does_not_evict_long_window_entries() {
        let l = RateLimiter::new();
        // A long-window entry at its limit…
        assert!(l.check("hourly", 1, HOUR).is_ok());
        assert!(l.check("hourly", 1, HOUR).is_err());
        // …then a flood of distinct SHORT-window keys, enough to trigger GC many times over, with
        // time passing so the short windows genuinely expire.
        const SHORT: i64 = 20;
        for i in 0..(GC_THRESHOLD + 500) {
            assert!(l.check(&format!("flood-a-{i}"), 1, SHORT).is_ok());
        }
        std::thread::sleep(std::time::Duration::from_millis(SHORT as u64 + 30));
        for i in 0..(GC_THRESHOLD + 500) {
            assert!(l.check(&format!("flood-b-{i}"), 1, SHORT).is_ok());
        }
        // GC ran and removed expired short windows…
        assert!(l.len() < 2 * (GC_THRESHOLD + 500), "expired short-window entries were collected ({})", l.len());
        // …but the long window survived with its count: still limited. (Before the fix the GC
        // judged it by the flood's 20 ms window, dropped it, and this call succeeded.)
        assert!(l.check("hourly", 1, HOUR).is_err(), "a long-window entry must outlive a short-window flood");
    }

    /// Audit M-1: a key is never longer than a digest, and expired windows are swept on a
    /// timer — not only once ten thousand of them have piled up.
    #[test]
    fn keys_are_bounded_and_expired_windows_are_swept_on_a_timer() {
        let l = RateLimiter::new();
        let huge = "x".repeat(2 * 1024 * 1024);
        assert!(l.check(&format!("login:{huge}"), 1, MINUTE).is_ok());
        assert!(l.check(&format!("login:{huge}"), 1, MINUTE).is_err(), "still the same key: the limit holds");
        assert!(l.has_room(&format!("login:{huge}"), 1).is_err());
        assert!(l.key_bytes() < 100, "{} bytes kept for a 2 MB key", l.key_bytes());
        l.forget(&format!("login:{huge}"));
        assert_eq!(l.len(), 0);

        // A few entries (far below the count threshold) with a short window…
        let l = RateLimiter::new();
        let t0 = 1_000_000;
        for i in 0..50 {
            assert!(l.check_at(&format!("short-{i}"), 1, 1_000, t0).is_ok());
        }
        assert!(l.check_at("hourly", 1, HOUR, t0).is_ok());
        assert_eq!(l.len(), 51);
        // …are gone at the first check after the sweep interval; a running window is kept.
        assert!(l.check_at("later", 1, MINUTE, t0 + SWEEP_EVERY_MS).is_ok());
        assert_eq!(l.len(), 2, "expired windows were swept; `hourly` and `later` remain");
        assert!(l.check_at("hourly", 1, HOUR, t0 + SWEEP_EVERY_MS).is_err());
    }

    #[test]
    fn once_set_survives_floods_and_only_expiry_frees_a_value() {
        let s = OnceSet::default();
        let now = 1_000_000;
        assert!(s.insert_at("stamp-1", now + 60_000, now));
        assert!(!s.insert_at("stamp-1", now + 60_000, now), "second use is a replay");
        // A flood of other (even already-expired) values never evicts a live one.
        for i in 0..50_000 {
            s.insert_at(&format!("flood-{i}"), now - 1, now);
        }
        assert!(!s.insert_at("stamp-1", now + 60_000, now + 59_999), "still remembered right up to its expiry");
        assert!(s.insert_at("stamp-1", now + 120_000, now + 60_000), "free again only once expired");
    }

    #[test]
    fn the_live_count_falls_when_stamps_expire() {
        let s = OnceSet::default();
        let now = 1_000_000;
        for i in 0..5_000 {
            assert!(s.insert_at(&format!("s-{i}"), now + 60_000, now));
        }
        assert_eq!(s.live_at(now + 59_999), 5_000);
        assert_eq!(s.live_at(now + 60_000), 0, "a flood that is over no longer counts");
    }

    #[test]
    fn once_set_fails_closed_when_full() {
        let s = OnceSet::default();
        let now = 1_000_000;
        for i in 0..OnceSet::CAPACITY {
            assert!(s.insert_at(&format!("live-{i}"), now + 60_000, now));
        }
        assert!(!s.insert_at("one-more", now + 60_000, now), "full of LIVE entries: refuse, never evict");
        assert!(!s.insert_at("live-0", now + 60_000, now), "and everything recorded is still a replay");
        assert!(s.insert_at("one-more", now + 120_000, now + 60_001), "expired entries make room");
    }

    #[test]
    fn window_rolls_over() {
        const WINDOW: i64 = 200;
        let l = RateLimiter::new();
        assert!(l.check("k", 1, WINDOW).is_ok());
        assert!(l.check("k", 1, WINDOW).is_err());
        std::thread::sleep(std::time::Duration::from_millis(WINDOW as u64 + 50));
        assert!(l.check("k", 1, WINDOW).is_ok(), "fresh window after expiry");
    }
}
