//! Who is this request from, for rate limiting — without trusting anything the client can forge
//! and without ever logging it.
//!
//! - **p2p (iroh) request** → the peer's node id (`node:<id>`), authenticated by the QUIC
//!   handshake. No IP is involved or known to this layer at all.
//! - **TCP request from a trusted proxy** (loopback, or a peer in `SKWOD_TRUSTED_PROXIES`) → the
//!   RIGHTMOST `X-Forwarded-For` hop: the address the trusted proxy itself observed. Anything to
//!   the left is client-supplied and ignored.
//! - **any other TCP request** → the socket peer address. `X-Forwarded-For` is ignored entirely
//!   (it used to be trusted blindly — one request with a forged header per attempt defeated every
//!   per-IP limit).
//!
//! The key lives only in the in-memory limiter window and is never written to a log or the DB.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::limiter::MINUTE;
use crate::state::AppState;

/// Set (as a request extension) on every request that arrived over the p2p tunnel.
#[derive(Clone, Debug)]
pub struct P2pPeer {
    /// The caller's node id (z-base-32), authenticated by the QUIC handshake.
    pub node: String,
    pub node_bytes: [u8; 32],
    /// Whether the connection runs through a relay (no source address was ever seen for it).
    pub relayed: bool,
}

/// The rate-limit identity of the caller.
pub struct ClientKey {
    pub(crate) key: String,
    /// `Some` for p2p callers.
    p2p: Option<P2pCaller>,
}

struct P2pCaller {
    node_bytes: [u8; 32],
    relayed: bool,
    /// The `x-skwod-pow` header, if any (see `skwod_net::pow`).
    stamp: Option<String>,
}

/// Ceiling on counted (= stamped) unauthenticated hits per minute for each p2p population
/// (direct, relayed), as a multiple of one caller's allowance. See [`ClientKey::limit_unauthenticated`].
pub const P2P_SHARED_FACTOR: u32 = 50;

/// One `ip` or `ip/prefix` entry of `SKWOD_TRUSTED_PROXIES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, prefix) = match s.trim().split_once('/') {
            Some((ip, p)) => (ip, Some(p.parse::<u8>().ok()?)),
            None => (s.trim(), None),
        };
        let addr: IpAddr = ip.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        fn bits(ip: IpAddr) -> (u128, u8) {
            match ip {
                IpAddr::V4(v4) => (u32::from(v4) as u128, 32),
                IpAddr::V6(v6) => (u128::from(v6), 128),
            }
        }
        let ((net, width), (ip, ip_width)) = (bits(self.addr), bits(ip));
        if width != ip_width {
            return false;
        }
        let shift = (width - self.prefix) as u32;
        self.prefix == 0 || (net >> shift) == (ip >> shift)
    }
}

pub fn parse_trusted_proxies(list: &str) -> Vec<IpNet> {
    list.split(',').filter(|s| !s.trim().is_empty()).filter_map(IpNet::parse).collect()
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`, what a dual-stack listener reports) → plain IPv4.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// The limiter bucket for an address: the IPv4 address itself, or the IPv6 **/64** — a single
/// subscriber controls a whole /64, so per-address IPv6 buckets would be no limit at all.
fn bucket(ip: IpAddr) -> String {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
    }
}

pub(crate) fn tcp_client_key(peer: Option<IpAddr>, forwarded_for: Option<&str>, trusted: &[IpNet]) -> String {
    let Some(peer) = peer.map(canonical) else { return "unknown".to_string() };
    // Only a proxy the operator NAMED is believed (`SKWOD_TRUSTED_PROXIES`). Loopback is not
    // trusted by default: any local process could otherwise pick its own rate-limit bucket per
    // request. A reverse proxy on the same machine is configured as `127.0.0.1,::1`.
    if trusted.iter().any(|n| n.contains(peer)) {
        if let Some(hop) = forwarded_for
            .and_then(|v| v.rsplit(',').next())
            .and_then(|h| h.trim().parse::<IpAddr>().ok())
        {
            return bucket(hop);
        }
    }
    bucket(peer)
}

#[axum::async_trait]
impl FromRequestParts<AppState> for ClientKey {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if let Some(peer) = parts.extensions.get::<P2pPeer>() {
            let stamp = parts.headers.get(skwod_net::pow::POW_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string);
            let caller = P2pCaller { node_bytes: peer.node_bytes, relayed: peer.relayed, stamp };
            return Ok(Self { key: format!("node:{}", peer.node), p2p: Some(caller) });
        }
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
        let xff = parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok());
        Ok(Self { key: tcp_client_key(peer, xff, &state.trusted_proxies), p2p: None })
    }
}

impl ClientKey {
    /// Count one hit in `bucket` for this caller: at most `per_minute` per caller. For routes
    /// that already authenticated the caller — no bucket is shared with anyone else, and no
    /// proof of work is asked.
    pub fn limit(&self, state: &AppState, bucket: &str, per_minute: u32) -> Result<(), ApiError> {
        state.limiter.check(&format!("{bucket}:ip:{}", self.key), per_minute, MINUTE)
    }

    /// Gate for UNAUTHENTICATED, credential-testing routes (signup, login).
    ///
    /// TCP callers: per-IP window (IPv4 address / IPv6 /64), as before.
    ///
    /// p2p callers have no address, only a node id — which is free to mint. So the design does
    /// not rest on counting identities; it rests on making every attempt COST something:
    ///
    /// 1. **Proof of work, first.** The request must carry a stamp (`skwod_net::pow`): 2^20
    ///    SHA-256 bound to this host, to the caller's QUIC-authenticated node id, and to a time
    ///    window; each stamp is accepted once. No stamp → `428`, and the request is NOT counted
    ///    in any bucket below — an attacker cannot consume anybody's allowance for free.
    /// 2. **Per caller**: `per_minute` per node id.
    /// 3. **Per account** (`auth.rs`): 10/min per username, whatever the caller. This is what
    ///    actually protects a password; no amount of keys or work gets around it.
    /// 4. **Per population ceiling**: `P2P_SHARED_FACTOR × per_minute` stamped hits per minute,
    ///    kept SEPARATELY for direct and for relayed callers, so flooding one population cannot
    ///    lock out the other.
    ///
    /// What it takes to hit a ceiling (login: per_minute = 30 → ceiling 1500/min):
    /// - 1500 fresh stamps per minute = 1500 × 2^20 ≈ 1.6 × 10^9 hashes/min ≈ 26 M SHA-256/s,
    ///   sustained for as long as the lockout is to last — several dedicated CPU cores, versus
    ///   ~0.1–0.4 s of one core, once, for a real login. Stamps can't be stockpiled (window) or
    ///   shared between keys (bound to the node id), and
    /// - at least 50 distinct node ids (each is capped at `per_minute` by layer 2). Direct: the
    ///   accept loop admits 30 new connections/min per IPv4 / IPv6 /64, so one source address
    ///   tops out at 30 × 30 = 900 < 1500 — it cannot reach the direct ceiling at all, however
    ///   much work it does. Relayed: the relay token bucket admits ≤ 120 new connections/min
    ///   (120 × 30 = 3600 > 1500), so there the ceiling CAN be reached by one attacker — but only
    ///   by paying the full ≈ 26 M hashes/s, and it only affects new relayed sign-ins.
    ///
    /// Since the second build-45 audit two of those numbers moved, both in the defender's
    /// favour: connections beyond the per-source / relay allowance are still admitted, but
    /// each for a connection stamp of its own (2^18 hashes, `skwod_net::host`), so "more
    /// node ids" now costs work as well; and the stamp difficulty here is no longer fixed —
    /// it rises one bit per doubling of the spent-stamp record beyond 1/64 full
    /// (`pow::required_bits`), so sustaining a ceiling costs up to 64 × the figures above.
    ///
    /// In every case the effect of reaching a ceiling is limited to signup/login of that one
    /// population for the current minute: authenticated requests never touch these buckets.
    pub fn limit_unauthenticated(&self, state: &AppState, bucket: &str, per_minute: u32) -> Result<(), ApiError> {
        let Some(caller) = &self.p2p else { return self.limit(state, bucket, per_minute) };
        use skwod_net::pow;
        let now = pow::current_window();
        // The difficulty rises with how full the record of spent stamps is (audit P6): the
        // record is what a flood has to fill to lock new sign-ins out, and at a fixed 2^20
        // one GPU could. Idle, it is the base every build can do.
        let bits = pow::required_bits(state.used_stamps.len(), crate::limiter::OnceSet::CAPACITY);
        let required = || if bits > pow::POW_BITS { ApiError::PowRequiredBits(now, bits) } else { ApiError::PowRequired(now) };
        let host = state.p2p.get().map(|s| s.node_bytes).ok_or(ApiError::Internal)?;
        let stamp = caller.stamp.as_deref().ok_or_else(required)?;
        let (window, nonce) = pow::verify_for(pow::Purpose::Request, &host, &caller.node_bytes, stamp, now, bits).map_err(|_| required())?;
        // Layer 2 BEFORE the stamp is recorded: one node id adds at most its own per-minute
        // allowance to the record, however many valid stamps it brings.
        self.limit(state, bucket, per_minute)?;
        // Single use. Spent stamps live in their own expiring set (NOT the rate limiter): an
        // entry leaves only when its own lifetime — longer than any window in which the stamp
        // could still verify — is over, and a full set refuses rather than forgets.
        let expires = crate::state::now_ms() + 3 * 1000 * pow::WINDOW_SECS as i64;
        if !state.used_stamps.insert(&format!("{}:{window}.{nonce}", self.key), expires) {
            return Err(required());
        }
        self.count_stamped(state, bucket, per_minute, caller.relayed)
    }

    /// Layer 4 for a request whose stamp has been verified and counted for its caller.
    fn count_stamped(&self, state: &AppState, bucket: &str, per_minute: u32, relayed: bool) -> Result<(), ApiError> {
        let population = if relayed { "p2p-relayed" } else { "p2p-direct" };
        state.limiter.check(&format!("{bucket}:{population}"), per_minute.saturating_mul(P2P_SHARED_FACTOR), MINUTE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_for() {
        // The old behaviour: a direct client rotating X-Forwarded-For got a fresh bucket each time.
        assert_eq!(tcp_client_key(ip("203.0.113.7"), Some("1.2.3.4"), &[]), "203.0.113.7");
        assert_eq!(tcp_client_key(ip("203.0.113.7"), Some("9.9.9.9, 8.8.8.8"), &[]), "203.0.113.7");
    }

    #[test]
    fn trusted_proxy_uses_rightmost_hop() {
        // Client-supplied junk on the left, the proxy-observed address on the right.
        let trusted = parse_trusted_proxies("172.16.0.0/12, 10.1.2.3, 127.0.0.1");
        assert_eq!(tcp_client_key(ip("127.0.0.1"), Some("6.6.6.6, 198.51.100.4"), &trusted), "198.51.100.4");
        assert_eq!(tcp_client_key(ip("172.18.0.5"), Some("198.51.100.4"), &trusted), "198.51.100.4");
        assert_eq!(tcp_client_key(ip("10.1.2.3"), Some("198.51.100.4"), &trusted), "198.51.100.4");
        assert_eq!(tcp_client_key(ip("10.1.2.4"), Some("198.51.100.4"), &trusted), "10.1.2.4");
        // No / unparsable header from a trusted proxy → fall back to the proxy itself.
        assert_eq!(tcp_client_key(ip("127.0.0.1"), None, &trusted), "127.0.0.1");
        assert_eq!(tcp_client_key(ip("127.0.0.1"), Some("not-an-ip"), &trusted), "127.0.0.1");
        assert_eq!(tcp_client_key(ip("::ffff:127.0.0.1"), Some("198.51.100.4"), &trusted), "198.51.100.4");
        assert_eq!(tcp_client_key(None, Some("1.2.3.4"), &trusted), "unknown");
    }

    /// Audit L9: loopback is a peer like any other. A local process cannot choose its own
    /// rate-limit bucket by sending `X-Forwarded-For`, unless the operator said a proxy lives there.
    #[test]
    fn loopback_is_not_a_trusted_proxy_unless_the_operator_says_so() {
        for peer in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "127.8.9.10"] {
            let direct = tcp_client_key(ip(peer), None, &[]);
            assert_eq!(tcp_client_key(ip(peer), Some("1.2.3.4"), &[]), direct, "{peer}: the header is ignored");
            assert_eq!(tcp_client_key(ip(peer), Some("5.6.7.8"), &[]), direct, "{peer}: …whatever it says");
        }
        let trusted = parse_trusted_proxies("127.0.0.1, ::1");
        assert_eq!(tcp_client_key(ip("127.0.0.1"), Some("1.2.3.4"), &trusted), "1.2.3.4");
        assert_eq!(tcp_client_key(ip("::1"), Some("1.2.3.4"), &trusted), "1.2.3.4");
        assert_eq!(tcp_client_key(ip("127.8.9.10"), Some("1.2.3.4"), &trusted), "127.8.9.10", "only the address that was named");
    }

    fn node(n: &str, relayed: bool) -> ClientKey {
        ClientKey { key: format!("node:{n}"), p2p: Some(P2pCaller { node_bytes: [0; 32], relayed, stamp: None }) }
    }

    #[tokio::test]
    async fn p2p_requests_are_keyed_by_node_id_and_authenticated_routes_share_nothing() {
        let (_app, db) = crate::tests::test_app().await;
        let state = AppState::new(db, std::env::temp_dir());
        let mut req = axum::http::Request::builder().uri("/").header("x-forwarded-for", "1.2.3.4").header("x-skwod-pow", "7.9").body(()).unwrap();
        req.extensions_mut().insert(P2pPeer { node: "nodeA".into(), node_bytes: [5; 32], relayed: true });
        let a = ClientKey::from_request_parts(&mut req.into_parts().0, &state).await.unwrap();
        assert_eq!(a.key, "node:nodeA", "the node id — never a header, never an address");
        let caller = a.p2p.as_ref().unwrap();
        assert!(caller.relayed && caller.node_bytes == [5; 32] && caller.stamp.as_deref() == Some("7.9"));
        assert!(a.limit(&state, "t", 2).is_ok() && a.limit(&state, "t", 2).is_ok());
        assert!(a.limit(&state, "t", 2).is_err());
        // Authenticated routes: no shared bucket — a flood of other identities changes nothing.
        for i in 0..500 {
            assert!(node(&format!("rotating{i}"), false).limit(&state, "t", 2).is_ok(), "node {i} has its own window");
        }
        assert!(node("nodeB", false).limit(&state, "t", 2).is_ok(), "an honest member is unaffected by the flood");
    }

    #[tokio::test]
    async fn unstamped_p2p_requests_are_refused_and_never_counted() {
        let (_app, db) = crate::tests::test_app().await;
        let state = AppState::new(db, std::env::temp_dir());
        let host = [9u8; 32];
        let _ = state.p2p.set(crate::p2p::P2pStatus { node_id: "host".into(), node_bytes: host, public_fallback: true });
        let caller = |stamp: Option<String>| ClientKey {
            key: "node:m".into(),
            p2p: Some(P2pCaller { node_bytes: [1; 32], relayed: false, stamp }),
        };
        let now = skwod_net::pow::current_window();
        // No stamp / junk / a stamp made for another node id: 428 with the host's window.
        for bad in [None, Some("garbage".to_string()), Some(skwod_net::pow::solve(&host, &[2; 32], now))] {
            for _ in 0..100 {
                assert!(matches!(caller(bad.clone()).limit_unauthenticated(&state, "login", 3), Err(ApiError::PowRequired(w)) if w == now));
            }
        }
        // …and those 300 refusals consumed NOTHING: the caller's own allowance is intact.
        for _ in 0..3 {
            let stamp = skwod_net::pow::solve(&host, &[1; 32], now);
            assert!(caller(Some(stamp)).limit_unauthenticated(&state, "login", 3).is_ok());
        }
        // The 4th stamped attempt hits the per-caller window; a replayed stamp is refused as such.
        let stamp = skwod_net::pow::solve(&host, &[1; 32], now);
        assert!(matches!(caller(Some(stamp.clone())).limit_unauthenticated(&state, "login", 3), Err(ApiError::RateLimited)));
        // (Refused by the caller's own window BEFORE it is recorded: a node id adds at most
        // its per-minute allowance to the spent-stamp record. Single use is shown below.)
        assert!(matches!(caller(Some(stamp)).limit_unauthenticated(&state, "login", 3), Err(ApiError::RateLimited)));
        assert_eq!(state.used_stamps.len(), 3, "only the three counted stamps were recorded");

        // Regression: a flood of short-window limiter keys (which triggers the limiter's GC)
        // must not make a spent stamp usable again.
        let spent = skwod_net::pow::solve(&host, &[4; 32], now);
        let other = |stamp: String| ClientKey { key: "node:n4".into(), p2p: Some(P2pCaller { node_bytes: [4; 32], relayed: false, stamp: Some(stamp) }) };
        assert!(other(spent.clone()).limit_unauthenticated(&state, "login", 3).is_ok());
        for i in 0..12_000 {
            let _ = state.limiter.check(&format!("flood-{i}"), 1, 1);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
        for i in 0..12_000 {
            let _ = state.limiter.check(&format!("flood2-{i}"), 1, 1);
        }
        assert!(matches!(other(spent).limit_unauthenticated(&state, "login", 3), Err(ApiError::PowRequired(_))), "spent stamps survive limiter GC");
        // Audit P6: under a flood (the spent-stamp record filling up) the host asks for more
        // work, says how much, and a base-difficulty stamp no longer passes.
        for i in 0..(crate::limiter::OnceSet::CAPACITY / 64 + 1) {
            state.used_stamps.insert(&format!("flood-stamp-{i}"), crate::state::now_ms() + 60_000);
        }
        let fresh = |n: u8| ClientKey { key: format!("node:f{n}"), p2p: Some(P2pCaller { node_bytes: [n; 32], relayed: false, stamp: Some(skwod_net::pow::solve(&host, &[n; 32], now)) }) };
        let refused = (50u8..60).filter(|n| matches!(fresh(*n).limit_unauthenticated(&state, "login", 3), Err(ApiError::PowRequiredBits(w, bits)) if w == now && bits == skwod_net::pow::POW_BITS + 1)).count();
        assert!(refused >= 1, "base-difficulty stamps are asked for one more bit (about half of them lack it)");
        let harder = skwod_net::pow::solve_for(skwod_net::pow::Purpose::Request, &host, &[77; 32], now, skwod_net::pow::POW_BITS + 1);
        let strong = ClientKey { key: "node:f77".into(), p2p: Some(P2pCaller { node_bytes: [77; 32], relayed: false, stamp: Some(harder) }) };
        assert!(strong.limit_unauthenticated(&state, "login", 3).is_ok(), "a stamp with the asked-for work passes");
        // TCP callers are not asked for work.
        assert!(ClientKey { key: "203.0.113.5".into(), p2p: None }.limit_unauthenticated(&state, "login", 3).is_ok());
    }

    #[tokio::test]
    async fn stamped_ceilings_are_separate_for_direct_and_relayed() {
        let (_app, db) = crate::tests::test_app().await;
        let state = AppState::new(db, std::env::temp_dir());
        let per_key = 2;
        // The most ONE direct source can do: 30 node ids a minute (accept-loop cap), each spending
        // its whole allowance — 30 × per_key < 50 × per_key, so the direct ceiling is out of reach.
        for i in 0..30 {
            for _ in 0..per_key {
                assert!(node(&format!("one-source-{i}"), false).count_stamped(&state, "login", per_key, false).is_ok());
            }
        }
        assert!(node("honest-direct", false).count_stamped(&state, "login", per_key, false).is_ok());
        // Relayed callers CAN fill their ceiling (given the work)…
        let mut allowed = 0;
        for i in 0..1000 {
            if node(&format!("relayed-{i}"), true).count_stamped(&state, "login", per_key, true).is_ok() {
                allowed += 1;
            }
        }
        assert_eq!(allowed, per_key * P2P_SHARED_FACTOR, "stamped relayed attempts per minute are bounded");
        // …and that leaves direct callers, other buckets, and TCP callers untouched.
        assert!(node("honest-direct-2", false).count_stamped(&state, "login", per_key, false).is_ok());
        assert!(node("x", true).count_stamped(&state, "signup", per_key, true).is_ok());
    }

    #[test]
    fn ipv6_is_bucketed_by_64() {
        let a = tcp_client_key(ip("2001:db8:aa:bb::1"), None, &[]);
        let b = tcp_client_key(ip("2001:db8:aa:bb:ffff:1:2:3"), None, &[]);
        assert_eq!(a, b, "addresses in one /64 share a bucket");
        assert_eq!(a, "2001:db8:aa:bb::/64");
        assert_ne!(a, tcp_client_key(ip("2001:db8:aa:bc::1"), None, &[]));
        // Also for the proxy-observed hop.
        assert_eq!(tcp_client_key(ip("127.0.0.1"), Some("2001:db8:aa:bb::9"), &parse_trusted_proxies("127.0.0.1")), a);
    }

    #[test]
    fn ipnet_parsing_and_matching() {
        let n = IpNet::parse("192.168.0.0/16").unwrap();
        assert!(n.contains("192.168.44.1".parse().unwrap()));
        assert!(!n.contains("192.169.0.1".parse().unwrap()));
        assert!(!n.contains("::1".parse().unwrap()));
        assert!(IpNet::parse("fd00::/8").unwrap().contains("fd12::1".parse().unwrap()));
        assert!(IpNet::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("nope").is_none());
        assert_eq!(parse_trusted_proxies(" , 10.0.0.1 ,bad").len(), 1);
    }
}
