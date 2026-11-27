//! Build 51: direct addresses a host was really reached at, for dialing it with relays off — when
//! the DHT (global addresses only) cannot say how. Nothing here is a claim of the host's: an address
//! comes from the selected, non-relay path of a connection whose TLS proved the host's key. Who the
//! host IS stays its key; an address is only where to knock.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use iroh::{EndpointAddr, EndpointId};

use crate::endpoint::is_global;

const MAX: usize = 4;
/// A private route: as long as our own address is still the one it was learned from.
const KEEP_SECS: u64 = 14 * 24 * 60 * 60;
/// A global one: a home connection's public address changes; kept briefly.
const KEEP_GLOBAL_SECS: u64 = 3 * 24 * 60 * 60;
/// A route seen again is written down again only after this long.
const REFRESH_SECS: u64 = 60 * 60;
const MAX_BLOB: usize = 1024;
const HEADER: &str = "skwod-routes-2";

pub(crate) fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// RFC 1918 and unique local addresses — minus the metadata services clouds put there.
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 && !(s == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254] || s == [0xfd20, 0xce, 0, 0, 0, 0, 0, 0x254])
        }
    }
}

/// The address as it may be remembered and dialed, or not at all: a private one, or — learned without
/// relays (with them it is usually a punched hole that nobody else's first packet passes) — a global
/// one. Everything not named here is refused.
fn usable(addr: SocketAddr, relays: bool) -> Option<SocketAddr> {
    let addr = SocketAddr::new(addr.ip().to_canonical(), addr.port());
    let private = is_private(addr.ip()) && addr.port() >= 1024;
    let global = !relays && is_global(addr.ip()) && addr.port() != 0;
    (private || global).then_some(addr)
}

/// Are we, with `source` as our own address, on the private network `route` is on? A VPN's, a
/// cellular or a loopback source is not.
fn same_network(source: IpAddr, route: IpAddr) -> bool {
    if !is_private(source) || !is_private(route) { return false }
    match (source, route) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[..4] == b.segments()[..4],
        _ => false,
    }
}

/// Our own address as a route is bound to it: IPv4 exactly (a look-alike network seldom gives the same
/// one), IPv6 its /64 (temporary addresses change within it).
fn own(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => { let s = v6.segments(); IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)) }
        v4 => v4,
    }
}

fn alive(from: Option<IpAddr>, at: u64, now: u64) -> bool {
    now.saturating_sub(at) < if from.is_some() { KEEP_SECS } else { KEEP_GLOBAL_SECS }
}

/// Our own address towards `route`, as the system would choose it. Connecting a UDP socket sends
/// nothing.
fn source_towards(route: SocketAddr) -> Option<IpAddr> {
    let any: SocketAddr = if route.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
    let socket = UdpSocket::bind(any).ok()?;
    socket.connect(route).ok()?;
    Some(socket.local_addr().ok()?.ip().to_canonical())
}

#[derive(Default)]
struct Known {
    host: Option<EndpointId>,
    /// Newest first: where, when it was last the selected path, and (private ones) OUR address
    /// then, as [`own`] keeps it.
    list: Vec<(SocketAddr, u64, Option<IpAddr>)>,
    changed: bool,
}

/// What is remembered of one host, shared by every member that is dialed for a session.
#[derive(Clone, Default)]
pub struct Routes(Arc<Mutex<Known>>);

impl std::fmt::Debug for Routes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Routes(..)") }   // never printed
}

impl Routes {
    fn known(&self) -> MutexGuard<'_, Known> { self.0.lock().unwrap_or_else(|e| e.into_inner()) }

    /// From what [`Self::take_blob`] gave (nil, anything malformed, or another host's: nothing).
    pub fn load(host: EndpointId, blob: Option<&str>) -> Self { Self::load_at(host, blob, now_secs()) }

    fn load_at(host: EndpointId, blob: Option<&str>, now: u64) -> Self {
        let mut list = Vec::new();
        let mut lines = blob.filter(|b| b.len() <= MAX_BLOB).unwrap_or_default().lines();
        if lines.next() == Some(&format!("{HEADER} {}", host.to_z32())) {
            for line in lines.take(MAX) {
                let mut f = line.split(' ');
                let (Some(Ok(addr)), Some(Ok(at))) = (f.next().map(str::parse::<SocketAddr>), f.next().map(str::parse::<u64>)) else { continue };
                let from = f.next().and_then(|s| s.parse::<IpAddr>().ok()).map(own);
                // (A global one was only ever kept from a session without relays.) A private one
                // without the address it was learned from is never dialed: not kept.
                let Some(addr) = usable(addr, false).filter(|_| at <= now) else { continue };
                if is_private(addr.ip()) != from.is_some_and(is_private) { continue }
                list.push((addr, at, from));
            }
        }
        Self(Arc::new(Mutex::new(Known { host: Some(host), list, changed: false })))
    }

    /// To be stored (encrypted, on this device only, with the workspace), if there is anything new.
    pub fn take_blob(&self) -> Option<String> {
        let mut k = self.known();
        let host = k.host.filter(|_| std::mem::take(&mut k.changed))?;
        Some(k.list.iter().fold(format!("{HEADER} {}", host.to_z32()), |b, (a, at, from)| match from {
            Some(f) => format!("{b}\n{a} {at} {f}"),
            None => format!("{b}\n{a} {at}"),
        }))
    }

    /// The connection runs over `addr` right now.
    pub(crate) fn saw(&self, addr: SocketAddr, relays: bool) { self.saw_at(addr, relays, now_secs(), source_towards) }

    fn saw_at(&self, addr: SocketAddr, relays: bool, now: u64, source: impl Fn(SocketAddr) -> Option<IpAddr>) {
        let Some(addr) = usable(addr, relays) else { return };
        // A private route belongs to the network we are on now: it is kept with our own address.
        let from = if is_private(addr.ip()) {
            match source(addr).filter(|s| same_network(*s, addr.ip())) { Some(s) => Some(own(s)), None => return }
        } else { None };
        let mut k = self.known();
        let fresh = k.list.first().is_some_and(|(a, at, f)| *a == addr && *f == from && now.saturating_sub(*at) < REFRESH_SECS);
        if fresh { return }
        k.list.retain(|(a, at, f)| *a != addr && alive(*f, *at, now));
        k.list.insert(0, (addr, now, from));
        k.list.truncate(MAX);
        k.changed = true;
    }

    /// `host`, with the addresses worth a packet from where we are now.
    pub(crate) fn onto(&self, host: EndpointAddr) -> EndpointAddr { self.onto_at(host, now_secs(), source_towards) }

    fn onto_at(&self, host: EndpointAddr, now: u64, source: impl Fn(SocketAddr) -> Option<IpAddr>) -> EndpointAddr {
        let k = self.known();
        if k.host != Some(host.id) { return host }
        k.list.iter().filter(|(_, at, from)| alive(*from, *at, now))
            // Private: only while our own address towards it is the one it was learned from — on
            // another network, or one that merely looks alike (same subnet), not a packet.
            .filter(|(a, _, from)| match from {
                None => !is_private(a.ip()),
                Some(f) => source(*a).is_some_and(|s| same_network(s, a.ip()) && own(s) == *f),
            })
            .fold(host, |h, (a, _, _)| h.with_ip_addr(*a))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn at(s: &str) -> SocketAddr { s.parse().unwrap() }
    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn only_addresses_named_usable_are() {
        for ok in ["10.0.0.7:4433", "172.16.1.1:1024", "192.168.1.5:65535", "[fd12:3456::1]:4433"] {
            assert!(usable(at(ok), true).is_some() && usable(at(ok), false).is_some(), "{ok}");
        }
        assert_eq!(usable(at("[::ffff:192.168.1.5]:4433"), true), Some(at("192.168.1.5:4433")), "canonical");
        for global in ["8.8.4.4:443", "[2606:4700::1111]:4433"] {
            assert!(usable(at(global), false).is_some() && usable(at(global), true).is_none(), "{global}");
        }
        for no in ["127.0.0.1:4433", "[::1]:4433", "0.0.0.0:4433", "169.254.169.254:4433", "[fe80::1]:4433", "[::ffff:127.0.0.1]:4433",
                   "[::ffff:169.254.169.254]:4433", "224.0.0.251:5353", "255.255.255.255:4433", "240.0.0.1:4433", "100.100.100.200:4433",
                   "[fd00:ec2::254]:4433", "[fd20:ce::254]:4433", "[fec0::1]:4433", "[ff02::1]:4433", "[2002:c0a8:101::1]:4433",
                   "[2001::1]:4433", "[64:ff9b::a00:1]:4433", "192.0.2.1:4433", "198.51.100.1:4433", "203.0.113.1:4433", "192.88.99.1:4433",
                   "198.18.0.1:4433", "192.168.1.1:80", "192.168.1.1:1023", "8.8.4.4:0"] {
            assert_eq!(usable(at(no), false), None, "{no}");
        }
    }

    #[test]
    fn a_private_route_is_for_the_network_we_are_on() {
        assert!(same_network(ip("192.168.1.9"), ip("192.168.1.5")));
        assert!(same_network(ip("172.20.10.3"), ip("172.20.10.1")), "a phone's hotspot");
        assert!(same_network(ip("fd12:3456:0:1::9"), ip("fd12:3456:0:1::5")));
        for (source, route) in [("192.168.2.9", "192.168.1.5"), ("10.8.0.2", "192.168.1.5"), ("100.101.102.103", "192.168.1.5"),
                                ("127.0.0.1", "192.168.1.5"), ("169.254.3.4", "169.254.3.5"), ("8.8.4.4", "8.8.4.5"),
                                ("fe80::9", "fe80::5"), ("fd12:3456:0:2::9", "fd12:3456:0:1::5"), ("fd12::9", "192.168.1.5")] {
            assert!(!same_network(ip(source), ip(route)), "{source} {route}");
        }
        // Several networks at once: the one the system would really use towards the route counts.
        let host = SecretKey::generate().public();
        let r = Routes::load(host, None);
        let wifi = |a: SocketAddr| Some(if a.ip() == ip("192.168.1.5") { ip("192.168.1.9") } else { ip("100.64.0.1") });
        r.saw_at(at("192.168.1.5:4433"), true, 100, wifi);
        r.saw_at(at("10.0.0.5:4433"), true, 100, wifi);   // not on a network of ours: not kept
        assert_eq!(r.onto_at(EndpointAddr::new(host), 200, wifi), EndpointAddr::new(host).with_ip_addr(at("192.168.1.5:4433")));
        assert_eq!(r.onto_at(EndpointAddr::new(host), 200, |_| None), EndpointAddr::new(host), "no way there");
    }

    /// Review of 51: a remembered LAN route is dialed only from the network it was learned on.
    #[test]
    fn a_private_route_is_not_dialed_from_another_network_or_a_look_alike() {
        let host = SecretKey::generate().public();
        let bare = EndpointAddr::new(host);
        let home = |_| Some(ip("192.168.1.9"));
        let r = Routes::load_at(host, None, 0);
        r.saw_at(at("192.168.1.5:4433"), false, 100, home);
        assert_eq!(r.onto_at(bare.clone(), 200, home), bare.clone().with_ip_addr(at("192.168.1.5:4433")), "at home");
        assert_eq!(r.onto_at(bare.clone(), 200, |_| Some(ip("10.1.2.3"))), bare, "another network");
        assert_eq!(r.onto_at(bare.clone(), 200, |_| Some(ip("192.168.1.23"))), bare, "a cafe on the same subnet");
        assert_eq!(r.onto_at(bare.clone(), 200, |_| Some(ip("100.64.0.1"))), bare, "mobile network");
        // And it stays so across a restart.
        let again = Routes::load_at(host, Some(&r.take_blob().unwrap()), 300);
        assert_eq!(again.onto_at(bare.clone(), 400, home), bare.clone().with_ip_addr(at("192.168.1.5:4433")));
        assert_eq!(again.onto_at(bare.clone(), 400, |_| Some(ip("192.168.1.23"))), bare);
        // IPv6: the network's /64, whatever temporary address we have in it.
        let r = Routes::load_at(host, None, 0);
        r.saw_at(at("[fd12:3456:0:1::5]:4433"), false, 100, |_| Some(ip("fd12:3456:0:1::9")));
        assert_eq!(r.onto_at(bare.clone(), 200, |_| Some(ip("fd12:3456:0:1:abcd::77"))).ip_addrs().count(), 1);
        assert_eq!(r.onto_at(bare.clone(), 200, |_| Some(ip("fd12:3456:0:2::9"))).ip_addrs().count(), 0);
        // A route without the address it was learned from (an older form, or edited) is not dialed.
        let old = format!("skwod-routes-1 {}\n192.168.1.5:4433 100", host.to_z32());
        let bare_line = format!("{HEADER} {}\n192.168.1.5:4433 100", host.to_z32());
        for blob in [old, bare_line] {
            assert_eq!(Routes::load_at(host, Some(&blob), 200).onto_at(bare.clone(), 200, home), bare, "{blob}");
        }
    }

    #[test]
    fn a_global_route_is_kept_briefly() {
        let host = SecretKey::generate().public();
        let r = Routes::load_at(host, None, 0);
        r.saw_at(at("8.8.4.4:4433"), false, 100, |_| Some(ip("192.168.1.9")));
        let count = |now| r.onto_at(EndpointAddr::new(host), now, |_| Some(ip("192.168.1.9"))).ip_addrs().count();
        assert_eq!((count(100 + KEEP_GLOBAL_SECS - 1), count(100 + KEEP_GLOBAL_SECS)), (1, 0));
        const { assert!(KEEP_GLOBAL_SECS <= 3 * 24 * 60 * 60) };
    }

    #[test]
    fn what_is_kept_is_bounded_ages_and_is_one_hosts() {
        let host = SecretKey::generate().public();
        let r = Routes::load_at(host, None, 0);
        assert_eq!(r.take_blob(), None, "nothing new");
        let here = |_| Some(ip("192.168.1.99"));
        for n in 1..=6 { r.saw_at(at(&format!("192.168.1.{n}:4433")), true, 1_000 + n, here); }
        r.saw_at(at("8.8.4.4:4433"), true, 1_007, here);   // with relays: not kept
        let blob = r.take_blob().unwrap();
        assert_eq!((blob.lines().count(), r.take_blob()), (1 + MAX, None));
        r.saw_at(at("192.168.1.6:4433"), true, 1_010, here);
        assert_eq!(r.take_blob(), None, "seen again a moment later");

        let count = |r: &Routes, h, now| r.onto_at(EndpointAddr::new(h), now, here).ip_addrs().count();
        let again = Routes::load_at(host, Some(&blob), 2_000);
        assert_eq!(count(&again, host, 2_000), MAX);
        assert_eq!(count(&again, host, 2_000 + KEEP_SECS), 0, "too old");
        let other = SecretKey::generate().public();
        assert_eq!(count(&Routes::load_at(other, Some(&blob), 2_000), other, 2_000), 0, "another host's");
        assert_eq!(count(&again, other, 2_000), 0, "never dialed for another host");
        for bad in ["", "x", "skwod-routes-1", &blob.replace("192.168.1", "127.0.0"), &blob.replace(" 100", " 99999"), &blob.repeat(40)] {
            assert_eq!(count(&Routes::load_at(host, Some(bad), 2_000), host, 2_000), 0, "{bad:.40}");
        }
        assert_eq!(format!("{r:?} {:?}", crate::NetConfig { routes: r.clone(), ..crate::NetConfig::member() }).matches("192.168").count(), 0);
    }
}
