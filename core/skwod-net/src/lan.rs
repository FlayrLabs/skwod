//! Same-LAN discovery (mDNS) that does not tell the LAN who is there.
//!
//! **Opt-in, off by default** ([`crate::NetConfig::local_discovery`]): a laptop host on café,
//! hotel or office Wi-Fi must not announce itself to everyone on that network.
//!
//! When the host turns it on, what goes out on link-local multicast (never routed) is:
//!
//! - a service instance named by a **rotating tag**, not the node id:
//!   `tag = HMAC-SHA256(lan key, "skwod-lan-v1" ‖ node id ‖ hour)[..16]`, re-keyed every hour.
//!   The *lan key* is a random secret the host hands only to its members (in the invite,
//!   `?l=…`, and over the authenticated API). Without it a tag is a random-looking string: it
//!   cannot be turned into the node id, matched against an invite, or linked to the tag the
//!   same host shows an hour later or on another network after the next rotation;
//! - the host's **private** addresses only (RFC 1918, 169.254/16, `fc00::/7`, `fe80::/10`) —
//!   never a global one, never a relay URL.
//!
//! A member announces nothing. It listens, computes the tag it expects for the host it is
//! dialing (this hour and the previous one, for clock skew), and feeds matching addresses to
//! its endpoint. A member without the lan key simply does not use mDNS.

use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use sha2::Sha256;
use swarm_discovery::{Discoverer, DropGuard, IpClass};

/// mDNS service label: `<tag>._skwod1._udp.local`.
pub const SERVICE: &str = "skwod1";
const EPOCH_SECS: u64 = 60 * 60;

/// The secret shared between a host and its members for LAN discovery. 128 bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LanKey(pub [u8; 16]);

impl std::fmt::Debug for LanKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LanKey(..)") // never printed
    }
}

impl LanKey {
    pub fn generate() -> Self {
        Self(rand::random())
    }
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        let mut b = [0u8; 16];
        hex::decode_to_slice(s.trim(), &mut b).ok()?;
        Some(Self(b))
    }
}

pub fn current_epoch() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() / EPOCH_SECS).unwrap_or(0)
}

/// The name a host answers to during `epoch`. 32 hex chars.
pub fn tag(key: &LanKey, node: &EndpointId, epoch: u64) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key.0).expect("hmac accepts any key length");
    mac.update(b"skwod-lan-v1");
    mac.update(node.as_bytes());
    mac.update(&epoch.to_be_bytes());
    hex::encode(&mac.finalize().into_bytes()[..16])
}

/// Private / link-local unicast: the only addresses worth announcing on a LAN, and the only
/// ones that say nothing to the outside world.
pub fn is_lan(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_lan(IpAddr::V4(v4)),
            None => (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
        },
    }
}

/// `(port, lan addresses)` this endpoint can be reached at on the local network.
fn lan_addrs(endpoint: &Endpoint) -> Vec<(u16, IpAddr)> {
    let mut addrs: Vec<(u16, IpAddr)> = endpoint.addr().ip_addrs().filter(|sa| is_lan(sa.ip())).map(|sa| (sa.port(), sa.ip())).collect();
    addrs.sort_unstable();
    addrs.dedup();
    addrs.truncate(8);
    addrs
}

fn announce(endpoint: &Endpoint, key: &LanKey, epoch: u64) -> Option<(DropGuard, Vec<(u16, IpAddr)>)> {
    let addrs = lan_addrs(endpoint);
    if addrs.is_empty() {
        return None;
    }
    let mut d = Discoverer::new_interactive(SERVICE.to_string(), tag(key, &endpoint.id(), epoch)).with_ip_class(IpClass::Auto);
    for (port, ip) in &addrs {
        d = d.with_addrs(*port, [*ip]);
    }
    d.spawn(&tokio::runtime::Handle::current()).ok().map(|g| (g, addrs))
}

/// Host: announce under the rotating tag until the returned handle is dropped. Re-announces
/// when the hour (→ tag) or the machine's LAN addresses change.
pub fn advertise(endpoint: &Endpoint, key: LanKey) -> tokio::task::JoinHandle<()> {
    let endpoint = endpoint.clone();
    tokio::spawn(async move {
        // (hour, the announcement's guard, the addresses announced)
        type Live = (u64, DropGuard, Vec<(u16, IpAddr)>);
        let mut live: Option<Live> = None;
        loop {
            let epoch = current_epoch();
            let stale = match &live {
                Some((e, _, addrs)) => *e != epoch || *addrs != lan_addrs(&endpoint),
                None => true,
            };
            if stale {
                drop(live.take()); // withdraw the old announcement (and its tag) first
                live = announce(&endpoint, &key, epoch).map(|(guard, addrs)| (epoch, guard, addrs));
                if live.is_none() {
                    tracing::debug!("local-network discovery: nothing to announce");
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    })
}

/// Member: listen for `host`'s tag and hand matching LAN addresses to the endpoint. Announces
/// nothing. Keep the returned guard alive for as long as the connection may need re-dialing.
pub fn listen(endpoint: &Endpoint, key: LanKey, host: EndpointId) -> Option<DropGuard> {
    let table = MemoryLookup::with_provenance("skwod-lan");
    endpoint.address_lookup().ok()?.add(table.clone());
    let callback = move |name: &str, peer: &swarm_discovery::Peer| {
        let epoch = current_epoch();
        if peer.is_expiry() || ![epoch, epoch.saturating_sub(1)].iter().any(|e| tag(&key, &host, *e) == name) {
            return;
        }
        let mut addr = EndpointAddr::new(host);
        for (ip, port) in peer.addrs().iter().filter(|(ip, _)| is_lan(*ip)).take(8) {
            addr = addr.with_ip_addr((*ip, *port).into());
        }
        table.add_endpoint_info(addr);
    };
    // The local name is random and never announced (no addresses are registered for it).
    let me = hex::encode(rand::random::<[u8; 16]>());
    Discoverer::new_interactive(SERVICE.to_string(), me)
        .with_ip_class(IpClass::Auto)
        .with_callback(callback)
        .spawn(&tokio::runtime::Handle::current())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn the_tag_needs_the_key_and_rotates() {
        let node = SecretKey::generate().public();
        let (key, other_key) = (LanKey::generate(), LanKey::generate());
        let t = tag(&key, &node, 500_000);
        assert_eq!(t.len(), 32);
        assert_eq!(t, tag(&key, &node, 500_000), "a member with the key computes the same tag");
        assert_ne!(t, tag(&other_key, &node, 500_000), "without the key the tag cannot be reproduced from the node id");
        assert_ne!(t, tag(&key, &node, 500_001), "a new, unlinkable tag every hour");
        assert_ne!(t, tag(&key, &SecretKey::generate().public(), 500_000));
        // The tag is not the node id in any of its spellings, nor a prefix/substring of one.
        let (z32, hexid) = (node.to_z32(), hex::encode(node.as_bytes()));
        assert!(!z32.contains(&t) && !hexid.contains(&t) && !t.contains(&hexid[..16]));
        // An unkeyed digest of the node id (what an observer could precompute from an invite)
        // does not match either.
        use sha2::Digest;
        assert_ne!(t, hex::encode(&Sha256::digest(node.as_bytes())[..16]));
        assert_eq!(LanKey::from_hex(&key.to_hex()), Some(key));
        assert_eq!(format!("{key:?}"), "LanKey(..)");
    }

    #[test]
    fn only_private_addresses_are_lan_addresses() {
        for lan in ["192.168.1.10", "10.0.0.7", "172.20.3.4", "169.254.9.9", "fd12:3456::1", "fe80::1", "::ffff:192.168.1.10"] {
            assert!(is_lan(lan.parse().unwrap()), "{lan}");
        }
        for not in ["8.8.4.4", "2606:4700::1111", "127.0.0.1", "::1", "0.0.0.0", "100.101.102.103", "203.0.113.9", "224.0.0.251"] {
            assert!(!is_lan(not.parse().unwrap()), "{not}");
        }
    }
}
