//! Endpoint construction — the ONE place that decides which third parties this process may talk to.
//!
//! | setting                 | Mainline DHT            | n0 relays | n0 DNS/pkarr |
//! |-------------------------|-------------------------|-----------|--------------|
//! | `public_fallback=true`  | publish (host) + lookup | yes       | yes          |
//! | `public_fallback=false` | publish (host) + lookup | **never** | **never**    |
//!
//! A member never publishes anything about itself anywhere.
//!
//! **What leaves the machine, and where** (the host's pkarr record is readable by anyone who
//! holds the node id — i.e. anyone who ever saw an invite):
//!
//! | channel              | carries                                                             |
//! |----------------------|---------------------------------------------------------------------|
//! | Mainline DHT record  | node id, **global** IP:port only, the relay URL (fallback on), a publish timestamp |
//! | n0 DNS/pkarr         | node id + relay URL only (never an IP) — fallback on                 |
//! | mDNS (`local_discovery`, **opt-in**) | a rotating keyed tag (not the node id) + private addresses, link-local multicast only — see `lan.rs` |
//!
//! Private / LAN / CGNAT / ULA addresses are never put in the DHT: they describe the home
//! network's layout to strangers and are useless off-LAN. A host that wants same-LAN members to
//! connect without the DHT turns on local discovery (`lan.rs`).

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use iroh::address_lookup::memory::MemoryLookup;
use iroh::address_lookup::{AddrFilter, PkarrPublisher, PkarrResolver};
use iroh::endpoint::{presets, PortmapperConfig};
use iroh::{Endpoint, RelayMap, RelayMode, SecretKey, TransportAddr};
use iroh_mainline_address_lookup::DhtAddressLookup;

use crate::NetError;

/// How often the host re-puts its DHT record. iroh's default is an hour, and that hour also
/// applies after a FAILED put (for example "Could not bootstrap the routing table" at start-up):
/// members without public fallback then cannot find the host for up to an hour. Ten minutes
/// recovers quickly and is still far inside the record's DHT lifetime.
pub const DHT_REPUBLISH: std::time::Duration = std::time::Duration::from_secs(10 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Accepts `skwod/1`, publishes its addresses under its key, asks the router for a port mapping.
    Host,
    /// Dials only. Publishes nothing, accepts nothing.
    Member,
}

#[derive(Debug, Clone)]
pub enum Discovery {
    /// BitTorrent Mainline DHT (pkarr) — the default, infrastructure-free mechanism.
    Dht,
    /// A fixed in-memory table (tests, or a caller that already knows the host's addresses).
    Static(MemoryLookup),
    /// No lookup at all: the caller must dial a full `EndpointAddr`.
    None,
}

#[derive(Debug, Clone)]
pub struct NetConfig {
    pub role: Role,
    /// Host: the persistent key (see [`load_or_create_secret_key`]). Member: `None` = a fresh
    /// throwaway key per process, so the host can't link a member's sessions by node id.
    pub secret_key: Option<SecretKey>,
    /// Allow n0's public relays + DNS as a fallback when the DHT / a direct path isn't enough.
    /// Default ON (seamless); OFF = strictly independent (direct paths only).
    pub public_fallback: bool,
    pub discovery: Discovery,
    /// Same-LAN discovery over mDNS (`lan.rs`). **Off by default — an explicit opt-in**: a host
    /// on someone else's Wi-Fi must not announce itself. Needs [`Self::lan_key`]; without the
    /// key nothing is announced or matched. Host: announces a rotating keyed tag + private
    /// addresses. Member: listens only, announces nothing.
    pub local_discovery: bool,
    /// The host's LAN-discovery secret (host: `<data>/lan.key`; member: from the invite / API).
    pub lan_key: Option<crate::lan::LanKey>,
    /// UPnP / NAT-PMP / PCP. Default: on for hosts, off for members (SSDP multicast raises the
    /// local-network permission prompt on iOS and members don't need an inbound mapping).
    pub portmapper: bool,
    /// Fixed UDP port (lets a power user forward it by hand). `None` = OS-assigned.
    pub bind_port: Option<u16>,
    /// Extra externally reachable addresses to advertise (manual port forward / static IP).
    pub external_addrs: Vec<SocketAddr>,
    /// The host's OWN relay(s), used instead of n0's and regardless of `public_fallback`
    /// (it isn't public infrastructure). Also how tests run against a local relay.
    pub custom_relays: Option<RelayMap>,
}

impl NetConfig {
    pub fn host(secret_key: SecretKey) -> Self {
        Self {
            role: Role::Host,
            secret_key: Some(secret_key),
            public_fallback: true,
            discovery: Discovery::Dht,
            local_discovery: false,
            lan_key: None,
            portmapper: true,
            bind_port: None,
            external_addrs: Vec::new(),
            custom_relays: None,
        }
    }

    pub fn member() -> Self {
        Self {
            role: Role::Member,
            secret_key: None,
            public_fallback: true,
            discovery: Discovery::Dht,
            local_discovery: false,
            lan_key: None,
            portmapper: false,
            bind_port: None,
            external_addrs: Vec::new(),
            custom_relays: None,
        }
    }

    /// What this configuration will contact. [`bind`] builds the endpoint from exactly this, so a
    /// test on the plan is a test on the endpoint.
    pub fn plan(&self) -> NetPlan {
        let relay = match (&self.custom_relays, self.public_fallback) {
            (Some(map), _) => RelayMode::Custom(map.clone()),
            (None, true) => iroh::endpoint::default_relay_mode(),
            (None, false) => RelayMode::Disabled,
        };
        let dht = matches!(self.discovery, Discovery::Dht);
        NetPlan {
            relay,
            dht_lookup: dht,
            dht_publish: dht && self.role == Role::Host,
            n0_dns_lookup: dht && self.public_fallback,
            n0_dns_publish: dht && self.public_fallback && self.role == Role::Host,
            mdns_lookup: self.local_discovery && self.lan_key.is_some() && self.role == Role::Member,
            mdns_advertise: self.local_discovery && self.lan_key.is_some() && self.role == Role::Host,
            portmapper: self.portmapper,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetPlan {
    pub relay: RelayMode,
    pub dht_lookup: bool,
    pub dht_publish: bool,
    pub n0_dns_lookup: bool,
    pub n0_dns_publish: bool,
    /// Member: listen on the local network for the host's rotating tag (mDNS).
    pub mdns_lookup: bool,
    /// Host: announce a rotating tag + private addresses on the local network (mDNS).
    pub mdns_advertise: bool,
    pub portmapper: bool,
}

impl NetPlan {
    /// True when nothing operated by n0 (or any other fixed third party) is ever contacted.
    pub fn is_independent(&self) -> bool {
        self.relay == RelayMode::Disabled && !self.n0_dns_lookup && !self.n0_dns_publish
    }
}

/// What goes into the host's **DHT** record: relay URLs + globally routable IPs, nothing else.
/// A private/LAN address tells every invite holder how the home network is laid out and is
/// unreachable from outside anyway; same-LAN members can use opt-in mDNS (`lan.rs`).
/// Capped so the signed pkarr packet stays within the DHT's 1000-byte value limit.
fn publish_filter() -> AddrFilter {
    AddrFilter::new(|addrs| {
        let mut keep: Vec<TransportAddr> = addrs
            .iter()
            .filter(|a| match a {
                TransportAddr::Ip(sa) => is_global(sa.ip()),
                _ => true,
            })
            .cloned()
            .collect();
        keep.truncate(8);
        Cow::Owned(keep)
    })
}

/// Globally routable unicast address? (std's `IpAddr::is_global` is unstable.) Everything that
/// is not — RFC 1918, CGNAT/Tailscale 100.64/10, link-local, loopback, ULA `fc00::/7`,
/// benchmarking, multicast, reserved — stays out of the DHT.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(o[0] == 0
                || v4.is_private()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 224)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_global(IpAddr::V4(v4)),
            // Global unicast is 2000::/3; minus the documentation prefix 2001:db8::/32.
            None => {
                let s = v6.segments();
                (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
            }
        },
    }
}

/// Bind an endpoint according to `cfg` (and nothing else — no preset that pulls in n0 defaults).
pub async fn bind(cfg: &NetConfig) -> Result<Endpoint, NetError> {
    let plan = cfg.plan();
    let mut b = Endpoint::builder(presets::Minimal).relay_mode(plan.relay.clone()).portmapper_config(
        if plan.portmapper { PortmapperConfig::default() } else { PortmapperConfig::Disabled },
    );
    if let Some(key) = &cfg.secret_key {
        b = b.secret_key(key.clone());
    }
    if cfg.role == Role::Host {
        b = b.alpns(vec![crate::ALPN.to_vec()]);
    }
    if let Some(port) = cfg.bind_port {
        b = b
            .clear_ip_transports()
            .bind_addr(SocketAddr::from(([0, 0, 0, 0], port)))
            .map_err(|e| NetError::Bind(e.to_string()))?
            .bind_addr(SocketAddr::from(([0u16; 8], port)))
            .map_err(|e| NetError::Bind(e.to_string()))?;
    }
    for addr in &cfg.external_addrs {
        b = b.external_addr(*addr);
    }
    match &cfg.discovery {
        Discovery::Dht => {
            let dht = DhtAddressLookup::builder().addr_filter(publish_filter()).republish_delay(DHT_REPUBLISH);
            b = b.address_lookup(if plan.dht_publish { dht } else { dht.no_publish() });
            if plan.n0_dns_publish {
                b = b.address_lookup(PkarrPublisher::n0_dns());
            }
            if plan.n0_dns_lookup {
                // The HTTPS resolver ONLY (audit P4). iroh's DNS lookup asks for
                // `_iroh.<node id>.dns.iroh.link` as a TXT record through the system
                // resolver — in plaintext: every Wi-Fi operator, ISP and resolver on the way
                // read which skwod this device belongs to and when it connects, and got the
                // node id itself. The pkarr resolver fetches the same record over TLS; what a
                // network observer sees is a connection to n0's server, as for any iroh app.
                b = b.address_lookup(PkarrResolver::n0_dns());
            }
        }
        Discovery::Static(table) => b = b.address_lookup(table.clone()),
        Discovery::None => {}
    }
    b.bind().await.map_err(|e| NetError::Bind(e.to_string()))
}

/// Load the host's persistent key from `path`, creating it (owner-only, 0600) on first use.
/// The file holds 64 hex chars. Losing it changes the skwod's address: every invite and every
/// member's pin dies with it — back it up with the rest of the data dir.
pub fn load_or_create_secret_key(path: &Path) -> std::io::Result<SecretKey> {
    use std::io::{Error, ErrorKind};
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let mut bytes = [0u8; 32];
            hex::decode_to_slice(text.trim(), &mut bytes)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "p2p key file is not 32 hex-encoded bytes"))?;
            restrict(path)?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let key = SecretKey::generate();
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            let mut f = opts.open(path)?;
            f.write_all(hex::encode(key.to_bytes()).as_bytes())?;
            f.sync_all()?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_is_stable_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p2p.key");
        let a = load_or_create_secret_key(&path).unwrap();
        let b = load_or_create_secret_key(&path).unwrap();
        assert_eq!(a.public(), b.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(&path, "garbage").unwrap();
        assert!(load_or_create_secret_key(&path).is_err(), "never silently replace a damaged key");
    }

    #[test]
    fn independent_mode_plans_no_public_infrastructure() {
        for mut cfg in [NetConfig::host(SecretKey::generate()), NetConfig::member()] {
            cfg.public_fallback = false;
            let plan = cfg.plan();
            assert_eq!(plan.relay, RelayMode::Disabled);
            assert!(!plan.n0_dns_lookup && !plan.n0_dns_publish);
            assert!(plan.dht_lookup, "the DHT stays: it is nobody's infrastructure");
            assert!(plan.is_independent());
            assert!(!plan.mdns_lookup && !plan.mdns_advertise);
        }
    }

    #[test]
    fn fallback_mode_and_roles() {
        let host = NetConfig::host(SecretKey::generate()).plan();
        assert!(host.dht_publish && host.n0_dns_publish && host.portmapper);
        assert_ne!(host.relay, RelayMode::Disabled);
        let member = NetConfig::member().plan();
        assert!(!member.dht_publish && !member.n0_dns_publish, "members never publish themselves");
        assert!(member.dht_lookup && member.n0_dns_lookup && !member.portmapper);
    }

    #[test]
    fn nothing_is_announced_on_the_lan_unless_the_host_opts_in() {
        // Defaults: no mDNS in either role.
        for cfg in [NetConfig::host(SecretKey::generate()), NetConfig::member()] {
            assert!(!cfg.local_discovery && cfg.lan_key.is_none());
            assert!(!cfg.plan().mdns_advertise && !cfg.plan().mdns_lookup);
        }
        // Opting in without a key still announces nothing (there is no keyless mode).
        let mut host = NetConfig::host(SecretKey::generate());
        host.local_discovery = true;
        assert!(!host.plan().mdns_advertise);
        host.lan_key = Some(crate::lan::LanKey::generate());
        assert!(host.plan().mdns_advertise && !host.plan().mdns_lookup);
        // A key alone (flag off) does not announce either.
        host.local_discovery = false;
        assert!(!host.plan().mdns_advertise);
        // A member never announces, with or without the key.
        let mut member = NetConfig::member();
        member.local_discovery = true;
        member.lan_key = Some(crate::lan::LanKey::generate());
        assert!(member.plan().mdns_lookup && !member.plan().mdns_advertise);
    }

    fn ip(s: &str) -> TransportAddr {
        TransportAddr::Ip(s.parse().unwrap())
    }

    #[test]
    fn dht_record_carries_only_global_addresses() {
        let addrs = vec![
            ip("127.0.0.1:1"),
            ip("169.254.1.1:1"),
            ip("[fe80::1]:1"),
            ip("192.168.1.10:1"),
            ip("10.0.0.7:1"),
            ip("172.20.3.4:1"),
            ip("100.101.102.103:1"), // CGNAT / Tailscale
            ip("[fd12:3456::1]:1"),  // ULA
            ip("[::ffff:192.168.1.10]:1"),
            ip("198.18.0.1:1"),
            ip("8.8.4.4:4433"),
            ip("[2606:4700::1111]:4433"),
        ];
        let kept = publish_filter().apply(&addrs).into_owned();
        assert_eq!(kept, vec![ip("8.8.4.4:4433"), ip("[2606:4700::1111]:4433")]);
    }
}
