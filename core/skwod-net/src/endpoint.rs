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
use futures_util::StreamExt;
use iroh::address_lookup::{
    AddrFilter, AddressLookup, AddressLookupBuilder, AddressLookupBuilderError, EndpointData, EndpointInfo, Error as LookupError, Item,
    PkarrPublisher, PkarrResolver, PkarrResolverBuilder,
};
use iroh::endpoint::{presets, BindOpts, PortmapperConfig};
use iroh::{Endpoint, EndpointId, RelayMap, RelayMode, SecretKey, TransportAddr};
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
    /// What a member with `public_fallback` takes its lease from (`relay_gate.rs`): this process's
    /// gate (tests: their own).
    pub relay_gate: std::sync::Arc<crate::relay_gate::RelayGate>,
    /// Member: where this host was reached directly (`routes.rs`), dialed only without relays.
    pub routes: crate::routes::Routes,
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
            relay_gate: crate::relay_gate::RelayGate::global(),
            routes: Default::default(),
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
            relay_gate: crate::relay_gate::RelayGate::global(),
            routes: Default::default(),
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
/// is not — RFC 1918, CGNAT/Tailscale 100.64/10, link-local, loopback, ULA `fc00::/7`, documentation,
/// benchmarking, transition (6to4, Teredo), multicast, reserved — stays out of the DHT, and out of
/// what is taken from it.
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(o[0] == 0
                || v4.is_private()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || v4.is_loopback()
                || v4.is_link_local()
                || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || o[0] >= 224)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_global(IpAddr::V4(v4)),
            // Global unicast is 2000::/3; minus what the IETF keeps for protocols (2001::/23: Teredo,
            // benchmarking, ORCHID, …), 6to4 (2002::/16, an IPv4 address in disguise) and the
            // documentation prefixes.
            None => {
                let s = v6.segments();
                (s[0] & 0xe000) == 0x2000
                    && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                    && s[0] != 0x2002
                    && !(s[0] == 0x3fff && s[1] < 0x1000)
            }
        },
    }
}

/// A lookup whose answers are taken only for their global addresses: a DHT record is whatever the
/// host signed, and must not have a member knock at loopback or at its own network. (What a host
/// offers over a live connection, as NAT-traversal candidates, is not seen here: `docs/SECURITY.md`.)
#[derive(Debug)]
struct GlobalOnly<T>(T);

/// Every lookup whose answer the HOST signs (the DHT above, n0's pkarr server here) goes through
/// [`GlobalOnly`]: a host must not be able to make its members dial private or internal addresses.
/// Local discovery, under the invite's LAN key, is the one way a private address is learnt.
fn host_signed(lookup: PkarrResolverBuilder) -> GlobalOnly<PkarrResolverBuilder> {
    GlobalOnly(lookup)
}

impl<T: AddressLookupBuilder> AddressLookupBuilder for GlobalOnly<T> {
    fn into_address_lookup(self, endpoint: &Endpoint) -> Result<impl AddressLookup, AddressLookupBuilderError> {
        self.0.into_address_lookup(endpoint).map(GlobalOnlyLookup)
    }
}

#[derive(Debug)]
struct GlobalOnlyLookup<T>(T);

impl<T: AddressLookup> AddressLookup for GlobalOnlyLookup<T> {
    fn publish(&self, data: &EndpointData) { self.0.publish(data) }
    fn resolve(&self, id: EndpointId) -> Option<futures_util::stream::BoxStream<'static, Result<Item, LookupError>>> {
        Some(self.0.resolve(id)?.map(|item| item.map(global_only)).boxed())
    }
}

fn global_only(item: Item) -> Item {
    let (provenance, updated) = (item.provenance(), item.last_updated());
    let mut info = EndpointInfo::from(item);
    let keep: Vec<SocketAddr> = info.data.ip_addrs().copied().filter(|a| is_global(a.ip())).collect();
    info.data.clear_ip_addrs();
    info.data.add_ip_addrs(keep);
    Item::new(info, provenance, updated)
}

/// A HOST's endpoint. A member's is only ever bound by its owner (`relay_gate.rs`), under a lease
/// when it may use relays.
pub async fn bind(cfg: &NetConfig) -> Result<Endpoint, NetError> {
    if cfg.role == Role::Member && cfg.public_fallback {
        return Err(NetError::Bind("a member's relay-allowed endpoint needs a lease (Member::connect)".into()));
    }
    bind_endpoint(cfg).await
}

/// Bind an endpoint according to `cfg` (and nothing else — no preset that pulls in n0 defaults).
pub(crate) async fn bind_endpoint(cfg: &NetConfig) -> Result<Endpoint, NetError> {
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
            // (A machine without IPv6 keeps its port all the same.)
            .bind_addr_with_opts(SocketAddr::from(([0u16; 8], port)), BindOpts::default().set_is_required(false))
            .map_err(|e| NetError::Bind(e.to_string()))?;
    }
    for addr in &cfg.external_addrs {
        b = b.external_addr(*addr);
    }
    match &cfg.discovery {
        Discovery::Dht => {
            let dht = DhtAddressLookup::builder().addr_filter(publish_filter()).republish_delay(DHT_REPUBLISH);
            b = b.address_lookup(GlobalOnly(if plan.dht_publish { dht } else { dht.no_publish() }));
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
                b = b.address_lookup(host_signed(PkarrResolver::n0_dns()));
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

    #[test]
    fn what_is_not_globally_routable_is_not_global() {
        for yes in ["8.8.4.4", "192.0.1.1", "192.88.98.1", "198.51.99.1", "203.0.112.1", "2606:4700::1111", "2001:200::1", "2003::1", "::ffff:8.8.4.4"] {
            assert!(is_global(yes.parse().unwrap()), "{yes}");
        }
        for no in ["192.0.0.8", "192.0.2.1", "198.51.100.7", "203.0.113.9", "192.88.99.1", "198.19.0.1", "100.64.0.1", "169.254.169.254", "240.0.0.1",
                   "255.255.255.255", "2001::1", "2001:2::1", "2001:10::1", "2001:20::1", "2001:db8::1", "2002:808:404::1", "3fff::1", "64:ff9b::808:404",
                   "fec0::1", "fe80::1", "fd00::1", "ff02::1", "::1", "::", "::ffff:203.0.113.9", "::ffff:10.0.0.1"] {
            assert!(!is_global(no.parse().unwrap()), "{no}");
        }
    }

    #[tokio::test]
    async fn an_answer_is_taken_for_its_global_addresses_only() {
        let id = SecretKey::generate().public();
        let table = MemoryLookup::new();
        let addrs = ["127.0.0.1:1", "169.254.169.254:80", "192.168.1.1:4433", "[fe80::1]:1", "100.64.0.1:1", "8.8.4.4:4433"];
        table.add_endpoint_info(addrs.iter().fold(iroh::EndpointAddr::new(id), |a, s| a.with_ip_addr(s.parse().unwrap())));
        let item = GlobalOnlyLookup(table).resolve(id).unwrap().next().await.unwrap().unwrap();
        assert_eq!(item.ip_addrs().map(ToString::to_string).collect::<Vec<_>>(), ["8.8.4.4:4433"]);
    }

    /// A record from a pkarr server (as n0's), signed by the host, naming private addresses: only
    /// its global one is dialed.
    #[tokio::test]
    async fn a_pkarr_answer_is_taken_for_its_global_addresses_only() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let key = SecretKey::generate();
        let addrs = ["127.0.0.1:1", "192.168.1.1:4433", "10.0.0.7:4433", "169.254.169.254:80", "[fd12::1]:4433", "8.8.4.4:4433"];
        let info = EndpointInfo::new(key.public()).with_ip_addrs(addrs.iter().map(|a| a.parse().unwrap()).collect());
        let body = info.to_pkarr_signed_packet(&key, 30).unwrap().to_relay_payload();
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", server.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut c, _)) = server.accept().await {
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf).await;
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len()).as_bytes()).await;
                let _ = c.write_all(&body).await;
            }
        });
        let ep = Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled).bind().await.unwrap();
        let lookup = host_signed(PkarrResolver::builder(url.parse().unwrap())).into_address_lookup(&ep).unwrap();
        let item = lookup.resolve(key.public()).unwrap().next().await.unwrap().unwrap();
        assert_eq!(item.ip_addrs().map(ToString::to_string).collect::<Vec<_>>(), ["8.8.4.4:4433"]);
        ep.close().await;
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
            ip("192.0.2.1:1"),
            ip("203.0.113.1:1"),
            ip("[2002:c0a8:101::1]:1"),
            ip("8.8.4.4:4433"),
            ip("[2606:4700::1111]:4433"),
        ];
        let kept = publish_filter().apply(&addrs).into_owned();
        assert_eq!(kept, vec![ip("8.8.4.4:4433"), ip("[2606:4700::1111]:4433")]);
    }
}
