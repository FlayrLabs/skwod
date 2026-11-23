//! Invite links. Two spellings of the same thing:
//!
//! - app form   `skwod://join/<node id>[?u=<https url>&l=<hex>&r=<relay url>]#<join code>` — what the apps
//!   register as a URL scheme, what is stored, and what every build understands.
//! - share form `https://skwod.io/join#<node id>[.<join code>][&u=<https url>][&l=<hex>][&r=<relay url>]` — what
//!   the apps hand out from build 42 on. It opens a static page that forwards to the app form (or
//!   the app itself, through universal links / app links). EVERYTHING after `#` is a URL fragment,
//!   which browsers never send to a server, so skwod.io learns neither the host key nor the code.
//!
//! - `<node id>` is the host's iroh public key in z-base-32 (52 chars). It is BOTH the address
//!   (looked up in the DHT) and the pinned identity (the QUIC handshake fails unless the peer
//!   holds the matching private key) — there is nothing else to trust or to go stale.
//! - `<join code>` rides in the fragment so it is never sent anywhere by URL-handling code.
//! - Optional query params are reserved for alternative transports; today only `u=<https url>`
//!   (a classic VPS address to fall back to), `l=<hex>` (LAN key) and, from build 48,
//!   `r=<relay url>` are understood; unknown params are ignored.
//! - `r=` is the host's **home relay** at the time the link was made. A member that allows public
//!   fallback dials the node id through that relay straight away, without waiting for a DHT or
//!   n0 DNS lookup. It is only a hint: the handshake still proves the host's key, and a stale
//!   relay just means the lookup decides. It must be an `https://` URL on an allow-listed relay
//!   domain ([`is_allowed_relay`]); anything else is dropped, so a link cannot point a member's
//!   traffic at an arbitrary server.

use iroh::EndpointId;

use crate::NetError;

const PREFIX: &str = "skwod://join/";
/// The share form's fixed part. Nothing may sit between it and the `#`: a query would be sent to
/// the web server, so a link carrying one is refused rather than parsed.
const SHARE_PREFIX: &str = "https://skwod.io/join";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub node_id: EndpointId,
    pub join_code: Option<String>,
    /// Optional `https://` address of the same skwod (VPS hosts), for clients without a p2p path.
    pub fallback_url: Option<String>,
    /// Optional `l=<hex>`: the host's LAN-discovery key (`lan.rs`), present only when the host
    /// turned local discovery on.
    pub lan_key: Option<crate::lan::LanKey>,
    /// Optional `r=<https url>`: the host's home relay (allow-listed, see [`is_allowed_relay`]).
    pub relay_url: Option<String>,
}

/// Relay domains a link may name in `r=`: n0's public relays (`<region>.relay.n0.iroh.link`),
/// the only relays a member with public fallback uses anyway.
pub const ALLOWED_RELAY_SUFFIXES: &[&str] = &[".relay.n0.iroh.link"];

/// The relay URL in canonical form (`https://<host>/`, lowercase, no trailing dot), if `url`
/// names an allow-listed relay. No port, path, query, credentials or fragment.
pub fn is_allowed_relay(url: &str) -> Option<String> {
    let rest = url.get(..8).filter(|h| h.eq_ignore_ascii_case("https://")).map(|_| &url[8..])?;
    let host = rest.strip_suffix('/').unwrap_or(rest);
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
        return None;
    }
    if host.split('.').any(|label| label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')) {
        return None;
    }
    ALLOWED_RELAY_SUFFIXES
        .iter()
        .any(|suffix| host.len() > suffix.len() && host.ends_with(suffix))
        .then(|| format!("https://{host}/"))
}

impl Invite {
    pub fn new(node_id: EndpointId, join_code: Option<String>) -> Self {
        Self { node_id, join_code, fallback_url: None, lan_key: None, relay_url: None }
    }

    /// Parse either spelling (see the module docs). Anything else is an error.
    pub fn parse(link: &str) -> Result<Self, NetError> {
        let link = link.trim();
        let (id, query, code) = if let Some(rest) = link.strip_prefix(PREFIX) {
            let (rest, fragment) = match rest.split_once('#') {
                Some((r, f)) => (r, Some(f)),
                None => (rest, None),
            };
            let (id, query) = match rest.split_once('?') {
                Some((i, q)) => (i, Some(q)),
                None => (rest, None),
            };
            (id.trim_end_matches('/'), query, fragment)
        } else if let Some(fragment) = strip_share_prefix(link) {
            // `<node id>[.<join code>][&k=v…]`, all of it in the fragment.
            let (head, params) = match fragment.split_once('&') {
                Some((h, p)) => (h, Some(p)),
                None => (fragment, None),
            };
            let (id, code) = match head.split_once('.') {
                Some((i, c)) => (i, Some(c)),
                None => (head, None),
            };
            (id, params, code)
        } else {
            return Err(NetError::Invite("not a skwod://join/ or https://skwod.io/join# link"));
        };
        let node_id = parse_node_id(id)?;
        let join_code = code.map(str::trim).filter(|c| !c.is_empty()).map(str::to_string);
        if let Some(code) = &join_code {
            if code.len() > 128 || !code.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(NetError::Invite("malformed join code"));
            }
        }
        let param = |key: &str| {
            query.into_iter().flat_map(|q| q.split('&')).filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == key).map(|(_, v)| v)
        };
        let fallback_url = param("u").map(str::to_string).filter(|u| u.starts_with("https://"));
        let lan_key = param("l").and_then(crate::lan::LanKey::from_hex);
        let relay_url = param("r").and_then(is_allowed_relay);
        Ok(Self { node_id, join_code, fallback_url, lan_key, relay_url })
    }

    /// The share form: `https://skwod.io/join#<node id>[.<join code>][&u=…][&l=…]`.
    /// [`Invite::parse`] reads it back to an equal invite.
    pub fn share_link(&self) -> String {
        let mut s = format!("{SHARE_PREFIX}#{}", self.node_id.to_z32());
        if let Some(code) = &self.join_code {
            s.push('.');
            s.push_str(code);
        }
        if let Some(u) = &self.fallback_url {
            s.push_str("&u=");
            s.push_str(u);
        }
        if let Some(l) = &self.lan_key {
            s.push_str("&l=");
            s.push_str(&l.to_hex());
        }
        if let Some(r) = &self.relay_url {
            s.push_str("&r=");
            s.push_str(r);
        }
        s
    }
}

/// The fragment of a share link, or `None` if `link` is not exactly `https://skwod.io/join#…`
/// (scheme and host compared case-insensitively, one optional `/` before the `#`). Look-alike
/// hosts, other paths, ports, credentials and query strings all fail here.
fn strip_share_prefix(link: &str) -> Option<&str> {
    let head = link.get(..SHARE_PREFIX.len())?;
    if !head.eq_ignore_ascii_case(SHARE_PREFIX) {
        return None;
    }
    let rest = &link[SHARE_PREFIX.len()..];
    rest.strip_prefix('#').or_else(|| rest.strip_prefix("/#"))
}

impl std::fmt::Display for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{PREFIX}{}", self.node_id.to_z32())?;
        let mut sep = '?';
        if let Some(u) = &self.fallback_url {
            write!(f, "{sep}u={u}")?;
            sep = '&';
        }
        if let Some(l) = &self.lan_key {
            write!(f, "{sep}l={}", l.to_hex())?;
            sep = '&';
        }
        if let Some(r) = &self.relay_url {
            write!(f, "{sep}r={r}")?;
        }
        if let Some(code) = &self.join_code {
            write!(f, "#{code}")?;
        }
        Ok(())
    }
}

/// What to dial for `node`: the bare node id (the DHT / n0 lookup finds it), plus the relay hint
/// when one was given, it is allow-listed, and the member allows public fallback. With the hint
/// the first packet goes out at once through the relay; the lookups still run alongside.
pub fn dial_addr(node: EndpointId, relay_hint: Option<&str>, public_fallback: bool) -> iroh::EndpointAddr {
    let addr = iroh::EndpointAddr::new(node);
    match relay_hint.filter(|_| public_fallback).and_then(is_allowed_relay).and_then(|u| u.parse::<iroh::RelayUrl>().ok()) {
        Some(url) => addr.with_relay_url(url),
        None => addr,
    }
}

/// Parse a node id: z-base-32 (the invite form) or 64-char hex (what iroh prints in logs).
pub fn parse_node_id(s: &str) -> Result<EndpointId, NetError> {
    EndpointId::from_z32(s)
        .ok()
        .or_else(|| s.parse::<EndpointId>().ok())
        .ok_or(NetError::Invite("malformed node id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = iroh::SecretKey::generate().public();
        let inv = Invite::new(id, Some("SKWD-AB12-CD34".into()));
        let s = inv.to_string();
        assert!(s.starts_with("skwod://join/"));
        assert!(s.ends_with("#SKWD-AB12-CD34"));
        assert_eq!(s.len(), "skwod://join/".len() + 52 + 1 + 14);
        assert_eq!(Invite::parse(&s).unwrap(), inv);
    }

    #[test]
    fn no_code_and_fallback_url() {
        let id = iroh::SecretKey::generate().public();
        let z = id.to_z32();
        assert_eq!(Invite::parse(&format!("skwod://join/{z}")).unwrap().join_code, None);
        let inv = Invite::parse(&format!("skwod://join/{z}?x=1&u=https://chat.example.org#abc")).unwrap();
        assert_eq!(inv.fallback_url.as_deref(), Some("https://chat.example.org"));
        assert_eq!(inv.join_code.as_deref(), Some("abc"));
        assert_eq!(Invite::parse(&inv.to_string()).unwrap(), inv);
        // http:// fallbacks are dropped, never honoured.
        assert_eq!(Invite::parse(&format!("skwod://join/{z}?u=http://evil")).unwrap().fallback_url, None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Invite::parse("https://example.com").is_err());
        assert!(Invite::parse("skwod://join/notakey#code").is_err());
        let z = iroh::SecretKey::generate().public().to_z32();
        assert!(Invite::parse(&format!("skwod://join/{z}#bad code!")).is_err());
    }
}

#[cfg(test)]
mod lan_key_tests {
    use super::*;

    #[test]
    fn the_lan_key_round_trips_and_is_optional() {
        let node = iroh::SecretKey::generate().public();
        let plain = Invite::new(node, Some("SKWD-AAAA-BBBB".into()));
        assert!(!plain.to_string().contains("l="));
        let mut with = plain.clone();
        with.lan_key = Some(crate::lan::LanKey::generate());
        with.fallback_url = Some("https://chat.example.org".into());
        let parsed = Invite::parse(&with.to_string()).unwrap();
        assert_eq!(parsed, with);
        // A malformed key is ignored, not an error (older/newer clients keep working).
        let odd = format!("skwod://join/{}?l=zz#SKWD-AAAA-BBBB", node.to_z32());
        assert_eq!(Invite::parse(&odd).unwrap().lan_key, None);
    }
}

#[cfg(test)]
mod share_link_tests {
    use super::*;

    fn node() -> EndpointId {
        iroh::SecretKey::generate().public()
    }

    #[test]
    fn share_form_round_trips_and_equals_the_app_form() {
        let id = node();
        let z = id.to_z32();
        let inv = Invite::new(id, Some("SKWD-AB12-CD34".into()));
        let share = inv.share_link();
        assert_eq!(share, format!("https://skwod.io/join#{z}.SKWD-AB12-CD34"));
        assert_eq!(Invite::parse(&share).unwrap(), inv);
        assert_eq!(Invite::parse(&share).unwrap(), Invite::parse(&inv.to_string()).unwrap());
        // No code: just the key.
        let bare = Invite::new(id, None);
        assert_eq!(bare.share_link(), format!("https://skwod.io/join#{z}"));
        assert_eq!(Invite::parse(&bare.share_link()).unwrap(), bare);
        // A trailing dot with no code is "no code", like a bare `#` in the app form.
        assert_eq!(Invite::parse(&format!("https://skwod.io/join#{z}.")).unwrap(), bare);
    }

    #[test]
    fn share_form_carries_the_fallback_and_lan_key_in_the_fragment() {
        let mut inv = Invite::new(node(), Some("tok_en-1".into()));
        inv.fallback_url = Some("https://chat.example.org".into());
        inv.lan_key = Some(crate::lan::LanKey::generate());
        let share = inv.share_link();
        // Nothing but the fixed prefix precedes the `#`: nothing reaches the web server.
        assert_eq!(share.split_once('#').unwrap().0, "https://skwod.io/join");
        assert!(!share.contains('?'));
        assert_eq!(Invite::parse(&share).unwrap(), inv);
        // http:// fallbacks are dropped; unknown params and a malformed lan key are ignored.
        let z = inv.node_id.to_z32();
        let odd = Invite::parse(&format!("https://skwod.io/join#{z}.abc&x=1&u=http://evil&l=zz")).unwrap();
        assert_eq!((odd.fallback_url, odd.lan_key), (None, None));
        assert_eq!(odd.join_code.as_deref(), Some("abc"));
    }

    #[test]
    fn share_form_accepts_only_the_exact_origin_and_path() {
        let z = node().to_z32();
        for ok in [
            format!("https://skwod.io/join#{z}.abc"),
            format!("https://skwod.io/join/#{z}.abc"),
            format!("HTTPS://Skwod.IO/join#{z}.abc"),
            format!("  https://skwod.io/join#{z}.abc\n"),
        ] {
            assert_eq!(Invite::parse(&ok).unwrap().join_code.as_deref(), Some("abc"), "{ok}");
        }
        for bad in [
            format!("http://skwod.io/join#{z}.abc"),
            format!("https://skwod.io.evil.example/join#{z}.abc"),
            format!("https://evil.example/join#{z}.abc"),
            format!("https://www.skwod.io/join#{z}.abc"),
            format!("https://skwod.io:8443/join#{z}.abc"),
            format!("https://user@skwod.io/join#{z}.abc"),
            format!("https://skwod.io/joined#{z}.abc"),
            format!("https://skwod.io/join/x#{z}.abc"),
            format!("https://skwod.io/#{z}.abc"),
            // A query would be sent to the server; refuse it instead of parsing around it.
            format!("https://skwod.io/join?n={z}#{z}.abc"),
            format!("https://skwod.io/join?u=https://chat.example.org#{z}.abc"),
            format!("https://skwod.io/join#{z}.bad code!"),
            format!("https://skwod.io/join#{z}.a.b"),
            format!("https://skwod.io/join#{z}x.abc"),
            "https://skwod.io/join#notakey.abc".to_string(),
            "https://skwod.io/join#".to_string(),
            "https://skwod.io/join".to_string(),
            "https://skwod.io/joi".to_string(),
            "https://skwöd.io/join#x".to_string(),
        ] {
            assert!(Invite::parse(&bad).is_err(), "{bad}");
        }
    }
}

#[cfg(test)]
mod relay_hint_tests {
    use super::*;

    #[test]
    fn the_relay_hint_round_trips_in_both_forms() {
        let mut inv = Invite::new(iroh::SecretKey::generate().public(), Some("SKWD-AB12-CD34".into()));
        inv.relay_url = Some("https://use1-1.relay.n0.iroh.link/".into());
        let share = inv.share_link();
        assert!(share.ends_with("&r=https://use1-1.relay.n0.iroh.link/"), "{share}");
        assert_eq!(Invite::parse(&share).unwrap(), inv);
        assert_eq!(Invite::parse(&inv.to_string()).unwrap(), inv);
        inv.fallback_url = Some("https://chat.example.org".into());
        assert_eq!(Invite::parse(&inv.share_link()).unwrap(), inv);
        assert_eq!(Invite::parse(&inv.to_string()).unwrap(), inv);
    }

    #[test]
    fn only_allow_listed_https_relays_are_kept() {
        // What iroh prints (trailing dot) is accepted and canonicalized.
        assert_eq!(is_allowed_relay("https://use1-1.relay.n0.iroh.link./").as_deref(), Some("https://use1-1.relay.n0.iroh.link/"));
        assert_eq!(is_allowed_relay("HTTPS://EUW1-1.relay.n0.iroh.link").as_deref(), Some("https://euw1-1.relay.n0.iroh.link/"));
        for bad in [
            "http://use1-1.relay.n0.iroh.link/",
            "https://relay.n0.iroh.link/",
            "https://.relay.n0.iroh.link/",
            "https://evil.example/",
            "https://use1-1.relay.n0.iroh.link.evil.example/",
            "https://evilrelay.n0.iroh.link/",
            "https://use1-1.relay.n0.iroh.link:8443/",
            "https://user@use1-1.relay.n0.iroh.link/",
            "https://use1-1.relay.n0.iroh.link/x",
            "https://use1-1.relay.n0.iroh.link/?a=b",
            "https://-x.relay.n0.iroh.link/",
            "https://a..relay.n0.iroh.link/",
            "",
        ] {
            assert_eq!(is_allowed_relay(bad), None, "{bad}");
        }
        // A link with a bad hint still parses; the hint is just dropped.
        let z = iroh::SecretKey::generate().public().to_z32();
        let inv = Invite::parse(&format!("https://skwod.io/join#{z}.abc&r=https://evil.example/")).unwrap();
        assert_eq!((inv.relay_url, inv.join_code.as_deref()), (None, Some("abc")));
    }

    #[test]
    fn the_hint_is_dialed_only_with_public_fallback_and_only_if_allowed() {
        let node = iroh::SecretKey::generate().public();
        let good = Some("https://use1-1.relay.n0.iroh.link/");
        assert_eq!(dial_addr(node, good, true).relay_urls().count(), 1);
        assert_eq!(dial_addr(node, good, false).relay_urls().count(), 0, "independent mode never touches n0");
        assert_eq!(dial_addr(node, Some("https://evil.example/"), true).relay_urls().count(), 0);
        assert_eq!(dial_addr(node, None, true), iroh::EndpointAddr::new(node));
    }
}
