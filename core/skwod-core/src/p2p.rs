//! p2p transport for the apps (see `docs/P2P.md`).
//!
//! The whole integration is ONE call: [`p2p_connect`] dials the host by its node id and returns a
//! [`P2pSession`] whose [`P2pSession::base_url`] is a drop-in replacement for the `https://…`
//! server URL — pass it to [`crate::signup`], [`crate::login`], [`crate::SkwodClient::new`], and
//! to the app's own URLSession / OkHttp / WebSocket code. It points at a loopback proxy inside the
//! app process (127.0.0.1, random port, unguessable path prefix) that carries every request to
//! the host over the p2p connection. Voice needs nothing extra: `SkwodClient::voice_token` returns
//! a loopback LiveKit URL when the session is p2p.
//!
//! `https://` server URLs keep working unchanged (VPS hosts) — just don't call `p2p_connect`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use skwod_net::{EndpointAddr, Invite, LocalProxy, Member, NetConfig};

use crate::CoreError;

fn net_err(e: skwod_net::NetError) -> CoreError {
    match e {
        skwod_net::NetError::Invite(_) => CoreError::Invalid { detail: e.to_string() },
        _ => CoreError::Engine { detail: e.to_string() },
    }
}

/// A parsed invite: `skwod://join/<node id>#<join code>` or its share form
/// `https://skwod.io/join#<node id>.<join code>`.
#[derive(Debug, uniffi::Record)]
pub struct P2pInvite {
    /// The host's node id (z-base-32): its address AND its pinned identity.
    pub node_id: String,
    /// The join code to present at signup, if the link carried one.
    pub join_code: Option<String>,
    /// An `https://` address of the same skwod, if the host has one (VPS). Not used for p2p.
    pub fallback_url: Option<String>,
}

/// Parse an invite link. Errors with `Invalid` unless it is a well-formed `skwod://join/…` link
/// or a well-formed `https://skwod.io/join#…` share link (both spellings parse to the same invite).
#[uniffi::export]
pub fn p2p_parse_invite(link: String) -> Result<P2pInvite, CoreError> {
    let inv = Invite::parse(&link).map_err(net_err)?;
    Ok(P2pInvite { node_id: inv.node_id.to_z32(), join_code: inv.join_code, fallback_url: inv.fallback_url })
}

/// Build an invite link from the host's node id (`GET /api/instance/p2p`) and a join code.
#[uniffi::export]
pub fn p2p_format_invite(node_id: String, join_code: Option<String>) -> Result<String, CoreError> {
    let node = skwod_net::invite::parse_node_id(&node_id).map_err(net_err)?;
    Ok(Invite::new(node, join_code.filter(|c| !c.trim().is_empty())).to_string())
}

/// Build the link people SHARE: `https://skwod.io/join#<node id>[.<join code>][&u=<https url>]`.
/// It opens a static page (or, through universal links / app links, the app itself) that hands the
/// invite to the app. Everything identifying the skwod sits in the URL fragment, which is never
/// sent to a server. [`p2p_parse_invite`] accepts it, as do builds from 42 on; older builds only
/// understand the `skwod://` form from [`p2p_format_invite`], which the page forwards to.
/// `fallback_url` is kept only if it is an `https://` address.
#[uniffi::export]
pub fn p2p_format_share_link(
    node_id: String,
    join_code: Option<String>,
    fallback_url: Option<String>,
) -> Result<String, CoreError> {
    let node = skwod_net::invite::parse_node_id(&node_id).map_err(net_err)?;
    let mut invite = Invite::new(node, join_code.map(|c| c.trim().to_string()).filter(|c| !c.is_empty()));
    invite.fallback_url = fallback_url.filter(|u| u.starts_with("https://"));
    let link = invite.share_link();
    // Never hand out a link we would refuse ourselves (e.g. a code outside the charset).
    Invite::parse(&link).map_err(net_err)?;
    Ok(link)
}

/// How we currently reach the host. Never contains an address.
#[derive(Debug, uniffi::Record)]
pub struct P2pPath {
    /// `"direct"` (straight UDP to the host), `"relay"` (via a relay — only with public fallback),
    /// or `"none"` (not connected right now; the next request re-dials).
    pub kind: String,
    /// Round-trip time of that path in milliseconds (0 when not connected).
    pub rtt_ms: u32,
}

/// Counters of the voice tunnel's media forwarder (UDP packets to/from LiveKit).
#[derive(Debug, uniffi::Record)]
pub struct P2pVoiceStats {
    pub packets_up: u64,
    pub bytes_up: u64,
    pub packets_down: u64,
    pub bytes_down: u64,
}

/// A live p2p connection to one skwod host, plus the loopback proxy in front of it.
#[derive(uniffi::Object)]
pub struct P2pSession {
    member: Arc<Member>,
    proxy: LocalProxy,
}

fn sessions() -> &'static Mutex<HashMap<String, Weak<P2pSession>>> {
    static SESSIONS: OnceLock<Mutex<HashMap<String, Weak<P2pSession>>>> = OnceLock::new();
    SESSIONS.get_or_init(Default::default)
}

/// The p2p session behind a base URL, if that URL is one of our loopback proxies.
pub(crate) fn session_for(base_url: &str) -> Option<Arc<P2pSession>> {
    sessions().lock().unwrap_or_else(|e| e.into_inner()).get(base_url.trim_end_matches('/')).and_then(Weak::upgrade)
}

/// Dial the skwod whose address is `node_id` (from [`p2p_parse_invite`]) and start the loopback
/// proxy. Finds the host through the Mainline DHT and connects directly when it can.
///
/// `public_fallback`: also allow n0's public relays + DNS (default choice: `true` — connects
/// through almost any NAT). `false` = strictly independent: DHT + direct connections only; fails
/// with an `Engine` error ("could not reach the host") when no direct path exists.
///
/// The member uses a fresh throwaway key per call, so the host cannot link sessions by node id.
#[uniffi::export(async_runtime = "tokio")]
pub async fn p2p_connect(node_id: String, public_fallback: bool) -> Result<Arc<P2pSession>, CoreError> {
    let node = skwod_net::invite::parse_node_id(&node_id).map_err(net_err)?;
    let mut cfg = NetConfig::member();
    cfg.public_fallback = public_fallback;
    connect_with(&cfg, EndpointAddr::new(node)).await
}

/// [`p2p_connect`] with an explicit network configuration / dialing info (tests, same-machine dial).
pub async fn connect_with(cfg: &NetConfig, host: EndpointAddr) -> Result<Arc<P2pSession>, CoreError> {
    let member = Member::connect(cfg, host).await.map_err(net_err)?;
    let proxy = LocalProxy::start(member.clone()).await.map_err(net_err)?;
    let session = Arc::new(P2pSession { member, proxy });
    let mut map = sessions().lock().unwrap_or_else(|e| e.into_inner());
    map.retain(|_, s| s.strong_count() > 0);
    map.insert(session.proxy.base_url(), Arc::downgrade(&session));
    Ok(session)
}

#[uniffi::export(async_runtime = "tokio")]
impl P2pSession {
    /// The server URL to use everywhere a `https://…` server URL was used:
    /// `http://127.0.0.1:<port>/<secret>`. Valid until [`P2pSession::close`] / app exit; it
    /// changes every launch, so persist the node id (not this URL) as the skwod's identity.
    pub fn base_url(&self) -> String {
        self.proxy.base_url()
    }

    /// The host's node id (z-base-32) this session is pinned to.
    pub fn node_id(&self) -> String {
        self.member.host_id().to_z32()
    }

    /// Direct or relayed, and the latency — for a connection indicator. Local only; no telemetry.
    pub async fn path(&self) -> P2pPath {
        let p = self.member.path().await;
        P2pPath { kind: p.kind.as_str().to_string(), rtt_ms: p.rtt_ms }
    }

    /// Start (or re-use) the voice tunnel for this session and return the URL to hand the LiveKit
    /// SDK instead of the server-reported one. `session_token` is the account's bearer token (it
    /// authorizes media forwarding on the host). `SkwodClient::voice_token` calls this for you.
    pub async fn voice_url(&self, session_token: String) -> Result<String, CoreError> {
        self.member.voice_start(&session_token).await.map_err(net_err)?;
        Ok(self.proxy.livekit_url())
    }

    /// Media carried by the voice tunnel so far — for a call-quality/debug readout. Local only.
    pub fn voice_stats(&self) -> P2pVoiceStats {
        let (packets_up, bytes_up, packets_down, bytes_down) = self.member.voice_stats();
        P2pVoiceStats { packets_up, bytes_up, packets_down, bytes_down }
    }

    /// Tell the transport the device's network changed (Wi-Fi ↔ cellular). Required on Android,
    /// harmless elsewhere.
    pub async fn network_changed(&self) {
        self.member.network_changed().await;
    }

    /// Close the connection and stop the loopback proxy.
    pub async fn disconnect(&self) {
        sessions().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.proxy.base_url());
        self.member.close().await;
    }
}

#[cfg(test)]
mod share_link_tests {
    use super::*;

    /// A valid node id (any 32-byte ed25519 public key in z-base-32).
    fn node_id() -> String {
        skwod_net::SecretKey::generate().public().to_z32()
    }

    #[test]
    fn the_share_link_parses_back_to_the_same_invite_as_the_app_link() {
        let node = node_id();
        let share = p2p_format_share_link(node.clone(), Some("SKWD-AB12-CD34".into()), None).unwrap();
        assert_eq!(share, format!("https://skwod.io/join#{node}.SKWD-AB12-CD34"));
        let app = p2p_format_invite(node.clone(), Some("SKWD-AB12-CD34".into())).unwrap();
        assert_eq!(app, format!("skwod://join/{node}#SKWD-AB12-CD34"));
        for link in [share, app] {
            let inv = p2p_parse_invite(link).unwrap();
            assert_eq!(inv.node_id, node);
            assert_eq!(inv.join_code.as_deref(), Some("SKWD-AB12-CD34"));
            assert_eq!(inv.fallback_url, None);
        }
    }

    #[test]
    fn the_share_link_keeps_an_https_fallback_and_nothing_else() {
        let node = node_id();
        let with = p2p_format_share_link(node.clone(), Some("abc".into()), Some("https://chat.example.org".into())).unwrap();
        assert_eq!(with, format!("https://skwod.io/join#{node}.abc&u=https://chat.example.org"));
        assert_eq!(p2p_parse_invite(with).unwrap().fallback_url.as_deref(), Some("https://chat.example.org"));
        let dropped = p2p_format_share_link(node.clone(), Some("  ".into()), Some("http://chat.example.org".into())).unwrap();
        assert_eq!(dropped, format!("https://skwod.io/join#{node}"));
    }

    #[test]
    fn the_share_link_refuses_bad_input() {
        assert!(matches!(p2p_format_share_link("notakey".into(), None, None), Err(CoreError::Invalid { .. })));
        assert!(matches!(p2p_format_share_link(node_id(), Some("bad code!".into()), None), Err(CoreError::Invalid { .. })));
        assert!(matches!(p2p_parse_invite("https://evil.example/join#x.y".into()), Err(CoreError::Invalid { .. })));
    }
}
