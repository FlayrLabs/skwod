//! skwod-net — the peer-to-peer transport (see `docs/P2P.md`).
//!
//! **The address of a skwod is the host's key.** The server owns a persistent iroh secret key; its
//! public half (the *node id*) is what an invite carries and what a member pins. A member finds the
//! host's current network addresses through the BitTorrent Mainline DHT (pkarr records signed by
//! that key), dials it over QUIC with hole punching, and then speaks the *unchanged* HTTP/WebSocket
//! API over QUIC streams. LiveKit signaling rides a stream; LiveKit media rides QUIC datagrams.
//!
//! The publisher runs no infrastructure. n0's public relays + DNS are an *optional* fallback
//! ([`NetConfig::public_fallback`]) that a host/member can turn off to be strictly independent.
//!
//! Layout:
//! - [`invite`]   — `skwod://join/<node id>#<join code>`
//! - [`endpoint`] — endpoint construction: key file, discovery, relay policy, port mapping
//! - [`lan`]      — opt-in same-LAN discovery under a rotating keyed tag
//! - [`host`]     — accept loop: bridges streams to the HTTP service / LiveKit
//! - [`member`]   — dial + (re)connect + stream opening + path reporting
//! - [`proxy`]    — authenticated loopback HTTP proxy the apps point their existing clients at
//! - [`pow`]      — proof-of-work stamps for unauthenticated first contact (signup/login)
//! - [`voice`]    — LiveKit UDP media over QUIC datagrams (framing + forwarders)
//!
//! Privacy: nothing in this crate logs a network address. Path reporting says only
//! "direct"/"relay" + RTT.

pub mod endpoint;
pub mod host;
pub mod invite;
pub mod lan;
pub mod member;
pub mod pow;
pub mod proxy;
pub mod voice;
mod wire;

pub use endpoint::{bind, load_or_create_secret_key, Discovery, NetConfig, NetPlan, Role};
pub use host::{Host, HostBackend, LiveKitTarget};
pub use invite::Invite;
pub use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};
/// The pinned iroh API, for callers that need more than the re-exports (watchers, relay maps).
pub use iroh as iroh_api;
pub use member::{Member, PathInfo, PathKind};
pub use proxy::LocalProxy;
pub use wire::BiStream;

/// ALPN for the skwod tunnel. Bump the suffix on any incompatible change to the stream preamble.
pub const ALPN: &[u8] = b"skwod/1";

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("invalid invite: {0}")]
    Invite(&'static str),
    #[error("could not start the p2p endpoint: {0}")]
    Bind(String),
    /// No path (direct or relayed) to the host could be established. This is the seam where a
    /// future transport (Tor onion service, stage 4) is tried next — see `docs/P2P.md`.
    #[error("could not reach the host: {0}")]
    Unreachable(String),
    #[error("p2p i/o error: {0}")]
    Io(String),
    #[error("voice is not available on this skwod")]
    VoiceUnavailable,
}

pub(crate) type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'static>>;
