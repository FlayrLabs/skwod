//! Stream preamble. Every bi-stream on a `skwod/1` connection starts with ONE kind byte written by
//! the opener (the member); what follows depends on the kind.

use iroh::endpoint::{RecvStream, SendStream};

/// Raw HTTP/1.1 (incl. WebSocket upgrade) against the skwod API.
pub(crate) const KIND_HTTP: u8 = 1;
/// Raw HTTP/1.1 against the host's LiveKit signaling port (only after a successful VOICE_HELLO).
pub(crate) const KIND_LIVEKIT: u8 = 2;
/// `u16 len || bearer token` → one JSON line `{"ok":bool,"udp_port":u16}`. Authorizes this
/// connection for LiveKit streams + media datagrams.
pub(crate) const KIND_VOICE_HELLO: u8 = 3;

/// A QUIC bi-stream as one `AsyncRead + AsyncWrite` object.
pub type BiStream = tokio::io::Join<RecvStream, SendStream>;

pub(crate) fn join(send: SendStream, recv: RecvStream) -> BiStream {
    tokio::io::join(recv, send)
}
/// A connection's proof-of-work stamp (`pow::Purpose::Connection`): the kind byte, then the
/// stamp as ASCII, then the stream ends. Sent by a member as the FIRST stream of every
/// connection; the host answers nothing. See `host.rs`, "Admission".
pub(crate) const KIND_PROOF: u8 = 4;
