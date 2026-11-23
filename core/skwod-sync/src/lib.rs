//! skwod-sync — the client-side data/sync engine shared by all native apps (ADR-001).
//!
//! - [`cache`] — SQLCipher-encrypted local store: decrypted messages, structure, sessions,
//!   and the optimistic-write outbox. The platform `KeyStore` supplies the 32-byte cache key
//!   (Secure Enclave / StrongBox gated); nothing here persists plaintext outside that store.
//!
//! - [`client`] / [`realtime`] — REST + WebSocket clients (ciphertext in, ciphertext out).
//! - [`engine`] — the E2EE session manager: libsignal (via `skwod-crypto`) wired to the server's
//!   key directory and sealed mailbox.
//! - [`beacon`] — the decentralized address beacon.
//!
//! See `docs/SECURITY.md` for what is and is not Signal-grade here.

pub mod beacon;
pub mod cache;
pub mod client;
pub mod engine;
pub mod realtime;

pub use cache::{Cache, CacheError};
pub use client::{valid_blob_id, ApiClient, ChunkOutcome, ClientError, Session, CLIENT_BUILD};
pub use engine::{
    is_undecryptable, undecryptable_body, DeviceInfo, DeviceState, MemorySentStore, OutgoingRow, ResentMessage, RetryEvent, SentStore, StateSink, SENT_RETENTION_MS, UNDECRYPTABLE_TAG,
};
pub use engine::{
    ChannelDelete, ChannelPage, ChannelPlaintext, DmConversation, DmOp, DmOpKind, Engine, EngineError, EventSink, InboundDm, InboundMessage, InboundReport, InboxOutcome, LoadOutcome, PageCursor, PeerId, Reaction,
    SecurityNotice, SystemEvent, Traffic, MAX_GROUP_DM, MAX_REPORT_EXCERPT, MAX_TEXT, PAGE, SELF_AUTHOR, SYSTEM_AUTHOR, SYSTEM_TAG,
};
pub use realtime::{RealtimeClient, RtEvent};
