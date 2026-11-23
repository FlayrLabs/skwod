//! Decentralized address beacon over Nostr.
//!
//! A self-hosted skwod on an ephemeral (quick-tunnel) address can move on any restart. To let friends
//! find the CURRENT address without a resolver the developer runs and without a per-host account, the
//! host publishes a small **signed, encrypted** "I'm now at X" note to public Nostr relays, keyed by a
//! throwaway secp256k1 key. Friends (who hold the beacon pubkey + a content key from the invite) look
//! it up when their cached address is dead, verify the signature, decrypt the address, and — critically
//! — still run the server fingerprint proof-of-possession before trusting it. So relays can at most
//! censor (→ fall back to the re-share link), never forge or redirect, and (because the address is
//! AEAD-encrypted) never even learn the URL. Normal traffic never touches Nostr — only the rare lookup.
//!
//! **Privacy (`*_private` variants): both sides talk to relays over Tor.** A member's lookup over Tor
//! keeps the relay from learning who is trying to reach a given skwod. The HOST's publish must go over
//! Tor too: the whole point of the quick tunnel is to hide the host's home IP, so publishing a beacon
//! note from the host's real IP would undo it. Tor is used ONLY here (rare lookups / address changes),
//! never for normal chat/media/game traffic — that stays on the fast direct tunnel.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream;

use arti_client::{TorClient, TorClientConfig};
use tokio::sync::OnceCell;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;

/// NIP-78 parameterized-replaceable app data — relays keep only the latest per (pubkey, kind, d-tag).
const KIND: u64 = 30078;
const D_TAG: &str = "skwod-addr";
/// A default set of public relays. Publishing to several gives redundancy; a lookup tries them in turn.
pub const DEFAULT_RELAYS: &[&str] =
    &["wss://relay.damus.io", "wss://nos.lol", "wss://relay.nostr.band", "wss://relay.primal.net"];

/// Whether relay traffic goes direct or is anonymized through Tor.
#[derive(Clone, Copy, PartialEq)]
enum Transport {
    Direct,
    Tor,
}

/// One bootstrapped Tor client, shared across all beacon calls (bootstrap is slow; connects are cheap).
static TOR: OnceCell<TorClient<PreferredRuntime>> = OnceCell::const_new();

/// Last Tor bootstrap failure, kept for diagnostics — the product paths swallow errors into
/// `Option`s, which makes platform-specific bootstrap failures (Android dirs, censored networks)
/// undebuggable without this.
static LAST_TOR_ERR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// The last Tor bootstrap error message, if bootstrap has ever failed this process.
pub fn last_tor_error() -> Option<String> {
    LAST_TOR_ERR.lock().ok()?.clone()
}

/// Debug probe: run the real beacon query on each relay over Tor and report how far it gets —
/// events returned, signatures verified, ciphertext decrypted. Pinpoints which stage kills a
/// resolve that "returns null" (relay filter, schnorr verify, or AEAD/content key).
pub async fn tor_probe_query(pubkey_hex: &str, content_key_hex: &str, relays: &[String]) -> String {
    let Some(tor) = tor_client().await else {
        return format!("bootstrap failed: {}", last_tor_error().unwrap_or_else(|| "unknown/timeout".into()));
    };
    let xonly = match hex::decode(pubkey_hex).ok().and_then(|b| XOnlyPublicKey::from_slice(&b).ok()) {
        Some(x) => x,
        None => return "bad pubkey".into(),
    };
    let key = match content_key(content_key_hex) {
        Ok(k) => k,
        Err(_) => return "bad content key".into(),
    };
    let req = json!(["REQ", "s", { "authors": [pubkey_hex], "kinds": [KIND], "#d": [D_TAG], "limit": 3 }])
        .to_string();
    let secp = Secp256k1::verification_only();
    let mut out = String::new();
    for relay in relays {
        let step = async {
            let (host, port) = relay_host_port(relay)?;
            let ds = tor.connect((host.as_str(), port)).await.ok()?;
            let (mut ws, _) = tokio_tungstenite::client_async_tls_with_config(
                relay.as_str(), ds.compat(), None, None).await.ok()?;
            ws.send(WsMessage::Text(req.clone())).await.ok()?;
            let (mut raw, mut valid) = (0u32, 0u32);
            let mut best: Option<(u64, String)> = None;
            while let Some(Ok(msg)) = ws.next().await {
                let text = match msg {
                    WsMessage::Text(t) => t,
                    WsMessage::Close(_) => break,
                    _ => continue,
                };
                let v: Value = match serde_json::from_str(&text) { Ok(v) => v, Err(_) => continue };
                match v.get(0).and_then(|x| x.as_str()) {
                    Some("EVENT") => {
                        raw += 1;
                        if let Some((ts, content)) = v.get(2).and_then(|ev| verify_event(&secp, &xonly, pubkey_hex, ev)) {
                            valid += 1;
                            if best.as_ref().map(|(b, _)| ts > *b).unwrap_or(true) {
                                best = Some((ts, content));
                            }
                        }
                    }
                    Some("EOSE") => break,
                    _ => {}
                }
            }
            let dec = best.map(|(_, c)| decrypt_address(&key, &c).is_some());
            Some(format!("raw={raw} valid={valid} decrypt={dec:?}"))
        };
        match tokio::time::timeout(Duration::from_secs(45), step).await {
            Err(_) => out.push_str(&format!("{relay}: timeout; ")),
            Ok(None) => out.push_str(&format!("{relay}: conn/ws fail; ")),
            Ok(Some(s)) => out.push_str(&format!("{relay}: {s}; ")),
        }
    }
    out
}

/// Debug probe: report bootstrap state + a connect/TLS probe of each relay over Tor.
pub async fn tor_probe(relays: &[String]) -> String {
    let Some(tor) = tor_client().await else {
        return format!("bootstrap failed: {}", last_tor_error().unwrap_or_else(|| "unknown/timeout".into()));
    };
    let mut out = String::from("bootstrap ok");
    for relay in relays {
        let Some((host, port)) = relay_host_port(relay) else {
            out.push_str(&format!("; {relay}: bad url"));
            continue;
        };
        let step = async {
            let ds = tor.connect((host.as_str(), port)).await.map_err(|e| format!("connect: {e}"))?;
            tokio_tungstenite::client_async_tls_with_config(relay.as_str(), ds.compat(), None, None)
                .await
                .map_err(|e| format!("tls/ws: {e}"))?;
            Ok::<(), String>(())
        };
        match tokio::time::timeout(Duration::from_secs(30), step).await {
            Err(_) => out.push_str(&format!("; {relay}: timeout")),
            Ok(Err(e)) => out.push_str(&format!("; {relay}: {e}")),
            Ok(Ok(())) => out.push_str(&format!("; {relay}: ok")),
        }
    }
    out
}

async fn tor_client() -> Option<&'static TorClient<PreferredRuntime>> {
    let init = TOR.get_or_try_init(|| async {
        // Arti's default config resolves its state/cache dirs from $HOME — which doesn't exist in an
        // Android app process, where bootstrap would fail instantly (and silently kill every beacon
        // lookup). The app layer sets SKWOD_TOR_DIR to a writable app dir; desktop keeps the default.
        let cfg = match std::env::var("SKWOD_TOR_DIR") {
            Ok(dir) if !dir.is_empty() => {
                let mut b = arti_client::config::TorClientConfigBuilder::from_directories(
                    format!("{dir}/arti-state"),
                    format!("{dir}/arti-cache"),
                );
                // App-private dirs sit under root-owned ancestors (/data/user/0/...) that
                // fs-mistrust's permission walk rejects; the dir itself is app-only, so the check
                // adds nothing here and would kill every bootstrap.
                b.storage().permissions().dangerously_trust_everyone();
                b.build().unwrap_or_default()
            }
            _ => TorClientConfig::default(),
        };
        TorClient::create_bootstrapped(cfg).await.inspect_err(|e| {
            if let Ok(mut g) = LAST_TOR_ERR.lock() {
                *g = Some(format!("{e:?}"));
            }
        })
    });
    // Bootstrap can hang on a censored network — bound it so a stuck client can't wedge a lookup.
    tokio::time::timeout(Duration::from_secs(90), init).await.ok()?.ok()
}

#[derive(Debug, thiserror::Error)]
pub enum BeaconError {
    #[error("bad key")]
    Key,
    #[error("no relay reachable")]
    Unreachable,
}

/// A throwaway beacon identity. `secret_hex` stays on the host; `pubkey_hex` (x-only) goes in invites.
pub struct BeaconKey {
    pub secret_hex: String,
    pub pubkey_hex: String,
}

/// Generate a fresh secp256k1 beacon key (no account, no signup — just a keypair).
pub fn generate_beacon_key() -> BeaconKey {
    let secp = Secp256k1::new();
    let sk = loop {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        if let Ok(sk) = SecretKey::from_slice(&b) {
            break sk;
        }
    };
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    BeaconKey {
        secret_hex: hex::encode(sk.secret_bytes()),
        pubkey_hex: hex::encode(xonly.serialize()),
    }
}

fn content_key(hex_key: &str) -> Result<Vec<u8>, BeaconError> {
    let k = hex::decode(hex_key).map_err(|_| BeaconError::Key)?;
    if k.len() != 32 {
        return Err(BeaconError::Key);
    }
    Ok(k)
}

/// AEAD-encrypt the address so relays store only ciphertext: base64(nonce(12) ‖ ct‖tag).
/// ChaCha20-Poly1305 via `skwod_crypto::aead` (static content key shared through the invite).
fn encrypt_address(key: &[u8], address: &str) -> String {
    let key: [u8; 32] = key.try_into().expect("content_key() validated the length");
    B64.encode(skwod_crypto::aead::seal(&key, b"skwod-beacon-v1", address.as_bytes()))
}

fn decrypt_address(key: &[u8], content: &str) -> Option<String> {
    let key: [u8; 32] = key.try_into().ok()?;
    let raw = B64.decode(content).ok()?;
    String::from_utf8(skwod_crypto::aead::open(&key, b"skwod-beacon-v1", &raw)?).ok()
}

/// The NIP-01 event id: sha256 of the compact array `[0, pubkey, created_at, kind, tags, content]`.
fn event_id(pubkey: &str, created_at: u64, content: &str) -> [u8; 32] {
    let serialized =
        serde_json::to_string(&json!([0, pubkey, created_at, KIND, [["d", D_TAG]], content]))
            .unwrap_or_default();
    Sha256::digest(serialized.as_bytes()).into()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// `wss://host[:port]/...` → (host, port). Defaults to 443.
fn relay_host_port(relay: &str) -> Option<(String, u16)> {
    let rest = relay
        .strip_prefix("wss://")
        .or_else(|| relay.strip_prefix("ws://"))?;
    let authority = rest.split('/').next()?;
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((authority.to_string(), 443)),
    }
}

// ---- transport-agnostic websocket helpers ------------------------------------------------------

/// Send one framed Nostr EVENT and return whether the relay actually ACCEPTED it — the NIP-20
/// `["OK", <id>, true, ...]` reply. Treating "sent" as "published" let every relay silently reject
/// a note (rate limits, PoW policy) while the host believed its move was announced.
async fn ws_send<S>(mut ws: WebSocketStream<S>, msg: &str) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if ws.send(WsMessage::Text(msg.to_string())).await.is_err() {
        return false;
    }
    let mut accepted = false;
    // Skip any non-OK frames (NOTICEs etc.) until the OK verdict, EOF, or close.
    while let Some(Ok(frame)) = ws.next().await {
        let text = match frame {
            WsMessage::Text(t) => t,
            WsMessage::Close(_) => break,
            _ => continue,
        };
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            if v.get(0).and_then(|x| x.as_str()) == Some("OK") {
                accepted = v.get(2).and_then(|x| x.as_bool()).unwrap_or(false);
                break;
            }
        }
    }
    let _ = ws.close(None).await;
    accepted
}

/// Send a REQ and collect the newest VALID beacon note (id + schnorr verified) until EOSE/close.
async fn ws_collect<S>(
    mut ws: WebSocketStream<S>,
    req: &str,
    pubkey: &str,
    xonly: &XOnlyPublicKey,
) -> Option<(u64, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let secp = Secp256k1::verification_only();
    ws.send(WsMessage::Text(req.to_string())).await.ok()?;
    let mut best: Option<(u64, String)> = None;
    while let Some(Ok(msg)) = ws.next().await {
        let text = match msg {
            WsMessage::Text(t) => t,
            WsMessage::Close(_) => break,
            _ => continue,
        };
        let v: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => continue,
        };
        match v.get(0).and_then(|x| x.as_str()) {
            Some("EVENT") => {
                if let Some((ts, content)) =
                    v.get(2).and_then(|ev| verify_event(&secp, xonly, pubkey, ev))
                {
                    if best.as_ref().map(|(b, _)| ts > *b).unwrap_or(true) {
                        best = Some((ts, content));
                    }
                }
            }
            Some("EOSE") => break,
            _ => {}
        }
    }
    let _ = ws.close(None).await;
    best
}

/// Open a websocket to `relay` over the chosen transport and hand it to `send`/`collect`.
async fn publish_one(relay: &str, msg: &str, transport: Transport) -> bool {
    match transport {
        Transport::Direct => {
            let fut = async {
                let (ws, _) = tokio_tungstenite::connect_async(relay).await.ok()?;
                Some(ws_send(ws, msg).await)
            };
            tokio::time::timeout(Duration::from_secs(8), fut)
                .await
                .ok()
                .flatten()
                .unwrap_or(false)
        }
        Transport::Tor => {
            let fut = async {
                let (host, port) = relay_host_port(relay)?;
                let tor = tor_client().await?;
                let ds = tor.connect((host.as_str(), port)).await.ok()?;
                let (ws, _) = tokio_tungstenite::client_async_tls_with_config(
                    relay,
                    ds.compat(),
                    None,
                    None,
                )
                .await
                .ok()?;
                Some(ws_send(ws, msg).await)
            };
            tokio::time::timeout(Duration::from_secs(45), fut)
                .await
                .ok()
                .flatten()
                .unwrap_or(false)
        }
    }
}

async fn query_one(
    relay: &str,
    pubkey_hex: &str,
    xonly: &XOnlyPublicKey,
    transport: Transport,
) -> Option<(u64, String)> {
    let req = json!(["REQ", "s", { "authors": [pubkey_hex], "kinds": [KIND], "#d": [D_TAG], "limit": 3 }])
        .to_string();
    match transport {
        Transport::Direct => {
            let fut = async {
                let (ws, _) = tokio_tungstenite::connect_async(relay).await.ok()?;
                ws_collect(ws, &req, pubkey_hex, xonly).await
            };
            tokio::time::timeout(Duration::from_secs(10), fut).await.ok().flatten()
        }
        Transport::Tor => {
            let fut = async {
                let (host, port) = relay_host_port(relay)?;
                let tor = tor_client().await?;
                let ds = tor.connect((host.as_str(), port)).await.ok()?;
                let (ws, _) = tokio_tungstenite::client_async_tls_with_config(
                    relay,
                    ds.compat(),
                    None,
                    None,
                )
                .await
                .ok()?;
                ws_collect(ws, &req, pubkey_hex, xonly).await
            };
            tokio::time::timeout(Duration::from_secs(45), fut).await.ok().flatten()
        }
    }
}

// ---- public API --------------------------------------------------------------------------------

async fn publish_impl(
    beacon_secret_hex: &str,
    content_key_hex: &str,
    address: &str,
    relays: &[String],
    transport: Transport,
) -> Result<(), BeaconError> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&hex::decode(beacon_secret_hex).map_err(|_| BeaconError::Key)?)
        .map_err(|_| BeaconError::Key)?;
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let pubkey = hex::encode(xonly.serialize());
    let created_at = now_secs();
    let content = encrypt_address(&content_key(content_key_hex)?, address);
    let id = event_id(&pubkey, created_at, &content);
    let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(id), &kp);
    let event = json!({
        "id": hex::encode(id), "pubkey": pubkey, "created_at": created_at, "kind": KIND,
        "tags": [["d", D_TAG]], "content": content, "sig": hex::encode(sig.as_ref() as &[u8]),
    });
    let msg = json!(["EVENT", event]).to_string();
    let mut any = false;
    for relay in relays {
        if publish_one(relay, &msg, transport).await {
            any = true;
        }
    }
    if any {
        Ok(())
    } else {
        Err(BeaconError::Unreachable)
    }
}

async fn resolve_impl(
    beacon_pubkey_hex: &str,
    content_key_hex: &str,
    relays: &[String],
    min_created_at: u64,
    transport: Transport,
) -> Option<(u64, String)> {
    let key = content_key(content_key_hex).ok()?;
    let xonly = XOnlyPublicKey::from_slice(&hex::decode(beacon_pubkey_hex).ok()?).ok()?;
    let mut best: Option<(u64, String)> = None;
    for relay in relays {
        if let Some((ts, content)) = query_one(relay, beacon_pubkey_hex, &xonly, transport).await {
            // Freshness floor: ignore any note older than the last address we adopted. `created_at`
            // is signed (verify_event), so a relay can't forge a newer timestamp — but it CAN
            // suppress the newest note and serve an old, still-validly-signed one to pin us to a
            // stale (possibly re-registered / attacker) address. Rejecting <= min_created_at closes
            // that suppression/rollback window.
            if ts < min_created_at {
                continue;
            }
            if best.as_ref().map(|(b, _)| ts > *b).unwrap_or(true) {
                best = Some((ts, content));
            }
        }
    }
    let (ts, content) = best?;
    Some((ts, decrypt_address(&key, &content)?))
}

/// Publish "my address is now `address`" directly (fast; reveals publisher IP to relays — tests/LAN).
pub async fn publish_address(
    beacon_secret_hex: &str,
    content_key_hex: &str,
    address: &str,
    relays: &[String],
) -> Result<(), BeaconError> {
    publish_impl(beacon_secret_hex, content_key_hex, address, relays, Transport::Direct).await
}

/// Publish over Tor so the relay never learns the host's real IP (preserves quick-tunnel anonymity).
pub async fn publish_address_private(
    beacon_secret_hex: &str,
    content_key_hex: &str,
    address: &str,
    relays: &[String],
) -> Result<(), BeaconError> {
    publish_impl(beacon_secret_hex, content_key_hex, address, relays, Transport::Tor).await
}

/// Resolve the current address directly (fast; reveals the looker-up's IP to relays — tests/LAN).
/// Rejects notes older than `min_created_at` (rollback protection). Returns `(created_at, address)`.
/// The caller MUST still verify the server fingerprint before trusting the returned address.
pub async fn resolve_address(
    beacon_pubkey_hex: &str,
    content_key_hex: &str,
    relays: &[String],
    min_created_at: u64,
) -> Option<(u64, String)> {
    resolve_impl(beacon_pubkey_hex, content_key_hex, relays, min_created_at, Transport::Direct).await
}

/// Resolve over Tor so the relay never learns which member is trying to reach the skwod.
/// Rejects notes older than `min_created_at` (rollback protection). Returns `(created_at, address)`.
/// The caller MUST still verify the server fingerprint before trusting the returned address.
pub async fn resolve_address_private(
    beacon_pubkey_hex: &str,
    content_key_hex: &str,
    relays: &[String],
    min_created_at: u64,
) -> Option<(u64, String)> {
    resolve_impl(beacon_pubkey_hex, content_key_hex, relays, min_created_at, Transport::Tor).await
}

/// Recompute the id + verify the schnorr signature so a relay can't hand us a forged note.
fn verify_event(
    secp: &Secp256k1<secp256k1::VerifyOnly>,
    xonly: &XOnlyPublicKey,
    expected_pubkey: &str,
    ev: &Value,
) -> Option<(u64, String)> {
    let pubkey = ev.get("pubkey")?.as_str()?;
    if pubkey != expected_pubkey {
        return None;
    }
    let created_at = ev.get("created_at")?.as_u64()?;
    let content = ev.get("content")?.as_str()?.to_string();
    let id_hex = ev.get("id")?.as_str()?;
    let sig_hex = ev.get("sig")?.as_str()?;
    let id = event_id(pubkey, created_at, &content);
    if hex::encode(id) != id_hex {
        return None;
    }
    let sig = secp256k1::schnorr::Signature::from_slice(&hex::decode(sig_hex).ok()?).ok()?;
    secp.verify_schnorr(&sig, &Message::from_digest(id), xonly).ok()?;
    Some((created_at, content))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_roundtrip_and_tamper() {
        let key = hex::encode([7u8; 32]);
        let k = content_key(&key).unwrap();
        let c = encrypt_address(&k, "https://abc.trycloudflare.com");
        assert_eq!(decrypt_address(&k, &c).as_deref(), Some("https://abc.trycloudflare.com"));
        // A different content key can't read it.
        let other = content_key(&hex::encode([9u8; 32])).unwrap();
        assert!(decrypt_address(&other, &c).is_none());
    }

    #[test]
    fn relay_host_port_parses() {
        assert_eq!(relay_host_port("wss://relay.damus.io"), Some(("relay.damus.io".into(), 443)));
        assert_eq!(relay_host_port("wss://example.com:7000/path"), Some(("example.com".into(), 7000)));
    }

    #[test]
    fn event_id_and_signature_verify_and_reject_tamper() {
        let secp = Secp256k1::new();
        let key = generate_beacon_key();
        let sk = SecretKey::from_slice(&hex::decode(&key.secret_hex).unwrap()).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let content = "ciphertext";
        let id = event_id(&key.pubkey_hex, 1000, content);
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(id), &kp);
        let xonly = XOnlyPublicKey::from_slice(&hex::decode(&key.pubkey_hex).unwrap()).unwrap();
        let vsecp = Secp256k1::verification_only();
        let ev = json!({ "pubkey": key.pubkey_hex, "created_at": 1000, "content": content,
                         "id": hex::encode(id), "sig": hex::encode(sig.as_ref() as &[u8]) });
        assert!(verify_event(&vsecp, &xonly, &key.pubkey_hex, &ev).is_some());
        // Tampered content → recomputed id mismatches → rejected.
        let mut bad = ev.clone();
        bad["content"] = json!("evil.com");
        assert!(verify_event(&vsecp, &xonly, &key.pubkey_hex, &bad).is_none());
    }
}
