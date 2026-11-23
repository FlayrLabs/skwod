//! Build 44a: devices, sessions and recovery — the server's half.

// Row-shaped tuples from sqlx look "complex" to clippy but are the idiomatic untyped-query form.
#![allow(clippy::type_complexity)]

use axum::http::StatusCode;
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use skwod_crypto::SignalStore;

use crate::state::{now_ms, AppState};
use crate::tests::{login, send, send_proved, signup, test_state};

pub(crate) fn b64(v: &[u8]) -> String {
    B64.encode(v)
}

fn key(k: &skwod_crypto::store::SignedPreKeyUpload) -> Value {
    json!({ "id": k.id, "public": b64(&k.public), "signature": b64(&k.signature) })
}

/// A registration (or rekey) body for `store` and the device-proof payload a rekey signs.
pub(crate) fn keys(store: &mut SignalStore) -> (Value, Vec<u8>) {
    let signed = store.generate_signed_prekey().unwrap();
    let last = store.generate_last_resort_kyber().unwrap();
    let kyber = |k: &skwod_crypto::store::KyberPreKeyUpload| json!({ "id": k.id, "public": b64(&k.public), "signature": b64(&k.signature) });
    let delivery = [9u8; 32];
    let empty = skwod_crypto::link::op_payload(&[]);
    let payload = skwod_crypto::link::op_payload(&[&store.registration_id().to_be_bytes(), &signed.public, &last.public, &delivery, &empty, &empty]);
    let body = json!({
        "protocol_version": 2,
        "registration_id": store.registration_id(),
        "identity_key": b64(&store.identity_key()),
        "signed_prekey": key(&signed),
        "last_resort_kyber_prekey": kyber(&last),
        "delivery_key": b64(&delivery),
        "install_hash": b64(&Sha256::digest(secret(store))),
    });
    let payload = skwod_crypto::link::op_payload(&[&payload, &Sha256::digest(secret(store))]);
    (body, payload)
}

/// The install secret of a test device: derived from its identity so helpers stay stateless.
pub(crate) fn secret(store: &SignalStore) -> [u8; 32] {
    Sha256::digest(store.identity_key()).into()
}

/// A bind request for `token` as `device`: (body, proof) signed by `signer` with `install` secret.
fn bind_req(signer: &SignalStore, install: &[u8; 32], user_id: &str, device: &str, token: &str) -> (Value, String) {
    let payload = skwod_crypto::link::op_payload(&[&Sha256::digest(token.as_bytes()), &Sha256::digest(install)]);
    (json!({ "install_secret": b64(install) }), proof(signer, "bind-session", user_id, device, &payload))
}

pub(crate) async fn bind(app: &Router, signer: &SignalStore, install: &[u8; 32], user_id: &str, device: &str, token: &str) -> (StatusCode, Value) {
    let (body, proof) = bind_req(signer, install, user_id, device, token);
    send_proved(app, "POST", &format!("/api/e2ee/devices/{device}/bind"), token, Some(body), &proof).await
}

pub(crate) fn proof(signer: &SignalStore, op: &str, user_id: &str, target: &str, payload: &[u8]) -> String {
    let ts = now_ms();
    format!("{ts}.{}", b64(&signer.sign_device_op(op, user_id, target, ts as u64, payload).unwrap()))
}

pub(crate) async fn register(app: &Router, token: &str, body: Value) -> String {
    let (status, body) = send(app, "POST", "/api/e2ee/devices/register", Some(token), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["device_id"].as_str().unwrap().to_string()
}

/// An account's first device, registered by its sign-up session.
pub(crate) async fn first_device(app: &Router, token: &str) -> (SignalStore, String) {
    let mut store = SignalStore::generate();
    let (body, _) = keys(&mut store);
    let device = register(app, token, body).await;
    (store, device)
}

/// A second device with a session of its own, linked the only way there is: it asks, the
/// linker's current install (`linker_token`) approves, it registers on that approval.
pub(crate) async fn linked_device(app: &Router, username: &str, user_id: &str, linker: &SignalStore, linker_dev: &str, linker_token: &str) -> (SignalStore, String, String) {
    let token = login(app, username).await;
    let mut store = SignalStore::generate();
    let sig = b64(&linker.sign_link(user_id, &store.identity_key()).unwrap());
    let request = json!({ "identity_key": b64(&store.identity_key()), "proof": b64(&[0u8; 32]) });
    let (_, created) = send(app, "POST", "/api/e2ee/link-requests", Some(&token), Some(request)).await;
    let approve = json!({ "device_id": linker_dev, "signature": sig, "approval_mac": b64(&[0u8; 32]) });
    let (status, body) = send(app, "POST", &format!("/api/e2ee/link-requests/{}/approve", created["request_id"].as_str().unwrap()), Some(linker_token), Some(approve)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (mut body, _) = keys(&mut store);
    body["link"] = json!({ "device_id": linker_dev, "signature": sig });
    let device = register(app, &token, body).await;
    (store, device, token)
}

pub(crate) async fn space(app: &Router, owner: &str) -> (String, String) {
    let (_, s) = send(app, "POST", "/api/servers", Some(owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
    let server = s["server_id"].as_str().unwrap().to_string();
    let (_, c) = send(app, "POST", &format!("/api/servers/{server}/channels"), Some(owner), Some(json!({ "name_ciphertext": b64(b"c"), "type": "text" }))).await;
    (server, c["channel_id"].as_str().unwrap().to_string())
}

pub(crate) async fn post_as(app: &Router, token: &str, channel: &str, device: &str) -> (StatusCode, Value) {
    let body = json!({ "ciphertext": b64(b"ct"), "author_device_id": device });
    send(app, "POST", &format!("/api/channels/{channel}/messages"), Some(token), Some(body)).await
}

pub(crate) async fn devices(app: &Router, token: &str) -> Value {
    send(app, "GET", "/api/e2ee/devices", Some(token), None).await.1
}

pub(crate) async fn app() -> (Router, AppState) {
    let state = test_state().await;
    (crate::api::router(state.clone()), state)
}

#[tokio::test]
async fn a_session_speaks_for_the_device_it_registered_and_the_list_says_so() {
    let (app, _state) = app().await;
    let (user_id, phone_token) = signup(&app, "alice").await;
    let (phone, phone_dev) = first_device(&app, &phone_token).await;
    let (_mac, mac_dev, mac_token) = linked_device(&app, "alice", &user_id, &phone, &phone_dev, &phone_token).await;

    let listing = devices(&app, &phone_token).await;
    assert_eq!(listing["max_devices"], 5, "the limit is shown");
    let current: Vec<(&str, bool)> = listing["devices"].as_array().unwrap().iter().map(|d| (d["device_id"].as_str().unwrap(), d["current"].as_bool().unwrap())).collect();
    assert_eq!(current, [(phone_dev.as_str(), true), (mac_dev.as_str(), false)], "\"this device\" follows the session");
    assert_eq!(devices(&app, &mac_token).await["devices"][1]["current"], true);

    // A bound session cannot act as another device of the account…
    let cert = |token: String, device: String| {
        let app = app.clone();
        async move { send(&app, "POST", "/api/e2ee/certificates", Some(&token), Some(json!({ "device_id": device }))).await.0 }
    };
    assert_eq!(cert(phone_token.clone(), phone_dev.clone()).await, StatusCode::OK);
    assert_eq!(cert(phone_token.clone(), mac_dev.clone()).await, StatusCode::FORBIDDEN);
    let (status, _) = send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={mac_dev}"), Some(&phone_token), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // …and only a device names itself.
    let name = json!({ "device_name_ciphertext": b64(b"sealed name") });
    let (status, _) = send(&app, "PUT", &format!("/api/e2ee/devices/{mac_dev}/name"), Some(&phone_token), Some(name.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&app, "PUT", &format!("/api/e2ee/devices/{mac_dev}/name"), Some(&mac_token), Some(name)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(devices(&app, &phone_token).await["devices"][1]["device_name_ciphertext"], b64(b"sealed name"));
}

#[tokio::test]
async fn a_removed_device_is_signed_out_announced_and_cannot_post() {
    let (app, state) = app().await;
    let (user_id, phone_token) = signup(&app, "alice").await;
    let (phone, phone_dev) = first_device(&app, &phone_token).await;
    let (mac, mac_dev, mac_token) = linked_device(&app, "alice", &user_id, &phone, &phone_dev, &phone_token).await;
    let (server, channel) = space(&app, &phone_token).await;
    assert_eq!(post_as(&app, &mac_token, &channel, &mac_dev).await.0, StatusCode::OK, "while it is on the account it posts");

    // Removing it takes a device signature; the session token alone is refused.
    let path = format!("/api/e2ee/devices/{mac_dev}");
    assert_eq!(send(&app, "DELETE", &path, Some(&phone_token), None).await.0, StatusCode::FORBIDDEN);
    let mut bus = state.rt.subscribe();
    let (status, _) = send_proved(&app, "DELETE", &path, &phone_token, None, &proof(&phone, "delete", &user_id, &mac_dev, b"")).await;
    assert_eq!(status, StatusCode::OK);

    // Its sessions are over…
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&mac_token), None).await.0, StatusCode::UNAUTHORIZED);
    // …everyone who may hold its keys is told (own devices and the servers it is in)…
    let mut topics = Vec::new();
    while let Ok(ev) = bus.try_recv() {
        let frame: Value = serde_json::from_str(&ev.frame).unwrap();
        if frame["event"] == "device_removed" {
            assert_eq!((frame["payload"]["user_id"].as_str(), frame["payload"]["device_id"].as_str()), (Some(user_id.as_str()), Some(mac_dev.as_str())));
            topics.push(ev.topic);
        }
    }
    assert!(topics.contains(&crate::rt::user_topic(&user_id)) && topics.contains(&crate::rt::server_topic(&server)), "{topics:?}");
    // …and signing in again does not bring it back: it cannot post, fetch mail, get a
    // certificate or bind the new session, even though it still holds its identity key.
    let again = login(&app, "alice").await;
    let (status, body) = post_as(&app, &again, &channel, &mac_dev).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")));
    let (status, _) = send(&app, "POST", "/api/e2ee/certificates", Some(&again), Some(json!({ "device_id": mac_dev }))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = bind(&app, &mac, &secret(&mac), &user_id, &mac_dev, &again).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")));
    // Nor can it remove the device that removed it (its key is no longer on the account).
    let (status, _) = send_proved(&app, "DELETE", &format!("/api/e2ee/devices/{phone_dev}"), &again, None, &proof(&mac, "delete", &user_id, &phone_dev, b"")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The remaining device carries on.
    assert_eq!(post_as(&app, &phone_token, &channel, &phone_dev).await.0, StatusCode::OK);
}

#[tokio::test]
async fn posts_and_edits_must_name_a_registered_device_of_the_author() {
    let (app, _state) = app().await;
    let (alice_id, alice) = signup(&app, "alice").await;
    let (phone, phone_dev) = first_device(&app, &alice).await;
    let (_, bob) = signup(&app, "bobby").await;
    let (_bob_store, bob_dev) = first_device(&app, &bob).await;
    let (_, channel) = space(&app, &alice).await;

    let (status, posted) = post_as(&app, &alice, &channel, &phone_dev).await;
    assert_eq!(status, StatusCode::OK);
    let message = posted["message_id"].as_str().unwrap();
    // A made-up device, and somebody else's device, are both "not a device of the author".
    for device in ["made-up", bob_dev.as_str()] {
        let (status, body) = post_as(&app, &alice, &channel, device).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")), "{device}");
        let edit = json!({ "ciphertext": b64(b"edit"), "author_device_id": device });
        assert_eq!(send(&app, "PATCH", &format!("/api/messages/{message}"), Some(&alice), Some(edit)).await.0, StatusCode::FORBIDDEN, "{device}");
    }
    // A second device of the author, speaking through ITS session, may edit; the first
    // device's session may not post in its name.
    let (_mac, mac_dev, mac_token) = linked_device(&app, "alice", &alice_id, &phone, &phone_dev, &alice).await;
    let edit = json!({ "ciphertext": b64(b"edit"), "author_device_id": mac_dev });
    assert_eq!(send(&app, "PATCH", &format!("/api/messages/{message}"), Some(&mac_token), Some(edit.clone())).await.0, StatusCode::OK);
    assert_eq!(send(&app, "PATCH", &format!("/api/messages/{message}"), Some(&alice), Some(edit)).await.0, StatusCode::FORBIDDEN);
    assert_eq!(post_as(&app, &alice, &channel, &mac_dev).await.0, StatusCode::FORBIDDEN);
    // A session that speaks for a device has to say which device sealed the message.
    let (status, _) = send(&app, "POST", &format!("/api/channels/{channel}/messages"), Some(&alice), Some(json!({ "ciphertext": b64(b"ct") }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn signing_back_in_binds_the_same_device_without_a_link() {
    let (app, _state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (phone, phone_dev) = first_device(&app, &token).await;
    let (mac, mac_dev, _mac_token) = linked_device(&app, "alice", &user_id, &phone, &phone_dev, &token).await;

    // "Sign out" drops the session and nothing else.
    assert_eq!(send(&app, "POST", "/api/auth/logout", Some(&token), None).await.0, StatusCode::OK);
    assert_eq!(devices(&app, &login(&app, "alice").await).await["devices"].as_array().unwrap().len(), 2, "the device row stays");

    // "Sign back in": a new session, bound to the SAME device by that device's own signature
    // over this session — no link request, no new device row.
    let again = login(&app, "alice").await;
    assert!(devices(&app, &again).await["devices"].as_array().unwrap().iter().all(|d| d["current"] == false), "a fresh session speaks for no device yet");
    let path = format!("/api/e2ee/devices/{phone_dev}/bind");
    let (body, good) = bind_req(&phone, &secret(&phone), &user_id, &phone_dev, &again);
    assert_eq!(send(&app, "POST", &path, Some(&again), Some(body.clone())).await.0, StatusCode::FORBIDDEN, "not on the token alone");
    // Until it has bound, the session cannot act as the device at all (fail closed).
    let (status, err) = send(&app, "POST", "/api/e2ee/certificates", Some(&again), Some(json!({ "device_id": phone_dev }))).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::FORBIDDEN, Some("device bind required")));
    // A sibling cannot bind a session as this device; a proof for another session is no use;
    // nor is the right signature with the wrong (or no) install secret.
    assert_eq!(bind(&app, &mac, &secret(&phone), &user_id, &phone_dev, &again).await.0, StatusCode::FORBIDDEN);
    let (_, other_session) = bind_req(&phone, &secret(&phone), &user_id, &phone_dev, "another session");
    assert_eq!(send_proved(&app, "POST", &path, &again, Some(body.clone()), &other_session).await.0, StatusCode::FORBIDDEN);
    assert_eq!(bind(&app, &phone, &[1u8; 32], &user_id, &phone_dev, &again).await.0, StatusCode::CONFLICT);
    let no_secret = proof(&phone, "bind-session", &user_id, &phone_dev, &skwod_crypto::link::op_payload(&[&Sha256::digest(again.as_bytes()), b""]));
    assert_eq!(send_proved(&app, "POST", &path, &again, Some(json!({})), &no_secret).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send_proved(&app, "POST", &path, &again, Some(body), &good).await.0, StatusCode::OK);
    let listing = devices(&app, &again).await;
    assert_eq!(listing["devices"].as_array().unwrap().len(), 2);
    assert_eq!((listing["devices"][0]["device_id"].as_str(), listing["devices"][0]["current"].as_bool()), (Some(phone_dev.as_str()), Some(true)));
    assert_eq!(send(&app, "POST", "/api/e2ee/certificates", Some(&again), Some(json!({ "device_id": mac_dev }))).await.0, StatusCode::FORBIDDEN, "and for that device only");
    // A rotated token keeps the binding.
    let (_, rotated) = send(&app, "POST", "/api/auth/rotate", Some(&again), None).await;
    assert_eq!(devices(&app, rotated["token"].as_str().unwrap()).await["devices"][0]["current"], true);
}

/// Every device-scoped route, tried by `token` as `device`: (route, status).
async fn every_route(app: &Router, token: &str, device: &str, channel: &str, message: &str) -> Vec<(&'static str, StatusCode)> {
    let d = json!({ "device_id": device });
    let mut out = Vec::new();
    for (name, method, path, body) in [
        ("inbox", "GET", format!("/api/e2ee/sealed/inbox?device_id={device}"), None),
        // A client-supplied generation is not a thing: claiming the new one changes nothing.
        ("inbox claiming a generation", "GET", format!("/api/e2ee/sealed/inbox?device_id={device}&generation=1"), None),
        ("ack", "POST", "/api/e2ee/sealed/ack".to_string(), Some(json!({ "device_id": device, "ids": [] }))),
        ("certificate", "POST", "/api/e2ee/certificates".to_string(), Some(d.clone())),
        ("certificate claiming a generation", "POST", "/api/e2ee/certificates".to_string(), Some(json!({ "device_id": device, "generation": 1 }))),
        ("prekey count", "GET", format!("/api/e2ee/prekeys/count?device_id={device}"), None),
        ("replenish", "POST", "/api/e2ee/prekeys/replenish".to_string(), Some(d.clone())),
        ("spk rotate", "POST", "/api/e2ee/spk/rotate".to_string(), Some(json!({ "device_id": device, "signed_prekey": { "id": 1, "public": "", "signature": "" } }))),
        ("delivery key", "PUT", format!("/api/e2ee/devices/{device}/delivery-key"), Some(json!({ "delivery_key": b64(&[1u8; 32]) }))),
        ("name", "PUT", format!("/api/e2ee/devices/{device}/name"), Some(json!({ "device_name_ciphertext": null }))),
        ("link approval", "POST", "/api/e2ee/link-requests/none/approve".to_string(), Some(json!({ "device_id": device, "signature": "", "approval_mac": "" }))),
        ("post", "POST", format!("/api/channels/{channel}/messages"), Some(json!({ "ciphertext": b64(b"ct"), "author_device_id": device, "author_device_generation": 1 }))),
        ("edit", "PATCH", format!("/api/messages/{message}"), Some(json!({ "ciphertext": b64(b"ct"), "author_device_id": device }))),
    ] {
        out.push((name, send(app, method, &path, Some(token), body).await.0));
    }
    out
}

/// A rekey request for `device` by `store` (an install holding `install`), on `token`.
pub(crate) async fn rekey(app: &Router, token: &str, store: &mut SignalStore, install: &[u8; 32], user_id: &str, device: &str, pin: Option<&str>) -> (StatusCode, Value) {
    let (mut body, _) = keys(store);
    let hash = Sha256::digest(install);
    body["install_hash"] = json!(b64(&hash));
    body["install_secret"] = json!(b64(install));
    if let Some(pin) = pin {
        body["pin"] = json!(pin);
    }
    let empty = skwod_crypto::link::op_payload(&[]);
    let unb = |v: &Value| B64.decode(v.as_str().unwrap()).unwrap();
    let inner = skwod_crypto::link::op_payload(&[
        &store.registration_id().to_be_bytes(),
        &unb(&body["signed_prekey"]["public"]),
        &unb(&body["last_resort_kyber_prekey"]["public"]),
        &[9u8; 32],
        &empty,
        &empty,
    ]);
    let payload = skwod_crypto::link::op_payload(&[&inner, &hash]);
    send_proved(app, "POST", &format!("/api/e2ee/devices/{device}/rekey"), token, Some(body), &proof(store, "rekey", user_id, device, &payload)).await
}

/// The server-issued id of the pending recovery of `device` (what approvals sign).
async fn request_id(app: &Router, token: &str, device: &str) -> String {
    let listing = devices(app, token).await;
    let pending = listing["recoveries"].as_array().unwrap().iter().find(|r| r["device_id"] == device).expect("a pending recovery");
    assert!(pending.get("install_hash").is_none(), "the hash is never handed out");
    pending["request_id"].as_str().unwrap().to_string()
}

/// The anti-clone rule, end to end. Someone holds a copy of the device's identity key (and a
/// session for the account) but not the live install's secret. They cannot bind, re-key, delete
/// devices or touch the account's recovery settings; a re-key they ask for is only a recovery
/// REQUEST, which the live device sees and cancels.
#[tokio::test]
async fn a_copy_of_the_identity_key_alone_gets_nowhere() {
    let (app, state) = app().await;
    let (user_id, live_token) = signup(&app, "alice").await;
    let (live, device) = first_device(&app, &live_token).await;
    let (sibling, sibling_dev, _sibling_token) = linked_device(&app, "alice", &user_id, &live, &device, &live_token).await;
    let (_, channel) = space(&app, &live_token).await;
    let message = post_as(&app, &live_token, &channel, &device).await.1["message_id"].as_str().unwrap().to_string();

    // The thief: the identity key (say, out of a stolen backup file) and a session.
    let mut copy = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let thief = login(&app, "alice").await;
    for (route, status) in every_route(&app, &thief, &device, &channel, &message).await {
        assert_ne!(status, StatusCode::OK, "{route}");
    }
    // Bind: the signature verifies, the secret does not exist on their side.
    assert_eq!(bind(&app, &copy, &[7u8; 32], &user_id, &device, &thief).await.0, StatusCode::CONFLICT);
    // The proof-only routes of build 43 — valid signatures, every one refused: the session is
    // not the signing device's current install. Their own device's routes and a sibling's alike.
    let signer = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let signed = |op: &str, target: &str, payload: &[u8]| proof(&signer, op, &user_id, target, payload);
    for (name, method, path, body, p) in [
        ("delete own", "DELETE", format!("/api/e2ee/devices/{device}"), None, signed("delete", &device, b"")),
        ("delete sibling", "DELETE", format!("/api/e2ee/devices/{sibling_dev}"), None, signed("delete", &sibling_dev, b"")),
        ("cancel reset", "POST", "/api/e2ee/devices/reset/cancel".to_string(), Some(json!({ "device_id": device })), signed("cancel-reset", &device, b"")),
        ("set pin", "POST", "/api/e2ee/registration-pin".to_string(), Some(json!({ "enable": true, "pin": "135790" })), signed("set-pin", "enable", b"135790")),
        ("backup delete", "DELETE", "/api/e2ee/key-backup".to_string(), None, signed("backup-delete", "backup", b"")),
        ("delivery key", "PUT", format!("/api/e2ee/devices/{device}/delivery-key"), Some(json!({ "delivery_key": b64(&[1u8; 32]) })), signed("delivery-key", &device, &[1u8; 32])),
        ("password", "POST", "/api/auth/password".to_string(), Some(json!({ "old_password": "correct horse", "new_password": "thief's password" })), signed("password", "", b"thief's password")),
    ] {
        let (status, body) = send_proved(&app, method, &path, &thief, body, &p).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{name}: {body}");
    }
    let backup = json!({ "encrypted_blob": b64(b"blob"), "salt": b64(&[0u8; 16]), "version": 3, "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 } });
    let p = signed("backup-put", "backup", &crate::keydir::backup_payload(b"blob", &[0u8; 16], 3, &backup["kdf_params"]));
    assert_eq!(send_proved(&app, "PUT", "/api/e2ee/key-backup", &thief, Some(backup), &p).await.0, StatusCode::FORBIDDEN, "backup put");
    assert_eq!(devices(&app, &live_token).await["devices"].as_array().unwrap().len(), 2, "nothing was removed");

    // Re-key: recorded as a recovery request, nothing changes, and the account's devices are told.
    let mut bus = state.rt.subscribe();
    let (status, body) = rekey(&app, &thief, &mut copy, &[7u8; 32], &user_id, &device, None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{body}");
    assert!(body["completes_at"].as_i64().unwrap() >= now_ms() + 6 * 24 * 3_600_000, "a 7-day hold");
    let told = std::iter::from_fn(|| bus.try_recv().ok()).any(|ev| ev.topic == crate::rt::user_topic(&user_id) && ev.frame.contains("device_recovery_requested"));
    assert!(told, "current devices hear about it");
    let listing = devices(&app, &live_token).await;
    assert_eq!((listing["devices"][0]["generation"].as_i64(), listing["recoveries"][0]["device_id"].as_str()), (Some(0), Some(device.as_str())));
    assert_eq!(rekey(&app, &thief, &mut copy, &[7u8; 32], &user_id, &device, None).await.0, StatusCode::FORBIDDEN, "asking again does not shorten it");
    // They cannot approve their own request (no current install behind the signature)…
    let id = request_id(&app, &thief, &device).await;
    let approve = format!("/api/e2ee/devices/{device}/recovery/approve");
    assert_eq!(send_proved(&app, "POST", &approve, &thief, Some(json!({ "request_id": id })), &signed("approve-recovery", &device, id.as_bytes())).await.0, StatusCode::FORBIDDEN);
    // …and a current device — here the sibling's key on the LIVE device's session is no good
    // either; the live device itself cancels.
    let cancel = format!("/api/e2ee/devices/{device}/recovery/cancel");
    assert_eq!(send_proved(&app, "POST", &cancel, &live_token, Some(json!({ "request_id": id })), &proof(&sibling, "cancel-recovery", &user_id, &device, id.as_bytes())).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send_proved(&app, "POST", &cancel, &live_token, Some(json!({ "request_id": id })), &proof(&live, "cancel-recovery", &user_id, &device, id.as_bytes())).await.0, StatusCode::OK);
    assert!(devices(&app, &live_token).await["recoveries"].as_array().unwrap().is_empty());
    // Even after "waiting", a cancelled request is gone: it starts over as a new one.
    assert_eq!(rekey(&app, &thief, &mut copy, &[7u8; 32], &user_id, &device, None).await.1["error"], "device recovery pending");
    // The live install was never disturbed.
    assert_eq!(post_as(&app, &live_token, &channel, &device).await.0, StatusCode::OK);
}

/// A re-key body for `device` that presents `install_hash` and whatever `secret` the caller
/// can come up with — everything else valid, the proof included.
async fn rekey_claiming(app: &Router, token: &str, store: &mut SignalStore, install_hash: &[u8], secret: Option<&[u8]>, user_id: &str, device: &str) -> (StatusCode, Value) {
    let (mut body, _) = keys(store);
    body["install_hash"] = json!(b64(install_hash));
    match secret {
        Some(secret) => body["install_secret"] = json!(b64(secret)),
        None => {
            body.as_object_mut().unwrap().remove("install_secret");
        }
    }
    let empty = skwod_crypto::link::op_payload(&[]);
    let unb = |v: &Value| B64.decode(v.as_str().unwrap()).unwrap();
    let inner = skwod_crypto::link::op_payload(&[&store.registration_id().to_be_bytes(), &unb(&body["signed_prekey"]["public"]), &unb(&body["last_resort_kyber_prekey"]["public"]), &[9u8; 32], &empty, &empty]);
    let payload = skwod_crypto::link::op_payload(&[&inner, install_hash]);
    send_proved(app, "POST", &format!("/api/e2ee/devices/{device}/rekey"), token, Some(body), &proof(store, "rekey", user_id, device, &payload)).await
}

/// Someone else's pending recovery cannot be taken over. A legitimate restore is waiting; the
/// attacker — a session of the account and a copy of the same identity key, i.e. everything
/// but the restoring install's secret — learns the install hash anyway (from the wire, a log,
/// a database dump). After the request is approved, and after the hold has run out, presenting
/// that hash still completes nothing: completion takes the secret. And no response hands the
/// hash out in the first place.
#[tokio::test]
async fn knowing_the_install_hash_of_a_pending_recovery_completes_nothing() {
    let (app, state) = app().await;
    let (user_id, original_token) = signup(&app, "alice").await;
    let (original, device) = first_device(&app, &original_token).await;
    let (sibling, _sibling_dev, sibling_token) = linked_device(&app, "alice", &user_id, &original, &device, &original_token).await;

    // The legitimate restore asks.
    let restorer = login(&app, "alice").await;
    let mut restored = SignalStore::from_bytes(&original.export_identity()).unwrap();
    let secret = [42u8; 32];
    let hash = Sha256::digest(secret).to_vec();
    let (status, body) = rekey(&app, &restorer, &mut restored, &secret, &user_id, &device, None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")));
    assert!(!body.to_string().contains(&b64(&hash)), "the answer does not echo the hash");

    // Nothing any session of the account can read contains it.
    let attacker = login(&app, "alice").await;
    for token in [&attacker, &restorer, &sibling_token, &original_token] {
        let listing = devices(&app, token).await;
        assert_eq!(listing["recoveries"].as_array().unwrap().len(), 1);
        assert!(!listing.to_string().contains(&b64(&hash)) && !listing.to_string().contains("install_hash"), "{listing}");
    }
    let id = request_id(&app, &attacker, &device).await;

    // The attacker knows the hash all the same. Before any approval:
    let mut copy = SignalStore::from_bytes(&original.export_identity()).unwrap();
    // (Re-keys are rate-limited per account, so each phase tries the two that matter.)
    let attempts: [(&str, Option<Vec<u8>>); 2] = [("the hash as the secret", Some(hash.clone())), ("a made-up secret", Some(vec![7u8; 32]))];
    let (status, body) = rekey_claiming(&app, &attacker, &mut copy, &hash, None, &user_id, &device).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::BAD_REQUEST, Some("install_secret required")));
    let try_all = |when: &'static str, copy: &mut SignalStore| {
        let (app, attacker, hash, user_id, device) = (app.clone(), attacker.clone(), hash.clone(), user_id.clone(), device.clone());
        let attempts = attempts.clone();
        let mut copy = SignalStore::from_bytes(&copy.to_bytes()).unwrap();
        async move {
            for (what, secret) in attempts {
                let (status, body) = rekey_claiming(&app, &attacker, &mut copy, &hash, secret.as_deref(), &user_id, &device).await;
                assert!(status == StatusCode::FORBIDDEN || status == StatusCode::BAD_REQUEST, "{when} / {what}: {status} {body}");
                assert_ne!(body["error"], "device recovery pending", "{when} / {what}: it did not even count as the request");
            }
        }
    };
    try_all("pending", &mut copy).await;

    // A current device approves the legitimate request. The approval is now on record for
    // that hash — and still only the secret's holder can use it.
    let approve = proof(&sibling, "approve-recovery", &user_id, &device, id.as_bytes());
    assert_eq!(send_proved(&app, "POST", &format!("/api/e2ee/devices/{device}/recovery/approve"), &sibling_token, Some(json!({ "request_id": id })), &approve).await.0, StatusCode::OK);
    try_all("approved", &mut copy).await;
    // Nor after the hold has run out.
    sqlx::query("UPDATE device_recoveries SET requested_at = requested_at - $1").bind(crate::keydir::RESET_DELAY_MS + 1000).execute(&state.db).await.unwrap();
    try_all("after the hold", &mut copy).await;
    // Through all of that the device did not move, and the request is still the restorer's.
    let listing = devices(&app, &original_token).await;
    assert_eq!((listing["devices"][0]["generation"].as_i64(), listing["recoveries"][0]["approved"].as_bool()), (Some(0), Some(true)));
    assert_eq!(send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={device}"), Some(&original_token), None).await.0, StatusCode::OK);

    // The install that holds the secret completes it.
    let (status, body) = rekey(&app, &restorer, &mut restored, &secret, &user_id, &device, None).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");
    assert_eq!(bind(&app, &copy, &hash.clone().try_into().unwrap(), &user_id, &device, &attacker).await.0, StatusCode::CONFLICT, "and the hash does not bind a session either");
}

/// A registration without an install secret is refused outright (rule 5).
#[tokio::test]
async fn a_registration_without_an_install_hash_is_refused() {
    let (app, _state) = app().await;
    let (_, token) = signup(&app, "alice").await;
    let mut store = SignalStore::generate();
    let (mut body, _) = keys(&mut store);
    body.as_object_mut().unwrap().remove("install_hash");
    let (status, err) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(body.clone())).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::BAD_REQUEST, Some("install_hash required")));
    body["install_hash"] = json!(b64(&[0u8; 5]));
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(body)).await.0, StatusCode::BAD_REQUEST);
    assert!(devices(&app, &token).await["devices"].as_array().unwrap().is_empty());
}

/// The waiting screen asks again every 15 s. However long the install has been waiting, the
/// approval that finally comes completes the restore on the next ask.
#[tokio::test]
async fn a_restore_that_waited_a_long_time_still_completes_when_it_is_approved() {
    let (app, _state) = app().await;
    let (user_id, original_token) = signup(&app, "alice").await;
    let (original, device) = first_device(&app, &original_token).await;
    let restored_token = login(&app, "alice").await;
    let mut restored = SignalStore::from_bytes(&original.export_identity()).unwrap();
    let new_secret = [42u8; 32];
    // Ten minutes of the waiting screen.
    for _ in 0..40 {
        let (status, body) = rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")));
    }
    // The device being moved is the account's only one: it approves its own move.
    let id = request_id(&app, &original_token, &device).await;
    let approve = format!("/api/e2ee/devices/{device}/recovery/approve");
    let right = proof(&original, "approve-recovery", &user_id, &device, id.as_bytes());
    assert_eq!(send_proved(&app, "POST", &approve, &original_token, Some(json!({ "request_id": id })), &right).await.0, StatusCode::OK);
    let (status, body) = rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, None).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");
}

/// The legitimate restore. It is a recovery too — the restoring install has the identity (from
/// the backup) but not the old install's secret — and completes by any of the three ways. When
/// it does, the install it was restored from is superseded on EVERY device-scoped route,
/// whatever it sends, and cannot bind back in.
#[tokio::test]
async fn a_restore_completes_by_approval_pin_or_hold_and_supersedes_the_old_install() {
    for way in ["approval", "pin", "hold"] {
        let (app, state) = app().await;
        let (user_id, original_token) = signup(&app, "alice").await;
        let (original, device) = first_device(&app, &original_token).await;
        let (sibling, sibling_dev, sibling_token) = linked_device(&app, "alice", &user_id, &original, &device, &original_token).await;
        let (_, channel) = space(&app, &original_token).await;
        let message = post_as(&app, &original_token, &channel, &device).await.1["message_id"].as_str().unwrap().to_string();
        if way == "pin" {
            let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &original_token, Some(json!({ "enable": true, "pin": "482913" })), &proof(&original, "set-pin", &user_id, "enable", b"482913")).await;
            assert_eq!(status, StatusCode::OK);
        }

        let restored_token = login(&app, "alice").await;
        let mut restored = SignalStore::from_bytes(&original.export_identity()).unwrap();
        let new_secret = [42u8; 32];
        let (status, body) = match way {
            "pin" => {
                // Only a PIN that has been in place for the hold period waives it (audit M4).
                sqlx::query("UPDATE e2ee_accounts SET pin_set_at = pin_set_at - $1 WHERE user_id = $2").bind(crate::keydir::RESET_DELAY_MS + 1000).bind(&user_id).execute(&state.db).await.unwrap();
                let (status, body) = rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, Some("000000")).await;
                assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("registration pin incorrect")), "{way}");
                rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, Some("482913")).await
            }
            _ => {
                let (status, body) = rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, None).await;
                assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{way}");
                if way == "approval" {
                    // Another current device of the account says yes — to THIS request.
                    let approve = format!("/api/e2ee/devices/{device}/recovery/approve");
                    let id = request_id(&app, &sibling_token, &device).await;
                    let wrong = proof(&sibling, "approve-recovery", &user_id, &device, b"some other request");
                    assert_eq!(send_proved(&app, "POST", &approve, &sibling_token, Some(json!({ "request_id": id })), &wrong).await.0, StatusCode::FORBIDDEN);
                    // (Signing the install hash — what build-44's first cut did — approves nothing.)
                    let by_hash = proof(&sibling, "approve-recovery", &user_id, &device, &Sha256::digest(new_secret));
                    assert_eq!(send_proved(&app, "POST", &approve, &sibling_token, Some(json!({ "request_id": id })), &by_hash).await.0, StatusCode::FORBIDDEN);
                    let right = proof(&sibling, "approve-recovery", &user_id, &device, id.as_bytes());
                    assert_eq!(send_proved(&app, "POST", &approve, &sibling_token, Some(json!({ "request_id": id })), &right).await.0, StatusCode::OK);
                    // Approved: nothing files beside it now — another install asking (anyone
                    // with the password) is refused, and the approval stands (audit L1).
                    let (status, body) = rekey(&app, &restored_token, &mut restored, &[1u8; 32], &user_id, &device, None).await;
                    assert_eq!((status, body["error"].as_str()), (StatusCode::CONFLICT, Some(crate::keydir::RECOVERY_REQUEST_TAKEN)), "{way}");
                    assert_eq!(request_id(&app, &sibling_token, &device).await, id, "{way}: the request on record is the one approved");
                } else {
                    sqlx::query("UPDATE device_recoveries SET requested_at = requested_at - $1 WHERE user_id = $2")
                        .bind(crate::keydir::RESET_DELAY_MS + 1000)
                        .bind(&user_id)
                        .execute(&state.db)
                        .await
                        .unwrap();
                }
                rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, None).await
            }
        };
        assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{way}: {body}");
        let listing = devices(&app, &restored_token).await;
        assert_eq!((listing["devices"][0]["generation"].as_i64(), listing["devices"][0]["current"].as_bool()), (Some(1), Some(true)), "{way}");
        assert!(listing["recoveries"].as_array().unwrap().is_empty());

        // The original is NOT signed out (so it can be told why it stopped)…
        assert_eq!(send(&app, "GET", "/api/auth/me", Some(&original_token), None).await.0, StatusCode::OK);
        // …but its session was bound at generation 0, and that is what the server goes by —
        // whether the request says nothing about generations or claims the new one.
        for (route, status) in every_route(&app, &original_token, &device, &channel, &message).await {
            assert_eq!(status, StatusCode::CONFLICT, "{way} / {route}: the superseded install is refused");
        }
        let (status, body) = send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={device}"), Some(&original_token), None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::CONFLICT, Some("device superseded")));
        // Its signatures still verify, and still authorize nothing — not against a sibling either.
        let (status, _) = send_proved(&app, "DELETE", &format!("/api/e2ee/devices/{sibling_dev}"), &original_token, None, &proof(&original, "delete", &user_id, &sibling_dev, b"")).await;
        assert_eq!(status, StatusCode::CONFLICT, "{way}");
        // A fresh sign-in on the old install: unbound, so nothing; and it cannot bind — with
        // its old secret, a made-up one, or none.
        let clone_token = login(&app, "alice").await;
        for (route, status) in every_route(&app, &clone_token, &device, &channel, &message).await {
            assert_eq!(status, StatusCode::FORBIDDEN, "{way} / {route}");
        }
        assert_eq!(bind(&app, &original, &secret(&original), &user_id, &device, &clone_token).await.0, StatusCode::CONFLICT);
        assert_eq!(bind(&app, &original, &[7u8; 32], &user_id, &device, &clone_token).await.0, StatusCode::CONFLICT);
        let bare = proof(&original, "bind-session", &user_id, &device, &skwod_crypto::link::op_payload(&[&Sha256::digest(clone_token.as_bytes()), b""]));
        assert_eq!(send_proved(&app, "POST", &format!("/api/e2ee/devices/{device}/bind"), &clone_token, Some(json!({ "generation": 1 })), &bare).await.0, StatusCode::BAD_REQUEST);
        for (route, status) in every_route(&app, &clone_token, &device, &channel, &message).await {
            assert_ne!(status, StatusCode::OK, "{way} / {route}");
        }

        // The restored install carries on, and a later sign-in on it binds with the new secret.
        assert_eq!(send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={device}"), Some(&restored_token), None).await.0, StatusCode::OK);
        assert_eq!(post_as(&app, &restored_token, &channel, &device).await.0, StatusCode::OK);
        let later = login(&app, "alice").await;
        assert_eq!(bind(&app, &restored, &new_secret, &user_id, &device, &later).await.0, StatusCode::OK);
        assert_eq!(post_as(&app, &later, &channel, &device).await.0, StatusCode::OK);
    }
}

/// A device row from before install secrets, as the migration leaves it.
async fn legacy_device(state: &AppState, user_id: &str, store: &SignalStore) {
    sqlx::query(
        &crate::tests::pg("INSERT INTO user_devices (id, user_id, device_id, protocol_version, registration_id, identity_key, signed_prekey_id, signed_prekey,
             signed_prekey_sig, kyber_last_resort_id, kyber_last_resort, kyber_last_resort_sig, delivery_key, legacy_unbound)
         VALUES ('row', $1, 'old-device', 2, 1, $2, 1, x'00', x'00', 1, x'00', x'00', x'00', 1)"),
    )
    .bind(user_id)
    .bind(store.identity_key())
    .execute(&state.db)
    .await
    .unwrap();
}

/// A device registered before install secrets existed keeps working on the session it already
/// had, and that session — only that one — binds it, once.
#[tokio::test]
async fn a_pre_existing_device_migrates_by_binding_once_from_its_pre_migration_session() {
    let (app, state) = app().await;
    let (user_id, old_session) = signup(&app, "alice").await;
    let old = SignalStore::generate();
    legacy_device(&state, &user_id, &old).await;
    // What the migration does to the sessions that exist when it runs.
    sqlx::query("UPDATE sessions SET pre_migration = 1").execute(&state.db).await.unwrap();
    let inbox = "/api/e2ee/sealed/inbox?device_id=old-device";
    assert_eq!(send(&app, "GET", inbox, Some(&old_session), None).await.0, StatusCode::OK, "a build-43 client is not locked out by the upgrade");

    // A sign-in made AFTER the migration reads the legacy device's traffic like any build-43
    // client could — but it can neither claim the row nor do anything that needs authority.
    let newcomer = login(&app, "alice").await;
    assert_eq!(bind(&app, &old, &[6u8; 32], &user_id, "old-device", &newcomer).await.0, StatusCode::CONFLICT, "a new login cannot claim a legacy row");
    let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/devices/old-device", &newcomer, None, &proof(&old, "delete", &user_id, "old-device", b"")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "an unbound session is never enough for a mutation");
    let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &newcomer, Some(json!({ "enable": true, "pin": "135790" })), &proof(&old, "set-pin", &user_id, "enable", b"135790")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // …not from the pre-migration session either, until it has bound.
    let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/devices/old-device", &old_session, None, &proof(&old, "delete", &user_id, "old-device", b"")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A re-key from the unbound newcomer is a recovery request, not a re-key.
    let mut copy = SignalStore::from_bytes(&old.export_identity()).unwrap();
    let (status, body) = rekey(&app, &newcomer, &mut copy, &[6u8; 32], &user_id, "old-device", None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")));

    // The pre-migration session binds: the secret is recorded, the flag cleared.
    assert_eq!(bind(&app, &old, &[5u8; 32], &user_id, "old-device", &old_session).await.0, StatusCode::OK, "first bind records the secret");
    assert_eq!(send(&app, "GET", inbox, Some(&old_session), None).await.0, StatusCode::OK);
    let (flag, hash): (i64, Option<Vec<u8>>) = sqlx::query_as("SELECT legacy_unbound, install_hash FROM user_devices WHERE device_id = 'old-device'").fetch_one(&state.db).await.unwrap();
    assert_eq!((flag, hash.map(|h| h.len())), (0, Some(32)));
    // From here on it is an ordinary device: unbound sessions get nothing, the bound one has
    // authority (it refuses the newcomer's recovery), and a later sign-in on the SAME install
    // binds with the secret.
    assert_eq!(send(&app, "GET", inbox, Some(&newcomer), None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(bind(&app, &old, &[6u8; 32], &user_id, "old-device", &newcomer).await.0, StatusCode::CONFLICT);
    let id = request_id(&app, &old_session, "old-device").await;
    let cancel = proof(&old, "cancel-recovery", &user_id, "old-device", id.as_bytes());
    assert_eq!(send_proved(&app, "POST", "/api/e2ee/devices/old-device/recovery/cancel", &old_session, Some(json!({ "request_id": id })), &cancel).await.0, StatusCode::OK);
    assert_eq!(bind(&app, &old, &[5u8; 32], &user_id, "old-device", &newcomer).await.0, StatusCode::OK);
}

/// A link signature made with a copied identity key admits nobody: a device joins only on an
/// approval recorded by the linker's current install.
#[tokio::test]
async fn a_device_is_linked_only_through_an_approval_by_the_linkers_live_install() {
    let (app, _state) = app().await;
    let (user_id, live_token) = signup(&app, "alice").await;
    let (live, device) = first_device(&app, &live_token).await;
    // The thief: a copy of the identity key and a session. They sign a perfectly valid link
    // for a device of their own…
    let copy = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let thief = login(&app, "alice").await;
    let mut theirs = SignalStore::generate();
    let sig = b64(&copy.sign_link(&user_id, &theirs.identity_key()).unwrap());
    let (mut body, _) = keys(&mut theirs);
    body["link"] = json!({ "device_id": device, "signature": sig });
    // …and presenting it inline gets them nothing…
    let (status, err) = send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(body.clone())).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::FORBIDDEN, Some("device link required")));
    // …nor does approving their own request: the approval must come from the linker's install.
    let request = json!({ "identity_key": b64(&theirs.identity_key()), "proof": b64(&[0u8; 32]) });
    let (_, created) = send(&app, "POST", "/api/e2ee/link-requests", Some(&thief), Some(request)).await;
    let approve_path = format!("/api/e2ee/link-requests/{}/approve", created["request_id"].as_str().unwrap());
    let approve = json!({ "device_id": device, "signature": sig, "approval_mac": b64(&[0u8; 32]) });
    assert_eq!(send(&app, "POST", &approve_path, Some(&thief), Some(approve.clone())).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(body.clone())).await.0, StatusCode::FORBIDDEN);
    assert_eq!(devices(&app, &live_token).await["devices"].as_array().unwrap().len(), 1);
    // An approval for a DIFFERENT signature than the one presented does not count either.
    assert_eq!(send(&app, "POST", &approve_path, Some(&live_token), Some(approve)).await.0, StatusCode::OK, "(the live install approves)");
    let mut swapped = body.clone();
    swapped["link"]["signature"] = json!(b64(&copy.sign_link(&user_id, &theirs.identity_key()).unwrap()));
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(swapped)).await.0, StatusCode::FORBIDDEN, "XEdDSA signatures are randomized: not the approved one");
    // With the live install's approval on record, exactly that link registers.
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(body)).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_password_change_needs_the_old_password_and_a_device_and_ends_other_sessions() {
    let (app, _state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (phone, _phone_dev) = first_device(&app, &token).await;
    let other = login(&app, "alice").await;
    let change = |old: &str, new: &str, signer: Option<&SignalStore>, signed: &str| {
        let body = Some(json!({ "old_password": old, "new_password": new }));
        let (app, token) = (app.clone(), token.clone());
        let proof = signer.map(|s| proof(s, "password", &user_id, "", signed.as_bytes()));
        async move {
            match proof {
                Some(p) => send_proved(&app, "POST", "/api/auth/password", &token, body, &p).await.0,
                None => send(&app, "POST", "/api/auth/password", Some(&token), body).await.0,
            }
        }
    };
    let new = "a much better passphrase";
    assert_eq!(change("correct horse", new, None, new).await, StatusCode::FORBIDDEN, "the session token and the old password are not enough");
    assert_eq!(change("wrong", new, Some(&phone), new).await, StatusCode::FORBIDDEN, "nor a device without the old password");
    assert_eq!(change("correct horse", new, Some(&SignalStore::generate()), new).await, StatusCode::FORBIDDEN, "nor a key that is not on the account");
    assert_eq!(change("correct horse", new, Some(&phone), "some other password").await, StatusCode::FORBIDDEN, "the proof covers the new password");
    assert_eq!(change("correct horse", "short", Some(&phone), "short").await, StatusCode::BAD_REQUEST);
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&other), None).await.0, StatusCode::OK, "nothing happened yet");

    assert_eq!(change("correct horse", new, Some(&phone), new).await, StatusCode::OK);
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&other), None).await.0, StatusCode::UNAUTHORIZED, "every other session is over");
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&token), None).await.0, StatusCode::OK, "this one carries on");
    let (status, _) = send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "alice", "password": "correct horse" }))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old password is dead");
    let (status, _) = send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "alice", "password": new }))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_reset_with_a_pin_set_is_typed_and_a_forgotten_pin_falls_back_to_the_hold() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (phone, _phone_dev) = first_device(&app, &token).await;
    let pin = "482913";
    let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(json!({ "enable": true, "pin": pin })), &proof(&phone, "set-pin", &user_id, "enable", pin.as_bytes())).await;
    assert_eq!(status, StatusCode::OK);

    // Everything is lost; someone signs in and asks to reset.
    let newcomer = login(&app, "alice").await;
    let mut fresh = SignalStore::generate();
    let (base, _) = keys(&mut fresh);
    let reset = |extra: Value| {
        let mut body = base.clone();
        body["force"] = json!(true);
        for (k, v) in extra.as_object().unwrap() {
            body[k] = v.clone();
        }
        let (app, newcomer) = (app.clone(), newcomer.clone());
        async move { send(&app, "POST", "/api/e2ee/devices/register", Some(&newcomer), Some(body)).await }
    };
    let (status, body) = reset(json!({})).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("registration pin required")));
    let (status, body) = reset(json!({ "pin": "000000" })).await;
    assert_eq!((status, body["error"].as_str(), body["attempts_left"].as_i64()), (StatusCode::FORBIDDEN, Some("registration pin incorrect"), Some(4)));

    // "I forgot my PIN": no shortcut — the same cancellable 7-day hold as an account without one.
    let (status, body) = reset(json!({ "forgot_pin": true })).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device reset pending")));
    assert!(body["completes_at"].as_i64().unwrap() >= now_ms() + 6 * 24 * 3_600_000);
    assert_eq!(devices(&app, &token).await["devices"].as_array().unwrap().len(), 1, "nothing was removed");
    // Not even a seasoned PIN is consulted on that path, and the hold has to run out.
    sqlx::query("UPDATE e2ee_accounts SET pin_set_at = 1 WHERE user_id = $1").bind(&user_id).execute(&state.db).await.unwrap();
    assert_eq!(reset(json!({ "forgot_pin": true })).await.1["error"], "device reset pending");
    sqlx::query("UPDATE e2ee_accounts SET reset_requested_at = reset_requested_at - $1 WHERE user_id = $2")
        .bind(crate::keydir::RESET_DELAY_MS + 1000)
        .bind(&user_id)
        .execute(&state.db)
        .await
        .unwrap();
    let (status, body) = reset(json!({ "forgot_pin": true })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&token), None).await.0, StatusCode::UNAUTHORIZED, "the old device set's sessions ended with it");
    let listing = devices(&app, &newcomer).await;
    assert_eq!((listing["devices"].as_array().unwrap().len(), listing["devices"][0]["current"].as_bool()), (1, Some(true)));
}

#[tokio::test]
async fn a_link_approval_carries_an_opaque_bundle_to_the_new_device() {
    let (app, _state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (phone, phone_dev) = first_device(&app, &token).await;
    let newcomer = login(&app, "alice").await;
    let fresh = SignalStore::generate();
    let code = skwod_crypto::link::generate_code();
    let request = json!({ "identity_key": b64(&fresh.identity_key()), "proof": b64(&skwod_crypto::link::request_proof(&code, &user_id, &fresh.identity_key())) });
    let (_, created) = send(&app, "POST", "/api/e2ee/link-requests", Some(&newcomer), Some(request)).await;
    let id = created["request_id"].as_str().unwrap();
    let approval = |bundle: Vec<u8>| {
        json!({
            "device_id": phone_dev,
            "signature": b64(&phone.sign_link(&user_id, &fresh.identity_key()).unwrap()),
            "approval_mac": b64(&skwod_crypto::link::approval_mac(&code, &user_id, &phone.identity_key(), &fresh.identity_key())),
            "bundle": b64(&bundle),
        })
    };
    let path = format!("/api/e2ee/link-requests/{id}/approve");
    assert_eq!(send(&app, "POST", &path, Some(&token), Some(approval(vec![0u8; 256 * 1024 + 1]))).await.0, StatusCode::BAD_REQUEST, "bounded");
    assert_eq!(send(&app, "POST", &path, Some(&newcomer), Some(approval(b"x".to_vec()))).await.0, StatusCode::FORBIDDEN, "only the approving device's own session may approve as it");
    assert_eq!(send(&app, "POST", &path, Some(&token), Some(approval(b"sealed bundle".to_vec()))).await.0, StatusCode::OK);
    let (_, poll) = send(&app, "GET", &format!("/api/e2ee/link-requests/{id}"), Some(&newcomer), None).await;
    assert_eq!((poll["approved"].as_bool(), poll["bundle"].as_str()), (Some(true), Some(b64(b"sealed bundle").as_str())));
}

/// A backup with a recovery verifier, written by `signer`'s current install on `token`.
pub(crate) async fn put_backup_with_verifier(app: &Router, token: &str, signer: &SignalStore, user_id: &str, backup_key: &[u8; 32]) {
    // (The blob stands in for "the backup sealed under this key".)
    put_backup_contents(app, token, signer, user_id, backup_key, &[b"backup under ".as_slice(), &backup_key[..1]].concat()).await;
}

pub(crate) async fn put_backup_contents(app: &Router, token: &str, signer: &SignalStore, user_id: &str, backup_key: &[u8; 32], blob: &[u8]) {
    let verifier = skwod_crypto::backup::recovery_verifier(backup_key).unwrap();
    let body = json!({ "encrypted_blob": b64(blob), "salt": b64(&[0u8; 16]), "version": 3, "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 }, "auth_verifier": b64(&verifier) });
    let payload = skwod_crypto::link::op_payload(&[&crate::keydir::backup_payload(blob, &[0u8; 16], 3, &body["kdf_params"]), &verifier]);
    let (status, body) = send_proved(app, "PUT", "/api/e2ee/key-backup", token, Some(body), &proof(signer, "backup-put", user_id, "backup", &payload)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Let the recovery key age past the hold (it only skips the wait once it has).
pub(crate) async fn season(state: &AppState, user_id: &str) {
    sqlx::query("UPDATE backup_keys SET set_at = set_at - $1 WHERE user_id = $2 AND retired_at IS NULL")
        .bind(crate::keydir::RESET_DELAY_MS + 1000)
        .bind(user_id)
        .execute(&state.db)
        .await
        .unwrap();
}

/// A fresh recovery-key proof for `purpose` on `target` by whoever holds `backup_key`.
pub(crate) async fn recovery_auth(app: &Router, token: &str, backup_key: &[u8; 32], user_id: &str, purpose: &str, target: &[u8], install: &[u8; 32]) -> String {
    let (status, challenge) = send(app, "POST", "/api/e2ee/key-backup/challenge", Some(token), Some(json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{challenge}");
    let message = skwod_crypto::backup::recovery_auth_message(user_id, purpose, target, challenge["nonce"].as_str().unwrap(), &Sha256::digest(install));
    b64(&skwod_crypto::backup::sign_recovery_auth(backup_key, &message).unwrap())
}

/// [`rekey`] carrying a recovery-key proof.
pub(crate) async fn rekey_with_recovery_key(app: &Router, token: &str, store: &mut SignalStore, install: &[u8; 32], user_id: &str, device: &str, auth: &str) -> (StatusCode, Value) {
    let (mut body, _) = keys(store);
    let hash = Sha256::digest(install);
    body["install_hash"] = json!(b64(&hash));
    body["install_secret"] = json!(b64(install));
    body["recovery_auth"] = json!(auth);
    let empty = skwod_crypto::link::op_payload(&[]);
    let unb = |v: &Value| B64.decode(v.as_str().unwrap()).unwrap();
    let inner = skwod_crypto::link::op_payload(&[&store.registration_id().to_be_bytes(), &unb(&body["signed_prekey"]["public"]), &unb(&body["last_resort_kyber_prekey"]["public"]), &[9u8; 32], &empty, &empty]);
    let payload = skwod_crypto::link::op_payload(&[&inner, &hash]);
    send_proved(app, "POST", &format!("/api/e2ee/devices/{device}/rekey"), token, Some(body), &proof(store, "rekey", user_id, device, &payload)).await
}

/// The owner's recovery policy. Whoever proves the RECOVERY KEY restores at once — no hold, no
/// approval — and the old install is superseded. A clone with the identity key and a session
/// but no recovery key is exactly where it was: a waiting request the account's devices can
/// refuse.
#[tokio::test]
async fn a_restore_that_proves_the_recovery_key_is_immediate_and_a_clone_without_it_still_waits() {
    let (app, state) = app().await;
    let (user_id, original_token) = signup(&app, "alice").await;
    let (original, device) = first_device(&app, &original_token).await;
    let (_, channel) = space(&app, &original_token).await;
    let message = post_as(&app, &original_token, &channel, &device).await.1["message_id"].as_str().unwrap().to_string();
    let backup_key = [0x5au8; 32];
    put_backup_with_verifier(&app, &original_token, &original, &user_id, &backup_key).await;
    season(&state, &user_id).await;

    // --- the clone: identity key + session, no recovery key ---
    let clone_token = login(&app, "alice").await;
    let mut clone = SignalStore::from_bytes(&original.export_identity()).unwrap();
    let clone_secret = [7u8; 32];
    assert_eq!(rekey(&app, &clone_token, &mut clone, &clone_secret, &user_id, &device, None).await.1["error"], "device recovery pending", "still the hold / approval");
    // It can ask for a challenge (anyone signed in can) — and cannot answer it: not with a key
    // of its own choosing, not with the device's identity key, not with a signature for
    // something else.
    for (what, key) in [("a made-up backup key", [1u8; 32]), ("the install secret as the key", clone_secret)] {
        let forged = recovery_auth(&app, &clone_token, &key, &user_id, "rekey", device.as_bytes(), &clone_secret).await;
        let (status, body) = rekey_with_recovery_key(&app, &clone_token, &mut clone, &clone_secret, &user_id, &device, &forged).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {body}");
        assert_ne!(body["error"], "device recovery pending", "{what}: a failed proof is refused, not quietly queued");
    }
    assert_eq!(devices(&app, &original_token).await["devices"][0]["generation"], 0);

    // --- the owner, with the recovery key ---
    let restorer = login(&app, "alice").await;
    let mut restored = SignalStore::from_bytes(&original.export_identity()).unwrap();
    let secret = [42u8; 32];
    // A proof is for one install, one device, one purpose, one nonce.
    let for_other_install = recovery_auth(&app, &restorer, &backup_key, &user_id, "rekey", device.as_bytes(), &[9u8; 32]).await;
    assert_eq!(rekey_with_recovery_key(&app, &restorer, &mut restored, &secret, &user_id, &device, &for_other_install).await.0, StatusCode::FORBIDDEN);
    let for_register = recovery_auth(&app, &restorer, &backup_key, &user_id, "register", device.as_bytes(), &secret).await;
    assert_eq!(rekey_with_recovery_key(&app, &restorer, &mut restored, &secret, &user_id, &device, &for_register).await.0, StatusCode::FORBIDDEN);
    // A proof made for a nonce issued to ANOTHER session is no proof here.
    let elsewhere = recovery_auth(&app, &clone_token, &backup_key, &user_id, "rekey", device.as_bytes(), &secret).await;
    assert_eq!(rekey_with_recovery_key(&app, &restorer, &mut restored, &secret, &user_id, &device, &elsewhere).await.0, StatusCode::FORBIDDEN, "another session's nonce");

    let mut bus = state.rt.subscribe();
    let good = recovery_auth(&app, &restorer, &backup_key, &user_id, "rekey", device.as_bytes(), &secret).await;
    let (status, body) = rekey_with_recovery_key(&app, &restorer, &mut restored, &secret, &user_id, &device, &good).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "at once — no hold, no approval: {body}");
    let told = std::iter::from_fn(|| bus.try_recv().ok()).any(|ev| ev.topic == crate::rt::user_topic(&user_id) && ev.frame.contains("account_restored"));
    assert!(told, "every other device is told the account was restored");
    assert!(devices(&app, &restorer).await["recoveries"].as_array().unwrap().is_empty(), "the clone's waiting request went with it");
    // The proof is single use.
    let (mut again, other_secret) = (SignalStore::from_bytes(&original.export_identity()).unwrap(), [43u8; 32]);
    assert_ne!(rekey_with_recovery_key(&app, &clone_token, &mut again, &other_secret, &user_id, &device, &good).await.0, StatusCode::OK);

    // The old install is superseded on every route, and so is the clone.
    for token in [&original_token, &clone_token] {
        for (route, status) in every_route(&app, token, &device, &channel, &message).await {
            assert_ne!(status, StatusCode::OK, "{route}");
        }
    }
    let (status, body) = send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={device}"), Some(&original_token), None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::CONFLICT, Some("device superseded")), "and it is told why");
    assert_eq!(post_as(&app, &restorer, &channel, &device).await.0, StatusCode::OK);
}

/// Erasing a device does not make a later restore impossible: the backup and its verifier
/// outlive the device, and whoever proves the recovery key seats the restored identity as a
/// fresh device row. Without the recovery key there is no such way in.
#[tokio::test]
async fn erase_then_restore_with_the_recovery_key_registers_a_fresh_device() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (original, device) = first_device(&app, &token).await;
    let backup_key = [0x5au8; 32];
    put_backup_with_verifier(&app, &token, &original, &user_id, &backup_key).await;
    season(&state, &user_id).await;
    // "Erase this device": it unregisters itself. The account has no device left.
    let (status, _) = send_proved(&app, "DELETE", &format!("/api/e2ee/devices/{device}"), &token, None, &proof(&original, "delete", &user_id, &device, b"")).await;
    assert_eq!(status, StatusCode::OK);
    let later = login(&app, "alice").await;
    assert!(devices(&app, &later).await["devices"].as_array().unwrap().is_empty());
    assert_eq!(send(&app, "GET", "/api/e2ee/key-backup", Some(&later), None).await.0, StatusCode::OK, "the backup is still there");

    // The restored identity cannot be re-keyed (no row) and cannot simply register…
    let mut restored = SignalStore::from_bytes(&original.export_identity()).unwrap();
    let secret = [42u8; 32];
    let (mut body, _) = keys(&mut restored);
    body["install_hash"] = json!(b64(&Sha256::digest(secret)));
    let (status, err) = send(&app, "POST", "/api/e2ee/devices/register", Some(&later), Some(body.clone())).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::FORBIDDEN, Some("device link required")));
    // …nor with a proof that is not the recovery key's, or one made for another identity.
    let identity = restored.identity_key();
    let mut forged = body.clone();
    forged["recovery_auth"] = json!(recovery_auth(&app, &later, &[1u8; 32], &user_id, "register", &identity, &secret).await);
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&later), Some(forged)).await.0, StatusCode::FORBIDDEN);
    let mut misdirected = body.clone();
    misdirected["recovery_auth"] = json!(recovery_auth(&app, &later, &backup_key, &user_id, "register", &SignalStore::generate().identity_key(), &secret).await);
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&later), Some(misdirected)).await.0, StatusCode::FORBIDDEN);

    // With the recovery key: a fresh device row, same identity key, at once.
    body["recovery_auth"] = json!(recovery_auth(&app, &later, &backup_key, &user_id, "register", &identity, &secret).await);
    let (status, registered) = send(&app, "POST", "/api/e2ee/devices/register", Some(&later), Some(body)).await;
    assert_eq!((status, registered["recovered"].as_bool()), (StatusCode::OK, Some(true)), "{registered}");
    let listing = devices(&app, &later).await;
    assert_eq!(listing["devices"].as_array().unwrap().len(), 1);
    assert_ne!(listing["devices"][0]["device_id"], device.as_str(), "a new row");
    assert_eq!((listing["devices"][0]["identity_key"].as_str(), listing["devices"][0]["current"].as_bool()), (Some(b64(&identity).as_str()), Some(true)));
    let new_device = registered["device_id"].as_str().unwrap();
    assert_eq!(send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={new_device}"), Some(&later), None).await.0, StatusCode::OK);
}

/// The request a device approves is the one its user was SHOWN. If another request takes its
/// place between the notice and the tap, the approval is refused — it does not land on the
/// request that was swapped in.
#[tokio::test]
async fn an_approval_is_for_the_request_that_was_shown_not_whatever_is_pending_now() {
    let (app, _state) = app().await;
    let (user_id, live_token) = signup(&app, "alice").await;
    let (live, device) = first_device(&app, &live_token).await;
    // The owner starts a restore (no recovery key at hand): the live device shows the request.
    let owner_token = login(&app, "alice").await;
    let mut owner = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let owner_secret = [42u8; 32];
    rekey(&app, &owner_token, &mut owner, &owner_secret, &user_id, &device, None).await;
    let listing = devices(&app, &live_token).await;
    let shown = listing["recoveries"][0]["request_id"].as_str().unwrap().to_string();
    let shown_code = listing["recoveries"][0]["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(shown_code, skwod_crypto::backup::recovery_fingerprint(&Sha256::digest(owner_secret)), "the code the restoring install shows");

    // Before the user taps, an attacker asks too. Its request is filed BESIDE the owner's,
    // with its own id, code and hold; the owner's is untouched (audit L1). Every device is
    // told of every filing, and that more than one install is trying.
    let mut events = _state.rt.subscribe();
    let attacker_token = login(&app, "alice").await;
    let mut attacker = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let attacker_secret = [7u8; 32];
    assert_eq!(rekey(&app, &attacker_token, &mut attacker, &attacker_secret, &user_id, &device, None).await.1["error"], "device recovery pending");
    let told: Vec<String> = std::iter::from_fn(|| events.try_recv().ok()).filter(|e| e.topic == crate::rt::user_topic(&user_id)).map(|e| e.frame).collect();
    assert!(told.iter().any(|f| f.contains("\"device_recovery_requested\"")), "{told:?}");
    assert!(told.iter().any(|f| f.contains("\"device_recovery_multiple\"")), "{told:?}");
    let listing = devices(&app, &live_token).await;
    let requests = listing["recoveries"].as_array().unwrap();
    assert_eq!(requests.len(), 2);
    let owners = requests.iter().find(|r| r["request_id"] == shown.as_str()).expect("the owner's request is still there");
    assert_eq!((owners["fingerprint"].as_str(), owners["approved"].as_bool()), (Some(shown_code.as_str()), Some(false)));
    let attackers = requests.iter().find(|r| r["request_id"] != shown.as_str()).unwrap();
    assert_ne!(attackers["fingerprint"], shown_code.as_str(), "each request shows its own install's code");
    // The owner's install asking again is the same request, untouched.
    assert_eq!(rekey(&app, &owner_token, &mut owner, &owner_secret, &user_id, &device, None).await.1["error"], "device recovery pending");
    assert_eq!(devices(&app, &live_token).await["recoveries"].as_array().unwrap().len(), 2);
    // Contested: NEITHER completes by waiting out the hold — not the attacker's, not the
    // owner's. Only a decision does.
    sqlx::query("UPDATE device_recoveries SET requested_at = requested_at - $1 WHERE user_id = $2")
        .bind(crate::keydir::RESET_DELAY_MS + 1000)
        .bind(&user_id)
        .execute(&_state.db)
        .await
        .unwrap();
    assert_eq!(rekey(&app, &attacker_token, &mut attacker, &attacker_secret, &user_id, &device, None).await.1["error"], "device recovery pending", "the attacker's request never completes by the hold");
    assert_eq!(rekey(&app, &owner_token, &mut owner, &owner_secret, &user_id, &device, None).await.1["error"], "device recovery pending");

    // The tap approves what was shown — the owner's — and that ends every other request.
    let approve = format!("/api/e2ee/devices/{device}/recovery/approve");
    // (A signature over one request's id cannot approve another.)
    let attacker_id = attackers["request_id"].as_str().unwrap().to_string();
    let tap = proof(&live, "approve-recovery", &user_id, &device, shown.as_bytes());
    assert_eq!(send_proved(&app, "POST", &approve, &live_token, Some(json!({ "request_id": attacker_id })), &tap).await.0, StatusCode::FORBIDDEN);
    let tap = proof(&live, "approve-recovery", &user_id, &device, shown.as_bytes());
    assert_eq!(send_proved(&app, "POST", &approve, &live_token, Some(json!({ "request_id": shown })), &tap).await.0, StatusCode::OK);
    let listing = devices(&app, &live_token).await;
    let left: Vec<&Value> = listing["recoveries"].as_array().unwrap().iter().collect();
    assert_eq!(left.len(), 1, "approving one clears the rest");
    assert_eq!((left[0]["request_id"].as_str(), left[0]["approved"].as_bool()), (Some(shown.as_str()), Some(true)));
    // An approval of the cleared request approves nothing.
    let late = proof(&live, "approve-recovery", &user_id, &device, attacker_id.as_bytes());
    assert_eq!(send_proved(&app, "POST", &approve, &live_token, Some(json!({ "request_id": attacker_id })), &late).await.0, StatusCode::CONFLICT);
    assert_eq!(rekey(&app, &owner_token, &mut owner, &owner_secret, &user_id, &device, None).await.0, StatusCode::OK, "the owner's restore completes");
}

/// The hold alone grants only an UNCONTESTED request; once one is granted (by the hold or by
/// an approval) nothing else files beside it until it is used or expires. (Audit L1.)
#[tokio::test]
async fn an_uncontested_request_completes_by_the_hold_and_a_granted_one_is_exclusive() {
    for granted_by in ["hold", "approval"] {
        let (app, state) = app().await;
        let (user_id, live_token) = signup(&app, "alice").await;
        let (live, device) = first_device(&app, &live_token).await;
        let owner_token = login(&app, "alice").await;
        let mut owner = SignalStore::from_bytes(&live.export_identity()).unwrap();
        assert_eq!(rekey(&app, &owner_token, &mut owner, &[42u8; 32], &user_id, &device, None).await.1["error"], "device recovery pending");
        if granted_by == "hold" {
            sqlx::query("UPDATE device_recoveries SET requested_at = requested_at - $1 WHERE user_id = $2")
                .bind(crate::keydir::RESET_DELAY_MS + 1000)
                .bind(&user_id)
                .execute(&state.db)
                .await
                .unwrap();
        } else {
            let id = request_id(&app, &live_token, &device).await;
            let tap = proof(&live, "approve-recovery", &user_id, &device, id.as_bytes());
            assert_eq!(send_proved(&app, "POST", &format!("/api/e2ee/devices/{device}/recovery/approve"), &live_token, Some(json!({ "request_id": id })), &tap).await.0, StatusCode::OK);
        }
        // Granted, not yet used: another install is refused (the cap counts it too).
        let attacker_token = login(&app, "alice").await;
        let mut attacker = SignalStore::from_bytes(&live.export_identity()).unwrap();
        let (status, body) = rekey(&app, &attacker_token, &mut attacker, &[7u8; 32], &user_id, &device, None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::CONFLICT, Some(crate::keydir::RECOVERY_REQUEST_TAKEN)), "{granted_by}");
        assert_eq!(devices(&app, &live_token).await["recoveries"].as_array().unwrap().len(), 1, "{granted_by}");
        let (status, body) = rekey(&app, &owner_token, &mut owner, &[42u8; 32], &user_id, &device, None).await;
        assert_eq!(status, StatusCode::OK, "{granted_by}: {body}");
    }
}

/// The "waiting" answer says when a request was contested: the first filing alone is not
/// (it may complete by the hold), and once a second install files, both are — every answer to
/// either install from then on carries `contested_at`, so neither promises the hold.
#[tokio::test]
async fn a_contested_request_says_so_in_every_waiting_answer() {
    let (app, _state) = app().await;
    let (user_id, live_token) = signup(&app, "alice").await;
    let (live, device) = first_device(&app, &live_token).await;
    let first_token = login(&app, "alice").await;
    let mut first = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let (status, body) = rekey(&app, &first_token, &mut first, &[21u8; 32], &user_id, &device, None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")));
    assert!(body["completes_at"].as_i64().is_some() && body["contested_at"].is_null(), "alone: uncontested {body}");
    let (_, body) = rekey(&app, &first_token, &mut first, &[21u8; 32], &user_id, &device, None).await;
    assert!(body["contested_at"].is_null(), "asking again, still alone: {body}");
    let second_token = login(&app, "alice").await;
    let mut second = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let (_, body) = rekey(&app, &second_token, &mut second, &[22u8; 32], &user_id, &device, None).await;
    let contested = body["contested_at"].as_i64().unwrap_or_else(|| panic!("the second filing is contested: {body}"));
    let (_, body) = rekey(&app, &first_token, &mut first, &[21u8; 32], &user_id, &device, None).await;
    assert_eq!((body["error"].as_str(), body["contested_at"].as_i64()), (Some("device recovery pending"), Some(contested)), "the first one is now contested too");
}

/// Filings racing each other never take a device past the cap: the check and the insert are
/// one step under a per-device lock (run against Postgres too, with SKWOD_TEST_POSTGRES).
#[tokio::test]
async fn concurrent_restore_requests_never_exceed_the_cap() {
    let (app, state) = app().await;
    let (user_id, live_token) = signup(&app, "alice").await;
    let (live, device) = first_device(&app, &live_token).await;
    let mut racers = Vec::new();
    for i in 0..8u8 {
        let token = login(&app, "alice").await;
        let store = SignalStore::from_bytes(&live.export_identity()).unwrap();
        racers.push((token, store, [90 + i; 32]));
    }
    let results = futures_util::future::join_all(racers.into_iter().map(|(token, mut store, secret)| {
        let (app, user_id, device) = (app.clone(), user_id.clone(), device.clone());
        async move { rekey(&app, &token, &mut store, &secret, &user_id, &device, None).await.0 }
    }))
    .await;
    let filed = results.iter().filter(|s| **s == StatusCode::FORBIDDEN).count();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_recoveries WHERE user_id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap();
    assert_eq!((filed as i64, rows), (crate::keydir::MAX_PENDING_RECOVERIES, crate::keydir::MAX_PENDING_RECOVERIES), "{results:?}");
    assert!(results.iter().all(|s| *s == StatusCode::FORBIDDEN || *s == StatusCode::CONFLICT), "{results:?}");
    assert_eq!(devices(&app, &live_token).await["recoveries"].as_array().unwrap().len(), 3);
}

/// Up to three installs may be waiting to restore one device; a fourth is refused until one
/// is cancelled. Each request is cancelled on its own. (Audit L1.)
#[tokio::test]
async fn three_restore_requests_may_wait_side_by_side_and_a_fourth_is_refused() {
    let (app, _state) = app().await;
    let (user_id, live_token) = signup(&app, "alice").await;
    let (live, device) = first_device(&app, &live_token).await;
    let mut installs = Vec::new();
    for i in 0..3u8 {
        let token = login(&app, "alice").await;
        let mut store = SignalStore::from_bytes(&live.export_identity()).unwrap();
        assert_eq!(rekey(&app, &token, &mut store, &[10 + i; 32], &user_id, &device, None).await.1["error"], "device recovery pending");
        installs.push((token, store, [10 + i; 32]));
    }
    assert_eq!(devices(&app, &live_token).await["recoveries"].as_array().unwrap().len(), 3);
    let fourth = login(&app, "alice").await;
    let mut store = SignalStore::from_bytes(&live.export_identity()).unwrap();
    let (status, body) = rekey(&app, &fourth, &mut store, &[99u8; 32], &user_id, &device, None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::CONFLICT, Some(crate::keydir::RECOVERY_REQUESTS_FULL)));
    // The ones waiting are untouched by it, and asking again is still "waiting".
    for (token, store, secret) in &mut installs {
        assert_eq!(rekey(&app, token, store, secret, &user_id, &device, None).await.1["error"], "device recovery pending");
    }
    // One is cancelled — that one alone — and there is room again.
    let listing = devices(&app, &live_token).await;
    let first = listing["recoveries"][0]["request_id"].as_str().unwrap().to_string();
    let refuse = proof(&live, "cancel-recovery", &user_id, &device, first.as_bytes());
    assert_eq!(send_proved(&app, "POST", &format!("/api/e2ee/devices/{device}/recovery/cancel"), &live_token, Some(json!({ "request_id": first })), &refuse).await.0, StatusCode::OK);
    assert_eq!(devices(&app, &live_token).await["recoveries"].as_array().unwrap().len(), 2);
    assert_eq!(rekey(&app, &fourth, &mut store, &[99u8; 32], &user_id, &device, None).await.1["error"], "device recovery pending");
}

/// Filings are rationed per server-issued session — not by anything the caller chooses, and
/// not per account, so nobody can spend the owner's allowance. A refused filing is not
/// counted. A seasoned PIN is outside every limit and completes at once. (Audit L1.)
#[tokio::test]
async fn filings_are_rationed_per_session_and_a_pin_bypasses_the_limits() {
    let (app, state) = app().await;
    let (user_id, live_token) = signup(&app, "alice").await;
    let (live, device) = first_device(&app, &live_token).await;
    let cancel = format!("/api/e2ee/devices/{device}/recovery/cancel");
    let cancel_all = || async {
        for r in devices(&app, &live_token).await["recoveries"].as_array().unwrap().clone() {
            let id = r["request_id"].as_str().unwrap().to_string();
            let refuse = proof(&live, "cancel-recovery", &user_id, &device, id.as_bytes());
            assert_eq!(send_proved(&app, "POST", &cancel, &live_token, Some(json!({ "request_id": id })), &refuse).await.0, StatusCode::OK);
        }
    };
    // One session, made-up install hashes: three filings, then no more from it today.
    let greedy = login(&app, "alice").await;
    let mut store = SignalStore::from_bytes(&live.export_identity()).unwrap();
    for i in 0..3u8 {
        assert_eq!(rekey(&app, &greedy, &mut store, &[20 + i; 32], &user_id, &device, None).await.1["error"], "device recovery pending");
    }
    cancel_all().await;
    assert_eq!(rekey(&app, &greedy, &mut store, &[30u8; 32], &user_id, &device, None).await.0, StatusCode::TOO_MANY_REQUESTS);
    // Its exhaustion is its own: another session files at once.
    let owner = login(&app, "alice").await;
    let mut owner_store = SignalStore::from_bytes(&live.export_identity()).unwrap();
    assert_eq!(rekey(&app, &owner, &mut owner_store, &[40u8; 32], &user_id, &device, None).await.1["error"], "device recovery pending");
    // Refused filings (the account is full) cost the session nothing.
    for i in 0..2u8 {
        let t = login(&app, "alice").await;
        let mut s = SignalStore::from_bytes(&live.export_identity()).unwrap();
        rekey(&app, &t, &mut s, &[50 + i; 32], &user_id, &device, None).await;
    }
    let late = login(&app, "alice").await;
    let mut late_store = SignalStore::from_bytes(&live.export_identity()).unwrap();
    for _ in 0..5 {
        assert_eq!(rekey(&app, &late, &mut late_store, &[60u8; 32], &user_id, &device, None).await.0, StatusCode::CONFLICT);
    }
    cancel_all().await;
    assert_eq!(rekey(&app, &late, &mut late_store, &[60u8; 32], &user_id, &device, None).await.1["error"], "device recovery pending");

    // Full again, and the greedy session spent: the owner's seasoned PIN completes anyway.
    for i in 0..2u8 {
        let t = login(&app, "alice").await;
        let mut s = SignalStore::from_bytes(&live.export_identity()).unwrap();
        rekey(&app, &t, &mut s, &[70 + i; 32], &user_id, &device, None).await;
    }
    assert_eq!(devices(&app, &live_token).await["recoveries"].as_array().unwrap().len(), 3);
    let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &live_token, Some(json!({ "enable": true, "pin": "482913" })), &proof(&live, "set-pin", &user_id, "enable", b"482913")).await;
    assert_eq!(status, StatusCode::OK);
    sqlx::query("UPDATE e2ee_accounts SET pin_set_at = pin_set_at - $1 WHERE user_id = $2").bind(crate::keydir::RESET_DELAY_MS + 1000).bind(&user_id).execute(&state.db).await.unwrap();
    let (status, body) = rekey(&app, &greedy, &mut store, &[80u8; 32], &user_id, &device, Some("482913")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// Move the whole recovery-key history of `user_id` back in time by `ms` (as time would).
async fn elapse(state: &AppState, user_id: &str, ms: i64) {
    sqlx::query("UPDATE backup_keys SET set_at = set_at - $1, replaced_at = replaced_at - $1, retired_at = retired_at - $1 WHERE user_id = $2")
        .bind(ms)
        .bind(user_id)
        .execute(&state.db)
        .await
        .unwrap();
    sqlx::query("UPDATE backup_blobs SET created_at = created_at - $1 WHERE user_id = $2").bind(ms).bind(user_id).execute(&state.db).await.unwrap();
}

const DAY: i64 = 24 * 3_600_000;

/// A restore attempt of `device` with `backup_key` from a fresh session: (status, body).
pub(crate) async fn restore_with(app: &Router, original: &SignalStore, backup_key: &[u8; 32], install: &[u8; 32], user_id: &str, device: &str) -> (StatusCode, Value) {
    let token = login(app, "alice").await;
    let mut restored = SignalStore::from_bytes(&original.export_identity()).unwrap();
    let auth = recovery_auth(app, &token, backup_key, user_id, "rekey", device.as_bytes(), install).await;
    rekey_with_recovery_key(app, &token, &mut restored, install, user_id, device, &auth).await
}

/// Which backups a restore is offered (the blobs), in order.
async fn offered_backups(app: &Router, token: &str) -> Vec<Vec<u8>> {
    let (status, body) = send(app, "GET", "/api/e2ee/key-backup", Some(token), None).await;
    if status != StatusCode::OK {
        return Vec::new();
    }
    let blob = |v: &Value| B64.decode(v["encrypted_blob"].as_str().unwrap()).unwrap();
    std::iter::once(blob(&body)).chain(body["alternates"].as_array().unwrap().iter().map(blob)).collect()
}

/// Seasoning. A recovery key only skips the wait once it has been in place for the length of
/// the hold; a routine re-upload under the same key neither restarts nor shortens that.
#[tokio::test]
async fn a_recovery_key_restores_at_once_only_after_it_has_seasoned() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let key = [0x11u8; 32];
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &key).await;
    let listing = devices(&app, &token).await;
    assert!(listing["recovery_key_instant_from"].as_i64().unwrap() >= now_ms() + 6 * DAY, "first enable: instant in 7 days, and the app can say so");
    assert!(listing["recovery_key_changed_at"].is_null(), "a first key is not a change");
    // The right key, too new: a valid proof, and still the hold / approval.
    let (status, body) = restore_with(&app, &device_store, &key, &[42u8; 32], &user_id, &device).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{body}");
    let before = devices(&app, &token).await["recovery_key_instant_from"].as_i64();
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &key).await;
    let listing = devices(&app, &token).await;
    assert_eq!(listing["recovery_key_instant_from"].as_i64(), before, "a re-upload under the same key does not move the clock");
    assert!(listing["recovery_key_changed_at"].is_null());
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_keys").fetch_one(&state.db).await.unwrap(), 1);
    // After the hold: at once.
    elapse(&state, &user_id, 7 * DAY + 1000).await;
    let (status, body) = restore_with(&app, &device_store, &key, &[42u8; 32], &user_id, &device).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");
}

/// The overlap. Someone who holds an unlocked device for a minute swaps in a backup under THEIR
/// recovery key. Their key is not seasoned and restores nothing at once; the owner's seasoned
/// key keeps working for the length of the hold — and using it retires the planted key and puts
/// the owner's backup back.
#[tokio::test]
async fn the_owner_restores_with_the_old_key_inside_the_window_which_retires_a_planted_key() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let (owners, planted) = ([0x11u8; 32], [0x66u8; 32]);
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &owners).await;
    elapse(&state, &user_id, 30 * DAY).await;

    let mut bus = state.rt.subscribe();
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &planted).await;
    let told = std::iter::from_fn(|| bus.try_recv().ok()).any(|ev| ev.topic == crate::rt::user_topic(&user_id) && ev.frame.contains("recovery_key_changed"));
    assert!(told, "every device hears that the recovery key was changed");
    assert!(devices(&app, &token).await["recovery_key_changed_at"].as_i64().is_some());
    // A restore from elsewhere (a session that is no current device) is offered the owner's
    // backup, still — and NOT the planted one: its key is new (audit M4). The device itself
    // sees both.
    let anyone = login(&app, "alice").await;
    assert_eq!(offered_backups(&app, &anyone).await, [b"backup under \x11".to_vec()]);
    assert_eq!(offered_backups(&app, &token).await, [b"backup under \x66".to_vec(), b"backup under \x11".to_vec()]);

    // The planted key proves fine — and does not restore at once, nor seat a fresh device.
    let (status, body) = restore_with(&app, &device_store, &planted, &[7u8; 32], &user_id, &device).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{body}");
    assert_eq!(devices(&app, &token).await["devices"][0]["generation"], 0);

    // Three days in, the owner restores with the OLD key: at once.
    elapse(&state, &user_id, 3 * DAY).await;
    let (status, body) = restore_with(&app, &device_store, &owners, &[42u8; 32], &user_id, &device).await;
    assert_eq!((status, body["generation"].as_i64(), body["recovery_key_consumed"].as_bool()), (StatusCode::OK, Some(1), Some(true)), "{body}");
    // That was the old key's ONE use. It is not back in force: it is consumed; the planted key
    // is cancelled; the planted backup is gone; and the account has NO recovery key until the
    // owner saves a new one.
    let rows: Vec<(Vec<u8>, Option<i64>, Option<String>)> = sqlx::query_as("SELECT verifier, retired_at, retire_reason FROM backup_keys ORDER BY set_at").fetch_all(&state.db).await.unwrap();
    let reasons: Vec<Option<&str>> = rows.iter().map(|r| r.2.as_deref()).collect();
    assert_eq!(reasons, [Some("consumed"), Some("cancelled")], "history is kept; nothing is in force");
    assert!(rows.iter().all(|r| r.1.is_some_and(|t| t <= now_ms())));
    let anyone = login(&app, "alice").await;
    assert!(offered_backups(&app, &anyone).await.is_empty(), "neither backup is served any more");
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&anyone), Some(json!({}))).await.0, StatusCode::NOT_FOUND, "no key to prove");
    let listing = devices(&app, &anyone).await;
    assert_eq!((listing["recovery_key_needed"].as_bool(), listing["recovery_key_instant_from"].is_null()), (Some(true), true), "the devices are told to save a new one");
    // Neither key restores anything now — at once or ever (a second restore just waits).
    elapse(&state, &user_id, 30 * DAY).await;
    for key in [&owners, &planted] {
        let token = login(&app, "alice").await;
        let mut again = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
        let (status, body) = rekey(&app, &token, &mut again, &[9u8; 32], &user_id, &device, None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{key:?}");
    }
    // The restored device saves a new key. It seasons from zero — also if it is the old secret.
    let restored_token = login(&app, "alice").await;
    let restored = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
    assert_eq!(bind(&app, &restored, &[42u8; 32], &user_id, &device, &restored_token).await.0, StatusCode::OK);
    put_backup_with_verifier(&app, &restored_token, &restored, &user_id, &owners).await;
    let listing = devices(&app, &restored_token).await;
    assert!(listing["recovery_key_instant_from"].as_i64().unwrap() >= now_ms() + 6 * DAY, "from zero");
    assert_eq!(listing["recovery_key_needed"], false);
}

/// The same wait on an install that typed a recovery key too new to skip it. The client
/// sends a fresh proof with every ask for as long as the server hands it challenges (20 an
/// hour per session) and none after that; neither phase may stop the approval from working.
#[tokio::test]
async fn a_restore_waiting_with_a_new_recovery_key_still_completes_when_it_is_approved() {
    let (app, _state) = app().await;
    let (user_id, original_token) = signup(&app, "alice").await;
    let (original, device) = first_device(&app, &original_token).await;
    let backup_key = [0x5au8; 32];
    put_backup_with_verifier(&app, &original_token, &original, &user_id, &backup_key).await;
    let restored_token = login(&app, "alice").await;
    let mut restored = SignalStore::from_bytes(&original.export_identity()).unwrap();
    let new_secret = [42u8; 32];
    for _ in 0..20 {
        let auth = recovery_auth(&app, &restored_token, &backup_key, &user_id, "rekey", device.as_bytes(), &new_secret).await;
        let (status, body) = rekey_with_recovery_key(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, &auth).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{body}");
    }
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&restored_token), Some(json!({}))).await.0, StatusCode::TOO_MANY_REQUESTS, "no more challenges this hour");
    for _ in 0..20 {
        let (status, body) = rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{body}");
    }
    let id = request_id(&app, &original_token, &device).await;
    let approve = format!("/api/e2ee/devices/{device}/recovery/approve");
    let right = proof(&original, "approve-recovery", &user_id, &device, id.as_bytes());
    assert_eq!(send_proved(&app, "POST", &approve, &original_token, Some(json!({ "request_id": id })), &right).await.0, StatusCode::OK);
    let (status, body) = rekey(&app, &restored_token, &mut restored, &new_secret, &user_id, &device, None).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");
}

/// A re-key refused for the hourly limit is refused before it uses anything up. The recovery
/// key in its overlap restores ONCE: a refusal after the proof was taken would spend that one
/// use (and the proof's challenge) on nothing, and the owner would be locked out.
#[tokio::test]
async fn a_rate_limited_rekey_uses_up_neither_the_recovery_key_nor_its_proof() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let owners = [0x11u8; 32];
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &owners).await;
    elapse(&state, &user_id, 30 * DAY).await;
    // The key is replaced by removing the backup: it is in its overlap, good for one restore.
    let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/key-backup", &token, None, &proof(&device_store, "backup-delete", &user_id, "backup", b"")).await;
    assert_eq!(status, StatusCode::OK);

    let restorer = login(&app, "alice").await;
    let mut restored = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
    let secret = [42u8; 32];
    let auth = recovery_auth(&app, &restorer, &owners, &user_id, "rekey", device.as_bytes(), &secret).await;
    // The hour's re-keys are used up.
    let budget = format!("e2ee_rekey:{user_id}");
    for _ in 0..10 {
        state.limiter.hit(&budget, crate::limiter::HOUR);
    }
    let (status, body) = rekey_with_recovery_key(&app, &restorer, &mut restored, &secret, &user_id, &device, &auth).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    let consumed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_keys WHERE user_id = $1 AND retire_reason = 'consumed'").bind(&user_id).fetch_one(&state.db).await.unwrap();
    assert_eq!(consumed, 0, "the refusal did not spend the key");
    assert_eq!(devices(&app, &token).await["devices"][0]["generation"], 0, "and nothing moved");

    // An hour later the SAME proof — same challenge, same key — restores.
    state.limiter.forget(&budget);
    let (status, body) = rekey_with_recovery_key(&app, &restorer, &mut restored, &secret, &user_id, &device, &auth).await;
    assert_eq!((status, body["recovery_key_consumed"].as_bool()), (StatusCode::OK, Some(true)), "{body}");
    // …and that one counted: only re-keys that happen do.
    for _ in 0..9 {
        state.limiter.hit(&budget, crate::limiter::HOUR);
    }
    assert!(state.limiter.has_room(&budget, 10).is_err(), "the completed re-key was the tenth");
}

/// The same for a restore after an erase: a registration the account has no room for is
/// refused before the overlap key's one use is taken.
#[tokio::test]
async fn a_restore_refused_for_the_device_limit_does_not_use_up_the_recovery_key() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (first, first_dev) = first_device(&app, &token).await;
    let (erased, erased_dev, erased_token) = linked_device(&app, "alice", &user_id, &first, &first_dev, &token).await;
    let owners = [0x11u8; 32];
    put_backup_with_verifier(&app, &token, &first, &user_id, &owners).await;
    elapse(&state, &user_id, 30 * DAY).await;
    // One device erases itself; the backup is removed (the key goes into its overlap); and the
    // account fills up to its five devices.
    let (status, _) = send_proved(&app, "DELETE", &format!("/api/e2ee/devices/{erased_dev}"), &erased_token, None, &proof(&erased, "delete", &user_id, &erased_dev, b"")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/key-backup", &token, None, &proof(&first, "backup-delete", &user_id, "backup", b"")).await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..4 {
        linked_device(&app, "alice", &user_id, &first, &first_dev, &token).await;
    }
    assert_eq!(devices(&app, &token).await["devices"].as_array().unwrap().len(), 5);

    let later = login(&app, "alice").await;
    let mut restored = SignalStore::from_bytes(&erased.export_identity()).unwrap();
    let secret = [42u8; 32];
    let (mut body, _) = keys(&mut restored);
    body["install_hash"] = json!(b64(&Sha256::digest(secret)));
    body["recovery_auth"] = json!(recovery_auth(&app, &later, &owners, &user_id, "register", &restored.identity_key(), &secret).await);
    let (status, refused) = send(&app, "POST", "/api/e2ee/devices/register", Some(&later), Some(body)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    let consumed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_keys WHERE user_id = $1 AND retire_reason = 'consumed'").bind(&user_id).fetch_one(&state.db).await.unwrap();
    let challenges: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM backup_auth_nonces WHERE user_id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap();
    assert_eq!((consumed, challenges), (0, 1), "neither the key nor the proof's challenge was spent");
}

/// Deleting the backup is not a way to lock the owner out: the history survives it, the delete
/// is announced, and the seasoned key restores at once for the length of the hold.
#[tokio::test]
async fn the_owner_still_restores_after_the_backup_was_deleted_inside_the_window() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let owners = [0x11u8; 32];
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &owners).await;
    elapse(&state, &user_id, 30 * DAY).await;

    let mut bus = state.rt.subscribe();
    let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/key-backup", &token, None, &proof(&device_store, "backup-delete", &user_id, "backup", b"")).await;
    assert_eq!(status, StatusCode::OK);
    let told = std::iter::from_fn(|| bus.try_recv().ok()).any(|ev| ev.topic == crate::rt::user_topic(&user_id) && ev.frame.contains("recovery_key_changed"));
    assert!(told, "a delete is announced like any change");
    let listing = devices(&app, &token).await;
    assert!(listing["recovery_key_changed_at"].as_i64().is_some() && listing["recovery_key_instant_from"].is_null());
    // A verifier-less write (a build-43 client) does not wipe the history either.
    let bare = json!({ "encrypted_blob": b64(b"no verifier"), "salt": b64(&[0u8; 16]), "version": 3, "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 } });
    let p = proof(&device_store, "backup-put", &user_id, "backup", &crate::keydir::backup_payload(b"no verifier", &[0u8; 16], 3, &bare["kdf_params"]));
    assert_eq!(send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(bare), &p).await.0, StatusCode::OK);

    // The owner's backup is still offered, and the owner's key still restores at once.
    let anyone = login(&app, "alice").await;
    assert!(offered_backups(&app, &anyone).await.contains(&b"backup under \x11".to_vec()));
    elapse(&state, &user_id, 6 * DAY).await;
    let (status, body) = restore_with(&app, &device_store, &owners, &[42u8; 32], &user_id, &device).await;
    assert_eq!((status, body["generation"].as_i64(), body["recovery_key_consumed"].as_bool()), (StatusCode::OK, Some(1), Some(true)), "{body}");
    assert!(offered_backups(&app, &anyone).await.is_empty(), "the key was used up; a new one has to be saved");
    assert_eq!(devices(&app, &anyone).await["recovery_key_needed"], true);
}

/// Chained changes neither reset nor extend the old key's window, and once the window is over
/// the key that has been in force for a full hold is the one that restores at once.
#[tokio::test]
async fn chained_changes_do_not_move_the_old_keys_window_and_after_it_the_new_key_is_instant() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let (first, second, third) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &first).await;
    elapse(&state, &user_id, 30 * DAY).await;
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &second).await; // day 0: first → overlap until day 7
    let window: i64 = sqlx::query_scalar("SELECT retired_at FROM backup_keys WHERE verifier = $1").bind(skwod_crypto::backup::recovery_verifier(&first).unwrap()).fetch_one(&state.db).await.unwrap();
    elapse(&state, &user_id, 3 * DAY).await;
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &third).await; // day 3: second (unseasoned) retired on the spot
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &second).await; // …and back again: a NEW row for it
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &third).await;
    let after: i64 = sqlx::query_scalar("SELECT retired_at FROM backup_keys WHERE verifier = $1").bind(skwod_crypto::backup::recovery_verifier(&first).unwrap()).fetch_one(&state.db).await.unwrap();
    assert_eq!(after, window - 3 * DAY, "the first key's window ends when it always did (3 days have passed; nothing moved it)");
    // An unseasoned key that was replaced never counts — not even for the wait.
    let (status, body) = restore_with(&app, &device_store, &second, &[2u8; 32], &user_id, &device).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_ne!(body["error"], "device recovery pending", "{body}");

    // Day 8: the first key's window is over — it restores nothing at once any more.
    elapse(&state, &user_id, 5 * DAY).await;
    let (status, body) = restore_with(&app, &device_store, &first, &[1u8; 32], &user_id, &device).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_ne!(body["error"], "device recovery pending");
    let anyone = login(&app, "alice").await;
    assert_eq!(offered_backups(&app, &token).await, [b"backup under \x33".to_vec()], "its backup is no longer offered");
    assert!(offered_backups(&app, &anyone).await.is_empty(), "and the key in force is too new to be handed to a session that is no device (audit M4)");
    // The key in force was set on day 3: not yet seasoned on day 8…
    let (_, body) = restore_with(&app, &device_store, &third, &[3u8; 32], &user_id, &device).await;
    assert_eq!(body["error"], "device recovery pending");
    // …and instant once it has been in force for the full hold.
    elapse(&state, &user_id, 3 * DAY).await;
    let (status, body) = restore_with(&app, &device_store, &third, &[3u8; 32], &user_id, &device).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");
}

/// Why a device left decides whether its identity may come back. One that another device
/// REMOVED (lost, stolen) is refused however it tries — a seasoned recovery key included —
/// short of a link approval by a current device. Removing it also retires the recovery key in
/// force (it may have known it). One that erased ITSELF may be restored.
#[tokio::test]
async fn a_removed_devices_identity_cannot_register_again_without_a_link_approval() {
    let (app, state) = app().await;
    let (user_id, phone_token) = signup(&app, "alice").await;
    let (phone, phone_dev) = first_device(&app, &phone_token).await;
    let (mut mac, mac_dev, _mac_token) = linked_device(&app, "alice", &user_id, &phone, &phone_dev, &phone_token).await;
    let key = [0x11u8; 32];
    put_backup_with_verifier(&app, &phone_token, &phone, &user_id, &key).await;
    elapse(&state, &user_id, 30 * DAY).await;

    // The phone removes the Mac (stolen).
    let mut bus = state.rt.subscribe();
    let (status, body) = send_proved(&app, "DELETE", &format!("/api/e2ee/devices/{mac_dev}"), &phone_token, None, &proof(&phone, "delete", &user_id, &mac_dev, b"")).await;
    assert_eq!((status, body["recovery_key_retired"].as_bool()), (StatusCode::OK, Some(true)), "{body}");
    let told = std::iter::from_fn(|| bus.try_recv().ok()).any(|ev| ev.frame.contains("recovery_key_changed"));
    assert!(told, "the devices are told to make a new recovery key");
    assert!(devices(&app, &phone_token).await["recovery_key_instant_from"].is_null(), "no key is in force");
    let reason: String = sqlx::query_scalar("SELECT reason FROM device_tombstones WHERE user_id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap();
    assert_eq!(reason, "removed");

    // The recovery key the Mac may have known is dead AT ONCE — no overlap: it is not served,
    // there is nothing to prove, and it restores nothing (not even the phone's identity).
    let thief = login(&app, "alice").await;
    assert!(offered_backups(&app, &thief).await.is_empty(), "the backup sealed under it is not served");
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&thief), Some(json!({}))).await.0, StatusCode::NOT_FOUND);
    let reasons: Vec<(Option<String>, i64)> = sqlx::query_as("SELECT retire_reason, retired_at FROM backup_keys").fetch_all(&state.db).await.unwrap();
    assert!(reasons.iter().all(|(reason, at)| reason.as_deref() == Some("compromised") && *at <= now_ms()), "{reasons:?}");
    let mut phone_copy = SignalStore::from_bytes(&phone.export_identity()).unwrap();
    let (status, err) = rekey(&app, &thief, &mut phone_copy, &[7u8; 32], &user_id, &phone_dev, None).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "with the old key they are just another copy of the identity key");
    assert_eq!(devices(&app, &phone_token).await["recovery_key_needed"], true, "the remaining device is prompted for a new key");
    // Nothing brings a compromised key back: time does not…
    elapse(&state, &user_id, 30 * DAY).await;
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&thief), Some(json!({}))).await.0, StatusCode::NOT_FOUND);

    // The owner saves a NEW recovery key; it seasons.
    let new_key = [0x22u8; 32];
    put_backup_with_verifier(&app, &phone_token, &phone, &user_id, &new_key).await;
    elapse(&state, &user_id, 30 * DAY).await;
    // Whoever holds the Mac tries to bring ITS identity back — plainly, even with the account's
    // (seasoned, valid) recovery key, and by a reset.
    let secret = [7u8; 32];
    let (mut body, _) = keys(&mut mac);
    body["install_hash"] = json!(b64(&Sha256::digest(secret)));
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(body.clone())).await.0, StatusCode::FORBIDDEN);
    let mut with_key = body.clone();
    with_key["recovery_auth"] = json!(recovery_auth(&app, &thief, &new_key, &user_id, "register", &mac.identity_key(), &secret).await);
    let (status, err) = send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(with_key)).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")), "a recovery key does not undo a removal");
    let mut reset = body.clone();
    reset["force"] = json!(true);
    sqlx::query("INSERT INTO e2ee_accounts (user_id, first_device_at, reset_requested_at, reset_identity_key) VALUES ($1, 0, 1, $2)
                 ON CONFLICT (user_id) DO UPDATE SET reset_requested_at = 1, reset_identity_key = excluded.reset_identity_key")
        .bind(&user_id)
        .bind(mac.identity_key())
        .execute(&state.db)
        .await
        .unwrap();
    let (status, err) = send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(reset)).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")), "nor does a reset that ran out its hold");
    assert_eq!(devices(&app, &phone_token).await["devices"].as_array().unwrap().len(), 1, "the phone is still there");

    // Only an explicit link approval by a current device takes it back.
    let sig = b64(&phone.sign_link(&user_id, &mac.identity_key()).unwrap());
    let (_, created) = send(&app, "POST", "/api/e2ee/link-requests", Some(&thief), Some(json!({ "identity_key": b64(&mac.identity_key()), "proof": b64(&[0u8; 32]) }))).await;
    let approve = json!({ "device_id": phone_dev, "signature": sig, "approval_mac": b64(&[0u8; 32]) });
    assert_eq!(send(&app, "POST", &format!("/api/e2ee/link-requests/{}/approve", created["request_id"].as_str().unwrap()), Some(&phone_token), Some(approve)).await.0, StatusCode::OK);
    body["link"] = json!({ "device_id": phone_dev, "signature": sig });
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&thief), Some(body)).await.0, StatusCode::OK);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM device_tombstones").fetch_one(&state.db).await.unwrap(), 0, "the approval is the re-trust");
}

/// Nobody can use up the owner's challenge. Nonces belong to the session they were issued to
/// and are consumed only by a valid proof, so a second session hammering the endpoint — asking
/// for challenges, answering with garbage — leaves the owner's restore untouched.
#[tokio::test]
async fn another_session_cannot_burn_the_owners_recovery_challenge() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let backup_key = [0x11u8; 32];
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &backup_key).await;
    season(&state, &user_id).await;

    // The owner gets a challenge and signs it…
    let owner = login(&app, "alice").await;
    let mut restored = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
    let secret = [42u8; 32];
    let proof_for_owner = recovery_auth(&app, &owner, &backup_key, &user_id, "rekey", device.as_bytes(), &secret).await;

    // …and before they send it, another session of the account goes to work.
    let pest = login(&app, "alice").await;
    let mut junk = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
    for round in 0..6 {
        let (status, _) = send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&pest), Some(json!({}))).await;
        assert_eq!(status, StatusCode::OK, "round {round}");
        let garbage = recovery_auth(&app, &pest, &[round as u8; 32], &user_id, "rekey", device.as_bytes(), &[1u8; 32]).await;
        let (status, _) = rekey_with_recovery_key(&app, &pest, &mut junk, &[1u8; 32], &user_id, &device, &garbage).await;
        assert!(status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS, "round {round}: {status}");
    }
    // It cannot replay the owner's proof from its own session either (not its nonce)…
    let (status, _) = rekey_with_recovery_key(&app, &pest, &mut junk, &secret, &user_id, &device, &proof_for_owner).await;
    assert_ne!(status, StatusCode::OK);
    // …and its own nonces are capped, not piling up.
    let held: i64 = sqlx::query_scalar("SELECT count(*) FROM backup_auth_nonces WHERE session_hash = $1").bind(Sha256::digest(pest.as_bytes()).to_vec()).fetch_one(&state.db).await.unwrap();
    assert!(held <= 4, "{held}");
    // Eventually the pest runs into ITS OWN limit; the owner's is separate.
    let mut limited = false;
    for _ in 0..30 {
        limited |= send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&pest), Some(json!({}))).await.0 == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "per-session limit");
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&owner), Some(json!({}))).await.0, StatusCode::OK, "the owner is not rate-limited by it");

    // The owner's proof, made before all that, still works — once.
    let (status, body) = rekey_with_recovery_key(&app, &owner, &mut restored, &secret, &user_id, &device, &proof_for_owner).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");
    // The nonce it answered is gone (single use); only the later, unanswered one remains.
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM backup_auth_nonces WHERE session_hash = $1").bind(Sha256::digest(owner.as_bytes()).to_vec()).fetch_one(&state.db).await.unwrap();
    assert_eq!(left, 1);
}

/// "My recovery key is compromised": retired at once, no overlap, never accepted again.
#[tokio::test]
async fn reporting_the_recovery_key_compromised_retires_it_at_once() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let key = [0x11u8; 32];
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &key).await;
    elapse(&state, &user_id, 30 * DAY).await;
    let path = "/api/e2ee/key-backup/compromised";
    // A current device says so (a session or a copied key cannot).
    let other = login(&app, "alice").await;
    assert_eq!(send(&app, "POST", path, Some(&other), None).await.0, StatusCode::FORBIDDEN);
    let copy = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
    assert_eq!(send_proved(&app, "POST", path, &other, None, &proof(&copy, "backup-compromised", &user_id, "backup", b"")).await.0, StatusCode::FORBIDDEN);
    let mut bus = state.rt.subscribe();
    // (A proof is single-use, and the copy's proof above is the same key over the same words:
    // made in the same millisecond it would BE this one, already spent.)
    tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    let (status, body) = send_proved(&app, "POST", path, &token, None, &proof(&device_store, "backup-compromised", &user_id, "backup", b"")).await;
    assert_eq!((status, body["retired"].as_bool()), (StatusCode::OK, Some(true)), "{body}");
    assert!(std::iter::from_fn(|| bus.try_recv().ok()).any(|ev| ev.frame.contains("recovery_key_changed")), "announced");

    // At once, and for good: not served, not provable, no overlap restore.
    assert!(offered_backups(&app, &other).await.is_empty());
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&other), Some(json!({}))).await.0, StatusCode::NOT_FOUND);
    let (reason, retired_at): (String, i64) = sqlx::query_as("SELECT retire_reason, retired_at FROM backup_keys").fetch_one(&state.db).await.unwrap();
    assert!(reason == "compromised" && retired_at <= now_ms());
    let mut holder = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
    assert_eq!(rekey(&app, &other, &mut holder, &[7u8; 32], &user_id, &device, None).await.1["error"], "device recovery pending", "whoever holds that key waits like anyone");
    let listing = devices(&app, &token).await;
    assert_eq!((listing["recovery_key_needed"].as_bool(), listing["recovery_key_changed_at"].as_i64().is_some()), (Some(true), true));
    // Saying it twice is harmless; a new key starts from zero.
    let (_, body) = send_proved(&app, "POST", path, &token, None, &proof(&device_store, "backup-compromised", &user_id, "backup", b"")).await;
    assert_eq!(body["retired"], false);
    put_backup_with_verifier(&app, &token, &device_store, &user_id, &[0x22u8; 32]).await;
    assert!(devices(&app, &token).await["recovery_key_instant_from"].as_i64().unwrap() >= now_ms() + 6 * DAY);
}

/// An erased device that turns out to have been stolen: a current device converts its
/// tombstone to `removed`. Its identity is then refused like any removed device's — recovery
/// key or not — and the recovery key in force is retired as compromised. A device erasing
/// itself "because it was lost" does both in one step.
#[tokio::test]
async fn an_erased_device_can_be_marked_removed_and_a_lost_erase_is_a_removal() {
    let (app, state) = app().await;
    let (user_id, phone_token) = signup(&app, "alice").await;
    let (phone, phone_dev) = first_device(&app, &phone_token).await;
    let (mut mac, mac_dev, mac_token) = linked_device(&app, "alice", &user_id, &phone, &phone_dev, &phone_token).await;
    let (mut tablet, tablet_dev, tablet_token) = linked_device(&app, "alice", &user_id, &phone, &phone_dev, &phone_token).await;
    let key = [0x11u8; 32];
    put_backup_with_verifier(&app, &phone_token, &phone, &user_id, &key).await;
    elapse(&state, &user_id, 30 * DAY).await;

    // The Mac erases itself: listed as erased, and the recovery key is untouched.
    let (status, body) = send_proved(&app, "DELETE", &format!("/api/e2ee/devices/{mac_dev}"), &mac_token, None, &proof(&mac, "delete", &user_id, &mac_dev, b"")).await;
    assert_eq!((status, body["recovery_key_retired"].as_bool()), (StatusCode::OK, Some(false)));
    let listing = devices(&app, &phone_token).await;
    assert_eq!((listing["erased"][0]["device_id"].as_str(), listing["recovery_key_needed"].as_bool()), (Some(mac_dev.as_str()), Some(false)));
    let mac_identity = mac.identity_key();
    assert_eq!(listing["erased"][0]["identity_key"], b64(&mac_identity).as_str());

    // Later it turns out the Mac was stolen. The phone converts the tombstone.
    let path = "/api/e2ee/devices/tombstones/remove";
    let body = json!({ "identity_key": b64(&mac_identity) });
    let other = login(&app, "alice").await;
    assert_eq!(send(&app, "POST", path, Some(&other), Some(body.clone())).await.0, StatusCode::FORBIDDEN, "a current device, not a session");
    let wrong = proof(&phone, "tombstone-remove", &user_id, "tombstone", b"another identity");
    assert_eq!(send_proved(&app, "POST", path, &phone_token, Some(body.clone()), &wrong).await.0, StatusCode::FORBIDDEN);
    let (status, answer) = send_proved(&app, "POST", path, &phone_token, Some(body), &proof(&phone, "tombstone-remove", &user_id, "tombstone", &mac_identity)).await;
    assert_eq!((status, answer["recovery_key_retired"].as_bool()), (StatusCode::OK, Some(true)), "{answer}");
    let listing = devices(&app, &phone_token).await;
    assert!(listing["erased"].as_array().unwrap().is_empty());
    assert_eq!(listing["recovery_key_needed"], true, "and the recovery key it may have known is retired");
    // Its identity is refused now, a seasoned recovery key or not.
    let new_key = [0x22u8; 32];
    put_backup_with_verifier(&app, &phone_token, &phone, &user_id, &new_key).await;
    elapse(&state, &user_id, 30 * DAY).await;
    let secret = [7u8; 32];
    let (mut reg, _) = keys(&mut mac);
    reg["install_hash"] = json!(b64(&Sha256::digest(secret)));
    reg["recovery_auth"] = json!(recovery_auth(&app, &other, &new_key, &user_id, "register", &mac_identity, &secret).await);
    let (status, err) = send(&app, "POST", "/api/e2ee/devices/register", Some(&other), Some(reg)).await;
    assert_eq!((status, err["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")));
    // An unknown identity has no tombstone to convert.
    let none = json!({ "identity_key": b64(&SignalStore::generate().identity_key()) });
    let p = proof(&phone, "tombstone-remove", &user_id, "tombstone", &B64.decode(none["identity_key"].as_str().unwrap()).unwrap());
    assert_eq!(send_proved(&app, "POST", path, &phone_token, Some(none), &p).await.0, StatusCode::NOT_FOUND);

    // The tablet is erased "because it was lost": a removal in one step. (The flag is signed.)
    let lost = format!("/api/e2ee/devices/{tablet_dev}?lost=1");
    assert_eq!(send_proved(&app, "DELETE", &lost, &tablet_token, None, &proof(&tablet, "delete", &user_id, &tablet_dev, b"")).await.0, StatusCode::FORBIDDEN, "a proof for a plain erase does not carry it");
    let (status, body) = send_proved(&app, "DELETE", &lost, &tablet_token, None, &proof(&tablet, "delete", &user_id, &tablet_dev, b"lost")).await;
    assert_eq!((status, body["recovery_key_retired"].as_bool()), (StatusCode::OK, Some(true)), "{body}");
    let reason: String = sqlx::query_scalar("SELECT reason FROM device_tombstones WHERE device_id = $1").bind(&tablet_dev).fetch_one(&state.db).await.unwrap();
    assert_eq!(reason, "removed");
    let (mut reg, _) = keys(&mut tablet);
    reg["install_hash"] = json!(b64(&Sha256::digest(secret)));
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&other), Some(reg)).await.0, StatusCode::FORBIDDEN);
}

/// New backup contents under the SAME recovery key append a blob: the key (one row, its age
/// untouched) is what is valid; earlier contents stay on record and restorable, and no blob is
/// ever rewritten in place. Blobs go only once their key is retired and the hold has passed.
#[tokio::test]
async fn new_backup_contents_under_the_same_key_append_a_blob() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let key = [0x11u8; 32];
    put_backup_contents(&app, &token, &device_store, &user_id, &key, b"contents v1").await;
    elapse(&state, &user_id, 30 * DAY).await;
    let instant_from = devices(&app, &token).await["recovery_key_instant_from"].as_i64();
    let first: (String, Vec<u8>) = sqlx::query_as("SELECT id, encrypted_blob FROM backup_blobs").fetch_one(&state.db).await.unwrap();

    let mut bus = state.rt.subscribe();
    put_backup_contents(&app, &token, &device_store, &user_id, &key, b"contents v2").await;
    let events: Vec<String> = std::iter::from_fn(|| bus.try_recv().ok()).map(|ev| ev.frame).collect();
    assert!(events.iter().any(|f| f.contains("backup_updated")), "announced: {events:?}");
    assert!(!events.iter().any(|f| f.contains("recovery_key_changed")), "…as new contents, not as a change of key");
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_keys").fetch_one(&state.db).await.unwrap(), 1, "one key, still");
    let blobs: Vec<(String, Vec<u8>)> = sqlx::query_as("SELECT id, encrypted_blob FROM backup_blobs ORDER BY created_at, id").fetch_all(&state.db).await.unwrap();
    assert_eq!(blobs.len(), 2, "a blob was appended");
    assert!(blobs.contains(&first), "the first blob still holds what it held");
    let listing = devices(&app, &token).await;
    assert_eq!(listing["recovery_key_instant_from"].as_i64(), instant_from, "the key did not start over");
    assert!(listing["recovery_key_changed_at"].is_null());
    let anyone = login(&app, "alice").await;
    assert_eq!(offered_backups(&app, &anyone).await, [b"contents v2".to_vec(), b"contents v1".to_vec()], "a restore is offered both");
    // The same contents again: nothing is recorded.
    put_backup_contents(&app, &token, &device_store, &user_id, &key, b"contents v2").await;
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_blobs").fetch_one(&state.db).await.unwrap(), 2);
    // Time alone removes nothing while the key is in force…
    elapse(&state, &user_id, 30 * DAY).await;
    put_backup_contents(&app, &token, &device_store, &user_id, &key, b"contents v3").await;
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_blobs").fetch_one(&state.db).await.unwrap(), 3);
    // And the key still restores at once (it never left force).
    let (status, body) = restore_with(&app, &device_store, &key, &[42u8; 32], &user_id, &device).await;
    assert_eq!((status, body["generation"].as_i64(), body["recovery_key_consumed"].as_bool()), (StatusCode::OK, Some(1), Some(false)), "{body}");
}

/// Validity is the KEY's, not a blob's. After a compromise, no key that was still valid — the
/// one in force, one in its overlap — proves anything, and none of the blobs under any of them
/// (however many versions, however recent) is served. Nothing un-retires them.
#[tokio::test]
async fn after_a_compromise_no_key_and_no_old_blob_of_any_key_is_usable() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let (old, current) = ([0x11u8; 32], [0x22u8; 32]);
    // An old key with two versions of contents, seasoned, then replaced (it is in its overlap)…
    put_backup_contents(&app, &token, &device_store, &user_id, &old, b"old v1").await;
    put_backup_contents(&app, &token, &device_store, &user_id, &old, b"old v2").await;
    elapse(&state, &user_id, 30 * DAY).await;
    // …by the current key, which seasons and gathers versions of its own.
    put_backup_contents(&app, &token, &device_store, &user_id, &current, b"current v1").await;
    put_backup_contents(&app, &token, &device_store, &user_id, &current, b"current v2").await;
    sqlx::query("UPDATE backup_keys SET set_at = set_at - $1 WHERE retired_at IS NULL").bind(8 * DAY).execute(&state.db).await.unwrap();
    let anyone = login(&app, "alice").await;
    assert_eq!(offered_backups(&app, &anyone).await.len(), 4, "before: both keys are valid, every version is offered");

    let (status, body) = send_proved(&app, "POST", "/api/e2ee/key-backup/compromised", &token, None, &proof(&device_store, "backup-compromised", &user_id, "backup", b"")).await;
    assert_eq!((status, body["retired"].as_bool()), (StatusCode::OK, Some(true)));
    // EVERY key that was still valid is retired as compromised, as of now.
    let keys_now: Vec<(Option<String>, Option<i64>)> = sqlx::query_as("SELECT retire_reason, retired_at FROM backup_keys").fetch_all(&state.db).await.unwrap();
    assert_eq!(keys_now.len(), 2);
    assert!(keys_now.iter().all(|(reason, at)| reason.as_deref() == Some("compromised") && at.is_some_and(|t| t <= now_ms())), "{keys_now:?}");
    // The blobs are still on record (four of them) — and not one is served or usable.
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_blobs").fetch_one(&state.db).await.unwrap(), 4);
    assert!(offered_backups(&app, &anyone).await.is_empty(), "nothing is served");
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&anyone), Some(json!({}))).await.0, StatusCode::NOT_FOUND, "there is no key to prove");
    // A proof needs a nonce; give the attacker one anyway (as if issued before) and try both keys.
    for key in [&old, &current] {
        let session = login(&app, "alice").await;
        sqlx::query("INSERT INTO backup_auth_nonces (nonce, user_id, session_hash, created_at) VALUES ('planted-nonce', $1, $2, $3)")
            .bind(&user_id)
            .bind(Sha256::digest(session.as_bytes()).to_vec())
            .bind(now_ms())
            .execute(&state.db)
            .await
            .unwrap();
        let secret = [7u8; 32];
        let message = skwod_crypto::backup::recovery_auth_message(&user_id, "rekey", device.as_bytes(), "planted-nonce", &Sha256::digest(secret));
        let auth = b64(&skwod_crypto::backup::sign_recovery_auth(key, &message).unwrap());
        let mut restored = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
        let (status, body) = rekey_with_recovery_key(&app, &session, &mut restored, &secret, &user_id, &device, &auth).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_ne!(body["error"], "device recovery pending", "the proof is not even recognised");
        sqlx::query("DELETE FROM backup_auth_nonces").execute(&state.db).await.unwrap();
    }
    assert_eq!(devices(&app, &token).await["devices"][0]["generation"], 0);
    // Time does not bring any of it back; in the end the sweep takes the blobs.
    elapse(&state, &user_id, 30 * DAY).await;
    assert!(offered_backups(&app, &anyone).await.is_empty());
    put_backup_contents(&app, &token, &device_store, &user_id, &[0x33u8; 32], b"new key").await;
    let left: Vec<Vec<u8>> = sqlx::query_scalar("SELECT encrypted_blob FROM backup_blobs").fetch_all(&state.db).await.unwrap();
    assert_eq!(left, [b"new key".to_vec()], "blobs go once their key is retired and the hold has passed");
}

/// Replacing an UNSEASONED key leaves nothing of it usable: the key is retired on the spot, so
/// no proof by it counts and none of its blobs — any version — is served. (A blob cannot keep
/// its key alive.) And replacing a SEASONED key leaves all of its versions usable for the hold.
#[tokio::test]
async fn replacing_an_unseasoned_key_leaves_no_usable_blob_of_it() {
    let (app, state) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (device_store, device) = first_device(&app, &token).await;
    let (owners, planted, next) = ([0x11u8; 32], [0x66u8; 32], [0x77u8; 32]);
    put_backup_contents(&app, &token, &device_store, &user_id, &owners, b"owner v1").await;
    put_backup_contents(&app, &token, &device_store, &user_id, &owners, b"owner v2").await;
    elapse(&state, &user_id, 30 * DAY).await;
    // A planted key, several versions — never seasoned — then replaced by yet another.
    put_backup_contents(&app, &token, &device_store, &user_id, &planted, b"planted v1").await;
    put_backup_contents(&app, &token, &device_store, &user_id, &planted, b"planted v2").await;
    elapse(&state, &user_id, DAY).await;
    put_backup_contents(&app, &token, &device_store, &user_id, &next, b"next v1").await;

    let (reason, retired_at, replaced_at): (String, i64, i64) =
        sqlx::query_as("SELECT retire_reason, retired_at, replaced_at FROM backup_keys WHERE verifier = $1").bind(skwod_crypto::backup::recovery_verifier(&planted).unwrap()).fetch_one(&state.db).await.unwrap();
    assert_eq!((reason.as_str(), retired_at), ("replaced", replaced_at), "retired the moment it was replaced: no overlap for a key that never seasoned");
    // Its blobs exist — and are not served; the owner's (seasoned, in overlap) are, all versions.
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_blobs b JOIN backup_keys k ON k.id = b.key_id WHERE k.retire_reason = 'replaced' AND k.retired_at = k.replaced_at").fetch_one(&state.db).await.unwrap(), 2);
    let anyone = login(&app, "alice").await;
    let offered = offered_backups(&app, &anyone).await;
    assert!(!offered.iter().any(|b| b.starts_with(b"planted")), "{offered:?}");
    assert!(offered.contains(&b"owner v1".to_vec()) && offered.contains(&b"owner v2".to_vec()));
    assert!(!offered.contains(&b"next v1".to_vec()), "the newest key is unseasoned: only a current device is served its blob (audit M4)");
    assert!(offered_backups(&app, &token).await.contains(&b"next v1".to_vec()));
    // No proof by the planted key is recognised — now, or after it "would have" seasoned.
    for wait in [0, 30 * DAY] {
        // (the owner's window is still open only in the first round; the planted key is dead in both)
        elapse(&state, &user_id, wait).await;
        let token = login(&app, "alice").await;
        let (status, challenge) = send(&app, "POST", "/api/e2ee/key-backup/challenge", Some(&token), Some(json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{challenge}");
        let secret = [7u8; 32];
        let message = skwod_crypto::backup::recovery_auth_message(&user_id, "rekey", device.as_bytes(), challenge["nonce"].as_str().unwrap(), &Sha256::digest(secret));
        let auth = b64(&skwod_crypto::backup::sign_recovery_auth(&planted, &message).unwrap());
        let mut restored = SignalStore::from_bytes(&device_store.export_identity()).unwrap();
        let (status, body) = rekey_with_recovery_key(&app, &token, &mut restored, &secret, &user_id, &device, &auth).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_ne!(body["error"], "device recovery pending", "wait {wait}: not recognised at all");
    }
}

/// The two build-44 batches meet in the mailbox poll: a build ≤ 42 on a pre-migration device is
/// told to UPDATE (the one answer it can show), while the device checks still come first for a
/// device that is not the caller's — "update" is never the answer to someone else's device id.
#[tokio::test]
async fn an_old_build_on_a_legacy_device_is_told_to_update_but_only_about_its_own_device() {
    let (app, state) = app().await;
    let (user_id, old_session) = signup(&app, "alice").await;
    let old = SignalStore::generate();
    legacy_device(&state, &user_id, &old).await;
    sqlx::query("UPDATE sessions SET pre_migration = 1").execute(&state.db).await.unwrap();
    let inbox = "/api/e2ee/sealed/inbox?device_id=old-device";
    assert_eq!(send(&app, "GET", inbox, Some(&old_session), None).await.0, StatusCode::OK);

    // It behaves like a build ≤ 42 (a channel send without an id of its own does this).
    crate::oldbuilds::seen_old(&state, &user_id, Some("old-device"));
    let (status, body) = send(&app, "GET", inbox, Some(&old_session), None).await;
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED, "{body}");
    assert!(body["error"].as_str().unwrap().contains("https://skwod.io/download"));
    // A session of the same account made after the migration cannot use the row with
    // authority, but an old build polling through it still gets the sentence it can show.
    let newcomer = login(&app, "alice").await;
    assert_eq!(send(&app, "GET", inbox, Some(&newcomer), None).await.0, StatusCode::UPGRADE_REQUIRED);

    // Somebody else naming that device id learns nothing about it: the device check answers.
    let (_, mallory) = signup(&app, "mallory").await;
    let (status, body) = send(&app, "GET", inbox, Some(&mallory), None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")), "not a device of the caller");

    // Updated: it is forgotten as old and polls normally again.
    crate::oldbuilds::seen_current(&state, &user_id, Some("old-device"));
    assert_eq!(send(&app, "GET", inbox, Some(&old_session), None).await.0, StatusCode::OK);
}
