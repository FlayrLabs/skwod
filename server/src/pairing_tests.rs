//! Build 48: "Add a device" by QR without a password — the server's half (`pairing.rs`).

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};
use skwod_crypto::SignalStore;

use crate::accounts_tests::{b64, first_device, proof};
use crate::pairing::{claim_payload, offer_payload, CLAIM_OP};
use crate::state::{now_ms, AppState};
use crate::tests::{send, send_proved, signup, test_state};

async fn app() -> (AppState, Router) {
    let mut state = test_state().await;
    state.qr_pairing = true;
    (state.clone(), crate::api::router(state))
}

fn offer() -> String {
    hex::encode(skwod_crypto::random_bytes::<16>())
}

/// A new device's pair request for `offer`: (store, poll secret, request body).
fn request(username: &str, offer: &str) -> (SignalStore, [u8; 32], Value) {
    let store = SignalStore::generate();
    let secret = skwod_crypto::random_bytes::<32>();
    let body = json!({ "username": username, "offer_id": offer, "identity_key": b64(&store.identity_key()), "proof": b64(&[7u8; 32]), "poll_secret": b64(&secret) });
    (store, secret, body)
}

/// The existing device registers the offer its QR shows (device-signed).
async fn register_offer(app: &Router, token: &str, device: &SignalStore, user_id: &str, username: &str, offer: &str) -> StatusCode {
    let expires = now_ms() + 5 * 60 * 1000;
    let p = proof(device, "pair-offer", user_id, offer, &offer_payload(expires, username));
    send_proved(app, "POST", "/api/e2ee/pair-offers", token, Some(json!({ "offer_id": offer, "expires_at": expires })), &p).await.0
}

async fn create(app: &Router, body: &Value) -> (StatusCode, Value) {
    send(app, "POST", "/api/e2ee/pair-requests", None, Some(body.clone())).await
}

/// The new device's claim, signed by `signer` (normally its own identity key).
async fn claim(app: &Router, id: &str, user_id: &str, offer: &str, secret: &[u8; 32], signer: &SignalStore) -> (StatusCode, Value) {
    let ts = now_ms();
    let sig = signer.sign_device_op(CLAIM_OP, user_id, id, ts as u64, &claim_payload(offer, secret)).unwrap();
    send(app, "POST", &format!("/api/e2ee/pair-requests/{id}/claim"), None, Some(json!({ "poll_secret": b64(secret), "timestamp": ts, "signature": b64(&sig) }))).await
}

/// The existing device releases its nonce for the key it saw.
async fn reveal(app: &Router, token: &str, id: &str, identity: &[u8], nonce: &[u8; 32]) -> (StatusCode, Value) {
    send(app, "POST", &format!("/api/e2ee/pair-requests/{id}/reveal"), Some(token), Some(json!({ "identity_key": b64(identity), "nonce": b64(nonce) }))).await
}

async fn approve(app: &Router, token: &str, linker: &SignalStore, linker_dev: &str, user_id: &str, id: &str, identity: &[u8]) -> (StatusCode, Value) {
    let sig = b64(&linker.sign_link(user_id, identity).unwrap());
    let body = json!({ "device_id": linker_dev, "signature": sig, "approval_mac": b64(&[0u8; 32]), "identity_key": b64(identity) });
    send(app, "POST", &format!("/api/e2ee/pair-requests/{id}/approve"), Some(token), Some(body)).await
}

#[tokio::test]
async fn off_unless_the_operator_turns_it_on() {
    let state = test_state().await;
    assert!(!state.qr_pairing);
    let app = crate::api::router(state);
    let (_, _, body) = request("alice", &offer());
    assert_eq!(create(&app, &body).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_pairing_without_a_password_gives_one_session_to_the_approved_key_only() {
    let (_state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    assert_eq!(register_offer(&app, &token, &linker, &user_id, "alice", &o).await, StatusCode::OK);
    // A token alone (no device proof) cannot register an offer.
    let unsigned = send(&app, "POST", "/api/e2ee/pair-offers", Some(&token), Some(json!({ "offer_id": offer(), "expires_at": now_ms() + 60_000 }))).await.0;
    assert_ne!(unsigned, StatusCode::OK);
    let (store, secret, body) = request("alice", &o);
    let (status, created) = create(&app, &body).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let id = created["request_id"].as_str().unwrap().to_string();
    // Retrying the same request is idempotent.
    assert_eq!(create(&app, &body).await.1["request_id"], created["request_id"]);

    // Not in the typed-code flow: not listed there, not approvable there.
    let (_, listed) = send(&app, "GET", "/api/e2ee/link-requests", Some(&token), None).await;
    assert_eq!(listed["requests"].as_array().unwrap().len(), 0, "{listed}");
    let sig = b64(&linker.sign_link(&user_id, &store.identity_key()).unwrap());
    let via_link = json!({ "device_id": linker_dev, "signature": sig, "approval_mac": b64(&[0u8; 32]) });
    assert_eq!(send(&app, "POST", &format!("/api/e2ee/link-requests/{id}/approve"), Some(&token), Some(via_link)).await.0, StatusCode::NOT_FOUND);

    // Before approval: nothing to claim. A claim not signed by the request's key: "not yet".
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.1["approved"], false);
    let stranger = SignalStore::generate();
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &stranger).await.1, json!({ "approved": false }));

    // The existing device reads it by offer, and approves exactly that key (not another).
    let (_, seen) = send(&app, "GET", &format!("/api/e2ee/pair-requests/by-offer/{o}"), Some(&token), None).await;
    assert_eq!((seen["request_id"].as_str(), seen["contested"].as_bool()), (Some(id.as_str()), Some(false)), "{seen}");
    assert_eq!(seen["revealed"], false);
    // Nothing is approved before the nonce was released (the emoji depend on it).
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await.0, StatusCode::BAD_REQUEST);
    // The nonce is released for the key that was seen, never for another, and only once.
    let nonce = [5u8; 32];
    assert_eq!(reveal(&app, &token, &id, &stranger.identity_key(), &nonce).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.1["nonce"], Value::Null, "nothing revealed yet");
    assert_eq!(reveal(&app, &token, &id, &store.identity_key(), &nonce).await.0, StatusCode::OK);
    assert_eq!(reveal(&app, &token, &id, &store.identity_key(), &nonce).await.0, StatusCode::OK, "idempotent");
    assert_eq!(reveal(&app, &token, &id, &store.identity_key(), &[6u8; 32]).await.0, StatusCode::CONFLICT, "one nonce");
    // Only the request's own device (key + secret) is handed the nonce.
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.1["nonce"], json!(b64(&nonce)));
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &stranger).await.1, json!({ "approved": false }));
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &stranger.identity_key()).await.0, StatusCode::BAD_REQUEST);
    let (status, body) = approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await.0, StatusCode::NOT_FOUND, "once");

    // The poll secret alone (signed by another key) gets no session, even now.
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &stranger).await.1, json!({ "approved": false }));
    // A wrong secret with the right key: nothing either.
    assert_eq!(claim(&app, &id, &user_id, &o, &[1u8; 32], &store).await.1, json!({ "approved": false }));
    let (status, got) = claim(&app, &id, &user_id, &o, &secret, &store).await;
    assert_eq!((status, got["approved"].as_bool()), (StatusCode::OK, Some(true)), "{got}");
    let session = got["session"]["token"].as_str().unwrap();
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(session), None).await.0, StatusCode::OK);
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.0, StatusCode::NOT_FOUND, "one session");

    // That session registers the approved key as a linked device; nothing else does.
    let mut store = store;
    // (The signature the approval carries: libsignal signatures are randomised.)
    let link_sig = got["signature"].as_str().unwrap().to_string();
    let mut other = SignalStore::generate();
    let (mut wrong, _) = crate::accounts_tests::keys(&mut other);
    wrong["link"] = json!({ "device_id": linker_dev, "signature": b64(&linker.sign_link(&user_id, &other.identity_key()).unwrap()) });
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(session), Some(wrong)).await.0, StatusCode::FORBIDDEN);
    let (mut body, _) = crate::accounts_tests::keys(&mut store);
    body["link"] = json!({ "device_id": linker_dev, "signature": link_sig });
    crate::accounts_tests::register(&app, session, body).await;
}

#[tokio::test]
async fn a_second_request_never_replaces_the_first_and_contests_the_offer() {
    let (_state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (mine, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    // The second request looks accepted from outside, but it is a decoy: nothing stored for it.
    let (_, _, theirs) = request("alice", &o);
    let (status, decoy) = create(&app, &theirs).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(decoy["request_id"], json!(id));

    // The first request is still the one there — but the offer is contested: nobody gets in.
    let (_, seen) = send(&app, "GET", &format!("/api/e2ee/pair-requests/by-offer/{o}"), Some(&token), None).await;
    assert_eq!(seen["request_id"].as_str(), Some(id.as_str()));
    assert_eq!(seen["identity_key"].as_str(), Some(b64(&mine.identity_key()).as_str()));
    assert_eq!(seen["contested"], true);
    assert_eq!(reveal(&app, &token, &id, &mine.identity_key(), &[5u8; 32]).await.0, StatusCode::CONFLICT, "no nonce for a contested offer");
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &mine.identity_key()).await.0, StatusCode::CONFLICT);
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &mine).await.0, StatusCode::NOT_FOUND, "its own device learns it");
}

/// From outside, a request for an unknown offer, another username or a malformed body is
/// answered exactly like a valid one, and stores nothing. Without an offer the owner made, an
/// attacker can neither probe usernames nor get in the way of the owner's pairing.
#[tokio::test]
async fn without_a_registered_offer_nothing_is_stored_and_nothing_is_told() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;

    let shape = |v: &Value| (v["request_id"].is_string(), v["expires_at"].is_i64(), v.as_object().unwrap().len());
    let (_, _, valid) = request("alice", &o);
    let (status, real) = create(&app, &valid).await;
    assert_eq!(status, StatusCode::OK);
    let mut attempts = Vec::new();
    for username in ["alice", "bob_nobody"] {
        for _ in 0..8 {
            attempts.push(request(username, &offer()).2); // offers nobody registered
        }
    }
    attempts.push(request("bob_nobody", &o).2); // the right offer, the wrong account
    let mut junk = valid.clone();
    junk["identity_key"] = json!("not base64!");
    attempts.push(junk);
    for body in &attempts {
        let (status, got) = create(&app, body).await;
        assert_eq!((status, shape(&got)), (StatusCode::OK, shape(&real)), "{got}");
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_pair_requests").fetch_one(&state.db).await.unwrap();
    assert_eq!(n, 1, "only the owner's request exists");
    let (_, seen) = send(&app, "GET", &format!("/api/e2ee/pair-requests/by-offer/{o}"), Some(&token), None).await;
    assert_eq!(seen["contested"], false, "none of that touched the owner's offer");

    // The owner's pairing still completes.
    let (store, secret, body) = request("alice", &offer());
    let o2 = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o2).await;
    let mut body = body;
    body["offer_id"] = json!(o2);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    assert_eq!(reveal(&app, &token, &id, &store.identity_key(), &[5u8; 32]).await.0, StatusCode::OK);
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await.0, StatusCode::OK);
    assert_eq!(claim(&app, &id, &user_id, &o2, &secret, &store).await.1["approved"], true);
    // A decoy request id never completes.
    let (_, _, d) = request("alice", &offer());
    let decoy = create(&app, &d).await.1["request_id"].as_str().unwrap().to_string();
    assert_eq!(claim(&app, &decoy, &user_id, &o, &secret, &store).await.1, json!({ "approved": false }));
}

#[tokio::test]
async fn an_expired_or_denied_request_is_refused() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;

    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (store, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    sqlx::query("UPDATE device_pair_requests SET created_at = $1 WHERE id = $2").bind(now_ms() - 11 * 60 * 1000).bind(&id).execute(&state.db).await.unwrap();
    assert_eq!(send(&app, "GET", &format!("/api/e2ee/pair-requests/by-offer/{o}"), Some(&token), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await.0, StatusCode::NOT_FOUND);
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.0, StatusCode::NOT_FOUND);

    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (store, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    assert_eq!(send(&app, "DELETE", &format!("/api/e2ee/pair-requests/{id}"), Some(&token), None).await.0, StatusCode::OK);
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.0, StatusCode::NOT_FOUND);
}

/// Over p2p — the only way a new device reaches a host — the create asks for a proof-of-work stamp
/// (the app's proxy attaches it), and the polled claim does not.
#[tokio::test]
async fn over_p2p_the_create_needs_work_and_the_claim_does_not() {
    use axum::body::Body;
    use axum::http::{header, Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let (state, app) = app().await;
    let host = [9u8; 32];
    let _ = state.p2p.set(crate::p2p::P2pStatus { node_id: "host".into(), node_bytes: host, public_fallback: true });
    let node = [4u8; 32];
    let peer = crate::client_key::P2pPeer { node: "newdevice".into(), node_bytes: node, relayed: false };
    let post = |path: String, body: Value, stamp: Option<String>| {
        let app = app.clone().layer(axum::Extension(peer.clone()));
        async move {
            let mut req = Request::builder().method("POST").uri(path).header(header::CONTENT_TYPE, "application/json");
            if let Some(s) = stamp {
                req = req.header(skwod_net::pow::POW_HEADER, s);
            }
            let res = app.oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
            let status = res.status();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null))
        }
    };
    let (_, _, body) = request("alice", &offer());
    assert_eq!(post("/api/e2ee/pair-requests".into(), body.clone(), None).await.0, StatusCode::PRECONDITION_REQUIRED, "no stamp, no request");
    let stamp = skwod_net::pow::solve_for(skwod_net::pow::Purpose::Request, &host, &node, skwod_net::pow::current_window(), skwod_net::pow::POW_BITS);
    let (status, made) = post("/api/e2ee/pair-requests".into(), body, Some(stamp)).await;
    assert_eq!(status, StatusCode::OK, "a stamped request is answered");
    let id = made["request_id"].as_str().unwrap().to_string();
    let claim = json!({ "poll_secret": b64(&[1u8; 32]), "timestamp": now_ms(), "signature": b64(&[0u8; 64]) });
    for _ in 0..5 {
        let (status, v) = post(format!("/api/e2ee/pair-requests/{id}/claim"), claim.clone(), None).await;
        assert_eq!((status, v["approved"].clone()), (StatusCode::OK, json!(false)), "polling the claim asks no work");
    }
}

/// A whole pairing up to the claimed session: (new device store, request id, session token, link
/// signature the approval carried).
async fn paired(app: &Router, token: &str, linker: &SignalStore, linker_dev: &str, user_id: &str, o: &str) -> (SignalStore, String, String, String) {
    let (store, secret, body) = request("alice", o);
    let id = create(app, &body).await.1["request_id"].as_str().unwrap().to_string();
    assert_eq!(reveal(app, token, &id, &store.identity_key(), &[5u8; 32]).await.0, StatusCode::OK);
    assert_eq!(approve(app, token, linker, linker_dev, user_id, &id, &store.identity_key()).await.0, StatusCode::OK);
    let (_, got) = claim(app, &id, user_id, o, &secret, &store).await;
    assert_eq!(got["approved"], true, "{got}");
    (store, id, got["session"]["token"].as_str().unwrap().to_string(), got["signature"].as_str().unwrap().to_string())
}

async fn rows_for(state: &AppState, o: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM device_pair_requests WHERE offer_id = $1").bind(o).fetch_one(&state.db).await.unwrap()
}

/// M1/L1: once a device registered on an offer, the row is marked (not deleted) and the offer
/// consumed — a later request for the same, still unexpired offer opens nothing.
#[tokio::test]
async fn after_register_the_offer_opens_nothing_again() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (mut store, id, session, link_sig) = paired(&app, &token, &linker, &linker_dev, &user_id, &o).await;
    let (mut body, _) = crate::accounts_tests::keys(&mut store);
    body["link"] = json!({ "device_id": linker_dev, "signature": link_sig });
    crate::accounts_tests::register(&app, &session, body).await;
    let registered: i64 = sqlx::query_scalar("SELECT registered FROM device_pair_requests WHERE id = $1").bind(&id).fetch_one(&state.db).await.unwrap();
    assert_eq!(registered, 1, "marked, not deleted");

    let (_, _, again) = request("alice", &o);
    let (status, decoy) = create(&app, &again).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(decoy["request_id"], json!(id));
    assert_eq!(rows_for(&state, &o).await, 1, "nothing new stored for a used offer");
}

/// L1: approve, deny and contest each consume the offer.
#[tokio::test]
async fn approve_deny_and_contest_consume_the_offer() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let consumed = |o: String| {
        let db = state.db.clone();
        async move { sqlx::query_scalar::<_, i64>("SELECT consumed FROM device_pair_offers WHERE offer_id = $1").bind(o).fetch_one(&db).await.unwrap() }
    };

    // Approved (not yet claimed): no new request, and the approved device still claims.
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (store, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    reveal(&app, &token, &id, &store.identity_key(), &[5u8; 32]).await;
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await.0, StatusCode::OK);
    assert_eq!(consumed(o.clone()).await, 1);
    create(&app, &request("alice", &o).2).await;
    let contested: i64 = sqlx::query_scalar("SELECT contested FROM device_pair_requests WHERE id = $1").bind(&id).fetch_one(&state.db).await.unwrap();
    assert_eq!((rows_for(&state, &o).await, contested), (1, 0), "a used offer is neither reopened nor disturbed");
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.1["approved"], true);

    // Denied.
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let id = create(&app, &request("alice", &o).2).await.1["request_id"].as_str().unwrap().to_string();
    assert_eq!(send(&app, "DELETE", &format!("/api/e2ee/pair-requests/{id}"), Some(&token), None).await.0, StatusCode::OK);
    assert_eq!(consumed(o.clone()).await, 1);
    create(&app, &request("alice", &o).2).await;
    assert_eq!(rows_for(&state, &o).await, 1);

    // Contested.
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    create(&app, &request("alice", &o).2).await;
    create(&app, &request("alice", &o).2).await;
    assert_eq!(consumed(o.clone()).await, 1);
}

/// L1: every step looks at the offer's own expiry, not only the request's age.
#[tokio::test]
async fn every_step_checks_the_offers_expiry() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let expire = |o: String| {
        let db = state.db.clone();
        async move { sqlx::query("UPDATE device_pair_offers SET expires_at = $1 WHERE offer_id = $2").bind(now_ms() - 1).bind(o).execute(&db).await.unwrap() }
    };

    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (store, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    expire(o.clone()).await;
    assert_eq!(send(&app, "GET", &format!("/api/e2ee/pair-requests/by-offer/{o}"), Some(&token), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(reveal(&app, &token, &id, &store.identity_key(), &[5u8; 32]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await.0, StatusCode::NOT_FOUND);
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.0, StatusCode::NOT_FOUND);

    // L3 + register: claimed, then the offer lapses before the device registered. The register
    // is refused and the session revoked.
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (mut store, _, session, link_sig) = paired(&app, &token, &linker, &linker_dev, &user_id, &o).await;
    expire(o.clone()).await;
    let (mut body, _) = crate::accounts_tests::keys(&mut store);
    body["link"] = json!({ "device_id": linker_dev, "signature": link_sig });
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&session), Some(body)).await.0, StatusCode::FORBIDDEN);
    // Any pairing traffic sweeps; the claimed, unregistered session is gone.
    create(&app, &request("alice", &offer()).2).await;
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&session), None).await.0, StatusCode::UNAUTHORIZED);
}

/// L1: an offer lives at most five minutes, whatever the device asks (a little clock skew is
/// tolerated and cut back).
#[tokio::test]
async fn offer_lifetimes_are_capped_at_five_minutes() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, _) = first_device(&app, &token).await;
    let post = |o: String, expires: i64| {
        let (app, token, linker, user_id) = (app.clone(), token.clone(), linker.clone(), user_id.clone());
        async move {
            let p = proof(&linker, "pair-offer", &user_id, &o, &offer_payload(expires, "alice"));
            send_proved(&app, "POST", "/api/e2ee/pair-offers", &token, Some(json!({ "offer_id": o, "expires_at": expires })), &p).await.0
        }
    };
    let o = offer();
    let before = now_ms();
    assert_eq!(post(o.clone(), before + 5 * 60 * 1000 + 30_000).await, StatusCode::OK, "30 s of skew is fine");
    let stored: i64 = sqlx::query_scalar("SELECT expires_at FROM device_pair_offers WHERE offer_id = $1").bind(&o).fetch_one(&state.db).await.unwrap();
    assert!(stored <= now_ms() + 5 * 60 * 1000, "stored as at most five minutes");
    assert_eq!(post(offer(), now_ms() + 10 * 60 * 1000).await, StatusCode::BAD_REQUEST);
}

/// L2: signature-checked claims have a ceiling per request — and only a caller holding the
/// request's poll secret is counted, so a flood of wrong guesses never blocks the real device.
#[tokio::test]
async fn bad_claims_never_use_up_the_real_devices_ceiling() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (store, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    let flood = json!({ "poll_secret": b64(&[1u8; 32]), "timestamp": now_ms(), "signature": b64(&[0u8; 64]) });
    for _ in 0..(crate::pairing::CLAIM_PER_REQUEST_PER_MINUTE + 40) {
        assert_eq!(send(&app, "POST", &format!("/api/e2ee/pair-requests/{id}/claim"), None, Some(flood.clone())).await.1, json!({ "approved": false }));
    }
    reveal(&app, &token, &id, &store.identity_key(), &[5u8; 32]).await;
    approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await;
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.1["approved"], true, "the flood cost the real device nothing");

    // The ceiling itself: a request's holder that polls far too fast is slowed down.
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (store, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    for _ in 0..crate::pairing::CLAIM_PER_REQUEST_PER_MINUTE {
        state.limiter.check(&format!("pair_claim:request:{id}"), crate::pairing::CLAIM_PER_REQUEST_PER_MINUTE, crate::limiter::MINUTE).unwrap();
    }
    assert_eq!(claim(&app, &id, &user_id, &o, &secret, &store).await.0, StatusCode::TOO_MANY_REQUESTS);
}

async fn sessions_of(state: &AppState, user_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE user_id = $1").bind(user_id).fetch_one(&state.db).await.unwrap()
}

/// Two claims at once: exactly one session, and no stray one for the loser.
#[tokio::test]
async fn racing_claims_hand_out_exactly_one_session() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (store, secret, body) = request("alice", &o);
    let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
    reveal(&app, &token, &id, &store.identity_key(), &[5u8; 32]).await;
    approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await;
    let before = sessions_of(&state, &user_id).await;
    let (a, b) = tokio::join!(claim(&app, &id, &user_id, &o, &secret, &store), claim(&app, &id, &user_id, &o, &secret, &store));
    let won = [&a, &b].iter().filter(|r| r.1["approved"] == true).count();
    assert_eq!(won, 1, "{a:?} {b:?}");
    assert_eq!(sessions_of(&state, &user_id).await, before + 1, "no orphan session for the losing claim");
}

/// A claim racing a contest: whichever lands first, no session survives (deleted by the losing
/// claim, or revoked by the contest).
#[tokio::test]
async fn a_claim_racing_a_contest_leaves_no_session() {
    for _ in 0..5 {
        let (state, app) = app().await;
        let (user_id, token) = signup(&app, "alice").await;
        let (linker, linker_dev) = first_device(&app, &token).await;
        let o = offer();
        register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
        let (store, secret, body) = request("alice", &o);
        let id = create(&app, &body).await.1["request_id"].as_str().unwrap().to_string();
        reveal(&app, &token, &id, &store.identity_key(), &[5u8; 32]).await;
        approve(&app, &token, &linker, &linker_dev, &user_id, &id, &store.identity_key()).await;
        let before = sessions_of(&state, &user_id).await;
        let _ = tokio::join!(claim(&app, &id, &user_id, &o, &secret, &store), crate::pairing::contest_for_tests(&state, &o));
        assert_eq!(sessions_of(&state, &user_id).await, before);
    }
}

/// Two registrations on one claimed session at once: one device, never two. And a register
/// racing a contest never ends with a registered device whose request was contested.
#[tokio::test]
async fn racing_registers_admit_one_device() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (mut store, _, session, link_sig) = paired(&app, &token, &linker, &linker_dev, &user_id, &o).await;
    let (mut body, _) = crate::accounts_tests::keys(&mut store);
    body["link"] = json!({ "device_id": linker_dev, "signature": link_sig });
    let (a, b) = tokio::join!(
        send(&app, "POST", "/api/e2ee/devices/register", Some(&session), Some(body.clone())),
        send(&app, "POST", "/api/e2ee/devices/register", Some(&session), Some(body.clone()))
    );
    let ok = [&a, &b].iter().filter(|r| r.0 == StatusCode::OK).count();
    assert_eq!(ok, 1, "{a:?} {b:?}");
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE user_id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap();
    assert_eq!(devices, 2);

    for _ in 0..5 {
        let o = offer();
        register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
        let (mut store, id, session, link_sig) = paired(&app, &token, &linker, &linker_dev, &user_id, &o).await;
        let (mut body, _) = crate::accounts_tests::keys(&mut store);
        body["link"] = json!({ "device_id": linker_dev, "signature": link_sig });
        let (r, _) = tokio::join!(send(&app, "POST", "/api/e2ee/devices/register", Some(&session), Some(body)), crate::pairing::contest_for_tests(&state, &o));
        let (registered, contested): (i64, i64) = sqlx::query_as("SELECT registered, contested FROM device_pair_requests WHERE id = $1").bind(&id).fetch_one(&state.db).await.unwrap();
        assert!(!(registered == 1 && contested == 1), "both registered and contested");
        assert_eq!(r.0 == StatusCode::OK, registered == 1, "{r:?}");
        if registered == 1 {
            // Remove it again so the account stays under its device limit.
            let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_devices WHERE user_id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap();
            assert!(n >= 3);
            sqlx::query("DELETE FROM user_devices WHERE user_id = $1 AND identity_key = $2").bind(&user_id).bind(store.identity_key()).execute(&state.db).await.unwrap();
        }
    }
}

/// L3: a session claimed for a request that is then contested (before it registered) is revoked,
/// and cannot register.
#[tokio::test]
async fn a_claimed_session_is_revoked_when_the_request_is_contested() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, linker_dev) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let (mut store, _, session, link_sig) = paired(&app, &token, &linker, &linker_dev, &user_id, &o).await;
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&session), None).await.0, StatusCode::OK);
    // The offer is consumed by the approval, so a second request no longer contests it...
    create(&app, &request("alice", &o).2).await;
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&session), None).await.0, StatusCode::OK);
    // ...but a contest that does land (a race) revokes the claimed session.
    crate::pairing::contest_for_tests(&state, &o).await;
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&session), None).await.0, StatusCode::UNAUTHORIZED);
    let (mut body, _) = crate::accounts_tests::keys(&mut store);
    body["link"] = json!({ "device_id": linker_dev, "signature": link_sig });
    assert_ne!(send(&app, "POST", "/api/e2ee/devices/register", Some(&session), Some(body)).await.0, StatusCode::OK);
}

/// L4: only a session bound to a current device may deny, and only so often.
#[tokio::test]
async fn deny_needs_a_bound_device_session_and_is_rate_limited() {
    let (state, app) = app().await;
    let (user_id, token) = signup(&app, "alice").await;
    let (linker, _) = first_device(&app, &token).await;
    let o = offer();
    register_offer(&app, &token, &linker, &user_id, "alice", &o).await;
    let id = create(&app, &request("alice", &o).2).await.1["request_id"].as_str().unwrap().to_string();
    let unbound = crate::tests::login(&app, "alice").await;
    assert_eq!(send(&app, "DELETE", &format!("/api/e2ee/pair-requests/{id}"), Some(&unbound), None).await.0, StatusCode::FORBIDDEN);
    let denied: i64 = sqlx::query_scalar("SELECT denied FROM device_pair_requests WHERE id = $1").bind(&id).fetch_one(&state.db).await.unwrap();
    assert_eq!(denied, 0, "an unbound session changed nothing");
    assert_eq!(send(&app, "DELETE", &format!("/api/e2ee/pair-requests/{id}"), Some(&token), None).await.0, StatusCode::OK);
    for _ in 1..30 {
        assert_eq!(send(&app, "DELETE", "/api/e2ee/pair-requests/nothing", Some(&token), None).await.0, StatusCode::OK);
    }
    assert_eq!(send(&app, "DELETE", "/api/e2ee/pair-requests/nothing", Some(&token), None).await.0, StatusCode::TOO_MANY_REQUESTS);
}
