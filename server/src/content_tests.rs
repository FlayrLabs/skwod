//! Build 44 "content": a send that can be retried, a clear that reaches offline members, and an
//! old build that is told to update in words it shows.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use skwod_crypto::SignalStore;
use tower::ServiceExt;

use crate::tests::{send, signup, test_state};

fn b64(v: &[u8]) -> String {
    B64.encode(v)
}

async fn space(app: &Router, owner: &str, members: &[&str]) -> (String, String) {
    let (st, body) = send(app, "POST", "/api/servers", Some(owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let server_id = body["server_id"].as_str().unwrap().to_string();
    for m in members {
        let (_, body) = send(app, "POST", &format!("/api/servers/{server_id}/invites"), Some(owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap().to_string();
        let (st, body) = send(app, "POST", &format!("/api/invites/{code}/accept"), Some(m), None).await;
        assert_eq!(st, StatusCode::OK, "{body}");
    }
    let (_, body) = send(app, "POST", &format!("/api/servers/{server_id}/channels"), Some(owner), Some(json!({ "name_ciphertext": b64(b"c") }))).await;
    (server_id, body["channel_id"].as_str().unwrap().to_string())
}

async fn rows(app: &Router, token: &str, channel: &str) -> Value {
    send(app, "GET", &format!("/api/channels/{channel}/messages"), Some(token), None).await.1
}

/// Register a libsignal device for `token`; returns its id.
async fn device(app: &Router, token: &str) -> String {
    let mut store = SignalStore::generate();
    let k = |id: u32, public: &[u8], signature: &[u8]| json!({ "id": id, "public": b64(public), "signature": b64(signature) });
    let spk = store.generate_signed_prekey().unwrap();
    let kyber = store.generate_last_resort_kyber().unwrap();
    let payload = json!({
        "protocol_version": 2,
        "registration_id": store.registration_id(),
        "identity_key": b64(&store.identity_key()),
        "signed_prekey": k(spk.id, &spk.public, &spk.signature),
        "last_resort_kyber_prekey": k(kyber.id, &kyber.public, &kyber.signature),
        "one_time_prekeys": [],
        "one_time_kyber_prekeys": [],
        "delivery_key": b64(&[7u8; 32]),
        // Build 44a: a registration names the install it is for.
        "install_hash": b64(&[9u8; 32]),
    });
    let (st, body) = send(app, "POST", "/api/e2ee/devices/register", Some(token), Some(payload)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    body["device_id"].as_str().unwrap().to_string()
}

/// `GET` with extra headers.
async fn get_with(app: &Router, path: &str, token: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut req = Request::builder().method("GET").uri(path).header(header::AUTHORIZATION, format!("Bearer {token}"));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The outbox contract: a client that never saw the answer to a send repeats it under the same
/// id, as often as it takes, and the channel holds the message exactly once.
#[tokio::test]
async fn a_repeated_send_is_stored_once_and_answers_like_the_first() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (_, channel) = space(&app, &alice, &[&bob]).await;
    let id = uuid::Uuid::new_v4().to_string();
    let path = format!("/api/channels/{channel}/messages");

    let (st, first) = send(&app, "POST", &path, Some(&alice), Some(json!({ "message_id": id, "ciphertext": b64(b"one") }))).await;
    assert_eq!(st, StatusCode::OK, "{first}");
    assert!(first["created_at"].as_i64().unwrap() > 0, "the server's time is what the sender files its own copy under");
    assert!(first.get("duplicate").is_none());

    // The retry re-seals, so its ciphertext differs; the first one stays.
    for _ in 0..3 {
        let (st, again) = send(&app, "POST", &path, Some(&alice), Some(json!({ "message_id": id, "ciphertext": b64(b"one, re-sealed") }))).await;
        assert_eq!(st, StatusCode::OK, "{again}");
        assert_eq!(again["message_id"], first["message_id"]);
        assert_eq!(again["created_at"], first["created_at"]);
        assert_eq!(again["duplicate"], true);
    }
    let listed = rows(&app, &bob, &channel).await;
    let msgs = listed["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 1, "delivered once");
    assert_eq!(B64.decode(msgs[0]["ciphertext"].as_str().unwrap()).unwrap(), b"one");

    // Somebody else's id is never "a retry": not for another author, not in another channel.
    let (st, _) = send(&app, "POST", &path, Some(&bob), Some(json!({ "message_id": id, "ciphertext": b64(b"mine now") }))).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (server_id, _) = space(&app, &alice, &[]).await;
    let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&alice), Some(json!({ "name_ciphertext": b64(b"d") }))).await;
    let other = body["channel_id"].as_str().unwrap();
    let (st, _) = send(&app, "POST", &format!("/api/channels/{other}/messages"), Some(&alice), Some(json!({ "message_id": id, "ciphertext": b64(b"moved") }))).await;
    assert_eq!(st, StatusCode::CONFLICT);

    // A retry that arrives after the author deleted the message does not bring it back.
    let (st, _) = send(&app, "DELETE", &format!("/api/messages/{id}"), Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    let (st, again) = send(&app, "POST", &path, Some(&alice), Some(json!({ "message_id": id, "ciphertext": b64(b"one") }))).await;
    assert_eq!((st, &again["duplicate"]), (StatusCode::OK, &json!(true)));
    let listed = rows(&app, &bob, &channel).await;
    assert!(listed["messages"][0]["deleted_at"].as_i64().is_some(), "still deleted");
}

/// A member whose device was offline for the `channel_cleared` event still learns of the clear:
/// every history page says when the channel was last cleared.
#[tokio::test]
async fn a_cleared_channel_says_so_on_every_later_page() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (server_id, channel) = space(&app, &alice, &[&bob]).await;
    let path = format!("/api/channels/{channel}/messages");
    for _ in 0..3 {
        send(&app, "POST", &path, Some(&alice), Some(json!({ "ciphertext": b64(b"x") }))).await;
    }
    assert!(rows(&app, &bob, &channel).await["cleared_at"].is_null(), "never cleared");

    let mut events = state.rt.subscribe();
    let (st, _) = send(&app, "DELETE", &path, Some(&bob), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a plain member cannot clear");
    let (st, body) = send(&app, "DELETE", &path, Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let listed = rows(&app, &bob, &channel).await;
    let cleared_at = listed["cleared_at"].as_i64().expect("cleared_at");
    assert!(listed["messages"].as_array().unwrap().is_empty());
    let ev = loop {
        let frame: Value = serde_json::from_str(&events.recv().await.unwrap().frame).unwrap();
        if frame["event"] == "channel_cleared" {
            break frame;
        }
    };
    assert_eq!(ev["payload"]["cleared_at"].as_i64(), Some(cleared_at));

    // Messages written afterwards are newer than the mark, so a purge "up to cleared_at" keeps them.
    tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    let (_, sent) = send(&app, "POST", &path, Some(&alice), Some(json!({ "ciphertext": b64(b"after") }))).await;
    assert!(sent["created_at"].as_i64().unwrap() > cleared_at);
    // …and the cursor read a returning device makes carries the mark too.
    let (_, page) = send(&app, "GET", &format!("{path}?after=0"), Some(&bob), None).await;
    assert_eq!(page["cleared_at"].as_i64(), Some(cleared_at));

    // "Clear everything" marks every channel of the server.
    tokio::time::sleep(std::time::Duration::from_millis(3)).await;
    let (st, _) = send(&app, "POST", &format!("/api/servers/{server_id}/clear"), Some(&alice), Some(json!({}))).await;
    assert_eq!(st, StatusCode::OK);
    assert!(rows(&app, &bob, &channel).await["cleared_at"].as_i64().unwrap() > cleared_at);
}

/// Builds 41/42 send a channel message without an id. They get a 426 whose body is the sentence
/// they show, their mailbox poll (the request their sync loop alerts on) answers the same from
/// then on, and the device is let back in the moment it has been updated.
#[tokio::test]
async fn an_old_build_is_told_to_update_in_words_it_can_show() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (_, channel) = space(&app, &alice, &[&bob]).await;
    let old = device(&app, &bob).await;
    let current = device(&app, &alice).await;
    let path = format!("/api/channels/{channel}/messages");
    let inbox = |d: &str| format!("/api/e2ee/sealed/inbox?device_id={d}");

    // Nobody is refused before showing what they are.
    assert_eq!(send(&app, "GET", &inbox(&old), Some(&bob), None).await.0, StatusCode::OK);

    let (st, body) = send(&app, "POST", &path, Some(&bob), Some(json!({ "message_id": null, "ciphertext": b64(b"v2"), "author_device_id": old }))).await;
    assert_eq!(st, StatusCode::UPGRADE_REQUIRED);
    let sentence = body["error"].as_str().expect("builds 41/42 read the `error` string");
    assert!(sentence.contains("https://skwod.io/download"), "{sentence}");
    assert!(!sentence.to_lowercase().starts_with("update required"), "the old app already titles its alert \"Update required\"");
    assert!(rows(&app, &alice, &channel).await["messages"].as_array().unwrap().is_empty(), "nothing was stored");

    // The sync loop of that device now gets the same sentence…
    let (st, body) = send(&app, "GET", &inbox(&old), Some(&bob), None).await;
    assert_eq!(st, StatusCode::UPGRADE_REQUIRED);
    assert_eq!(body["error"].as_str(), Some(sentence));
    // …while a current device (of anyone) is untouched.
    assert_eq!(send(&app, "GET", &inbox(&current), Some(&alice), None).await.0, StatusCode::OK);

    // A build that names itself is judged by the number: 42 is refused without having sent.
    assert_eq!(get_with(&app, &inbox(&current), &alice, &[("x-skwod-build", "42")]).await.0, StatusCode::UPGRADE_REQUIRED);
    assert_eq!(get_with(&app, &inbox(&current), &alice, &[("x-skwod-build", "44")]).await.0, StatusCode::OK);

    // Updated: the device sends with its own id (or names its build) and is let back in.
    let (st, _) = send(&app, "POST", &path, Some(&bob), Some(json!({ "ciphertext": b64(b"v3"), "author_device_id": old }))).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(send(&app, "GET", &inbox(&old), Some(&bob), None).await.0, StatusCode::OK);
}
