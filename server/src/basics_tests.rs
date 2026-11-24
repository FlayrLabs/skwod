//! Build 43 "broken basics": attachments two accounts can both open, sliding sessions, edits
//! from another device, the feed channel, history catch-up, silent traffic, a visible join flow.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use crate::state::{now_ms, AppState};
use crate::tests::{send, signup, test_state};

fn b64(v: &[u8]) -> String {
    B64.encode(v)
}

/// A request with arbitrary headers and a binary body; `token` is optional (the capability
/// download path sends none).
async fn raw(app: &Router, method: &str, path: &str, token: Option<&str>, headers: &[(&str, &str)], body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = app.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
    let status = res.status();
    (status, res.into_body().collect().await.unwrap().to_bytes().to_vec())
}

/// Owner + space + text channel; `members` join through a single-use invite each.
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

/// Create + fully upload a blob; returns its id.
async fn upload(app: &Router, token: &str, bytes: &[u8], download_token: Option<&str>) -> String {
    let mut body = json!({ "total_size": bytes.len() });
    if let Some(t) = download_token {
        body["download_token_hash"] = json!(hex::encode(Sha256::digest(t.as_bytes())));
    }
    let (st, body) = send(app, "POST", "/api/blobs", Some(token), Some(body)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let id = body["blob_id"].as_str().unwrap().to_string();
    let (st, _) = raw(app, "PATCH", &format!("/api/blobs/{id}"), Some(token), &[("upload-offset", "0")], bytes.to_vec()).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    id
}

async fn post(app: &Router, token: &str, channel: &str, extra: Value) -> String {
    let mut body = json!({ "ciphertext": b64(b"ct") });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    let (st, body) = send(app, "POST", &format!("/api/channels/{channel}/messages"), Some(token), Some(body)).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    body["message_id"].as_str().unwrap().to_string()
}

// ---- 1. attachments ----

#[tokio::test]
async fn a_channel_attachment_opens_for_the_other_member_and_dies_with_the_message() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (bob_id, bob) = signup(&app, "bobby").await;
    let (_, mallory) = signup(&app, "mallory").await;
    let (server_id, channel) = space(&app, &alice, &[&bob]).await;

    let blob = upload(&app, &alice, b"photo-ciphertext", None).await;
    // Before it is attached to anything, only the uploader can fetch it — this was the whole
    // bug: nothing ever attached it, so it stayed that way.
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&bob), &[], vec![]).await.0, StatusCode::NOT_FOUND);

    // The send names the blob; the link is made in the same transaction.
    let msg = post(&app, &alice, &channel, json!({ "blob_ids": [blob] })).await;
    let (st, bytes) = raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&bob), &[], vec![]).await;
    assert_eq!((st, bytes.as_slice()), (StatusCode::OK, b"photo-ciphertext".as_slice()), "the other member opens it");
    // Not someone outside the space, with or without a guessed token.
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&mallory), &[], vec![]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), None, &[("x-skwod-blob-token", "guess")], vec![]).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), None, &[], vec![]).await.0, StatusCode::UNAUTHORIZED);

    // A send naming someone else's blob, or one still uploading, fails whole: no message.
    let (st, _) = send(&app, "POST", &format!("/api/channels/{channel}/messages"), Some(&bob), Some(json!({ "ciphertext": b64(b"x"), "blob_ids": [blob] }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (_, body) = send(&app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 9 }))).await;
    let half = body["blob_id"].as_str().unwrap().to_string();
    let (st, _) = send(&app, "POST", &format!("/api/channels/{channel}/messages"), Some(&alice), Some(json!({ "ciphertext": b64(b"x"), "blob_ids": [half] }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages"), Some(&alice), None).await;
    assert_eq!(body["messages"].as_array().unwrap().len(), 1, "the refused sends left nothing behind");

    // A removed member loses the file with the channel.
    let (st, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{bob_id}"), Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&bob), &[], vec![]).await.0, StatusCode::NOT_FOUND);

    // Deleting the message deletes the file.
    let file = state.blob_dir.join(&blob);
    assert!(file.exists());
    let (st, _) = send(&app, "DELETE", &format!("/api/messages/{msg}"), Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!file.exists(), "the blob file is gone");
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&alice), &[], vec![]).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_dm_attachment_opens_with_its_token_and_only_with_it() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (_, channel) = space(&app, &alice, &[&bob]).await;

    let token = "b2f1c3d4e5f60718293a4b5c6d7e8f90";
    let blob = upload(&app, &alice, b"dm-photo", Some(token)).await;
    // Bob holds the token (it arrived inside the sealed DM). He sends NO session with it.
    let (st, bytes) = raw(&app, "GET", &format!("/api/blobs/{blob}"), None, &[("x-skwod-blob-token", token)], vec![]).await;
    assert_eq!((st, bytes.as_slice()), (StatusCode::OK, b"dm-photo".as_slice()));
    // A wrong token, or Bob's session without the token: nothing.
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), None, &[("x-skwod-blob-token", "nope")], vec![]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&bob), &[], vec![]).await.0, StatusCode::NOT_FOUND);
    // The server stores only the hash.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM blobs WHERE id = $1").bind(&blob).fetch_one(&state.db).await.unwrap();
    assert_eq!(stored, Sha256::digest(token.as_bytes()).to_vec());

    // Once a blob is attached in a channel, access follows the channel — a token cannot outlive
    // a removal.
    post(&app, &alice, &channel, json!({ "blob_ids": [blob] })).await;
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), None, &[("x-skwod-blob-token", token)], vec![]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&bob), &[], vec![]).await.0, StatusCode::OK);

    // The uploader can delete it (a DM delete has no server row to cascade from).
    let dm_blob = upload(&app, &alice, b"second", Some(token)).await;
    assert_eq!(raw(&app, "DELETE", &format!("/api/blobs/{dm_blob}"), Some(&bob), &[], vec![]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(raw(&app, "DELETE", &format!("/api/blobs/{dm_blob}"), Some(&alice), &[], vec![]).await.0, StatusCode::OK);
    assert_eq!(raw(&app, "GET", &format!("/api/blobs/{dm_blob}"), None, &[("x-skwod-blob-token", token)], vec![]).await.0, StatusCode::NOT_FOUND);
    // A malformed hash is refused at creation.
    let (st, _) = send(&app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 4, "download_token_hash": "abc" }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn uploads_need_membership_and_respect_quota_disk_floor_and_the_sweep() {
    let mut state = test_state().await;
    state.blob_quota_bytes = 100;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, stray) = signup(&app, "stray").await;
    space(&app, &alice, &[]).await;

    // An account that is in no space gets no storage.
    let (st, _) = send(&app, "POST", "/api/blobs", Some(&stray), Some(json!({ "total_size": 4 }))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Quota: 100 bytes in total, counted on what was DECLARED (so it cannot be dodged by not finishing).
    let kept = upload(&app, &alice, &[7u8; 60], Some("a-token-of-sufficient-len")).await;
    let (st, body) = send(&app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 41 }))).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert!(body["error"].as_str().unwrap().contains("attachment storage"));
    let (st, body) = send(&app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 40 }))).await;
    assert_eq!(st, StatusCode::OK);
    let abandoned = body["blob_id"].as_str().unwrap().to_string();

    // Free-space floor.
    let mut tight = state.clone();
    tight.blob_quota_bytes = i64::MAX;
    tight.blob_free_floor_bytes = u64::MAX / 2;
    let tight_app = crate::api::router(tight);
    let (st, body) = send(&tight_app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 4 }))).await;
    assert_eq!(st, StatusCode::INSUFFICIENT_STORAGE, "{body}");

    // Sweep: nothing young is touched…
    let mut roomy = state.clone();
    roomy.blob_quota_bytes = i64::MAX;
    let roomy_app = crate::api::router(roomy);
    let unlinked = upload(&roomy_app, &alice, b"never attached", None).await;
    assert_eq!(crate::blobs::sweep(&state).await, 0);
    // …after 24 h the unfinished upload and the finished-but-unreferenced one go; the one with a
    // download token (a DM attachment) stays.
    sqlx::query("UPDATE blobs SET updated_at = $1").bind(now_ms() - crate::blobs::ORPHAN_TTL_MS - 1).execute(&state.db).await.unwrap();
    assert_eq!(crate::blobs::sweep(&state).await, 2);
    let left: Vec<String> = sqlx::query_scalar("SELECT id FROM blobs").fetch_all(&state.db).await.unwrap();
    assert_eq!(left, vec![kept.clone()]);
    assert!(!state.blob_dir.join(&abandoned).exists() && !state.blob_dir.join(&unlinked).exists() && state.blob_dir.join(&kept).exists());
    // The retention pass runs it.
    assert_eq!(crate::retention::sweep(&state).await.blobs, 0);
}

#[tokio::test]
async fn deleting_a_message_only_deletes_blobs_that_are_the_deleters_and_referenced_nowhere_else() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (_, channel) = space(&app, &alice, &[&bob]).await;
    let get = |blob: String, token: String| {
        let app = app.clone();
        async move { raw(&app, "GET", &format!("/api/blobs/{blob}"), Some(&token), &[], vec![]).await.0 }
    };

    // Linking a blob that is not the sender's is refused — so nobody can attach a file of
    // someone else's to a message of their own in order to delete it.
    let alices = upload(&app, &alice, b"alice file", None).await;
    let (st, _) = send(&app, "POST", &format!("/api/channels/{channel}/messages"), Some(&bob), Some(json!({ "ciphertext": b64(b"x"), "blob_ids": [alices] }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(get(alices.clone(), alice.clone()).await, StatusCode::OK);

    // A blob with a download token may be referenced from a DM the server cannot see: deleting
    // a channel message that also carries it must not destroy it.
    let token = "0123456789abcdef0123456789abcdef";
    let shared = upload(&app, &alice, b"also in a dm", Some(token)).await;
    let m1 = post(&app, &alice, &channel, json!({ "blob_ids": [shared] })).await;
    assert_eq!(send(&app, "DELETE", &format!("/api/messages/{m1}"), Some(&alice), None).await.0, StatusCode::OK);
    assert!(state.blob_dir.join(&shared).exists());
    let (st, bytes) = raw(&app, "GET", &format!("/api/blobs/{shared}"), None, &[("x-skwod-blob-token", token)], vec![]).await;
    assert_eq!((st, bytes.as_slice()), (StatusCode::OK, b"also in a dm".as_slice()), "the DM copy still opens");

    // …nor one that a (legacy) DM attachment row refers to.
    let in_dm = upload(&app, &alice, b"dm row", None).await;
    let (_, body) = send(&app, "POST", "/api/dms", Some(&alice), Some(json!({ "participant_ids": [] }))).await;
    let convo = body["conversation_id"].as_str().unwrap().to_string();
    let (_, body) = send(&app, "POST", &format!("/api/dms/{convo}/messages"), Some(&alice), Some(json!({ "ciphertext": b64(b"dm") }))).await;
    let dm_msg = body["message_id"].as_str().unwrap().to_string();
    let (st, _) = send(&app, "POST", &format!("/api/dm-messages/{dm_msg}/attachments"), Some(&alice), Some(json!({ "blob_id": in_dm, "metadata_ciphertext": b64(b"m") }))).await;
    assert_eq!(st, StatusCode::OK);
    let m2 = post(&app, &alice, &channel, json!({ "blob_ids": [in_dm] })).await;
    send(&app, "DELETE", &format!("/api/messages/{m2}"), Some(&alice), None).await;
    assert_eq!(get(in_dm.clone(), alice.clone()).await, StatusCode::OK);

    // …nor one another channel message still carries.
    let twice = upload(&app, &alice, b"posted twice", None).await;
    let m3 = post(&app, &alice, &channel, json!({ "blob_ids": [twice] })).await;
    let m4 = post(&app, &alice, &channel, json!({ "blob_ids": [twice] })).await;
    send(&app, "DELETE", &format!("/api/messages/{m3}"), Some(&alice), None).await;
    assert_eq!(get(twice.clone(), bob.clone()).await, StatusCode::OK, "the other message still shows it");
    send(&app, "DELETE", &format!("/api/messages/{m4}"), Some(&alice), None).await;
    assert_eq!(get(twice.clone(), alice.clone()).await, StatusCode::NOT_FOUND, "the last reference took it");
    assert!(!state.blob_dir.join(&twice).exists());

    // A moderator (the owner) deleting BOB's message does not destroy Bob's file: only the
    // link goes. Bob keeps it; the channel no longer serves it; the sweep takes it later.
    let bobs = upload(&app, &bob, b"bob file", None).await;
    let m5 = post(&app, &bob, &channel, json!({ "blob_ids": [bobs] })).await;
    assert_eq!(send(&app, "DELETE", &format!("/api/messages/{m5}"), Some(&alice), None).await.0, StatusCode::OK);
    assert_eq!(get(bobs.clone(), bob.clone()).await, StatusCode::OK);
    assert_eq!(get(bobs.clone(), alice.clone()).await, StatusCode::NOT_FOUND);
    sqlx::query("UPDATE blobs SET updated_at = $1 WHERE id = $2").bind(now_ms() - crate::blobs::ORPHAN_TTL_MS - 1).bind(&bobs).execute(&state.db).await.unwrap();
    assert_eq!(crate::blobs::sweep(&state).await, 1);
}

// ---- 3. sessions ----

async fn expiry(state: &AppState, token: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT expires_at FROM sessions WHERE token_hash = $1").bind(crate::auth::token_hash(token)).fetch_optional(&state.db).await.unwrap()
}

#[tokio::test]
async fn a_session_slides_while_used_dies_when_idle_and_never_outlives_the_absolute_limit() {
    let mut state = test_state().await;
    state.session_ttl_ms = 600; // "30 days"
    state.session_max_ms = 2500; // "1 year"
    let app = crate::api::router(state.clone());
    let (_, token) = signup(&app, "slider").await;
    let first = expiry(&state, &token).await.unwrap();

    // Used every 300 ms — half the idle limit — for well past the original expiry: still in.
    let mut last = first;
    for _ in 0..5 {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(send(&app, "GET", "/api/auth/me", Some(&token), None).await.0, StatusCode::OK);
        let e = expiry(&state, &token).await.unwrap();
        assert!(e >= last, "expiry never moves backwards");
        last = e;
    }
    assert!(last > first + 600, "expiry slid forward with use ({first} → {last})");

    // The absolute limit: use keeps it alive only up to origin + max, however active.
    let origin: i64 = sqlx::query_scalar("SELECT origin_at FROM sessions WHERE token_hash = $1").bind(crate::auth::token_hash(&token)).fetch_one(&state.db).await.unwrap();
    let mut refused = false;
    for _ in 0..12 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let st = send(&app, "GET", "/api/auth/me", Some(&token), None).await.0;
        assert!(expiry(&state, &token).await.unwrap() <= origin + 2500, "expiry is capped at sign-in + max");
        if st == StatusCode::UNAUTHORIZED {
            refused = true;
            break;
        }
    }
    assert!(refused, "an always-busy session is still signed out at the absolute limit");
    assert!(now_ms() >= origin + 2500);

    // Idle: a fresh session nobody uses is dead after the idle limit — 401, not 5xx.
    let (st, body) = send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "slider", "password": "correct horse" }))).await;
    assert_eq!(st, StatusCode::OK);
    let idle = body["token"].as_str().unwrap().to_string();
    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&idle), None).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rotating_a_token_keeps_the_sign_in_and_the_push_registration() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user, old) = signup(&app, "rotator").await;
    let reg = json!({ "provider": "gateway", "gateway": "https://push.example.org", "apns_token": "ab".repeat(32), "voip_token": null, "topic": "io.skwod.app" });
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&old), Some(reg)).await.0, StatusCode::OK);
    sqlx::query("UPDATE sessions SET origin_at = $1").bind(now_ms() - 1000).execute(&state.db).await.unwrap();
    let origin: i64 = sqlx::query_scalar("SELECT origin_at FROM sessions").fetch_one(&state.db).await.unwrap();

    let (st, body) = send(&app, "POST", "/api/auth/rotate", Some(&old), None).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let new = body["token"].as_str().unwrap().to_string();
    assert_ne!(new, old);
    assert_eq!(body["user_id"], user.as_str());
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&new), None).await.0, StatusCode::OK);

    // Same sign-in: the absolute limit did not restart.
    let new_origin: i64 = sqlx::query_scalar("SELECT origin_at FROM sessions WHERE token_hash = $1").bind(crate::auth::token_hash(&new)).fetch_one(&state.db).await.unwrap();
    assert_eq!(new_origin, origin);
    // The push registration followed the token instead of being cascaded away with the old one.
    let hash: Vec<u8> = sqlx::query_scalar("SELECT session_hash FROM push_registrations").fetch_one(&state.db).await.unwrap();
    assert_eq!(hash, crate::auth::token_hash(&new));

    // The old token: works during the grace period, cannot rotate again, then is gone — and the
    // registration survives its removal.
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&old), None).await.0, StatusCode::OK);
    assert_eq!(send(&app, "POST", "/api/auth/rotate", Some(&old), None).await.0, StatusCode::UNAUTHORIZED);
    assert!(expiry(&state, &old).await.unwrap() <= now_ms() + crate::auth::ROTATE_GRACE_MS);
    sqlx::query("UPDATE sessions SET expires_at = $1 WHERE superseded = 1").bind(now_ms() - 1).execute(&state.db).await.unwrap();
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&old), None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(crate::retention::sweep(&state).await.sessions, 1);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap();
    assert_eq!(n, 1);
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&new), None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn usernames_are_plain_ascii_only() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    // Cyrillic е, a zero-width joiner, full-width letters, uppercase, a dot: all refused, so two
    // names that LOOK the same cannot both exist on one server.
    for bad in ["m\u{0435}rhan", "mer\u{200d}han", "\u{ff4d}\u{ff45}\u{ff52}han", "Merhan", "mer.han", "mer han", "ab"] {
        let (st, _) = send(&app, "POST", "/api/auth/signup", None, Some(json!({ "username": bad, "password": "correct horse" }))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad:?} must be refused");
    }
    signup(&app, "merhan_01").await;
}

// ---- 4. cross-device edits ----

#[tokio::test]
async fn an_edit_records_the_device_that_made_it() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (alice_id, alice) = signup(&app, "alice").await;
    let (_, channel) = space(&app, &alice, &[]).await;
    for device in ["phone", "mac"] {
        crate::tests::seed_device(&state.db, &alice_id, device).await;
    }
    let mut bus = state.rt.subscribe();
    let msg = post(&app, &alice, &channel, json!({ "author_device_id": "phone" })).await;
    let _ = bus.recv().await;

    // Edited on the Mac: re-encrypted under the Mac's sender key.
    let (st, _) = send(&app, "PATCH", &format!("/api/messages/{msg}"), Some(&alice), Some(json!({ "ciphertext": b64(b"edited"), "author_device_id": "mac" }))).await;
    assert_eq!(st, StatusCode::OK);
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages"), Some(&alice), None).await;
    let row = &body["messages"][0];
    assert_eq!((row["author_device_id"].as_str(), row["is_edited"].as_bool()), (Some("mac"), Some(true)), "readers decrypt it as the editing device");
    let ev: Value = serde_json::from_str(&bus.recv().await.unwrap().frame).unwrap();
    assert_eq!((ev["event"].as_str(), ev["payload"]["author_device_id"].as_str()), (Some("message_update"), Some("mac")));

    // A build-42 client sends no device: the original stays.
    let (st, _) = send(&app, "PATCH", &format!("/api/messages/{msg}"), Some(&alice), Some(json!({ "ciphertext": b64(b"again") }))).await;
    assert_eq!(st, StatusCode::OK);
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages"), Some(&alice), None).await;
    assert_eq!(body["messages"][0]["author_device_id"], "mac");
}

// ---- 5. the feed channel ----

#[tokio::test]
async fn a_server_has_exactly_one_feed_channel() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (server_id, text) = space(&app, &alice, &[&bob]).await;
    let feed = json!({ "name_ciphertext": b64(b"feed"), "purpose": "feed" });

    // A member cannot create it; the owner can; creating it again hands back the same one.
    assert_eq!(send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&bob), Some(feed.clone())).await.0, StatusCode::FORBIDDEN);
    let (st, body) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&alice), Some(feed.clone())).await;
    assert_eq!(st, StatusCode::OK, "{body}");
    let id = body["channel_id"].as_str().unwrap().to_string();
    let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&alice), Some(feed)).await;
    assert_eq!((body["channel_id"].as_str(), body["existing"].as_bool()), (Some(id.as_str()), Some(true)));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM channels WHERE purpose = 'feed'").fetch_one(&state.db).await.unwrap();
    assert_eq!(n, 1);
    // Only a plain text channel can be the feed.
    let (st, _) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&alice), Some(json!({ "name_ciphertext": b64(b"v"), "type": "voice", "purpose": "feed" }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    // Everyone sees which one it is — the same id on every device.
    for token in [&alice, &bob] {
        let (_, body) = send(&app, "GET", &format!("/api/servers/{server_id}/channels"), Some(token), None).await;
        let chans = body["channels"].as_array().unwrap();
        let feeds: Vec<&str> = chans.iter().filter(|c| c["purpose"] == "feed").map(|c| c["channel_id"].as_str().unwrap()).collect();
        assert_eq!(feeds, vec![id.as_str()]);
        assert!(chans.iter().any(|c| c["channel_id"] == text.as_str() && c["purpose"].is_null()));
    }
}

// ---- 6 + 7. history, lanes, reactions, silent sends ----

#[tokio::test]
async fn history_pages_backwards_and_the_after_cursor_catches_up_on_edits_and_deletes() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (alice_id, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (_, carol) = signup(&app, "carol").await;
    let (_, dave) = signup(&app, "dave_").await;
    let (_, channel) = space(&app, &alice, &[&bob, &carol, &dave]).await;
    crate::tests::seed_device(&state.db, &alice_id, "d2").await;

    // Bob is up to date as of here.
    let first = post(&app, &alice, &channel, json!({})).await;
    let edited_later = post(&app, &alice, &channel, json!({})).await;
    let deleted_later = post(&app, &alice, &channel, json!({})).await;
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages"), Some(&bob), None).await;
    let mut cursor = body["messages"].as_array().unwrap().iter().map(|m| m["updated_at"].as_i64().unwrap()).max().unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    // While Bob is offline: 150 new messages (with whiteboard noise in between), one edit, one delete.
    sqlx::query("UPDATE messages SET created_at = created_at - 100000, updated_at = updated_at - 100000").execute(&state.db).await.unwrap();
    cursor -= 100000;
    let mut sent = Vec::new();
    for i in 0..150 {
        // Distinct timestamps, as real traffic has.
        let id = post(&app, if i % 2 == 0 { &alice } else { &carol }, &channel, json!({})).await;
        sqlx::query("UPDATE messages SET created_at = $1, updated_at = $1 WHERE id = $2").bind(now_ms() - 50000 + i).bind(&id).execute(&state.db).await.unwrap();
        sent.push(id);
        if i % 3 == 0 {
            // Other traffic in between (to the server it is just more messages).
            post(&app, &dave, &channel, json!({})).await;
        }
    }
    send(&app, "PATCH", &format!("/api/messages/{edited_later}"), Some(&alice), Some(json!({ "ciphertext": b64(b"edit"), "author_device_id": "d2" }))).await;
    send(&app, "DELETE", &format!("/api/messages/{deleted_later}"), Some(&alice), None).await;

    // Catch-up: pages of 100 from the cursor until a short page.
    let mut seen: Vec<Value> = Vec::new();
    let mut pages = 0;
    loop {
        let (st, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages?after={cursor}&limit=100"), Some(&bob), None).await;
        assert_eq!(st, StatusCode::OK);
        let page = body["messages"].as_array().unwrap().clone();
        pages += 1;
        let top = page.iter().map(|m| m["updated_at"].as_i64().unwrap()).max().unwrap_or(cursor);
        let full = page.len() == 100;
        seen.extend(page);
        cursor = if top == cursor { cursor + 1 } else { top };
        if !full {
            break;
        }
    }
    assert!(pages >= 2, "150 missed messages do not fit in one page");
    let ids: std::collections::HashSet<&str> = seen.iter().map(|m| m["message_id"].as_str().unwrap()).collect();
    assert!(sent.iter().all(|id| ids.contains(id.as_str())), "every missed message was served ({} of 150)", sent.iter().filter(|id| ids.contains(id.as_str())).count());
    assert!(seen.iter().any(|m| m["message_id"] == edited_later.as_str() && m["is_edited"] == true && m["author_device_id"] == "d2"), "the edit is in the catch-up");
    assert!(seen.iter().any(|m| m["message_id"] == deleted_later.as_str() && !m["deleted_at"].is_null()), "the delete is in the catch-up");
    assert!(!ids.contains(first.as_str()), "what Bob already had and nobody touched is not re-sent");
    assert_eq!(ids.len(), 202, "150 + 50 in between + the edit + the delete");

    // Backwards paging ("load older") walks the whole chat lane, 100 at a time, no gaps, no dupes.
    let mut before = i64::MAX;
    let mut all: Vec<String> = Vec::new();
    loop {
        let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages?before={before}&limit=100"), Some(&bob), None).await;
        let page = body["messages"].as_array().unwrap().clone();
        if page.is_empty() {
            break;
        }
        before = page.last().unwrap()["created_at"].as_i64().unwrap();
        all.extend(page.iter().map(|m| m["message_id"].as_str().unwrap().to_string()));
    }
    assert_eq!(all.len(), 203);
    assert_eq!(all.iter().collect::<std::collections::HashSet<_>>().len(), 203);
}

#[tokio::test]
async fn reactions_come_with_the_message_list_and_move_the_cursor() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (alice_id, alice) = signup(&app, "alice").await;
    let (bob_id, bob) = signup(&app, "bobby").await;
    let (_, channel) = space(&app, &alice, &[&bob]).await;
    let msg = post(&app, &alice, &channel, json!({})).await;
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages"), Some(&bob), None).await;
    assert_eq!(body["messages"][0]["reactions"], json!([]));
    let cursor = body["messages"][0]["updated_at"].as_i64().unwrap() + 1;
    tokio::time::sleep(std::time::Duration::from_millis(3)).await;

    let mut bus = state.rt.subscribe();
    for token in [&alice, &bob] {
        let (st, _) = send(&app, "POST", &format!("/api/messages/{msg}/reactions"), Some(token), Some(json!({ "emoji_hash": "h1", "emoji_ciphertext": b64(b"sealed") }))).await;
        assert_eq!(st, StatusCode::OK);
    }
    let ev: Value = serde_json::from_str(&bus.recv().await.unwrap().frame).unwrap();
    assert_eq!((ev["event"].as_str(), ev["payload"]["message_id"].as_str()), (Some("reaction"), Some(msg.as_str())));

    // One list call carries who reacted with what; the cursor serves the message again.
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages?after={cursor}"), Some(&bob), None).await;
    let reactions = body["messages"][0]["reactions"].as_array().unwrap();
    let who: std::collections::HashSet<&str> = reactions.iter().map(|r| r["user_id"].as_str().unwrap()).collect();
    assert_eq!(who, [alice_id.as_str(), bob_id.as_str()].into_iter().collect());
    assert!(reactions.iter().all(|r| r["emoji_hash"] == "h1" && r["emoji_ciphertext"] == b64(b"sealed")));
    let (st, _) = send(&app, "DELETE", &format!("/api/messages/{msg}/reactions/h1"), Some(&bob), None).await;
    assert_eq!(st, StatusCode::OK);
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages"), Some(&bob), None).await;
    assert_eq!(body["messages"][0]["reactions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn the_server_cannot_be_told_what_kind_of_message_it_is_carrying() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (_, channel) = space(&app, &alice, &[&bob]).await;
    let reg = json!({ "provider": "gateway", "gateway": "https://push.example.org", "apns_token": "cd".repeat(32), "voip_token": null, "topic": "io.skwod.app" });
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&bob), Some(reg)).await.0, StatusCode::OK);

    // A client that TRIES to label its traffic (an older build of this branch did) is not
    // listened to: the message is stored, listed, announced and pushed like any other.
    let mut bus = state.rt.subscribe();
    let labelled = post(&app, &alice, &channel, json!({ "silent": true, "lane": "aux" })).await;
    let plain = post(&app, &alice, &channel, json!({})).await;
    let a: Value = serde_json::from_str(&bus.recv().await.unwrap().frame).unwrap();
    let b: Value = serde_json::from_str(&bus.recv().await.unwrap().frame).unwrap();
    for ev in [&a, &b] {
        assert_eq!(ev["event"], "message");
        let keys: std::collections::BTreeSet<&str> = ev["payload"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["author_device_id", "author_id", "channel_id", "ciphertext", "created_at", "message_id", "reply_to_id"].into_iter().collect(), "no field describes the content");
    }
    assert_eq!(state.waker.pending_len(), 1, "one coalesced wake for the device, whatever was sent");
    let (_, body) = send(&app, "GET", &format!("/api/channels/{channel}/messages"), Some(&bob), None).await;
    let ids: Vec<&str> = body["messages"].as_array().unwrap().iter().map(|m| m["message_id"].as_str().unwrap()).collect();
    assert!(ids.contains(&labelled.as_str()) && ids.contains(&plain.as_str()), "one history for everything");
    // …and the stored rows differ in nothing but id, time and bytes. (`pragma_table_info` is
    // SQLite's; the two migration sets declare the same columns, so SQLite speaks for both.)
    if std::env::var_os("SKWOD_TEST_POSTGRES").is_none() {
        let cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('messages')").fetch_all(&state.db).await.unwrap();
        assert!(!cols.iter().any(|c| c == "lane" || c == "silent" || c == "kind"), "{cols:?}");
    }
}

// ---- 8. the join flow ----

#[tokio::test]
async fn a_join_request_reaches_the_owner_and_the_approval_reaches_the_joiner() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (alice_id, alice) = signup(&app, "alice").await;
    let (bob_id, bob) = signup(&app, "bobby").await;
    let (server_id, _) = space(&app, &alice, &[]).await;
    let reg = json!({ "provider": "gateway", "gateway": "https://push.example.org", "apns_token": "ef".repeat(32), "voip_token": null, "topic": "io.skwod.app" });
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&alice), Some(reg)).await.0, StatusCode::OK);
    let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&alice), Some(json!({ "kind": "code" }))).await;
    let code = body["code"].as_str().unwrap().to_string();

    // The pre-check, with no account: this code is good and needs approval.
    let (st, body) = send(&app, "GET", &format!("/api/invites/{code}/check"), None, None).await;
    assert_eq!((st, body["valid"].as_bool(), body["requires_approval"].as_bool()), (StatusCode::OK, Some(true), Some(true)));

    let mut bus = state.rt.subscribe();
    let (st, body) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&bob), None).await;
    assert_eq!((st, body["pending"].as_bool()), (StatusCode::OK, Some(true)));
    // → the owner hears about it on their own topic, with the pending count for a badge…
    let ev = bus.recv().await.unwrap();
    let frame: Value = serde_json::from_str(&ev.frame).unwrap();
    assert_eq!(ev.topic, format!("user:{alice_id}"));
    assert_eq!((frame["event"].as_str(), frame["payload"]["user_id"].as_str(), frame["payload"]["pending"].as_i64()), (Some("join_request"), Some(bob_id.as_str()), Some(1)));
    // …and their phone is woken if the app is not open.
    assert_eq!(state.waker.pending_len(), 1);
    // Asking again while pending does not notify again.
    send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&bob), None).await;
    assert!(bus.try_recv().is_err());

    // Approval → the joiner hears, on their own topic.
    let (st, _) = send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{bob_id}/approve"), Some(&alice), None).await;
    assert_eq!(st, StatusCode::OK);
    let ev = bus.recv().await.unwrap();
    let frame: Value = serde_json::from_str(&ev.frame).unwrap();
    assert_eq!((ev.topic.as_str(), frame["event"].as_str(), frame["payload"]["server_id"].as_str()), (format!("user:{bob_id}").as_str(), Some("join_approved"), Some(server_id.as_str())));
}

#[tokio::test]
async fn an_expired_invite_is_reported_before_signup() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (server_id, _) = space(&app, &alice, &[]).await;
    let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&alice), Some(json!({ "kind": "code" }))).await;
    let code = body["code"].as_str().unwrap().to_string();
    sqlx::query("UPDATE invites SET expires_at = $1 WHERE code = $2").bind(now_ms() - 1).bind(&code).execute(&state.db).await.unwrap();

    let (st, body) = send(&app, "GET", &format!("/api/invites/{code}/check"), None, None).await;
    assert_eq!((st, body["valid"].as_bool(), body["reason"].as_str()), (StatusCode::OK, Some(false), Some("expired")));
    let (_, body) = send(&app, "GET", "/api/invites/SKWD-NOPE-NOPE/check", None, None).await;
    assert_eq!((body["valid"].as_bool(), body["reason"].as_str()), (Some(false), Some("unknown")));
    // It tells a prober nothing about the skwod.
    assert_eq!(body.as_object().unwrap().len(), 2);
    // Revoked → "used".
    let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&alice), Some(json!({ "kind": "code" }))).await;
    let code2 = body["code"].as_str().unwrap().to_string();
    send(&app, "DELETE", &format!("/api/invites/{code2}"), Some(&alice), None).await;
    let (_, body) = send(&app, "GET", &format!("/api/invites/{code2}/check"), None, None).await;
    assert_eq!((body["valid"].as_bool(), body["reason"].as_str()), (Some(false), Some("used")));
    // Throttled.
    let mut limited = false;
    for _ in 0..30 {
        limited |= send(&app, "GET", &format!("/api/invites/{code}/check"), None, None).await.0 == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited);
}

// ---- 10. the admin page hands out share links ----

#[test]
fn host_invites_are_share_links() {
    let node = skwod_net::SecretKey::from_bytes(&[7u8; 32]).public();
    let link = crate::p2p::invite_link(node, Some("SKWD-AAAA-BBBB"));
    assert!(link.starts_with("https://skwod.io/join#"), "{link}");
    assert!(!link.contains("skwod://"));
    // …which the apps parse back to the same host and code.
    let parsed = skwod_net::invite::Invite::parse(&link).unwrap();
    assert_eq!((parsed.node_id, parsed.join_code.as_deref()), (node, Some("SKWD-AAAA-BBBB")));
}

// ---- 11. sockets that went quiet, and devices that said goodbye ----

pub(crate) async fn serve(state: &AppState) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = crate::api::router(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

#[tokio::test]
async fn a_socket_that_stops_answering_pings_is_closed_and_the_device_becomes_wakeable() {
    use futures_util::StreamExt;
    let mut state = test_state().await;
    state.ws_ping = std::time::Duration::from_millis(200);
    let app = crate::api::router(state.clone());
    let addr = serve(&state).await;
    let (_, token) = signup(&app, "sleeper").await;
    let hash = crate::auth::token_hash(&token);

    // A healthy client (it reads, so it answers pings) stays connected well past the deadline.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={token}")).await.unwrap();
    let quiet = tokio::time::timeout(std::time::Duration::from_millis(1500), async {
        while let Some(Ok(m)) = ws.next().await {
            if m.is_close() {
                return false;
            }
        }
        false
    })
    .await;
    assert!(quiet.is_err(), "a socket that answers pings must stay open");
    assert!(state.session_connected(&hash));

    // The app is suspended: the socket is still "open" but nothing reads it any more.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    assert!(!state.session_connected(&hash), "a silent socket is given up, so pushes resume");
    drop(ws);
}

#[tokio::test]
async fn a_device_that_announced_offline_is_wakeable_while_its_socket_lingers() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let addr = serve(&state).await;
    let (_, token) = signup(&app, "backgrounder").await;
    let hash = crate::auth::token_hash(&token);
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={token}")).await.unwrap();
    ws.send(Message::Text(json!({"type":"presence","status":"online"}).to_string())).await.unwrap();
    ws.send(Message::Text(json!({"type":"ping"}).to_string())).await.unwrap();
    ws.next().await;
    assert!(state.session_connected(&hash));

    // Backgrounded: the app says so; the socket has not closed yet.
    ws.send(Message::Text(json!({"type":"presence","status":"offline"}).to_string())).await.unwrap();
    ws.send(Message::Text(json!({"type":"ping"}).to_string())).await.unwrap();
    ws.next().await;
    assert!(!state.session_connected(&hash), "offline presence makes the install wakeable");
    // Foreground again.
    ws.send(Message::Text(json!({"type":"presence","status":"online"}).to_string())).await.unwrap();
    ws.send(Message::Text(json!({"type":"ping"}).to_string())).await.unwrap();
    ws.next().await;
    assert!(state.session_connected(&hash));
    drop(ws);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(!state.session_connected(&hash));
}

#[tokio::test]
async fn sealed_mail_is_all_alike_to_the_server() {
    // Seeds a device row from `pragma_table_info`: SQLite only.
    if std::env::var_os("SKWOD_TEST_POSTGRES").is_some() {
        eprintln!("skipped on PostgreSQL: seeds its device row through SQLite's pragma_table_info");
        return;
    }
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (bob_id, bob) = signup(&app, "bobby").await;
    let reg = json!({ "provider": "gateway", "gateway": "https://push.example.org", "apns_token": "aa".repeat(32), "voip_token": null, "topic": "io.skwod.app" });
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&bob), Some(reg)).await.0, StatusCode::OK);
    // A device row to deposit to (only the routing columns matter here).
    sqlx::query("UPDATE user_devices SET delivery_key = delivery_key WHERE 1 = 0").execute(&state.db).await.unwrap();
    let cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('user_devices') WHERE \"notnull\" = 1 AND dflt_value IS NULL").fetch_all(&state.db).await.unwrap();
    let mut names = Vec::new();
    let mut values = Vec::new();
    for c in &cols {
        names.push(c.clone());
        values.push(match c.as_str() {
            "user_id" => format!("'{bob_id}'"),
            "device_id" => "'d1'".to_string(),
            "delivery_key" => "x'01020304'".to_string(),
            _ => "x'00'".to_string(),
        });
    }
    sqlx::query(&format!("INSERT INTO user_devices ({}) VALUES ({})", names.join(", "), values.join(", "))).execute(&state.db).await.unwrap();

    // A sender that tries to label an envelope ("silent") is not listened to: every envelope
    // is announced and wakes the same way, so the server cannot tell a DM from a sender key.
    let deposit = |silent: bool| json!({ "messages": [{ "user_id": bob_id, "device_id": "d1", "delivery_key": b64(&[1, 2, 3, 4]), "envelope": b64(b"sealed"), "silent": silent }] });
    let mut bus = state.rt.subscribe();
    let (st, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(deposit(true))).await;
    assert_eq!((st, body["results"][0]["status"].as_str()), (StatusCode::OK, Some("ok")), "{body}");
    let ev: Value = serde_json::from_str(&bus.recv().await.unwrap().frame).unwrap();
    assert_eq!((ev["event"].as_str(), &ev["payload"]), (Some("sealed"), &json!({})), "the event says nothing about the envelope");
    assert_eq!(state.waker.pending_len(), 1);
    send(&app, "POST", "/api/e2ee/sealed/send", None, Some(deposit(false))).await;
    assert_eq!(state.waker.pending_len(), 1, "coalesced: still one pending wake for the device");
}

// ---- 13. a p2p node is "signed in" only once a session has been resolved for it ----

async fn p2p_request(app: &Router, node: [u8; 32], path: &str, bearer: Option<&str>) -> StatusCode {
    let mut req = Request::builder().method("GET").uri(path);
    if let Some(b) = bearer {
        req = req.header(header::AUTHORIZATION, format!("Bearer {b}"));
    }
    let peer = crate::client_key::P2pPeer { node: "n".into(), node_bytes: node, relayed: false };
    app.clone().layer(axum::Extension(peer)).oneshot(req.body(Body::empty()).unwrap()).await.unwrap().status()
}

#[tokio::test]
async fn a_garbage_bearer_does_not_make_a_p2p_node_signed_in() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (alice_id, alice) = signup(&app, "alice").await;
    let (stray_id, stray) = signup(&app, "stray").await;
    let (server_id, _) = space(&app, &alice, &[]).await;
    let nodes = &state.p2p_authenticated;

    // Routes that answer something other than 401 to a made-up token — 404, 200, 400 — must not
    // hand out standing. (The previous rule was "has a bearer and was not answered 401".)
    let ghost = [9u8; 32];
    for (path, expect) in [("/api/nope", StatusCode::NOT_FOUND), ("/health", StatusCode::OK), ("/api/invites/SKWD-NOPE-NOPE/check", StatusCode::OK), ("/api/instance/identity", StatusCode::OK)] {
        assert_eq!(p2p_request(&app, ghost, path, Some("x")).await, expect, "{path}");
        assert_eq!(nodes.user(&ghost), None, "{path} with a garbage bearer must not mark the node");
        assert_eq!(nodes.account(&state, &ghost).await, None);
    }
    assert_eq!(p2p_request(&app, ghost, "/api/auth/me", Some("x")).await, StatusCode::UNAUTHORIZED);
    assert_eq!(nodes.user(&ghost), None);
    // A real token on a route that does not authenticate (404) does not count either.
    assert_eq!(p2p_request(&app, ghost, "/api/nope", Some(&alice)).await, StatusCode::NOT_FOUND);
    assert_eq!(nodes.user(&ghost), None);

    // A resolved session does — and it is tied to that account.
    let phone = [1u8; 32];
    assert_eq!(p2p_request(&app, phone, "/api/auth/me", Some(&alice)).await, StatusCode::OK);
    assert_eq!(nodes.account(&state, &phone).await.as_deref(), Some(alice_id.as_str()));

    // An account that is in no space has a live session but gets no standing at all.
    let loner = [2u8; 32];
    assert_eq!(p2p_request(&app, loner, "/api/auth/me", Some(&stray)).await, StatusCode::OK);
    assert_eq!(nodes.user(&loner), None, "not a member of anything: never noted");
    let _ = &stray_id;

    // One account, many node ids: it keeps only its newest few entries — its own oldest go.
    for n in 10..60u8 {
        assert_eq!(p2p_request(&app, [n; 32], "/api/auth/me", Some(&alice)).await, StatusCode::OK);
        assert!(nodes.nodes_of(&alice_id) <= skwod_net::host::MAX_PER_ACCOUNT);
    }
    assert_eq!(nodes.nodes_of(&alice_id), skwod_net::host::MAX_PER_ACCOUNT);
    assert_eq!(nodes.user(&[59u8; 32]).as_deref(), Some(alice_id.as_str()));
    assert_eq!(nodes.user(&phone), None, "the account's own oldest entry made room");
    assert_eq!(p2p_request(&app, phone, "/api/auth/me", Some(&alice)).await, StatusCode::OK);

    // A full map records nobody new and evicts nobody: churn cannot cost others their standing.
    let (bob_id, bob) = signup(&app, "bobby").await;
    let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&alice), Some(json!({ "kind": "token" }))).await;
    send(&app, "POST", &format!("/api/invites/{}/accept", body["code"].as_str().unwrap()), Some(&bob), None).await;
    nodes.fill(crate::p2p::AuthenticatedNodes::CAP);
    assert_eq!(p2p_request(&app, [3u8; 32], "/api/auth/me", Some(&bob)).await, StatusCode::OK);
    assert_eq!(nodes.nodes_of(&bob_id), 0, "full: not recorded");
    assert_eq!(nodes.nodes_of(&alice_id), skwod_net::host::MAX_PER_ACCOUNT, "and nobody else lost theirs");
    assert_eq!(nodes.user(&phone).as_deref(), Some(alice_id.as_str()));

    // A node's standing ends when its connection closes…
    nodes.forget(&[59u8; 32]);
    assert_eq!(nodes.user(&[59u8; 32]), None);

    // …and standing ends with the session (logout) or the membership (removal).
    assert_eq!(send(&app, "POST", "/api/auth/logout", Some(&alice), None).await.0, StatusCode::OK);
    assert_eq!(nodes.account(&state, &phone).await, None, "a logged-out session no longer vouches for the node");
}

// ---- the host app can tell its own child from an impostor on the same port ----

#[tokio::test]
async fn only_the_supervised_child_can_answer_the_local_proof() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let nonce = "000102030405060708090a0b0c0d0e0f";
    // No secret was handed to this process: the route does not exist.
    std::env::remove_var("SKWOD_LOCAL_PROOF_SECRET");
    assert_eq!(send(&app, "GET", &format!("/api/instance/local-proof?nonce={nonce}"), None, None).await.0, StatusCode::NOT_FOUND);

    let secret = "4f1c0d7e9a2b48c6b3e5d1a07f9c2e8451b6a3d0c7e9f2a4";
    std::env::set_var("SKWOD_LOCAL_PROOF_SECRET", secret);
    let (st, body) = send(&app, "GET", &format!("/api/instance/local-proof?nonce={nonce}"), None, None).await;
    std::env::remove_var("SKWOD_LOCAL_PROOF_SECRET");
    assert_eq!(st, StatusCode::OK, "{body}");
    // What the supervisor computes with the secret it generated…
    let expected = crate::api::local_proof_for(secret.as_bytes(), &hex::decode(nonce).unwrap());
    assert_eq!(body["proof"], expected.as_str());
    // …is not what an impostor on the port can produce: it does not have the secret, so any
    // answer it gives (here: computed under its own guess) differs, as does a replay of an old
    // answer against a new nonce.
    assert_ne!(crate::api::local_proof_for(b"an impostor's guess, 32+ bytes long....", &hex::decode(nonce).unwrap()), expected);
    assert_ne!(crate::api::local_proof_for(secret.as_bytes(), &[9u8; 16]), expected);
    // Known vector, so the Swift and Kotlin sides can be checked against the same bytes.
    assert_eq!(expected, crate::api::local_proof_for(secret.as_bytes(), &(0u8..16).collect::<Vec<_>>()));
}

/// Build 49: a rename is a bounded ciphertext, and only someone with MANAGE_SERVER may make it.
#[tokio::test]
async fn a_server_rename_is_bounded_and_needs_manage_server() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, alice) = signup(&app, "alice").await;
    let (_, bob) = signup(&app, "bobby").await;
    let (server_id, _) = space(&app, &alice, &[&bob]).await;
    let path = format!("/api/servers/{server_id}");
    let (st, _) = send(&app, "PATCH", &path, Some(&alice), Some(json!({ "name_ciphertext": b64(&[7u8; 300]) }))).await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = send(&app, "PATCH", &path, Some(&alice), Some(json!({ "name_ciphertext": b64(&vec![7u8; crate::structure::MAX_NAME_CIPHERTEXT + 1]) }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "an oversized name was stored");
    let (st, _) = send(&app, "PATCH", &path, Some(&alice), Some(json!({ "name_ciphertext": "" }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = send(&app, "PATCH", &path, Some(&bob), Some(json!({ "name_ciphertext": b64(b"mine now") }))).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a member without MANAGE_SERVER renamed the server");
    let (st, _) = send(&app, "POST", "/api/servers", Some(&alice), Some(json!({ "name_ciphertext": b64(&vec![1u8; crate::structure::MAX_NAME_CIPHERTEXT + 1]) }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    // L9: the description is bounded too, on rename and on create.
    let big = b64(&vec![2u8; crate::structure::MAX_DESCRIPTION_CIPHERTEXT + 1]);
    let (st, _) = send(&app, "PATCH", &path, Some(&alice), Some(json!({ "description_ciphertext": big }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "an oversized description was stored");
    let (st, _) = send(&app, "POST", "/api/servers", Some(&alice), Some(json!({ "name_ciphertext": b64(b"n"), "description_ciphertext": big }))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = send(&app, "PATCH", &path, Some(&alice), Some(json!({ "description_ciphertext": b64(b"short") }))).await;
    assert_eq!(st, StatusCode::OK);
}
