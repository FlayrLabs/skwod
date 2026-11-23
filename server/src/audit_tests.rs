//! Build 45 security audit: one test (at least) per finding fixed in the server.

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::accounts_tests::{b64, first_device, post_as, proof, put_backup_with_verifier, rekey, season, space};
use crate::state::AppState;
use crate::tests::{login, send, send_proved, test_state};

const ADMIN_CODE: &str = "admin-setup-code";

/// An INITIALISED instance (as `skwod init` leaves it): signup needs a code, the first signup
/// owns the instance. Returns the owner's (user id, token), a server of theirs and its channel.
pub(crate) async fn hosted(state: &AppState) -> (Router, String, String, String, String) {
    sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('admin_setup_code', $1, 0)")
        .bind(Sha256::digest(ADMIN_CODE.as_bytes()).to_vec())
        .execute(&state.db)
        .await
        .unwrap();
    let app = crate::api::router(state.clone());
    let (status, body) = join_as(&app, "host", ADMIN_CODE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (owner, token) = (body["user_id"].as_str().unwrap().to_string(), body["token"].as_str().unwrap().to_string());
    let (server, channel) = space(&app, &token).await;
    (app, owner, token, server, channel)
}

pub(crate) async fn join_as(app: &Router, username: &str, code: &str) -> (StatusCode, Value) {
    send(app, "POST", "/api/auth/signup", None, Some(json!({ "username": username, "password": "correct horse", "join_code": code }))).await
}

pub(crate) async fn invite(app: &Router, owner: &str, server: &str, body: Value) -> String {
    let (status, res) = send(app, "POST", &format!("/api/servers/{server}/invites"), Some(owner), Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{res}");
    res["code"].as_str().unwrap().to_string()
}

/// Sign up with a one-time link and redeem it: an admitted member. Returns (user id, token).
pub(crate) async fn member(app: &Router, owner: &str, server: &str, username: &str) -> (String, String) {
    let code = invite(app, owner, server, json!({ "kind": "token" })).await;
    let (status, body) = join_as(app, username, &code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let (status, res) = send(app, "POST", &format!("/api/invites/{code}/accept"), Some(&token), None).await;
    assert_eq!(status, StatusCode::OK, "{res}");
    (body["user_id"].as_str().unwrap().to_string(), token)
}

/// Sign up with a "code" invite and ask to join: an account in the waiting room.
pub(crate) async fn waiting(app: &Router, code: &str, username: &str) -> (String, String) {
    let (status, body) = join_as(app, username, code).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let (status, res) = send(app, "POST", &format!("/api/invites/{code}/accept"), Some(&token), None).await;
    assert_eq!((status, res["pending"].as_bool()), (StatusCode::OK, Some(true)), "{res}");
    (body["user_id"].as_str().unwrap().to_string(), token)
}

// ---- H1 ----

#[tokio::test]
async fn h1_a_signup_uses_the_invite_up() {
    let mut state = test_state().await;
    state.invite_pending_signups = 2;
    let (app, _owner, host, server, _) = hosted(&state).await;

    // A one-time link makes ONE account — and that account can still redeem the link.
    let link = invite(&app, &host, &server, json!({ "kind": "token" })).await;
    let (status, first) = join_as(&app, "first", &link).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(join_as(&app, "second", &link).await.0, StatusCode::FORBIDDEN, "the link's one use is taken");
    let token = first["token"].as_str().unwrap();
    assert_eq!(send(&app, "POST", &format!("/api/invites/{link}/accept"), Some(token), None).await.0, StatusCode::OK);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users").fetch_one(&state.db).await.unwrap(), 2, "host + first; the refused signup left nothing");

    // max_uses counts accounts too.
    let two = invite(&app, &host, &server, json!({ "kind": "code", "max_uses": 2 })).await;
    for name in ["acct1", "acct2"] {
        assert_eq!(join_as(&app, name, &two).await.0, StatusCode::OK);
    }
    assert_eq!(join_as(&app, "acct3", &two).await.0, StatusCode::FORBIDDEN);

    // An unlimited code: only so many accounts nobody has admitted, at a time.
    let code = invite(&app, &host, &server, json!({ "kind": "code" })).await;
    let (w1, _) = waiting(&app, &code, "wait1").await;
    waiting(&app, &code, "wait2").await;
    let mut host_events = state.rt.subscribe();
    let mut told = move || std::iter::from_fn(|| host_events.try_recv().ok()).filter(|e| e.frame.contains("\"invite_full\"")).map(|e| e.frame).collect::<Vec<_>>();
    let (status, refused) = join_as(&app, "wait3", &code).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "two are already waiting on this code");
    // …and both sides are told why: the joiner in words its app shows, the host in an event,
    // in the invite list and on the admin page — not a bare "forbidden" nobody can act on.
    assert_eq!(refused["error"], crate::join::INVITE_FULL);
    let events = told();
    assert!(events.len() == 1 && events[0].contains(&code) && events[0].contains(&crate::rt::user_topic(&_owner)), "the host is told: {events:?}");
    assert_eq!(join_as(&app, "wait3", &code).await.0, StatusCode::FORBIDDEN);
    assert!(told().is_empty(), "once an hour per invite, however often it is tried");
    let (_, list) = send(&app, "GET", &format!("/api/servers/{server}/invites"), Some(&host), None).await;
    let listed = list["invites"].as_array().unwrap().iter().find(|i| i["code"] == code.as_str()).unwrap();
    assert_eq!((listed["waiting"].as_i64(), listed["waiting_cap"].as_i64(), listed["waiting_full"].as_bool()), (Some(2), Some(2), Some(true)), "{listed}");
    // An invalid or used-up invite still answers the plain refusal.
    assert_eq!(join_as(&app, "nocode", "not-a-code").await.1["error"], "forbidden");
    // The host lets one in: a place is free again.
    assert_eq!(send(&app, "POST", &format!("/api/servers/{server}/join-requests/{w1}/approve"), Some(&host), Some(json!({}))).await.0, StatusCode::OK);
    assert_eq!(join_as(&app, "wait3", &code).await.0, StatusCode::OK);
    assert_eq!(join_as(&app, "wait4", &code).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn h1_an_unapproved_account_gets_the_waiting_room_and_nothing_else() {
    let state = test_state().await;
    let (app, owner, host, server, channel) = hosted(&state).await;
    let (_host_store, host_device) = first_device(&app, &host).await;
    let (friend, _) = member(&app, &host, &server, "friend").await;
    let code = invite(&app, &host, &server, json!({ "kind": "code" })).await;
    let (stranger, token) = waiting(&app, &code, "stranger").await;

    // What it needs to wait and to be let in.
    let (_store, device) = first_device(&app, &token).await;
    for (method, path) in [
        ("GET", "/api/auth/me".to_string()),
        ("GET", "/api/servers".to_string()),
        ("GET", "/api/dms".to_string()),
        ("GET", "/api/e2ee/devices".to_string()),
        ("GET", format!("/api/e2ee/sealed/inbox?device_id={device}")),
        ("GET", format!("/api/e2ee/users/{stranger}/devices")),
        ("GET", format!("/api/invites/{code}/check")),
        ("GET", "/api/instance/can-create-servers".to_string()),
    ] {
        assert_eq!(send(&app, method, &path, Some(&token), None).await.0, StatusCode::OK, "{method} {path}");
    }

    // Everything else: closed, with an answer an app can tell from an error.
    let gateway = json!({ "provider": "gateway", "gateway": "https://push.example.org", "apns_token": "ab".repeat(32), "voip_token": null, "topic": "io.skwod.app" });
    for (method, path, body) in [
        ("GET", "/api/users/lookup?username=friend".to_string(), None),
        ("GET", "/api/users/lookup?username=host".to_string(), None),
        ("POST", "/api/dms".to_string(), Some(json!({ "participant_ids": [friend] }))),
        ("POST", "/api/dms".to_string(), Some(json!({ "participant_ids": [] }))),
        ("GET", format!("/api/e2ee/users/{friend}/devices"), None),
        ("GET", format!("/api/e2ee/users/{owner}/devices"), None),
        ("GET", format!("/api/e2ee/member-devices?server_id={server}"), None),
        ("POST", "/api/e2ee/prekey-bundle".to_string(), Some(json!({ "protocol_version": 2, "user_id": owner, "device_id": host_device }))),
        ("POST", "/api/e2ee/certificates".to_string(), Some(json!({ "device_id": device }))),
        ("POST", "/api/push/register".to_string(), Some(gateway)),
        ("POST", "/api/push/register".to_string(), Some(json!({ "token": "t", "platform": "ios" }))),
        ("POST", "/api/blobs".to_string(), Some(json!({ "total_size": 10 }))),
        ("POST", "/api/servers".to_string(), Some(json!({ "name_ciphertext": b64(b"mine") }))),
        ("GET", format!("/api/servers/{server}/members"), None),
        ("POST", format!("/api/channels/{channel}/messages"), Some(json!({ "ciphertext": b64(b"x") }))),
        ("PUT", format!("/api/blocks/{friend}"), Some(json!({}))),
    ] {
        let (status, res) = send(&app, method, &path, Some(&token), body).await;
        assert_eq!((status, res["error"].as_str()), (StatusCode::FORBIDDEN, Some("waiting for approval")), "{method} {path}");
    }
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap(), 0);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM dm_conversations").fetch_one(&state.db).await.unwrap(), 0);

    // The host — who decides — sees the newcomer (name check, fingerprint, the keys to
    // provision them with); the newcomer has no such claim on the host.
    let (status, found) = send(&app, "GET", "/api/users/lookup?username=stranger", Some(&host), None).await;
    assert_eq!((status, found["user_id"].as_str()), (StatusCode::OK, Some(stranger.as_str())));
    assert_eq!(send(&app, "GET", &format!("/api/e2ee/users/{stranger}/devices"), Some(&host), None).await.0, StatusCode::OK);
    // A member who does not decide has nothing to do with them yet.
    let friend_token = login(&app, "friend").await;
    assert_eq!(send(&app, "GET", "/api/users/lookup?username=stranger", Some(&friend_token), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, "GET", &format!("/api/e2ee/users/{stranger}/devices"), Some(&friend_token), None).await.0, StatusCode::FORBIDDEN);

    // Let in: the same token now works everywhere a member's does.
    assert_eq!(send(&app, "POST", &format!("/api/servers/{server}/join-requests/{stranger}/approve"), Some(&host), Some(json!({}))).await.0, StatusCode::OK);
    assert_eq!(send(&app, "GET", "/api/users/lookup?username=friend", Some(&token), None).await.0, StatusCode::OK);
    assert_eq!(send(&app, "POST", "/api/dms", Some(&token), Some(json!({ "participant_ids": [friend] }))).await.0, StatusCode::OK);
    // …and removed again: back outside.
    assert_eq!(send(&app, "DELETE", &format!("/api/servers/{server}/members/{stranger}"), Some(&host), None).await.0, StatusCode::OK);
    assert_eq!(send(&app, "GET", "/api/users/lookup?username=friend", Some(&token), None).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn h1_lookup_and_dms_need_a_shared_server_and_are_rate_limited() {
    let state = test_state().await;
    let (app, _owner, host, server, _) = hosted(&state).await;
    let (alice, alice_token) = member(&app, &host, &server, "alice").await;
    let (bob, _) = member(&app, &host, &server, "bob").await;
    // Carol is admitted — but to ANOTHER server, which the owner let someone else create.
    let (dave, dave_token) = member(&app, &host, &server, "dave").await;
    assert_eq!(send(&app, "PUT", &format!("/api/instance/server-creators/{dave}"), Some(&host), None).await.0, StatusCode::OK);
    let (other_server, _) = space(&app, &dave_token).await;
    let (carol, carol_token) = member(&app, &dave_token, &other_server, "carol").await;

    // Same server: found, and a conversation opens.
    let (status, found) = send(&app, "GET", "/api/users/lookup?username=bob", Some(&alice_token), None).await;
    assert_eq!((status, found["user_id"].as_str()), (StatusCode::OK, Some(bob.as_str())));
    assert_eq!(send(&app, "POST", "/api/dms", Some(&alice_token), Some(json!({ "participant_ids": [bob] }))).await.0, StatusCode::OK);
    // No server in common: "not found", exactly like a name nobody has — and no conversation,
    // alone or smuggled into a group with someone the caller does know.
    assert_eq!(send(&app, "GET", "/api/users/lookup?username=alice", Some(&carol_token), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, "GET", "/api/users/lookup?username=nobody_here", Some(&carol_token), None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, "POST", "/api/dms", Some(&carol_token), Some(json!({ "participant_ids": [alice] }))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, "POST", "/api/dms", Some(&carol_token), Some(json!({ "participant_ids": [dave, alice] }))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, "POST", "/api/dms", Some(&alice_token), Some(json!({ "participant_ids": [carol] }))).await.0, StatusCode::NOT_FOUND);
    assert_eq!(send(&app, "POST", "/api/dms", Some(&carol_token), Some(json!({ "participant_ids": [dave] }))).await.0, StatusCode::OK);

    // Lookups: 120 a minute. (Alice made one above.)
    for _ in 0..119 {
        assert_eq!(send(&app, "GET", "/api/users/lookup?username=bob", Some(&alice_token), None).await.0, StatusCode::OK);
    }
    assert_eq!(send(&app, "GET", "/api/users/lookup?username=bob", Some(&alice_token), None).await.0, StatusCode::TOO_MANY_REQUESTS);
    // New conversations: 30 an hour (group conversations are never deduplicated).
    let mut last = StatusCode::OK;
    for _ in 0..31 {
        last = send(&app, "POST", "/api/dms", Some(&dave_token), Some(json!({ "participant_ids": [alice, bob] }))).await.0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // Re-opening an existing 1:1 is not a new conversation and is not counted.
    assert_eq!(send(&app, "POST", "/api/dms", Some(&alice_token), Some(json!({ "participant_ids": [bob] }))).await.1["existing"], true);
}

#[tokio::test]
async fn h1_a_conversation_row_alone_unlocks_no_keys() {
    let state = test_state().await;
    let (app, _owner, host, server, _) = hosted(&state).await;
    let (alice, alice_token) = member(&app, &host, &server, "alice").await;
    let (_alice_store, alice_device) = first_device(&app, &alice_token).await;
    let (mallory, mallory_token) = member(&app, &host, &server, "mallory").await;
    first_device(&app, &mallory_token).await;
    // A row from before conversations needed a relationship: Mallory opened it, then left the
    // server (she stays admitted through a grant, so only the relationship is in question).
    let (_, conv) = send(&app, "POST", "/api/dms", Some(&mallory_token), Some(json!({ "participant_ids": [alice] }))).await;
    let conv = conv["conversation_id"].as_str().unwrap().to_string();
    assert_eq!(send(&app, "PUT", &format!("/api/instance/server-creators/{mallory}"), Some(&host), None).await.0, StatusCode::OK);
    assert_eq!(send(&app, "DELETE", &format!("/api/servers/{server}/members/{mallory}"), Some(&host), None).await.0, StatusCode::OK);

    let devices = format!("/api/e2ee/users/{alice}/devices");
    let bundle = json!({ "protocol_version": 2, "user_id": alice, "device_id": alice_device });
    assert_eq!(send(&app, "GET", &devices, Some(&mallory_token), None).await.0, StatusCode::FORBIDDEN, "the row alone is not a relationship");
    assert_eq!(send(&app, "POST", "/api/e2ee/prekey-bundle", Some(&mallory_token), Some(bundle.clone())).await.0, StatusCode::FORBIDDEN);
    // Nor a way to keep writing to her.
    assert_eq!(send(&app, "POST", &format!("/api/dms/{conv}/messages"), Some(&mallory_token), Some(json!({ "ciphertext": b64(b"hi") }))).await.0, StatusCode::FORBIDDEN);
    // One side having written changes nothing…
    let write = |author: String| {
        let (db, conv) = (state.db.clone(), conv.clone());
        async move {
            sqlx::query(&crate::tests::pg("INSERT INTO dm_messages (id, conversation_id, author_id, ciphertext, created_at, updated_at) VALUES ($1, $2, $3, x'00', 0, 0)"))
                .bind(crate::state::new_id())
                .bind(conv)
                .bind(author)
                .execute(&db)
                .await
                .unwrap();
        }
    };
    write(mallory.clone()).await;
    assert_eq!(send(&app, "GET", &devices, Some(&mallory_token), None).await.0, StatusCode::FORBIDDEN);
    // …both having written is a conversation Alice took part in.
    write(alice.clone()).await;
    assert_eq!(send(&app, "GET", &devices, Some(&mallory_token), None).await.0, StatusCode::OK);
    assert_eq!(send(&app, "POST", &format!("/api/dms/{conv}/messages"), Some(&mallory_token), Some(json!({ "ciphertext": b64(b"hi") }))).await.0, StatusCode::OK);
}

// ---- M1 ----

#[tokio::test]
async fn m1_ciphertexts_and_reactions_are_capped_and_reactions_rate_limited() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, token) = crate::tests::signup(&app, "alice").await;
    let (_store, device) = first_device(&app, &token).await;
    let (_server, channel) = space(&app, &token).await;
    let (_, dm) = send(&app, "POST", "/api/dms", Some(&token), Some(json!({ "participant_ids": [] }))).await;
    let dm = dm["conversation_id"].as_str().unwrap().to_string();
    let send_to = |path: String, bytes: usize| {
        let (app, token, device) = (app.clone(), token.clone(), device.clone());
        async move { send(&app, "POST", &path, Some(&token), Some(json!({ "ciphertext": b64(&vec![7u8; bytes]), "author_device_id": device }))).await }
    };
    let max = crate::storage::MAX_MESSAGE_CIPHERTEXT;
    for path in [format!("/api/channels/{channel}/messages"), format!("/api/dms/{dm}/messages")] {
        // The largest message a current client can produce is accepted…
        let (status, body) = send_to(path.clone(), max).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        // …one byte more is not stored, and neither is anything near the old 2 MB.
        assert_eq!(send_to(path.clone(), max + 1).await.0, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
        assert_eq!(send_to(path.clone(), 1024 * 1024).await.0, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
    }
    // Edits store a ciphertext too.
    let message = post_as(&app, &token, &channel, &device).await.1["message_id"].as_str().unwrap().to_string();
    let edit = json!({ "ciphertext": b64(&vec![7u8; max + 1]), "author_device_id": device });
    assert_eq!(send(&app, "PATCH", &format!("/api/messages/{message}"), Some(&token), Some(edit)).await.0, StatusCode::PAYLOAD_TOO_LARGE);

    // Reactions: small, and not unlimited.
    let react = |hash: String, bytes: usize| {
        let (app, token, message) = (app.clone(), token.clone(), message.clone());
        async move { send(&app, "POST", &format!("/api/messages/{message}/reactions"), Some(&token), Some(json!({ "emoji_ciphertext": b64(&vec![1u8; bytes]), "emoji_hash": hash }))).await.0 }
    };
    assert_eq!(react("h-big".into(), crate::storage::MAX_REACTION_CIPHERTEXT + 1).await, StatusCode::BAD_REQUEST);
    assert_eq!(react("h".repeat(crate::storage::MAX_REACTION_HASH + 1), 40).await, StatusCode::BAD_REQUEST);
    let mut statuses = Vec::new();
    for i in 0..125 {
        statuses.push(react(format!("h{i}"), 40).await);
    }
    assert_eq!(statuses[0], StatusCode::OK);
    assert_eq!(statuses[110], StatusCode::OK);
    assert_eq!(statuses[124], StatusCode::TOO_MANY_REQUESTS, "120 reactions a minute (the two refused above count)");
}

#[tokio::test]
async fn m1_quota_and_free_space_floor_cover_messages_dms_reactions_and_attachment_metadata() {
    // Everything an account can make the database store, as (what, method, path, body).
    async fn attempts(state: &AppState, app: &Router, user: &str, token: &str) -> Vec<(&'static str, StatusCode)> {
        sqlx::query("INSERT INTO blobs (id, owner_id, total_size, received_bytes, complete, created_at, updated_at) VALUES ('b1', $1, 4, 4, 1, 0, 0)").bind(user).execute(&state.db).await.unwrap();
        let (_store, device) = first_device(app, token).await;
        let (_server, channel) = space(app, token).await;
        let (_, dm) = send(app, "POST", "/api/dms", Some(token), Some(json!({ "participant_ids": [] }))).await;
        let dm = dm["conversation_id"].as_str().unwrap().to_string();
        // One small message in each, to react and attach to (the quota below leaves room for these).
        let body = json!({ "ciphertext": b64(b"ok"), "author_device_id": device });
        let message = send(app, "POST", &format!("/api/channels/{channel}/messages"), Some(token), Some(body.clone())).await.1["message_id"].as_str().unwrap().to_string();
        let dm_message = send(app, "POST", &format!("/api/dms/{dm}/messages"), Some(token), Some(body)).await.1["message_id"].as_str().unwrap().to_string();
        let big = json!({ "ciphertext": b64(&[7u8; 2000]), "author_device_id": device });
        let reaction = json!({ "emoji_ciphertext": b64(&[1u8; 400]), "emoji_hash": "h".repeat(100) });
        let attach = json!({ "blob_id": "b1", "metadata_ciphertext": b64(&[2u8; 2000]) });
        let mut out = Vec::new();
        for (what, method, path, body) in [
            ("channel message", "POST", format!("/api/channels/{channel}/messages"), big.clone()),
            ("channel edit", "PATCH", format!("/api/messages/{message}"), big.clone()),
            ("dm message", "POST", format!("/api/dms/{dm}/messages"), big.clone()),
            ("dm edit", "PATCH", format!("/api/dm-messages/{dm_message}"), big.clone()),
            ("reaction", "POST", format!("/api/messages/{message}/reactions"), reaction.clone()),
            ("dm reaction", "POST", format!("/api/dm-messages/{dm_message}/reactions"), reaction),
            ("attachment metadata", "POST", format!("/api/messages/{message}/attachments"), attach.clone()),
            ("dm attachment metadata", "POST", format!("/api/dm-messages/{dm_message}/attachments"), attach),
        ] {
            out.push((what, send(app, method, &path, Some(token), Some(body)).await.0));
        }
        out
    }

    // Over the account's quota: 413 on every route.
    let mut state = test_state().await;
    state.message_quota_bytes = 300;
    // (No free-space floor in this half: the test must not depend on how full the build machine is.)
    state.blob_free_floor_bytes = 0;
    let app = crate::api::router(state.clone());
    let (user, token) = crate::tests::signup(&app, "alice").await;
    for (what, status) in attempts(&state, &app, &user, &token).await {
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{what} must count against the quota");
    }
    assert!(sqlx::query_scalar::<_, i64>("SELECT COALESCE(SUM(length(ciphertext)), 0) FROM messages").fetch_one(&state.db).await.unwrap() < 300);
    // The quota is per account: someone else is not affected by Alice being full.
    let (_, bob) = crate::tests::signup(&app, "bob").await;
    let (_bob_store, bob_device) = first_device(&app, &bob).await;
    let (_s, bob_channel) = space(&app, &bob).await;
    assert_eq!(post_as(&app, &bob, &bob_channel, &bob_device).await.0, StatusCode::OK);

    // Below the free-space floor: 507 on every route, whoever asks.
    let mut state = test_state().await;
    state.blob_free_floor_bytes = 0;
    let app = crate::api::router(state.clone());
    let (_, token) = crate::tests::signup(&app, "alice").await;
    let (_store, device) = first_device(&app, &token).await;
    let (_server, channel) = space(&app, &token).await;
    assert_eq!(post_as(&app, &token, &channel, &device).await.0, StatusCode::OK, "with room to spare, a message is stored");
    let mut state = test_state().await;
    state.blob_free_floor_bytes = u64::MAX / 4;
    let app = crate::api::router(state.clone());
    let (user, token) = crate::tests::signup(&app, "alice").await;
    // (The setup rows are written directly: with the floor this high nothing gets in by the API.)
    let (_store, device) = first_device(&app, &token).await;
    let (_server, channel) = space(&app, &token).await;
    let (_, dm) = send(&app, "POST", "/api/dms", Some(&token), Some(json!({ "participant_ids": [] }))).await;
    let dm = dm["conversation_id"].as_str().unwrap().to_string();
    sqlx::query(&crate::tests::pg("INSERT INTO messages (id, channel_id, author_id, ciphertext, created_at, updated_at) VALUES ('m1', $1, $2, x'00', 0, 0)")).bind(&channel).bind(&user).execute(&state.db).await.unwrap();
    sqlx::query(&crate::tests::pg("INSERT INTO dm_messages (id, conversation_id, author_id, ciphertext, created_at, updated_at) VALUES ('d1', $1, $2, x'00', 0, 0)")).bind(&dm).bind(&user).execute(&state.db).await.unwrap();
    sqlx::query("INSERT INTO blobs (id, owner_id, total_size, received_bytes, complete, created_at, updated_at) VALUES ('b1', $1, 4, 4, 1, 0, 0)").bind(&user).execute(&state.db).await.unwrap();
    let small = json!({ "ciphertext": b64(b"ok"), "author_device_id": device });
    let reaction = json!({ "emoji_ciphertext": b64(&[1u8; 40]), "emoji_hash": "h" });
    let attach = json!({ "blob_id": "b1", "metadata_ciphertext": b64(&[2u8; 40]) });
    for (what, method, path, body) in [
        ("channel message", "POST", format!("/api/channels/{channel}/messages"), small.clone()),
        ("channel edit", "PATCH", "/api/messages/m1".to_string(), small.clone()),
        ("dm message", "POST", format!("/api/dms/{dm}/messages"), small.clone()),
        ("dm edit", "PATCH", "/api/dm-messages/d1".to_string(), small.clone()),
        ("reaction", "POST", "/api/messages/m1/reactions".to_string(), reaction.clone()),
        ("dm reaction", "POST", "/api/dm-messages/d1/reactions".to_string(), reaction),
        ("attachment metadata", "POST", "/api/messages/m1/attachments".to_string(), attach.clone()),
        ("dm attachment metadata", "POST", "/api/dm-messages/d1/attachments".to_string(), attach),
    ] {
        assert_eq!(send(&app, method, &path, Some(&token), Some(body)).await.0, StatusCode::INSUFFICIENT_STORAGE, "{what} must respect the free-space floor");
    }
}

#[tokio::test]
async fn m1_attachment_metadata_routes_take_a_small_body_only() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user, token) = crate::tests::signup(&app, "alice").await;
    let (_store, device) = first_device(&app, &token).await;
    let (_server, channel) = space(&app, &token).await;
    let message = post_as(&app, &token, &channel, &device).await.1["message_id"].as_str().unwrap().to_string();
    sqlx::query("INSERT INTO blobs (id, owner_id, total_size, received_bytes, complete, created_at, updated_at) VALUES ('b1', $1, 4, 4, 1, 0, 0)").bind(&user).execute(&state.db).await.unwrap();
    let path = format!("/api/messages/{message}/attachments");
    let attach = |bytes: usize| json!({ "blob_id": "b1", "metadata_ciphertext": b64(&vec![2u8; bytes]) });
    assert_eq!(send(&app, "POST", &path, Some(&token), Some(attach(1024))).await.0, StatusCode::OK);
    assert_eq!(send(&app, "POST", &path, Some(&token), Some(attach(crate::storage::MAX_ATTACHMENT_METADATA + 1))).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    // The 16 MiB chunk limit no longer applies here: a megabyte of JSON is cut off by the framework.
    assert_eq!(send(&app, "POST", &path, Some(&token), Some(attach(1024 * 1024))).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    // (Chunk uploads still take their 16 MiB.)
    const { assert!(crate::blobs::MAX_CHUNK > crate::storage::SMALL_BODY_LIMIT) };
}

// ---- M3 ----

#[tokio::test]
async fn m3_deleting_an_account_needs_a_device_not_just_a_token() {
    let state = test_state().await;
    let (app, owner, host, server, _) = hosted(&state).await;
    let (host_store, _host_device) = first_device(&app, &host).await;
    let (alice, alice_token) = member(&app, &host, &server, "alice").await;
    let (alice_store, _alice_device) = first_device(&app, &alice_token).await;
    let (bob, _bob_token) = member(&app, &host, &server, "bob").await;
    let (nodev, nodev_token) = member(&app, &host, &server, "nodevice").await;
    let exists = |id: String| {
        let db = state.db.clone();
        async move { sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE id = $1").bind(id).fetch_one(&db).await.unwrap() == 1 }
    };

    // A second session of Alice's — password only, bound to no device (or a stolen token).
    let stolen = login(&app, "alice").await;
    let path = format!("/api/auth/users/{alice}");
    assert_eq!(send(&app, "DELETE", &path, Some(&stolen), None).await.0, StatusCode::FORBIDDEN);
    // Even with a valid proof by her device, an unbound session is not that device.
    let p = proof(&alice_store, "delete-account", &alice, &alice, b"");
    assert_ne!(send_proved(&app, "DELETE", &path, &stolen, None, &p).await.0, StatusCode::OK);
    // The device's own session without a proof, or with a proof for something else: no.
    assert_eq!(send(&app, "DELETE", &path, Some(&alice_token), None).await.0, StatusCode::FORBIDDEN);
    let wrong = proof(&alice_store, "delete-account", &alice, &bob, b"");
    assert_eq!(send_proved(&app, "DELETE", &path, &alice_token, None, &wrong).await.0, StatusCode::FORBIDDEN);
    assert!(exists(alice.clone()).await);

    // The owner deleting someone else is held to the same rule.
    let bob_path = format!("/api/auth/users/{bob}");
    assert_eq!(send(&app, "DELETE", &bob_path, Some(&host), None).await.0, StatusCode::FORBIDDEN);
    let p = proof(&host_store, "delete-account", &owner, &bob, b"");
    assert_eq!(send_proved(&app, "DELETE", &bob_path, &host, None, &p).await.0, StatusCode::OK);
    assert!(!exists(bob).await);

    // The real thing: her device's session, and its signature over this deletion.
    let p = proof(&alice_store, "delete-account", &alice, &alice, b"");
    assert_eq!(send_proved(&app, "DELETE", &path, &alice_token, None, &p).await.0, StatusCode::OK);
    assert!(!exists(alice).await);

    // An account that never registered a device has nothing to prove with (as for a password change).
    assert_eq!(send(&app, "DELETE", &format!("/api/auth/users/{nodev}"), Some(&nodev_token), None).await.0, StatusCode::OK);
}

// ---- M4 ----

async fn season_pin(state: &AppState, user_id: &str) {
    sqlx::query("UPDATE e2ee_accounts SET pin_set_at = pin_set_at - $1 WHERE user_id = $2").bind(crate::keydir::RESET_DELAY_MS + 1000).bind(user_id).execute(&state.db).await.unwrap();
}

#[tokio::test]
async fn m4_a_fresh_pin_does_not_waive_the_recovery_hold() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user_id, token) = crate::tests::signup(&app, "alice").await;
    let (original, device) = first_device(&app, &token).await;
    // Whoever holds the unlocked phone sets a PIN…
    let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(json!({ "enable": true, "pin": "482913" })), &proof(&original, "set-pin", &user_id, "enable", b"482913")).await;
    assert_eq!(status, StatusCode::OK);
    // …and re-keys the device from their own machine with a copy of the identity key.
    let thief = login(&app, "alice").await;
    let mut copy = skwod_crypto::SignalStore::from_bytes(&original.export_identity()).unwrap();
    let install = [42u8; 32];
    let (status, body) = rekey(&app, &thief, &mut copy, &install, &user_id, &device, Some("482913")).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "a PIN set minutes ago waives nothing: {body}");
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM device_recoveries").fetch_one(&state.db).await.unwrap(), 1, "the request is recorded (and announced), like any other");
    // A wrong PIN is still refused as a wrong PIN, and counted.
    let (status, body) = rekey(&app, &thief, &mut copy, &install, &user_id, &device, Some("000000")).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("registration pin incorrect")));
    // Seven days on, the same PIN is the owner's: at once.
    season_pin(&state, &user_id).await;
    let (status, body) = rekey(&app, &thief, &mut copy, &install, &user_id, &device, Some("482913")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn m4_a_backup_under_an_unseasoned_key_is_only_served_to_a_current_device() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user_id, token) = crate::tests::signup(&app, "alice").await;
    let (store, _device) = first_device(&app, &token).await;
    put_backup_with_verifier(&app, &token, &store, &user_id, &[0x11; 32]).await;
    // The device that wrote it (its session is bound to it) reads it back.
    assert_eq!(send(&app, "GET", "/api/e2ee/key-backup", Some(&token), None).await.0, StatusCode::OK);
    // A password-only session from somewhere else does not get the blob while its key is new…
    let elsewhere = login(&app, "alice").await;
    let (status, body) = send(&app, "GET", "/api/e2ee/key-backup", Some(&elsewhere), None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.get("encrypted_blob").is_none());
    // …and does once the key has been in place for the hold period.
    season(&state, &user_id).await;
    let (status, body) = send(&app, "GET", "/api/e2ee/key-backup", Some(&elsewhere), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["encrypted_blob"].is_string());
}

/// `GET /api/e2ee/key-backup`, presenting an install secret (or none).
async fn backup_as(app: &Router, token: &str, secret: Option<&[u8; 32]>) -> (StatusCode, Value) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let mut req = axum::http::Request::builder().method("GET").uri("/api/e2ee/key-backup").header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(secret) = secret {
        req = req.header("x-skwod-install-secret", b64(secret));
    }
    let res = app.clone().oneshot(req.body(axum::body::Body::empty()).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

/// The pending restore request for `device`, as a current device sees it: its id.
/// The ids of every restore request waiting for `device` (the listing has no order).
async fn restore_requests(app: &Router, token: &str, device: &str) -> Vec<String> {
    let listing = send(app, "GET", "/api/e2ee/devices", Some(token), None).await.1;
    listing["recoveries"].as_array().into_iter().flatten().filter(|r| r["device_id"] == device).filter_map(|r| r["request_id"].as_str().map(str::to_string)).collect()
}

async fn restore_request(app: &Router, token: &str, device: &str) -> Option<String> {
    let listing = send(app, "GET", "/api/e2ee/devices", Some(token), None).await.1;
    let pending = listing["recoveries"].as_array()?.iter().find(|r| r["device_id"] == device)?.clone();
    assert!(pending.get("install_hash").is_none(), "the hash is never handed out");
    pending["request_id"].as_str().map(str::to_string)
}

/// M4, the other half: restore by approval still works. A sign-in that is not a device cannot
/// be handed a backup under a young recovery key — so it ASKS (`/key-backup/request`), and
/// that request is the ordinary recovery request: the account's devices see it, one approves
/// it (device-signed), and only then is the backup served — to the install that asked, and to
/// nobody else — and the re-key that follows completes without a second approval.
#[tokio::test]
async fn m4_a_withheld_backup_is_served_to_the_install_whose_restore_request_was_approved() {
    let mut state = test_state().await;
    // The production default (build 45): the restoring sign-in is bound to no device, and
    // asking for the withheld backup must still reach the server.
    state.require_bound_sessions = true;
    let app = crate::api::router(state.clone());
    let (user_id, token) = crate::tests::signup(&app, "alice").await;
    let (store, device) = first_device(&app, &token).await;
    put_backup_with_verifier(&app, &token, &store, &user_id, &[0x11; 32]).await;
    let elsewhere = login(&app, "alice").await;
    let (install, other_install) = ([0x51u8; 32], [0x52u8; 32]);
    let ask = |install: &[u8; 32]| json!({ "install_hash": b64(&Sha256::digest(install)) });

    // Withheld, with or without a secret; and asking is not being given.
    assert_eq!(backup_as(&app, &elsewhere, Some(&install)).await.0, StatusCode::CONFLICT);
    let (status, body) = send(&app, "POST", "/api/e2ee/key-backup/request", Some(&elsewhere), Some(ask(&install))).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device recovery pending")), "{body}");
    assert!(body["completes_at"].as_i64().is_some());
    assert_eq!(backup_as(&app, &elsewhere, Some(&install)).await.0, StatusCode::CONFLICT, "a request alone opens nothing");
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/request", Some(&elsewhere), Some(ask(&install))).await.0, StatusCode::FORBIDDEN, "asking again is still waiting");
    // The request is about the device the backup restores — the server's record, not the
    // caller's word — and a request needs a well-formed hash.
    let id = restore_request(&app, &token, &device).await.expect("the device is shown the request");
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/request", Some(&elsewhere), Some(json!({ "install_hash": "AAAA" }))).await.0, StatusCode::BAD_REQUEST);
    // The requesting session cannot approve its own request: that takes a device's signature
    // on a session bound to the device.
    let approve = format!("/api/e2ee/devices/{device}/recovery/approve");
    let forged = proof(&skwod_crypto::SignalStore::generate(), "approve-recovery", &user_id, &device, id.as_bytes());
    assert_eq!(send_proved(&app, "POST", &approve, &elsewhere, Some(json!({ "request_id": id })), &forged).await.0, StatusCode::FORBIDDEN);
    assert_eq!(backup_as(&app, &elsewhere, Some(&install)).await.0, StatusCode::CONFLICT);

    // The device approves what it was shown.
    let signed = proof(&store, "approve-recovery", &user_id, &device, id.as_bytes());
    assert_eq!(send_proved(&app, "POST", &approve, &token, Some(json!({ "request_id": id })), &signed).await.0, StatusCode::OK);
    // Served — to the install that holds the secret the request was made with, only.
    assert_eq!(backup_as(&app, &elsewhere, None).await.0, StatusCode::CONFLICT, "not to the session as such");
    assert_eq!(backup_as(&app, &elsewhere, Some(&other_install)).await.0, StatusCode::CONFLICT, "not to another install");
    let third = login(&app, "alice").await;
    assert_eq!(backup_as(&app, &third, Some(&other_install)).await.0, StatusCode::CONFLICT);
    let (status, body) = backup_as(&app, &elsewhere, Some(&install)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["encrypted_blob"].is_string());
    assert_eq!(send(&app, "POST", "/api/e2ee/key-backup/request", Some(&elsewhere), Some(ask(&install))).await.0, StatusCode::OK, "granted");
    // The re-key by the restored identity, from that install, completes on the same approval.
    let mut restored = skwod_crypto::SignalStore::from_bytes(&store.export_identity()).unwrap();
    let (status, body) = rekey(&app, &elsewhere, &mut restored, &install, &user_id, &device, None).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");
    assert!(restore_request(&app, &elsewhere, &device).await.is_none(), "the request is spent");
}

/// The same request refused, replaced, and left unanswered: a refusal withdraws it (nothing is
/// served); another install's request takes its place and the approval of the first does not
/// carry over; and un-cancelled it is granted when the hold has run out — not a moment before.
#[tokio::test]
async fn m4_a_restore_request_can_be_refused_and_otherwise_completes_after_the_hold() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user_id, token) = crate::tests::signup(&app, "alice").await;
    let (store, device) = first_device(&app, &token).await;
    put_backup_with_verifier(&app, &token, &store, &user_id, &[0x11; 32]).await;
    let elsewhere = login(&app, "alice").await;
    let (install, intruder) = ([0x51u8; 32], [0x66u8; 32]);
    let ask = |install: &[u8; 32]| json!({ "install_hash": b64(&Sha256::digest(install)) });
    let request = "/api/e2ee/key-backup/request";

    assert_eq!(send(&app, "POST", request, Some(&elsewhere), Some(ask(&install))).await.0, StatusCode::FORBIDDEN);
    let first = restore_request(&app, &token, &device).await.unwrap();
    // Refused by the device.
    let cancel = proof(&store, "cancel-recovery", &user_id, &device, first.as_bytes());
    assert_eq!(send_proved(&app, "POST", &format!("/api/e2ee/devices/{device}/recovery/cancel"), &token, Some(json!({ "request_id": first })), &cancel).await.0, StatusCode::OK);
    assert!(restore_request(&app, &token, &device).await.is_none());
    assert_eq!(backup_as(&app, &elsewhere, Some(&install)).await.0, StatusCode::CONFLICT);

    // Asked again; then another install asks too. Its request is filed beside this one and
    // changes nothing about it (audit L1); nothing is served to either yet.
    assert_eq!(send(&app, "POST", request, Some(&elsewhere), Some(ask(&install))).await.0, StatusCode::FORBIDDEN);
    let shown = restore_request(&app, &token, &device).await.unwrap();
    assert_ne!(shown, first);
    let other_session = login(&app, "alice").await;
    assert_eq!(send(&app, "POST", request, Some(&other_session), Some(ask(&intruder))).await.0, StatusCode::FORBIDDEN);
    // (Two are listed now, in no particular order: the first is still among them, as it was.)
    let both = restore_requests(&app, &token, &device).await;
    assert!(both.len() == 2 && both.contains(&shown), "the first request is untouched: {both:?}");
    assert_eq!(backup_as(&app, &elsewhere, Some(&install)).await.0, StatusCode::CONFLICT);
    assert_eq!(backup_as(&app, &other_session, Some(&intruder)).await.0, StatusCode::CONFLICT);
    // The device refuses the intruder's request — that one alone.
    let listing = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await.1;
    let theirs = listing["recoveries"].as_array().unwrap().iter().map(|r| r["request_id"].as_str().unwrap().to_string()).find(|id| id != &shown).unwrap();
    let refuse = proof(&store, "cancel-recovery", &user_id, &device, theirs.as_bytes());
    assert_eq!(send_proved(&app, "POST", &format!("/api/e2ee/devices/{device}/recovery/cancel"), &token, Some(json!({ "request_id": theirs })), &refuse).await.0, StatusCode::OK);
    assert_eq!(restore_request(&app, &token, &device).await.as_deref(), Some(shown.as_str()));

    // It was contested while it waited, so the hold alone never grants it — even past it.
    let age = |by: i64| sqlx::query("UPDATE device_recoveries SET requested_at = requested_at - $1").bind(by).execute(&state.db);
    age(crate::keydir::RESET_DELAY_MS + 60_000).await.unwrap();
    assert_eq!(backup_as(&app, &elsewhere, Some(&install)).await.0, StatusCode::CONFLICT);
    assert_eq!(send(&app, "POST", request, Some(&elsewhere), Some(ask(&install))).await.0, StatusCode::FORBIDDEN);
    // The device approves what it was shown: granted to that install — and only that one.
    let tap = proof(&store, "approve-recovery", &user_id, &device, shown.as_bytes());
    assert_eq!(send_proved(&app, "POST", &format!("/api/e2ee/devices/{device}/recovery/approve"), &token, Some(json!({ "request_id": shown })), &tap).await.0, StatusCode::OK);
    assert_eq!(backup_as(&app, &other_session, Some(&intruder)).await.0, StatusCode::CONFLICT);
    assert_eq!(backup_as(&app, &elsewhere, Some(&install)).await.0, StatusCode::OK);
    assert_eq!(send(&app, "POST", request, Some(&elsewhere), Some(ask(&install))).await.0, StatusCode::OK);

    // An account with no backup has nothing to ask for; and a backup whose device the server
    // cannot name (written before it kept track, several devices) is as before: wait.
    let (_, bob) = crate::tests::signup(&app, "bob").await;
    assert_eq!(send(&app, "POST", request, Some(&bob), Some(ask(&install))).await.0, StatusCode::NOT_FOUND);
    sqlx::query("UPDATE e2ee_key_backups SET device_id = 'gone-device' WHERE user_id = $1").bind(&user_id).execute(&state.db).await.unwrap();
    assert_eq!(send(&app, "POST", request, Some(&elsewhere), Some(ask(&install))).await.0, StatusCode::CONFLICT);
    assert_eq!(backup_as(&app, &other_session, Some(&intruder)).await.0, StatusCode::CONFLICT, "and a grant for a device it no longer names serves nothing");
}

// ---- M6 ----

#[tokio::test]
async fn m6_one_source_cannot_take_a_whole_mailbox() {
    let mut state = test_state().await;
    state.blob_free_floor_bytes = 0;
    let app = crate::api::router(state.clone());
    let (user_id, token) = crate::tests::signup(&app, "alice").await;
    let (_store, device) = first_device(&app, &token).await;
    let delivery_key = b64(&[9u8; 32]);
    let deposit = |n: usize, bytes: usize| {
        let (app, user_id, device, delivery_key) = (app.clone(), user_id.clone(), device.clone(), delivery_key.clone());
        async move {
            let messages: Vec<Value> = (0..n).map(|_| json!({ "user_id": user_id, "device_id": device, "delivery_key": delivery_key, "envelope": b64(&vec![5u8; bytes]) })).collect();
            let (status, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(json!({ "messages": messages }))).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["results"].as_array().unwrap().iter().filter(|r| r["status"] == "ok").count()
        }
    };
    assert_eq!(deposit(3, 100).await, 3);
    // The device stops reading and its box fills to half (by whoever: deposits carry no sender).
    for i in 0..2500 {
        sqlx::query(&crate::tests::pg("INSERT INTO sealed_envelopes (id, user_id, device_id, envelope, seq, created_at) VALUES ($1, $2, $3, x'00', $4, $5)"))
            .bind(format!("fill-{i}"))
            .bind(&user_id)
            .bind(&device)
            .bind(i as i64)
            .bind(crate::state::now_ms())
            .execute(&state.db)
            .await
            .unwrap();
    }
    // From here one source gets 500 more today, and then "busy" — the other half stays free.
    assert_eq!(deposit(250, 10).await, 250);
    assert_eq!(deposit(256, 10).await, 250, "the source's share of a crowded box is used up mid-request");
    assert_eq!(deposit(10, 10).await, 0);
    let queued: i64 = sqlx::query_scalar("SELECT count(*) FROM sealed_envelopes").fetch_one(&state.db).await.unwrap();
    assert_eq!(queued, 3 + 2500 + 500, "half the box is still free for everyone else");
    // Reading empties the box, and the same source is welcome again.
    sqlx::query("DELETE FROM sealed_envelopes").execute(&state.db).await.unwrap();
    assert_eq!(deposit(5, 10).await, 5);
}

#[tokio::test]
async fn m6_a_mailbox_is_bounded_in_bytes_and_respects_the_free_space_floor() {
    let mut state = test_state().await;
    state.blob_free_floor_bytes = 0;
    let app = crate::api::router(state.clone());
    let (user_id, token) = crate::tests::signup(&app, "alice").await;
    let (_store, device) = first_device(&app, &token).await;
    let one = |app: Router, bytes: usize| {
        let (user_id, device) = (user_id.clone(), device.clone());
        async move {
            let body = json!({ "messages": [{ "user_id": user_id, "device_id": device, "delivery_key": b64(&[9u8; 32]), "envelope": b64(&vec![5u8; bytes]) }] });
            send(&app, "POST", "/api/e2ee/sealed/send", None, Some(body)).await.1["results"][0]["status"].as_str().unwrap().to_string()
        }
    };
    // 64 MiB of queued mail, written directly (zeroblob keeps the test fast).
    sqlx::query(&crate::tests::pg("INSERT INTO sealed_envelopes (id, user_id, device_id, envelope, seq, created_at) VALUES ('big', $1, $2, zeroblob(67108864 - 100), 1, $3)"))
        .bind(&user_id)
        .bind(&device)
        .bind(crate::state::now_ms())
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(one(app.clone(), 100).await, "ok");
    assert_eq!(one(app.clone(), 1).await, "busy", "the box is full in bytes long before 5,000 envelopes");
    sqlx::query("DELETE FROM sealed_envelopes").execute(&state.db).await.unwrap();
    assert_eq!(one(app.clone(), 100).await, "ok");
    state.blob_free_floor_bytes = u64::MAX / 4;
    assert_eq!(one(crate::api::router(state.clone()), 100).await, "busy", "a host below its free-space floor queues nothing");
}

// ---- L1 ----

#[test]
fn l1_a_connection_has_a_frame_budget() {
    let mut budget = crate::ws::FrameBudget::new();
    let start = std::time::Instant::now();
    for _ in 0..crate::ws::FRAMES_PER_WINDOW {
        assert!(budget.take(start));
    }
    assert!(!budget.take(start), "over budget inside the window");
    assert!(budget.take(start + crate::ws::FRAME_WINDOW), "a new window, a new budget");
}

#[tokio::test]
async fn l1_a_flooding_socket_is_closed_and_sockets_per_account_are_capped() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let addr = crate::basics_tests::serve(&state).await;
    let (user, token) = crate::tests::signup(&app, "alice").await;
    let url = format!("ws://{addr}/api/ws?token={token}");

    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    for _ in 0..=crate::ws::FRAMES_PER_WINDOW {
        if ws.send(Message::Text(r#"{"type":"ping"}"#.into())).await.is_err() {
            break;
        }
    }
    let closed = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut told = false;
        while let Some(Ok(m)) = ws.next().await {
            match m {
                Message::Text(t) if t.contains("too many frames") => told = true,
                Message::Close(_) => return told,
                _ => {}
            }
        }
        told
    })
    .await;
    assert_eq!(closed, Ok(true), "the connection is told why and closed");

    // The cap on open sockets: at the limit, the next upgrade is refused.
    state.ws_conns.lock().await.insert(user.clone(), crate::ws::MAX_SOCKETS_PER_USER);
    let refused = tokio_tungstenite::connect_async(&url).await;
    assert!(matches!(refused, Err(tokio_tungstenite::tungstenite::Error::Http(ref r)) if r.status() == 429), "{refused:?}");
    state.ws_conns.lock().await.insert(user, crate::ws::MAX_SOCKETS_PER_USER - 1);
    assert!(tokio_tungstenite::connect_async(&url).await.is_ok());
}

// ---- L2 ----

#[tokio::test]
async fn l2_the_unauthenticated_transparency_and_attestation_routes_are_gone() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user, token) = crate::tests::signup(&app, "alice").await;
    let (_store, device) = first_device(&app, &token).await;
    for (method, path, body) in [
        ("POST", "/api/e2ee/transparency".to_string(), Some(json!({ "device_id": device, "commitment": "c", "identity_key_hash": "h" }))),
        ("GET", format!("/api/e2ee/transparency?user_id={user}"), None),
        ("POST", "/api/e2ee/attestations/challenge".to_string(), Some(json!({ "target_device_id": device, "challenger_device_id": device, "challenge_data": "{}" }))),
        ("POST", "/api/e2ee/attestations/respond".to_string(), Some(json!({ "target_device_id": device, "challenger_device_id": device, "proof_data": "{}" }))),
        ("GET", format!("/api/e2ee/attestations?device_id={device}"), None),
    ] {
        assert_eq!(send(&app, method, &path, Some(&token), body).await.0, StatusCode::NOT_FOUND, "{method} {path}");
    }
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_devices WHERE attested = 1").fetch_one(&state.db).await.unwrap(), 0);
}

// ---- L8 ----

#[tokio::test]
async fn l8_without_an_allowlist_the_owner_decides_the_gateway_host() {
    let state = test_state().await;
    assert!(state.waker.policy.allowed_hosts.is_none(), "this test is about a build and environment with no list");
    let (app, _owner, host, server, _) = hosted(&state).await;
    let (_, member_token) = member(&app, &host, &server, "alice").await;
    let reg = |gateway: &str, token: char| json!({ "provider": "gateway", "gateway": gateway, "apns_token": token.to_string().repeat(64), "voip_token": null, "topic": "io.skwod.app" });
    // A member cannot make the host call a server of the member's choosing…
    let (status, body) = send(&app, "POST", "/api/push/register", Some(&member_token), Some(reg("https://attacker.example.org", 'a'))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    // …the owner's app names the gateway, once…
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&host), Some(reg("https://push.example.org", 'b'))).await.0, StatusCode::OK);
    // …and from then on that host, and only that host, is accepted — from anyone, the owner included.
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&member_token), Some(reg("https://push.example.org/", 'a'))).await.0, StatusCode::OK);
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&member_token), Some(reg("https://attacker.example.org", 'a'))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(send(&app, "POST", "/api/push/register", Some(&host), Some(reg("https://other.example.org", 'b'))).await.0, StatusCode::BAD_REQUEST);
    let gateways: Vec<String> = sqlx::query_scalar("SELECT DISTINCT gateway FROM push_registrations").fetch_all(&state.db).await.unwrap();
    assert_eq!(gateways, ["https://push.example.org"]);
}

/// Rows written under an older, laxer rule must not keep the server dialling another host:
/// the rule is applied again when a wake fires and once at startup.
#[tokio::test]
async fn l8_the_gateway_rule_is_enforced_at_wake_time_and_at_startup() {
    let state = test_state().await;
    let (app, owner, host, server, _) = hosted(&state).await;
    let (alice, alice_token) = member(&app, &host, &server, "alice").await;
    let (bob, bob_token) = member(&app, &host, &server, "bob").await;
    // Registrations from before the rule existed: the owner's with the real gateway, Alice's
    // with a host of her choosing, Bob's with the real one.
    let seed = |user: String, token: String, gateway: &'static str, apns: char| {
        let db = state.db.clone();
        async move {
            sqlx::query("INSERT INTO push_registrations (id, user_id, session_hash, gateway, apns_token, topic, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, 'io.skwod.app', 0, 0)")
                .bind(crate::state::new_id())
                .bind(user)
                .bind(crate::auth::token_hash(&token))
                .bind(gateway)
                .bind(apns.to_string().repeat(64))
                .execute(&db)
                .await
                .unwrap();
        }
    };
    seed(alice.clone(), alice_token.clone(), "https://attacker.example.org", 'a').await;
    seed(bob.clone(), bob_token.clone(), "https://push.example.org", 'b').await;
    let gateways = || {
        let db = state.db.clone();
        async move { sqlx::query_scalar::<_, String>("SELECT gateway FROM push_registrations ORDER BY gateway").fetch_all(&db).await.unwrap() }
    };

    // No list, no pin, and the owner has no registration: no host is allowed, so nothing is
    // dialled — but with no rule to judge by, nothing is deleted either (an upgrade must not
    // wipe every member's registration).
    assert!(!crate::push::gateway_allowed(&state, "https://attacker.example.org").await.unwrap());
    assert!(!crate::push::gateway_allowed(&state, "https://push.example.org").await.unwrap());
    assert_eq!(crate::push::enforce_gateway_policy(&state).await.unwrap(), 0);
    crate::gateway::wake_users(&state, std::slice::from_ref(&alice), crate::gateway::Kind::Message).await;
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    assert_eq!(gateways().await.len(), 2, "kept until there is a rule");

    // Startup: the owner's existing registration becomes the pin; rows for any other host go.
    seed(owner.clone(), host.clone(), "https://push.example.org", 'c').await;
    assert_eq!(crate::push::enforce_gateway_policy(&state).await.unwrap(), 1);
    assert_eq!(gateways().await, ["https://push.example.org", "https://push.example.org"]);
    assert!(crate::push::gateway_allowed(&state, "https://push.example.org").await.unwrap());
    assert!(!crate::push::gateway_allowed(&state, "https://attacker.example.org").await.unwrap());
    assert_eq!(crate::push::enforce_gateway_policy(&state).await.unwrap(), 0, "idempotent");

    // With an allowlist (the operator's, or the one baked into the build) the pin is not consulted.
    let mut listed = state.clone();
    listed.waker = crate::gateway::Waker::new(crate::gateway::Policy { allowed_hosts: Some(vec!["official.example.org".into()]), insecure_loopback: false }, Default::default());
    assert!(!crate::push::gateway_allowed(&listed, "https://push.example.org").await.unwrap());
    assert_eq!(crate::push::enforce_gateway_policy(&listed).await.unwrap(), 2, "rows for hosts off the list are removed; those devices register again");
}

/// However signups race, an invite never creates more accounts than it has uses, nor more
/// unadmitted accounts than the cap.
///
/// Run on a pool of several connections and several threads, so the signups really overlap in
/// the database. (Checked against the count-then-insert it replaced: that version lets extra
/// accounts through here.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h1_concurrent_signups_never_exceed_an_invites_limits() {
    let mut state = crate::tests::test_state_concurrent().await;
    state.invite_pending_signups = 3;
    let (app, _owner, host, server, _) = hosted(&state).await;
    let race = |code: String, prefix: &'static str| {
        let app = app.clone();
        async move {
            let attempts = (0..12).map(|i| {
                let (app, code) = (app.clone(), code.clone());
                tokio::spawn(async move { join_as(&app, &format!("{prefix}{i:02}"), &code).await.0 })
            });
            let mut ok = 0;
            for attempt in attempts.collect::<Vec<_>>() {
                match attempt.await.unwrap() {
                    StatusCode::OK => ok += 1,
                    // (Refused by the invite, or by the per-address signup window.)
                    StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {}
                    other => panic!("unexpected {other}"),
                }
            }
            ok
        }
    };
    let users = || {
        let db = state.db.clone();
        async move { sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users").fetch_one(&db).await.unwrap() }
    };
    let before = users().await;
    // max_uses = 2: exactly two accounts.
    let two = invite(&app, &host, &server, json!({ "kind": "code", "max_uses": 2 })).await;
    assert_eq!(race(two.clone(), "cap").await, 2);
    assert_eq!(users().await, before + 2, "a refused signup leaves no account behind");
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT signup_count FROM invites WHERE code = $1").bind(&two).fetch_one(&state.db).await.unwrap(), 2, "a rolled-back claim is not counted");
    // Unlimited uses: the unadmitted cap (3) holds.
    state.limiter.forget("signup:ip:unknown");
    let open = invite(&app, &host, &server, json!({ "kind": "code" })).await;
    assert_eq!(race(open, "pend").await, 3);
    assert_eq!(users().await, before + 5);
}
