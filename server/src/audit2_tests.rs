//! Build 45 security audit, second pass (the per-area reports): one test (at least) per
//! finding fixed in the server. Named after the report's finding ids.

use std::time::Duration;

use axum::http::StatusCode;
use axum::Router;
use serde_json::{json, Value};

use crate::accounts_tests::{b64, first_device, keys, post_as, proof, put_backup_contents, put_backup_with_verifier, restore_with, season, space};
use crate::audit_tests::{hosted, invite, join_as, member, waiting};
use crate::tests::{login, send, send_proved, signup, test_state};

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Serve `app` on a real socket (WebSocket tests).
async fn serve(app: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Read frames until one contains `needle`, or the socket ends / `within` passes.
async fn hears(ws: &mut Ws, needle: &str, within: Duration) -> bool {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    let heard = async {
        while let Some(Ok(m)) = ws.next().await {
            if matches!(&m, Message::Text(t) if t.contains(needle)) {
                return true;
            }
        }
        false
    };
    tokio::time::timeout(within, heard).await.unwrap_or(false)
}

// ---- H-1: a restore cuts the old install off from everything ----

/// What a member's app reads that is NOT device-scoped: channel history, the DM table, the
/// member list, the server list, blobs. (route, status) as `token`.
async fn metadata_routes(app: &Router, token: &str, server: &str, channel: &str) -> Vec<(String, StatusCode, Value)> {
    let mut out = Vec::new();
    for path in [
        format!("/api/channels/{channel}/messages"),
        "/api/dms".to_string(),
        "/api/servers".to_string(),
        format!("/api/servers/{server}/members"),
        format!("/api/servers/{server}/channels"),
        format!("/api/e2ee/member-devices?server_id={server}"),
        "/api/blocks".to_string(),
        "/api/e2ee/key-backup".to_string(),
    ] {
        let (status, body) = send(app, "GET", &path, Some(token), None).await;
        out.push((path, status, body));
    }
    out
}

#[tokio::test]
async fn h1_a_restore_cuts_the_old_install_off_from_every_route_and_the_socket() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user_id, old_token) = signup(&app, "alice").await;
    let (original, device) = first_device(&app, &old_token).await;
    let (server, channel) = space(&app, &old_token).await;
    assert_eq!(post_as(&app, &old_token, &channel, &device).await.0, StatusCode::OK);
    let backup_key = [0x5au8; 32];
    put_backup_with_verifier(&app, &old_token, &original, &user_id, &backup_key).await;
    season(&state, &user_id).await;
    for (path, status, body) in metadata_routes(&app, &old_token, &server, &channel).await {
        assert_eq!(status, StatusCode::OK, "before the restore {path}: {body}");
    }
    // The old install is connected, and registered for push wakes.
    let addr = serve(app.clone()).await;
    let (mut old_ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={old_token}")).await.unwrap();
    old_ws.send(Message::Text(json!({"type":"subscribe","topic":format!("channel:{channel}")}).to_string())).await.unwrap();
    assert!(hears(&mut old_ws, "subscribed", Duration::from_secs(2)).await);
    sqlx::query("INSERT INTO push_registrations (id, user_id, session_hash, device_id, gateway, apns_token, topic, created_at, updated_at) VALUES ('r1', $1, $2, $3, 'https://gw.example', '', 'io.skwod.app', 0, 0)")
        .bind(&user_id)
        .bind(crate::auth::token_hash(&old_token))
        .bind(&device)
        .execute(&state.db)
        .await
        .unwrap();

    // The phone is stolen; the owner restores onto a new one with the recovery key.
    let mut bus = state.rt.subscribe();
    let (status, body) = restore_with(&app, &original, &backup_key, &[9u8; 32], &user_id, &device).await;
    assert_eq!((status, body["generation"].as_i64()), (StatusCode::OK, Some(1)), "{body}");

    // The thief's session — still signed in — gets nothing a member's app reads…
    for (path, status, body) in metadata_routes(&app, &old_token, &server, &channel).await {
        assert_eq!((status, body["error"].as_str()), (StatusCode::CONFLICT, Some("device superseded")), "{path}: {body}");
    }
    let (status, _) = send(&app, "POST", "/api/dms", Some(&old_token), Some(json!({ "user_id": user_id }))).await;
    assert_eq!(status, StatusCode::CONFLICT, "nor writes");
    // …its open socket is closed at once, told why, and hears nothing posted afterwards…
    assert!(hears(&mut old_ws, "device superseded", Duration::from_secs(2)).await, "the open socket is told and closed");
    // …a new socket is refused, with the same typed answer…
    let refused = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={old_token}")).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(res)) => assert_eq!(res.status().as_u16(), 409),
        other => panic!("the superseded install opened a socket: {:?}", other.map(|_| ())),
    }
    // …voice and p2p standing are gone, and it is not woken any more.
    assert!(!crate::p2p::voice_allowed(&state, &old_token).await);
    assert_eq!(crate::auth::current_session_user(&state, &crate::auth::token_hash(&old_token)).await, None);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM push_registrations").fetch_one(&state.db).await.unwrap(), 0);
    // What it may still do: learn why it stopped.
    assert_eq!(send(&app, "GET", "/api/auth/me", Some(&old_token), None).await.0, StatusCode::OK);
    let (status, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&old_token), None).await;
    assert_eq!((status, listing["devices"][0]["generation"].as_i64(), listing["devices"][0]["current"].as_bool()), (StatusCode::OK, Some(1), Some(false)));

    // Everyone who may hold keys for the device is told, with the new generation, and the
    // directory lists it — so they rotate what the old install still holds.
    let mut topics = Vec::new();
    while let Ok(ev) = bus.try_recv() {
        let frame: Value = serde_json::from_str(&ev.frame).unwrap();
        if frame["event"] == "device_rekeyed" {
            assert_eq!((frame["payload"]["user_id"].as_str(), frame["payload"]["generation"].as_i64()), (Some(user_id.as_str()), Some(1)));
            topics.push(ev.topic);
        }
    }
    assert!(topics.contains(&crate::rt::user_topic(&user_id)) && topics.contains(&crate::rt::server_topic(&server)), "{topics:?}");
    let (_, bob) = signup(&app, "bobby").await;
    crate::tests::share_server(&state.db, &[&user_id, &sqlx::query_scalar::<_, String>("SELECT id FROM profiles WHERE username = 'bobby'").fetch_one(&state.db).await.unwrap()]).await;
    let (status, directory) = send(&app, "GET", &format!("/api/e2ee/users/{user_id}/devices"), Some(&bob), None).await;
    assert_eq!((status, directory["devices"][0]["generation"].as_i64()), (StatusCode::OK, Some(1)), "{directory}");
}

#[test]
fn h1_a_stopped_install_reaches_only_the_routes_that_explain_or_repair() {
    use axum::http::Method;
    for (method, path) in [
        (Method::GET, "/api/auth/me"),
        (Method::GET, "/api/e2ee/devices"),
        (Method::GET, "/api/e2ee/trust-root"),
        (Method::GET, "/api/updates/manifest"),
        (Method::POST, "/api/e2ee/devices/d1/rekey"),
        (Method::POST, "/api/e2ee/devices/d1/bind"),
        (Method::POST, "/api/e2ee/devices/register"),
        (Method::POST, "/api/e2ee/link-requests"),
        (Method::GET, "/api/e2ee/link-requests/r1"),
        (Method::POST, "/api/e2ee/key-backup/challenge"),
    ] {
        assert!(crate::auth::stopped_install_allows(&method, path), "{method} {path} should stay open");
    }
    for (method, path) in [
        (Method::GET, "/api/servers"),
        (Method::GET, "/api/dms"),
        (Method::GET, "/api/channels/c1/messages"),
        (Method::GET, "/api/e2ee/key-backup"),
        (Method::GET, "/api/e2ee/link-requests"),
        (Method::POST, "/api/e2ee/link-requests/r1/approve"),
        (Method::POST, "/api/e2ee/devices/d1/recovery/approve"),
        (Method::DELETE, "/api/e2ee/devices/d1"),
        (Method::GET, "/api/auth/users"),
        (Method::POST, "/api/auth/password"),
        (Method::DELETE, "/api/auth/users/u1"),
        (Method::GET, "/api/blobs/b1"),
        (Method::POST, "/api/some/route/added/later"),
    ] {
        assert!(!crate::auth::stopped_install_allows(&method, path), "{method} {path} should be closed");
    }
}

/// Strict mode (`SKWOD_REQUIRE_BOUND_SESSIONS`): once an account has a device, a session that
/// has not proved which install it is — a password alone — reaches only link / restore / bind.
#[tokio::test]
async fn h1_strict_mode_gives_a_password_only_session_nothing_but_the_way_in() {
    let mut state = test_state().await;
    state.require_bound_sessions = true;
    let app = crate::api::router(state.clone());
    let (user_id, token) = signup(&app, "alice").await;
    // No device yet: nothing to bind to, the account works (it is about to register one).
    assert_eq!(send(&app, "GET", "/api/servers", Some(&token), None).await.0, StatusCode::OK);
    let (store, device) = first_device(&app, &token).await;
    let (server, channel) = space(&app, &token).await;
    let password_only = login(&app, "alice").await;
    for (path, status, body) in metadata_routes(&app, &password_only, &server, &channel).await {
        if path == "/api/e2ee/key-backup" {
            assert_eq!(status, StatusCode::NOT_FOUND, "a restore may ask for the backup (there is none here)");
            continue;
        }
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device bind required")), "{path}: {body}");
    }
    let addr = serve(app.clone()).await;
    assert!(tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={password_only}")).await.is_err(), "no socket either");
    // Binding (the device's signature AND its install secret) is the way in.
    let (status, body) = crate::accounts_tests::bind(&app, &store, &crate::accounts_tests::secret(&store), &user_id, &device, &password_only).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (path, status, body) in metadata_routes(&app, &password_only, &server, &channel).await {
        assert!(status == StatusCode::OK || path == "/api/e2ee/key-backup", "{path}: {body}");
    }
}

// ---- H-2: what was still open in the approval gate ----

#[tokio::test]
async fn h2_requests_and_approvals_count_against_the_invite_and_a_denial_is_final() {
    let state = test_state().await;
    let (app, _owner, host, server, _) = hosted(&state).await;
    let (_alice, alice) = member(&app, &host, &server, "alice").await;
    let (_bob, bob) = member(&app, &host, &server, "bob").await;
    let (carol_id, carol) = member(&app, &host, &server, "carol").await;
    // A second space of the host's, with a "single-use" code that needs approval.
    let (club, _) = space(&app, &host).await;
    let once = invite(&app, &host, &club, json!({ "kind": "code", "max_uses": 1 })).await;
    let accept = |token: String, code: String| {
        let app = app.clone();
        async move { send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&token), None).await }
    };
    let (status, body) = accept(alice.clone(), once.clone()).await;
    assert_eq!((status, body["pending"].as_bool()), (StatusCode::OK, Some(true)), "{body}");
    // The one use is spoken for: nobody else queues up behind it (and notifies the host).
    assert_eq!(accept(bob.clone(), once.clone()).await.0, StatusCode::BAD_REQUEST);
    // Approving is the use. (It was never counted: a single-use code admitted without limit.)
    let alice_id: String = sqlx::query_scalar("SELECT id FROM profiles WHERE username = 'alice'").fetch_one(&state.db).await.unwrap();
    assert_eq!(send(&app, "POST", &format!("/api/servers/{club}/join-requests/{alice_id}/approve"), Some(&host), None).await.0, StatusCode::OK);
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT use_count FROM invites WHERE code = $1").bind(&once).fetch_one(&state.db).await.unwrap(), 1);
    assert_eq!(accept(carol.clone(), once.clone()).await.0, StatusCode::BAD_REQUEST, "used up");
    // A request that got in under a limit that was lowered since is not approved past it.
    let two = invite(&app, &host, &club, json!({ "kind": "code", "max_uses": 2 })).await;
    assert_eq!(accept(bob.clone(), two.clone()).await.0, StatusCode::OK);
    assert_eq!(accept(carol.clone(), two.clone()).await.0, StatusCode::OK);
    sqlx::query("UPDATE invites SET max_uses = 1 WHERE code = $1").bind(&two).execute(&state.db).await.unwrap();
    let bob_id: String = sqlx::query_scalar("SELECT id FROM profiles WHERE username = 'bob'").fetch_one(&state.db).await.unwrap();
    assert_eq!(send(&app, "POST", &format!("/api/servers/{club}/join-requests/{bob_id}/approve"), Some(&host), None).await.0, StatusCode::OK);
    let (status, body) = send(&app, "POST", &format!("/api/servers/{club}/join-requests/{carol_id}/approve"), Some(&host), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let member_now: i64 = sqlx::query_scalar("SELECT count(*) FROM server_members WHERE server_id = $1 AND user_id = $2").bind(&club).bind(&carol_id).fetch_one(&state.db).await.unwrap();
    assert_eq!(member_now, 0, "the refused approval admitted nobody and left the request pending");

    // A denial is final for that invite: asking again neither reopens it nor pings the host.
    sqlx::query("UPDATE invites SET max_uses = 5 WHERE code = $1").bind(&two).execute(&state.db).await.unwrap();
    assert_eq!(send(&app, "POST", &format!("/api/servers/{club}/join-requests/{carol_id}/deny"), Some(&host), None).await.0, StatusCode::OK);
    let mut bus = state.rt.subscribe();
    state.limiter.forget("accept_invite:ip:unknown"); // (the per-source window: every caller here is one source)
    for _ in 0..3 {
        let (status, body) = accept(carol.clone(), two.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    }
    assert!(std::iter::from_fn(|| bus.try_recv().ok()).all(|ev| !ev.frame.contains("join_request")), "nobody is notified again");
    let status: String = sqlx::query_scalar("SELECT status FROM join_requests WHERE server_id = $1 AND user_id = $2").bind(&club).bind(&carol_id).fetch_one(&state.db).await.unwrap();
    assert_eq!(status, "denied");
    // The host changes their mind by sending another invite.
    let again = invite(&app, &host, &club, json!({ "kind": "code" })).await;
    let (status, body) = accept(carol.clone(), again).await;
    assert_eq!((status, body["pending"].as_bool()), (StatusCode::OK, Some(true)), "{body}");
}

#[tokio::test]
async fn h2_an_instance_ban_survives_signing_up_again() {
    let state = test_state().await;
    let (app, _owner, host, server, _) = hosted(&state).await;
    let code = invite(&app, &host, &server, json!({ "kind": "code" })).await;
    let (mallory, mallory_token) = waiting(&app, &code, "mallory").await;
    let mut store = skwod_crypto::store::SignalStore::generate();
    let (device_body, _) = keys(&mut store);
    assert_eq!(send(&app, "POST", "/api/e2ee/devices/register", Some(&mallory_token), Some(device_body.clone())).await.0, StatusCode::OK);

    // Deleting alone used to be undone by signing up again with the same code. Only the
    // instance owner bans, and never themselves.
    let (_, alice) = member(&app, &host, &server, "alice").await;
    assert_eq!(send(&app, "DELETE", &format!("/api/auth/users/{mallory}?ban=1"), Some(&alice), None).await.0, StatusCode::FORBIDDEN);
    let (status, body) = send(&app, "DELETE", &format!("/api/auth/users/{mallory}?ban=1"), Some(&host), None).await;
    assert_eq!((status, body["banned"].as_bool(), body["invite_revoked"].as_bool()), (StatusCode::OK, Some(true), Some(true)), "{body}");

    // The code they came in on lets nobody in any more; the name is not available again; and
    // the identity key of their device registers under no account.
    assert_eq!(join_as(&app, "mallory2", &code).await.0, StatusCode::FORBIDDEN);
    let fresh = invite(&app, &host, &server, json!({ "kind": "code" })).await;
    assert_eq!(join_as(&app, "mallory", &fresh).await.0, StatusCode::CONFLICT);
    let (status, body) = join_as(&app, "mallory3", &fresh).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = send(&app, "POST", "/api/e2ee/devices/register", body["token"].as_str(), Some(device_body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "the banned identity key");
}

#[tokio::test]
async fn h2_the_waiting_room_has_no_lan_key_and_an_unadmitted_account_hears_no_conversation() {
    let state = test_state().await;
    let (app, _owner, host, server, _) = hosted(&state).await;
    let (alice_id, _alice) = member(&app, &host, &server, "alice").await;
    let (bob_id, bob) = member(&app, &host, &server, "bob").await;
    let (status, dm) = send(&app, "POST", "/api/dms", Some(&bob), Some(json!({ "participant_ids": [alice_id] }))).await;
    assert_eq!(status, StatusCode::OK, "{dm}");
    let topic = format!("dm:{}", dm["conversation_id"].as_str().unwrap());
    assert!(crate::ws::may_subscribe(&state, &bob_id, &topic).await.unwrap());
    assert_eq!(send(&app, "GET", "/api/instance/p2p", Some(&bob), None).await.0, StatusCode::OK);
    // Removed from the only space he was in: the conversation row stays, his reach does not.
    assert_eq!(send(&app, "DELETE", &format!("/api/servers/{server}/members/{bob_id}"), Some(&host), None).await.0, StatusCode::OK);
    assert!(!crate::ws::may_subscribe(&state, &bob_id, &topic).await.unwrap(), "no DM events for an account in the waiting room");
    let (status, body) = send(&app, "GET", "/api/instance/p2p", Some(&bob), None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("waiting for approval")), "{body}");
    assert_eq!(send(&app, "GET", "/api/instance/can-create-servers", Some(&bob), None).await.0, StatusCode::OK);
}

// ---- M-1: nothing a stranger sends decides how much memory is kept ----

#[tokio::test]
async fn m1_signin_bodies_are_small_names_are_checked_before_they_are_keys_and_only_failures_count() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (_, _token) = signup(&app, "alice").await;
    // A body far below the old 2 MB default is already too large for these routes…
    let huge = "a".repeat(64 * 1024);
    for path in ["/api/auth/login", "/api/auth/signup"] {
        let (status, _) = send(&app, "POST", path, None, Some(json!({ "username": huge, "password": "correct horse" }))).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{path}");
    }
    // …and a name that fits in the body but is no username never becomes a limiter key.
    let before = state.limiter.key_bytes();
    let long = "b".repeat(8 * 1024);
    assert_eq!(send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": long, "password": "correct horse" }))).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&app, "POST", "/api/auth/signup", None, Some(json!({ "username": long, "password": "correct horse" }))).await.0, StatusCode::BAD_REQUEST);
    assert!(state.limiter.key_bytes() - before < 200, "{} bytes of keys for two 8 KB names", state.limiter.key_bytes() - before);

    // The per-account window counts wrong passwords only: the owner's own sign-ins do not
    // use it up (12 here, with the old 10-a-minute window the 11th was refused)…
    for _ in 0..12 {
        assert_eq!(send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "alice", "password": "correct horse" }))).await.0, StatusCode::OK);
    }
    // …and it still stops guessing: after ten wrong passwords not even the right one is
    // looked at until the window is over.
    for _ in 0..crate::auth::LOGIN_FAILURES_PER_MINUTE {
        assert_eq!(send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "alice", "password": "wrong horse" }))).await.0, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "alice", "password": "correct horse" }))).await.0, StatusCode::TOO_MANY_REQUESTS);

    // A parallel burst gets no more guesses than a patient one: the attempt is taken before
    // the password is looked at. (Another account, so its window is fresh.)
    signup(&app, "bobby").await;
    state.limiter.forget("login:ip:unknown");
    let burst = (0..18).map(|_| send(&app, "POST", "/api/auth/login", None, Some(json!({ "username": "bobby", "password": "wrong horse" }))));
    let verified = futures_util::future::join_all(burst).await.into_iter().filter(|(status, _)| *status == StatusCode::UNAUTHORIZED).count();
    assert_eq!(verified as u32, crate::auth::LOGIN_FAILURES_PER_MINUTE, "exactly the window's worth of passwords was checked");
}

// ---- M-2: the remaining ways to fill the host ----

#[tokio::test]
async fn m2_a_chunk_is_refused_before_it_is_read_and_dm_attachments_follow_the_send_rules() {
    let state = test_state().await;
    let (app, _owner, host, server, _) = hosted(&state).await;
    let (alice_id, alice) = member(&app, &host, &server, "alice").await;
    let (bob_id, bob) = member(&app, &host, &server, "bob").await;
    let (status, blob) = send(&app, "POST", "/api/blobs", Some(&alice), Some(json!({ "total_size": 4 }))).await;
    assert_eq!(status, StatusCode::OK, "{blob}");
    let blob_id = blob["blob_id"].as_str().unwrap().to_string();
    let chunk = |token: String, id: String, body: Vec<u8>| {
        let app = app.clone();
        async move {
            use tower::ServiceExt;
            let req = axum::http::Request::builder()
                .method("PATCH")
                .uri(format!("/api/blobs/{id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("upload-offset", "0")
                .header("content-length", body.len())
                .body(axum::body::Body::from(body))
                .unwrap();
            app.oneshot(req).await.unwrap().status()
        }
    };
    // Somebody else's blob, a blob that does not exist, and more than the blob has room for:
    // each answered from the headers alone.
    assert_eq!(chunk(bob.clone(), blob_id.clone(), vec![0; 1024 * 1024]).await, StatusCode::NOT_FOUND);
    assert_eq!(chunk(alice.clone(), "no-such-blob".into(), vec![0; 1024 * 1024]).await, StatusCode::NOT_FOUND);
    assert_eq!(chunk(alice.clone(), blob_id.clone(), vec![0; 5]).await, StatusCode::BAD_REQUEST);
    assert_eq!(chunk(alice.clone(), blob_id.clone(), vec![7; 4]).await, StatusCode::NO_CONTENT);

    // A DM attachment: only on a message that still exists, in a conversation the author is
    // still in, with nobody blocking.
    let (_, dm) = send(&app, "POST", "/api/dms", Some(&alice), Some(json!({ "participant_ids": [bob_id] }))).await;
    let conversation = dm["conversation_id"].as_str().unwrap().to_string();
    let say = || {
        let (app, alice, conversation) = (app.clone(), alice.clone(), conversation.clone());
        async move { send(&app, "POST", &format!("/api/dms/{conversation}/messages"), Some(&alice), Some(json!({ "ciphertext": b64(b"hi") }))).await.1["message_id"].as_str().unwrap().to_string() }
    };
    let attach = |message: String| {
        let (app, alice, blob_id) = (app.clone(), alice.clone(), blob_id.clone());
        async move { send(&app, "POST", &format!("/api/dm-messages/{message}/attachments"), Some(&alice), Some(json!({ "blob_id": blob_id, "metadata_ciphertext": b64(b"meta") }))).await.0 }
    };
    let first = say().await;
    assert_eq!(attach(first.clone()).await, StatusCode::OK);
    let deleted = say().await;
    assert_eq!(send(&app, "DELETE", &format!("/api/dm-messages/{deleted}"), Some(&alice), None).await.0, StatusCode::OK);
    assert_eq!(attach(deleted).await, StatusCode::NOT_FOUND, "a deleted message takes no attachment");
    assert_eq!(send(&app, "PUT", &format!("/api/blocks/{alice_id}"), Some(&bob), None).await.0, StatusCode::OK);
    assert_eq!(attach(first).await, StatusCode::FORBIDDEN, "blocked: no more files into the conversation");
}

#[tokio::test]
async fn m2_backup_history_and_sealed_deposit_lookups_are_bounded() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user_id, token) = signup(&app, "alice").await;
    let (store, _device) = first_device(&app, &token).await;
    let key = [0x21u8; 32];
    for n in 0..12u8 {
        put_backup_contents(&app, &token, &store, &user_id, &key, &[b"state ".as_slice(), &[n]].concat()).await;
    }
    let kept: Vec<Vec<u8>> = sqlx::query_scalar("SELECT encrypted_blob FROM backup_blobs WHERE user_id = $1 ORDER BY created_at DESC, id DESC").bind(&user_id).fetch_all(&state.db).await.unwrap();
    assert_eq!(kept.len(), 8, "the newest few contents under one key, not every one ever uploaded");
    assert!(kept.contains(&[b"state ".as_slice(), &[11]].concat()), "the newest is among them");
    // The history as a whole has a ceiling, and going over it REFUSES (it never evicts an
    // older key's blobs, which the owner may still need).
    sqlx::query(&crate::tests::pg("UPDATE backup_blobs SET encrypted_blob = zeroblob(4 * 1024 * 1024) WHERE user_id = $1")).bind(&user_id).execute(&state.db).await.unwrap();
    let blob = vec![1u8; 16];
    let verifier = skwod_crypto::backup::recovery_verifier(&key).unwrap();
    let body = json!({ "encrypted_blob": b64(&blob), "salt": b64(&[0u8; 16]), "version": 3, "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 }, "auth_verifier": b64(&verifier) });
    let payload = skwod_crypto::link::op_payload(&[&crate::keydir::backup_payload(&blob, &[0u8; 16], 3, &body["kdf_params"]), &verifier]);
    let (status, res) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(body), &proof(&store, "backup-put", &user_id, "backup", &payload)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{res}");
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM backup_blobs WHERE user_id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap(), 8);

    // An unauthenticated deposit full of misses is answered without a lookup per entry.
    let bogus: Vec<Value> = (0..200).map(|i| json!({ "user_id": format!("u{i}"), "device_id": "d", "delivery_key": b64(&[0u8; 32]), "envelope": b64(b"e") })).collect();
    let (status, res) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(json!({ "messages": bogus }))).await;
    assert_eq!(status, StatusCode::OK, "{res}");
    assert!(res["results"].as_array().unwrap().iter().all(|r| r["status"] == "gone"));
    assert_eq!(res["results"].as_array().unwrap().len(), 200);
}

// ---- M-3: a bare token destroys nothing ----

#[tokio::test]
async fn m3_wiping_or_deleting_a_space_and_repointing_voice_need_a_current_device() {
    let mut state = test_state().await;
    let (app, owner, host, server, channel) = hosted(&state).await;
    let (host_store, host_device) = first_device(&app, &host).await;
    assert_eq!(post_as(&app, &host, &channel, &host_device).await.0, StatusCode::OK);
    let voice = json!({ "url": "wss://sfu.attacker.example", "api_key": "k", "api_secret": "s" });
    // The owner's password — or a token that is not a current install — is not enough.
    let stolen = login(&app, "host").await;
    let attempts = |token: String| {
        let (app, server, channel, voice) = (app.clone(), server.clone(), channel.clone(), voice.clone());
        async move {
            vec![
                ("clear channel", send(&app, "DELETE", &format!("/api/channels/{channel}/messages"), Some(&token), None).await.0),
                ("purge", send(&app, "POST", &format!("/api/servers/{server}/purge"), Some(&token), Some(json!({ "older_than_ms": 0 }))).await.0),
                ("clear server", send(&app, "POST", &format!("/api/servers/{server}/clear"), Some(&token), Some(json!({}))).await.0),
                ("voice config", send(&app, "PUT", "/api/voice/config", Some(&token), Some(voice)).await.0),
                ("clear voice config", send(&app, "DELETE", "/api/voice/config", Some(&token), None).await.0),
                ("delete server", send(&app, "DELETE", &format!("/api/servers/{server}"), Some(&token), None).await.0),
            ]
        }
    };
    for (what, status) in attempts(stolen.clone()).await {
        assert_eq!(status, StatusCode::FORBIDDEN, "{what} with a bare token");
    }
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM messages").fetch_one(&state.db).await.unwrap(), 1, "nothing was wiped");
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM instance_secrets WHERE name = 'livekit_url'").fetch_one(&state.db).await.unwrap(), 0);
    // A proof that is offered must hold — for exactly this action.
    let wrong = proof(&host_store, "clear-channel", &owner, "another-channel", b"");
    assert_eq!(send_proved(&app, "DELETE", &format!("/api/channels/{channel}/messages"), &host, None, &wrong).await.0, StatusCode::FORBIDDEN);
    // A value with a newline never reaches the SFU's configuration file (L-5).
    let injected = json!({ "url": "wss://sfu.example", "api_key": "k", "api_secret": "s\nwebhook:\n  urls: [https://x]" });
    assert_eq!(send(&app, "PUT", "/api/voice/config", Some(&host), Some(injected)).await.0, StatusCode::BAD_REQUEST);
    // The owner's current install: allowed (signed, or — until every build signs — bound).
    let signed = proof(&host_store, "clear-channel", &owner, &channel, b"");
    assert_eq!(send_proved(&app, "DELETE", &format!("/api/channels/{channel}/messages"), &host, None, &signed).await.0, StatusCode::OK);
    assert_eq!(send(&app, "POST", &format!("/api/servers/{server}/clear"), Some(&host), Some(json!({}))).await.0, StatusCode::OK);

    // Strict mode: the signature is required; the bound session alone is refused too.
    state.require_device_proofs = true;
    let app = crate::api::router(state.clone());
    assert_eq!(send(&app, "DELETE", &format!("/api/servers/{server}"), Some(&host), None).await.0, StatusCode::FORBIDDEN);
    // Clearing the saved call server goes the same way, under its own op: a signature for
    // another action is not one for this.
    assert_eq!(send(&app, "DELETE", "/api/voice/config", Some(&host), None).await.0, StatusCode::FORBIDDEN);
    let wrong = proof(&host_store, "voice-config", &owner, "", b"");
    assert_eq!(send_proved(&app, "DELETE", "/api/voice/config", &host, None, &wrong).await.0, StatusCode::FORBIDDEN);
    let signed = proof(&host_store, "voice-config-clear", &owner, "", b"");
    assert_eq!(send_proved(&app, "DELETE", "/api/voice/config", &host, None, &signed).await.0, StatusCode::OK);
    let signed = proof(&host_store, "delete-server", &owner, &server, b"");
    assert_eq!(send_proved(&app, "DELETE", &format!("/api/servers/{server}"), &host, None, &signed).await.0, StatusCode::OK);
}

// ---- M-4: a backup download by something that is not a device is rare and never silent ----

#[tokio::test]
async fn m4_a_backup_fetch_without_a_device_is_limited_and_announced() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user_id, token) = signup(&app, "alice").await;
    let (store, _device) = first_device(&app, &token).await;
    put_backup_with_verifier(&app, &token, &store, &user_id, &[0x31; 32]).await;
    season(&state, &user_id).await;
    let mut bus = state.rt.subscribe();
    // The device itself: as often as it likes (within the general limit), and nobody is told.
    for _ in 0..10 {
        assert_eq!(send(&app, "GET", "/api/e2ee/key-backup", Some(&token), None).await.0, StatusCode::OK);
    }
    assert!(bus.try_recv().is_err());
    // The password alone: a few a day, each one announced to the account's devices.
    let elsewhere = login(&app, "alice").await;
    for _ in 0..crate::keydir::BACKUP_FETCHES_WITHOUT_A_DEVICE_PER_DAY {
        assert_eq!(send(&app, "GET", "/api/e2ee/key-backup", Some(&elsewhere), None).await.0, StatusCode::OK);
    }
    assert_eq!(send(&app, "GET", "/api/e2ee/key-backup", Some(&elsewhere), None).await.0, StatusCode::TOO_MANY_REQUESTS);
    let told = std::iter::from_fn(|| bus.try_recv().ok()).filter(|ev| ev.topic == crate::rt::user_topic(&user_id) && ev.frame.contains("backup_fetched")).count();
    assert_eq!(told as u32, crate::keydir::BACKUP_FETCHES_WITHOUT_A_DEVICE_PER_DAY);
}

// ---- M-5: a burst of PIN guesses gets no more tries than a patient one ----

#[tokio::test]
async fn m5_parallel_pin_guesses_cannot_outrun_the_attempt_counter() {
    let state = test_state().await;
    let app = crate::api::router(state.clone());
    let (user_id, token) = signup(&app, "alice").await;
    let (store, _device) = first_device(&app, &token).await;
    let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(json!({ "enable": true, "pin": "482913" })), &proof(&store, "set-pin", &user_id, "enable", b"482913")).await;
    assert_eq!(status, StatusCode::OK);
    // A burst of wrong guesses, all at once. The counter used to be read by all of them before
    // any wrote it back, so every one of them was verified. Now exactly the first four are
    // looked at and answered "wrong, N left"; the fifth locks, and the rest are not looked at.
    // (Wrong guesses only: on a pool of connections the order the guesses reach the counter is
    // not the order they were sent, and a right guess that wins an early slot is the owner.)
    let guesses: Vec<String> = (1..=12).map(|n| format!("{n:06}")).collect();
    let results = futures_util::future::join_all(guesses.iter().map(|pin| crate::keydir::verify_registration_pin(&state, &user_id, Some(pin)))).await;
    let answered = results.iter().filter(|r| matches!(r, Err(crate::error::ApiError::PinIncorrect { locked_until: None, .. }))).count();
    assert_eq!(answered as i64, crate::keydir::PIN_MAX_ATTEMPTS - 1, "guesses verified before the lock: {results:?}");
    assert!(results.iter().all(|r| matches!(r, Err(crate::error::ApiError::PinIncorrect { .. }))), "{results:?}");
    let locked: Option<i64> = sqlx::query_scalar("SELECT pin_locked_until FROM profiles WHERE id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap();
    assert!(locked.is_some_and(|t| t > crate::state::now_ms()), "and the account is locked for the lockout period");
    // While locked, even the right PIN is not looked at.
    assert!(crate::keydir::verify_registration_pin(&state, &user_id, Some("482913")).await.is_err());
    // After the lockout the right PIN works, and resets the count.
    sqlx::query("UPDATE profiles SET pin_locked_until = 0 WHERE id = $1").bind(&user_id).execute(&state.db).await.unwrap();
    assert!(crate::keydir::verify_registration_pin(&state, &user_id, Some("482913")).await.is_ok());
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT pin_attempt_count FROM profiles WHERE id = $1").bind(&user_id).fetch_one(&state.db).await.unwrap(), 0);
}
