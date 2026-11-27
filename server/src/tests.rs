//! Integration-style tests: an in-memory SQLite DB with the real migrations, driven through the
//! real router with tower's `oneshot`.
//!
//! `SKWOD_TEST_POSTGRES=postgres://localhost/postgres cargo test` runs the same tests against
//! PostgreSQL instead: every test gets a database of its own (`skwod_test_…`, created through
//! that URL and left behind — drop them afterwards), with the Postgres migrations and a pool of
//! several connections, as in production.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};

use crate::api;
use crate::state::{AppState, Db};

pub async fn test_app() -> (Router, Db) {
    let state = test_state().await;
    (api::router(state.clone()), state.db)
}

/// The state behind [`test_app`], for tests that need to adjust it before building the router.
pub async fn test_state() -> AppState {
    sqlx::any::install_default_drivers();
    if let Ok(admin) = std::env::var("SKWOD_TEST_POSTGRES") {
        return finish_state(postgres_pool(&admin).await);
    }
    // A single shared connection: each :memory: SQLite connection is its own database, so the pool
    // must hold exactly one. Served over the `Any` pool (same path as production) with FKs on.
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("PRAGMA foreign_keys=ON").execute(conn).await?;
                Ok(())
            })
        })
        .connect("sqlite::memory:")
        .await
        .expect("open in-memory db");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrate");
    finish_state(pool)
}

/// A state whose pool has SEVERAL connections, so requests really run at the same time against
/// the database (the in-memory pool of [`test_state`] has one, which serialises everything):
/// PostgreSQL under `SKWOD_TEST_POSTGRES`, otherwise a SQLite file opened the way `main.rs`
/// opens it (WAL, 8 connections).
pub async fn test_state_concurrent() -> AppState {
    sqlx::any::install_default_drivers();
    if let Ok(admin) = std::env::var("SKWOD_TEST_POSTGRES") {
        return finish_state(postgres_pool(&admin).await);
    }
    use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
    let dir = std::env::temp_dir().join(format!("skwod-test-db-{}", crate::state::new_id()));
    std::fs::create_dir_all(&dir).expect("create test db dir");
    let path = dir.join("skwod.db");
    let options = SqliteConnectOptions::new().filename(&path).create_if_missing(true).journal_mode(SqliteJournalMode::Wal).foreign_keys(true);
    let sqlite = SqlitePoolOptions::new().max_connections(1).connect_with(options).await.expect("open db file");
    sqlx::migrate!("./migrations").run(&sqlite).await.expect("migrate");
    sqlite.close().await;
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(8)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("PRAGMA foreign_keys=ON").execute(conn).await?;
                Ok(())
            })
        })
        .connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("open db file");
    finish_state(pool)
}

/// A fresh PostgreSQL database for one test, created through the `admin` URL.
pub async fn postgres_pool(admin: &str) -> Db {
    let name = format!("skwod_test_{}", crate::state::new_id().replace('-', "").to_lowercase());
    let maintenance = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(admin).await.expect("connect to SKWOD_TEST_POSTGRES");
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&maintenance).await.expect("create test database");
    maintenance.close().await;
    let url = match admin.rsplit_once('/') {
        Some((base, _)) => format!("{base}/{name}"),
        None => panic!("SKWOD_TEST_POSTGRES must end in /<database>"),
    };
    let pg = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect(&url).await.expect("connect to test database");
    sqlx::migrate!("./migrations-postgres").run(&pg).await.expect("migrate");
    pg.close().await;
    sqlx::any::AnyPoolOptions::new().max_connections(8).connect(&url).await.expect("open test database")
}

/// SQL written for SQLite, as PostgreSQL wants it when the tests run there: the blob literals
/// (`x'00'`, `zeroblob(n)`) that seed rows directly.
pub fn pg(sql: &str) -> String {
    if std::env::var_os("SKWOD_TEST_POSTGRES").is_none() {
        return sql.to_string();
    }
    let mut out = sql.replace("x'00'", "'\\x00'::bytea");
    while let Some(at) = out.find("zeroblob(") {
        let end = at + out[at..].find(')').expect("zeroblob(…)");
        let size = out[at + "zeroblob(".len()..end].to_string();
        out.replace_range(at..=end, &format!("decode(repeat('00', {size}), 'hex')"));
    }
    out
}

fn finish_state(pool: Db) -> AppState {
    let blob_dir = std::env::temp_dir().join(format!("skwod-test-blobs-{}", crate::state::new_id()));
    std::fs::create_dir_all(&blob_dir).expect("create test blob dir");
    let mut state = AppState::new(pool, blob_dir);
    // Tests must not depend on how full the build machine's disk is: no free-space floor unless
    // a test sets one (the floor's own tests do).
    state.blob_free_floor_bytes = 0;
    state
}

pub async fn send(app: &Router, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let mut req = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = match body {
        Some(v) => req
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(as_current_build(method, path, v).to_string()))
            .unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    (status, value)
}

/// Every current build chooses the id of a channel message it sends; a send without one is a
/// build ≤ 42 and is refused (`oldbuilds.rs`). Tests that just "post a message" get a fresh id
/// here, as a real client would supply. To send like an old build, pass `"message_id": null`.
pub fn as_current_build(method: &str, path: &str, mut body: Value) -> Value {
    if method == "POST" && path.starts_with("/api/channels/") && path.ends_with("/messages") {
        match body.get("message_id") {
            None => body["message_id"] = Value::String(uuid::Uuid::new_v4().to_string()),
            Some(Value::Null) => {
                body.as_object_mut().expect("object").remove("message_id");
            }
            Some(_) => {}
        }
    }
    body
}

/// Like [`send`], with a device-proof header (`<timestamp>.<base64 signature>`).
pub async fn send_proved(app: &Router, method: &str, path: &str, token: &str, body: Option<Value>, proof: &str) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-skwod-device-proof", proof);
    let req = match body {
        Some(v) => req.header(header::CONTENT_TYPE, "application/json").body(Body::from(v.to_string())).unwrap(),
        None => req.body(Body::empty()).unwrap(),
    };
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) })
}

/// Sign up a fresh user and return (user_id, token).
pub async fn signup(app: &Router, username: &str) -> (String, String) {
    let (status, body) = send(
        app,
        "POST",
        "/api/auth/signup",
        None,
        Some(json!({ "username": username, "password": "correct horse" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "signup failed: {body}");
    (body["user_id"].as_str().unwrap().to_string(), body["token"].as_str().unwrap().to_string())
}

/// Log in again (a second, independent session) and return its token.
pub async fn login(app: &Router, username: &str) -> String {
    let (status, body) = send(app, "POST", "/api/auth/login", None, Some(json!({ "username": username, "password": "correct horse" }))).await;
    assert_eq!(status, StatusCode::OK, "login failed: {body}");
    body["token"].as_str().unwrap().to_string()
}

/// A placeholder device row for tests that only need "this device id is registered".
pub async fn seed_device(db: &Db, user_id: &str, device_id: &str) {
    seed_device_sql(db, user_id, device_id, &crate::tests::pg(SEED_DEVICE)).await;
}

/// The same on a SQLite database whatever the test run's backend (the host-backup tests:
/// a host backup is of a SQLite data folder only).
pub async fn seed_device_sqlite(db: &Db, user_id: &str, device_id: &str) {
    seed_device_sql(db, user_id, device_id, SEED_DEVICE).await;
}

const SEED_DEVICE: &str = "INSERT INTO user_devices (id, user_id, device_id, protocol_version, registration_id, identity_key, signed_prekey_id, signed_prekey,
             signed_prekey_sig, kyber_last_resort_id, kyber_last_resort, kyber_last_resort_sig, delivery_key, legacy_unbound)
         VALUES ($1, $2, $3, 2, 1, x'00', 1, x'00', x'00', 1, x'00', x'00', x'00', 1)";

async fn seed_device_sql(db: &Db, user_id: &str, device_id: &str, sql: &str) {
    sqlx::query(sql)
    .bind(crate::state::new_id())
    .bind(user_id)
    .bind(device_id)
    .execute(db)
    .await
    .unwrap();
}

/// Put `users` in one server (the first owns it): since the build-45 audit a conversation, a
/// lookup or a key fetch needs the two accounts to share one.
pub async fn share_server(db: &Db, users: &[&str]) -> String {
    let server_id = crate::state::new_id();
    sqlx::query(&crate::tests::pg("INSERT INTO servers (id, name_ciphertext, owner_id) VALUES ($1, x'00', $2)")).bind(&server_id).bind(users[0]).execute(db).await.unwrap();
    for user in users {
        sqlx::query("INSERT INTO server_members (id, server_id, user_id) VALUES ($1, $2, $3)").bind(crate::state::new_id()).bind(&server_id).bind(user).execute(db).await.unwrap();
    }
    server_id
}

mod auth {
    use super::*;

    #[tokio::test]
    async fn signup_login_me_logout_roundtrip() {
        let (app, _db) = test_app().await;
        let (user_id, token) = signup(&app, "alice").await;

        let (status, body) = send(&app, "GET", "/api/auth/me", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["user_id"], user_id.as_str());
        assert_eq!(body["username"], "alice");

        // Fresh login (by username) issues a second, independent session.
        let (status, body) = send(
            &app,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({ "username": "alice", "password": "correct horse" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let token2 = body["token"].as_str().unwrap().to_string();
        assert_ne!(token, token2);

        // Logout kills only the presented session.
        let (status, _) = send(&app, "POST", "/api/auth/logout", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "GET", "/api/auth/me", Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = send(&app, "GET", "/api/auth/me", Some(&token2), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_user_are_indistinguishable() {
        let (app, _db) = test_app().await;
        signup(&app, "bob").await;
        let (s1, b1) = send(
            &app,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({ "username": "bob", "password": "wrong password" })),
        )
        .await;
        let (s2, b2) = send(
            &app,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({ "username": "nobody", "password": "wrong password" })),
        )
        .await;
        assert_eq!(s1, StatusCode::UNAUTHORIZED);
        assert_eq!((s1, b1), (s2, b2));
    }

    #[tokio::test]
    async fn duplicate_username_conflicts() {
        let (app, _db) = test_app().await;
        signup(&app, "carol").await;
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "username": "carol", "password": "password123" })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn invalid_inputs_rejected() {
        let (app, _db) = test_app().await;
        for (password, username) in [
            ("short", "dave"),
            ("password123", "D@ve"),
            ("password123", "ab"),
        ] {
            let (status, _) = send(
                &app,
                "POST",
                "/api/auth/signup",
                None,
                Some(json!({ "username": username, "password": password })),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "should reject {password}/{username}");
        }
        // Garbage / missing token.
        let (status, _) = send(&app, "GET", "/api/auth/me", Some("deadbeef"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = send(&app, "GET", "/api/auth/me", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

mod keydir {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use skwod_crypto::store::{KyberPreKeyUpload, PreKeyBundleData, PreKeyUpload, SignedPreKeyUpload};
    use skwod_crypto::{certs, DeviceAddress, SignalStore};

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    fn unb64(v: &Value) -> Vec<u8> {
        B64.decode(v.as_str().expect("b64 string")).expect("valid b64")
    }

    fn now_ms() -> u64 {
        crate::state::now_ms() as u64
    }

    fn signed(k: &SignedPreKeyUpload) -> Value {
        json!({ "id": k.id, "public": b64(&k.public), "signature": b64(&k.signature) })
    }
    fn kyber(k: &KyberPreKeyUpload) -> Value {
        json!({ "id": k.id, "public": b64(&k.public), "signature": b64(&k.signature) })
    }
    fn prekey(k: &PreKeyUpload) -> Value {
        json!({ "id": k.id, "public": b64(&k.public) })
    }

    /// A fresh libsignal device and its registration payload with `n` one-time keys of each kind.
    fn device_payload(n: usize) -> (SignalStore, Value) {
        let mut store = SignalStore::generate();
        let payload = key_payload(&mut store, n);
        (store, payload)
    }

    fn key_payload(store: &mut SignalStore, n: usize) -> Value {
        json!({
            "protocol_version": 2,
            "registration_id": store.registration_id(),
            "identity_key": b64(&store.identity_key()),
            "signed_prekey": signed(&store.generate_signed_prekey().unwrap()),
            "last_resort_kyber_prekey": kyber(&store.generate_last_resort_kyber().unwrap()),
            "one_time_prekeys": store.generate_one_time_prekeys(n).unwrap().iter().map(prekey).collect::<Vec<_>>(),
            "one_time_kyber_prekeys": store.generate_one_time_kyber(n).unwrap().iter().map(kyber).collect::<Vec<_>>(),
            "delivery_key": b64(&[7u8; 32]),
            "install_hash": b64(&install_hash()),
            "install_secret": b64(&INSTALL_SECRET),
        })
    }

    /// Every test device shares one install secret (these tests are not about telling installs apart).
    const INSTALL_SECRET: [u8; 32] = [3u8; 32];
    fn install_hash() -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(INSTALL_SECRET).to_vec()
    }

    /// Bind `token`'s session to `device` as its current install.
    async fn bind_as(app: &Router, token: &str, store: &SignalStore, user_id: &str, device: &str) {
        use sha2::Digest;
        let payload = skwod_crypto::link::op_payload(&[&sha2::Sha256::digest(token.as_bytes()), &install_hash()]);
        let body = json!({ "install_secret": b64(&INSTALL_SECRET) });
        let (status, body) = send_proved(app, "POST", &format!("/api/e2ee/devices/{device}/bind"), token, Some(body), &proof(store, "bind-session", user_id, device, &payload)).await;
        assert_eq!(status, StatusCode::OK, "bind failed: {body}");
    }

    async fn register(app: &Router, token: &str, payload: Value) -> String {
        let (status, body) = send(app, "POST", "/api/e2ee/devices/register", Some(token), Some(payload)).await;
        assert_eq!(status, StatusCode::OK, "register failed: {body}");
        body["device_id"].as_str().unwrap().to_string()
    }

    /// A device-proof header value: `signer`'s signature authorizing `op` on `target` with `payload`.
    fn proof_at(signer: &SignalStore, op: &str, user_id: &str, target: &str, payload: &[u8], ts: i64) -> String {
        format!("{ts}.{}", b64(&signer.sign_device_op(op, user_id, target, ts as u64, payload).unwrap()))
    }
    fn proof(signer: &SignalStore, op: &str, user_id: &str, target: &str, payload: &[u8]) -> String {
        proof_at(signer, op, user_id, target, payload, crate::state::now_ms())
    }

    /// The public keys of one uploaded batch, as the device-proof payload field.
    fn keys_blob(keys: Vec<&[u8]>) -> Vec<u8> {
        skwod_crypto::link::op_payload(&keys)
    }
    fn rotate_proof(signer: &SignalStore, user_id: &str, device: &str, spk: &SignedPreKeyUpload, lr: Option<&KyberPreKeyUpload>) -> String {
        let payload = skwod_crypto::link::op_payload(&[&spk.public, lr.map(|k| k.public.as_slice()).unwrap_or_default()]);
        proof(signer, "spk-rotate", user_id, device, &payload)
    }
    fn replenish_proof(signer: &SignalStore, user_id: &str, device: &str, ec: &[PreKeyUpload], ky: &[KyberPreKeyUpload]) -> String {
        let payload = skwod_crypto::link::op_payload(&[
            &keys_blob(ec.iter().map(|k| k.public.as_slice()).collect()),
            &keys_blob(ky.iter().map(|k| k.public.as_slice()).collect()),
        ]);
        proof(signer, "replenish", user_id, device, &payload)
    }

    async fn delete_device(app: &Router, token: &str, signer: &SignalStore, user_id: &str, device: &str) -> StatusCode {
        send_proved(app, "DELETE", &format!("/api/e2ee/devices/{device}"), token, None, &proof(signer, "delete", user_id, device, b"")).await.0
    }

    async fn cancel_reset(app: &Router, token: &str, signer: &SignalStore, user_id: &str, device: &str) -> StatusCode {
        send_proved(app, "POST", "/api/e2ee/devices/reset/cancel", token, Some(json!({ "device_id": device })), &proof(signer, "cancel-reset", user_id, device, b"")).await.0
    }

    /// Register an ADDITIONAL device on `user_id`, vouched for by `linker` (an existing device)
    /// through the link-request flow. `token` must be a session of the linker's install; it
    /// ends up bound to the new device (these tests drive several devices through one session).
    async fn register_linked(app: &Router, token: &str, user_id: &str, linker: &SignalStore, linker_dev: &str) -> (SignalStore, String) {
        let (store, mut payload) = device_payload(1);
        let sig = linker.sign_link(user_id, &store.identity_key()).unwrap();
        let request = json!({ "identity_key": b64(&store.identity_key()), "proof": b64(&[0u8; 32]) });
        let (status, created) = send(app, "POST", "/api/e2ee/link-requests", Some(token), Some(request)).await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let approve = json!({ "device_id": linker_dev, "signature": b64(&sig), "approval_mac": b64(&[0u8; 32]) });
        let (status, body) = send(app, "POST", &format!("/api/e2ee/link-requests/{}/approve", created["request_id"].as_str().unwrap()), Some(token), Some(approve)).await;
        assert_eq!(status, StatusCode::OK, "approve failed: {body}");
        payload["link"] = json!({ "device_id": linker_dev, "signature": b64(&sig) });
        let dev = register(app, token, payload).await;
        (store, dev)
    }

    /// Seed a server + text channel with the given members (bypasses structure CRUD, which has
    /// its own module/tests).
    async fn seed_server(db: &crate::state::Db, owner: &str, members: &[&str]) -> (String, String) {
        let server_id = crate::state::new_id();
        let channel_id = crate::state::new_id();
        sqlx::query(&crate::tests::pg("INSERT INTO servers (id, name_ciphertext, owner_id) VALUES ($1, x'00', $2)"))
            .bind(&server_id)
            .bind(owner)
            .execute(db)
            .await
            .unwrap();
        sqlx::query(&crate::tests::pg("INSERT INTO channels (id, server_id, name_ciphertext) VALUES ($1, $2, x'00')"))
            .bind(&channel_id)
            .bind(&server_id)
            .execute(db)
            .await
            .unwrap();
        for member in members {
            sqlx::query("INSERT INTO server_members (id, server_id, user_id) VALUES ($1, $2, $3)")
                .bind(crate::state::new_id())
                .bind(&server_id)
                .bind(member)
                .execute(db)
                .await
                .unwrap();
        }
        (server_id, channel_id)
    }

    async fn fetch_bundle(app: &Router, token: &str, user: &str, device: &str) -> (StatusCode, Value) {
        send(app, "POST", "/api/e2ee/prekey-bundle", Some(token), Some(json!({ "protocol_version": 2, "user_id": user, "device_id": device }))).await
    }

    fn parse_bundle(v: &Value) -> PreKeyBundleData {
        let id = |x: &Value| x.as_u64().unwrap() as u32;
        PreKeyBundleData {
            registration_id: id(&v["registration_id"]),
            identity_key: unb64(&v["identity_key"]),
            signed_pre_key: SignedPreKeyUpload {
                id: id(&v["signed_prekey"]["id"]),
                public: unb64(&v["signed_prekey"]["public"]),
                signature: unb64(&v["signed_prekey"]["signature"]),
            },
            kyber_pre_key: KyberPreKeyUpload {
                id: id(&v["kyber_prekey"]["id"]),
                public: unb64(&v["kyber_prekey"]["public"]),
                signature: unb64(&v["kyber_prekey"]["signature"]),
            },
            pre_key: (!v["one_time_prekey"].is_null())
                .then(|| PreKeyUpload { id: id(&v["one_time_prekey"]["id"]), public: unb64(&v["one_time_prekey"]["public"]) }),
        }
    }

    /// The pinned-key → trust-root chain, the way a client checks it.
    async fn verified_trust_root(app: &Router) -> Vec<u8> {
        let (_, identity) = send(app, "GET", "/api/instance/identity", None, None).await;
        assert_eq!(identity["e2ee_protocol"], 2);
        let pinned = unb64(&identity["server_public"]);
        let (status, tr) = send(app, "GET", "/api/e2ee/trust-root", None, None).await;
        assert_eq!(status, StatusCode::OK, "trust root is public (verified, not trusted)");
        let root = unb64(&tr["trust_root_public"]);
        assert_eq!(unb64(&tr["server_public"]), pinned);
        assert!(certs::verify_root_binding(&pinned, &root, &unb64(&tr["signature"])), "root signed by the instance key");
        root
    }

    async fn certificate(app: &Router, token: &str, device: &str) -> Vec<u8> {
        let (status, body) = send(app, "POST", "/api/e2ee/certificates", Some(token), Some(json!({ "device_id": device }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        unb64(&body["certificate"])
    }

    /// The whole v2 flow through the real router: libsignal registration, an authorized bundle
    /// fetch, PQXDH, a sealed-sender envelope deposited WITHOUT credentials, and decryption +
    /// sender authentication on the other side against the invite-pinned trust chain.
    #[tokio::test]
    async fn served_bundle_establishes_pqxdh_session_and_sealed_delivery() {
        let (app, db) = test_app().await;
        let (alice_id, alice_token) = signup(&app, "alice").await;
        let (bob_id, bob_token) = signup(&app, "bob").await;
        seed_server(&db, &alice_id, &[&alice_id, &bob_id]).await;

        let (mut alice, alice_payload) = device_payload(3);
        let (mut bob, bob_payload) = device_payload(3);
        let alice_dev = register(&app, &alice_token, alice_payload).await;
        let bob_dev = register(&app, &bob_token, bob_payload).await;
        let alice_addr = DeviceAddress::new(alice_id.clone(), alice_dev.clone());
        let bob_addr = DeviceAddress::new(bob_id.clone(), bob_dev.clone());

        let (status, bundle) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
        assert_eq!(status, StatusCode::OK, "{bundle}");
        assert_eq!(bundle["kyber_last_resort"], false);
        assert!(!bundle["one_time_prekey"].is_null());
        alice.process_bundle(&alice_addr, &bob_addr, &parse_bundle(&bundle)).expect("server-served bundle verifies + PQXDH");
        assert!(alice.has_session(&bob_addr));

        let root = verified_trust_root(&app).await;
        let cert = certificate(&app, &alice_token, &alice_dev).await;
        let info = certs::validate(&cert, &root, now_ms()).expect("certificate chains to the pinned root");
        assert_eq!(info.sender, alice_addr);
        assert_eq!(info.identity_key, alice.identity_key());
        assert!(info.expires_ms > now_ms() && info.expires_ms <= now_ms() + 25 * 60 * 60 * 1000);

        // Deposit: NO Authorization header. A wrong delivery key is refused without detail.
        let envelope = alice.sealed_encrypt(&bob_addr, &bob.identity_key(), &cert, b"hello bob").unwrap();
        let deposit = |key: &[u8]| json!({ "messages": [{ "user_id": bob_id, "device_id": bob_dev, "delivery_key": b64(key), "envelope": b64(&envelope) }] });
        let (status, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(deposit(&[0u8; 32]))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["results"][0]["status"], "gone");
        let (status, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(deposit(&unb64(&bundle["delivery_key"])))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["results"][0]["status"], "ok");

        // What the server stored names the recipient only; the sender appears nowhere in the row.
        let rows: Vec<(String, String, Vec<u8>)> = sqlx::query_as("SELECT user_id, device_id, envelope FROM sealed_envelopes").fetch_all(&db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].0.as_str(), rows[0].1.as_str()), (bob_id.as_str(), bob_dev.as_str()));
        let stored = String::from_utf8_lossy(&rows[0].2).to_string();
        assert!(!stored.contains(&alice_id) && !stored.contains(&alice_dev) && !stored.contains("hello bob"));

        // Only bob's device can read its mailbox.
        let inbox = format!("/api/e2ee/sealed/inbox?device_id={bob_dev}");
        let (status, _) = send(&app, "GET", &inbox, Some(&alice_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "GET", &inbox, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = send(&app, "GET", &inbox, Some(&bob_token), None).await;
        assert_eq!(status, StatusCode::OK);
        let envelopes = body["envelopes"].as_array().unwrap();
        assert_eq!(envelopes.len(), 1);
        assert!(envelopes[0].get("sender").is_none() && envelopes[0].get("author_id").is_none());

        let m = bob.sealed_decrypt(&bob_addr, &root, now_ms(), &unb64(&envelopes[0]["envelope"]), |_| Some(alice.identity_key())).expect("bob opens it");
        assert_eq!(m.sender, alice_addr, "sender authenticated end to end, never by the server");
        assert_eq!(m.plaintext, b"hello bob");

        // Ack: someone else's ack is a no-op; bob's empties the mailbox.
        let ack = json!({ "device_id": bob_dev, "ids": [envelopes[0]["id"]] });
        let (status, _) = send(&app, "POST", "/api/e2ee/sealed/ack", Some(&alice_token), Some(ack.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "alice's session speaks for alice's device only");
        let (_, body) = send(&app, "POST", "/api/e2ee/sealed/ack", Some(&bob_token), Some(ack)).await;
        assert_eq!(body["removed"], 1);
        let (_, body) = send(&app, "GET", &inbox, Some(&bob_token), None).await;
        assert!(body["envelopes"].as_array().unwrap().is_empty());

        // Bob replies on the established session; alice decrypts.
        let bob_cert = certificate(&app, &bob_token, &bob_dev).await;
        let reply = bob.sealed_encrypt(&alice_addr, &alice.identity_key(), &bob_cert, b"hi alice").unwrap();
        assert_eq!(alice.sealed_decrypt(&alice_addr, &root, now_ms(), &reply, |_| Some(bob.identity_key())).unwrap().plaintext, b"hi alice");
    }

    /// The legacy bug class: any account could pull (and burn) any other account's prekeys, and
    /// plant keys on devices it does not own. Bundles and device lists are relationship-gated;
    /// every key write is owner-scoped and signature-checked.
    #[tokio::test]
    async fn keys_are_owner_scoped_and_bundles_relationship_gated() {
        let (app, db) = test_app().await;
        let (victim_id, victim_token) = signup(&app, "victim").await;
        let (stranger_id, stranger_token) = signup(&app, "stranger").await;
        let (mut victim, payload) = device_payload(2);
        let victim_dev = register(&app, &victim_token, payload).await;
        let (mut stranger, payload) = device_payload(1);
        let stranger_dev = register(&app, &stranger_token, payload).await;

        // A stranger gets nothing: no bundle, no device list — and burns no one-time key.
        let (status, _) = fetch_bundle(&app, &stranger_token, &victim_id, &victim_dev).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "GET", &format!("/api/e2ee/users/{victim_id}/devices"), Some(&stranger_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = fetch_bundle(&app, "not-a-token", &victim_id, &victim_dev).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (_, counts) = send(&app, "GET", &format!("/api/e2ee/prekeys/count?device_id={victim_dev}"), Some(&victim_token), None).await;
        assert_eq!((counts["remaining"].as_i64(), counts["kyber_remaining"].as_i64()), (Some(2), Some(2)));

        // The stranger cannot upload, rotate, rekey, delete or certify the victim's device.
        let planted = json!({
            "device_id": victim_dev,
            "one_time_prekeys": stranger.generate_one_time_prekeys(1).unwrap().iter().map(prekey).collect::<Vec<_>>(),
        });
        let (status, _) = send(&app, "POST", "/api/e2ee/prekeys/replenish", Some(&stranger_token), Some(planted)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let rotate = json!({ "device_id": victim_dev, "signed_prekey": signed(&stranger.generate_signed_prekey().unwrap()) });
        let (status, _) = send(&app, "POST", "/api/e2ee/spk/rotate", Some(&stranger_token), Some(rotate)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "POST", &format!("/api/e2ee/devices/{victim_dev}/rekey"), Some(&stranger_token), Some(key_payload(&mut stranger, 1))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(delete_device(&app, &stranger_token, &stranger, &stranger_id, &victim_dev).await, StatusCode::NOT_FOUND);
        let (status, _) = send(&app, "POST", "/api/e2ee/certificates", Some(&stranger_token), Some(json!({ "device_id": victim_dev }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Even the OWNER cannot swap in prekeys signed by a different identity (a stolen session
        // token must not be able to re-key a device into something the thief can read).
        let rotate = json!({ "device_id": victim_dev, "signed_prekey": signed(&stranger.generate_signed_prekey().unwrap()) });
        let (status, _) = send(&app, "POST", "/api/e2ee/spk/rotate", Some(&victim_token), Some(rotate)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = send(&app, "POST", &format!("/api/e2ee/devices/{victim_dev}/rekey"), Some(&victim_token), Some(key_payload(&mut stranger, 1))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let planted = json!({
            "device_id": victim_dev,
            "one_time_kyber_prekeys": stranger.generate_one_time_kyber(1).unwrap().iter().map(kyber).collect::<Vec<_>>(),
        });
        let (status, _) = send(&app, "POST", "/api/e2ee/prekeys/replenish", Some(&victim_token), Some(planted)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Once they share a server, the same requests succeed; one's own devices always do.
        let (server_id, _) = seed_server(&db, &victim_id, &[&victim_id, &stranger_id]).await;
        let (status, bundle) = fetch_bundle(&app, &stranger_token, &victim_id, &victim_dev).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(unb64(&bundle["identity_key"]), victim.identity_key());
        let (status, body) = send(&app, "GET", &format!("/api/e2ee/users/{victim_id}/devices"), Some(&stranger_token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["devices"][0]["device_id"], victim_dev.as_str());
        assert_eq!(unb64(&body["devices"][0]["identity_key"]), victim.identity_key());
        let (status, _) = fetch_bundle(&app, &victim_token, &victim_id, &victim_dev).await;
        assert_eq!(status, StatusCode::OK);

        // member-devices: every device of every member, for members only.
        let path = format!("/api/e2ee/member-devices?server_id={server_id}");
        let (status, body) = send(&app, "GET", &path, Some(&stranger_token), None).await;
        assert_eq!(status, StatusCode::OK);
        let mut listed: Vec<&str> = body["devices"].as_array().unwrap().iter().map(|d| d["device_id"].as_str().unwrap()).collect();
        listed.sort_unstable();
        let mut expected = [victim_dev.as_str(), stranger_dev.as_str()];
        expected.sort_unstable();
        assert_eq!(listed, expected);
        let (_, outsider_token) = signup(&app, "outsider").await;
        let (status, _) = send(&app, "GET", &path, Some(&outsider_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A legitimate rotation by the owner works and is what the next bundle serves.
        let new_spk = victim.generate_signed_prekey().unwrap();
        let new_lr = victim.generate_last_resort_kyber().unwrap();
        let rotate = json!({ "device_id": victim_dev, "signed_prekey": signed(&new_spk), "last_resort_kyber_prekey": kyber(&new_lr) });
        let p = rotate_proof(&victim, &victim_id, &victim_dev, &new_spk, Some(&new_lr));
        let (status, _) = send_proved(&app, "POST", "/api/e2ee/spk/rotate", &victim_token, Some(rotate), &p).await;
        assert_eq!(status, StatusCode::OK);
        let (_, bundle) = fetch_bundle(&app, &stranger_token, &victim_id, &victim_dev).await;
        assert_eq!(bundle["signed_prekey"]["id"], new_spk.id);
    }

    /// M1: THE ATTACK. A stolen session token (no device key) replays the device's own PUBLIC
    /// signed-prekey signatures — they are served in every bundle — to "rekey" it: that wiped the
    /// mailbox and the one-time prekeys and pointed the delivery key at the thief. The same token
    /// could roll the signed prekey back and plant unsigned EC one-time prekeys. All three now
    /// need a device proof bound to the exact keys, single use.
    #[tokio::test]
    async fn token_only_rekey_rotate_and_replenish_are_refused() {
        let (app, db) = test_app().await;
        let (victim_id, token) = signup(&app, "victim").await;
        let (peer_id, peer_token) = signup(&app, "peer").await;
        seed_server(&db, &victim_id, &[&victim_id, &peer_id]).await;
        let mut victim = SignalStore::generate();
        let payload = key_payload(&mut victim, 2);
        let published = payload.clone(); // everything in here is public or known to a token holder
        let dev = register(&app, &token, payload).await;
        let mailbox = |app: Router, token: String, dev: String| async move {
            send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={dev}"), Some(&token), None).await.1["envelopes"].as_array().map(|a| a.len()).unwrap_or(0)
        };
        // Something is waiting in the victim's mailbox.
        let deposit = json!({ "messages": [{ "user_id": victim_id, "device_id": dev, "delivery_key": b64(&[7u8; 32]), "envelope": b64(b"sealed") }] });
        let (status, _) = send(&app, "POST", "/api/e2ee/sealed/send", Some(&peer_token), Some(deposit)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(mailbox(app.clone(), token.clone(), dev.clone()).await, 1);

        // --- the thief: token only ---
        // Rekey with the device's own published keys, the thief's delivery key, no one-time keys.
        let mut replay = published.clone();
        replay["delivery_key"] = json!(b64(&[0x66u8; 32]));
        replay["one_time_prekeys"] = json!([]);
        replay["one_time_kyber_prekeys"] = json!([]);
        let path = format!("/api/e2ee/devices/{dev}/rekey");
        let (status, _) = send(&app, "POST", &path, Some(&token), Some(replay.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a token-only rekey was accepted");
        assert_eq!(mailbox(app.clone(), token.clone(), dev.clone()).await, 1, "the mailbox was wiped");
        let (_, counts) = send(&app, "GET", &format!("/api/e2ee/prekeys/count?device_id={dev}"), Some(&token), None).await;
        assert_eq!(counts["remaining"].as_i64(), Some(2), "the one-time prekeys were wiped");
        let (_, listing) = send(&app, "GET", &format!("/api/e2ee/users/{victim_id}/devices"), Some(&peer_token), None).await;
        assert_eq!(unb64(&listing["devices"][0]["delivery_key"]), [7u8; 32], "the delivery key was redirected");
        // Roll the signed prekey "forward" to the published one again (a rollback in general).
        let rotate = json!({ "device_id": dev, "signed_prekey": published["signed_prekey"], "last_resort_kyber_prekey": published["last_resort_kyber_prekey"] });
        let (status, _) = send(&app, "POST", "/api/e2ee/spk/rotate", Some(&token), Some(rotate.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a token-only signed-prekey rotation was accepted");
        // Plant EC one-time prekeys the thief holds the private halves of (they carry no signature).
        let mut thief = SignalStore::generate();
        let planted_keys = thief.generate_one_time_prekeys(3).unwrap();
        let planted = json!({ "device_id": dev, "one_time_prekeys": planted_keys.iter().map(prekey).collect::<Vec<_>>() });
        let (status, _) = send(&app, "POST", "/api/e2ee/prekeys/replenish", Some(&token), Some(planted.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "token-only prekey planting was accepted");
        // A proof by a key that is not on the account, or the victim's proof for OTHER keys /
        // another operation, does not help.
        let p = replenish_proof(&thief, &victim_id, &dev, &planted_keys, &[]);
        assert_eq!(send_proved(&app, "POST", "/api/e2ee/prekeys/replenish", &token, Some(planted.clone()), &p).await.0, StatusCode::FORBIDDEN);
        let own_keys = victim.generate_one_time_prekeys(1).unwrap();
        let observed = replenish_proof(&victim, &victim_id, &dev, &own_keys, &[]);
        assert_eq!(send_proved(&app, "POST", "/api/e2ee/prekeys/replenish", &token, Some(planted), &observed).await.0, StatusCode::FORBIDDEN, "a proof was reused with different keys");
        assert_eq!(send_proved(&app, "POST", "/api/e2ee/spk/rotate", &token, Some(rotate), &observed).await.0, StatusCode::FORBIDDEN);

        // --- the device itself ---
        let body = json!({ "device_id": dev, "one_time_prekeys": own_keys.iter().map(prekey).collect::<Vec<_>>() });
        assert_eq!(send_proved(&app, "POST", "/api/e2ee/prekeys/replenish", &token, Some(body.clone()), &observed).await.0, StatusCode::OK);
        // Single use: the same proof (and request) a second time is refused.
        assert_eq!(send_proved(&app, "POST", "/api/e2ee/prekeys/replenish", &token, Some(body), &observed).await.0, StatusCode::FORBIDDEN);
        // A real rekey (after a backup restore): proof over exactly the new keys.
        let fresh = key_payload(&mut victim, 1);
        let pubs = |v: &Value, k: &str| -> Vec<Vec<u8>> { v[k].as_array().unwrap().iter().map(|e| unb64(&e["public"])).collect() };
        let (ec, ky) = (pubs(&fresh, "one_time_prekeys"), pubs(&fresh, "one_time_kyber_prekeys"));
        let rekey_payload = skwod_crypto::link::op_payload(&[
            &victim.registration_id().to_be_bytes(),
            &unb64(&fresh["signed_prekey"]["public"]),
            &unb64(&fresh["last_resort_kyber_prekey"]["public"]),
            &[7u8; 32],
            &keys_blob(ec.iter().map(Vec::as_slice).collect()),
            &keys_blob(ky.iter().map(Vec::as_slice).collect()),
        ]);
        let rekey_payload = skwod_crypto::link::op_payload(&[&rekey_payload, &install_hash()]);
        let p = proof(&victim, "rekey", &victim_id, &dev, &rekey_payload);
        // ...which a thief cannot redirect by swapping the delivery key under the same proof.
        let mut redirected = fresh.clone();
        redirected["delivery_key"] = json!(b64(&[0x66u8; 32]));
        assert_eq!(send_proved(&app, "POST", &path, &token, Some(redirected), &p).await.0, StatusCode::FORBIDDEN);
        let (status, body) = send_proved(&app, "POST", &path, &token, Some(fresh), &p).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(mailbox(app.clone(), token.clone(), dev.clone()).await, 0, "a genuine rekey drops mail for keys that no longer exist");
    }

    /// One-time keys are handed out once each; when they run out the device's last-resort Kyber
    /// key is served (never a bundle without a KEM key), and a session still establishes.
    #[tokio::test]
    async fn exhausted_one_time_keys_fall_back_to_last_resort_kyber() {
        let (app, db) = test_app().await;
        let (bob_id, bob_token) = signup(&app, "bob").await;
        let (alice_id, alice_token) = signup(&app, "alice").await;
        seed_server(&db, &bob_id, &[&bob_id, &alice_id]).await;
        let (mut bob, payload) = device_payload(1);
        let last_resort_id = payload["last_resort_kyber_prekey"]["id"].clone();
        let bob_dev = register(&app, &bob_token, payload).await;
        let (mut alice, payload) = device_payload(1);
        let alice_dev = register(&app, &alice_token, payload).await;
        let (alice_addr, bob_addr) = (DeviceAddress::new(alice_id, alice_dev.clone()), DeviceAddress::new(bob_id.clone(), bob_dev.clone()));

        let (_, first) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
        assert!(!first["one_time_prekey"].is_null());
        assert_eq!(first["kyber_last_resort"], false);
        assert_ne!(first["kyber_prekey"]["id"], last_resort_id);

        let (status, second) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
        assert_eq!(status, StatusCode::OK);
        assert!(second["one_time_prekey"].is_null(), "EC one-time keys exhausted");
        assert_eq!(second["kyber_last_resort"], true);
        assert_eq!(second["kyber_prekey"]["id"], last_resort_id);
        // Never handed out twice.
        assert_ne!(first["kyber_prekey"]["id"], second["kyber_prekey"]["id"]);

        // A session over the last-resort bundle is still a full PQXDH + SPQR session.
        alice.process_bundle(&alice_addr, &bob_addr, &parse_bundle(&second)).unwrap();
        assert!(alice.has_session(&bob_addr));
        let root = verified_trust_root(&app).await;
        let cert = certificate(&app, &alice_token, &alice_dev).await;
        let env = alice.sealed_encrypt(&bob_addr, &bob.identity_key(), &cert, b"via last resort").unwrap();
        assert_eq!(bob.sealed_decrypt(&bob_addr, &root, now_ms(), &env, |_| Some(alice.identity_key())).unwrap().plaintext, b"via last resort");

        // Replenish restocks both kinds; consumed rows are dropped.
        let (ec, ky) = (bob.generate_one_time_prekeys(5).unwrap(), bob.generate_one_time_kyber(4).unwrap());
        let replenish = json!({
            "device_id": bob_dev,
            "one_time_prekeys": ec.iter().map(prekey).collect::<Vec<_>>(),
            "one_time_kyber_prekeys": ky.iter().map(kyber).collect::<Vec<_>>(),
        });
        let p = replenish_proof(&bob, &bob_id, &bob_dev, &ec, &ky);
        let (status, body) = send_proved(&app, "POST", "/api/e2ee/prekeys/replenish", &bob_token, Some(replenish), &p).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!((body["remaining"].as_i64(), body["kyber_remaining"].as_i64()), (Some(5), Some(4)));
        let (_, third) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
        assert!(!third["one_time_prekey"].is_null());
        assert_eq!(third["kyber_last_resort"], false);
    }

    /// Prekey-exhaustion DoS bound: bundle fetches are capped per (caller, target account).
    #[tokio::test]
    async fn bundle_fetches_are_rate_limited_per_target() {
        let (app, db) = test_app().await;
        let (bob_id, bob_token) = signup(&app, "bob").await;
        let (alice_id, alice_token) = signup(&app, "alice").await;
        let (carol_id, carol_token) = signup(&app, "carol").await;
        seed_server(&db, &bob_id, &[&bob_id, &alice_id, &carol_id]).await;
        let (_, payload) = device_payload(40);
        let bob_dev = register(&app, &bob_token, payload).await;

        for i in 0..15 {
            let (status, _) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
            assert_eq!(status, StatusCode::OK, "fetch {i}");
        }
        let (status, _) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // The limiter stopped the drain: bob still has one-time keys, and another member is unaffected.
        let (_, counts) = send(&app, "GET", &format!("/api/e2ee/prekeys/count?device_id={bob_dev}"), Some(&bob_token), None).await;
        assert_eq!(counts["remaining"], 25);
        let (status, bundle) = fetch_bundle(&app, &carol_token, &bob_id, &bob_dev).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!bundle["one_time_prekey"].is_null());
    }

    #[tokio::test]
    async fn bad_or_missing_key_material_is_rejected() {
        let (app, _db) = test_app().await;
        let (_, token) = signup(&app, "eve").await;
        let reject = |payload: Value| {
            let app = app.clone();
            let token = token.clone();
            async move { send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(payload)).await.0 }
        };
        let flip = |field: &str| {
            let (_, mut p) = device_payload(1);
            let mut sig = unb64(&p[field]["signature"]);
            sig[5] ^= 1;
            p[field]["signature"] = json!(b64(&sig));
            p
        };
        assert_eq!(reject(flip("signed_prekey")).await, StatusCode::BAD_REQUEST);
        assert_eq!(reject(flip("last_resort_kyber_prekey")).await, StatusCode::BAD_REQUEST);

        // Post-quantum is mandatory: no last-resort Kyber key, no registration.
        let (_, mut p) = device_payload(1);
        p.as_object_mut().unwrap().remove("last_resort_kyber_prekey");
        assert_eq!(reject(p).await, StatusCode::BAD_REQUEST);
        // A one-time Kyber key signed by someone else.
        let (_, mut p) = device_payload(1);
        let (mut other, _) = device_payload(0);
        p["one_time_kyber_prekeys"] = json!(other.generate_one_time_kyber(1).unwrap().iter().map(kyber).collect::<Vec<_>>());
        assert_eq!(reject(p).await, StatusCode::BAD_REQUEST);
        // Garbage identity / one-time key / delivery key.
        let (_, mut p) = device_payload(1);
        p["identity_key"] = json!(b64(&[1u8; 33]));
        assert_eq!(reject(p).await, StatusCode::BAD_REQUEST);
        let (_, mut p) = device_payload(1);
        p["one_time_prekeys"] = json!([{ "id": 1, "public": b64(&[0u8; 5]) }]);
        assert_eq!(reject(p).await, StatusCode::BAD_REQUEST);
        let (_, mut p) = device_payload(1);
        p["delivery_key"] = json!(b64(b"short"));
        assert_eq!(reject(p).await, StatusCode::BAD_REQUEST);
        // And an intact payload goes through.
        let (_, p) = device_payload(1);
        assert_eq!(reject(p).await, StatusCode::OK);
    }

    /// Builds 29–40 (in-house protocol) get an explicit, user-facing "update required" — on
    /// registration and on bundle fetch — instead of a confusing failure.
    #[tokio::test]
    async fn pre_libsignal_clients_get_update_required() {
        let (app, _db) = test_app().await;
        let (user_id, token) = signup(&app, "oldtimer").await;
        // The exact body shape build 40 sends.
        let v1 = json!({
            "identity_dh_public": b64(&[1u8; 32]),
            "identity_signing_public": b64(&[2u8; 32]),
            "spk_public": b64(&[3u8; 32]),
            "spk_sig": b64(&[4u8; 64]),
            "pq_spk_public": b64(&[5u8; 1568]),
            "pq_spk_sig": b64(&[6u8; 64]),
            "one_time_prekeys": [{ "key_id": 0, "public_key": b64(&[7u8; 32]) }],
        });
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(v1)).await;
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
        assert!(body["error"].as_str().unwrap().contains("update required"), "{body}");
        let (status, body) =
            send(&app, "POST", "/api/e2ee/prekey-bundle", Some(&token), Some(json!({ "user_id": user_id, "device_id": "x" }))).await;
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
        assert!(body["error"].as_str().unwrap().contains("update"));
        // A client from the future is told the server is the stale side.
        let (_, mut p) = device_payload(1);
        p["protocol_version"] = json!(3);
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(p)).await;
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
        assert!(body["error"].as_str().unwrap().contains("server"));
        // No device row was created by any of that.
        let (_, body) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert!(body["devices"].as_array().unwrap().is_empty());
    }

    /// A valid session token is NOT enough to add a device to an account that already has one:
    /// the new device must carry a link signature from an existing device's identity key. This is
    /// what stops a stolen token from silently enrolling an attacker device that would then
    /// receive synced DMs and be treated as "one of mine".
    #[tokio::test]
    async fn extra_devices_must_be_linked_by_an_existing_device() {
        let (app, _db) = test_app().await;
        let (user_id, token) = signup(&app, "linker").await;
        let (first, payload) = device_payload(1);
        let first_dev = register(&app, &token, payload).await;

        // Stolen-token attempt: plain registration of a second device.
        let (attacker, payload) = device_payload(1);
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(payload.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "device link required");
        // ...self-signed "link", a link naming a device that does not exist, a link signature for
        // a different identity, and a link signed for a different account: all refused.
        let try_link = |device: &str, sig: Vec<u8>| {
            let mut p = payload.clone();
            p["link"] = json!({ "device_id": device, "signature": b64(&sig) });
            let (app, token) = (app.clone(), token.clone());
            async move { send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(p)).await.0 }
        };
        let attacker_ik = attacker.identity_key();
        assert_eq!(try_link(&first_dev, attacker.sign_link(&user_id, &attacker_ik).unwrap()).await, StatusCode::FORBIDDEN);
        assert_eq!(try_link("no-such-device", first.sign_link(&user_id, &attacker_ik).unwrap()).await, StatusCode::FORBIDDEN);
        assert_eq!(try_link(&first_dev, first.sign_link(&user_id, &first.identity_key()).unwrap()).await, StatusCode::FORBIDDEN);
        assert_eq!(try_link(&first_dev, first.sign_link("someone-else", &attacker_ik).unwrap()).await, StatusCode::FORBIDDEN);
        let (_, body) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert_eq!(body["devices"].as_array().unwrap().len(), 1, "nothing was enrolled");

        // The real flow: the new device files a request (public values + an HMAC under the link
        // code), the existing device approves with its signature, the new device registers with it.
        let (new, mut new_payload) = device_payload(1);
        let code = skwod_crypto::link::generate_code();
        let req = json!({
            "identity_key": b64(&new.identity_key()),
            "proof": b64(&skwod_crypto::link::request_proof(&code, &user_id, &new.identity_key())),
        });
        let (status, body) = send(&app, "POST", "/api/e2ee/link-requests", Some(&token), Some(req)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let request_id = body["request_id"].as_str().unwrap().to_string();
        let (_, pending) = send(&app, "GET", "/api/e2ee/link-requests", Some(&token), None).await;
        let listed = &pending["requests"][0];
        assert_eq!(listed["request_id"], request_id.as_str());
        let listed_ik = unb64(&listed["identity_key"]);
        assert!(skwod_crypto::link::verify_request_proof(&code, &user_id, &listed_ik, &unb64(&listed["proof"])));
        let (_, poll) = send(&app, "GET", &format!("/api/e2ee/link-requests/{request_id}"), Some(&token), None).await;
        assert_eq!(poll["approved"], false);

        // An approval whose signature is not the approving device's vouching is rejected.
        let bad = json!({ "device_id": first_dev, "signature": b64(&attacker.sign_link(&user_id, &listed_ik).unwrap()), "approval_mac": b64(&[0u8; 32]) });
        let (status, _) = send(&app, "POST", &format!("/api/e2ee/link-requests/{request_id}/approve"), Some(&token), Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let sig = first.sign_link(&user_id, &listed_ik).unwrap();
        let mac = skwod_crypto::link::approval_mac(&code, &user_id, &first.identity_key(), &listed_ik);
        let approve = json!({ "device_id": first_dev, "signature": b64(&sig), "approval_mac": b64(&mac) });
        let (status, _) = send(&app, "POST", &format!("/api/e2ee/link-requests/{request_id}/approve"), Some(&token), Some(approve)).await;
        assert_eq!(status, StatusCode::OK);
        // Another account can neither see nor approve the request.
        let (_, other_token) = signup(&app, "bystander").await;
        let (status, _) = send(&app, "GET", &format!("/api/e2ee/link-requests/{request_id}"), Some(&other_token), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, poll) = send(&app, "GET", &format!("/api/e2ee/link-requests/{request_id}"), Some(&token), None).await;
        assert_eq!(poll["approved"], true);
        assert!(skwod_crypto::link::verify_approval_mac(&code, &user_id, &unb64(&poll["identity_key"]), &new.identity_key(), &unb64(&poll["approval_mac"])));
        new_payload["link"] = json!({ "device_id": poll["device_id"], "signature": poll["signature"] });
        let new_dev = register(&app, &token, new_payload).await;

        // Every sibling can verify the stored link proof without trusting the server.
        let (_, body) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        let row = body["devices"].as_array().unwrap().iter().find(|d| d["device_id"] == new_dev.as_str()).unwrap();
        assert_eq!(row["linked_by"], first_dev.as_str());
        assert!(skwod_crypto::link::verify_link(&first.identity_key(), &user_id, &unb64(&row["identity_key"]), &unb64(&row["link_sig"])));
        let (_, pending) = send(&app, "GET", "/api/e2ee/link-requests", Some(&token), None).await;
        assert!(pending["requests"].as_array().unwrap().is_empty(), "consumed");

    }

    /// The bypasses a bare session token used to have around linking: empty the device list and
    /// register as a "first device", or ask for a forced reset. "First device" is a durable
    /// per-account fact; deletion needs a signature from a device on the account; a reset needs
    /// the registration-lock PIN or survives a 7-day window in which any device can cancel it.
    #[tokio::test]
    async fn session_token_alone_cannot_delete_devices_or_reset_the_account() {
        let (app, db) = test_app().await;
        let (user_id, token) = signup(&app, "target").await;
        let (first, payload) = device_payload(1);
        let first_dev = register(&app, &token, payload).await;
        let (second, second_dev) = register_linked(&app, &token, &user_id, &first, &first_dev).await;
        let (attacker, attacker_payload) = device_payload(1);
        let device_count = || async {
            let (_, body) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
            body["devices"].as_array().unwrap().len()
        };

        // --- delete ---
        // Token only; a signature by a key that is not on the account; a valid signature for a
        // DIFFERENT device; a stale signature; the proof smuggled in the query string: all refused.
        let path = format!("/api/e2ee/devices/{first_dev}");
        let (status, _) = send(&app, "DELETE", &path, Some(&token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(delete_device(&app, &token, &attacker, &user_id, &first_dev).await, StatusCode::FORBIDDEN);
        let for_other = proof(&first, "delete", &user_id, &second_dev, b"");
        assert_eq!(send_proved(&app, "DELETE", &path, &token, None, &for_other).await.0, StatusCode::FORBIDDEN);
        let stale = proof_at(&first, "delete", &user_id, &first_dev, b"", crate::state::now_ms() - 3_600_000);
        assert_eq!(send_proved(&app, "DELETE", &path, &token, None, &stale).await.0, StatusCode::FORBIDDEN);
        let good = proof(&first, "delete", &user_id, &first_dev, b"");
        let (ts, sig) = good.split_once('.').unwrap();
        let in_query = format!("{path}?timestamp={ts}&signature={}", sig.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D"));
        assert_eq!(send(&app, "DELETE", &in_query, Some(&token), None).await.0, StatusCode::FORBIDDEN, "proofs are not read from the URL");
        assert_eq!(device_count().await, 2);

        // --- forced reset without a PIN: only a REQUEST; the devices stay ---
        let mut reset = attacker_payload.clone();
        reset["force"] = json!(true);
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "device reset pending");
        let completes_at = body["completes_at"].as_i64().unwrap();
        assert!(completes_at >= crate::state::now_ms() + 6 * 24 * 3_600_000, "a 7-day hold");
        let (status, _) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "asking again does not shorten it");
        assert_eq!(device_count().await, 2);
        // The existing devices can see it...
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert_eq!(listing["reset_completes_at"], completes_at);
        // ...and cancel it — but only with a device signature, not with the token the attacker also has.
        let (status, _) = send(&app, "POST", "/api/e2ee/devices/reset/cancel", Some(&token), Some(json!({ "device_id": first_dev }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(cancel_reset(&app, &token, &attacker, &user_id, &first_dev).await, StatusCode::FORBIDDEN);
        assert_eq!(cancel_reset(&app, &token, &second, &user_id, &second_dev).await, StatusCode::OK);
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert!(listing["reset_completes_at"].is_null());

        // --- the owner removes BOTH devices legitimately (signed) ---
        // (Removing a device ends the sessions bound to it — here the one that registered both —
        // so the rest of the test runs on a fresh sign-in.)
        let bound = token;
        let token = login(&app, "target").await;
        assert_eq!(delete_device(&app, &token, &first, &user_id, &second_dev).await, StatusCode::FORBIDDEN, "a signature is not enough: the session must be that device's");
        bind_as(&app, &token, &first, &user_id, &first_dev).await;
        assert_eq!(delete_device(&app, &token, &first, &user_id, &second_dev).await, StatusCode::OK, "a sibling may remove a device");
        assert_eq!(send(&app, "GET", "/api/auth/me", Some(&bound), None).await.0, StatusCode::UNAUTHORIZED, "the removed device's session is over");
        assert_eq!(delete_device(&app, &token, &first, &user_id, &first_dev).await, StatusCode::OK, "a device may remove itself");
        let token = login(&app, "target").await;
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert_eq!(listing["devices"].as_array().unwrap().len(), 0);

        // --- an EMPTY device list is not a fresh account ---
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(attacker_payload.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "delete-then-register must not reach the first-device path");
        assert_eq!(body["error"], "device link required");
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset.clone())).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device reset pending")));
        // A different identity cannot ride on that pending request, even after the wait...
        sqlx::query("UPDATE e2ee_accounts SET reset_requested_at = reset_requested_at - $1 WHERE user_id = $2")
            .bind(super::super::keydir::RESET_DELAY_MS + 1000)
            .bind(&user_id)
            .execute(&db)
            .await
            .unwrap();
        let (_, mut other) = device_payload(1);
        other["force"] = json!(true);
        let (status, _) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(other)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a new identity restarts the clock");
        // ...while the identity that waited out the full, uncancelled window gets through, as the
        // account's only device, unlinked (so every peer sees a new identity).
        sqlx::query("UPDATE e2ee_accounts SET reset_requested_at = $1, reset_identity_key = $2 WHERE user_id = $3")
            .bind(crate::state::now_ms() - super::super::keydir::RESET_DELAY_MS - 1000)
            .bind(attacker.identity_key())
            .bind(&user_id)
            .execute(&db)
            .await
            .unwrap();
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        let devices = listing["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 1);
        assert!(devices[0]["linked_by"].is_null());
        assert!(listing["reset_completes_at"].is_null());
    }

    /// A block cuts off EVERY path to key material, including the per-server member-device list
    /// (which two members of the same server would otherwise still share).
    #[tokio::test]
    async fn blocks_hide_devices_on_every_directory_path() {
        let (app, db) = test_app().await;
        let (alice_id, alice_token) = signup(&app, "alice").await;
        let (mallory_id, mallory_token) = signup(&app, "mallory").await;
        let (carol_id, carol_token) = signup(&app, "carol").await;
        let (server_id, _) = seed_server(&db, &alice_id, &[&alice_id, &mallory_id, &carol_id]).await;
        let mut devs = std::collections::HashMap::new();
        let mut stores = std::collections::HashMap::new();
        for (name, token) in [("alice", &alice_token), ("mallory", &mallory_token), ("carol", &carol_token)] {
            let (store, payload) = device_payload(2);
            devs.insert(name, register(&app, token, payload).await);
            stores.insert(name, store);
        }
        // A delivery-key rotation request signed by `signer` over the new key.
        let rotate = |token: &str, signer: &SignalStore, owner: &str, dev: &str, key: u8, signed_key: u8| {
            let (app, token, path) = (app.clone(), token.to_string(), format!("/api/e2ee/devices/{dev}/delivery-key"));
            let proof = proof(signer, "delivery-key", owner, dev, &[signed_key; 32]);
            async move { send_proved(&app, "PUT", &path, &token, Some(json!({ "delivery_key": b64(&[key; 32]) })), &proof).await.0 }
        };
        let member_path = format!("/api/e2ee/member-devices?server_id={server_id}");
        let listed = |body: &Value| -> Vec<String> {
            let mut v: Vec<String> = body["devices"].as_array().unwrap().iter().map(|d| d["user_id"].as_str().unwrap().to_string()).collect();
            v.sort();
            v
        };
        let all = { let mut v = vec![alice_id.clone(), mallory_id.clone(), carol_id.clone()]; v.sort(); v };
        let (_, before) = send(&app, "GET", &member_path, Some(&mallory_token), None).await;
        assert_eq!(listed(&before), all);

        // Alice blocks Mallory.
        let (status, _) = send(&app, "PUT", &format!("/api/blocks/{mallory_id}"), Some(&alice_token), None).await;
        assert_eq!(status, StatusCode::OK);

        // Mallory no longer gets Alice's delivery/identity keys by ANY route...
        let (_, after) = send(&app, "GET", &member_path, Some(&mallory_token), None).await;
        assert!(!listed(&after).contains(&alice_id), "member-devices leaked a blocker's devices");
        assert!(listed(&after).contains(&carol_id), "unrelated members are unaffected");
        let (status, _) = send(&app, "GET", &format!("/api/e2ee/users/{alice_id}/devices"), Some(&mallory_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = fetch_bundle(&app, &mallory_token, &alice_id, &devs["alice"]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // ...and the block is symmetric: Alice is not handed Mallory's either.
        let (_, alice_view) = send(&app, "GET", &member_path, Some(&alice_token), None).await;
        assert!(!listed(&alice_view).contains(&mallory_id));
        let (status, _) = fetch_bundle(&app, &alice_token, &mallory_id, &devs["mallory"]).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Carol still sees everyone.
        let (_, carol_view) = send(&app, "GET", &member_path, Some(&carol_token), None).await;
        assert_eq!(listed(&carol_view), all);

        // The delivery key Mallory already held dies when Alice rotates hers (what the client does
        // on block), and Mallory cannot fetch the new one.
        let old_key = before["devices"].as_array().unwrap().iter().find(|d| d["user_id"] == alice_id.as_str()).unwrap()["delivery_key"].clone();
        assert_eq!(rotate(&alice_token, &stores["alice"], &alice_id, &devs["alice"], 3, 3).await, StatusCode::OK);
        // A session token without the device's key cannot rotate it; nor can a proof signed for
        // one key install another.
        assert_eq!(rotate(&alice_token, &stores["mallory"], &alice_id, &devs["alice"], 5, 5).await, StatusCode::FORBIDDEN);
        assert_eq!(rotate(&alice_token, &stores["alice"], &alice_id, &devs["alice"], 6, 7).await, StatusCode::FORBIDDEN);
        let deposit = json!({ "messages": [{ "user_id": alice_id, "device_id": devs["alice"], "delivery_key": old_key, "envelope": b64(b"spam") }] });
        let (_, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(deposit)).await;
        assert_eq!(body["results"][0]["status"], "gone");
        // Only the owner can rotate a device's delivery key.
        assert_eq!(rotate(&mallory_token, &stores["mallory"], &mallory_id, &devs["alice"], 4, 4).await, StatusCode::FORBIDDEN);

        // Unblock restores visibility.
        let (status, _) = send(&app, "DELETE", &format!("/api/blocks/{mallory_id}"), Some(&alice_token), None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, restored) = send(&app, "GET", &member_path, Some(&mallory_token), None).await;
        assert_eq!(listed(&restored), all);
    }

    #[tokio::test]
    async fn max_five_devices_enforced() {
        let (app, _db) = test_app().await;
        let (user_id, token) = signup(&app, "hoarder").await;
        let (first, payload) = device_payload(1);
        let first_dev = register(&app, &token, payload).await;
        // (One session drives every device here and ends up bound to the newest, so each
        // device links the next.)
        let (mut linker, mut linker_dev) = (first, first_dev);
        for _ in 0..4 {
            (linker, linker_dev) = register_linked(&app, &token, &user_id, &linker, &linker_dev).await;
        }
        // A sixth, properly approved, is still refused.
        let (sixth, mut payload) = device_payload(1);
        let sig = b64(&linker.sign_link(&user_id, &sixth.identity_key()).unwrap());
        let (_, created) = send(&app, "POST", "/api/e2ee/link-requests", Some(&token), Some(json!({ "identity_key": b64(&sixth.identity_key()), "proof": b64(&[0u8; 32]) }))).await;
        let approve = json!({ "device_id": linker_dev, "signature": sig, "approval_mac": b64(&[0u8; 32]) });
        let (status, _) = send(&app, "POST", &format!("/api/e2ee/link-requests/{}/approve", created["request_id"].as_str().unwrap()), Some(&token), Some(approve)).await;
        assert_eq!(status, StatusCode::OK);
        payload["link"] = json!({ "device_id": linker_dev, "signature": sig });
        let (status, _) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(payload)).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    fn pin_body(pin: Option<&str>, current: Option<&str>) -> Value {
        json!({ "enable": pin.is_some(), "pin": pin, "current_pin": current })
    }
    fn pin_proof(signer: &SignalStore, user_id: &str, pin: Option<&str>) -> String {
        proof(signer, "set-pin", user_id, if pin.is_some() { "enable" } else { "disable" }, pin.unwrap_or("").as_bytes())
    }

    /// The registration-lock PIN is what lets a reset skip the 7-day hold, so the PIN itself must
    /// not be settable with a session token — otherwise a token thief plants a PIN and resets at
    /// once. Setting it needs a device signature (+ the current PIN if one exists), and a PIN only
    /// waives the hold after it has been in place for the length of the hold.
    #[tokio::test]
    async fn registration_pin_needs_device_proof_and_cannot_shortcut_a_reset() {
        let (app, db) = test_app().await;
        let (user_id, token) = signup(&app, "locked").await;
        let (device, payload) = device_payload(1);
        let device_id = register(&app, &token, payload).await;
        let (attacker, attacker_payload) = device_payload(1);
        // `set(signer, pin, current)`: a set-pin request signed by `signer` over that exact PIN.
        let set = |signer: &SignalStore, pin: Option<&str>, current: Option<&str>| {
            let (app, token, body, proof) = (app.clone(), token.clone(), pin_body(pin, current), pin_proof(signer, &user_id, pin));
            async move { send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(body), &proof).await.0 }
        };
        let hash = || async {
            sqlx::query_scalar::<_, Option<String>>("SELECT registration_pin_hash FROM profiles WHERE id = $1").bind(&user_id).fetch_one(&db).await.unwrap()
        };

        // Session-only attacker: no proof at all, and a proof by a key that is not on the account.
        let (status, _) = send(&app, "POST", "/api/e2ee/registration-pin", Some(&token), Some(pin_body(Some("666666"), None))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(set(&attacker, Some("666666"), None).await, StatusCode::FORBIDDEN);
        assert!(hash().await.is_none(), "no PIN was planted");

        // The real device sets one. Too short is refused; stored as an Argon2id hash only.
        assert_eq!(set(&device, Some("1234"), None).await, StatusCode::BAD_REQUEST);
        // The attacker OBSERVES this legitimate request (same token, a proxy log, a compromised
        // relay) and keeps its proof.
        let observed = pin_proof(&device, &user_id, Some("482913"));
        let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(pin_body(Some("482913"), None)), &observed).await;
        assert_eq!(status, StatusCode::OK);
        let stored = hash().await.unwrap();
        assert!(stored.starts_with("$argon2id$") && !stored.contains("482913"), "stored: {stored}");
        // Payload swap: the observed signature with a PIN of the attacker's choosing — refused,
        // because the signature covers the PIN. (Tried with and without knowing the current PIN.)
        for current in [None, Some("482913")] {
            let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(pin_body(Some("666666"), current)), &observed).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "payload swap");
        }
        // Verbatim replay: refused too — each proof is accepted once.
        let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(pin_body(Some("482913"), Some("482913"))), &observed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "replay");
        // Malleated replay: the used signature re-encoded as (R, S + L). libsignal's raw verifier
        // would accept that encoding, and its bytes (so any hash of them) differ — it must still
        // be refused, both as non-canonical and because the replay record is keyed on what was
        // signed rather than on the signature.
        let (ts, sig) = observed.split_once('.').unwrap();
        let raw = B64.decode(sig).unwrap();
        let mut twin = raw.clone();
        let order: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x10,
        ];
        let sign_bit = twin[63] & 0x80;
        twin[63] &= 0x7f;
        let mut carry = 0u16;
        for i in 0..32 {
            let v = twin[32 + i] as u16 + order[i] as u16 + carry;
            twin[32 + i] = v as u8;
            carry = v >> 8;
        }
        twin[63] |= sign_bit;
        assert_ne!(twin, raw);
        let mutated = format!("{ts}.{}", b64(&twin));
        let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(pin_body(Some("482913"), Some("482913"))), &mutated).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "malleated replay");
        // And a SECOND, perfectly valid signature by the device over the same request (same
        // timestamp) is still the same authorization, already spent.
        let ts: i64 = ts.parse().unwrap();
        let resigned = proof_at(&device, "set-pin", &user_id, "enable", b"482913", ts);
        assert_ne!(resigned, observed, "XEdDSA signatures are randomized");
        let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(pin_body(Some("482913"), Some("482913"))), &resigned).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "same signed request, different signature bytes");
        // A proof for one operation does not authorize another ("disable" with an "enable" proof).
        let (status, _) = send_proved(&app, "POST", "/api/e2ee/registration-pin", &token, Some(pin_body(None, Some("482913"))), &pin_proof(&device, &user_id, Some("482913"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(hash().await.unwrap(), stored, "PIN unchanged by any of that");

        // Changing it: device proof AND the current PIN.
        assert_eq!(set(&device, Some("777777"), None).await, StatusCode::FORBIDDEN, "current PIN missing");
        assert_eq!(set(&device, Some("777777"), Some("000000")).await, StatusCode::FORBIDDEN, "wrong current PIN");
        assert_eq!(set(&attacker, Some("777777"), Some("482913")).await, StatusCode::FORBIDDEN, "PIN without a device");
        assert_eq!(set(&device, Some("135790"), Some("482913")).await, StatusCode::OK, "legitimate change");
        assert_ne!(hash().await.unwrap(), stored);

        // A FRESH PIN never shortcuts a reset: right PIN, still only a pending request.
        let reset = |pin: Option<&str>| {
            let mut p = attacker_payload.clone();
            p["force"] = json!(true);
            p["pin"] = json!(pin);
            let (app, token) = (app.clone(), token.clone());
            async move { send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(p)).await }
        };
        let (status, body) = reset(Some("135790")).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device reset pending")));
        // The device vetoes it.
        assert_eq!(cancel_reset(&app, &token, &device, &user_id, &device_id).await, StatusCode::OK);
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert_eq!(listing["devices"].as_array().unwrap().len(), 1);
        assert_eq!(listing["devices"][0]["device_id"], device_id.as_str());

        // Once the PIN has been in place for the full hold period it does waive the hold — with
        // the right PIN only.
        sqlx::query("UPDATE e2ee_accounts SET pin_set_at = pin_set_at - $1 WHERE user_id = $2")
            .bind(super::super::keydir::RESET_DELAY_MS + 1000)
            .bind(&user_id)
            .execute(&db)
            .await
            .unwrap();
        let (status, body) = reset(None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("registration pin required")), "typed, so the app shows the PIN screen");
        assert_eq!(reset(Some("000000")).await.0, StatusCode::FORBIDDEN, "wrong PIN");
        let (status, body) = reset(Some("135790")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert_eq!(listing["devices"].as_array().unwrap().len(), 1, "full reset replaced the device list");
        assert_ne!(listing["devices"][0]["device_id"], device_id.as_str());
        assert!(hash().await.is_none(), "the old lock does not carry over to the new device set");

        // Lockout: five wrong PINs lock further attempts, even with the right one.
        assert_eq!(set(&attacker, Some("246810"), None).await, StatusCode::OK, "(now the sole device)");
        let (_, wrong_payload) = device_payload(1);
        let try_reset = |pin: &str| {
            let mut p = wrong_payload.clone();
            p["force"] = json!(true);
            p["pin"] = json!(pin);
            let (app, token) = (app.clone(), token.clone());
            async move { send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(p)).await.0 }
        };
        for _ in 0..5 {
            assert_eq!(try_reset("111111").await, StatusCode::FORBIDDEN);
        }
        let locked_until: Option<i64> = sqlx::query_scalar("SELECT pin_locked_until FROM profiles WHERE id = $1").bind(&user_id).fetch_one(&db).await.unwrap();
        assert!(locked_until.is_some_and(|t| t > crate::state::now_ms()), "locked out after five wrong PINs");
    }

    /// Completing a held reset claims the pending request atomically: of two racing completions
    /// exactly one wins, and a request that was cancelled after being validated completes nothing.
    #[tokio::test]
    async fn held_reset_completion_is_atomic() {
        let (app, db) = test_app().await;
        let (user_id, token) = signup(&app, "racer").await;
        let (device, payload) = device_payload(1);
        let device_id = register(&app, &token, payload).await;
        let (newcomer, mut reset) = device_payload(1);
        reset["force"] = json!(true);
        let (status, _) = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let expire = || async {
            sqlx::query("UPDATE e2ee_accounts SET reset_requested_at = $1, reset_identity_key = $2 WHERE user_id = $3")
                .bind(crate::state::now_ms() - super::super::keydir::RESET_DELAY_MS - 1000)
                .bind(newcomer.identity_key())
                .bind(&user_id)
                .execute(&db)
                .await
                .unwrap();
        };
        expire().await;

        // Cancelled between "validated" and "completed" (the cancel lands first here): nothing is
        // wiped, and the stale completion is refused rather than acting on what it read earlier.
        let cancel = cancel_reset(&app, &token, &device, &user_id, &device_id);
        let complete = send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset.clone()));
        let (cancel_status, (complete_status, _)) = tokio::join!(cancel, complete);
        assert_eq!(cancel_status, StatusCode::OK);
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        let ids: Vec<&str> = listing["devices"].as_array().unwrap().iter().map(|d| d["device_id"].as_str().unwrap()).collect();
        if complete_status == StatusCode::OK {
            // The completion won the race outright (it claimed the request before the cancel).
            assert_eq!(ids.len(), 1);
            assert_ne!(ids[0], device_id);
            return;
        }
        assert_eq!(ids, [device_id.as_str()], "cancel won: the original device is untouched");

        // Two racing completions of one expired request: exactly one device results.
        expire().await;
        let (a, b) = tokio::join!(
            send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset.clone())),
            send(&app, "POST", "/api/e2ee/devices/register", Some(&token), Some(reset.clone())),
        );
        let wins = [a.0, b.0].iter().filter(|s| **s == StatusCode::OK).count();
        assert_eq!(wins, 1, "{:?} / {:?}", a, b);
        let (_, listing) = send(&app, "GET", "/api/e2ee/devices", Some(&token), None).await;
        assert_eq!(listing["devices"].as_array().unwrap().len(), 1);
        let claimed: Option<i64> = sqlx::query_scalar("SELECT reset_requested_at FROM e2ee_accounts WHERE user_id = $1").bind(&user_id).fetch_one(&db).await.unwrap();
        assert!(claimed.is_none());
    }

    /// Rekey (after a backup restore): same identity + device id, all prekeys replaced, stale
    /// mailbox dropped.
    #[tokio::test]
    async fn rekey_keeps_identity_and_replaces_prekeys() {
        let (app, db) = test_app().await;
        let (bob_id, bob_token) = signup(&app, "bob").await;
        let (alice_id, alice_token) = signup(&app, "alice").await;
        seed_server(&db, &bob_id, &[&bob_id, &alice_id]).await;
        let (bob, payload) = device_payload(2);
        let bob_dev = register(&app, &bob_token, payload).await;
        let (_, before) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
        // Something is queued for the old key material.
        let deposit = json!({ "messages": [{ "user_id": bob_id, "device_id": bob_dev, "delivery_key": before["delivery_key"], "envelope": b64(b"old") }] });
        send(&app, "POST", "/api/e2ee/sealed/send", None, Some(deposit.clone())).await;

        // "Restore": only the identity survives.
        let mut restored = SignalStore::from_bytes(&bob.export_identity()).unwrap();
        let mut body = key_payload(&mut restored, 3);
        body["delivery_key"] = json!(b64(&[9u8; 32]));
        // A rekey needs a device proof over exactly the new keys (a session token is not enough).
        let pubs = |k: &str| -> Vec<Vec<u8>> { body[k].as_array().unwrap().iter().map(|e| unb64(&e["public"])).collect() };
        let (ec, ky) = (pubs("one_time_prekeys"), pubs("one_time_kyber_prekeys"));
        let rekey_payload = skwod_crypto::link::op_payload(&[
            &restored.registration_id().to_be_bytes(),
            &unb64(&body["signed_prekey"]["public"]),
            &unb64(&body["last_resort_kyber_prekey"]["public"]),
            &[9u8; 32],
            &keys_blob(ec.iter().map(Vec::as_slice).collect()),
            &keys_blob(ky.iter().map(Vec::as_slice).collect()),
        ]);
        let rekey_payload = skwod_crypto::link::op_payload(&[&rekey_payload, &install_hash()]);
        let p = proof(&restored, "rekey", &bob_id, &bob_dev, &rekey_payload);
        let (status, resp) = send_proved(&app, "POST", &format!("/api/e2ee/devices/{bob_dev}/rekey"), &bob_token, Some(body), &p).await;
        assert_eq!(status, StatusCode::OK, "{resp}");

        let (_, after) = fetch_bundle(&app, &alice_token, &bob_id, &bob_dev).await;
        assert_eq!(after["identity_key"], before["identity_key"], "identity (and so the safety number) is unchanged");
        assert_ne!(after["signed_prekey"]["id"], before["signed_prekey"]["id"]);
        assert_eq!(unb64(&after["delivery_key"]), [9u8; 32]);
        let (_, counts) = send(&app, "GET", &format!("/api/e2ee/prekeys/count?device_id={bob_dev}"), Some(&bob_token), None).await;
        assert_eq!(counts["remaining"], 2, "3 fresh one-time keys minus the one just served");
        let (_, inbox) = send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={bob_dev}"), Some(&bob_token), None).await;
        assert!(inbox["envelopes"].as_array().unwrap().is_empty(), "mail for the lost keys is dropped");
        // The old delivery key no longer works.
        let (_, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(deposit)).await;
        assert_eq!(body["results"][0]["status"], "gone");
    }

    #[tokio::test]
    async fn sealed_mailbox_bounds_and_device_deletion() {
        let (app, _db) = test_app().await;
        let (user_id, token) = signup(&app, "boxed").await;
        let (store, payload) = device_payload(1);
        let dev = register(&app, &token, payload).await;
        let key = b64(&[7u8; 32]);
        let msg = |envelope: Vec<u8>| json!({ "user_id": user_id, "device_id": dev, "delivery_key": key, "envelope": b64(&envelope) });

        let (status, _) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(json!({ "messages": [] }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(json!({ "messages": [msg(vec![0u8; 256 * 1024 + 1])] }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let many: Vec<Value> = (0..257).map(|_| msg(vec![1])).collect();
        let (status, _) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(json!({ "messages": many }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // A deposit for an unknown device reports "gone" without failing the rest of the batch.
        let batch = json!({ "messages": [
            { "user_id": user_id, "device_id": "nope", "delivery_key": key, "envelope": b64(b"x") },
            msg(b"one".to_vec()), msg(b"two".to_vec()),
        ] });
        let (status, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(batch)).await;
        assert_eq!(status, StatusCode::OK);
        let statuses: Vec<&str> = body["results"].as_array().unwrap().iter().map(|r| r["status"].as_str().unwrap()).collect();
        assert_eq!(statuses, ["gone", "ok", "ok"]);
        // A bearer token on the deposit is ignored, not required and not recorded.
        let (status, _) = send(&app, "POST", "/api/e2ee/sealed/send", Some("garbage-token"), Some(json!({ "messages": [msg(b"three".to_vec())] }))).await;
        assert_eq!(status, StatusCode::OK);

        let (_, inbox) = send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={dev}"), Some(&token), None).await;
        let got: Vec<Vec<u8>> = inbox["envelopes"].as_array().unwrap().iter().map(|e| unb64(&e["envelope"])).collect();
        assert_eq!(got, [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()], "FIFO");
        assert_eq!(inbox["more"], false);

        // Deleting the device (with its own signature) removes its mailbox and prekeys.
        assert_eq!(delete_device(&app, &token, &store, &user_id, &dev).await, StatusCode::OK);
        // ...and ends the session that spoke for it; a new sign-in is told the device is gone.
        let (status, _) = send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={dev}"), Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let again = login(&app, "boxed").await;
        let (status, body) = send(&app, "GET", &format!("/api/e2ee/sealed/inbox?device_id={dev}"), Some(&again), None).await;
        assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("device removed")));
        let (_, body) = send(&app, "POST", "/api/e2ee/sealed/send", None, Some(json!({ "messages": [msg(b"late".to_vec())] }))).await;
        assert_eq!(body["results"][0]["status"], "gone");
    }

    #[tokio::test]
    async fn key_backup_roundtrip_and_writes_need_device_proof() {
        let (app, _db) = test_app().await;
        let (user_id, token) = signup(&app, "backer").await;
        let (device, payload) = device_payload(1);
        register(&app, &token, payload).await;
        let (attacker, _) = device_payload(0);
        let (status, _) = send(&app, "GET", "/api/e2ee/key-backup", Some(&token), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let backup = |blob: &[u8], salt: &[u8]| {
            json!({ "encrypted_blob": b64(blob), "salt": b64(salt), "version": 3, "kdf_params": { "m_kib": 65536, "t": 3, "p": 1 } })
        };
        let backup_proof = |signer: &SignalStore, blob: &[u8], salt: &[u8]| {
            let payload = super::super::keydir::backup_payload(blob, salt, 3, &json!({ "m_kib": 65536, "t": 3, "p": 1 }));
            proof(signer, "backup-put", &user_id, "backup", &payload)
        };
        let salt = b"0123456789abcdef";
        let observed = backup_proof(&device, b"wrapped-master-key", salt);
        let (status, _) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(backup(b"wrapped-master-key", salt)), &observed).await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = send(&app, "GET", "/api/e2ee/key-backup", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(unb64(&body["encrypted_blob"]), b"wrapped-master-key");
        assert_eq!(body["kdf"], "argon2id");
        assert_eq!(body["kdf_params"]["m_kib"], 65536);

        // A session token alone can neither replace nor delete the backup...
        let (status, _) = send(&app, "PUT", "/api/e2ee/key-backup", Some(&token), Some(backup(b"attacker-blob", salt))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(backup(b"attacker-blob", salt)), &backup_proof(&attacker, b"attacker-blob", salt)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // ...not even with a proof captured from the legitimate upload: swapping the blob, the
        // salt or the KDF cost breaks the signature, and replaying it verbatim is refused.
        let (status, _) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(backup(b"attacker-blob", salt)), &observed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "blob swap");
        let (status, _) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(backup(b"wrapped-master-key", b"fedcba9876543210")), &observed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "salt swap");
        let mut weak = backup(b"wrapped-master-key", salt);
        weak["kdf_params"]["m_kib"] = json!(8);
        let (status, _) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(weak), &observed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "KDF downgrade swap");
        let (status, _) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(backup(b"wrapped-master-key", salt)), &observed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "replay");
        let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/key-backup", &token, None, &proof(&attacker, "backup-delete", &user_id, "backup", b"")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/key-backup", &token, None, &observed).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a put proof does not delete");
        let (status, _) = send(&app, "DELETE", "/api/e2ee/key-backup", Some(&token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, body) = send(&app, "GET", "/api/e2ee/key-backup", Some(&token), None).await;
        assert_eq!(unb64(&body["encrypted_blob"]), b"wrapped-master-key", "backup intact");

        // Short salt refused.
        let (status, _) = send_proved(&app, "PUT", "/api/e2ee/key-backup", &token, Some(backup(b"x", b"tiny")), &backup_proof(&device, b"x", b"tiny")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Turning backup off (from the device) deletes the server copy; that proof is single-use too.
        let del = proof(&device, "backup-delete", &user_id, "backup", b"");
        let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/key-backup", &token, None, &del).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "GET", "/api/e2ee/key-backup", Some(&token), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = send_proved(&app, "DELETE", "/api/e2ee/key-backup", &token, None, &del).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "replayed delete");
    }
}

mod structure {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    /// Create a server as `token` and return its id.
    async fn create_server(app: &Router, token: &str) -> String {
        let (status, body) = send(
            app,
            "POST",
            "/api/servers",
            Some(token),
            Some(json!({ "name_ciphertext": b64(b"enc-name") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["server_id"].as_str().unwrap().to_string()
    }

    /// Owner invites; `token` accepts and becomes a member immediately. Uses a multi-use auto-join
    /// invite (kind="username" with no reservation would gate; kind="token" is single-use, so for a
    /// reusable auto-join helper we mint a fresh token per call).
    async fn join(app: &Router, owner_token: &str, server_id: &str, token: &str) {
        let (status, body) = send(
            app,
            "POST",
            &format!("/api/servers/{server_id}/invites"),
            Some(owner_token),
            Some(json!({ "kind": "token" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let code = body["code"].as_str().unwrap();
        let (status, body) = send(app, "POST", &format!("/api/invites/{code}/accept"), Some(token), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("pending").is_none(), "token invite should auto-join: {body}");
    }

    #[tokio::test]
    async fn instance_identity_and_proof_of_possession() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let verify = skwod_crypto::instance::verify;
        let (app, _db) = test_app().await;

        // Identity is public (no auth needed — a client must verify BEFORE sending its token) + stable.
        let (status, id1) = send(&app, "GET", "/api/instance/identity", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let server_public = B64.decode(id1["server_public"].as_str().unwrap()).unwrap();
        assert!(!id1["instance_id"].as_str().unwrap().is_empty());
        let (_, id2) = send(&app, "GET", "/api/instance/identity", None, None).await;
        assert_eq!(id1["instance_id"], id2["instance_id"], "identity is stable");

        // Proof-of-possession: the server signs OUR nonce; it verifies against the pinned public key
        // over the domain-separated message. A spoof server holding only the (public) key can't do this.
        let nonce = b"client-random-nonce-1234";
        let (status, proof) =
            send(&app, "POST", "/api/instance/prove", None, Some(json!({ "nonce": B64.encode(nonce) }))).await;
        assert_eq!(status, StatusCode::OK);
        let sig = B64.decode(proof["signature"].as_str().unwrap()).unwrap();
        let mut msg = b"skwod-instance-proof-v1:".to_vec();
        msg.extend_from_slice(nonce);
        assert!(verify(&server_public, &msg, &sig), "proof verifies against pinned key");
        // A different challenge doesn't verify (no replay), and — crucially — the signature does NOT
        // verify over the BARE nonce, so `/prove` can't be abused as a certificate-forging oracle.
        assert!(!verify(&server_public, b"skwod-instance-proof-v1:other", &sig));
        assert!(!verify(&server_public, nonce, &sig), "domain separation holds");

        // Bad input is rejected.
        let (status, _) = send(&app, "POST", "/api/instance/prove", None, Some(json!({ "nonce": "" }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// H3: the proof of possession must be bound to the address the client dialed. An impostor at
    /// `https://evil.example` relays the victim's challenge to the real server; the real server
    /// must not produce a signature the victim accepts for the impostor's address.
    #[tokio::test]
    async fn instance_proof_is_bound_to_a_served_origin_and_cannot_be_relayed() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use skwod_crypto::instance::{proof_message_v2, verify};
        let mut state = test_state().await;
        state.public_urls = std::sync::Arc::new(vec!["https://Real.Example/".to_string()]);
        let app = api::router(state);
        let (_, id) = send(&app, "GET", "/api/instance/identity", None, None).await;
        let pinned = B64.decode(id["server_public"].as_str().unwrap()).unwrap();
        let nonce = b"victim-nonce";
        let prove = |origin: &str| json!({ "nonce": B64.encode(nonce), "origin": origin });

        // The real address: signed, and the signature covers the origin.
        let (status, ok) = send(&app, "POST", "/api/instance/prove", None, Some(prove("https://real.example"))).await;
        assert_eq!(status, StatusCode::OK);
        let sig = B64.decode(ok["signature"].as_str().unwrap()).unwrap();
        assert!(verify(&pinned, &proof_message_v2(nonce, "https://real.example").unwrap(), &sig));

        // The relay: the impostor forwards the victim's challenge (origin = the address the victim
        // dialed, i.e. the impostor's). Refused — there is no signature to hand back.
        let (status, _) = send(&app, "POST", "/api/instance/prove", None, Some(prove("https://evil.example"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "the real server must not vouch for an address it does not serve");
        // ...and lying about the origin to get one only yields a signature for the REAL address,
        // which fails the victim's check for the address it dialed.
        assert!(!verify(&pinned, &proof_message_v2(nonce, "https://evil.example").unwrap(), &sig));
        // The legacy unbound proof (still answered for build-42 clients) is a different message:
        // it never verifies as an origin-bound proof for any address.
        let (_, v1) = send(&app, "POST", "/api/instance/prove", None, Some(json!({ "nonce": B64.encode(nonce) }))).await;
        let v1sig = B64.decode(v1["signature"].as_str().unwrap()).unwrap();
        for origin in ["https://evil.example", "https://real.example", ""] {
            assert!(!verify(&pinned, &proof_message_v2(nonce, origin).unwrap(), &v1sig));
        }
        let (status, _) = send(&app, "POST", "/api/instance/prove", None, Some(prove("http://127.0.0.1.evil.example"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// A loopback origin is signed only for a client on this machine talking to the server
    /// directly. Behind a reverse proxy every request has no p2p peer, so "no p2p peer" must not
    /// be enough: an attacker's relay claiming `http://127.0.0.1:…` would get a valid signature.
    #[tokio::test]
    async fn loopback_origin_proof_needs_a_direct_loopback_peer() {
        use axum::extract::ConnectInfo;
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use std::net::SocketAddr;
        use tower::ServiceExt;
        let (app, _db) = test_app().await;
        let prove = |peer: Option<&str>, header: Option<(&str, &str)>, p2p: bool, origin: &str| {
            let app = app.clone();
            let mut req = Request::builder().method("POST").uri("/api/instance/prove").header(header::CONTENT_TYPE, "application/json");
            if let Some((k, v)) = header {
                req = req.header(k, v);
            }
            let mut req = req.body(Body::from(json!({ "nonce": B64.encode(b"n"), "origin": origin }).to_string())).unwrap();
            if let Some(peer) = peer {
                req.extensions_mut().insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
            }
            if p2p {
                req.extensions_mut().insert(crate::client_key::P2pPeer { node: "nodeA".into(), node_bytes: [5; 32], relayed: false });
            }
            async move { app.oneshot(req).await.unwrap().status() }
        };
        let lo = "http://127.0.0.1:3000";
        // The host's own app on this machine: direct loopback socket, no proxy hop.
        assert_eq!(prove(Some("127.0.0.1:50000"), None, false, lo).await, StatusCode::OK);
        assert_eq!(prove(Some("[::1]:50000"), None, false, "http://localhost:3000").await, StatusCode::OK);
        // Via a "proxy": the socket peer is not loopback (a proxy container / another host).
        assert_eq!(prove(Some("172.31.250.2:40000"), None, false, lo).await, StatusCode::FORBIDDEN);
        assert_eq!(prove(Some("203.0.113.9:40000"), None, false, lo).await, StatusCode::FORBIDDEN);
        // Via a proxy ON this host: loopback socket, but the request was forwarded.
        for h in [("x-forwarded-for", "203.0.113.9"), ("forwarded", "for=203.0.113.9"), ("x-real-ip", "203.0.113.9"), ("via", "1.1 caddy")] {
            assert_eq!(prove(Some("127.0.0.1:50000"), Some(h), false, lo).await, StatusCode::FORBIDDEN, "{h:?}");
        }
        // Unknown socket peer, or a request that arrived over p2p: never.
        assert_eq!(prove(None, None, false, lo).await, StatusCode::FORBIDDEN);
        assert_eq!(prove(Some("127.0.0.1:50000"), None, true, lo).await, StatusCode::FORBIDDEN);
    }

    /// A dev setup may list an exact loopback origin in `SKWOD_PUBLIC_URL`; then it is served.
    #[tokio::test]
    async fn listed_loopback_origin_is_served() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let mut state = test_state().await;
        state.public_urls = std::sync::Arc::new(vec!["http://127.0.0.1:3000".to_string()]);
        let app = api::router(state);
        let body = |o: &str| json!({ "nonce": B64.encode(b"n"), "origin": o });
        let (status, _) = send(&app, "POST", "/api/instance/prove", None, Some(body("http://127.0.0.1:3000"))).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "POST", "/api/instance/prove", None, Some(body("http://127.0.0.1:3001"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // A loopback entry is never advertised as the instance's public address.
        let (status, _) = send(&app, "GET", "/api/instance/address-record", None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// The address record is signed by the instance key, names the configured public address, and
    /// its timestamp only moves (forward) when the address changes.
    #[tokio::test]
    async fn address_record_is_signed_and_monotonic() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        let mut state = test_state().await;
        let app = api::router(state.clone());
        let (status, _) = send(&app, "GET", "/api/instance/address-record", None, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "no public address configured");

        state.public_urls = std::sync::Arc::new(vec!["https://old.example".to_string()]);
        let app = api::router(state.clone());
        let (_, id) = send(&app, "GET", "/api/instance/identity", None, None).await;
        let pinned = B64.decode(id["server_public"].as_str().unwrap()).unwrap();
        let (status, r1) = send(&app, "GET", "/api/instance/address-record", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let check = |r: &Value| {
            skwod_crypto::instance::verify_address_record(
                &pinned,
                r["address"].as_str().unwrap(),
                r["ts"].as_i64().unwrap(),
                &B64.decode(r["signature"].as_str().unwrap()).unwrap(),
            )
        };
        assert_eq!(r1["address"], "https://old.example");
        assert!(check(&r1));
        let (_, again) = send(&app, "GET", "/api/instance/address-record", None, None).await;
        assert_eq!(again["ts"], r1["ts"], "same address, same record");

        state.public_urls = std::sync::Arc::new(vec!["https://new.example".to_string()]);
        let app = api::router(state);
        let (_, r2) = send(&app, "GET", "/api/instance/address-record", None, None).await;
        assert_eq!(r2["address"], "https://new.example");
        assert!(check(&r2) && r2["ts"].as_i64() > r1["ts"].as_i64());
        // A record cannot be re-pointed: the signature covers the address and the time.
        let sig = B64.decode(r2["signature"].as_str().unwrap()).unwrap();
        assert!(!skwod_crypto::instance::verify_address_record(&pinned, "https://evil.example", r2["ts"].as_i64().unwrap(), &sig));
    }

    #[tokio::test]
    async fn server_creation_is_host_only_and_grantable() {
        let (app, db) = test_app().await;
        let (owner_id, owner) = signup(&app, "host").await;
        let (member_id, member) = signup(&app, "member").await;
        let name = json!({ "name_ciphertext": b64(b"enc-name") });

        // Un-bootstrapped instance: creation is open (dev/self-host-before-init behaviour).
        let (status, _) = send(&app, "POST", "/api/servers", Some(&member), Some(name.clone())).await;
        assert_eq!(status, StatusCode::OK, "open instance allows creation");

        // Claim instance ownership for `host` — now the gate is live.
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('owner_user_id', $1, $2)")
            .bind(owner_id.as_bytes())
            .bind(crate::state::now_ms())
            .execute(&db)
            .await
            .unwrap();

        // Host can create; a plain member cannot.
        let (status, _) = send(&app, "POST", "/api/servers", Some(&owner), Some(name.clone())).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "POST", "/api/servers", Some(&member), Some(name.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, body) = send(&app, "GET", "/api/instance/can-create-servers", Some(&member), None).await;
        assert_eq!(body["can_create"], false);
        assert_eq!(body["is_owner"], false);

        // A non-owner can't hand out the grant.
        let (status, _) = send(&app, "PUT", &format!("/api/instance/server-creators/{member_id}"), Some(&member), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Host grants the member → member can now create; revoke → forbidden again.
        let (status, _) = send(&app, "PUT", &format!("/api/instance/server-creators/{member_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "POST", "/api/servers", Some(&member), Some(name.clone())).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "DELETE", &format!("/api/instance/server-creators/{member_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "POST", "/api/servers", Some(&member), Some(name)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn owner_creates_and_member_joins_via_invite() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "owner1").await;
        let (_, member) = signup(&app, "member1").await;
        let server_id = create_server(&app, &owner).await;

        // Non-member sees nothing.
        let (status, _) = send(&app, "GET", &format!("/api/servers/{server_id}/channels"), Some(&member), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        join(&app, &owner, &server_id, &member).await;
        let (status, body) = send(&app, "GET", "/api/servers", Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["servers"].as_array().unwrap().len(), 1);

        // Accepting the same invite again is a no-op.
        let (status, body) = send(&app, "GET", &format!("/api/servers/{server_id}/members"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["members"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn permissions_gate_channel_and_role_management() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "owner2").await;
        let (member_id, member) = signup(&app, "member2").await;
        let server_id = create_server(&app, &owner).await;
        join(&app, &owner, &server_id, &member).await;

        // Default role lacks MANAGE_CHANNELS.
        let make_channel = json!({ "name_ciphertext": b64(b"enc-general") });
        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&member), Some(make_channel.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Owner grants a moderator role with MANAGE_CHANNELS (bit 1).
        let (status, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/roles"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"enc-mod"), "permissions": 1 })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let role_id = body["role_id"].as_str().unwrap().to_string();
        let (status, _) = send(
            &app,
            "PUT",
            &format!("/api/servers/{server_id}/members/{member_id}/roles/{role_id}"),
            Some(&owner),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Now the member can create the channel.
        let (status, body) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&member), Some(make_channel)).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // But still cannot manage roles.
        let (status, _) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/roles"),
            Some(&member),
            Some(json!({ "name_ciphertext": b64(b"enc-x"), "permissions": 1 })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Unknown permission bits are rejected.
        let (status, _) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/roles"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"enc-x"), "permissions": 1 << 20 })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let _ = body;
    }

    #[tokio::test]
    async fn owner_protections_hold() {
        let (app, _db) = test_app().await;
        let (owner_id, owner) = signup(&app, "owner3").await;
        let (_, admin) = signup(&app, "admin3").await;
        let (admin_id, _) = {
            let (_, body) = send(&app, "GET", "/api/auth/me", Some(&admin), None).await;
            (body["user_id"].as_str().unwrap().to_string(), ())
        };
        let server_id = create_server(&app, &owner).await;
        join(&app, &owner, &server_id, &admin).await;

        // Give the second user ADMINISTRATOR (8192).
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/roles"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"enc-admin"), "permissions": 8192 })),
        )
        .await;
        let role_id = body["role_id"].as_str().unwrap().to_string();
        send(&app, "PUT", &format!("/api/servers/{server_id}/members/{admin_id}/roles/{role_id}"), Some(&owner), None).await;

        // Even an administrator cannot kick the owner or delete the server.
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{owner_id}"), Some(&admin), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}"), Some(&admin), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The owner can delete it.
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = send(&app, "GET", "/api/servers", Some(&owner), None).await;
        assert_eq!(body["servers"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn kick_and_leave() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "owner4").await;
        let (member_id, member) = signup(&app, "member4").await;
        let server_id = create_server(&app, &owner).await;
        join(&app, &owner, &server_id, &member).await;

        // A plain member can't kick others but can leave (kick self).
        let (owner_id, _) = {
            let (_, body) = send(&app, "GET", "/api/auth/me", Some(&owner), None).await;
            (body["user_id"].as_str().unwrap().to_string(), ())
        };
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{owner_id}"), Some(&member), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{member_id}"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = send(&app, "GET", &format!("/api/servers/{server_id}/members"), Some(&owner), None).await;
        assert_eq!(body["members"].as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invite_expiry_max_uses_and_revocation() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "owner5").await;
        let server_id = create_server(&app, &owner).await;

        // Expired invite (auto-join kind so the only failure is expiry).
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/invites"),
            Some(&owner),
            Some(json!({ "kind": "token", "expires_at": 1000 })),
        )
        .await;
        let expired_code = body["code"].as_str().unwrap().to_string();
        let (_, u1) = signup(&app, "user5a").await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{expired_code}/accept"), Some(&u1), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Single-use auto-join invite: first accept wins, second is refused.
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/invites"),
            Some(&owner),
            Some(json!({ "kind": "token", "max_uses": 1 })),
        )
        .await;
        let single = body["code"].as_str().unwrap().to_string();
        let (status, _) = send(&app, "POST", &format!("/api/invites/{single}/accept"), Some(&u1), None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, u2) = signup(&app, "user5b").await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{single}/accept"), Some(&u2), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Revoked invite.
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let revoked = body["code"].as_str().unwrap().to_string();
        let (status, _) = send(&app, "DELETE", &format!("/api/invites/{revoked}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "POST", &format!("/api/invites/{revoked}/accept"), Some(&u2), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn channel_overrides_shape_effective_permissions() {
        let (app, db) = test_app().await;
        let (_, owner) = signup(&app, "owner6").await;
        let (member_id, member) = signup(&app, "member6").await;
        let server_id = create_server(&app, &owner).await;
        join(&app, &owner, &server_id, &member).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"enc-secret") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();

        // Deny SEND_MESSAGES (64) for this member in this channel.
        let (status, _) = send(
            &app,
            "PUT",
            &format!("/api/channels/{channel_id}/overrides"),
            Some(&owner),
            Some(json!({ "user_id": member_id, "allow": 0, "deny": 64 })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let state = crate::state::AppState::new(db.clone(), std::env::temp_dir());
        let p = crate::structure::effective_permissions(&state, &server_id, &member_id, Some(&channel_id)).await.unwrap();
        assert!(!crate::perms::has_permission(p, crate::perms::SEND_MESSAGES));
        assert!(crate::perms::has_permission(p, crate::perms::READ_MESSAGES));
        // Elsewhere (no channel context) the default role still allows sending.
        let p = crate::structure::effective_permissions(&state, &server_id, &member_id, None).await.unwrap();
        assert!(crate::perms::has_permission(p, crate::perms::SEND_MESSAGES));
    }
}

mod messages {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    /// owner + member in one server with one channel; returns (owner_tok, member_tok, channel_id, server_id).
    async fn chat_world(app: &Router) -> (String, String, String, String) {
        let (_, owner) = signup(app, "chatowner").await;
        let (_, member) = signup(app, "chatmember").await;
        let (status, body) =
            send(app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        assert_eq!(status, StatusCode::OK);
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) =
            send(app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        let (_, body) = send(
            app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"general") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();
        (owner, member, channel_id, server_id)
    }

    #[tokio::test]
    async fn send_list_edit_delete_roundtrip() {
        let (app, _db) = test_app().await;
        let (owner, member, channel_id, _) = chat_world(&app).await;

        // Member sends an opaque envelope.
        let (status, body) = send(
            &app,
            "POST",
            &format!("/api/channels/{channel_id}/messages"),
            Some(&member),
            Some(json!({ "ciphertext": b64(b"envelope-1") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let msg_id = body["message_id"].as_str().unwrap().to_string();

        // Owner reads it back, ciphertext intact.
        let (status, body) = send(&app, "GET", &format!("/api/channels/{channel_id}/messages"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(B64.decode(msgs[0]["ciphertext"].as_str().unwrap()).unwrap(), b"envelope-1");

        // Only the author can edit; even the owner (MANAGE_MESSAGES) cannot.
        let edit = json!({ "ciphertext": b64(b"envelope-1-edited") });
        let (status, _) = send(&app, "PATCH", &format!("/api/messages/{msg_id}"), Some(&owner), Some(edit.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "PATCH", &format!("/api/messages/{msg_id}"), Some(&member), Some(edit)).await;
        assert_eq!(status, StatusCode::OK);

        // Moderator delete tombstones: row remains, ciphertext blanked.
        let (status, _) = send(&app, "DELETE", &format!("/api/messages/{msg_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = send(&app, "GET", &format!("/api/channels/{channel_id}/messages"), Some(&owner), None).await;
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0]["deleted_at"].is_i64());
        assert_eq!(msgs[0]["ciphertext"], "");
    }

    #[tokio::test]
    async fn permissions_gate_sending_and_reading() {
        let (app, db) = test_app().await;
        let (owner, member, channel_id, _server_id) = chat_world(&app).await;
        let (_, body) = send(&app, "GET", "/api/auth/me", Some(&member), None).await;
        let member_id = body["user_id"].as_str().unwrap().to_string();

        // Deny SEND in this channel for the member → 403 on send, read still fine.
        let (status, _) = send(
            &app,
            "PUT",
            &format!("/api/channels/{channel_id}/overrides"),
            Some(&owner),
            Some(json!({ "user_id": member_id, "allow": 0, "deny": 64 })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(
            &app,
            "POST",
            &format!("/api/channels/{channel_id}/messages"),
            Some(&member),
            Some(json!({ "ciphertext": b64(b"x") })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "GET", &format!("/api/channels/{channel_id}/messages"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);

        // A total outsider gets 403 on both.
        let (_, outsider) = signup(&app, "chatoutsider").await;
        let (status, _) = send(&app, "GET", &format!("/api/channels/{channel_id}/messages"), Some(&outsider), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let _ = db;
    }

    #[tokio::test]
    async fn pagination_backfills_in_order() {
        let (app, _db) = test_app().await;
        let (owner, _, channel_id, _) = chat_world(&app).await;
        for i in 0..7 {
            let (_, body) = send(
                &app,
                "POST",
                &format!("/api/channels/{channel_id}/messages"),
                Some(&owner),
                Some(json!({ "ciphertext": b64(format!("m{i}").as_bytes()) })),
            )
            .await;
            assert!(body["message_id"].is_string());
            // Distinct created_at per message (ms clock) isn't guaranteed in a tight loop;
            // the (created_at, id) tiebreaker keeps ordering stable regardless.
        }
        let (_, body) =
            send(&app, "GET", &format!("/api/channels/{channel_id}/messages?limit=5"), Some(&owner), None).await;
        let first_page = body["messages"].as_array().unwrap();
        assert_eq!(first_page.len(), 5);
        let oldest_ts = first_page.last().unwrap()["created_at"].as_i64().unwrap();
        let (_, body) = send(
            &app,
            "GET",
            &format!("/api/channels/{channel_id}/messages?limit=5&before={oldest_ts}"),
            Some(&owner),
            None,
        )
        .await;
        let second_page = body["messages"].as_array().unwrap();
        assert!(second_page.len() <= 2, "only the remaining older messages");
    }

    #[tokio::test]
    async fn reactions_unique_by_hash_and_pins_gated() {
        let (app, _db) = test_app().await;
        let (owner, member, channel_id, _) = chat_world(&app).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/channels/{channel_id}/messages"),
            Some(&owner),
            Some(json!({ "ciphertext": b64(b"react-me") })),
        )
        .await;
        let msg_id = body["message_id"].as_str().unwrap().to_string();

        let react = json!({ "emoji_ciphertext": b64(b"enc-emoji"), "emoji_hash": "h1" });
        let (status, body) = send(&app, "POST", &format!("/api/messages/{msg_id}/reactions"), Some(&member), Some(react.clone())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["already_reacted"].is_null());
        let (_, body) = send(&app, "POST", &format!("/api/messages/{msg_id}/reactions"), Some(&member), Some(react)).await;
        assert_eq!(body["already_reacted"], true);
        let (status, _) = send(&app, "DELETE", &format!("/api/messages/{msg_id}/reactions/h1"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);

        // Pin requires MANAGE_MESSAGES: member no, owner yes.
        let (status, _) = send(&app, "PUT", &format!("/api/messages/{msg_id}/pin"), Some(&member), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "PUT", &format!("/api/messages/{msg_id}/pin"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = send(&app, "GET", &format!("/api/channels/{channel_id}/messages"), Some(&owner), None).await;
        assert_eq!(body["messages"][0]["is_pinned"], true);
    }

    #[tokio::test]
    async fn dm_lifecycle_and_isolation() {
        let (app, db) = test_app().await;
        let (alice_id, alice) = signup(&app, "dmalice").await;
        let (bob_id, bob) = signup(&app, "dmbob").await;
        let (mallory_id, mallory) = signup(&app, "dmmallory").await;
        share_server(&db, &[&alice_id, &bob_id, &mallory_id]).await;

        let (status, body) =
            send(&app, "POST", "/api/dms", Some(&alice), Some(json!({ "participant_ids": [bob_id] }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let convo = body["conversation_id"].as_str().unwrap().to_string();

        // Same pair again → same conversation.
        let (_, body) = send(&app, "POST", "/api/dms", Some(&bob), Some(json!({ "participant_ids": [alice_id] }))).await;
        assert_eq!(body["conversation_id"].as_str().unwrap(), convo);
        assert_eq!(body["existing"], true);

        // Alice sends; Bob reads; Mallory can do neither.
        let (status, body) = send(
            &app,
            "POST",
            &format!("/api/dms/{convo}/messages"),
            Some(&alice),
            Some(json!({ "ciphertext": b64(b"dm-envelope") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let dm_msg = body["message_id"].as_str().unwrap().to_string();
        let (status, body) = send(&app, "GET", &format!("/api/dms/{convo}/messages"), Some(&bob), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
        let (status, _) = send(&app, "GET", &format!("/api/dms/{convo}/messages"), Some(&mallory), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(
            &app,
            "POST",
            &format!("/api/dms/{convo}/messages"),
            Some(&mallory),
            Some(json!({ "ciphertext": b64(b"intrusion") })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Bob can't delete Alice's DM message; Alice can.
        let (status, _) = send(&app, "DELETE", &format!("/api/dm-messages/{dm_msg}"), Some(&bob), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "DELETE", &format!("/api/dm-messages/{dm_msg}"), Some(&alice), None).await;
        assert_eq!(status, StatusCode::OK);

        // Group DM has is_group set.
        let (mallory_id, _) = {
            let (_, body) = send(&app, "GET", "/api/auth/me", Some(&mallory), None).await;
            (body["user_id"].as_str().unwrap().to_string(), ())
        };
        let (_, body) = send(
            &app,
            "POST",
            "/api/dms",
            Some(&alice),
            Some(json!({ "participant_ids": [bob_id, mallory_id] })),
        )
        .await;
        assert!(body["conversation_id"].is_string());
        let (_, body) = send(&app, "GET", "/api/dms", Some(&alice), None).await;
        let convos = body["conversations"].as_array().unwrap();
        assert_eq!(convos.len(), 2);
        assert!(convos.iter().any(|c| c["is_group"] == true));
    }

    #[tokio::test]
    async fn read_state_upserts() {
        let (app, _db) = test_app().await;
        let (owner, _, channel_id, _) = chat_world(&app).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/channels/{channel_id}/messages"),
            Some(&owner),
            Some(json!({ "ciphertext": b64(b"m") })),
        )
        .await;
        let msg_id = body["message_id"].as_str().unwrap().to_string();
        for _ in 0..2 {
            let (status, _) = send(
                &app,
                "PUT",
                &format!("/api/read-states/{channel_id}"),
                Some(&owner),
                Some(json!({ "last_read_message_id": msg_id, "mention_count": 0 })),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
    }
}

mod ws {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use futures_util::{SinkExt, StreamExt};
    use std::time::Duration;
    use tokio_tungstenite::tungstenite::Message as WsMessage;
    use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

    type WsClient = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    /// Serve the app on an ephemeral port; REST keeps going through `send()` on the same
    /// Router clone (shared AppState → shared realtime hub).
    async fn ws_world() -> (Router, String) {
        let (app, _db) = test_app().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = app.clone();
        tokio::spawn(async move {
            axum::serve(listener, served).await.unwrap();
        });
        (app, format!("ws://{addr}/api/ws"))
    }

    async fn connect(url: &str, token: &str) -> WsClient {
        let (client, _) = connect_async(format!("{url}?token={token}")).await.expect("ws connect");
        client
    }

    async fn send_frame(ws: &mut WsClient, v: Value) {
        ws.send(WsMessage::Text(v.to_string())).await.unwrap();
    }

    async fn recv_frame(ws: &mut WsClient) -> Value {
        // (Control frames are skipped: a message event is followed by the delivery-ack Ping.)
        loop {
            let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("frame within 5s")
                .expect("stream open")
                .expect("frame ok");
            if msg.is_text() {
                return serde_json::from_str(msg.to_text().unwrap()).unwrap();
            }
        }
    }

    #[tokio::test]
    async fn rejects_bad_or_missing_token() {
        let (_app, url) = ws_world().await;
        assert!(connect_async(&url).await.is_err(), "no token");
        assert!(connect_async(format!("{url}?token=bogus")).await.is_err(), "bad token");
    }

    #[tokio::test]
    async fn channel_message_fan_out_with_authorization() {
        let (app, url) = ws_world().await;
        let (_, owner) = signup(&app, "wsowner").await;
        let (_, member) = signup(&app, "wsmember").await;
        let (_, outsider) = signup(&app, "wsoutsider").await;
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"c") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();
        let topic = format!("channel:{channel_id}");

        // Member may subscribe; outsider is refused.
        let mut member_ws = connect(&url, &member).await;
        send_frame(&mut member_ws, json!({ "type": "subscribe", "topic": topic })).await;
        assert_eq!(recv_frame(&mut member_ws).await["type"], "subscribed");
        let mut outsider_ws = connect(&url, &outsider).await;
        send_frame(&mut outsider_ws, json!({ "type": "subscribe", "topic": topic })).await;
        assert_eq!(recv_frame(&mut outsider_ws).await["type"], "error");

        // REST send → member's socket gets the envelope.
        let (status, _) = send(
            &app,
            "POST",
            &format!("/api/channels/{channel_id}/messages"),
            Some(&owner),
            Some(json!({ "ciphertext": b64(b"live-envelope") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let ev = recv_frame(&mut member_ws).await;
        assert_eq!(ev["type"], "event");
        assert_eq!(ev["event"], "message");
        assert_eq!(ev["topic"], topic.as_str());
        assert_eq!(B64.decode(ev["payload"]["ciphertext"].as_str().unwrap()).unwrap(), b"live-envelope");
    }

    #[tokio::test]
    async fn typing_and_presence_relay() {
        let (app, url) = ws_world().await;
        let (owner_id, owner) = signup(&app, "wstyper").await;
        let (_, peer) = signup(&app, "wspeer").await;
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&peer), None).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"c") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();
        let channel = format!("channel:{channel_id}");
        let server = format!("server:{server_id}");

        let mut a = connect(&url, &owner).await;
        let mut b = connect(&url, &peer).await;
        for (ws, topics) in [(&mut a, vec![&channel, &server]), (&mut b, vec![&channel, &server])] {
            for t in topics {
                send_frame(ws, json!({ "type": "subscribe", "topic": t })).await;
                assert_eq!(recv_frame(ws).await["type"], "subscribed");
            }
        }

        // Typing from A reaches B.
        send_frame(&mut a, json!({ "type": "typing", "topic": channel })).await;
        let ev = recv_frame(&mut b).await;
        assert_eq!(ev["event"], "typing");
        assert_eq!(ev["payload"]["user_id"], owner_id.as_str());

        // Presence updates the profile and reaches server-topic subscribers.
        send_frame(&mut a, json!({ "type": "presence", "status": "idle" })).await;
        let ev = recv_frame(&mut b).await;
        assert_eq!(ev["event"], "presence");
        assert_eq!(ev["payload"]["status"], "idle");

        // Ping/pong sanity.
        send_frame(&mut a, json!({ "type": "ping" })).await;
        // A also received its own typing/presence events (it subscribed to both topics) — drain
        // until pong to avoid ordering assumptions.
        for _ in 0..5 {
            let f = recv_frame(&mut a).await;
            if f["type"] == "pong" {
                return;
            }
        }
        panic!("no pong received");
    }

    #[tokio::test]
    async fn dm_events_reach_participants_only() {
        let (app, url) = ws_world().await;
        let (_, alice) = signup(&app, "wsdalice").await;
        let (bob_id, bob) = signup(&app, "wsdbob").await;
        let (_, eve) = signup(&app, "wsdeve").await;
        // A conversation needs a server in common (audit H1): Bob joins Alice's.
        let (_, server) = send(&app, "POST", "/api/servers", Some(&alice), Some(json!({ "name_ciphertext": B64.encode(b"s") }))).await;
        let (_, invite) = send(&app, "POST", &format!("/api/servers/{}/invites", server["server_id"].as_str().unwrap()), Some(&alice), Some(json!({ "kind": "token" }))).await;
        assert_eq!(send(&app, "POST", &format!("/api/invites/{}/accept", invite["code"].as_str().unwrap()), Some(&bob), None).await.0, StatusCode::OK);
        let (_, body) = send(&app, "POST", "/api/dms", Some(&alice), Some(json!({ "participant_ids": [bob_id] }))).await;
        let convo = body["conversation_id"].as_str().unwrap().to_string();
        let topic = format!("dm:{convo}");

        let mut bob_ws = connect(&url, &bob).await;
        send_frame(&mut bob_ws, json!({ "type": "subscribe", "topic": topic })).await;
        assert_eq!(recv_frame(&mut bob_ws).await["type"], "subscribed");
        let mut eve_ws = connect(&url, &eve).await;
        send_frame(&mut eve_ws, json!({ "type": "subscribe", "topic": topic })).await;
        assert_eq!(recv_frame(&mut eve_ws).await["type"], "error");

        send(&app, "POST", &format!("/api/dms/{convo}/messages"), Some(&alice), Some(json!({ "ciphertext": b64(b"dm-live") }))).await;
        let ev = recv_frame(&mut bob_ws).await;
        assert_eq!(ev["event"], "message");
        assert_eq!(B64.decode(ev["payload"]["ciphertext"].as_str().unwrap()).unwrap(), b"dm-live");
    }

    /// Drain frames for `ms`, failing on any relay event. Returns the non-event frames seen.
    async fn assert_no_event(ws: &mut WsClient, ms: u64) -> Vec<Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        let mut frames = Vec::new();
        while let Ok(Some(Ok(msg))) = tokio::time::timeout_at(deadline, ws.next()).await {
            let Ok(text) = msg.to_text() else { continue };
            let v: Value = serde_json::from_str(text).unwrap();
            assert_ne!(v["type"], "event", "removed member received an event: {v}");
            frames.push(v);
        }
        frames
    }

    /// Next relay event on `ws`, skipping control frames.
    async fn next_event(ws: &mut WsClient) -> Value {
        loop {
            let f = recv_frame(ws).await;
            if f["type"] == "event" {
                return f;
            }
        }
    }

    async fn subscribe_ok(ws: &mut WsClient, topic: &str) {
        send_frame(ws, json!({ "type": "subscribe", "topic": topic })).await;
        assert_eq!(recv_frame(ws).await["type"], "subscribed", "subscribe {topic}");
    }

    struct RemovalWorld {
        app: Router,
        url: String,
        owner: String,
        member_id: String,
        member: String,
        server_id: String,
        channel_id: String,
        member_ws: WsClient,
        peer_ws: WsClient,
    }

    /// Owner + member + peer in one server/channel; member and peer hold live sockets subscribed to
    /// the channel and server topics.
    async fn removal_world(tag: &str) -> RemovalWorld {
        let (app, url) = ws_world().await;
        let (_, owner) = signup(&app, &format!("{tag}owner")).await;
        let (member_id, member) = signup(&app, &format!("{tag}member")).await;
        let (_, peer) = signup(&app, &format!("{tag}peer")).await;
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        for t in [&member, &peer] {
            let (_, body) =
                send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
            let code = body["code"].as_str().unwrap();
            let (status, _) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(t), None).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"c") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();
        let mut member_ws = connect(&url, &member).await;
        let mut peer_ws = connect(&url, &peer).await;
        for ws in [&mut member_ws, &mut peer_ws] {
            subscribe_ok(ws, &format!("channel:{channel_id}")).await;
            subscribe_ok(ws, &format!("server:{server_id}")).await;
        }
        RemovalWorld { app, url, owner, member_id, member, server_id, channel_id, member_ws, peer_ws }
    }

    /// After a removal: the member's open socket gets no further channel/server events or typing
    /// relay and is told the channel topic was revoked; the peer keeps receiving; a reconnect cannot
    /// re-subscribe to the channel (nor the server topic when `expect_server_cut`).
    /// With `typing_first`, the removed member signals typing before any channel event could evict
    /// the cached topic, so the typing re-check (not the delivery re-check) must refuse it.
    async fn assert_member_cut_off(w: &mut RemovalWorld, expect_server_cut: bool, typing_first: bool) {
        let channel = format!("channel:{}", w.channel_id);
        if typing_first {
            // The peer's next channel event below must be the message, not this typing relay.
            send_frame(&mut w.member_ws, json!({ "type": "typing", "topic": channel })).await;
        }
        let (status, _) = send(
            &w.app,
            "POST",
            &format!("/api/channels/{}/messages", w.channel_id),
            Some(&w.owner),
            Some(json!({ "ciphertext": b64(b"after-removal") })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Unaffected peer still gets the live message (skipping server-topic events such as
        // member_removed, but never a typing relay from the removed member).
        loop {
            let ev = next_event(&mut w.peer_ws).await;
            if ev["topic"] == channel.as_str() {
                assert_eq!(ev["event"], "message", "peer saw {ev}");
                assert_eq!(B64.decode(ev["payload"]["ciphertext"].as_str().unwrap()).unwrap(), b"after-removal");
                break;
            }
        }
        let frames = assert_no_event(&mut w.member_ws, 400).await;
        assert!(
            frames.iter().any(|f| f["type"] == "unsubscribed" && f["topic"] == channel.as_str() && f["reason"] == "revoked"),
            "member should be told the channel topic was revoked: {frames:?}"
        );
        // A fresh socket cannot re-subscribe.
        let mut again = connect(&w.url, &w.member).await;
        send_frame(&mut again, json!({ "type": "subscribe", "topic": channel })).await;
        assert_eq!(recv_frame(&mut again).await["type"], "error");
        if expect_server_cut {
            send_frame(&mut again, json!({ "type": "subscribe", "topic": format!("server:{}", w.server_id) })).await;
            assert_eq!(recv_frame(&mut again).await["type"], "error");
        }
    }

    #[tokio::test]
    async fn kicked_member_socket_stops_receiving() {
        let mut w = removal_world("wskick").await;
        let (status, _) =
            send(&w.app, "DELETE", &format!("/api/servers/{}/members/{}", w.server_id, w.member_id), Some(&w.owner), None).await;
        assert_eq!(status, StatusCode::OK);
        // The peer is told about the removal (the sender-key rotation signal).
        let ev = next_event(&mut w.peer_ws).await;
        assert_eq!(ev["event"], "member_removed");
        assert_eq!(ev["payload"]["user_id"], w.member_id.as_str());
        assert_member_cut_off(&mut w, true, false).await;
    }

    #[tokio::test]
    async fn banned_member_socket_stops_receiving() {
        let mut w = removal_world("wsban").await;
        let (status, _) = send(
            &w.app,
            "POST",
            &format!("/api/servers/{}/bans/{}", w.server_id, w.member_id),
            Some(&w.owner),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let ev = next_event(&mut w.peer_ws).await;
        assert_eq!(ev["event"], "member_removed");
        assert_member_cut_off(&mut w, true, false).await;
    }

    #[tokio::test]
    async fn member_who_left_stops_receiving() {
        let mut w = removal_world("wsleave").await;
        let member = w.member.clone();
        let (status, _) =
            send(&w.app, "DELETE", &format!("/api/servers/{}/members/{}", w.server_id, w.member_id), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_member_cut_off(&mut w, true, true).await;
    }

    #[tokio::test]
    async fn read_permission_override_revokes_live_channel_subscription() {
        let mut w = removal_world("wsdeny").await;
        // Deny READ_MESSAGES (128) for the member in this channel; they stay a server member.
        let (status, _) = send(
            &w.app,
            "PUT",
            &format!("/api/channels/{}/overrides", w.channel_id),
            Some(&w.owner),
            Some(json!({ "user_id": w.member_id, "allow": 0, "deny": 128 })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_member_cut_off(&mut w, false, false).await;
        // Still a server member: server-topic events keep flowing to the original socket.
        let mut peer_presence = connect(&w.url, &w.owner).await;
        send_frame(&mut peer_presence, json!({ "type": "presence", "status": "idle" })).await;
        let ev = next_event(&mut w.member_ws).await;
        assert_eq!(ev["event"], "presence");
        assert_eq!(ev["topic"], format!("server:{}", w.server_id).as_str());
    }

    /// A device woken by a push connects AFTER the one-shot `ring` event: subscribing to its own
    /// topic replays the call that is still ringing.
    #[tokio::test]
    async fn a_late_socket_gets_the_active_ring_on_subscribe() {
        let (app, url) = ws_world().await;
        let (_, owner) = signup(&app, "ringowner").await;
        let (member_id, member) = signup(&app, "ringmember").await;
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        send(&app, "POST", &format!("/api/invites/{}/accept", body["code"].as_str().unwrap()), Some(&member), None).await;
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&owner), Some(json!({ "name_ciphertext": b64(b"v"), "type": "voice" }))).await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();

        // The member is offline when the owner rings.
        let (status, rang) = send(&app, "POST", &format!("/api/channels/{channel_id}/ring"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK, "{rang}");

        // …then wakes up, connects and subscribes to its own topic.
        let mut ws = connect(&url, &member).await;
        let topic = format!("user:{member_id}");
        send_frame(&mut ws, json!({ "type": "subscribe", "topic": topic })).await;
        assert_eq!(recv_frame(&mut ws).await["type"], "subscribed");
        let ev = recv_frame(&mut ws).await;
        assert_eq!((ev["type"].as_str(), ev["event"].as_str(), ev["topic"].as_str()), (Some("event"), Some("ring"), Some(topic.as_str())));
        assert_eq!(ev["payload"]["channel_id"], channel_id.as_str());
        assert_eq!(ev["payload"]["server_id"], server_id.as_str());
        assert_eq!(ev["payload"]["ring_id"], rang["ring_id"]);
        assert_eq!(ev["payload"]["replay"], true);

        // The caller's own socket is not rung, and a cancelled ring is not replayed.
        let owner_id = send(&app, "GET", "/api/auth/me", Some(&owner), None).await.1["user_id"].as_str().unwrap().to_string();
        let mut caller = connect(&url, &owner).await;
        send_frame(&mut caller, json!({ "type": "subscribe", "topic": format!("user:{owner_id}") })).await;
        assert_eq!(recv_frame(&mut caller).await["type"], "subscribed");
        assert!(assert_no_event(&mut caller, 200).await.is_empty());
        send(&app, "DELETE", &format!("/api/channels/{channel_id}/ring"), Some(&owner), None).await;
        let ev = recv_frame(&mut ws).await;
        assert_eq!(ev["event"], "ring_cancel");
        let mut again = connect(&url, &member).await;
        send_frame(&mut again, json!({ "type": "subscribe", "topic": topic })).await;
        assert_eq!(recv_frame(&mut again).await["type"], "subscribed");
        assert!(assert_no_event(&mut again, 200).await.is_empty());
    }
}

mod blobs {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use tower::ServiceExt;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    /// Raw request with arbitrary headers/body (the JSON `send` helper can't do binary chunks).
    async fn raw(
        app: &Router,
        method: &str,
        path: &str,
        token: &str,
        extra_headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        for (k, v) in extra_headers {
            req = req.header(*k, *v);
        }
        let res = app.clone().oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, headers, bytes)
    }

    fn hdr(headers: &axum::http::HeaderMap, name: &str) -> String {
        headers.get(name).map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
    }

    #[tokio::test]
    async fn resumable_upload_roundtrip() {
        let (app, _db) = test_app().await;
        let (_, token) = signup(&app, "uploader").await;
        send(&app, "POST", "/api/servers", Some(&token), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let (status, body) = send(&app, "POST", "/api/blobs", Some(&token), Some(json!({ "total_size": 10 }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let blob_id = body["blob_id"].as_str().unwrap().to_string();

        // Incomplete blob can't be downloaded.
        let (status, _, _) = raw(&app, "GET", &format!("/api/blobs/{blob_id}"), &token, &[], vec![]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // First chunk (4 bytes at offset 0).
        let (status, headers, _) =
            raw(&app, "PATCH", &format!("/api/blobs/{blob_id}"), &token, &[("upload-offset", "0")], b"encr".to_vec()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(hdr(&headers, "upload-offset"), "4");

        // Replaying the same offset → 409 with the true resume point.
        let (status, headers, _) =
            raw(&app, "PATCH", &format!("/api/blobs/{blob_id}"), &token, &[("upload-offset", "0")], b"encr".to_vec()).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(hdr(&headers, "upload-offset"), "4");

        // Resume probe agrees.
        let (status, headers, _) = raw(&app, "GET", &format!("/api/blobs/{blob_id}/offset"), &token, &[], vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(hdr(&headers, "upload-offset"), "4");
        assert_eq!(hdr(&headers, "upload-length"), "10");

        // Overflow is refused.
        let (status, _, _) = raw(
            &app,
            "PATCH",
            &format!("/api/blobs/{blob_id}"),
            &token,
            &[("upload-offset", "4")],
            b"way-too-long".to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Final chunk completes it; download returns the exact ciphertext.
        let (status, headers, _) =
            raw(&app, "PATCH", &format!("/api/blobs/{blob_id}"), &token, &[("upload-offset", "4")], b"ypted!".to_vec()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(hdr(&headers, "upload-complete"), "1");
        let (status, _, bytes) = raw(&app, "GET", &format!("/api/blobs/{blob_id}"), &token, &[], vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, b"encrypted!");
    }

    #[tokio::test]
    async fn uploads_are_owner_scoped() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "blobowner").await;
        send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let (_, other) = signup(&app, "blobother").await;
        let (_, body) = send(&app, "POST", "/api/blobs", Some(&owner), Some(json!({ "total_size": 4 }))).await;
        let blob_id = body["blob_id"].as_str().unwrap().to_string();

        let (status, _, _) =
            raw(&app, "PATCH", &format!("/api/blobs/{blob_id}"), &other, &[("upload-offset", "0")], b"hack".to_vec()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = raw(&app, "DELETE", &format!("/api/blobs/{blob_id}"), &other, &[], vec![]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = raw(&app, "DELETE", &format!("/api/blobs/{blob_id}"), &owner, &[], vec![]).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn attachment_linkage_and_read_gating() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "atowner").await;
        let (_, member) = signup(&app, "atmember").await;
        let (_, outsider) = signup(&app, "atoutsider").await;
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"c") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/channels/{channel_id}/messages"),
            Some(&owner),
            Some(json!({ "ciphertext": b64(b"msg-with-file") })),
        )
        .await;
        let msg_id = body["message_id"].as_str().unwrap().to_string();

        // Upload + complete a blob.
        let (_, body) = send(&app, "POST", "/api/blobs", Some(&owner), Some(json!({ "total_size": 4 }))).await;
        let blob_id = body["blob_id"].as_str().unwrap().to_string();

        // Attaching an incomplete blob is refused.
        let attach = json!({ "blob_id": blob_id, "metadata_ciphertext": b64(b"enc-meta") });
        let (status, _) = send(&app, "POST", &format!("/api/messages/{msg_id}/attachments"), Some(&owner), Some(attach.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        raw(&app, "PATCH", &format!("/api/blobs/{blob_id}"), &owner, &[("upload-offset", "0")], b"file".to_vec()).await;

        // Only the author attaches; someone else's blob 404s.
        let (status, _) = send(&app, "POST", &format!("/api/messages/{msg_id}/attachments"), Some(&member), Some(attach.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, body) = send(&app, "POST", &format!("/api/messages/{msg_id}/attachments"), Some(&owner), Some(attach)).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // Members with READ list it; outsiders don't.
        let (status, body) = send(&app, "GET", &format!("/api/messages/{msg_id}/attachments"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        let atts = body["attachments"].as_array().unwrap();
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0]["blob_id"], blob_id.as_str());
        assert_eq!(atts[0]["file_size"], 4);
        let (status, _) = send(&app, "GET", &format!("/api/messages/{msg_id}/attachments"), Some(&outsider), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The member downloads the ciphertext by capability id.
        let (status, _, bytes) = raw(&app, "GET", &format!("/api/blobs/{blob_id}"), &member, &[], vec![]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, b"file");

        // Defense-in-depth: an outsider who somehow learns the blob id still can't download it —
        // they have no READ on the channel it's attached to. NotFound (not Forbidden) so the blob
        // id can't be used as an existence oracle.
        let (status, _, _) = raw(&app, "GET", &format!("/api/blobs/{blob_id}"), &outsider, &[], vec![]).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}

mod limits {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    #[tokio::test]
    async fn login_attempts_are_rate_limited_per_account() {
        let (app, _db) = test_app().await;
        signup(&app, "bruteforced").await;
        let attempt = json!({ "username": "bruteforced", "password": "guess-wrong" });
        let mut last = StatusCode::OK;
        for _ in 0..11 {
            let (status, _) = send(&app, "POST", "/api/auth/login", None, Some(attempt.clone())).await;
            last = status;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
        // A different account is unaffected.
        signup(&app, "innocent").await;
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/login",
            None,
            Some(json!({ "username": "innocent", "password": "correct horse" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn purge_deletes_old_messages_and_requires_manage_server() {
        let (app, db) = test_app().await;
        let (_, owner) = signup(&app, "purgeowner").await;
        let (_, member) = signup(&app, "purgemember").await;
        let (status, body) =
            send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        assert_eq!(status, StatusCode::OK);
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"c") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();

        // One fresh message via the API, one artificially old row.
        send(
            &app,
            "POST",
            &format!("/api/channels/{channel_id}/messages"),
            Some(&owner),
            Some(json!({ "ciphertext": b64(b"fresh") })),
        )
        .await;
        sqlx::query(&crate::tests::pg("INSERT INTO messages (id, channel_id, author_id, ciphertext, created_at, updated_at) VALUES ($1, $2, NULL, x'00', 1000, 1000)"))
            .bind(crate::state::new_id())
            .bind(&channel_id)
            .execute(&db)
            .await
            .unwrap();

        // Member without MANAGE_SERVER can't purge.
        let purge = json!({ "older_than_ms": 24 * 3600 * 1000i64 });
        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/purge"), Some(&member), Some(purge.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Owner purges: the ancient row goes, the fresh one stays.
        let (status, body) = send(&app, "POST", &format!("/api/servers/{server_id}/purge"), Some(&owner), Some(purge)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["purged_messages"], 1);
        let (_, body) = send(&app, "GET", &format!("/api/channels/{channel_id}/messages"), Some(&owner), None).await;
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(B64.decode(msgs[0]["ciphertext"].as_str().unwrap()).unwrap(), b"fresh");
    }
}

mod voice {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    async fn seed_livekit(db: &crate::state::Db) {
        for (name, value) in [("livekit_url", "wss://sfu.example.org"), ("livekit_api_key", "lk_testkey"), ("livekit_api_secret", "test-secret-value")] {
            sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, 0)")
                .bind(name)
                .bind(value.as_bytes())
                .execute(db)
                .await
                .unwrap();
        }
    }

    /// owner + a voice channel; returns (owner_token, member_token, voice_channel_id).
    async fn voice_world(app: &Router) -> (String, String, String) {
        let (_, owner) = signup(app, "voiceowner").await;
        let (_, member) = signup(app, "voicemember").await;
        let (_, body) = send(app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        let (_, body) = send(
            app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"voice"), "type": "voice" })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();
        (owner, member, channel_id)
    }

    #[tokio::test]
    async fn fails_closed_without_livekit_config() {
        let (app, _db) = test_app().await;
        let (owner, _member, channel_id) = voice_world(&app).await;
        // No LiveKit creds seeded → no token, even for a permitted member — and said as what it
        // is: 503 with a code, not the 403 that means "you may not".
        let path = format!("/api/channels/{channel_id}/voice-token");
        let (status, body) = send(&app, "POST", &path, Some(&owner), None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!((body["code"].as_str(), body["reason"].as_str()), (Some("voice_off"), Some("not_set_up")));
        assert!(body.get("token").is_none());
        // Only to someone who may join.
        let (_, outsider) = signup(&app, "voicestranger").await;
        assert_eq!(send(&app, "POST", &path, Some(&outsider), None).await.0, StatusCode::FORBIDDEN);
        // What a 0.50 app reads of the status is unchanged.
        let (status, body) = send(&app, "GET", "/api/voice/config", Some(&owner), None).await;
        assert_eq!((status, body["configured"].as_bool(), body["url"].is_null()), (StatusCode::OK, Some(false), true));
        assert_eq!((body["status"].as_str(), body["bundled"].as_bool(), body["external"].as_bool()), (Some("off"), Some(false), Some(false)));
    }

    /// The credentials are there but the call server is down (it is being restarted): the same
    /// answer, "starting" — never a token without anywhere to go.
    #[tokio::test]
    async fn a_call_server_that_is_down_or_starting_is_a_503_with_its_code() {
        let state = test_state().await;
        let app = api::router(state.clone());
        seed_livekit(&state.db).await;
        let (_owner, member, channel_id) = voice_world(&app).await;
        let path = format!("/api/channels/{channel_id}/voice-token");
        sqlx::query("DELETE FROM instance_secrets WHERE name = 'livekit_url'").execute(&state.db).await.unwrap();
        use crate::livekit::{Reason, VoicePhase};
        for (phase, reason, code) in [(VoicePhase::Starting, Reason::Exited, "voice_starting"), (VoicePhase::Off, Reason::Ports, "voice_off")] {
            state.voice.set(phase, reason, true);
            let (status, body) = send(&app, "POST", &path, Some(&member), None).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!((body["code"].as_str(), body["reason"].as_str()), (Some(code), Some(reason.code())));
            // Any member may read it too.
            let (_, config) = send(&app, "GET", "/api/voice/config", Some(&member), None).await;
            assert_eq!((config["status"].as_str(), config["reason"].as_str(), config["bundled"].as_bool()), (Some(phase.as_str()), Some(reason.code()), Some(true)));
        }
        state.voice.set(VoicePhase::On, Reason::Managed, true);
        for (name, value) in [("livekit_url", "ws://127.0.0.1:7880"), ("livekit_managed", "1")] {
            sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, 0)").bind(name).bind(value.as_bytes()).execute(&state.db).await.unwrap();
        }
        assert_eq!(send(&app, "POST", &path, Some(&member), None).await.0, StatusCode::OK);
    }

    /// Who may change the call server: the owner, and on a skwod with its own call server nobody
    /// can save another by mistake (a 0.50 app's setup sheet did, and it kept the bundled one off
    /// on every start). One that IS saved can be seen, changed and cleared.
    #[tokio::test]
    async fn the_saved_call_server_is_the_owners_to_clear_and_not_to_set_by_mistake() {
        let state = test_state().await;
        let app = api::router(state.clone());
        let (owner, member, _) = voice_world(&app).await;
        let (_, me) = send(&app, "GET", "/api/auth/me", Some(&owner), None).await;
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('owner_user_id', $1, 0)").bind(me["user_id"].as_str().unwrap().as_bytes()).execute(&state.db).await.unwrap();
        let voice = json!({ "url": "wss://sfu.example.org", "api_key": "k", "api_secret": "s" });
        use crate::livekit::{Reason, VoicePhase};
        state.voice.set(VoicePhase::Starting, Reason::Launching, true);
        let (status, _) = send(&app, "PUT", "/api/voice/config", Some(&owner), Some(voice.clone())).await;
        assert_eq!(status, StatusCode::CONFLICT, "there is nothing to set up here");
        // Nothing saved: nothing to clear.
        let (status, body) = send(&app, "DELETE", "/api/voice/config", Some(&owner), None).await;
        assert_eq!((status, body["cleared"].as_bool()), (StatusCode::OK, Some(false)));
        // What the bundled server advertises is never cleared from here.
        for (name, value) in [("livekit_url", "ws://127.0.0.1:7880"), ("livekit_managed", "1")] {
            sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, 0)").bind(name).bind(value.as_bytes()).execute(&state.db).await.unwrap();
        }
        assert_eq!(send(&app, "DELETE", "/api/voice/config", Some(&owner), None).await.1["cleared"], false);
        assert!(crate::livekit::external_url(&state).await.is_none());

        // Without a bundled server it is set as before; the managed mark does not outlive it.
        state.voice.set(VoicePhase::Off, Reason::NoBinary, false);
        assert_eq!(send(&app, "PUT", "/api/voice/config", Some(&owner), Some(voice)).await.0, StatusCode::OK);
        assert_eq!(crate::livekit::external_url(&state).await.as_deref(), Some("wss://sfu.example.org"));
        let (_, config) = send(&app, "GET", "/api/voice/config", Some(&member), None).await;
        assert_eq!((config["external"].as_bool(), config["configured"].as_bool(), config["status"].as_str()), (Some(true), Some(true), Some("on")));
        // A member may not clear it; the owner may, key and secret with it.
        assert_eq!(send(&app, "DELETE", "/api/voice/config", Some(&member), None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, "DELETE", "/api/voice/config", Some(&owner), None).await.1["cleared"], true);
        let left: i64 = sqlx::query_scalar("SELECT count(*) FROM instance_secrets WHERE name IN ('livekit_url', 'livekit_api_key', 'livekit_api_secret', 'livekit_managed')").fetch_one(&state.db).await.unwrap();
        assert_eq!(left, 0);
    }

    #[tokio::test]
    async fn mints_verifiable_token_for_permitted_member() {
        let (app, db) = test_app().await;
        seed_livekit(&db).await;
        let (owner, member, channel_id) = voice_world(&app).await;

        let (_, owner_me) = send(&app, "GET", "/api/auth/me", Some(&owner), None).await;
        let owner_id = owner_me["user_id"].as_str().unwrap().to_string();

        let (status, body) = send(&app, "POST", &format!("/api/channels/{channel_id}/voice-token"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["token"].as_str().unwrap();
        let room = body["room"].as_str().unwrap();

        // The minted JWT verifies against the instance secret and carries the right grant.
        let claims = crate::voice::verify::verify(token, "test-secret-value").expect("token must verify");
        assert_eq!(claims["iss"], "lk_testkey");
        assert_eq!(claims["sub"], owner_id.as_str());
        assert_eq!(claims["video"]["room"], room);
        assert_eq!(claims["video"]["roomJoin"], true);
        // Wrong secret must not verify.
        assert!(crate::voice::verify::verify(token, "wrong-secret").is_none());

        // A default member also has CONNECT_VOICE (in DEFAULT_PERMISSIONS).
        let (status, _) = send(&app, "POST", &format!("/api/channels/{channel_id}/voice-token"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn denies_non_members_and_text_channels() {
        let (app, db) = test_app().await;
        seed_livekit(&db).await;
        let (owner, _member, voice_channel) = voice_world(&app).await;

        // Outsider without membership.
        let (_, outsider) = signup(&app, "voiceoutsider").await;
        let (status, _) = send(&app, "POST", &format!("/api/channels/{voice_channel}/voice-token"), Some(&outsider), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Text channel is not joinable for voice.
        let (_, srv) = send(&app, "GET", "/api/servers", Some(&owner), None).await;
        let server_id = srv["servers"][0]["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"text") })),
        )
        .await;
        let text_channel = body["channel_id"].as_str().unwrap().to_string();
        let (status, _) = send(&app, "POST", &format!("/api/channels/{text_channel}/voice-token"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// owner + member in a server with NO voice channel; returns (owner, member, server_id).
    async fn roomless_world(app: &Router) -> (String, String, String) {
        let (_, owner) = signup(app, "roomowner").await;
        let (_, member) = signup(app, "roommember").await;
        let (_, body) = send(app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        (owner, member, server_id)
    }

    #[tokio::test]
    async fn a_member_opens_the_first_voice_room_and_nothing_else() {
        let (app, db) = test_app().await;
        seed_livekit(&db).await;
        let (owner, member, server_id) = roomless_world(&app).await;
        let path = format!("/api/servers/{server_id}/channels");
        let voice = json!({ "name_ciphertext": b64(b"General"), "type": "voice" });

        // Not a member: nothing.
        let (_, outsider) = signup(&app, "roomoutsider").await;
        let (status, _) = send(&app, "POST", &path, Some(&outsider), Some(voice.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // A member still cannot create text channels, or dress the room up.
        for refused in [
            json!({ "name_ciphertext": b64(b"x") }),
            json!({ "name_ciphertext": b64(b"x"), "type": "announcement" }),
            json!({ "name_ciphertext": b64(b"x"), "type": "voice", "is_private": true }),
            json!({ "name_ciphertext": b64(b"x"), "type": "voice", "topic_ciphertext": b64(b"t") }),
            json!({ "name_ciphertext": b64(b"x"), "type": "voice", "category_id": "c" }),
        ] {
            let (status, _) = send(&app, "POST", &path, Some(&member), Some(refused.clone())).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        }
        let (status, _) = send(&app, "POST", &path, Some(&member), Some(json!({ "name_ciphertext": b64(&[0u8; 600]), "type": "voice" }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "oversized name");

        // …but the first voice room: yes, and the token for it follows.
        let (status, body) = send(&app, "POST", &path, Some(&member), Some(voice.clone())).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let room = body["channel_id"].as_str().unwrap().to_string();
        let (status, _) = send(&app, "POST", &format!("/api/channels/{room}/voice-token"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);

        // Asking again never makes a second room — the existing one is handed back.
        let (status, body) = send(&app, "POST", &path, Some(&member), Some(voice.clone())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["channel_id"], room.as_str());
        assert_eq!(body["existing"], true);
        let (_, listed) = send(&app, "GET", &path, Some(&owner), None).await;
        let voices = listed["channels"].as_array().unwrap().iter().filter(|c| c["type"] == "voice").count();
        assert_eq!(voices, 1);
    }

    #[tokio::test]
    async fn two_members_calling_at_once_get_one_room() {
        let (app, _db) = test_app().await;
        let (owner, member, server_id) = roomless_world(&app).await;
        let (_, third) = signup(&app, "roomthird").await;
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        send(&app, "POST", &format!("/api/invites/{}/accept", body["code"].as_str().unwrap()), Some(&third), None).await;
        let path = format!("/api/servers/{server_id}/channels");
        let voice = json!({ "name_ciphertext": b64(b"General"), "type": "voice" });
        let (a, b) = tokio::join!(
            send(&app, "POST", &path, Some(&member), Some(voice.clone())),
            send(&app, "POST", &path, Some(&third), Some(voice.clone()))
        );
        assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK));
        assert_eq!(a.1["channel_id"], b.1["channel_id"]);
    }

    #[tokio::test]
    async fn a_member_without_voice_permission_cannot_open_the_room() {
        let (app, db) = test_app().await;
        let (_owner, member, server_id) = roomless_world(&app).await;
        // @everyone loses CONNECT_VOICE.
        sqlx::query("UPDATE roles SET permissions = $1 WHERE server_id = $2 AND is_default = 1")
            .bind(crate::perms::SEND_MESSAGES | crate::perms::READ_MESSAGES)
            .bind(&server_id)
            .execute(&db)
            .await
            .unwrap();
        let (status, _) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&member),
            Some(json!({ "name_ciphertext": b64(b"General"), "type": "voice" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn ring_is_members_only_and_rate_limited() {
        let (app, _db) = test_app().await;
        let (owner, member, channel_id) = voice_world(&app).await;
        let path = format!("/api/channels/{channel_id}/ring");

        let (_, outsider) = signup(&app, "ringoutsider").await;
        let (status, _) = send(&app, "POST", &path, Some(&outsider), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "POST", &path, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        // An outsider's refused attempts cost the members nothing, and they see no rings.
        let (status, body) = send(&app, "GET", "/api/rings", Some(&outsider), None).await;
        assert_eq!((status, body["rings"].as_array().unwrap().len()), (StatusCode::OK, 0));

        for _ in 0..3 {
            let (status, body) = send(&app, "POST", &path, Some(&member), None).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["rang"], 1);
        }
        let (status, _) = send(&app, "POST", &path, Some(&member), None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        // The limit is per caller.
        let (status, _) = send(&app, "POST", &path, Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_ring_is_kept_for_late_devices_until_answered_cancelled_or_expired() {
        let state = crate::tests::test_state().await;
        let app = api::router(state.clone());
        seed_livekit(&state.db).await;
        let (owner, member, channel_id) = voice_world(&app).await;
        let path = format!("/api/channels/{channel_id}/ring");
        let rings = |token: String| {
            let app = app.clone();
            async move { send(&app, "GET", "/api/rings", Some(&token), None).await.1["rings"].as_array().unwrap().clone() }
        };

        let (_, rang) = send(&app, "POST", &path, Some(&owner), None).await;
        let pending = rings(member.clone()).await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["channel_id"], channel_id.as_str());
        assert_eq!(pending[0]["ring_id"], rang["ring_id"]);
        assert_eq!(pending[0]["replay"], true);
        assert!(rings(owner.clone()).await.is_empty(), "the caller is not rung");

        // Only the caller can cancel.
        let (_, body) = send(&app, "DELETE", &path, Some(&member), None).await;
        assert_eq!(body["cancelled"], false);
        assert_eq!(rings(member.clone()).await.len(), 1);
        let (_, body) = send(&app, "DELETE", &path, Some(&owner), None).await;
        assert_eq!(body["cancelled"], true);
        assert!(rings(member.clone()).await.is_empty());

        // Joining (fetching the room token) answers it.
        send(&app, "POST", &path, Some(&owner), None).await;
        assert_eq!(rings(member.clone()).await.len(), 1);
        let (status, _) = send(&app, "POST", &format!("/api/channels/{channel_id}/voice-token"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(rings(member.clone()).await.is_empty());

        // It dies by itself after RING_TTL_MS.
        send(&app, "POST", &path, Some(&owner), None).await;
        let (_, me) = send(&app, "GET", "/api/auth/me", Some(&member), None).await;
        let member_id = me["user_id"].as_str().unwrap();
        let now = crate::state::now_ms();
        assert_eq!(state.rings.for_user(member_id, now).len(), 1);
        assert_eq!(state.rings.for_user(member_id, now + crate::voice::RING_TTL_MS - 1_000).len(), 1);
        assert!(state.rings.for_user(member_id, now + crate::voice::RING_TTL_MS + 1).is_empty());

        // A member blocked by the caller after the ring started is not shown it.
        let (status, body) = send(&app, "PUT", &format!("/api/blocks/{member_id}"), Some(&owner), None).await;
        assert!(status.is_success(), "{body}");
        assert!(rings(member.clone()).await.is_empty());
    }
}

mod push {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    #[tokio::test]
    async fn register_validates_platform_and_rebinds_token() {
        let (app, _db) = test_app().await;
        let (_, alice) = signup(&app, "pushalice").await;
        let (_, bob) = signup(&app, "pushbob").await;

        let t1 = "a1".repeat(32);
        // Bad platform (web dropped per ADR-009).
        let (status, _) =
            send(&app, "POST", "/api/push/register", Some(&alice), Some(json!({ "token": t1, "platform": "web" }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Valid registration, then the same device token rebinds to Bob.
        let (status, _) =
            send(&app, "POST", "/api/push/register", Some(&alice), Some(json!({ "token": t1, "platform": "ios" }))).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) =
            send(&app, "POST", "/api/push/register", Some(&bob), Some(json!({ "token": t1, "platform": "android" }))).await;
        assert_eq!(status, StatusCode::OK);

        // Unregister only affects the caller's binding.
        let (status, _) = send(&app, "POST", "/api/push/unregister", Some(&alice), Some(json!({ "token": t1 }))).await;
        assert_eq!(status, StatusCode::OK); // no-op for alice (token now bob's), still 200
    }

    /// Audit B6: the direct route took any string as a token, any number of them, and kept
    /// them after logout. An Apple token goes into the path of the request to Apple.
    #[tokio::test]
    async fn direct_tokens_are_validated_capped_and_end_with_their_session() {
        let (app, db) = test_app().await;
        let (user_id, token) = signup(&app, "directpush").await;
        let hex = |i: usize| format!("{i:02x}").repeat(32);
        for (bad, platform) in [
            (String::new(), "ios"),
            ("t1".to_string(), "ios"),
            (format!("{}/../../3/device/x", "ab".repeat(32)), "ios"),
            (format!("{}?x=1", "ab".repeat(32)), "ios"),
            ("ab".repeat(101), "ios"),
            ("abc".repeat(21), "macos"),
            ("zz".repeat(32), "ios"),
            ("short".to_string(), "android"),
            (format!("{} with spaces and / slashes", "f".repeat(40)), "android"),
            ("f".repeat(600), "android"),
        ] {
            let (status, _) = send(&app, "POST", "/api/push/register", Some(&token), Some(json!({ "token": bad, "platform": platform }))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{platform} token {bad:?} must be refused");
        }
        // Hex is stored in one spelling.
        let (status, _) = send(&app, "POST", "/api/push/register", Some(&token), Some(json!({ "token": "AB".repeat(32), "platform": "ios" }))).await;
        assert_eq!(status, StatusCode::OK);
        let stored: Vec<String> = sqlx::query_scalar("SELECT token FROM push_tokens WHERE user_id = $1").bind(&user_id).fetch_all(&db).await.unwrap();
        assert_eq!(stored, vec!["ab".repeat(32)]);

        // A dozen more: the account keeps eight, the newest.
        for i in 0..12 {
            let (status, _) = send(&app, "POST", "/api/push/register", Some(&token), Some(json!({ "token": hex(i), "platform": "ios" }))).await;
            assert_eq!(status, StatusCode::OK);
        }
        let held: i64 = sqlx::query_scalar("SELECT count(*) FROM push_tokens WHERE user_id = $1").bind(&user_id).fetch_one(&db).await.unwrap();
        assert_eq!(held, 8);

        // A row that predates validation (or was written around it) is never handed to a sender…
        let session: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions WHERE user_id = $1").bind(&user_id).fetch_one(&db).await.unwrap();
        sqlx::query("INSERT INTO push_tokens (id, user_id, token, platform, created_at, session_hash) VALUES ('old', $1, '../../evil', 'ios', $2, $3)")
            .bind(&user_id)
            .bind(crate::state::now_ms() + 1_000)
            .bind(&session)
            .execute(&db)
            .await
            .unwrap();
        // …and neither is one that names no session.
        sqlx::query("INSERT INTO push_tokens (id, user_id, token, platform, created_at) VALUES ('orphan', $1, $2, 'ios', $3)")
            .bind(&user_id)
            .bind("cd".repeat(32))
            .bind(crate::state::now_ms() + 2_000)
            .execute(&db)
            .await
            .unwrap();
        let state = crate::state::AppState::new(db.clone(), std::env::temp_dir());
        let wakeups = crate::push::build_wakeups(&state, "sealed", "", "", std::slice::from_ref(&user_id)).await.unwrap();
        assert!(!wakeups.is_empty() && wakeups.len() <= 8);
        assert!(wakeups.iter().all(|w| crate::push::valid_direct_token(&w.token, &w.platform) && w.token != "cd".repeat(32)), "{wakeups:?}");

        // Signing out ends the session's tokens: a signed-out install is not woken.
        let (status, _) = send(&app, "POST", "/api/auth/logout", Some(&token), None).await;
        assert!(status.is_success());
        let left: Vec<String> = sqlx::query_scalar("SELECT id FROM push_tokens WHERE user_id = $1").bind(&user_id).fetch_all(&db).await.unwrap();
        assert_eq!(left, vec!["orphan".to_string()]);
        assert!(crate::push::build_wakeups(&state, "sealed", "", "", &[user_id]).await.unwrap().is_empty());
    }

    /// Audit C5: removing one device deleted every registration of the account that named no
    /// device — the account's other phones went silent until they were next opened.
    #[tokio::test]
    async fn removing_a_device_forgets_only_that_devices_registrations() {
        let (app, db) = test_app().await;
        let (user_id, _first) = signup(&app, "threephones").await;
        let now = crate::state::now_ms();
        // Three installs: one names the device, one is a session bound to it, one names nothing.
        for (id, row_device, session_device) in [("named", Some("gone"), None), ("bound", None, Some("gone")), ("other", None, None::<&str>), ("kept", Some("stays"), Some("stays"))] {
            let hash = id.as_bytes().to_vec();
            sqlx::query("INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_used_at, origin_at, device_id) VALUES ($1, $2, $3, $4, $5, $4, $4, $6)")
                .bind(id)
                .bind(&user_id)
                .bind(&hash)
                .bind(now)
                .bind(now + 60_000)
                .bind(session_device)
                .execute(&db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO push_registrations (id, user_id, session_hash, device_id, gateway, apns_token, topic, created_at, updated_at, wake_credential) VALUES ($1, $2, $3, $4, 'https://push.example.org', '', '', 0, 0, $5)")
                .bind(id)
                .bind(&user_id)
                .bind(&hash)
                .bind(row_device)
                .bind(format!("w1.{}", id.repeat(8)))
                .execute(&db)
                .await
                .unwrap();
        }
        let mut tx = db.begin().await.unwrap();
        crate::push::forget_device(&mut tx, &user_id, "gone").await.unwrap();
        tx.commit().await.unwrap();
        let mut left: Vec<String> = sqlx::query_scalar("SELECT id FROM push_registrations WHERE user_id = $1").bind(&user_id).fetch_all(&db).await.unwrap();
        left.sort();
        assert_eq!(left, ["kept", "other"], "the install that named no device keeps its push");
    }

    #[tokio::test]
    async fn wakeups_target_recipients_excluding_author_and_carry_no_plaintext() {
        let (app, db) = test_app().await;
        let (owner_id, owner) = signup(&app, "pushowner").await;
        let (member_id, member) = signup(&app, "pushmember").await;
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap();
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        let (_, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/channels"),
            Some(&owner),
            Some(json!({ "name_ciphertext": b64(b"c") })),
        )
        .await;
        let channel_id = body["channel_id"].as_str().unwrap().to_string();

        // Both register a device.
        let member_dev = "member-dev".repeat(4);
        send(&app, "POST", "/api/push/register", Some(&owner), Some(json!({ "token": "0d".repeat(32), "platform": "ios" }))).await;
        send(&app, "POST", "/api/push/register", Some(&member), Some(json!({ "token": member_dev, "platform": "android" }))).await;

        // Owner sends "the-secret-plaintext" as ciphertext; wakeups target the member, not the author.
        let state = crate::state::AppState::new(db.clone(), std::env::temp_dir());
        let recipients = crate::push::channel_recipients(&state, &channel_id).await.unwrap();
        assert!(recipients.contains(&owner_id) && recipients.contains(&member_id));
        let wakeups = crate::push::build_wakeups(&state, &format!("channel:{channel_id}"), "msg-1", &owner_id, &recipients)
            .await
            .unwrap();
        assert_eq!(wakeups.len(), 1, "only the non-author member's device");
        assert_eq!(wakeups[0].token, member_dev);
        assert_eq!(wakeups[0].message_id, "msg-1");

        // The serialized wakeup contains routing only — no content field at all.
        let json = serde_json::to_string(&wakeups[0]).unwrap();
        assert!(json.contains("channel:") && json.contains("msg-1"));
        assert!(!json.contains("plaintext") && !json.contains("ciphertext") && !json.contains("content"));

        // Audit B2. A member who has blocked the author is not woken for them (the reverse
        // block changes nothing for the member)…
        let unblocked = crate::push::without_blockers(&state, &owner_id, recipients.clone()).await.unwrap();
        assert!(unblocked.contains(&member_id));
        let (status, body) = send(&app, "PUT", &format!("/api/blocks/{member_id}"), Some(&owner), None).await;
        assert!(status.is_success(), "{body}");
        assert!(crate::push::without_blockers(&state, &owner_id, recipients.clone()).await.unwrap().contains(&member_id), "the author's own blocks do not hide the author's messages from anyone");
        assert!(!crate::push::without_blockers(&state, &member_id, recipients.clone()).await.unwrap().contains(&owner_id), "the owner blocked the member: the member's messages do not wake the owner");
        // …and a member who may not read the channel is not a recipient at all.
        let (status, body) = send(
            &app,
            "PUT",
            &format!("/api/channels/{channel_id}/overrides"),
            Some(&owner),
            Some(json!({ "user_id": member_id, "allow": 0, "deny": 128 })),
        )
        .await;
        assert!(status.is_success(), "{body}");
        let readers = crate::push::channel_recipients(&state, &channel_id).await.unwrap();
        assert!(readers.contains(&owner_id) && !readers.contains(&member_id), "{readers:?}");
    }
}

mod join {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Simulate `init` having set an admin setup code.
    async fn set_admin_code(db: &crate::state::Db, code: &str) {
        let hash = Sha256::digest(code.as_bytes()).to_vec();
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('admin_setup_code', $1, 0)")
            .bind(hash)
            .execute(db)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn signup_open_before_init_gated_after() {
        let (app, db) = test_app().await;
        // Fresh (never-initialized) instance: open signup, no code needed.
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "password": "password123", "username": "firstuser" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Operator runs init → admin code set → signup now requires a valid code.
        set_admin_code(&db, "SKWD-ADMIN-CODE").await;
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "password": "password123", "username": "nocode" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no code after init");

        // Wrong code rejected.
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "password": "password123", "username": "badcode", "join_code": "WRONG" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Admin code works.
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "password": "password123", "username": "adminuser", "join_code": "SKWD-ADMIN-CODE" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn server_invite_code_authorizes_signup() {
        let (app, db) = test_app().await;
        // Owner (first signup, open) creates a server + invite.
        let (_, owner) = signup(&app, "invowner").await;
        set_admin_code(&db, "ADMIN").await; // now gated
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": "ZW5j" }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let code = body["code"].as_str().unwrap().to_string();

        // A new user signs up using the invite code.
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "password": "password123", "username": "inviteduser", "join_code": code })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_code_is_one_time_bootstrap() {
        let (app, db) = test_app().await;
        set_admin_code(&db, "SKWD-BOOT-CODE").await;

        // The first signup with the admin code succeeds and claims instance ownership.
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "password": "password123", "username": "owner", "join_code": "SKWD-BOOT-CODE" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // The SAME admin code is now permanently dead — a leaked init code can't mint a 2nd account.
        let (status, _) = send(
            &app,
            "POST",
            "/api/auth/signup",
            None,
            Some(json!({ "password": "password123", "username": "intruder", "join_code": "SKWD-BOOT-CODE" })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "admin code must die once ownership is claimed");
    }

    #[tokio::test]
    async fn bootstrap_ownership_claim_is_atomic() {
        let (app, db) = test_app().await;
        set_admin_code(&db, "SKWD-RACE-CODE").await;

        // Fire several concurrent signups that all present the one-time admin code with distinct
        // usernames. Only the signup that wins the owner_user_id INSERT may succeed; the rest must
        // be rejected — the admin code mints exactly one account even under a race, because the
        // ownership claim is atomic with the signup transaction.
        let attempts = (0..5).map(|i| {
            let app = app.clone();
            async move {
                let (status, _) = send(
                    &app,
                    "POST",
                    "/api/auth/signup",
                    None,
                    Some(json!({
                        "password": "password123",
                        "username": format!("racer{i}"),
                        "join_code": "SKWD-RACE-CODE"
                    })),
                )
                .await;
                status
            }
        });
        let results = futures_util::future::join_all(attempts).await;
        let ok = results.iter().filter(|s| **s == StatusCode::OK).count();
        assert_eq!(ok, 1, "exactly one bootstrap signup may claim ownership, got {ok}: {results:?}");

        // And exactly one owner row exists in the DB.
        let owners: i64 = sqlx::query_scalar("SELECT count(*) FROM instance_secrets WHERE name = 'owner_user_id'")
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(owners, 1, "exactly one owner row");
    }

    #[tokio::test]
    async fn invite_defaults_to_seven_day_expiry() {
        let (app, _) = test_app().await;
        let (_, owner) = signup(&app, "expowner").await;
        let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": "ZW5j" }))).await;
        let server_id = body["server_id"].as_str().unwrap().to_string();
        // No expires_at supplied → server defaults it to now + 7 days.
        let (_, body) = send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        let expires_at = body["expires_at"].as_i64().expect("expires_at present in response");
        let expected = crate::state::now_ms() + 7 * 24 * 60 * 60 * 1000;
        assert!((expires_at - expected).abs() < 60_000, "expected ~7d expiry, got {expires_at} vs {expected}");
    }
}

mod secure_join {
    use super::*;

    /// Owner signs up and creates a server; returns (owner_token, server_id).
    async fn owner_with_server(app: &Router) -> (String, String) {
        let (_, owner) = signup(app, "hostowner").await;
        let (status, body) = send(app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": "ZW5j" }))).await;
        assert_eq!(status, StatusCode::OK, "create server: {body}");
        (owner, body["server_id"].as_str().unwrap().to_string())
    }

    async fn create_invite(app: &Router, owner: &str, server_id: &str, req: Value) -> Value {
        let (status, body) = send(app, "POST", &format!("/api/servers/{server_id}/invites"), Some(owner), Some(req)).await;
        assert_eq!(status, StatusCode::OK, "create invite: {body}");
        body
    }

    async fn is_member(app: &Router, server_id: &str, token: &str) -> bool {
        // list_members is member-gated; a non-member gets 403.
        let (status, _) = send(app, "GET", &format!("/api/servers/{server_id}/members"), Some(token), None).await;
        status == StatusCode::OK
    }

    #[tokio::test]
    async fn token_invite_auto_joins_and_is_single_use() {
        let (app, _) = test_app().await;
        let (owner, server_id) = owner_with_server(&app).await;
        let inv = create_invite(&app, &owner, &server_id, json!({ "kind": "token" })).await;
        assert_eq!(inv["requires_approval"], false);
        let code = inv["code"].as_str().unwrap().to_string();

        // First redeemer auto-joins.
        let (_, joiner) = signup(&app, "tokjoiner").await;
        let (status, body) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&joiner), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("pending").is_none(), "token invite should NOT be pending");
        assert!(is_member(&app, &server_id, &joiner).await, "joiner should be a member");

        // Token is single-use: a second person cannot reuse it.
        let (_, second) = signup(&app, "tokjoiner2").await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&second), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "one-time token must be exhausted");
    }

    #[tokio::test]
    async fn username_invite_only_admits_the_reserved_name() {
        let (app, _) = test_app().await;
        let (owner, server_id) = owner_with_server(&app).await;
        let inv = create_invite(&app, &owner, &server_id, json!({ "kind": "username", "reserved_username": "robin" })).await;
        let code = inv["code"].as_str().unwrap().to_string();

        // Wrong username is rejected.
        let (_, mallory) = signup(&app, "mallory").await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&mallory), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "only the reserved username may join");
        assert!(!is_member(&app, &server_id, &mallory).await);

        // The reserved username auto-joins.
        let (_, robin) = signup(&app, "robin").await;
        let (status, body) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&robin), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(is_member(&app, &server_id, &robin).await, "reserved user should be a member");
    }

    #[tokio::test]
    async fn code_invite_requires_host_approval() {
        let (app, _) = test_app().await;
        let (owner, server_id) = owner_with_server(&app).await;
        let inv = create_invite(&app, &owner, &server_id, json!({ "kind": "code" })).await;
        assert_eq!(inv["requires_approval"], true);
        let code = inv["code"].as_str().unwrap().to_string();

        // Redeeming files a pending request — NOT a member yet.
        let (joiner_id, joiner) = signup(&app, "requester").await;
        let (status, body) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&joiner), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["pending"], true, "code invite must be pending approval");
        assert!(!is_member(&app, &server_id, &joiner).await, "not a member before approval");

        // Host sees the pending request.
        let (status, body) = send(&app, "GET", &format!("/api/servers/{server_id}/join-requests"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["requests"][0]["username"], "requester");

        // A non-host cannot approve.
        let (_, outsider) = signup(&app, "outsider").await;
        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{joiner_id}/approve"), Some(&outsider), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Host approves → joiner becomes a member.
        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{joiner_id}/approve"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(is_member(&app, &server_id, &joiner).await, "member after approval");

        // The request queue is now empty.
        let (_, body) = send(&app, "GET", &format!("/api/servers/{server_id}/join-requests"), Some(&owner), None).await;
        assert!(body["requests"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn host_can_deny_a_join_request() {
        let (app, _) = test_app().await;
        let (owner, server_id) = owner_with_server(&app).await;
        let inv = create_invite(&app, &owner, &server_id, json!({ "kind": "code" })).await;
        let code = inv["code"].as_str().unwrap().to_string();
        let (joiner_id, joiner) = signup(&app, "denied").await;
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&joiner), None).await;

        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{joiner_id}/deny"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!is_member(&app, &server_id, &joiner).await, "denied user is not a member");
    }
}

mod safety {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    /// Create a server as `token` and return its id.
    async fn create_server(app: &Router, token: &str) -> String {
        let (status, body) =
            send(app, "POST", "/api/servers", Some(token), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["server_id"].as_str().unwrap().to_string()
    }

    /// Mint a fresh auto-join (token) invite and return its code.
    async fn token_invite(app: &Router, owner: &str, server_id: &str) -> String {
        let (status, body) =
            send(app, "POST", &format!("/api/servers/{server_id}/invites"), Some(owner), Some(json!({ "kind": "token" }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["code"].as_str().unwrap().to_string()
    }

    async fn is_member(app: &Router, server_id: &str, token: &str) -> bool {
        let (status, _) = send(app, "GET", &format!("/api/servers/{server_id}/channels"), Some(token), None).await;
        status == StatusCode::OK
    }

    #[tokio::test]
    async fn ban_evicts_and_blocks_rejoin_until_unbanned() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "banowner").await;
        let (target_id, target) = signup(&app, "bantarget").await;
        let server_id = create_server(&app, &owner).await;

        // Target joins via an auto-join invite.
        let code = token_invite(&app, &owner, &server_id).await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&target), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(is_member(&app, &server_id, &target).await);

        // A plain member cannot ban (no BAN_MEMBERS).
        let (other_id, other) = signup(&app, "banother").await;
        let code = token_invite(&app, &owner, &server_id).await;
        send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&other), None).await;
        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/bans/{target_id}"), Some(&other), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Owner bans with a reason → membership gone.
        let (status, body) = send(
            &app,
            "POST",
            &format!("/api/servers/{server_id}/bans/{target_id}"),
            Some(&owner),
            Some(json!({ "reason": "spam" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!is_member(&app, &server_id, &target).await, "banned user is evicted");

        // THE fix over kick: a fresh, perfectly valid invite no longer readmits them.
        let code = token_invite(&app, &owner, &server_id).await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&target), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "banned user cannot redeem any invite");
        assert!(!is_member(&app, &server_id, &target).await);

        // Ban list shows them (admins only).
        let (status, body) = send(&app, "GET", &format!("/api/servers/{server_id}/bans"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let bans = body["bans"].as_array().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0]["user_id"], target_id.as_str());
        assert_eq!(bans[0]["reason"], "spam");
        let (status, _) = send(&app, "GET", &format!("/api/servers/{server_id}/bans"), Some(&other), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "ban list is admin-only");

        // Owner cannot be banned; self-ban rejected; unban restores joinability (with a NEW invite).
        let (_, me) = send(&app, "GET", "/api/auth/me", Some(&owner), None).await;
        let owner_id = me["user_id"].as_str().unwrap();
        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/bans/{owner_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/bans/{target_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let code = token_invite(&app, &owner, &server_id).await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&target), None).await;
        assert_eq!(status, StatusCode::OK, "unbanned user can join again");
        let _ = other_id;
    }

    #[tokio::test]
    async fn ban_gates_join_request_approval() {
        let (app, db) = test_app().await;
        let (_, owner) = signup(&app, "reqowner").await;
        let (joiner_id, joiner) = signup(&app, "reqjoiner").await;
        let server_id = create_server(&app, &owner).await;

        // Joiner files a pending request via a bare code invite.
        let (_, body) =
            send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "code" }))).await;
        let code = body["code"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&joiner), None).await;
        assert_eq!(body["pending"], true);

        // Ban denies the pending request → approve finds no pending row and refuses (404). The
        // status-guarded `pending` read runs before the ban check, so an already-denied request is
        // rejected as "not found" rather than reaching the ban branch — either way the user is not
        // admitted.
        let (status, _) = send(&app, "POST", &format!("/api/servers/{server_id}/bans/{joiner_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) =
            send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{joiner_id}/approve"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "approval finds no pending request (the ban denied it)");

        // Race path: even if a pending row (re)appears after the ban, approve refuses it.
        sqlx::query("UPDATE join_requests SET status = 'pending' WHERE server_id = $1 AND user_id = $2")
            .bind(&server_id)
            .bind(&joiner_id)
            .execute(&db)
            .await
            .unwrap();
        let (status, _) =
            send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{joiner_id}/approve"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "approval path itself checks the ban");
        assert!(!is_member(&app, &server_id, &joiner).await);
    }

    #[tokio::test]
    async fn approve_wont_resurrect_denied_request() {
        // The approve UPDATE is guarded on `status = 'pending'` and checks the affected-row count.
        // A request that left 'pending' (denied, or flipped by a concurrent admin) must not be
        // resurrected into an approval — no membership may be created.
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "resowner").await;
        let (joiner_id, joiner) = signup(&app, "resjoiner").await;
        let server_id = create_server(&app, &owner).await;

        // Joiner files a pending request via a bare code invite.
        let (_, body) =
            send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "code" }))).await;
        let code = body["code"].as_str().unwrap().to_string();
        let (_, body) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&joiner), None).await;
        assert_eq!(body["pending"], true);

        // Owner denies the request → it leaves 'pending'.
        let (status, _) =
            send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{joiner_id}/deny"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);

        // A now-stale approve click must be rejected (no pending row) and must NOT add a member.
        let (status, _) =
            send(&app, "POST", &format!("/api/servers/{server_id}/join-requests/{joiner_id}/approve"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "denied request is not approvable");
        assert!(!is_member(&app, &server_id, &joiner).await);
    }

    #[tokio::test]
    async fn blocks_gate_dm_creation_and_sends() {
        let (app, db) = test_app().await;
        let (alice_id, alice) = signup(&app, "blockalice").await;
        let (bob_id, bob) = signup(&app, "blockbob").await;
        share_server(&db, &[&alice_id, &bob_id]).await;

        // Bob opens a DM and both sides can send.
        let (status, body) =
            send(&app, "POST", "/api/dms", Some(&bob), Some(json!({ "participant_ids": [alice_id] }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let convo = body["conversation_id"].as_str().unwrap().to_string();
        let envelope = json!({ "ciphertext": b64(b"dm-envelope") });
        let (status, _) = send(&app, "POST", &format!("/api/dms/{convo}/messages"), Some(&bob), Some(envelope.clone())).await;
        assert_eq!(status, StatusCode::OK);

        // You can't block yourself.
        let (status, _) = send(&app, "PUT", &format!("/api/blocks/{alice_id}"), Some(&alice), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Alice blocks Bob → Bob's sends into the existing 1:1 DM are refused; so are Alice's
        // (symmetric — unblock before contacting them again); new-DM creation is refused too.
        let (status, _) = send(&app, "PUT", &format!("/api/blocks/{bob_id}"), Some(&alice), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "POST", &format!("/api/dms/{convo}/messages"), Some(&bob), Some(envelope.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "blocked sender is refused");
        let (status, _) = send(&app, "POST", &format!("/api/dms/{convo}/messages"), Some(&alice), Some(envelope.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "block is symmetric until lifted");
        let (status, _) = send(&app, "POST", "/api/dms", Some(&bob), Some(json!({ "participant_ids": [alice_id] }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "no new conversation past a block");

        // Alice sees her block list; Bob's is empty (self-scoped).
        let (_, body) = send(&app, "GET", "/api/blocks", Some(&alice), None).await;
        assert_eq!(body["blocks"].as_array().unwrap().len(), 1);
        assert_eq!(body["blocks"][0]["user_id"], bob_id.as_str());
        let (_, body) = send(&app, "GET", "/api/blocks", Some(&bob), None).await;
        assert!(body["blocks"].as_array().unwrap().is_empty());

        // Unblock → sends flow again.
        let (status, _) = send(&app, "DELETE", &format!("/api/blocks/{bob_id}"), Some(&alice), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "POST", &format!("/api/dms/{convo}/messages"), Some(&bob), Some(envelope)).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn reports_are_rate_limited_and_owner_triaged() {
        let (app, db) = test_app().await;
        let (owner_id, owner) = signup(&app, "repowner").await;
        let (subject_id, _subject) = signup(&app, "repsubject").await;
        let (reporter_id, reporter) = signup(&app, "repreporter").await;
        share_server(&db, &[&owner_id, &subject_id, &reporter_id]).await;

        // File a report with a self-disclosed excerpt (the server never decrypts anything).
        let (status, body) = send(
            &app,
            "POST",
            "/api/reports",
            Some(&reporter),
            Some(json!({ "category": "harassment", "body": "they said: ...", "subject_user_id": subject_id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let report_id = body["report_id"].as_str().unwrap().to_string();

        // Bad input is rejected.
        let (status, _) = send(&app, "POST", "/api/reports", Some(&reporter), Some(json!({ "category": "" }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // The queue is instance-owner-only. Reporter (and even a server owner) can't read it.
        let (status, _) = send(&app, "GET", "/api/reports", Some(&reporter), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('owner_user_id', $1, $2)")
            .bind(owner_id.as_bytes())
            .bind(crate::state::now_ms())
            .execute(&db)
            .await
            .unwrap();
        let (status, body) = send(&app, "GET", "/api/reports", Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let reports = body["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0]["category"], "harassment");
        assert_eq!(reports[0]["subject_username"], "repsubject");
        assert_eq!(reports[0]["status"], "open");

        // Owner resolves it.
        let (status, _) = send(&app, "POST", &format!("/api/reports/{report_id}/resolve"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (_, body) = send(&app, "GET", "/api/reports", Some(&owner), None).await;
        assert_eq!(body["reports"][0]["status"], "resolved");

        // Rate limit: 5 per hour per user (1 valid + the invalid one counted; 3 more pass, then 429).
        for _ in 0..3 {
            let (status, _) =
                send(&app, "POST", "/api/reports", Some(&reporter), Some(json!({ "category": "spam" }))).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, _) = send(&app, "POST", "/api/reports", Some(&reporter), Some(json!({ "category": "spam" }))).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }

    /// A server-scoped report is only accepted from a member of that server (kept from main's
    /// parallel implementation); an unknown server id is dropped to NULL rather than refused.
    #[tokio::test]
    async fn server_scoped_report_requires_membership() {
        let (app, db) = test_app().await;
        let (_, owner) = signup(&app, "gateowner").await;
        let (_, member) = signup(&app, "gatemember").await;
        let (_, outsider) = signup(&app, "gateoutsider").await;
        let server_id = create_server(&app, &owner).await;
        let code = token_invite(&app, &owner, &server_id).await;
        let (status, _) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);

        let report = json!({ "category": "spam", "server_id": server_id });
        let (status, _) = send(&app, "POST", "/api/reports", Some(&outsider), Some(report.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "non-member cannot file a server-scoped report");
        let (status, body) = send(&app, "POST", "/api/reports", Some(&member), Some(report)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let stored: Option<String> = sqlx::query_scalar("SELECT server_id FROM abuse_reports WHERE id = $1")
            .bind(body["report_id"].as_str().unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(stored.as_deref(), Some(server_id.as_str()));

        let (status, body) =
            send(&app, "POST", "/api/reports", Some(&outsider), Some(json!({ "category": "spam", "server_id": "nope" }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let stored: Option<String> = sqlx::query_scalar("SELECT server_id FROM abuse_reports WHERE id = $1")
            .bind(body["report_id"].as_str().unwrap())
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(stored, None);
    }

    #[tokio::test]
    async fn invite_creation_is_rate_limited() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "inviteowner").await;
        let server_id = create_server(&app, &owner).await;
        // 30 per hour pass, the 31st is refused.
        for i in 0..30 {
            let (status, _) =
                send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
            assert_eq!(status, StatusCode::OK, "invite {i} within the window");
        }
        let (status, _) =
            send(&app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    }
}

/// Regression tests for the build-43 security batch (role hierarchy, channel overrides,
/// removed authors, client-chosen message ids, member approvals, live-socket session checks).
mod security_batch {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use skwod_crypto::SignalStore;

    fn b64(v: &[u8]) -> String {
        B64.encode(v)
    }

    async fn server_with(app: &Router, owner: &str, members: &[&str]) -> (String, String) {
        let (status, body) = send(app, "POST", "/api/servers", Some(owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let server_id = body["server_id"].as_str().unwrap().to_string();
        for m in members {
            let (_, body) = send(app, "POST", &format!("/api/servers/{server_id}/invites"), Some(owner), Some(json!({ "kind": "token" }))).await;
            let code = body["code"].as_str().unwrap().to_string();
            let (status, _) = send(app, "POST", &format!("/api/invites/{code}/accept"), Some(m), None).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (_, body) = send(app, "POST", &format!("/api/servers/{server_id}/channels"), Some(owner), Some(json!({ "name_ciphertext": b64(b"c") }))).await;
        (server_id, body["channel_id"].as_str().unwrap().to_string())
    }

    async fn role(app: &Router, token: &str, server_id: &str, permissions: i64, position: i64) -> (StatusCode, String) {
        let (status, body) = send(
            app,
            "POST",
            &format!("/api/servers/{server_id}/roles"),
            Some(token),
            Some(json!({ "name_ciphertext": b64(b"r"), "permissions": permissions, "position": position })),
        )
        .await;
        (status, body["role_id"].as_str().unwrap_or_default().to_string())
    }

    async fn assign(app: &Router, token: &str, server_id: &str, user: &str, role: &str) -> StatusCode {
        send(app, "PUT", &format!("/api/servers/{server_id}/members/{user}/roles/{role}"), Some(token), None).await.0
    }

    /// H5: `position` was unchecked, so a MANAGE_ROLES moderator could create a low role, take
    /// it, and then MOVE it above the admins — or strip roles from members above them, or delete
    /// a role carrying powers they do not hold.
    #[tokio::test]
    async fn role_hierarchy_cannot_be_climbed() {
        use crate::perms::{BAN_MEMBERS, KICK_MEMBERS, MANAGE_ROLES};
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "h5owner").await;
        let (mod_id, moderator) = signup(&app, "h5mod").await;
        let (senior_id, senior) = signup(&app, "h5senior").await;
        let (server_id, _) = server_with(&app, &owner, &[&moderator, &senior]).await;
        let (_, mod_role) = role(&app, &owner, &server_id, MANAGE_ROLES, 5).await;
        let (_, senior_role) = role(&app, &owner, &server_id, MANAGE_ROLES | KICK_MEMBERS, 10).await;
        let (_, ban_role) = role(&app, &owner, &server_id, BAN_MEMBERS, 1).await;
        assert_eq!(assign(&app, &owner, &server_id, &mod_id, &mod_role).await, StatusCode::OK);
        assert_eq!(assign(&app, &owner, &server_id, &senior_id, &senior_role).await, StatusCode::OK);

        // Create: only strictly below the creator's own rank (5).
        for position in [5, 10, 1_000_000, -1] {
            assert_ne!(role(&app, &moderator, &server_id, 0, position).await.0, StatusCode::OK, "created a role at position {position}");
        }
        let (status, low) = role(&app, &moderator, &server_id, 0, 3).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(assign(&app, &moderator, &server_id, &mod_id, &low).await, StatusCode::OK);

        // THE CLIMB: move the role they now hold above everyone.
        let patch = |position: i64| json!({ "position": position });
        for position in [5, 11, 1_000_000] {
            let (status, _) = send(&app, "PATCH", &format!("/api/roles/{low}"), Some(&moderator), Some(patch(position))).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "moved a held role to position {position}");
        }
        // ...so the moderator still cannot touch the senior role or its holder.
        let (status, _) = send(&app, "PATCH", &format!("/api/roles/{senior_role}"), Some(&moderator), Some(json!({ "permissions": 0 }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{senior_id}/roles/{senior_role}"), Some(&moderator), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // A legitimate move below their rank works.
        let (status, _) = send(&app, "PATCH", &format!("/api/roles/{low}"), Some(&moderator), Some(patch(4))).await;
        assert_eq!(status, StatusCode::OK);
        // A refused update changes nothing (no half-applied write).
        let (status, _) = send(&app, "PATCH", &format!("/api/roles/{low}"), Some(&moderator), Some(json!({ "color": "#fff", "position": 99 }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, roles) = send(&app, "GET", &format!("/api/servers/{server_id}/roles"), Some(&owner), None).await;
        let low_row = roles["roles"].as_array().unwrap().iter().find(|r| r["role_id"] == low.as_str()).unwrap().clone();
        assert_eq!((low_row["position"].as_i64(), low_row["color"].is_null()), (Some(4), true));

        // remove_role: not from a member at or above you, even a role that is below you.
        assert_eq!(assign(&app, &owner, &server_id, &senior_id, &low).await, StatusCode::OK);
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{senior_id}/roles/{low}"), Some(&moderator), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "stripped a role from a higher-ranked member");
        // ...and not a role carrying powers you do not hold (ceiling), from anyone.
        assert_eq!(assign(&app, &owner, &server_id, &mod_id, &ban_role).await, StatusCode::OK);
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{mod_id}/roles/{ban_role}"), Some(&senior), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "removed a role carrying a permission the actor lacks");
        // Dropping your own lower role is fine.
        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{mod_id}/roles/{low}"), Some(&moderator), None).await;
        assert_eq!(status, StatusCode::OK);

        // delete_role / update_role: ceiling applies to the role as it stands.
        let (status, _) = send(&app, "DELETE", &format!("/api/roles/{ban_role}"), Some(&senior), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "deleted a role carrying a permission the actor lacks");
        let (status, _) = send(&app, "PATCH", &format!("/api/roles/{ban_role}"), Some(&senior), Some(json!({ "permissions": 0 }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = send(&app, "DELETE", &format!("/api/roles/{low}"), Some(&senior), None).await;
        assert_eq!(status, StatusCode::OK);
        // The owner is above all of it.
        let (status, _) = send(&app, "PATCH", &format!("/api/roles/{senior_role}"), Some(&owner), Some(patch(1_000_000))).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// M12: a channel override could target any role or user id (another server's role, a
    /// non-member) and act on members above the actor.
    #[tokio::test]
    async fn channel_overrides_need_rank_and_scope() {
        use crate::perms::{BAN_MEMBERS, KICK_MEMBERS, MANAGE_ROLES, READ_MESSAGES, SEND_MESSAGES};
        let (app, _db) = test_app().await;
        let (owner_id, owner) = signup(&app, "m12owner").await;
        let (mod_id, moderator) = signup(&app, "m12mod").await;
        let (senior_id, senior) = signup(&app, "m12senior").await;
        let (outsider_id, outsider) = signup(&app, "m12outsider").await;
        let (server_id, channel_id) = server_with(&app, &owner, &[&moderator, &senior]).await;
        let (other_server, _) = server_with(&app, &outsider, &[]).await;
        let (_, mod_role) = role(&app, &owner, &server_id, MANAGE_ROLES, 5).await;
        let (_, senior_role) = role(&app, &owner, &server_id, MANAGE_ROLES | KICK_MEMBERS, 10).await;
        let (_, low_role) = role(&app, &owner, &server_id, 0, 1).await;
        let (_, foreign_role) = role(&app, &outsider, &other_server, 0, 1).await;
        assign(&app, &owner, &server_id, &mod_id, &mod_role).await;
        assign(&app, &owner, &server_id, &senior_id, &senior_role).await;
        let put = |token: &str, body: Value| {
            let (app, path, token) = (app.clone(), format!("/api/channels/{channel_id}/overrides"), token.to_string());
            async move { send(&app, "PUT", &path, Some(&token), Some(body)).await.0 }
        };
        // Rank: not on a role or member at or above the actor (this muted the seniors).
        assert_eq!(put(&moderator, json!({ "role_id": senior_role, "allow": 0, "deny": READ_MESSAGES })).await, StatusCode::FORBIDDEN);
        assert_eq!(put(&moderator, json!({ "user_id": senior_id, "allow": 0, "deny": READ_MESSAGES })).await, StatusCode::FORBIDDEN);
        assert_eq!(put(&moderator, json!({ "role_id": mod_role, "allow": 0, "deny": SEND_MESSAGES })).await, StatusCode::FORBIDDEN, "own rank is not below");
        // Scope: the target must belong to this server.
        assert_eq!(put(&moderator, json!({ "role_id": foreign_role, "allow": 0, "deny": SEND_MESSAGES })).await, StatusCode::NOT_FOUND);
        assert_eq!(put(&moderator, json!({ "user_id": outsider_id, "allow": 0, "deny": SEND_MESSAGES })).await, StatusCode::NOT_FOUND);
        // Ceiling covers deny as well as allow.
        assert_eq!(put(&moderator, json!({ "role_id": low_role, "allow": 0, "deny": BAN_MEMBERS })).await, StatusCode::FORBIDDEN);
        // A moderator the senior DENIED sending in this channel cannot lift it by writing an
        // override on themselves (there is no self-exemption from the rank check)...
        let send_msg = || {
            let (app, path, token) = (app.clone(), format!("/api/channels/{channel_id}/messages"), moderator.clone());
            async move { send(&app, "POST", &path, Some(&token), Some(json!({ "ciphertext": b64(b"hi") }))).await.0 }
        };
        assert_eq!(send_msg().await, StatusCode::OK);
        assert_eq!(put(&senior, json!({ "user_id": mod_id, "allow": 0, "deny": SEND_MESSAGES })).await, StatusCode::OK);
        assert_eq!(send_msg().await, StatusCode::FORBIDDEN);
        assert_eq!(put(&moderator, json!({ "user_id": mod_id, "allow": SEND_MESSAGES, "deny": 0 })).await, StatusCode::FORBIDDEN, "lifted their own denial");
        assert_eq!(put(&moderator, json!({ "user_id": mod_id, "allow": 0, "deny": 0 })).await, StatusCode::FORBIDDEN, "cleared their own denial");
        assert_eq!(send_msg().await, StatusCode::FORBIDDEN, "the admin's denial no longer holds");
        // ...while the owner (top rank) may still set an override on themselves.
        assert_eq!(put(&owner, json!({ "user_id": owner_id, "allow": 0, "deny": 0 })).await, StatusCode::OK);
        // Downward, within their own powers: fine. So is the senior acting on the moderator.
        assert_eq!(put(&moderator, json!({ "role_id": low_role, "allow": 0, "deny": SEND_MESSAGES })).await, StatusCode::OK);
        assert_eq!(put(&senior, json!({ "user_id": mod_id, "allow": 0, "deny": SEND_MESSAGES })).await, StatusCode::OK);
        let _ = outsider;
    }

    /// A kicked author could still edit their old messages and attach files to them.
    #[tokio::test]
    async fn removed_author_cannot_edit_or_attach() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "rmowner").await;
        let (member_id, member) = signup(&app, "rmmember").await;
        let (server_id, channel_id) = server_with(&app, &owner, &[&member]).await;
        let (_, body) = send(&app, "POST", &format!("/api/channels/{channel_id}/messages"), Some(&member), Some(json!({ "ciphertext": b64(b"original") }))).await;
        let mid = body["message_id"].as_str().unwrap().to_string();
        let edit = json!({ "ciphertext": b64(b"rewritten after the kick") });
        let (status, _) = send(&app, "PATCH", &format!("/api/messages/{mid}"), Some(&member), Some(json!({ "ciphertext": b64(b"a normal edit") }))).await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{member_id}"), Some(&owner), None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = send(&app, "PATCH", &format!("/api/messages/{mid}"), Some(&member), Some(edit)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a kicked author edited a message");
        let attach = json!({ "blob_id": "no-such-blob", "metadata_ciphertext": b64(b"m") });
        let (status, _) = send(&app, "POST", &format!("/api/messages/{mid}/attachments"), Some(&member), Some(attach)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a kicked author reached the attach path");
        let (_, body) = send(&app, "GET", &format!("/api/channels/{channel_id}/messages"), Some(&owner), None).await;
        assert_eq!(B64.decode(body["messages"][0]["ciphertext"].as_str().unwrap()).unwrap(), b"a normal edit");
    }

    /// M3 (server half): a client-chosen message id is honoured exactly; a duplicate — of any
    /// message, by anyone — is a 409, never a different id and never an overwrite.
    #[tokio::test]
    async fn client_chosen_message_ids_are_honoured_and_never_reused() {
        let (app, _db) = test_app().await;
        let (_, owner) = signup(&app, "idowner").await;
        let (_, member) = signup(&app, "idmember").await;
        let (_, channel_id) = server_with(&app, &owner, &[&member]).await;
        let path = format!("/api/channels/{channel_id}/messages");
        let id = crate::state::new_id();
        let (status, body) = send(&app, "POST", &path, Some(&owner), Some(json!({ "ciphertext": b64(b"one"), "message_id": id }))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["message_id"], id.as_str(), "the server substituted its own id");
        // Anyone else reusing the id: 409. The AUTHOR repeating its own send (a retry from its
        // outbox, build 44) is told the message is there — and the first ciphertext stays.
        let (status, _) = send(&app, "POST", &path, Some(&member), Some(json!({ "ciphertext": b64(b"two"), "message_id": id }))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, again) = send(&app, "POST", &path, Some(&owner), Some(json!({ "ciphertext": b64(b"two"), "message_id": id }))).await;
        assert_eq!((status, &again["duplicate"], &again["created_at"]), (StatusCode::OK, &json!(true), &body["created_at"]));
        let (_, listed) = send(&app, "GET", &path, Some(&member), None).await;
        assert_eq!(listed["messages"].as_array().unwrap().len(), 1);
        assert_eq!(B64.decode(listed["messages"][0]["ciphertext"].as_str().unwrap()).unwrap(), b"one", "a repeat never overwrites");
        // Still taken after the message is deleted (an id is never recycled).
        send(&app, "DELETE", &format!("/api/messages/{id}"), Some(&owner), None).await;
        let (status, _) = send(&app, "POST", &path, Some(&member), Some(json!({ "ciphertext": b64(b"three"), "message_id": id }))).await;
        assert_eq!(status, StatusCode::CONFLICT);
        for bad in ["not-a-uuid", "", &id.to_uppercase(), "../x"] {
            let (status, _) = send(&app, "POST", &path, Some(&owner), Some(json!({ "ciphertext": b64(b"x"), "message_id": bad }))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }
        // Build-42 clients (no id) are told to update (`content_tests.rs`); nothing is stored.
        let (status, _) = send(&app, "POST", &path, Some(&member), Some(json!({ "ciphertext": b64(b"old client"), "message_id": null }))).await;
        assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
        let (status, body) = send(&app, "POST", &path, Some(&member), Some(json!({ "ciphertext": b64(b"current client") }))).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(body["message_id"], id.as_str());

        // Reactions: the listing carries the sealed emoji alongside the (opaque) tag.
        let mid = body["message_id"].as_str().unwrap();
        let react = json!({ "emoji_hash": "a".repeat(64), "emoji_ciphertext": b64(b"sealed-emoji") });
        send(&app, "POST", &format!("/api/messages/{mid}/reactions"), Some(&owner), Some(react)).await;
        let (_, body) = send(&app, "GET", &format!("/api/messages/{mid}/reactions"), Some(&member), None).await;
        assert_eq!(B64.decode(body["reactions"][0]["emoji_ciphertext"].as_str().unwrap()).unwrap(), b"sealed-emoji");
    }

    /// C1 interim (server half): the server stores and relays member approvals; it accepts one
    /// only when it is really signed by a device of the caller, and drops them on removal.
    #[tokio::test]
    async fn member_approvals_are_relayed_only_when_signed_by_the_approver_device() {
        let (app, _db) = test_app().await;
        let (owner_id, owner) = signup(&app, "apowner").await;
        let (member_id, member) = signup(&app, "apmember").await;
        let (_, outsider) = signup(&app, "apoutsider").await;
        let (server_id, _) = server_with(&app, &owner, &[&member]).await;
        let mut device = SignalStore::generate();
        let spk = device.generate_signed_prekey().unwrap();
        let lr = device.generate_last_resort_kyber().unwrap();
        let payload = json!({
            "protocol_version": 2,
            "registration_id": device.registration_id(),
            "identity_key": b64(&device.identity_key()),
            "signed_prekey": { "id": spk.id, "public": b64(&spk.public), "signature": b64(&spk.signature) },
            "last_resort_kyber_prekey": { "id": lr.id, "public": b64(&lr.public), "signature": b64(&lr.signature) },
            "one_time_prekeys": [],
            "one_time_kyber_prekeys": [],
            "delivery_key": b64(&[7u8; 32]),
            "install_hash": b64(&[1u8; 32]),
        });
        let (status, body) = send(&app, "POST", "/api/e2ee/devices/register", Some(&owner), Some(payload)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let dev = body["device_id"].as_str().unwrap().to_string();
        let path = format!("/api/servers/{server_id}/member-approvals");
        let ts = crate::state::now_ms();
        let approval = |signer: &SignalStore, user: &str, ts: i64| {
            json!({ "user_id": user, "approver_device_id": dev, "ts": ts, "signature": b64(&signer.sign_member_approval(&server_id, user, &owner_id, ts).unwrap()) })
        };
        // Not signed by the caller's device / signed for someone else / stale: refused.
        let (status, _) = send(&app, "POST", &path, Some(&owner), Some(approval(&SignalStore::generate(), &member_id, ts))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let mut wrong_user = approval(&device, &owner_id, ts);
        wrong_user["user_id"] = json!(member_id);
        assert_eq!(send(&app, "POST", &path, Some(&owner), Some(wrong_user)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, "POST", &path, Some(&owner), Some(approval(&device, &member_id, ts - 3_600_000))).await.0, StatusCode::BAD_REQUEST);
        // Not a member of the server: cannot post or read.
        assert_eq!(send(&app, "POST", &path, Some(&outsider), Some(approval(&device, &member_id, ts))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, "GET", &path, Some(&outsider), None).await.0, StatusCode::FORBIDDEN);
        // The real thing is stored and served to members, who can verify it themselves.
        assert_eq!(send(&app, "POST", &path, Some(&owner), Some(approval(&device, &member_id, ts))).await.0, StatusCode::OK);
        let (status, body) = send(&app, "GET", &path, Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        let row = &body["approvals"][0];
        assert_eq!((row["user_id"].as_str(), row["approver_user_id"].as_str(), row["approver_device_id"].as_str()), (Some(member_id.as_str()), Some(owner_id.as_str()), Some(dev.as_str())));
        assert!(skwod_crypto::link::verify_member_approval(
            &device.identity_key(),
            &server_id,
            &member_id,
            &owner_id,
            row["ts"].as_i64().unwrap(),
            &B64.decode(row["signature"].as_str().unwrap()).unwrap()
        ));
        // Removal drops it: a re-inserted member does not come back pre-approved.
        send(&app, "DELETE", &format!("/api/servers/{server_id}/members/{member_id}"), Some(&owner), None).await;
        let (_, body) = send(&app, "GET", &path, Some(&owner), None).await;
        assert!(body["approvals"].as_array().unwrap().is_empty());
    }

    /// The owner attestation is signed by the instance key over (server, owner), members only.
    #[tokio::test]
    async fn owner_attestation_is_instance_signed_and_members_only() {
        let (app, _db) = test_app().await;
        let (owner_id, owner) = signup(&app, "oaowner").await;
        let (_, member) = signup(&app, "oamember").await;
        let (_, outsider) = signup(&app, "oaoutsider").await;
        let (server_id, _) = server_with(&app, &owner, &[&member]).await;
        let (_, id) = send(&app, "GET", "/api/instance/identity", None, None).await;
        let pinned = B64.decode(id["server_public"].as_str().unwrap()).unwrap();
        let path = format!("/api/servers/{server_id}/owner-attestation");
        assert_eq!(send(&app, "GET", &path, Some(&outsider), None).await.0, StatusCode::FORBIDDEN);
        let (status, body) = send(&app, "GET", &path, Some(&member), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["owner_id"], owner_id.as_str());
        let sig = B64.decode(body["signature"].as_str().unwrap()).unwrap();
        assert!(skwod_crypto::instance::verify_owner_attestation(&pinned, &server_id, &owner_id, &sig));
        assert!(!skwod_crypto::instance::verify_owner_attestation(&pinned, &server_id, "someone-else", &sig));
        assert!(!skwod_crypto::instance::verify_owner_attestation(&pinned, "other-server", &owner_id, &sig));
    }

    /// The instance-owner attestation is signed by the instance key over the owner's id.
    #[tokio::test]
    async fn instance_owner_attestation_is_instance_signed() {
        let (app, db) = test_app().await;
        let (owner_id, owner) = signup(&app, "ioowner").await;
        let (_, member) = signup(&app, "iomember").await;
        let path = "/api/instance/owner-attestation";
        assert_eq!(send(&app, "GET", path, Some(&member), None).await.0, StatusCode::NOT_FOUND, "no owner claimed yet");
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ('owner_user_id', $1, $2)")
            .bind(owner_id.as_bytes())
            .bind(crate::state::now_ms())
            .execute(&db)
            .await
            .unwrap();
        assert_eq!(send(&app, "GET", path, None, None).await.0, StatusCode::UNAUTHORIZED);
        let (_, id) = send(&app, "GET", "/api/instance/identity", None, None).await;
        let pinned = B64.decode(id["server_public"].as_str().unwrap()).unwrap();
        for token in [&owner, &member] {
            let (status, body) = send(&app, "GET", path, Some(token), None).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["owner_id"], owner_id.as_str());
            let sig = B64.decode(body["signature"].as_str().unwrap()).unwrap();
            assert!(skwod_crypto::instance::verify_instance_owner(&pinned, &owner_id, &sig));
            assert!(!skwod_crypto::instance::verify_instance_owner(&pinned, "someone-else", &sig));
            // Not interchangeable with a server-owner attestation.
            assert!(!skwod_crypto::instance::verify_owner_attestation(&pinned, "", &owner_id, &sig));
        }
    }

    /// The owner and an administrator both ranked `i64::MAX`, and acting on a member needs a
    /// strictly higher rank — so the owner could not kick, ban or demote an administrator.
    #[tokio::test]
    async fn owner_outranks_administrators() {
        use crate::perms::ADMINISTRATOR;
        let (app, _db) = test_app().await;
        let (owner_id, owner) = signup(&app, "rkowner").await;
        let (admin_id, admin) = signup(&app, "rkadmin").await;
        let (admin2_id, admin2) = signup(&app, "rkadmin2").await;
        let (plain_id, plain) = signup(&app, "rkplain").await;
        let (server_id, channel_id) = server_with(&app, &owner, &[&admin, &admin2, &plain]).await;
        let (_, admin_role) = role(&app, &owner, &server_id, ADMINISTRATOR, 50).await;
        assert_eq!(assign(&app, &owner, &server_id, &admin_id, &admin_role).await, StatusCode::OK);
        assert_eq!(assign(&app, &owner, &server_id, &admin2_id, &admin_role).await, StatusCode::OK);
        let member = |user: &str| format!("/api/servers/{server_id}/members/{user}");
        let ban = |user: &str| format!("/api/servers/{server_id}/bans/{user}");
        let member_role = |user: &str| format!("/api/servers/{server_id}/members/{user}/roles/{admin_role}");
        let overrides = format!("/api/channels/{channel_id}/overrides");

        // An administrator acts on ordinary members...
        assert_eq!(send(&app, "DELETE", &member(&plain_id), Some(&admin), None).await.0, StatusCode::OK);
        // ...but never on the owner, nor on a fellow administrator (equals).
        assert_ne!(send(&app, "DELETE", &member(&owner_id), Some(&admin), None).await.0, StatusCode::OK);
        assert_ne!(send(&app, "POST", &ban(&owner_id), Some(&admin), Some(json!({}))).await.0, StatusCode::OK);
        assert_eq!(send(&app, "DELETE", &member(&admin2_id), Some(&admin), None).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, "DELETE", &member_role(&admin2_id), Some(&admin), None).await.0, StatusCode::FORBIDDEN);
        let deny = |user: &str| json!({ "user_id": user, "allow": 0, "deny": 1 });
        assert_eq!(send(&app, "PUT", &overrides, Some(&admin), Some(deny(&owner_id))).await.0, StatusCode::FORBIDDEN);
        // No role can be placed level with the administrators, by anyone.
        assert_ne!(role(&app, &owner, &server_id, 0, i64::MAX - 1).await.0, StatusCode::OK);
        assert_ne!(role(&app, &admin, &server_id, 0, i64::MAX - 1).await.0, StatusCode::OK);

        // THE BUG: the owner acts on an administrator — override, demote, kick, ban.
        assert_eq!(send(&app, "PUT", &overrides, Some(&owner), Some(deny(&admin_id))).await.0, StatusCode::OK);
        assert_eq!(send(&app, "DELETE", &member_role(&admin2_id), Some(&owner), None).await.0, StatusCode::OK);
        assert_eq!(send(&app, "DELETE", &member(&admin2_id), Some(&owner), None).await.0, StatusCode::OK);
        assert_eq!(send(&app, "POST", &ban(&admin_id), Some(&owner), Some(json!({}))).await.0, StatusCode::OK);
        let (_, members) = send(&app, "GET", &format!("/api/servers/{server_id}/members"), Some(&owner), None).await;
        let left: Vec<&str> = members["members"].as_array().unwrap().iter().filter_map(|m| m["user_id"].as_str()).collect();
        assert_eq!(left, vec![owner_id.as_str()], "only the owner is left");
        let _ = admin2;
        let _ = plain;
    }

    /// M6: a WebSocket authenticated once kept delivering after its session was logged out.
    #[tokio::test]
    async fn open_websocket_is_closed_when_its_session_ends() {
        use futures_util::StreamExt;
        std::env::set_var("SKWOD_WS_SESSION_RECHECK_SECS", "1");
        let (app, _db) = test_app().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = app.clone();
        tokio::spawn(async move {
            axum::serve(listener, served).await.unwrap();
        });
        let (_, token) = signup(&app, "wslogout").await;
        let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={token}")).await.expect("ws connect");
        // Still open while the session is live (two re-check periods).
        assert!(tokio::time::timeout(std::time::Duration::from_millis(2300), ws.next()).await.is_err(), "closed a live session's socket");
        let (status, _) = send(&app, "POST", "/api/auth/logout", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        // After logout the next re-check ends it: an error frame, then the close.
        let closed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut said_why = false;
            while let Some(Ok(msg)) = ws.next().await {
                if msg.is_text() && msg.to_text().unwrap().contains("session ended") {
                    said_why = true;
                }
                if msg.is_close() {
                    break;
                }
            }
            said_why
        })
        .await;
        assert_eq!(closed, Ok(true), "the socket of a logged-out session stayed open");
    }
}
