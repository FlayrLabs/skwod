//! The real router served over a real iroh connection, in one process: host + member endpoints
//! with discovery and relays disabled (loopback only), the member going through the loopback
//! proxy with ordinary HTTP/WebSocket clients — exactly what the apps do.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use skwod_net::{Discovery, LocalProxy, Member, NetConfig, PathKind, SecretKey};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::state::AppState;
use crate::tests::{send, signup};

struct World {
    /// The host's own (local, direct) access to the API.
    app: Router,
    state: AppState,
    host: skwod_net::Host,
    member: Arc<Member>,
    proxy: LocalProxy,
    http: reqwest::Client,
}

fn local_only(mut cfg: NetConfig) -> NetConfig {
    cfg.public_fallback = false;
    cfg.discovery = Discovery::None;
    cfg.portmapper = false;
    cfg
}

async fn world() -> World {
    let (_, db) = crate::tests::test_app().await;
    let blob_dir = std::env::temp_dir().join(format!("skwod-p2p-test-{}", crate::state::new_id()));
    std::fs::create_dir_all(&blob_dir).unwrap();
    let mut state = AppState::new(db, blob_dir);
    state.blob_free_floor_bytes = 0; // not a test of how full the build machine is
    let app = crate::api::router(state.clone());
    let host = crate::p2p::start_with(state.clone(), app.clone(), &local_only(NetConfig::host(SecretKey::generate()))).await.unwrap();
    let member = Member::connect(&local_only(NetConfig::member()), host.loopback_addr()).await.unwrap();
    // (The front takes credentials only, and swaps them for the token: here the credential names it.)
    let tokens: skwod_net::proxy::TokenSource = std::sync::Arc::new(|_, credential| credential.strip_prefix("front-").map(str::to_string));
    let proxy = LocalProxy::start_with_tokens(member.clone(), tokens).await.unwrap();
    World { app, state, host, member, proxy, http: reqwest::Client::new() }
}

impl World {
    /// A request from the MEMBER: plain HTTP to the loopback proxy → QUIC stream → router.
    async fn member_send(&self, method: reqwest::Method, path: &str, token: Option<&str>, body: Option<Value>) -> (u16, Value) {
        let mut req = self.http.request(method, format!("{}{path}", self.proxy.base_url()));
        if let Some(t) = token {
            req = req.bearer_auth(format!("front-{t}"));
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await.expect("request through the tunnel");
        let status = res.status().as_u16();
        (status, res.json().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn http_and_websocket_round_trip_through_the_tunnel() {
    let w = world().await;
    use reqwest::Method;

    // Health, straight through.
    let (status, body) = w.member_send(Method::GET, "/health", None, None).await;
    assert_eq!((status, body["status"].as_str()), (200, Some("ok")));

    // The host sets up a space locally; the member signs up + joins entirely over p2p.
    let (_, owner) = signup(&w.app, "p2powner").await;
    let (_, body) = send(&w.app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": B64.encode(b"s") }))).await;
    let server_id = body["server_id"].as_str().unwrap().to_string();
    let (_, body) = send(&w.app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
    let code = body["code"].as_str().unwrap().to_string();
    let (_, body) = send(&w.app, "POST", &format!("/api/servers/{server_id}/channels"), Some(&owner), Some(json!({ "name_ciphertext": B64.encode(b"c") }))).await;
    let channel_id = body["channel_id"].as_str().unwrap().to_string();

    let (status, body) = w
        .member_send(Method::POST, "/api/auth/signup", None, Some(json!({ "username": "p2pmember", "password": "correct horse" })))
        .await;
    assert_eq!(status, 200, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let (status, _) = w.member_send(Method::POST, &format!("/api/invites/{code}/accept"), Some(&token), None).await;
    assert_eq!(status, 200);
    let (status, _) = w.member_send(Method::GET, "/api/auth/me", None, None).await;
    assert_eq!(status, 401, "auth still applies inside the tunnel");

    // A session token itself is never taken over loopback: refused by the front, not sent on.
    let raw = w.http.get(format!("{}/api/auth/me", w.proxy.base_url())).bearer_auth(&token).send().await.unwrap();
    assert_eq!((raw.status().as_u16(), raw.headers().get("x-skwod-front").and_then(|v| v.to_str().ok())), (503, Some("stale-credential")));

    // WebSocket subscription through the proxy (HTTP upgrade → raw QUIC stream).
    let ws_url = format!("{}/api/ws?token={token}", w.proxy.base_url().replacen("http://", "ws://", 1));
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.expect("ws through the tunnel");
    let topic = format!("channel:{channel_id}");
    ws.send(WsMessage::Text(json!({ "type": "subscribe", "topic": topic }).to_string())).await.unwrap();
    assert_eq!(recv_frame(&mut ws).await["type"], "subscribed");

    // Host → member: the host posts locally, the member's socket gets it over p2p.
    let (status, _) =
        send(&w.app, "POST", &format!("/api/channels/{channel_id}/messages"), Some(&owner), Some(json!({ "ciphertext": B64.encode(b"from-host") }))).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let ev = recv_frame(&mut ws).await;
    assert_eq!((ev["type"].as_str(), ev["event"].as_str()), (Some("event"), Some("message")));
    assert_eq!(B64.decode(ev["payload"]["ciphertext"].as_str().unwrap()).unwrap(), b"from-host");

    // Member → host: posted through the tunnel, echoed on the member's own subscription, and
    // readable back over REST through the tunnel.
    let (status, body) = w
        .member_send(Method::POST, &format!("/api/channels/{channel_id}/messages"), Some(&token), Some(json!({ "message_id": uuid::Uuid::new_v4().to_string(), "ciphertext": B64.encode(b"from-member") })))
        .await;
    assert_eq!(status, 200, "{body}");
    let ev = recv_frame(&mut ws).await;
    assert_eq!(B64.decode(ev["payload"]["ciphertext"].as_str().unwrap()).unwrap(), b"from-member");
    let (status, body) =
        w.member_send(Method::GET, &format!("/api/channels/{channel_id}/messages?before={}&limit=10", i64::MAX), Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["messages"].as_array().unwrap().len(), 2);

    // The p2p address is discoverable by members (for building invites), not by strangers.
    let (status, body) = w.member_send(Method::GET, "/api/instance/p2p", Some(&token), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["node_id"].as_str().unwrap(), w.host.node_id().to_z32());
    assert_eq!(body["public_fallback"], false);
    // No public fallback: no n0 relay to hint at in share links (build 48).
    assert!(body["relay_url"].is_null(), "{body}");
    assert_eq!(w.member_send(Method::GET, "/api/instance/p2p", None, None).await.0, 401);

    assert_eq!(w.member.path().await.kind, PathKind::Direct);
}

async fn recv_frame(ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>) -> Value {
    // (Control frames are skipped: a message event is followed by the delivery-ack Ping.)
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next()).await.expect("frame within 5s").expect("open").expect("ok");
        if msg.is_text() {
            return serde_json::from_str(msg.to_text().unwrap()).unwrap();
        }
    }
}

#[tokio::test]
async fn independent_mode_uses_no_relay_and_no_public_dns() {
    let w = world().await;
    use skwod_net::iroh_api::Watcher;
    // Traffic has flowed…
    assert_eq!(w.member_send(reqwest::Method::GET, "/health", None, None).await.0, 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // …and neither side has a relay configured, advertised, or connected.
    for ep in [w.host.endpoint(), w.member.endpoint()] {
        assert_eq!(ep.addr().relay_urls().count(), 0);
        assert!(ep.home_relay_status().get().is_empty());
    }
    assert_eq!(w.member.path().await.kind, PathKind::Direct);
    // The production config for `--public-fallback false` plans exactly that (and keeps the DHT).
    let mut cfg = NetConfig::host(SecretKey::generate());
    cfg.public_fallback = false;
    assert!(cfg.plan().is_independent() && cfg.plan().dht_publish);
    assert!(!w.state.p2p.get().unwrap().public_fallback);
}

#[tokio::test]
async fn login_over_p2p_is_rate_limited_by_node_not_by_forged_headers() {
    let w = world().await;
    signup(&w.app, "victim").await;
    let mut limited = false;
    for i in 0..35 {
        // A different username each time (dodges the per-account window) and a different forged
        // X-Forwarded-For each time (used to dodge the per-IP window).
        let res = w
            .http
            .post(format!("{}/api/auth/login", w.proxy.base_url()))
            .header("x-forwarded-for", format!("10.9.{i}.1"))
            .json(&json!({ "username": format!("nobody{i}"), "password": "wrong-password" }))
            .send()
            .await
            .unwrap();
        if res.status().as_u16() == 429 {
            assert!(i >= 30, "limit is 30/min per node, tripped at {i}");
            limited = true;
            break;
        }
    }
    assert!(limited, "the node-id window must trip regardless of X-Forwarded-For");
}

#[tokio::test]
async fn voice_token_tells_p2p_members_to_use_the_tunnel() {
    let w = world().await;
    use reqwest::Method;
    let (_, owner) = signup(&w.app, "voiceowner").await;
    let (_, body) = send(&w.app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": B64.encode(b"s") }))).await;
    let server_id = body["server_id"].as_str().unwrap().to_string();
    let (_, body) = send(
        &w.app,
        "POST",
        &format!("/api/servers/{server_id}/channels"),
        Some(&owner),
        Some(json!({ "name_ciphertext": B64.encode(b"v"), "type": "voice" })),
    )
    .await;
    let channel_id = body["channel_id"].as_str().unwrap().to_string();
    // A local (managed-style) LiveKit: plain ws:// on loopback + a known UDP port.
    for (name, value) in [("livekit_url", "ws://127.0.0.1:7880"), ("livekit_api_key", "k"), ("livekit_api_secret", "s"), ("livekit_udp_port", "50555")] {
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, 0)")
            .bind(name)
            .bind(value.as_bytes())
            .execute(&w.state.db)
            .await
            .unwrap();
    }
    // The host's own app (local path) connects to LiveKit directly…
    let (status, body) = send(&w.app, "POST", &format!("/api/channels/{channel_id}/voice-token"), Some(&owner), None).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["tunnel"], false);
    // …a p2p caller is told to go through its tunnel.
    let (status, body) = w.member_send(Method::POST, &format!("/api/channels/{channel_id}/voice-token"), Some(&owner), None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["tunnel"], true);
    // An external SFU (wss://) is never tunnelled.
    sqlx::query("UPDATE instance_secrets SET value = $1 WHERE name = 'livekit_url'")
        .bind("wss://sfu.example.org".as_bytes())
        .execute(&w.state.db)
        .await
        .unwrap();
    let (_, body) = w.member_send(Method::POST, &format!("/api/channels/{channel_id}/voice-token"), Some(&owner), None).await;
    assert_eq!(body["tunnel"], false);
}

/// owner + member in a space with a voice channel → (owner token, member id, member token, server id, voice channel id)
async fn voice_space(w: &World, tag: &str) -> (String, String, String, String, String) {
    let (_, owner) = signup(&w.app, &format!("{tag}owner")).await;
    let (member_id, member) = signup(&w.app, &format!("{tag}member")).await;
    let (_, body) = send(&w.app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": B64.encode(b"s") }))).await;
    let server_id = body["server_id"].as_str().unwrap().to_string();
    let (_, body) = send(&w.app, "POST", &format!("/api/servers/{server_id}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
    let code = body["code"].as_str().unwrap().to_string();
    send(&w.app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
    let (_, body) = send(
        &w.app,
        "POST",
        &format!("/api/servers/{server_id}/channels"),
        Some(&owner),
        Some(json!({ "name_ciphertext": B64.encode(b"v"), "type": "voice" })),
    )
    .await;
    (owner, member_id, member, server_id, body["channel_id"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn voice_grant_is_bound_to_the_room_and_follows_membership() {
    let w = world().await;
    use crate::p2p::{room_allowed, voice_allowed};
    let (owner_a, member_id, member, server_a, voice_a) = voice_space(&w, "a").await;
    let room_a = format!("skwod-{voice_a}");
    assert!(!voice_allowed(&w.state, "not-a-token").await);
    assert!(voice_allowed(&w.state, &member).await);
    assert!(room_allowed(&w.state, &member, &room_a, &member_id).await, "member, own identity, own room");
    assert!(!room_allowed(&w.state, &member, &room_a, "someone-else").await, "can't join as another identity");
    assert!(!room_allowed(&w.state, &member, "skwod-nope", &member_id).await, "unknown room");
    assert!(!room_allowed(&w.state, &member, &voice_a, &member_id).await, "not a skwod room name");

    // A second space the same user stays in.
    let (owner_b, _, _, server_b, voice_b) = voice_space(&w, "b").await;
    let (_, body) = send(&w.app, "POST", &format!("/api/servers/{server_b}/invites"), Some(&owner_b), Some(json!({ "kind": "token" }))).await;
    send(&w.app, "POST", &format!("/api/invites/{}/accept", body["code"].as_str().unwrap()), Some(&member), None).await;
    let room_b = format!("skwod-{voice_b}");
    assert!(room_allowed(&w.state, &member, &room_b, &member_id).await);

    // Kicked from A (through the real endpoint): A's room closes, B's stays, session still valid.
    let (status, _) = send(&w.app, "DELETE", &format!("/api/servers/{server_a}/members/{member_id}"), Some(&owner_a), None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(!room_allowed(&w.state, &member, &room_a, &member_id).await, "kicked from A → no tunnel into A's room");
    assert!(room_allowed(&w.state, &member, &room_b, &member_id).await, "still a member of B");
    assert!(voice_allowed(&w.state, &member).await);

    // Logout kills everything.
    send(&w.app, "POST", "/api/auth/logout", Some(&member), None).await;
    assert!(!voice_allowed(&w.state, &member).await);
    assert!(!room_allowed(&w.state, &member, &room_b, &member_id).await);
}

#[tokio::test]
async fn kick_removes_the_participant_from_livekit_and_room_tokens_are_short_lived() {
    let w = world().await;
    let (owner, member_id, member, server_id, voice) = voice_space(&w, "k").await;

    // A stand-in LiveKit API that records RemoveParticipant calls.
    let calls: Arc<std::sync::Mutex<Vec<(String, Value)>>> = Arc::default();
    let seen = calls.clone();
    let fake = Router::new().route(
        "/twirp/livekit.RoomService/RemoveParticipant",
        axum::routing::post(move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
            let seen = seen.clone();
            async move {
                let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                seen.lock().unwrap().push((auth, body));
                axum::Json(json!({}))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, fake).await.unwrap() });
    for (name, value) in [("livekit_url", format!("ws://{addr}")), ("livekit_api_key", "k".into()), ("livekit_api_secret", "s3cret".into())] {
        sqlx::query("INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, 0)")
            .bind(name)
            .bind(value.as_bytes())
            .execute(&w.state.db)
            .await
            .unwrap();
    }

    // Tokens: minted only for members, and valid for minutes, not hours.
    let (status, body) = send(&w.app, "POST", &format!("/api/channels/{voice}/voice-token"), Some(&member), None).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    let claims = crate::voice::verify::verify(body["token"].as_str().unwrap(), "s3cret").unwrap();
    let ttl = claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap();
    assert!(ttl <= 15 * 60, "room token TTL is {ttl}s");

    // Kick → LiveKit is told to drop that identity from this server's room.
    let (status, _) = send(&w.app, "DELETE", &format!("/api/servers/{server_id}/members/{member_id}"), Some(&owner), None).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].1, json!({ "room": format!("skwod-{voice}"), "identity": member_id }));
    let admin = crate::voice::verify::verify(calls[0].0.strip_prefix("Bearer ").unwrap(), "s3cret").expect("signed with the API secret");
    assert_eq!(admin["video"]["roomAdmin"], true);
    assert_eq!(admin["video"]["room"], format!("skwod-{voice}"));

    // And no new token for the kicked user.
    let (status, _) = send(&w.app, "POST", &format!("/api/channels/{voice}/voice-token"), Some(&member), None).await;
    assert_ne!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn p2p_login_without_proof_of_work_gets_428_end_to_end() {
    use tower::ServiceExt;
    let w = world().await;
    signup(&w.app, "powuser").await;
    let member_id = [3u8; 32];
    let peer = crate::client_key::P2pPeer { node: "m".into(), node_bytes: member_id, relayed: false };
    let app = w.app.clone().layer(axum::Extension(peer));
    let login = |stamp: Option<String>| {
        let mut req = axum::http::Request::builder().method("POST").uri("/api/auth/login").header("content-type", "application/json");
        if let Some(s) = stamp {
            req = req.header("x-skwod-pow", s);
        }
        let body = json!({ "username": "powuser", "password": "definitely-wrong" }).to_string();
        app.clone().oneshot(req.body(axum::body::Body::from(body)).unwrap())
    };
    // A raw p2p client that skips the work is refused before any credential is looked at.
    let res = login(None).await.unwrap();
    assert_eq!(res.status().as_u16(), 428);
    let window: u64 = res.headers()["x-skwod-pow-window"].to_str().unwrap().parse().unwrap();
    // With the work done for the advertised window, the request reaches the credential check.
    let host = w.state.p2p.get().unwrap().node_bytes;
    let stamp = skwod_net::pow::solve(&host, &member_id, window);
    assert_eq!(login(Some(stamp.clone())).await.unwrap().status().as_u16(), 401);
    assert_eq!(login(Some(stamp)).await.unwrap().status().as_u16(), 428, "a stamp is single-use");
    // The loopback proxy does all of this for the apps (other tests log in through it unchanged).
    let (status, _) = w
        .member_send(reqwest::Method::POST, "/api/auth/login", None, Some(json!({ "username": "powuser", "password": "definitely-wrong" })))
        .await;
    assert_eq!(status, 401);
}

/// LAN announcement is an explicit opt-in, and its key reaches members only while it is on.
#[tokio::test]
async fn local_discovery_is_off_until_the_host_opts_in() {
    let state = crate::tests::test_state().await;
    let app = crate::api::router(state.clone());
    let (_user, token) = signup(&app, "member").await;

    // Default host config: nothing announced, no key anywhere.
    let host = crate::p2p::start_with(state.clone(), app.clone(), &local_only(NetConfig::host(SecretKey::generate()))).await.unwrap();
    assert!(!host.lan_advertising());
    let (_, info) = send(&app, "GET", "/api/instance/p2p", Some(&token), None).await;
    assert_eq!(info["lan_key"], Value::Null);
    assert!(!crate::p2p::invite_link_with(host.node_id(), Some("SKWD-AAAA-BBBB"), *state.lan_key.lock().unwrap()).contains("l="));
    host.shutdown().await;

    // Opted in: the key is handed to authenticated members and rides in invites.
    let mut cfg = local_only(NetConfig::host(SecretKey::generate()));
    cfg.local_discovery = true;
    cfg.lan_key = Some(skwod_net::lan::LanKey::generate());
    let host = crate::p2p::start_with(state.clone(), app.clone(), &cfg).await.unwrap();
    assert!(host.lan_advertising());
    let (_, info) = send(&app, "GET", "/api/instance/p2p", Some(&token), None).await;
    assert_eq!(info["lan_key"].as_str(), cfg.lan_key.map(|k| k.to_hex()).as_deref());
    assert_eq!(send(&app, "GET", "/api/instance/p2p", None, None).await.0, axum::http::StatusCode::UNAUTHORIZED, "never to strangers");
    let link = crate::p2p::invite_link_with(host.node_id(), Some("SKWD-AAAA-BBBB"), *state.lan_key.lock().unwrap());
    assert_eq!(skwod_net::Invite::parse(&link).unwrap().lan_key, cfg.lan_key);
    host.shutdown().await;
}

/// The host comes back on the port it was last reached at; a taken one is given up, not fatal.
#[tokio::test]
async fn the_udp_port_survives_a_restart() {
    let (_, db) = crate::tests::test_app().await;
    let data = tempfile::tempdir().unwrap();
    let key = SecretKey::generate();
    let start = |port: Option<u16>| {
        let state = AppState::new(db.clone(), data.path().join("blobs"));
        let app = crate::api::router(state.clone());
        let mut cfg = local_only(NetConfig::host(key.clone()));
        cfg.bind_port = port;
        let data = data.path().to_path_buf();
        async move { crate::p2p::start_on_last_port(state, app, cfg, &data).await.unwrap() }
    };
    let port_of = |h: &skwod_net::Host| h.endpoint().bound_sockets().iter().find(|s| s.is_ipv4()).unwrap().port();
    let host = start(None).await;
    let first = port_of(&host);
    host.shutdown().await;
    let host = start(None).await;
    assert_eq!(port_of(&host), first);
    host.shutdown().await;
    let squatter = std::net::UdpSocket::bind(("0.0.0.0", first)).unwrap();
    let host = start(None).await;
    let second = port_of(&host);
    assert_ne!(second, first);
    host.shutdown().await;
    drop(squatter);
    let host = start(None).await;
    assert_eq!(port_of(&host), second, "the new one is kept");
    host.shutdown().await;
    // The operator's choice is the operator's: used, and not remembered.
    let host = start(Some(first)).await;
    assert_eq!(port_of(&host), first);
    host.shutdown().await;
    let host = start(None).await;
    assert_eq!(port_of(&host), second);
    host.shutdown().await;
}
