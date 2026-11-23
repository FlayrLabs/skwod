//! Build 47: who is in a voice room (`voice_state.rs`) — read from LiveKit's room service, kept
//! in memory, published to the server's members only.

use axum::http::StatusCode;
use axum::Router;
use base64::Engine;
use serde_json::{json, Value};

use crate::state::AppState;
use crate::tests::{send, signup, test_state};
use crate::voice_state::{apply_listing, parse_participant, reconcile_once};

fn b64(v: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

struct World {
    app: Router,
    server: String,
    channel: String,
    owner_id: String,
    owner: String,
    member_id: String,
    member: String,
    outsider_id: String,
    outsider: String,
}

/// An owner and a member in one server with a voice channel; an outsider in none.
async fn world(state: &AppState) -> World {
    let app = crate::api::router(state.clone());
    let (owner_id, owner) = signup(&app, "voiceowner").await;
    let (member_id, member) = signup(&app, "voicemember").await;
    let (outsider_id, outsider) = signup(&app, "outsider").await;
    let (_, body) = send(&app, "POST", "/api/servers", Some(&owner), Some(json!({ "name_ciphertext": b64(b"s") }))).await;
    let server = body["server_id"].as_str().unwrap().to_string();
    let (_, body) = send(&app, "POST", &format!("/api/servers/{server}/invites"), Some(&owner), Some(json!({ "kind": "token" }))).await;
    let code = body["code"].as_str().unwrap().to_string();
    let (status, res) = send(&app, "POST", &format!("/api/invites/{code}/accept"), Some(&member), None).await;
    assert_eq!(status, StatusCode::OK, "{res}");
    let (_, body) = send(
        &app,
        "POST",
        &format!("/api/servers/{server}/channels"),
        Some(&owner),
        Some(json!({ "name_ciphertext": b64(b"voice"), "type": "voice" })),
    )
    .await;
    let channel = body["channel_id"].as_str().unwrap().to_string();
    World { app, server, channel, owner_id, owner, member_id, member, outsider_id, outsider }
}

fn participant(identity: &str, joined_at: &str, tracks: Value) -> Value {
    json!({ "sid": "PA_x", "identity": identity, "state": "ACTIVE", "joined_at": joined_at, "tracks": tracks })
}

/// Every `voice_state` event published so far, as (topic, payload).
fn drain(bus: &mut tokio::sync::broadcast::Receiver<crate::rt::RtEvent>) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    while let Ok(e) = bus.try_recv() {
        let frame: Value = serde_json::from_str(&e.frame).unwrap();
        if frame["event"] == "voice_state" {
            out.push((e.topic.clone(), frame["payload"].clone()));
        }
    }
    out
}

fn ids(payload: &Value) -> Vec<String> {
    payload["participants"].as_array().unwrap().iter().map(|p| p["user_id"].as_str().unwrap().to_string()).collect()
}

#[test]
fn a_participant_is_read_whichever_way_livekit_spells_it() {
    let p = participant(
        "u1",
        "1700000000",
        json!([
            { "type": "AUDIO", "source": "MICROPHONE", "muted": true },
            { "type": "VIDEO", "source": "CAMERA", "muted": false },
        ]),
    );
    let m = parse_participant(&p).unwrap();
    assert_eq!((m.user_id.as_str(), m.muted, m.video, m.screen, m.joined_at), ("u1", true, true, false, 1_700_000_000));
    // Numeric enums and lowerCamelCase.
    let p = json!({ "identity": "u2", "state": 2, "joinedAt": 5, "tracks": [{ "type": 0, "source": 2 }, { "type": 1, "source": 3 }] });
    let m = parse_participant(&p).unwrap();
    assert_eq!((m.muted, m.video, m.screen, m.joined_at), (false, false, true, 5));
    // No microphone at all is muted; a disconnected or nameless one is not in the room.
    assert!(parse_participant(&participant("u3", "1", json!([]))).unwrap().muted);
    assert!(parse_participant(&json!({ "identity": "u4", "state": "DISCONNECTED" })).is_none());
    assert!(parse_participant(&json!({ "identity": "", "state": "ACTIVE" })).is_none());
}

#[tokio::test]
async fn joins_and_leaves_reach_the_servers_members_and_nobody_else() {
    let state = test_state().await;
    let w = world(&state).await;
    let mut bus = state.rt.subscribe();
    let room = format!("skwod-{}", w.channel);
    let mic = json!([{ "type": "AUDIO", "source": "MICROPHONE", "muted": false }]);

    // The owner and the member join; an identity that is not a member of this server (an
    // external SFU's say-so), and a room that is no voice channel here, are not listed.
    let listing = vec![
        (
            room.clone(),
            vec![participant(&w.member_id, "20", mic.clone()), participant(&w.owner_id, "10", json!([])), participant(&w.outsider_id, "5", mic.clone())],
        ),
        ("skwod-not-a-channel".to_string(), vec![participant(&w.owner_id, "1", json!([]))]),
        ("someone-elses-room".to_string(), vec![participant(&w.owner_id, "1", json!([]))]),
    ];
    assert!(apply_listing(&state, listing.clone()).await);
    let events = drain(&mut bus);
    assert_eq!(events.len(), 1, "{events:?}");
    let (topic, payload) = &events[0];
    assert_eq!(topic, &format!("server:{}", w.server), "only on the server's own topic");
    assert_eq!(payload["channel_id"], w.channel.as_str());
    assert_eq!(ids(payload), vec![w.owner_id.clone(), w.member_id.clone()], "in join order; the outsider is not listed");
    assert_eq!(payload["participants"][0]["muted"], true);
    assert_eq!(payload["participants"][1]["muted"], false);

    // The same answer again publishes nothing.
    apply_listing(&state, listing).await;
    assert!(drain(&mut bus).is_empty(), "only a change is published");

    // Members read it; someone who is not in the server does not.
    let path = format!("/api/servers/{}/voice-state", w.server);
    let (status, body) = send(&w.app, "GET", &path, Some(&w.member), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["channels"][0]["channel_id"], w.channel.as_str());
    assert_eq!(body["channels"][0]["participants"].as_array().unwrap().len(), 2);
    assert_eq!(send(&w.app, "GET", &path, Some(&w.outsider), None).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&w.app, "GET", &path, None, None).await.0, StatusCode::UNAUTHORIZED);

    // The member leaves the call.
    apply_listing(&state, vec![(room.clone(), vec![participant(&w.owner_id, "10", json!([]))])]).await;
    let events = drain(&mut bus);
    assert_eq!(ids(&events[0].1), vec![w.owner_id.clone()]);

    // The room empties (LiveKit closes it): an empty roster is published, and nothing is listed.
    assert!(!apply_listing(&state, Vec::new()).await);
    let events = drain(&mut bus);
    assert_eq!(events.len(), 1);
    assert!(ids(&events[0].1).is_empty());
    let (_, body) = send(&w.app, "GET", &path, Some(&w.owner), None).await;
    assert_eq!(body["channels"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn someone_removed_from_the_server_drops_off_the_list() {
    let state = test_state().await;
    let w = world(&state).await;
    let room = format!("skwod-{}", w.channel);
    let both = vec![(room.clone(), vec![participant(&w.owner_id, "1", json!([])), participant(&w.member_id, "2", json!([]))])];
    apply_listing(&state, both.clone()).await;
    assert_eq!(state.voice_states.snapshot(&w.server).len(), 1);
    // Kicked — and, for the moment, the SFU still lists them: they are not shown any more.
    let (status, body) = send(&w.app, "DELETE", &format!("/api/servers/{}/members/{}", w.server, w.member_id), Some(&w.owner), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    apply_listing(&state, both).await;
    assert_eq!(ids(&state.voice_states.snapshot(&w.server)[0]), vec![w.owner_id.clone()]);
}

/// A fake LiveKit room service: checks the server's admin token like LiveKit does and answers
/// with whoever `people` holds for the one room.
async fn fake_livekit(room: String, people: std::sync::Arc<std::sync::Mutex<Vec<Value>>>) -> std::net::SocketAddr {
    use axum::routing::post;
    async fn grant(headers: &axum::http::HeaderMap) -> Option<Value> {
        let token = headers.get("authorization")?.to_str().ok()?.strip_prefix("Bearer ")?;
        let claims = crate::voice::verify::verify(token, "test-secret-value")?;
        (claims["iss"] == "lk_testkey").then(|| claims["video"].clone())
    }
    let r1 = room.clone();
    let app = Router::new()
        .route(
            "/twirp/livekit.RoomService/ListRooms",
            post(move |headers: axum::http::HeaderMap| {
                let room = r1.clone();
                async move {
                    match grant(&headers).await {
                        Some(g) if g["roomList"] == true => (StatusCode::OK, axum::Json(json!({ "rooms": [{ "name": room, "num_participants": 1 }] }))),
                        _ => (StatusCode::UNAUTHORIZED, axum::Json(json!({ "code": "unauthenticated" }))),
                    }
                }
            }),
        )
        .route(
            "/twirp/livekit.RoomService/ListParticipants",
            post(move |headers: axum::http::HeaderMap, axum::Json(body): axum::Json<Value>| {
                let (room, people) = (room.clone(), people.clone());
                async move {
                    match grant(&headers).await {
                        Some(g) if g["roomAdmin"] == true && g["room"] == room.as_str() && body["room"] == room.as_str() => {
                            let list = people.lock().unwrap().clone();
                            (StatusCode::OK, axum::Json(json!({ "participants": list })))
                        }
                        _ => (StatusCode::UNAUTHORIZED, axum::Json(json!({ "code": "unauthenticated" }))),
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

async fn put_secret(state: &AppState, name: &str, value: &str) {
    sqlx::query(
        "INSERT INTO instance_secrets (name, value, created_at) VALUES ($1, $2, 0)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value",
    )
    .bind(name)
    .bind(value.as_bytes())
    .execute(&state.db)
    .await
    .unwrap();
}

#[tokio::test]
async fn the_list_comes_from_the_sfus_room_service_and_a_new_socket_gets_it_at_once() {
    use futures_util::{SinkExt, StreamExt};
    let state = test_state().await;
    let w = world(&state).await;
    let people = std::sync::Arc::new(std::sync::Mutex::new(vec![participant(&w.member_id, "3", json!([]))]));
    let lk = fake_livekit(format!("skwod-{}", w.channel), people.clone()).await;
    // Voice not configured: nobody is in any call (and the SFU is never asked).
    assert!(!reconcile_once(&state).await);
    put_secret(&state, "livekit_api_key", "lk_testkey").await;
    put_secret(&state, "livekit_api_secret", "test-secret-value").await;
    put_secret(&state, "livekit_url", &format!("ws://{lk}")).await;

    // Minting a token is no joining: nobody is listed until the SFU says so.
    let (status, _) = send(&w.app, "POST", &format!("/api/channels/{}/voice-token", w.channel), Some(&w.member), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(state.voice_states.snapshot(&w.server).is_empty());

    assert!(reconcile_once(&state).await);
    assert_eq!(ids(&state.voice_states.snapshot(&w.server)[0]), vec![w.member_id.clone()]);

    // A member's socket subscribing to the server's topic is handed the list right away.
    let addr = crate::basics_tests::serve(&state).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={}", w.owner)).await.unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Text(json!({ "type": "subscribe", "topic": format!("server:{}", w.server) }).to_string()))
        .await
        .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(Ok(m)) = ws.next().await {
            if let Ok(text) = m.to_text() {
                let v: Value = serde_json::from_str(text).unwrap_or_default();
                if v["event"] == "voice_state" {
                    return v;
                }
            }
        }
        Value::Null
    })
    .await
    .expect("voice_state on subscribe");
    assert_eq!(got["topic"], format!("server:{}", w.server));
    assert_eq!(ids(&got["payload"]), vec![w.member_id.clone()]);
    // An outsider cannot subscribe to that topic at all (so is never handed it).
    let (mut other, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={}", w.outsider)).await.unwrap();
    other
        .send(tokio_tungstenite::tungstenite::Message::Text(json!({ "type": "subscribe", "topic": format!("server:{}", w.server) }).to_string()))
        .await
        .unwrap();
    let refused = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(Ok(m)) = other.next().await {
            let v: Value = serde_json::from_str(m.to_text().unwrap_or("")).unwrap_or_default();
            assert_ne!(v["event"], "voice_state", "an outsider is never handed the list");
            if v["type"] == "error" {
                return true;
            }
        }
        false
    })
    .await
    .unwrap();
    assert!(refused);

    // The SFU goes away (the managed LiveKit was withdrawn): nobody is in a call any more.
    sqlx::query("DELETE FROM instance_secrets WHERE name = 'livekit_url'").execute(&state.db).await.unwrap();
    assert!(!reconcile_once(&state).await);
    assert!(state.voice_states.snapshot(&w.server).is_empty());
}

/// Read the next `voice_state` frame on a socket (or `Null` after `wait`).
async fn next_voice_state<S>(ws: &mut S, wait: std::time::Duration) -> Value
where
    S: futures_util::Stream<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    use futures_util::StreamExt;
    tokio::time::timeout(wait, async {
        while let Some(Ok(m)) = ws.next().await {
            let v: Value = serde_json::from_str(m.to_text().unwrap_or("")).unwrap_or_default();
            if v["event"] == "voice_state" {
                return v;
            }
        }
        Value::Null
    })
    .await
    .unwrap_or(Value::Null)
}

#[tokio::test]
async fn who_is_in_a_private_voice_channel_reaches_only_those_who_may_see_it() {
    use futures_util::SinkExt;
    let state = test_state().await;
    let w = world(&state).await;
    // A second voice channel the member may not see or join.
    let (_, body) = send(
        &w.app,
        "POST",
        &format!("/api/servers/{}/channels", w.server),
        Some(&w.owner),
        Some(json!({ "name_ciphertext": b64(b"staff"), "type": "voice" })),
    )
    .await;
    let private = body["channel_id"].as_str().unwrap().to_string();
    let deny = crate::perms::READ_MESSAGES | crate::perms::CONNECT_VOICE;
    let (status, res) = send(
        &w.app,
        "PUT",
        &format!("/api/channels/{private}/overrides"),
        Some(&w.owner),
        Some(json!({ "user_id": w.member_id, "allow": 0, "deny": deny })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{res}");

    // The owner is in the private room; the member is in the open one.
    apply_listing(
        &state,
        vec![
            (format!("skwod-{private}"), vec![participant(&w.owner_id, "1", json!([]))]),
            (format!("skwod-{}", w.channel), vec![participant(&w.member_id, "2", json!([]))]),
        ],
    )
    .await;

    // REST: the member reads only the open room; the owner reads both.
    let path = format!("/api/servers/{}/voice-state", w.server);
    let (_, body) = send(&w.app, "GET", &path, Some(&w.member), None).await;
    let seen: Vec<&str> = body["channels"].as_array().unwrap().iter().map(|c| c["channel_id"].as_str().unwrap()).collect();
    assert_eq!(seen, vec![w.channel.as_str()], "{body}");
    let (_, body) = send(&w.app, "GET", &path, Some(&w.owner), None).await;
    assert_eq!(body["channels"].as_array().unwrap().len(), 2, "{body}");

    // Replay on subscribe: the member is handed the open room only.
    let addr = crate::basics_tests::serve(&state).await;
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/api/ws?token={}", w.member)).await.unwrap();
    ws.send(tokio_tungstenite::tungstenite::Message::Text(json!({ "type": "subscribe", "topic": format!("server:{}", w.server) }).to_string()))
        .await
        .unwrap();
    let first = next_voice_state(&mut ws, std::time::Duration::from_secs(5)).await;
    assert_eq!(first["payload"]["channel_id"], w.channel.as_str());
    assert_eq!(next_voice_state(&mut ws, std::time::Duration::from_millis(500)).await, Value::Null, "nothing about the private room");

    // Live: a change in the private room is never handed to the member; the next change in
    // the open room is.
    apply_listing(
        &state,
        vec![
            (format!("skwod-{private}"), vec![participant(&w.owner_id, "1", json!([])), participant(&w.outsider_id, "3", json!([]))]),
            (format!("skwod-{}", w.channel), vec![participant(&w.member_id, "2", json!([]))]),
        ],
    )
    .await;
    // (The outsider is no member: the private roster did not change, nothing was published.)
    let owner_only = vec![(format!("skwod-{private}"), vec![]), (format!("skwod-{}", w.channel), vec![participant(&w.member_id, "2", json!([]))])];
    apply_listing(&state, owner_only).await; // the private room empties
    apply_listing(&state, Vec::new()).await; // then the open one
    let got = next_voice_state(&mut ws, std::time::Duration::from_secs(5)).await;
    assert_eq!(got["payload"]["channel_id"], w.channel.as_str(), "the private room's change was skipped: {got}");
    assert!(ids(&got["payload"]).is_empty());
}
