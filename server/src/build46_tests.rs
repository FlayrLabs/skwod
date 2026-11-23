//! Build 46: the skwod's name (owner-set, device-signed, members read it signed in) and the
//! `server_deleted` event members get when a server is deleted.

use axum::http::StatusCode;
use serde_json::json;

use crate::accounts_tests::{first_device, proof};
use crate::audit_tests::{hosted, invite, member, waiting};
use crate::tests::{send, send_proved, test_state};

#[tokio::test]
async fn the_owner_names_the_skwod_signed_and_members_read_it() {
    let mut state = test_state().await;
    state.require_device_proofs = true;
    let (app, owner, host, server, _channel) = hosted(&state).await;
    let (host_store, _device) = first_device(&app, &host).await;
    let (_bob, bob) = member(&app, &host, &server, "bob").await;

    // Nothing set yet; and no name for someone who is not signed in.
    let (status, body) = send(&app, "GET", "/api/instance/name", Some(&bob), None).await;
    assert_eq!((status, body["name"].is_null()), (StatusCode::OK, true), "{body}");
    assert_eq!(send(&app, "GET", "/api/instance/name", None, None).await.0, StatusCode::UNAUTHORIZED);
    // The pre-login identity stays name-free.
    let (_, identity) = send(&app, "GET", "/api/instance/identity", None, None).await;
    assert!(identity.get("name").is_none());

    let set = |name: &str| json!({ "name": name });
    // A member may not; the owner's token alone may not (strict mode: a device signs it).
    assert_eq!(send(&app, "PUT", "/api/instance/name", Some(&bob), Some(set("Bob's"))).await.0, StatusCode::FORBIDDEN);
    assert_eq!(send(&app, "PUT", "/api/instance/name", Some(&host), Some(set("Crew"))).await.0, StatusCode::FORBIDDEN);
    // A proof for another name is not a proof for this one.
    let other = proof(&host_store, "instance-name", &owner, "", b"Other");
    assert_eq!(send_proved(&app, "PUT", "/api/instance/name", &host, Some(set("Crew")), &other).await.0, StatusCode::FORBIDDEN);
    let signed = proof(&host_store, "instance-name", &owner, "", b"Weekend Crew");
    let (status, body) = send_proved(&app, "PUT", "/api/instance/name", &host, Some(set("Weekend Crew")), &signed).await;
    assert_eq!((status, body["name"].as_str()), (StatusCode::OK, Some("Weekend Crew")), "{body}");
    let (_, body) = send(&app, "GET", "/api/instance/name", Some(&bob), None).await;
    assert_eq!(body["name"].as_str(), Some("Weekend Crew"));
    // An account still in the waiting room is not a member yet: it does not read the name.
    let code = invite(&app, &host, &server, json!({ "kind": "code" })).await;
    let (_carol, carol) = waiting(&app, &code, "carol").await;
    let (status, body) = send(&app, "GET", "/api/instance/name", Some(&carol), None).await;
    assert_eq!((status, body["error"].as_str()), (StatusCode::FORBIDDEN, Some("waiting for approval")), "{body}");
    assert!(body.get("name").is_none(), "{body}");

    // Hidden characters and over-long names are refused (before anything is stored).
    for bad in ["Crew\u{202E}lab", "a\u{200B}b", "line\nbreak", &"x".repeat(65)] {
        let p = proof(&host_store, "instance-name", &owner, "", bad.as_bytes());
        assert_eq!(send_proved(&app, "PUT", "/api/instance/name", &host, Some(set(bad)), &p).await.0, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    // Empty clears it.
    let p = proof(&host_store, "instance-name", &owner, "", b"");
    assert_eq!(send_proved(&app, "PUT", "/api/instance/name", &host, Some(set("")), &p).await.0, StatusCode::OK);
    let (_, body) = send(&app, "GET", "/api/instance/name", Some(&bob), None).await;
    assert!(body["name"].is_null());
}

#[test]
fn instance_names_are_cleaned() {
    use crate::structure::clean_instance_name;
    assert_eq!(clean_instance_name("  Crew  ").unwrap().as_deref(), Some("Crew"));
    assert_eq!(clean_instance_name("   ").unwrap(), None);
    assert!(clean_instance_name("a\u{2066}b").is_err());
    assert!(clean_instance_name(&"é".repeat(64)).unwrap().is_some());
    assert!(clean_instance_name(&"é".repeat(65)).is_err());
}

#[tokio::test]
async fn deleting_a_server_tells_each_member_on_their_own_topic() {
    let state = test_state().await;
    let (app, owner, host, server, _channel) = hosted(&state).await;
    let (bob_id, _bob) = member(&app, &host, &server, "bob").await;
    let mut bus = state.rt.subscribe();
    assert_eq!(send(&app, "DELETE", &format!("/api/servers/{server}"), Some(&host), None).await.0, StatusCode::OK);
    let events: Vec<_> = std::iter::from_fn(|| bus.try_recv().ok()).collect();
    for user in [&owner, &bob_id] {
        assert!(
            events.iter().any(|ev| ev.topic == crate::rt::user_topic(user) && ev.frame.contains("server_deleted") && ev.frame.contains(&server)),
            "{user} was told"
        );
    }
}
