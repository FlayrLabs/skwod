//! Verifies libsignal session state survives a serialize → restore cycle (an app restart).
//!
//! Alice sends a DM, we snapshot her engine and rebuild a fresh engine from it, then she
//! sends another message on the SAME ratchet. Bob must decrypt both — proving the session persisted.
//!
//! Run: `SKWOD_BASE=http://127.0.0.1:3000 cargo run -p skwod-sync --example persist_e2e`

use skwod_sync::{ApiClient, Engine, LoadOutcome, PeerId};

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(run());
}

async fn run() {
    let base = std::env::var("SKWOD_BASE").expect("set SKWOD_BASE to the server to test against (e.g. http://127.0.0.1:3000)");
    let stamp = std::process::id();
    let a_user = format!("pa{stamp}");
    let b_user = format!("pb{stamp}");

    let a = ApiClient::new(base.clone()).signup(&a_user, "e2e-strong-pw-123").await.expect("alice signup");
    let b = ApiClient::new(base.clone()).signup(&b_user, "e2e-strong-pw-123").await.expect("bob signup");
    let a_token = a.token.clone();

    let mut alice = Engine::new(ApiClient::new(base.clone()).with_token(a.token));
    let mut bob = Engine::new(ApiClient::new(base.clone()).with_token(b.token));
    alice.register().await.expect("alice register");
    bob.register().await.expect("bob register");

    let (bob_uid, bob_dev) = alice.find_user(&b_user).await.expect("find bob");
    let convo = alice.open_dm(&bob_uid).await.expect("open dm");
    let bob_peer = PeerId { user_id: bob_uid, device_id: bob_dev };

    // First message establishes the ratchet.
    alice.send_dm(&convo, &bob_peer, "before restart").await.expect("send 1");

    // Snapshot Alice's engine, then rebuild a brand-new engine from the bytes (app relaunch).
    let snapshot = alice.export_state();
    drop(alice);
    let mut alice2 = Engine::new(ApiClient::new(base.clone()).with_token(a_token));
    assert_eq!(alice2.load_state(&snapshot), LoadOutcome::Restored);

    // Continue the SAME conversation on the restored ratchet.
    alice2.send_dm(&convo, &bob_peer, "after restart").await.expect("send 2");

    // Bob decrypts both messages across the restart boundary.
    let (alice_uid, alice_dev) = bob.find_user(&a_user).await.expect("find alice");
    let alice_peer = PeerId { user_id: alice_uid, device_id: alice_dev };
    let got = bob.fetch_inbound_dm(&convo, &alice_peer, &b.user_id).await.expect("bob fetch");

    assert!(got.iter().any(|m| m.text == "before restart"), "lost pre-restart message: {got:?}");
    assert!(got.iter().any(|m| m.text == "after restart"), "restored ratchet failed: {got:?}");
    println!("PERSIST_OK snapshot_bytes={} decrypted={got:?}", snapshot.len());
}
