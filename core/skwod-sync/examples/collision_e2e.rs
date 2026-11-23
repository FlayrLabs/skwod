//! Regression test for simultaneous DM initiation (both peers send their first message before
//! either receives the other's). Without deterministic resolution this permanently breaks the
//! session; with it, both sides converge on one session and exchange messages in both directions.
//!
//! Run: `SKWOD_BASE=http://127.0.0.1:3000 cargo run -p skwod-sync --example collision_e2e`

use skwod_sync::{ApiClient, Engine, PeerId};

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(run());
}

async fn run() {
    let base = std::env::var("SKWOD_BASE").expect("set SKWOD_BASE to the server to test against (e.g. http://127.0.0.1:3000)");
    let stamp = std::process::id();
    let a_user = format!("ca{stamp}");
    let b_user = format!("cb{stamp}");

    let a = ApiClient::new(base.clone()).signup(&a_user, "e2e-strong-pw-123").await.unwrap();
    let b = ApiClient::new(base.clone()).signup(&b_user, "e2e-strong-pw-123").await.unwrap();

    let mut alice = Engine::new(ApiClient::new(base.clone()).with_token(a.token));
    let mut bob = Engine::new(ApiClient::new(base.clone()).with_token(b.token));
    alice.register().await.unwrap();
    bob.register().await.unwrap();

    let (bob_uid, bob_dev) = alice.find_user(&b_user).await.unwrap();
    let (alice_uid, alice_dev) = bob.find_user(&a_user).await.unwrap();
    let bob_peer = PeerId { user_id: bob_uid.clone(), device_id: bob_dev };
    let alice_peer = PeerId { user_id: alice_uid.clone(), device_id: alice_dev };
    let convo = alice.open_dm(&bob_uid).await.unwrap();
    assert_eq!(convo, bob.open_dm(&alice_uid).await.unwrap());

    // BOTH initiate before either fetches — the collision case.
    alice.send_dm(&convo, &bob_peer, "from alice").await.unwrap();
    bob.send_dm(&convo, &alice_peer, "from bob").await.unwrap();

    // Each resolves the collision and decrypts the other's first message.
    let alice_got = alice.fetch_inbound_dm(&convo, &bob_peer, &a.user_id).await.unwrap();
    let bob_got = bob.fetch_inbound_dm(&convo, &alice_peer, &b.user_id).await.unwrap();
    assert!(alice_got.iter().any(|m| m.text == "from bob"), "alice lost bob's first msg: {alice_got:?}");
    assert!(bob_got.iter().any(|m| m.text == "from alice"), "bob lost alice's first msg: {bob_got:?}");

    // The session has converged: follow-ups work in both directions.
    alice.send_dm(&convo, &bob_peer, "alice second").await.unwrap();
    bob.send_dm(&convo, &alice_peer, "bob second").await.unwrap();
    let alice_got2 = alice.fetch_inbound_dm(&convo, &bob_peer, &a.user_id).await.unwrap();
    let bob_got2 = bob.fetch_inbound_dm(&convo, &alice_peer, &b.user_id).await.unwrap();
    assert!(alice_got2.iter().any(|m| m.text == "bob second"), "convergence failed for alice: {alice_got2:?}");
    assert!(bob_got2.iter().any(|m| m.text == "alice second"), "convergence failed for bob: {bob_got2:?}");

    println!("COLLISION_OK both directions converged");
}
