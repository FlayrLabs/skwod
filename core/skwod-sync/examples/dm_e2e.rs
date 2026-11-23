//! End-to-end real-DM smoke test against a live server.
//!
//! Creates two fresh accounts, registers devices, looks each other up by username, opens a 1:1
//! conversation, sends a Double-Ratchet-encrypted message, and verifies the peer decrypts it.
//!
//! Run: `SKWOD_BASE=http://127.0.0.1:3000 cargo run -p skwod-sync --example dm_e2e`

use skwod_sync::{ApiClient, Engine, PeerId};

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(run());
}

async fn run() {
    let base = std::env::var("SKWOD_BASE").expect("set SKWOD_BASE to the server to test against (e.g. http://127.0.0.1:3000)");
    let stamp = std::process::id();
    let a_user = format!("alice{stamp}");
    let b_user = format!("bob{stamp}");

    let a = ApiClient::new(base.clone())
        .signup(&a_user, "e2e-strong-pw-123")
        .await
        .expect("alice signup");
    let b = ApiClient::new(base.clone())
        .signup(&b_user, "e2e-strong-pw-123")
        .await
        .expect("bob signup");

    let mut alice = Engine::new(ApiClient::new(base.clone()).with_token(a.token));
    let mut bob = Engine::new(ApiClient::new(base.clone()).with_token(b.token));
    alice.register().await.expect("alice register device");
    bob.register().await.expect("bob register device");

    // Alice looks Bob up and sends him an encrypted message.
    let (bob_uid, bob_dev) = alice.find_user(&b_user).await.expect("alice finds bob");
    let convo = alice.open_dm(&bob_uid).await.expect("open dm");
    let bob_peer = PeerId { user_id: bob_uid, device_id: bob_dev };
    let plaintext = "hello from alice — real E2EE DM";
    alice.send_dm(&convo, &bob_peer, plaintext).await.expect("alice sends");

    // Bob resolves the same conversation (open_dm is idempotent for 1:1), then fetches + decrypts.
    let (alice_uid, alice_dev) = bob.find_user(&a_user).await.expect("bob finds alice");
    let bob_convo = bob.open_dm(&alice_uid).await.expect("bob opens same dm");
    assert_eq!(convo, bob_convo, "1:1 conversation must be the same for both sides");
    let alice_peer = PeerId { user_id: alice_uid, device_id: alice_dev };
    let got = bob.fetch_inbound_dm(&bob_convo, &alice_peer, &b.user_id).await.expect("bob fetches");

    assert!(
        got.iter().any(|m| m.text == plaintext),
        "bob failed to decrypt alice's message; got {got:?}"
    );
    println!("NATIVE_DM_OK convo={convo} decrypted={got:?}");
}
