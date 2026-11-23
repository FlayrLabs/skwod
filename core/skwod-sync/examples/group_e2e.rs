//! End-to-end real group-channel test against a live server.
//!
//! Alice creates an E2EE space (server + channel with encrypted names) and an invite. Bob joins
//! with the invite + space key. They exchange sender keys over their DM, then both post channel
//! messages encrypted with Sender Keys — and each decrypts the other's.
//!
//! Run: `SKWOD_BASE=http://127.0.0.1:3000 cargo run -p skwod-sync --example group_e2e`

use skwod_sync::{ApiClient, Engine, PeerId};

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(run());
}

async fn run() {
    let base = std::env::var("SKWOD_BASE").expect("set SKWOD_BASE to the server to test against (e.g. http://127.0.0.1:3000)");
    let stamp = std::process::id();
    let a_user = format!("ga{stamp}");
    let b_user = format!("gb{stamp}");

    let a = ApiClient::new(base.clone()).signup(&a_user, "e2e-strong-pw-123").await.expect("alice signup");
    let b = ApiClient::new(base.clone()).signup(&b_user, "e2e-strong-pw-123").await.expect("bob signup");

    let mut alice = Engine::new(ApiClient::new(base.clone()).with_token(a.token));
    let mut bob = Engine::new(ApiClient::new(base.clone()).with_token(b.token));
    let alice_dev = alice.register().await.expect("alice register");
    let bob_dev = bob.register().await.expect("bob register");

    // Alice creates a space with encrypted names + an invite.
    let space = alice.create_space("Weekend Crew", "general").await.expect("create space");

    // Bob joins with the invite and the shared space key, and can read the channel name.
    bob.join_space(&space.invite_code, &space.space_key_hex, &space.channel_id).await.expect("bob joins");

    // Peers resolve each other's devices for the sender-key handshake (over DM).
    let (bob_uid, bob_dev_id) = alice.find_user(&b_user).await.expect("alice finds bob");
    assert_eq!(bob_dev_id, bob_dev);
    let (alice_uid, alice_dev_id) = bob.find_user(&a_user).await.expect("bob finds alice");
    assert_eq!(alice_dev_id, alice_dev);
    let bob_peer = PeerId { user_id: bob_uid.clone(), device_id: bob_dev_id };
    let alice_peer = PeerId { user_id: alice_uid.clone(), device_id: alice_dev_id };

    // Sender-key handshake over DM. Sequence each direction fully (send → peer drains) before the
    // reverse, so the Double Ratchet is bidirectional over one session (no double-initiation).
    alice.share_group_key(&space.channel_id, &bob_peer).await.expect("alice shares key");
    let bob_convo = bob.open_dm(&alice_uid).await.unwrap();
    let _ = bob.fetch_inbound_dm(&bob_convo, &alice_peer, &b.user_id).await.expect("bob drains dm");

    bob.share_group_key(&space.channel_id, &alice_peer).await.expect("bob shares key");
    let alice_convo = alice.open_dm(&bob_uid).await.unwrap();
    let _ = alice.fetch_inbound_dm(&alice_convo, &bob_peer, &a.user_id).await.expect("alice drains dm");

    // Both post encrypted channel messages.
    alice.send_channel_message(&space.channel_id, "welcome to the channel").await.expect("alice posts");
    bob.send_channel_message(&space.channel_id, "glad to be here").await.expect("bob posts");

    // Each decrypts the other's channel message.
    let alice_sees = alice.fetch_channel_messages(&space.channel_id, &a.user_id).await.expect("alice fetch");
    let bob_sees = bob.fetch_channel_messages(&space.channel_id, &b.user_id).await.expect("bob fetch");

    assert!(alice_sees.iter().any(|m| m.text == "glad to be here"), "alice didn't decrypt bob's msg: {alice_sees:?}");
    assert!(bob_sees.iter().any(|m| m.text == "welcome to the channel"), "bob didn't decrypt alice's msg: {bob_sees:?}");

    println!("GROUP_OK space={} channel={}", space.server_id, space.channel_id);
    println!("  alice sees: {alice_sees:?}");
    println!("  bob sees:   {bob_sees:?}");
}
