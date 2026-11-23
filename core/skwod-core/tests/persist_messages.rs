//! Verifies locally-authored messages persist across an app "restart" via the encrypted cache.
//!
//! Own DM messages can't be recovered from the relay (they're encrypted to the peer), so they must
//! be cached locally. This drives the real SkwodClient against the live server: send a DM, then
//! rebuild the client from the same on-disk cache and confirm the sent message is still in history.
//!
//! Network-gated: set `SKWOD_E2E=1` to run (`SKWOD_E2E=1 cargo test -p skwod-core --test
//! persist_messages -- --nocapture`). Without it the test is a no-op so `cargo test` stays offline.

use skwod_core::{signup, SkwodClient};

#[tokio::test]
async fn own_messages_persist_across_restart() {
    if std::env::var("SKWOD_E2E").as_deref() != Ok("1") {
        eprintln!("skipping (set SKWOD_E2E=1 to run against the live server)");
        return;
    }
    let base = std::env::var("SKWOD_BASE").expect("set SKWOD_BASE to the server to test against (e.g. http://127.0.0.1:3000)");
    let stamp = std::process::id();
    let a_user = format!("ma{stamp}");
    let b_user = format!("mb{stamp}");

    let a = signup(base.clone(), a_user.clone(), "e2e-strong-pw-123".into(), String::new()).await.unwrap();
    let b = signup(base.clone(), b_user.clone(), "e2e-strong-pw-123".into(), String::new()).await.unwrap();

    let dir = std::env::temp_dir().join(format!("skwod-persist-{stamp}"));
    std::fs::create_dir_all(&dir).unwrap();
    let cache_a = dir.join("a.sqlite3").to_string_lossy().to_string();
    let key = "ab".repeat(32);

    // Alice (first launch): attach cache, register, send a DM.
    let alice = SkwodClient::new(base.clone(), a.token.clone());
    alice.attach_cache(cache_a.clone(), key.clone()).await.unwrap();
    alice.register_device().await.unwrap();
    // Bob just needs to exist + have a device for the lookup/session to work.
    let bob = SkwodClient::new(base.clone(), b.token.clone());
    // (A device is only registered with a cache to remember it in.)
    bob.attach_cache(dir.join("b.sqlite3").to_string_lossy().to_string(), key.clone()).await.unwrap();
    bob.register_device().await.unwrap();

    // Build 45: a lookup, a new conversation and a key fetch need a server in common (to a
    // stranger the server answers 404). So they meet in one first, the way people do.
    assert!(alice.find_user(b_user.clone()).await.is_err(), "a stranger cannot be looked up");
    let space = alice.create_space("Shared".into(), "general".into()).await.unwrap();
    assert!(!bob.join_space(space.invite_code.clone(), space.space_key_hex.clone(), space.channel_id.clone()).await.unwrap().pending);

    let found = alice.find_user(b_user.clone()).await.unwrap();
    let convo = alice.open_dm(found.user_id.clone()).await.unwrap();
    alice.send_dm(convo.clone(), found.user_id.clone(), found.device_id.clone(), "persisted hello".into()).await.unwrap();

    // Sanity: it's in the live client's history now.
    let before = alice.history(format!("dm:{convo}")).await;
    assert!(before.iter().any(|m| m.content.as_deref() == Some("persisted hello")), "not in live history");
    drop(alice);

    // Second "launch": brand-new client, same cache file → history restored from disk.
    let relaunched = SkwodClient::new(base.clone(), a.token.clone());
    let restored = relaunched.attach_cache(cache_a.clone(), key.clone()).await.unwrap();
    assert!(restored, "engine state should have been restored");
    let after = relaunched.history(format!("dm:{convo}")).await;
    assert!(
        after.iter().any(|m| m.content.as_deref() == Some("persisted hello") && m.author_id.as_deref() == Some("__me__")),
        "own message lost across restart: {after:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
    println!("MSG_PERSIST_OK history_len={}", after.len());
}
