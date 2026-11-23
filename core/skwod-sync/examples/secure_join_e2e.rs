//! End-to-end secure-join through the engine against a live server: host creates a space, mints a
//! code invite, a joiner redeems it (→ pending), host sees + approves it, joiner becomes a member.
//!
//! Run: `SKWOD_BASE=http://127.0.0.1:4100 cargo run -p skwod-sync --example secure_join_e2e`

use skwod_sync::{ApiClient, Engine};

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(run());
}

async fn run() {
    let base = std::env::var("SKWOD_BASE").unwrap_or_else(|_| "http://127.0.0.1:4100".to_string());
    let code = std::env::var("JOIN_CODE").ok();
    let stamp = std::process::id();
    let host_user = format!("host{stamp}");
    let join_user = format!("join{stamp}");

    // Signups (a fresh/uninitialized instance allows open signup; an init'd one needs JOIN_CODE).
    let host_signup = signup(&base, &host_user, code.as_deref()).await;
    let join_signup = signup(&base, &join_user, code.as_deref()).await;

    let mut host = Engine::new(ApiClient::new(base.clone()).with_token(host_signup.token));
    let mut joiner = Engine::new(ApiClient::new(base.clone()).with_token(join_signup.token));
    host.register().await.expect("host register");
    joiner.register().await.expect("joiner register");

    // Host creates a space + a code (approval-required) invite.
    let space = host.create_space("Secure Crew", "general").await.expect("create space");
    let invite = host.invite_to_space(&space.server_id, "code", None).await.expect("mint code invite");

    // Joiner redeems it → pending (not a member yet).
    let outcome = joiner.join_space(&invite, &space.space_key_hex, &space.channel_id).await.expect("join");
    assert!(outcome.pending, "a code invite must be pending approval, got {:?}", outcome.pending);

    // Host sees the pending request and approves it.
    let reqs = host.list_join_requests(&space.server_id).await.expect("list requests");
    assert!(reqs.iter().any(|(_, name)| name == &join_user), "host should see the request: {reqs:?}");
    let (join_uid, _) = reqs.iter().find(|(_, n)| n == &join_user).unwrap().clone();
    host.approve_join_request(&space.server_id, &join_uid).await.expect("approve");

    // The queue is now empty.
    let after = host.list_join_requests(&space.server_id).await.expect("list after");
    assert!(!after.iter().any(|(_, name)| name == &join_user), "request should be cleared: {after:?}");

    println!("SECURE_JOIN_OK server={} approved={}", space.server_id, join_user);
}

struct S { token: String }
async fn signup(base: &str, user: &str, code: Option<&str>) -> S {
    let api = ApiClient::new(base.to_string());
    let s = match code {
        Some(c) => api.signup_with_code(user, "e2e-strong-pw-123", Some(c)).await,
        None => api.signup(user, "e2e-strong-pw-123").await,
    }
    .expect("signup");
    S { token: s.token }
}
