use skwod_sync::{ApiClient, Engine, PeerId};
fn main() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(run());
}
async fn run() {
    let base = std::env::var("SKWOD_BASE").unwrap();
    let code = std::env::var("JOIN_CODE").ok();
    let s = std::process::id();
    let a = signup(&base, &format!("sa{s}"), code.as_deref()).await;
    let b = signup(&base, &format!("sb{s}"), code.as_deref()).await;
    let mut alice = Engine::new(ApiClient::new(base.clone()).with_token(a.1));
    let mut bob = Engine::new(ApiClient::new(base.clone()).with_token(b.1));
    alice.register().await.unwrap();
    bob.register().await.unwrap();
    let (buid, bdev) = alice.find_user(&format!("sb{s}")).await.unwrap();
    let (auid, adev) = bob.find_user(&format!("sa{s}")).await.unwrap();
    let sn_a = alice.safety_number(&a.0, &PeerId{user_id:buid, device_id:bdev}).await.unwrap();
    let sn_b = bob.safety_number(&b.0, &PeerId{user_id:auid, device_id:adev}).await.unwrap();
    assert_eq!(sn_a, sn_b, "safety numbers must match on both sides");
    assert_eq!(sn_a.len(), 60);
    println!("SAFETY_OK both sides = {sn_a}");
}
async fn signup(base:&str, u:&str, code:Option<&str>) -> (String,String) {
    let api = ApiClient::new(base.to_string());
    let s = match code {
        Some(c) => api.signup_with_code(u, "e2e-strong-pw-123", Some(c)).await,
        None => api.signup(u, "e2e-strong-pw-123").await,
    }.unwrap();
    (s.user_id, s.token)
}
