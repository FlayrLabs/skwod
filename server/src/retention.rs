//! Retention: the server forgets what it no longer needs, on a timer rather than "whenever
//! someone happens to touch the row". `docs/SECURITY.md` ("What the server stores, and for how
//! long") is the contract; this file is its implementation.
//!
//! Nothing here logs what it removed about whom — only aggregate counts, at debug level.

use std::time::Duration;

use crate::state::{now_ms, AppState};

/// How often the sweep runs.
pub const SWEEP_EVERY: Duration = Duration::from_secs(5 * 60);

/// Undelivered sealed mail is dropped after this long (delivered mail is deleted on ack).
pub const MAILBOX_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// A device-link request nobody approved.
pub const LINK_REQUEST_TTL_MS: i64 = 10 * 60 * 1000;
/// Presence older than this is stale: the user is shown offline and "last seen" is erased.
pub const PRESENCE_STALE_MS: i64 = 3 * 60 * 1000;
/// Resolved abuse reports and finished join requests are kept this long for the owner's records.
pub const RESOLVED_RETENTION_MS: i64 = 90 * 24 * 60 * 60 * 1000;
/// Dead (expired / revoked / used-up) invites.
pub const DEAD_INVITE_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    pub sessions: u64,
    pub envelopes: u64,
    pub proofs: u64,
    pub link_requests: u64,
    pub presence: u64,
    pub read_states: u64,
    pub prekeys: u64,
    pub invites: u64,
    pub blobs: u64,
}

async fn run(state: &AppState, sql: &str, cutoff: Option<i64>) -> u64 {
    let q = sqlx::query(sql);
    let q = match cutoff {
        Some(c) => q.bind(c),
        None => q,
    };
    match q.execute(&state.db).await {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            tracing::warn!(error = %e, "retention sweep step failed");
            0
        }
    }
}

/// One pass. Safe to run at any time and any number of times.
pub async fn sweep(state: &AppState) -> Swept {
    let now = now_ms();
    // A session about to be removed takes its push registration with it (cascade) — after which
    // that phone is never woken again and its owner has no way to know why the chat went quiet.
    // So the install gets one last wake first: it wakes, finds itself signed out (401) and says
    // so. (A rotated token's registration has already moved to its successor — `auth.rs`.)
    let orphaned: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT r.id, r.session_hash FROM push_registrations r JOIN sessions s ON s.token_hash = r.session_hash WHERE s.expires_at <= $1",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    for (id, _) in &orphaned {
        crate::gateway::final_wake(state, id).await;
    }
    let mut swept = Swept {
        blobs: crate::blobs::sweep(state).await,
        // Expired sessions (and, by cascade, their push-gateway registrations).
        sessions: run(state, "DELETE FROM sessions WHERE expires_at <= $1", Some(now)).await,
        // Mail nobody fetched. Fetched mail is deleted when the device acknowledges it.
        envelopes: run(state, "DELETE FROM sealed_envelopes WHERE created_at < $1", Some(now - MAILBOX_RETENTION_MS)).await,
        // Replay records for device proofs that can no longer be replayed anyway.
        proofs: run(state, "DELETE FROM device_op_proofs WHERE expires_at < $1", Some(now)).await,
        link_requests: run(state, "DELETE FROM device_link_requests WHERE created_at < $1", Some(now - LINK_REQUEST_TTL_MS)).await,
        // One-time prekeys that were handed out: the public half has no further use.
        prekeys: run(state, "DELETE FROM one_time_prekeys WHERE used = 1", None).await,
        // Read markers of people who are no longer in that channel's space.
        read_states: run(
            state,
            "DELETE FROM read_states WHERE NOT EXISTS (
               SELECT 1 FROM channels c JOIN server_members m ON m.server_id = c.server_id
               WHERE c.id = read_states.channel_id AND m.user_id = read_states.user_id)",
            None,
        )
        .await,
        invites: run(
            state,
            "DELETE FROM invites WHERE ((expires_at IS NOT NULL AND expires_at < $1) OR status <> 'active')
               AND updated_at < $1
               AND NOT EXISTS (SELECT 1 FROM join_requests j WHERE j.invite_id = invites.id AND j.status = 'pending')",
            Some(now - DEAD_INVITE_RETENTION_MS),
        )
        .await,
        presence: 0,
    };
    run(state, "DELETE FROM join_requests WHERE status <> 'pending' AND updated_at < $1", Some(now - RESOLVED_RETENTION_MS)).await;
    run(state, "DELETE FROM abuse_reports WHERE status <> 'open' AND created_at < $1", Some(now - RESOLVED_RETENTION_MS)).await;

    // Stale presence. Someone with a live socket is never stale; everyone else whose heartbeat
    // stopped is offline, and the timestamp of when they were last around is not kept.
    let online: Vec<String> = state.ws_conns.lock().await.keys().cloned().collect();
    let stale: Vec<String> = sqlx::query_scalar("SELECT id FROM profiles WHERE last_seen_at > 0 AND last_seen_at < $1")
        .bind(now - PRESENCE_STALE_MS)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    for user_id in stale.into_iter().filter(|u| !online.contains(u)) {
        swept.presence += sqlx::query("UPDATE profiles SET status = 'offline', last_seen_at = 0 WHERE id = $1 AND last_seen_at < $2")
            .bind(&user_id)
            .bind(now - PRESENCE_STALE_MS)
            .execute(&state.db)
            .await
            .map(|r| r.rows_affected())
            .unwrap_or(0);
    }
    swept
}

/// Run [`sweep`] now and then every [`SWEEP_EVERY`], for the life of the process.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        loop {
            tick.tick().await;
            let swept = sweep(&state).await;
            if swept != Swept::default() {
                tracing::debug!(?swept, "retention sweep");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{send, signup, test_state};
    use serde_json::json;

    async fn count(state: &AppState, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}")).fetch_one(&state.db).await.unwrap()
    }

    #[tokio::test]
    async fn the_sweep_removes_what_has_expired_and_nothing_else() {
        let state = test_state().await;
        let app = crate::api::router(state.clone());
        let (alice, alice_token) = signup(&app, "alice").await;
        let (bob, _bob_token) = signup(&app, "bobby").await;
        let now = now_ms();
        let old = now - 40 * 24 * 60 * 60 * 1000;

        // A push registration on alice's session, then let that session expire.
        let reg = json!({ "provider": "gateway", "gateway": "https://push.example.org", "apns_token": "ab".repeat(32), "voip_token": null, "topic": "io.skwod.app" });
        assert_eq!(send(&app, "POST", "/api/push/register", Some(&alice_token), Some(reg)).await.0, axum::http::StatusCode::OK);
        assert_eq!(count(&state, "push_registrations").await, 1);
        sqlx::query("UPDATE sessions SET expires_at = $1 WHERE user_id = $2").bind(now - 1).bind(&alice).execute(&state.db).await.unwrap();

        for (id, created) in [("fresh", now), ("stale", old)] {
            sqlx::query("INSERT INTO sealed_envelopes (id, user_id, device_id, envelope, seq, created_at) VALUES ($1, $2, 'd1', $3, 1, $4)")
                .bind(id)
                .bind(&bob)
                .bind(vec![1u8, 2, 3])
                .bind(created)
                .execute(&state.db)
                .await
                .unwrap();
        }
        for (hash, exp) in [("live", now + 60_000), ("dead", now - 1)] {
            sqlx::query("INSERT INTO device_op_proofs (proof_hash, user_id, expires_at) VALUES ($1, $2, $3)").bind(hash).bind(&bob).bind(exp).execute(&state.db).await.unwrap();
        }
        // Bob "went away" ten minutes ago without a goodbye; alice heartbeated just now.
        sqlx::query("UPDATE profiles SET status = 'online', last_seen_at = $1 WHERE id = $2").bind(now - 10 * 60 * 1000).bind(&bob).execute(&state.db).await.unwrap();
        sqlx::query("UPDATE profiles SET status = 'online', last_seen_at = $1 WHERE id = $2").bind(now).bind(&alice).execute(&state.db).await.unwrap();

        let swept = sweep(&state).await;
        assert_eq!(swept.sessions, 1, "alice's expired session");
        assert_eq!(count(&state, "push_registrations").await, 0, "…and the push registration tied to it");
        assert_eq!((swept.envelopes, count(&state, "sealed_envelopes").await), (1, 1), "only the 40-day-old envelope");
        assert_eq!((swept.proofs, count(&state, "device_op_proofs").await), (1, 1));
        assert_eq!(swept.presence, 1);
        let (status, seen): (String, i64) = sqlx::query_as("SELECT status, last_seen_at FROM profiles WHERE id = $1").bind(&bob).fetch_one(&state.db).await.unwrap();
        assert_eq!((status.as_str(), seen), ("offline", 0), "stale presence is cleared and its timestamp erased");
        let (status, seen): (String, i64) = sqlx::query_as("SELECT status, last_seen_at FROM profiles WHERE id = $1").bind(&alice).fetch_one(&state.db).await.unwrap();
        assert_eq!((status.as_str(), seen), ("online", now), "fresh presence is untouched");

        assert_eq!(sweep(&state).await, Swept::default(), "a second pass finds nothing");
    }
}
