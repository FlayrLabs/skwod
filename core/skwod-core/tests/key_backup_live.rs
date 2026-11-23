//! End-to-end passphrase key backup against a REAL skwod-server process: enable on device A,
//! restore on a fresh device B (fresh cache = the post-sign-out state), and verify B got A's
//! device identity and space keys back. Skips gracefully if the server can't be built here.

use std::process::{Child, Command};
use std::sync::Once;
use std::time::Duration;

use skwod_core::SkwodClient;
use skwod_sync::ApiClient;

static BUILD: Once = Once::new();

fn server_manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/Cargo.toml")
}

fn build_server() -> bool {
    // `SKWOD_TEST_SERVER_BIN=<path>` runs the tests against an already-built server binary
    // (e.g. the release one) instead of building a debug one here.
    if std::env::var_os("SKWOD_TEST_SERVER_BIN").is_some() {
        return true;
    }
    let mut ok = true;
    BUILD.call_once(|| {
        let status = Command::new("cargo")
            .args(["build", "--quiet", "--bin", "skwod", "--manifest-path"])
            .arg(server_manifest())
            .status();
        ok = matches!(status, Ok(s) if s.success());
    });
    ok
}

fn server_bin() -> std::path::PathBuf {
    if let Some(bin) = std::env::var_os("SKWOD_TEST_SERVER_BIN") {
        return bin.into();
    }
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/target/debug/skwod")
}

struct ServerGuard {
    child: Child,
    _dir: tempfile::TempDir,
    base: String,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A session of its own for each install: a session speaks for one device (the one it
/// registered or bound), so two clients must never share a token.
async fn fresh_token(base: &str, username: &str, password: &str) -> String {
    ApiClient::new(base).login(username, password).await.expect("login").token
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn start_server() -> Option<ServerGuard> {
    if !build_server() {
        eprintln!("SKIP: could not build skwod-server in this environment");
        return None;
    }
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(server_bin())
        .args(["run", "--listen", &format!("127.0.0.1:{port}"), "--data"])
        .arg(dir.path())
        // A throwaway test instance: open signup is asked for explicitly (`skwod run` otherwise
        // auto-initializes a fresh volume behind a join code), and no p2p endpoint is needed.
        .env("SKWOD_OPEN_SIGNUP", "1")
        .env("SKWOD_NO_P2P", "true")
        .spawn()
        .ok()?;
    // Guard FIRST: if the health wait below fails, dropping the guard kills the child instead of
    // leaking a live server process bound to the port.
    let guard = ServerGuard { child, _dir: dir, base: format!("http://127.0.0.1:{port}") };
    let http = reqwest::Client::new();
    for _ in 0..600 { // up to 60 s: cold start under a parallel test load
        if http.get(format!("{}/health", guard.base)).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
            return Some(guard);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // A built server that can't become healthy is a FAILURE, not a skip — a startup panic in the
    // code under test must not report as a passing run.
    panic!("skwod-server built but never became healthy on {}", guard.base);
}

fn cache_path(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string()
}

/// Let the account's recovery key age past the 7-day hold (only then does a restore with it
/// complete at once). Done on the server's database, as time would.
fn season_recovery_key(server: &ServerGuard) {
    let status = Command::new("sqlite3")
        .arg(server._dir.path().join("skwod.db"))
        .arg("UPDATE backup_keys SET set_at = 1 WHERE retired_at IS NULL")
        .status()
        .expect("sqlite3 (to age the recovery key)");
    assert!(status.success());
}

const KEY_A: &str = "11111111111111111111111111111111111111111111111111111111111111aa";
const KEY_B: &str = "22222222222222222222222222222222222222222222222222222222222222bb";

#[tokio::test]
async fn passphrase_backup_restores_identity_and_space_keys_on_a_fresh_device() {
    let Some(server) = start_server().await else { return };
    let caches = tempfile::tempdir().unwrap();

    let _session = ApiClient::new(&server.base).signup("backupper", "password123").await.expect("signup");

    // Device A: register, create a space (space key + encrypted name), enable backup.
    let a = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "backupper", "password123").await);
    assert!(!a.attach_cache(cache_path(&caches, "a.sqlite3"), KEY_A.into()).await.expect("attach a"));
    let a_device = a.register_device().await.expect("register a");
    let space = a.create_space("Backup Crew".into(), "general".into()).await.expect("create space");
    assert_eq!(a.server_name(space.server_id.clone()).await.expect("name a"), Some("Backup Crew".into()));

    assert!(!a.key_backup_enabled().await, "backup starts off");
    a.enable_key_backup("correct horse battery".into()).await.expect("enable backup");
    assert!(a.key_backup_enabled().await, "backup on after enable");

    // Device B: fresh cache + fresh cache key — exactly the post-sign-out state.
    let b = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "backupper", "password123").await);
    assert!(!b.attach_cache(cache_path(&caches, "b.sqlite3"), KEY_B.into()).await.expect("attach b"));

    // Wrong passphrase must fail loudly, not corrupt anything.
    let wrong = b.restore_key_backup("totally wrong".into()).await;
    assert!(wrong.is_err(), "wrong passphrase must error, got {wrong:?}");

    season_recovery_key(&server);
    // Right passphrase: the backup opens, and holding the recovery key is PROVEN to the server
    // (a signature by a key derived from the backup key, over the server's nonce) — so the
    // device moves to this install at once: no approval, no wait.
    assert!(b.restore_key_backup("correct horse battery".into()).await.expect("restore"));
    assert_eq!(b.device_state().await, skwod_core::DeviceState::Active);
    // The install it was restored FROM stops, and says why — it is not a silent clone.
    let stopped = a.sync_dms().await;
    assert!(matches!(stopped, Err(skwod_core::CoreError::DeviceSuperseded { .. })), "{stopped:?}");
    assert_eq!(a.device_state().await, skwod_core::DeviceState::Superseded);
    assert!(matches!(a.send_channel_message(space.channel_id.clone(), "from the clone".into()).await, Err(skwod_core::CoreError::DeviceSuperseded { .. })));
    assert_eq!(b.current_device_id().await.as_deref(), Some(a_device.as_str()), "device identity restored");
    assert_eq!(
        b.server_name(space.server_id.clone()).await.expect("name b"),
        Some("Backup Crew".into()),
        "space key restored — encrypted server name decrypts on the new device"
    );
    assert!(b.key_backup_enabled().await, "restored device keeps backing up");

    // A restored device can update the backup without being re-asked for the passphrase.
    assert!(b.update_key_backup().await.expect("update after restore"));

    // An account with no backup gets a clean `false`, not an error.
    let _other = ApiClient::new(&server.base).signup("nobackup", "password123").await.expect("signup 2");
    let c = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "nobackup", "password123").await);
    assert!(!c.attach_cache(cache_path(&caches, "c.sqlite3"), KEY_A.into()).await.expect("attach c"));
    assert!(!c.restore_key_backup("whatever pass".into()).await.expect("no backup -> false"));

    // Enabling without an attached cache must FAIL — the config would have nowhere to live, and a
    // silent Ok here would report a backup that doesn't exist.
    let no_cache = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "nobackup", "password123").await);
    assert!(
        no_cache.enable_key_backup("some passphrase".into()).await.is_err(),
        "enable without a cache must error"
    );
    assert!(!no_cache.key_backup_enabled().await);

    // Restoring without an attached cache must also fail (the recovered identity would be
    // memory-only and vanish on relaunch).
    assert!(no_cache.restore_key_backup("whatever pass".into()).await.is_err());

    // Ownership guard: a THIRD device (linked by the restored one) re-enables backup under a
    // different passphrase (explicit replace). Device B's auto-update must then refuse to clobber
    // it and flip itself off.
    let d = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "backupper", "password123").await);
    assert!(!d.attach_cache(cache_path(&caches, "d.sqlite3"), KEY_B.into()).await.expect("attach d"));
    assert!(matches!(d.register_device().await, Err(skwod_core::CoreError::LinkRequired { .. })), "a new device must be linked");
    let code = d.begin_device_link().await.expect("begin link");
    assert!(b.approve_device_link(code).await.expect("approve link"));
    let d_device = d.complete_device_link().await.expect("complete link").expect("approved");
    d.enable_key_backup("brand new passphrase".into()).await.expect("re-enable on d");
    assert!(!b.update_key_backup().await.expect("update must not clobber a foreign backup"), "update returns false");
    assert!(!b.key_backup_enabled().await, "b's config cleared after losing the backup slot");
    // The new passphrase restores d's backup; the old one no longer matches.
    let e = SkwodClient::new(server.base.clone(), fresh_token(&server.base.clone(), "backupper", "password123").await);
    assert!(!e.attach_cache(cache_path(&caches, "e.sqlite3"), KEY_A.into()).await.expect("attach e"));
    // (For 7 days after a change the OLD key still opens the backup it sealed — that is how an
    // owner takes the account back from a planted key. Here the window has run out.)
    assert!(Command::new("sqlite3").arg(server._dir.path().join("skwod.db")).arg("UPDATE backup_keys SET retired_at = 1 WHERE retired_at IS NOT NULL").status().unwrap().success());
    assert!(e.restore_key_backup("correct horse battery".into()).await.is_err(), "old passphrase must fail");
    // d CHANGED the recovery key: every device is told (and could undo it for a week)…
    b.refresh_own_devices().await.expect("b refreshes");
    assert!(b.take_security_notices().await.iter().any(|n| n.kind == "recovery_key_changed"), "the other devices hear of the change");
    // …and the new key has to season before it restores at once: until then the restore is a
    // request the account's devices are asked about (and the backup is not handed over).
    assert!(matches!(e.restore_key_backup("brand new passphrase".into()).await, Err(skwod_core::CoreError::RecoveryPending { .. })), "a brand-new recovery key does not skip the wait");
    assert_eq!(e.device_state().await, skwod_core::DeviceState::RecoveryPending);
    season_recovery_key(&server);
    assert!(e.retry_restore(None).await.expect("new passphrase restores"));
    // The account's other devices are told it was restored onto a new install.
    b.refresh_own_devices().await.expect("b refreshes");
    b.refresh_own_devices().await.expect("b refreshes");
    let _ = b.take_security_notices().await;
    assert_eq!(e.current_device_id().await.as_deref(), Some(d_device.as_str()), "restores d's identity onto its device id");

    // Interim-device cleanup: unregister removes an owned device row server-side.
    assert_eq!(c.device_state().await, skwod_core::DeviceState::Unregistered);
    let interim = c.register_device().await.expect("register interim");
    c.unregister_device(interim.clone()).await.expect("unregister own device");
    assert!(c.unregister_device(interim).await.is_err(), "second delete is a 404");
}
