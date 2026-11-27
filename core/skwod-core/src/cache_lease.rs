//! Letting go of the encrypted cache at once (build 51).
//!
//! On iOS the cache is in a container two processes share, and one cross-process lock says which
//! of them may use it. A process that is suspended while it holds that lock is killed by the
//! system, so the lock must go the moment the app leaves the foreground — and with it every use
//! of the cache: the app's calls into the core are not interrupted by anything, and one that went
//! on writing after the lock was let go would advance a ratchet the other process is advancing.
//!
//! A [`CacheLease`] ends that use from any thread, without the async runtime. A client whose
//! cache was detached never uses it again (a new client is made): nothing it does is stored,
//! so nothing it receives is acknowledged and nothing it seals is sent.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use skwod_sync::Cache;

use crate::CoreError;

/// Both are only read and written for a decision while the cache slot's lock is held.
#[derive(Default)]
pub(crate) struct CacheUse {
    detached: AtomicBool,
    critical: AtomicUsize,
}

impl CacheUse {
    pub(crate) fn detached(&self) -> bool {
        self.detached.load(Ordering::SeqCst)
    }

    pub(crate) fn refuse_if_detached(&self) -> Result<(), CoreError> {
        if self.detached() {
            return Err(CoreError::NoCache { detail: "detached".into() });
        }
        Ok(())
    }

    /// For a call whose effect on the server this device must remember (a registration: the
    /// server makes the device, then the state that says so is stored). Taken before the call
    /// looks at the cache.
    pub(crate) fn critical(self: &Arc<Self>) -> Critical {
        self.critical.fetch_add(1, Ordering::SeqCst);
        Critical(self.clone())
    }
}

pub(crate) struct Critical(Arc<CacheUse>);

impl Drop for Critical {
    fn drop(&mut self) {
        self.0.critical.fetch_sub(1, Ordering::SeqCst);
    }
}

/// See the module documentation. Holds neither the client nor its cache.
#[derive(uniffi::Object)]
pub struct CacheLease {
    cache: Weak<Mutex<Option<Cache>>>,
    state: Arc<CacheUse>,
}

impl CacheLease {
    pub(crate) fn new(cache: &Arc<Mutex<Option<Cache>>>, state: Arc<CacheUse>) -> Arc<Self> {
        Arc::new(Self { cache: Arc::downgrade(cache), state })
    }
}

#[uniffi::export]
impl CacheLease {
    /// End the use of the cache NOW: when this returns nothing of this client reads or writes the
    /// file any more, or ever will. Waits only for the database call in progress, if any.
    pub fn detach(&self) {
        let Some(cache) = self.cache.upgrade() else { return };
        let mut slot = cache.lock().unwrap_or_else(|e| e.into_inner());
        self.state.detached.store(true, Ordering::SeqCst);
        *slot = None;
    }

    /// [`detach`](Self::detach), unless a call is going on that must not be cut short (a
    /// registration, a link, a restore). Returns whether the use has ended.
    pub fn detach_if_idle(&self) -> bool {
        let Some(cache) = self.cache.upgrade() else { return true };
        let mut slot = cache.lock().unwrap_or_else(|e| e.into_inner());
        if self.state.critical.load(Ordering::SeqCst) > 0 && !self.state.detached() {
            return false;
        }
        self.state.detached.store(true, Ordering::SeqCst);
        *slot = None;
        true
    }

    /// Has the use ended (detached, or the client is gone)?
    pub fn is_over(&self) -> bool {
        self.state.detached() || self.cache.strong_count() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SkwodClient;

    fn client() -> Arc<SkwodClient> {
        SkwodClient::new("http://127.0.0.1:9".into(), "t".into())
    }

    #[tokio::test]
    async fn a_detached_client_uses_the_cache_no_more_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sqlite3").to_string_lossy().to_string();
        let c = client();
        let lease = c.cache_lease();
        c.attach_cache(path.clone(), "ab".repeat(32)).await.unwrap();
        c.kv_write("k".into(), "v".into()).await.unwrap();
        assert!(!lease.is_over());

        lease.detach();
        assert!(lease.is_over() && !c.cache_attached());
        assert!(matches!(c.kv_write("k".into(), "late".into()).await, Err(CoreError::NoCache { .. })));
        assert!(c.register_device().await.is_err());
        // Never again, also by name.
        assert!(matches!(c.attach_cache(path.clone(), "ab".repeat(32)).await, Err(CoreError::NoCache { .. })));
        assert!(!c.cache_attached());

        // What is stored is as it was, and a new client reads it.
        let next = client();
        next.attach_cache(path, "ab".repeat(32)).await.unwrap();
        assert_eq!(next.kv_read("k".into()).await.unwrap().as_deref(), Some("v"));
    }

    #[tokio::test]
    async fn nothing_is_opened_after_a_detach_and_nothing_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sqlite3");
        let c = client();
        c.cache_lease().detach();
        assert!(c.attach_cache(path.to_string_lossy().to_string(), "ab".repeat(32)).await.is_err());
        assert!(!path.exists());
    }

    /// Detaching is a plain call: it needs no runtime and does not wait for the engine.
    #[tokio::test]
    async fn detaching_does_not_wait_for_a_call_in_progress() {
        let dir = tempfile::tempdir().unwrap();
        let c = client();
        c.attach_cache(dir.path().join("c.sqlite3").to_string_lossy().to_string(), "ab".repeat(32)).await.unwrap();
        let lease = c.cache_lease();
        let _busy = c.engine.lock().await;   // an engine call waiting for the network
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            lease.detach();
            tx.send(()).unwrap();
        });
        rx.recv_timeout(std::time::Duration::from_secs(2)).expect("detached");
        assert!(!c.cache_attached());
    }

    /// The state that a detached client could not store is not taken for stored.
    #[tokio::test]
    async fn what_a_detached_client_seals_is_not_sent_and_what_it_reads_is_not_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sqlite3").to_string_lossy().to_string();
        let c = client();
        c.attach_cache(path, "ab".repeat(32)).await.unwrap();
        assert!(c.engine.lock().await.checkpoint_for_test().is_ok());
        c.cache_lease().detach();
        assert!(c.engine.lock().await.checkpoint_for_test().is_err(), "nothing leaves");
        assert!(!c.store_state(b"state"), "nothing is acknowledged");
    }

    /// No moment with nowhere to save to: before a cache is attached (and so while one is being
    /// attached), what the engine would seal does not leave and what it read is not acknowledged —
    /// unless the client keeps everything in memory by choice.
    #[tokio::test]
    async fn before_a_cache_is_attached_nothing_sealed_leaves_and_nothing_read_is_acknowledged() {
        let c = client();
        assert!(c.engine.lock().await.checkpoint_for_test().is_err(), "the state sink is there from the start");
        assert!(!c.store_state(b"state"), "not stored, so not acknowledged");
        let memory = client();
        memory.allow_without_cache();
        assert!(memory.engine.lock().await.checkpoint_for_test().is_ok());
        assert!(memory.store_state(b"state"));
        memory.cache_lease().detach();
        assert!(memory.engine.lock().await.checkpoint_for_test().is_err(), "detached: nothing leaves");
        assert!(!memory.store_state(b"state"));
    }

    #[tokio::test]
    async fn a_registration_in_progress_is_not_cut_short_unless_time_is_up() {
        let dir = tempfile::tempdir().unwrap();
        let c = client();
        c.attach_cache(dir.path().join("c.sqlite3").to_string_lossy().to_string(), "ab".repeat(32)).await.unwrap();
        let lease = c.cache_lease();
        let registering = c.cache_use.critical();
        assert!(!lease.detach_if_idle());
        assert!(c.cache_attached() && !lease.is_over());
        drop(registering);
        assert!(lease.detach_if_idle());
        assert!(!c.cache_attached());

        let c = client();
        c.attach_cache(dir.path().join("d.sqlite3").to_string_lossy().to_string(), "ab".repeat(32)).await.unwrap();
        let _registering = c.cache_use.critical();
        let lease = c.cache_lease();
        lease.detach();   // out of time
        assert!(!c.cache_attached() && lease.detach_if_idle());
    }

    #[tokio::test]
    async fn a_lease_does_not_keep_a_client_or_its_cache() {
        let c = client();
        let lease = c.cache_lease();
        drop(c);
        assert!(lease.is_over() && lease.detach_if_idle());
        lease.detach();
    }
}
