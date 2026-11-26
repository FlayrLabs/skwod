//! Build 51: THE one place that decides whether this process may use public relays, and knows
//! whether it still does.
//!
//! Every member endpoint that may use them (`NetConfig::public_fallback`) holds a [`RelayLease`],
//! taken from a [`RelayGate`] BEFORE the endpoint is bound and given back only when its
//! `Endpoint::close` has finished. Both happen in one task per endpoint ([`OwnedEndpoint`]) that
//! nothing else owns, waits on or can drop: whatever becomes of the dial, the `Member` or the
//! session around it, there is no state in which a relay-allowed endpoint exists without a lease.
//! So "relays are off" is one number — leases live — and needs no list of who holds what.
//!
//! The gate of a process starts CLOSED: a relay-allowed dial is refused until the app has applied
//! its stored setting. (A HOST's own endpoint is not under it: that is the server process's
//! `--public-fallback`, fixed for its lifetime.)

use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use iroh::Endpoint;
use tokio::sync::{oneshot, watch, Notify};

use crate::endpoint::bind_endpoint;
use crate::{NetConfig, NetError, Role};

#[derive(Debug, Clone, Copy)]
struct GateState {
    allowed: bool,
    /// Moves on every time the setting changes: a lease of an earlier generation is revoked.
    generation: u64,
    live: usize,
}

pub struct RelayGate {
    state: watch::Sender<GateState>,
    /// Tests: every relay-allowed endpoint bound under this gate (`record_for_test`).
    bound: Mutex<Option<Vec<Endpoint>>>,
}

impl std::fmt::Debug for RelayGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.state.borrow().fmt(f) }
}

fn revoked() -> NetError { NetError::Unreachable("relays are turned off".into()) }

impl RelayGate {
    pub fn new(allowed: bool) -> Arc<Self> {
        Arc::new(Self { state: watch::channel(GateState { allowed, generation: 0, live: 0 }).0, bound: Mutex::new(None) })
    }

    /// This process's gate (closed until `on`).
    pub fn global() -> Arc<Self> {
        static GLOBAL: LazyLock<Arc<RelayGate>> = LazyLock::new(|| RelayGate::new(false));
        GLOBAL.clone()
    }

    pub fn allowed(&self) -> bool { self.state.borrow().allowed }

    /// How many relay-allowed endpoints are not fully closed (dials in progress included).
    pub fn live(&self) -> usize { self.state.borrow().live }

    pub fn on(&self) {
        self.state.send_if_modified(|s| {
            if s.allowed { return false }
            s.allowed = true;
            s.generation += 1;
            true
        });
    }

    /// Off, from now: no lease is given any more and every lease is revoked (each holder stops
    /// its dial and starts closing its endpoint, wherever it lives). Waits for nothing.
    pub fn revoke(&self) {
        self.state.send_if_modified(|s| {
            if !s.allowed { return false }
            s.allowed = false;
            s.generation += 1;
            true
        });
    }

    /// Off, and confirmed: true only when not one lease is left within `bound`.
    pub async fn off(&self, bound: Duration) -> bool {
        self.revoke();
        let mut state = self.state.subscribe();
        // (Turned on again meanwhile: not off.)
        let end = tokio::time::timeout(bound, state.wait_for(|s| s.allowed || s.live == 0)).await;
        matches!(end, Ok(Ok(s)) if !s.allowed && s.live == 0)
    }

    fn acquire(self: &Arc<Self>) -> Result<RelayLease, NetError> {
        let mut lease = None;
        self.state.send_modify(|s| {
            if s.allowed {
                s.live += 1;
                lease = Some(s.generation);
            }
        });
        let generation = lease.ok_or_else(revoked)?;
        Ok(RelayLease { gate: self.clone(), generation })
    }

    #[doc(hidden)]
    pub fn record_for_test(&self) {
        *self.bound.lock().unwrap_or_else(|e| e.into_inner()) = Some(Vec::new());
    }

    /// Tests: how many of the recorded endpoints are not closed — asked of the endpoints.
    #[doc(hidden)]
    pub fn open_for_test(&self) -> (usize, usize) {
        let bound = self.bound.lock().unwrap_or_else(|e| e.into_inner());
        let all = bound.as_deref().unwrap_or_default();
        (all.iter().filter(|e| !e.is_closed()).count(), all.len())
    }
}

/// One relay-allowed endpoint, from before its bind until its close has finished.
struct RelayLease {
    gate: Arc<RelayGate>,
    generation: u64,
}

impl Drop for RelayLease {
    fn drop(&mut self) {
        // A close that panicked did not finish: it counts for good (fail closed).
        if !std::thread::panicking() { self.gate.state.send_modify(|s| s.live -= 1); }
    }
}

/// The right to dial under `cfg` as it is now: for a whole dial (bind, connect, voice start, proxy
/// start, registration) to run under, and to check again before its result is published.
#[derive(Clone)]
pub struct RelayPermit(Option<(Arc<RelayGate>, u64)>);

impl RelayPermit {
    /// Refused when `cfg` allows relays and the gate does not.
    pub fn new(cfg: &NetConfig) -> Result<Self, NetError> {
        if !cfg.public_fallback { return Ok(Self(None)) }
        let s = *cfg.relay_gate.state.borrow();
        if !s.allowed { return Err(revoked()) }
        Ok(Self(Some((cfg.relay_gate.clone(), s.generation))))
    }

    pub fn is_current(&self) -> bool {
        self.0.as_ref().is_none_or(|(gate, generation)| gate.state.borrow().generation == *generation)
    }

    /// Resolves when it is not current any more (never, without relays).
    pub async fn revoked(&self) {
        match &self.0 {
            Some((gate, generation)) => {
                let mut state = gate.state.subscribe();
                let _ = state.wait_for(|s| s.generation != *generation).await;
            }
            None => std::future::pending().await,
        }
    }

    /// `dial`, given up the moment the permit is not current any more.
    pub async fn run<T>(&self, dial: impl std::future::Future<Output = T>) -> Result<T, NetError> {
        tokio::select! {
            biased;
            _ = self.revoked() => Err(revoked()),
            r = dial => Ok(r),
        }
    }
}

/// A member's endpoint and the one task that owns its life: lease → bind → (until asked, dropped
/// or revoked) → close → lease given back. Dropping this asks for the close; nothing can drop the
/// close itself.
pub(crate) struct OwnedEndpoint {
    pub(crate) endpoint: Endpoint,
    /// Closing (asked, or revoked): nothing new may use the endpoint.
    pub(crate) closing: Arc<watch::Sender<bool>>,
    ask: watch::Sender<bool>,
    closed: watch::Receiver<bool>,
    permit: RelayPermit,
    hold: Arc<Mutex<Option<Arc<Notify>>>>,
}

impl OwnedEndpoint {
    pub(crate) async fn bind(cfg: &NetConfig) -> Result<Self, NetError> {
        debug_assert!(cfg.role == Role::Member);
        let lease = if cfg.public_fallback { Some(cfg.relay_gate.acquire()?) } else { None };
        let (tx, rx) = oneshot::channel();
        tokio::spawn(own(cfg.clone(), lease, tx));
        rx.await.map_err(|_| NetError::Bind("stopped".into()))?
    }

    pub(crate) fn start_close(&self) {
        self.closing.send_replace(true);
        self.ask.send_replace(true);
    }

    pub(crate) async fn closed(&self) {
        let _ = self.closed.clone().wait_for(|c| *c).await;
    }

    pub(crate) fn is_closed(&self) -> bool { *self.closed.borrow() }

    pub(crate) fn is_closing(&self) -> bool { *self.closing.borrow() || !self.permit.is_current() }

    pub(crate) fn hold_close_for_test(&self) -> Arc<Notify> {
        let gate = Arc::new(Notify::new());
        *self.hold.lock().unwrap_or_else(|e| e.into_inner()) = Some(gate.clone());
        gate
    }
}

async fn own(cfg: NetConfig, lease: Option<RelayLease>, tx: oneshot::Sender<Result<OwnedEndpoint, NetError>>) {
    let endpoint = match bind_endpoint(&cfg).await {
        Ok(e) => e,
        Err(e) => { drop(lease); let _ = tx.send(Err(e)); return }
    };
    if let Some(lease) = &lease {
        if let Some(bound) = lease.gate.bound.lock().unwrap_or_else(|e| e.into_inner()).as_mut() { bound.push(endpoint.clone()); }
    }
    let permit = RelayPermit(lease.as_ref().map(|l| (l.gate.clone(), l.generation)));
    let closing = Arc::new(watch::channel(false).0);
    let (ask, mut asked) = watch::channel(false);
    let (done, closed) = watch::channel(false);
    let hold: Arc<Mutex<Option<Arc<Notify>>>> = Arc::default();
    let owned = OwnedEndpoint { endpoint: endpoint.clone(), closing: closing.clone(), ask, closed, permit: permit.clone(), hold: hold.clone() };
    // (Not taken — the dial was given up during the bind: dropped, which asks for the close.)
    let _ = tx.send(Ok(owned));
    tokio::select! {
        _ = permit.revoked() => {}
        _ = asked.wait_for(|a| *a) => {}   // asked, or the owner is gone
    }
    closing.send_replace(true);
    let gate = hold.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(gate) = gate { gate.notified().await; }
    // The only call: a second one would return at once while the first still runs.
    endpoint.close().await;
    while !endpoint.is_closed() { tokio::time::sleep(Duration::from_millis(10)).await; }
    done.send_replace(true);
    drop(lease);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Discovery, Member};

    fn cfg(gate: &Arc<RelayGate>) -> NetConfig {
        let mut cfg = NetConfig::member();
        cfg.discovery = Discovery::None;
        cfg.relay_gate = gate.clone();
        cfg
    }
    const BOUND: Duration = Duration::from_secs(6);

    /// The process gate starts closed (nothing has applied the stored setting): a relay-allowed
    /// dial is refused before anything is bound; one without relays is not affected.
    #[tokio::test]
    async fn an_off_setting_at_startup_refuses_a_relay_dial() {
        assert!(!RelayGate::global().allowed());
        assert!(RelayPermit::new(&NetConfig::member()).is_err());
        let gate = RelayGate::new(false);
        gate.record_for_test();
        let nobody = iroh::EndpointAddr::new(iroh::SecretKey::generate().public());
        assert!(Member::connect_within(&cfg(&gate), nobody, BOUND).await.is_err());
        assert_eq!((gate.open_for_test(), gate.live()), ((0, 0), 0), "nothing was bound");
        let mut direct = cfg(&gate);
        direct.public_fallback = false;
        let e = OwnedEndpoint::bind(&direct).await.unwrap();
        e.start_close();
        e.closed().await;
        gate.on();
        assert!(RelayPermit::new(&cfg(&gate)).is_ok());
    }

    /// The lease is there before the bind and until the close has FINISHED: not while it hangs,
    /// not for being asked twice, and not for a dropped owner.
    #[tokio::test]
    async fn a_stalled_close_is_not_off() {
        for dropped in [false, true] {
            let gate = RelayGate::new(true);
            let e = OwnedEndpoint::bind(&cfg(&gate)).await.unwrap();
            assert_eq!(gate.live(), 1);
            let hold = e.hold_close_for_test();
            let endpoint = e.endpoint.clone();
            if dropped { drop(e); }
            for _ in 0..2 { assert!(!gate.off(Duration::from_millis(300)).await, "not finished"); }
            assert!(!endpoint.is_closed());
            hold.notify_one();
            assert!(gate.off(BOUND).await);
            assert!(endpoint.is_closed());
        }
    }

    /// A dial given up during its bind: the endpoint is closed and its lease given back.
    #[tokio::test]
    async fn a_dial_dropped_at_any_point_gives_its_lease_back_only_when_closed() {
        for millis in [0u64, 1, 3, 10, 40, 120] {
            let gate = RelayGate::new(true);
            gate.record_for_test();
            let cfg = cfg(&gate);
            let _ = tokio::time::timeout(Duration::from_millis(millis), OwnedEndpoint::bind(&cfg)).await.map(drop);
            assert!(gate.off(BOUND).await, "{millis} ms");
            assert_eq!(gate.open_for_test().0, 0, "{millis} ms");
        }
    }

    #[tokio::test]
    async fn off_is_not_off_when_it_was_turned_on_again() {
        let gate = RelayGate::new(true);
        let e = OwnedEndpoint::bind(&cfg(&gate)).await.unwrap();
        let hold = e.hold_close_for_test();
        let off = { let gate = gate.clone(); tokio::spawn(async move { gate.off(BOUND).await }) };
        tokio::time::sleep(Duration::from_millis(50)).await;
        gate.on();
        assert!(!off.await.unwrap());
        assert!(e.is_closing(), "a lease of before stays revoked");
        hold.notify_one();
        assert!(gate.off(BOUND).await);
    }
}
