import Foundation
import os

// The cross-process lock on the encrypted cache, and when this process may hold it (build 51).
// Foundation only: the app, the notification extension and the logic tests compile this file.

/// What a holder of the lock uses the cache through, as the lock can end it (`CacheLease`).
protocol StoreLease: AnyObject {
    /// End it now: nothing of it touches the cache once this returns.
    func detach()
    /// The same, unless something is going on that must not be cut short. False: still in use.
    func detachIfIdle() -> Bool
    /// Ended, or whoever it belonged to is gone.
    func isOver() -> Bool
}

/// One process at a time may hold the encrypted cache open: it carries the Signal session state,
/// and two processes advancing the same ratchet would corrupt it.
///
/// - The APP must actually HOLD this lock before it opens a cache (`holdForApp`). If the
///   notification extension has it, the app asks it to yield and waits; it never opens the
///   cache without the lock.
/// - The EXTENSION only ever tries (`WakeHold`) and gives up at once if the app has it. While
///   it holds the lock it watches for the app's yield request (`onYield` / `yieldRequested`):
///   it stops what it is doing, lets go of its client, and releases.
///
/// The lock is an advisory `flock` on a file in the shared container; the yield request is a
/// marker file beside it plus a Darwin notification (so a waiting extension reacts at once and
/// one that missed the notification still sees the marker between steps).
///
/// Build 51: iOS kills an app that is suspended while it holds a lock on a file in a shared
/// container. So the app's lock has a GATE, closed until the app is in front: while it is closed
/// nothing takes the lock, whatever was already on its way to it; and closing it ends every use
/// of the cache (`lease`) and lets the lock go, in one step. The lock is never let go with a
/// client still using the cache, and no client uses the cache without a lease.
final class StoreLock {
    static let yieldNotification = "io.skwod.store.yield"

    private var fd: Int32 = -1
    private let queue = DispatchQueue(label: "io.skwod.storelock")
    private var gateOpen: Bool
    /// Bumped whenever the lock is let go: a lease asked for under an earlier hold is refused.
    private var epoch = 0
    private var leases: [StoreLease] = []
    /// Uses that could not be ended when the gate closed (`closeGate(draining: true)`).
    private var draining: [StoreLease] = []
    private var yieldHandler: (() -> Void)?
    private var observing = false
    private let container: () -> URL?
    /// Overrides where the lock lives (DEBUG checks on builds with no shared container).
    var directoryOverride: URL?

    /// `gated`: the app on iOS. Everything else (the extension, the Mac — which has no other
    /// process to share with and is not suspended) has no gate to open.
    init(gated: Bool = false, directory: @escaping () -> URL? = { nil }) {
        gateOpen = !gated
        container = directory
    }

    deinit {
        // The Darwin center keeps only an unretained pointer to this lock (`onYield`).
        if observing {
            CFNotificationCenterRemoveObserver(CFNotificationCenterGetDarwinNotifyCenter(), Unmanaged.passUnretained(self).toOpaque(),
                                               CFNotificationName(Self.yieldNotification as CFString), nil)
            Self.observers.decrement()
        }
    }

    /// Locks currently registered for the yield notification (tests).
    static let observers = Counter()
    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        var value: Int { lock.withLock { n } }
        func increment() { lock.withLock { n += 1 } }
        func decrement() { lock.withLock { n -= 1 } }
    }

    private var directory: URL? { directoryOverride ?? container() }
    private var path: String? { directory?.appendingPathComponent("store.lock").path }
    private var yieldPath: String? { directory?.appendingPathComponent("store.yield").path }

    /// Whether this process holds the lock right now. With no shared container no other process
    /// can reach the cache, and the gate alone decides.
    var isHeld: Bool { queue.sync { held } }
    private var held: Bool { path == nil ? gateOpen || !draining.isEmpty : fd >= 0 }

    var isOpen: Bool { queue.sync { gateOpen } }

    /// Every use that was ended has ended.
    var isDrained: Bool { queue.sync { draining.isEmpty } }

    // MARK: The gate

    func openGate(_ why: String) {
        queue.sync {
            guard !gateOpen else { return }
            gateOpen = true
            StoreLockTrace.note("gate_open \(why)")
        }
    }

    /// Nothing takes the lock from here on, every use of the cache is ended and the lock is let
    /// go — all before this returns. `draining`: a use that must not be cut short (a registration
    /// on its way) keeps the lock until `drain`; false is returned, and the caller sees to it that
    /// the process is not suspended meanwhile.
    @discardableResult
    func closeGate(_ why: String, draining mayDrain: Bool = false) -> Bool {
        queue.sync {
            if gateOpen { StoreLockTrace.note("gate_closed \(why)") }
            gateOpen = false
            let all = draining + leases
            leases = []
            draining = all.filter { lease in
                if mayDrain { return !lease.detachIfIdle() }
                lease.detach()
                return false
            }
            if draining.isEmpty { unlock(why) }
            return draining.isEmpty
        }
    }

    /// End what has become idle. True: nothing is left, and the lock went unless the gate is open
    /// again.
    @discardableResult
    func drain() -> Bool {
        queue.sync {
            draining = draining.filter { !$0.detachIfIdle() }
            if draining.isEmpty, !gateOpen { unlock("drained") }
            return draining.isEmpty
        }
    }

    // MARK: Taking and letting go

    /// One attempt, no waiting. Refused while the gate is closed.
    func tryAcquire() -> Bool { queue.sync { take() } }

    private func take() -> Bool {
        guard gateOpen else { return false }
        guard let path else { return true }
        if fd >= 0 { return true }
        let handle = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
        guard handle >= 0 else { return false }
        guard flock(handle, LOCK_EX | LOCK_NB) == 0 else { close(handle); return false }
        fd = handle
        StoreLockTrace.note("lock_taken")
        return true
    }

    private func unlock(_ why: String) {
        epoch += 1
        guard fd >= 0 else { return }
        flock(fd, LOCK_UN)
        close(fd)
        fd = -1
        StoreLockTrace.note("lock_released \(why)")
    }

    /// Let the lock go, ending every use of the cache first.
    func release() {
        queue.sync {
            for lease in draining + leases { lease.detach() }
            (draining, leases) = ([], [])
            unlock("released")
        }
    }

    /// A use of the cache, to be ended before the lock is let go. False: the lock is not held (any
    /// more), or what used the cache before has not ended — then the cache must not be opened.
    func lease(_ lease: StoreLease) -> Bool {
        queue.sync {
            guard gateOpen, held, draining.isEmpty else { return false }
            leases.removeAll { $0.isOver() }
            leases.append(lease)
            return true
        }
    }

    // MARK: The app's side

    enum Hold { case held, busy, closed }

    /// Hold the lock for the app, asking the extension to yield for as long as it takes (up to
    /// `maxWait` — longer than the system ever lets an extension run). The caller opens a cache
    /// ONLY on `.held`. `.closed`: the app may not hold it now (the gate is closed, or closed
    /// while waiting — the wait ends at once); it is tried again when the app is in front.
    func holdForApp(maxWait: TimeInterval = 40, poll: Duration = .milliseconds(100)) async -> Hold {
        let deadline = Date().addingTimeInterval(maxWait)
        var asked = false
        while true {
            guard isOpen, !Task.isCancelled else {
                if asked { clearYieldRequest() }
                return .closed
            }
            // (Only once what used the cache in this process has ended too.)
            if tryAcquire(), drain() {
                if asked { StoreLockTrace.note("app_acquired_after_wait") }
                clearYieldRequest()
                return .held
            }
            if Date() >= deadline { break }
            if !isHeld {
                if !asked { StoreLockTrace.note("app_wait_started") }
                asked = true
                requestYield()
            }
            try? await Task.sleep(for: poll)
        }
        // Out of time: a use of our own that never ended is ended now, for the next attempt.
        queue.sync {
            for lease in draining { lease.detach() }
            draining = []
        }
        return .busy
    }

    /// Tell whoever holds the lock that the app needs the cache now.
    private func requestYield() {
        guard let yieldPath else { return }
        // Written afresh on every request: a marker left by an earlier run is older than a minute,
        // and the extension would take this request for debris. Atomically: never half a number.
        let first = !FileManager.default.fileExists(atPath: yieldPath)
        try? Data(String(Date().timeIntervalSince1970).utf8).write(to: URL(fileURLWithPath: yieldPath), options: .atomic)
        if first { StoreLockTrace.note("yield_requested") }
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             CFNotificationName(Self.yieldNotification as CFString), nil, nil, true)
    }

    private func clearYieldRequest() {
        if let yieldPath { try? FileManager.default.removeItem(atPath: yieldPath) }
    }

    // MARK: The extension's side

    /// For one wake: the hold's epoch, or nil (someone holds it — also another wake of this process).
    fileprivate func acquireForWake() -> Int? {
        queue.sync { fd < 0 && take() ? epoch : nil }
    }

    fileprivate func lease(_ lease: StoreLease, epoch: Int) -> Bool {
        queue.sync {
            guard self.epoch == epoch, held else { return false }
            leases.append(lease)
            return true
        }
    }

    fileprivate func release(epoch: Int) {
        queue.sync {
            guard self.epoch == epoch else { return }
            for lease in leases { lease.detach() }
            leases = []
            unlock("wake over")
        }
    }

    /// The app has asked for the cache (a marker younger than a minute — an old one is debris
    /// of a run that ended, not a request).
    var yieldRequested: Bool {
        guard let yieldPath, let text = try? String(contentsOfFile: yieldPath, encoding: .utf8),
              let at = Double(text) else { return false }
        return Date().timeIntervalSince1970 - at < 60
    }

    /// Call `handler` (once, on an arbitrary thread) when the app asks for the cache.
    func onYield(_ handler: @escaping () -> Void) {
        queue.sync { yieldHandler = handler }
        guard !observing else { return }
        observing = true
        Self.observers.increment()
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), observer, { _, observer, _, _, _ in
            guard let observer else { return }
            Unmanaged<StoreLock>.fromOpaque(observer).takeUnretainedValue().fireYield()
        }, Self.yieldNotification as CFString, nil, .deliverImmediately)
    }

    private func fireYield() {
        let handler: (() -> Void)? = queue.sync {
            let h = yieldHandler
            yieldHandler = nil
            return h
        }
        handler?()
    }
}

/// One wake of the notification extension and its hold on the cache: let go when the wake is over
/// — before its banner is delivered, and at once when the system says time is up — whatever a call
/// that was left behind is still doing. Over is over: a step that comes later gets nothing.
final class WakeHold: @unchecked Sendable {
    private let store: StoreLock
    private let lock = NSLock()
    private var epoch: Int?
    private var over = false

    init(_ store: StoreLock) { self.store = store }

    /// False: someone has the cache (or wants it), or the wake is over.
    func acquire() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !over, epoch == nil, !store.yieldRequested, let e = store.acquireForWake() else { return false }
        epoch = e
        return true
    }

    /// False: this wake does not hold the cache: it must not be opened.
    func lease(_ lease: StoreLease) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !over, let epoch else { return false }
        return store.lease(lease, epoch: epoch)
    }

    func end() {
        lock.lock(); defer { lock.unlock() }
        over = true
        if let epoch { store.release(epoch: epoch) }
        epoch = nil
    }
}

/// Set (from any thread) when the app asks the extension for the cache.
final class YieldFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
    func set() { lock.lock(); value = true; lock.unlock() }
}

/// Opening a workspace's cache, the one way it is done in the app: the key, the lock, a lease, the
/// file — and at every step the attempt may have been superseded, or the app sent away.
@MainActor
struct CacheOpening {
    let lock: StoreLock
    /// Is this attempt still the one that counts? Asked after every suspension.
    var isCurrent: () -> Bool
    var key: () -> String?
    var lease: () -> StoreLease
    var attach: (_ keyHex: String) async throws -> Void
    var keyRetry: Duration = .milliseconds(300)
    var maxWait: TimeInterval = 40

    enum Outcome {
        case open
        /// Another attempt took over: nothing is to be done or said.
        case superseded
        /// The app is not in front: silent, and tried again when it is.
        case closed
        /// The Keychain could not be read right now.
        case noKey
        /// The notification extension did not let go of the cache.
        case busy
        case failed(Error)
    }

    func run() async -> Outcome {
        guard lock.isOpen else { return .closed }
        var keyHex = key()
        for _ in 0..<3 where keyHex == nil {
            try? await Task.sleep(for: keyRetry)
            keyHex = key()
        }
        guard isCurrent() else { return .superseded }
        guard let keyHex else { return .noKey }
        let hold = await lock.holdForApp(maxWait: maxWait)
        guard isCurrent() else { return .superseded }
        switch hold {
        case .busy: return .busy
        case .closed: return .closed
        case .held: break
        }
        let lease = lease()
        guard lock.lease(lease) else { return .closed }
        do { try await attach(keyHex) } catch {
            let ended = lease.isOver()
            lease.detach()
            return !isCurrent() ? .superseded : ended ? .closed : .failed(error)
        }
        guard isCurrent() else { lease.detach(); return .superseded }
        return lease.isOver() ? .closed : .open
    }
}

/// When the app may hold the cache, in one place: in front; and behind only during a live call, or
/// for as long as a registration on its way needs — both under a background task, which the system
/// ends BEFORE it suspends the process, and which lets the cache go before it returns.
///
/// Why a call keeps it: in a call the core goes on exchanging keys (people join and leave, and the
/// call's media key changes with them), and every exchange advances the ratchets in the cache. So
/// the client needs the cache, and the lock with it. To let only the lock go and keep the client
/// working was build 50's mistake; to take the client away would leave whoever joins later unable
/// to hear this device. A call that ends, or stops being audio that keeps the process running,
/// takes both away.
@MainActor
final class StoreLifecycle {
    enum Phase: String { case launch, active, background }

    let lock: StoreLock
    private let system: BackgroundTime?
    /// Take the client down and cancel what would put one up.
    var takeDown: () -> Void = {}
    var callIsLive: () -> Bool = { false }
    /// Every front is SUSPECT from here on (the OS may take its listener and another process its
    /// port while the app is suspended): nothing is sent to it until it is proved ours again.
    /// Called on the way out, and on the way back in before anything that was queued runs.
    var suspectFronts: () -> Void = {}

    private(set) var phase: Phase = .launch
    /// Counts activations: one that suspended gives way to a later one — or to the background.
    private var generation = 0
    /// Counts returns to the front.
    private var fronts = 0
    /// The client was taken down (or not put up) because the app was not in front.
    private(set) var needsActivation = false

    init(lock: StoreLock, system: BackgroundTime? = nil) {
        self.lock = lock
        self.system = system
    }

    struct Ticket: Equatable { fileprivate let generation: Int; fileprivate let front: Int; let mayBind: Bool }

    /// An activation starts: every earlier one is over.
    func begin() -> Ticket {
        generation += 1
        let open = lock.isOpen
        needsActivation = !open
        return Ticket(generation: generation, front: fronts, mayBind: open)
    }

    /// Was it begun since the app came to the front? Only then has it proved — or will it prove —
    /// the front it binds through: suspicion was raised before it started.
    func begunInThisFront(_ ticket: Ticket) -> Bool { phase == .active && ticket.front == fronts }

    /// Is this still the latest activation, and the app still allowed to finish it?
    func holds(_ ticket: Ticket) -> Bool { ticket.generation == generation && (!ticket.mayBind || lock.isOpen) }

    /// The app is in front: the gate opens now, before anything that was waiting for it runs.
    func becameActive() {
        let back = phase != .active
        phase = .active
        StoreLockTrace.phase = phase.rawValue
        stopCallHold()
        stopDraining()
        if back {
            fronts += 1
            suspectFronts()
        }
        lock.openGate("active")
    }

    /// The app left the front. Without a live call nothing of the cache is in use, and the lock is
    /// free, when this returns (or, mid-registration, within the declared time).
    func enteredBackground() {
        guard phase != .background else { return }
        phase = .background
        StoreLockTrace.phase = phase.rawValue
        if lock.isOpen, callIsLive(), startCallHold() { return }
        close("background")
    }

    /// A call was answered while the app is not in front. True: the client may be put up now.
    func callAnswered() -> Bool {
        guard phase != .active, !lock.isOpen, callIsLive(), startCallHold() else { return false }
        lock.openGate("call")
        return true
    }

    /// Something a call needs ended: if the call was why the cache is held, it goes.
    func callMayHaveEnded() {
        guard callHold != nil, !callIsLive() else { return }
        close("call over")
    }

    private func close(_ why: String) {
        generation += 1
        needsActivation = true
        stopCallHold()
        takeDown()
        suspectFronts()
        guard !lock.closeGate(why, draining: true) else { return }
        // A registration is on its way: cut short, the host would know a device this device does
        // not remember.
        guard drainTask == nil else { return }
        drainTask = system?.begin("skwod.store.drain") { [weak self] in
            self?.lock.closeGate("time is up")
            self?.stopDraining()
        }
        guard drainTask != nil else { lock.closeGate("no background time"); return }
        pollDrain()
    }

    // MARK: Draining

    private var drainTask: Int?

    private func pollDrain() {
        system?.after(0.1) { [weak self] in
            guard let self, self.drainTask != nil else { return }
            if self.lock.drain() { self.stopDraining() } else { self.pollDrain() }
        }
    }

    private func stopDraining() {
        guard let task = drainTask else { return }
        drainTask = nil
        system?.end(task)
    }

    // MARK: A live call in the background

    /// How often the call's background task is replaced by a fresh one. While audio keeps the
    /// process running each is simply given back; when it no longer does, the system ends the one
    /// that is up before it suspends the process.
    static let callRenewal: TimeInterval = 10
    private var callHold: Int?

    private func startCallHold() -> Bool {
        let previous = callHold
        var expired = false
        guard let system, let task = system.begin("skwod.store.call", { [weak self] in
            expired = true
            self?.close("call: time is up")
        }) else { return false }
        if expired { system.end(task); return false }   // out of time before it was even granted
        callHold = task
        if let previous { system.end(previous) }
        system.after(Self.callRenewal) { [weak self] in
            guard let self, self.callHold == task else { return }
            if !self.callIsLive() || !self.startCallHold() { self.close("call over") }
        }
        return true
    }

    private func stopCallHold() {
        guard let task = callHold else { return }
        callHold = nil
        system?.end(task)
    }
}

/// The system's background tasks (UIKit's; injected in the tests).
struct BackgroundTime {
    /// Nil: none was granted. `expired` runs on the main thread; the task is given back there.
    var begin: @MainActor (_ name: String, _ expired: @escaping @MainActor () -> Void) -> Int?
    var end: @MainActor (Int) -> Void
    var after: @MainActor (TimeInterval, @escaping @MainActor () -> Void) -> Void
}

/// When the lock was taken and let go, with the scene's phase: in this device's own log only
/// (`log collect`), and read by DEBUG checks. Never content — only which step happened and when.
enum StoreLockTrace {
    private static let log = Logger(subsystem: "io.skwod.client", category: "storelock")
    private static let lock = NSLock()
    private static var events: [(String, Double)] = []
    private static var current = "launch"
    /// Keep the steps in memory too (DEBUG checks).
    static var enabled = false

    static var phase: String {
        get { lock.lock(); defer { lock.unlock() }; return current }
        set { lock.lock(); current = newValue; lock.unlock() }
    }

    static func note(_ step: String) {
        lock.lock(); defer { lock.unlock() }
        log.notice("\(step, privacy: .public) phase=\(current, privacy: .public)")
        guard enabled else { return }
        events.append((step, Date().timeIntervalSince1970))
    }

    static func snapshot() -> [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return events.map { ["step": $0.0, "at_ms": Int($0.1 * 1000)] }
    }
}
