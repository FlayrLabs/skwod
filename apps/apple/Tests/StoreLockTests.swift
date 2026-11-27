import XCTest

// Build 51: the cross-process lock on the encrypted cache, against a real lock file — the app sent
// away at every step of putting a client up, a launch in the background, a live call, and a wake of
// the notification extension that runs out of time.

/// The lock file as another process sees it (its own descriptor: `flock` really contends).
private final class OtherProcess {
    let directory: URL
    init() {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent("skwod-lock-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }
    deinit { try? FileManager.default.removeItem(at: directory) }
    private var fd: Int32 = -1

    /// Is the lock free right now?
    var free: Bool {
        guard take() else { return false }
        letGo()
        return true
    }
    func take() -> Bool {
        let h = open(directory.appendingPathComponent("store.lock").path, O_CREAT | O_RDWR, 0o600)
        guard h >= 0, flock(h, LOCK_EX | LOCK_NB) == 0 else { if h >= 0 { close(h) }; return false }
        fd = h
        return true
    }
    func letGo() { flock(fd, LOCK_UN); close(fd); fd = -1 }
    var yieldAsked: Bool { FileManager.default.fileExists(atPath: directory.appendingPathComponent("store.yield").path) }
}

/// A client's use of the cache.
private final class FakeLease: StoreLease {
    var over = false
    var busy = false
    var onDetach: (() -> Void)?
    func detach() { if !over { onDetach?() }; over = true }
    func detachIfIdle() -> Bool {
        if busy, !over { return false }
        detach()
        return true
    }
    func isOver() -> Bool { over }
}

private final class FakeClient {
    let lease = FakeLease()
    var online = false
    private(set) var usedWithoutLease = 0
    /// Everything the core does with the cache after the lease ended is refused there (Rust tests).
    func use() { if lease.over { usedWithoutLease += 1 } }
}

@MainActor
private final class FakeSystem {
    var granted: Int? = 100
    var running: [Int: @MainActor () -> Void] = [:]
    var ended: [Int] = []
    var timers: [(at: TimeInterval, fire: @MainActor () -> Void)] = []
    var now: TimeInterval = 0
    var expireWhileAsking = false

    func advance(_ seconds: TimeInterval) {
        let target = now + seconds
        while let next = timers.filter({ $0.at <= target }).min(by: { $0.at < $1.at }), let i = timers.firstIndex(where: { $0.at == next.at }) {
            now = next.at
            timers.remove(at: i).fire()
        }
        now = target
    }
    func expireAll() { for expired in Array(running.values) { expired() } }

    var system: BackgroundTime {
        .init(begin: { _, expired in
            guard let id = self.granted else { return nil }
            self.granted = id + 1
            if self.expireWhileAsking { expired() }
            self.running[id] = expired
            return id
        }, end: { self.running[$0] = nil; self.ended.append($0) },
           after: { s, f in self.timers.append((self.now + s, f)) })
    }
}

/// What `AppState` does with the lock, the lifecycle and the binding — the same calls in the same
/// order (`activate`, `bind`, `scheduleReconnect`, `enterForeground`) — with every await held open
/// on request.
@MainActor
private final class AppModel {
    let other = OtherProcess()
    let lock: StoreLock
    let store: StoreLifecycle
    let system = FakeSystem()
    let binding = ClientBinding<FakeClient>()
    var inCall = false
    var reconnect: Task<Void, Never>?
    var offline = false
    var hasKey = true
    var notices = 0
    var binds = 0
    var clients: [FakeClient] = []
    /// The front: suspect or not, and what was sent through it (in which return to the front).
    var suspect = false
    var challenges = 0
    var returns = 0
    var sent: [(foreground: Int, whileSuspect: Bool, provedIn: Int)] = []
    private var provedIn = 0
    var exempt = false
    /// The message a person wrote while the client was on its way.
    private var active: StoreLifecycle.Ticket?

    init() {
        let directory = other.directory
        lock = StoreLock(gated: true, directory: { directory })
        store = StoreLifecycle(lock: lock, system: system.system)
        store.takeDown = { [unowned self] in self.reconnect?.cancel(); self.binding.begin() }
        store.callIsLive = { [unowned self] in self.inCall }
        store.suspectFronts = { [unowned self] in if !(self.exempt && self.inCall) { self.suspect = true } }
    }

    // Steps.
    var stopAt: String?
    private(set) var reached: String?
    private var held: CheckedContinuation<Void, Never>?
    func step(_ name: String) async {
        guard stopAt == name else { return }
        stopAt = nil
        await withCheckedContinuation { held = $0; reached = name }
    }
    func go() { let h = held; held = nil; reached = nil; stopAt = nil; h?.resume() }
    func reach(_ name: String) async {
        for _ in 0..<400 where reached != name { try? await Task.sleep(for: .milliseconds(5)) }
        XCTAssertEqual(reached, name)
    }

    // `AppState`.
    func activate() async {
        reconnect?.cancel()
        let ticket = store.begin()
        active = ticket
        defer { if active == ticket { active = nil } }
        await step("flush")
        guard store.holds(ticket) else { return }
        guard ticket.mayBind else { return }
        let dial = Task { await self.resolve() }
        if binding.bound == nil {
            await bind(online: false)
            guard store.holds(ticket) else { return }
        }
        await dial.value
        guard store.holds(ticket) else { return }
        if suspect { return }   // (unproved: offline, and the reconnect loop)
        await step("arm")
        guard store.holds(ticket) else { return }
        send()
        if let up = binding.bound, up.cacheOpen, !up.client.online {
            if !offline {
                await step("session")
                guard binding.bound?.client === up.client, binding.bound?.turn == up.turn else { return }
                up.client.online = true
                binding.renew()
                await step("register")
            }
        } else {
            await bind(online: !offline)
        }
        guard store.holds(ticket), binding.bound != nil else { return }
        await step("lists")
        guard binding.bound != nil else { return }
        if offline { scheduleReconnect() }
    }

    /// `resolveBase`: the dial, and the challenge of a front that is suspect.
    func resolve() async {
        await step("dial")
        if suspect { await challenge() }
    }
    func challenge() async {
        challenges += 1
        let now = returns
        await step("challenge")
        // (Raised again meanwhile: this proof is of an earlier return.)
        if now == returns, store.phase == .active { suspect = false; provedIn = returns }
    }
    func send() { sent.append((returns, suspect, provedIn)) }

    func bind(online: Bool) async {
        let turn = binding.begin()
        let c = FakeClient()
        c.online = online
        clients.append(c)
        let opening = CacheOpening(
            lock: lock, isCurrent: { self.binding.isCurrent(turn) },
            key: { self.hasKey ? "key" : nil }, lease: { c.lease },
            attach: { _ in
                await self.step("attach")
                if c.lease.over { throw CancellationError() }   // (the core: `NoCache`)
            }, keyRetry: .milliseconds(40), maxWait: 5)
        switch await opening.run() {
        case .open: break
        case .superseded, .closed: return
        case .noKey: _ = binding.commit(turn, workspaceId: "w", client: c, cacheOpen: false); return
        case .busy, .failed:
            _ = binding.commit(turn, workspaceId: "w", client: c, cacheOpen: false)
            notices += 1
            return
        }
        c.use()
        await step("pin")
        guard binding.isCurrent(turn) else { return }
        guard binding.commit(turn, workspaceId: "w", client: c, cacheOpen: true) else { return }
        binds += 1
    }

    /// `AppState.clientForSending`.
    func clientForSending() async -> FakeClient? {
        for _ in 0..<200 {
            if let bound = binding.bound, bound.cacheOpen { return bound.client }
            try? await Task.sleep(for: .milliseconds(10))
        }
        return nil
    }

    func returnToFront() {
        if store.phase != .active { returns += 1 }
        store.becameActive()
    }

    func scheduleReconnect() {
        reconnect?.cancel()
        reconnect = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(20))
                guard !Task.isCancelled else { return }
                await self.step("redial")
                guard !Task.isCancelled else { return }
                self.offline = false
                Task { await self.activate() }
                return
            }
        }
    }

    func enterForeground() async {
        guard store.phase == .active else { return }
        if exempt, inCall { await challenge() }
        guard store.phase == .active else { return }
        if let active, active.mayBind, store.holds(active) {
            if !store.begunInThisFront(active) { await activate() }
            return
        }
        if store.needsActivation { await activate() }
    }

    /// The app may do nothing with the cache, and another process may take it.
    func assertGone(_ message: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(other.free, "the lock is held: \(message)", file: file, line: line)
        XCTAssertNil(binding.bound, "a client is up: \(message)", file: file, line: line)
        XCTAssertFalse(clients.contains { !$0.lease.over && lock.isHeld }, "a client has the cache: \(message)", file: file, line: line)
    }
    func settle(_ ms: Int = 120) async { try? await Task.sleep(for: .milliseconds(ms)) }
}

@MainActor
final class StoreLockTests: XCTestCase {
    // MARK: The gate

    func testNothingIsTakenBeforeTheAppIsInFront() async {
        let other = OtherProcess()
        let lock = StoreLock(gated: true, directory: { other.directory })
        XCTAssertFalse(lock.isOpen); XCTAssertFalse(lock.tryAcquire())
        let hold = await lock.holdForApp(maxWait: 1)
        XCTAssertEqual(hold, .closed); XCTAssertTrue(other.free); XCTAssertFalse(other.yieldAsked)
        lock.openGate("test")
        let opened = await lock.holdForApp(maxWait: 1)
        XCTAssertEqual(opened, .held); XCTAssertFalse(other.free)
        XCTAssertTrue(lock.closeGate("test"))
        XCTAssertTrue(other.free); XCTAssertFalse(lock.tryAcquire()); XCTAssertTrue(other.free)
    }

    func testEveryUseIsEndedBeforeTheLockIsLetGo() {
        let other = OtherProcess()
        let lock = StoreLock(gated: true, directory: { other.directory })
        lock.openGate("test")
        let early = FakeLease()
        XCTAssertFalse(lock.lease(early), "no use without the lock")
        XCTAssertTrue(lock.tryAcquire())
        let a = FakeLease(), b = FakeLease()
        XCTAssertTrue(lock.lease(a)); XCTAssertTrue(lock.lease(b))
        var freeWhenDetached: [Bool] = []
        for l in [a, b] { l.onDetach = { freeWhenDetached.append(other.free) } }
        lock.closeGate("test")
        XCTAssertEqual(freeWhenDetached, [false, false])
        XCTAssertTrue(other.free)
        XCTAssertFalse(lock.lease(FakeLease()))
    }

    func testAWaitForTheLockEndsAtOnceWhenTheAppIsSentAway() async {
        let other = OtherProcess()
        let lock = StoreLock(gated: true, directory: { other.directory })
        lock.openGate("test")
        XCTAssertTrue(other.take())
        let waiting = Task { await lock.holdForApp() }
        for _ in 0..<100 where !other.yieldAsked { try? await Task.sleep(for: .milliseconds(10)) }
        XCTAssertTrue(other.yieldAsked, "the extension is asked to yield")
        let left = Date()
        lock.closeGate("test")
        XCTAssertLessThan(Date().timeIntervalSince(left), 0.05, "closing does not wait for the waiter")
        let hold = await waiting.value
        XCTAssertEqual(hold, .closed)
        XCTAssertLessThan(Date().timeIntervalSince(left), 1)
        XCTAssertFalse(other.yieldAsked, "a wake meanwhile is not told the app wants the cache")
        other.letGo()
        try? await Task.sleep(for: .milliseconds(300))
        XCTAssertTrue(other.free)
    }

    func testTheExtensionStillYieldsToTheApp() async {
        let other = OtherProcess()
        let app = StoreLock(gated: true, directory: { other.directory })
        let wake = WakeHold(StoreLock(directory: { other.directory }))
        app.openGate("test")
        XCTAssertTrue(wake.acquire())
        let ext = StoreLock(directory: { other.directory })
        let lease = FakeLease()
        XCTAssertTrue(wake.lease(lease))
        let watcher = Task {
            while !ext.yieldRequested { try? await Task.sleep(for: .milliseconds(20)) }
            wake.end()
        }
        let hold = await app.holdForApp(maxWait: 5)
        await watcher.value
        XCTAssertEqual(hold, .held); XCTAssertTrue(lease.over); XCTAssertFalse(other.free); XCTAssertFalse(other.yieldAsked)
        XCTAssertFalse(WakeHold(ext).acquire(), "and gives up at once while the app has it")
    }

    /// A marker left behind by an earlier run (older than a minute) is written afresh, so the
    /// extension takes the app's request for one.
    func testAStaleYieldMarkerIsRenewedByTheNextRequest() async {
        let other = OtherProcess()
        let marker = other.directory.appendingPathComponent("store.yield")
        try? Data(String(Date().timeIntervalSince1970 - 600).utf8).write(to: marker)
        let app = StoreLock(gated: true, directory: { other.directory })
        let wake = WakeHold(StoreLock(directory: { other.directory }))
        app.openGate("test")
        XCTAssertTrue(wake.acquire())
        let ext = StoreLock(directory: { other.directory })
        XCTAssertFalse(ext.yieldRequested, "debris, not a request")
        let watcher = Task {
            for _ in 0..<150 where !ext.yieldRequested { try? await Task.sleep(for: .milliseconds(20)) }
            wake.end()
        }
        let hold = await app.holdForApp(maxWait: 2)
        await watcher.value
        XCTAssertEqual(hold, .held, "the extension saw the request and let go")
    }

    /// A lock that asked for the yield notification and is gone is no longer called by it.
    func testALockThatIsGoneIsNoLongerObserved() async {
        let before = StoreLock.observers.value
        let other = OtherProcess()
        weak var gone: StoreLock?
        do {
            let lock = StoreLock(directory: { other.directory })
            lock.onYield {}
            gone = lock
            XCTAssertEqual(StoreLock.observers.value, before + 1)
        }
        XCTAssertNil(gone)
        XCTAssertEqual(StoreLock.observers.value, before, "removed from the Darwin center")
        // A request now reaches only the lock that is still there.
        let still = StoreLock(directory: { other.directory })
        let fired = YieldFlag()
        still.onYield { fired.set() }
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             CFNotificationName(StoreLock.yieldNotification as CFString), nil, nil, true)
        for _ in 0..<100 where !fired.isSet { try? await Task.sleep(for: .milliseconds(20)) }
        XCTAssertTrue(fired.isSet)
    }

    // MARK: Sent away at every step

    private let steps = ["flush", "dial", "challenge", "arm", "attach", "pin", "session", "register", "lists"]

    func testSentAwayAtEveryStepOfAnActivationAndBroughtBack() async {
        for name in steps {
            let app = AppModel()
            app.returnToFront()
            app.stopAt = name
            let activation = Task { await app.activate() }
            await app.reach(name)
            app.store.enteredBackground()
            app.assertGone("sent away at \(name)")
            app.go()
            await activation.value
            await app.settle()
            app.assertGone("after \(name) came back")
            XCTAssertEqual(app.notices, 0, "\(name): silent")
            let before = app.binds
            app.returnToFront()
            async let one: Void = app.enterForeground()
            async let two: Void = app.enterForeground()
            _ = await (one, two)
            XCTAssertEqual(app.binds, before + 1, "\(name): exactly one activation")
            XCTAssertNotNil(app.binding.bound); XCTAssertFalse(app.other.free)
            app.store.enteredBackground()
            app.assertGone("away again after \(name)")
        }
    }

    // MARK: The fronts

    /// Nothing is sent to a front before a challenge of THIS return to the front, whatever was
    /// already on its way, and whichever of UIKit and the scene says first that the app is back.
    func testNothingIsSentToAFrontNotProvedSinceTheAppCameBack() async {
        for sceneFirst in [true, false] {
            for name in ["flush", "dial", "challenge", "arm", "attach", "pin", "session", "lists"] {
                let app = AppModel()
                app.returnToFront()
                app.stopAt = name
                let before = Task { await app.activate() }
                await app.reach(name)
                app.store.enteredBackground()
                XCTAssertTrue(app.suspect, "\(name): suspect before the process can be suspended")
                app.returnToFront()
                XCTAssertTrue(app.suspect, "\(name): and on the way back, at once")
                let scene = { app.returnToFront(); await app.enterForeground() }
                let uikit = { app.returnToFront(); if app.store.needsActivation { await app.enterForeground() } }
                let first = Task { @MainActor in if sceneFirst { await scene() } else { await uikit() } }
                let second = Task { @MainActor in if sceneFirst { await uikit() } else { await scene() } }
                app.go()
                _ = await (before.value, first.value, second.value)
                await app.settle(30)
                XCTAssertFalse(app.sent.contains { $0.whileSuspect }, name)
                XCTAssertFalse(app.sent.contains { $0.foreground == 2 && $0.provedIn != 2 }, "\(name): a proof of an earlier return counts for nothing")
                XCTAssertFalse(app.suspect, "\(name): proved"); XCTAssertTrue(app.binding.bound?.client.online ?? false, name)
                XCTAssertEqual(app.returns, 2, "one return, however many say so")
            }
        }
    }

    func testDuringACallAnActivationFromBehindStartsOverAndTheCallsFrontIsChallengedAtOnce() async {
        for exempt in [true, false] {
            for name in ["dial", "arm", "session"] {
                let app = AppModel()
                app.inCall = true
                app.exempt = exempt
                XCTAssertTrue(app.store.callAnswered())
                app.stopAt = name
                let behind = Task { await app.activate() }
                await app.reach(name)
                app.returnToFront()
                XCTAssertEqual(app.suspect, !exempt)
                let challenged = app.challenges
                let back = Task { await app.enterForeground() }
                await app.settle(20)
                XCTAssertGreaterThan(app.challenges, challenged, "\(name): challenged at once")
                app.go()
                _ = await (behind.value, back.value)
                XCTAssertFalse(app.sent.contains { $0.whileSuspect }, name)
                XCTAssertFalse(app.sent.contains { $0.foreground == 1 && $0.provedIn != 1 }, name)
                XCTAssertNotNil(app.binding.bound, name)
            }
        }
        // A call whose hold lapses behind the front: suspect before the process can be suspended.
        let app = AppModel()
        app.returnToFront(); await app.activate(); app.inCall = true; app.exempt = true
        app.store.enteredBackground()
        XCTAssertFalse(app.suspect)
        app.inCall = false
        app.system.expireAll()
        XCTAssertTrue(app.suspect)
        app.assertGone("lapsed")
    }

    // MARK: What the user writes and reads

    /// The host does not answer: what this device has is up at once, and takes what is written.
    func testWithNoAnswerFromTheHostTheClientIsUpAtOnceAndStaysUpWhenItAnswers() async {
        let app = AppModel()
        app.returnToFront()
        app.stopAt = "dial"
        let start = Date()
        let activation = Task { await app.activate() }
        let client = await app.clientForSending()
        XCTAssertNotNil(client); XCTAssertLessThan(Date().timeIntervalSince(start), 0.5)
        XCTAssertEqual(client?.online, false); XCTAssertFalse(client?.lease.over ?? true)
        let turn = app.binding.bound?.turn
        await app.reach("dial")
        app.go()
        await activation.value
        XCTAssertTrue(app.binding.bound?.client === client, "the same client, its cache open throughout")
        XCTAssertEqual(client?.online, true); XCTAssertEqual(app.binds, 1)
        XCTAssertNotEqual(app.binding.bound?.turn, turn, "screens catch up through it")
    }

    /// Written in the instant the app comes back: it waits for the client, and is handed to it.
    func testWhatIsWrittenBeforeTheClientIsUpIsHandedToIt() async {
        let app = AppModel()
        app.returnToFront(); await app.activate()
        app.store.enteredBackground()
        app.returnToFront()
        let written = Task { await app.clientForSending() }
        await app.settle(30)
        await app.enterForeground()
        let client = await written.value
        XCTAssertNotNil(client); XCTAssertFalse(client?.lease.over ?? true)
        // Also while the notification extension finishes.
        app.store.enteredBackground()
        XCTAssertTrue(app.other.take())
        app.returnToFront()
        let back = Task { await app.enterForeground() }
        let waiting = Task { await app.clientForSending() }
        await app.settle(200)
        app.other.letGo()
        let late = await waiting.value
        await back.value
        XCTAssertNotNil(late); XCTAssertEqual(app.notices, 0)
    }

    func testSentAwayWhileTheKeychainIsAskedAgain() async {
        let app = AppModel()
        app.returnToFront()
        app.hasKey = false
        let activation = Task { await app.activate() }
        await app.settle(60)
        app.store.enteredBackground()
        app.hasKey = true
        await activation.value
        app.assertGone("key retry")
        XCTAssertEqual(app.notices, 0)
    }

    func testSentAwayWhileTheExtensionHasTheCache() async {
        let app = AppModel()
        app.returnToFront()
        XCTAssertTrue(app.other.take())
        let activation = Task { await app.activate() }
        await app.settle()
        app.store.enteredBackground()
        app.other.letGo()
        await activation.value
        await app.settle(300)
        app.assertGone("waiting for the extension")
        XCTAssertEqual(app.notices, 0, "no notice, no retry from behind")
    }

    func testTheReconnectLoopPutsNothingUpFromBehind() async {
        let app = AppModel()
        app.returnToFront()
        app.offline = true
        app.stopAt = "redial"
        await app.activate()
        await app.reach("redial")
        app.store.enteredBackground()
        app.assertGone("redialing")
        app.go()
        await app.settle()
        app.assertGone("the dial came back")
        XCTAssertEqual(app.binds, 1)
    }

    func testAForegroundTaskThatRunsTooLateDoesNothing() async {
        let app = AppModel()
        app.returnToFront()
        await app.activate()
        app.store.enteredBackground()
        app.returnToFront()
        let queued = Task { await app.enterForeground() }   // not run yet
        app.store.enteredBackground()
        await queued.value
        await app.settle()
        app.assertGone("a queued foreground task")
    }

    func testALaunchInTheBackgroundTakesNothingAndOpeningTheAppActivatesOnce() async {
        let app = AppModel()
        await app.activate()   // `restore`
        await app.activate()   // a wake, a network change, a ring
        app.assertGone("background launch")
        XCTAssertEqual(app.binds, 0)
        app.returnToFront()
        await app.enterForeground()
        await app.enterForeground()
        XCTAssertEqual(app.binds, 1)
        // One begun behind that is still on its way does not stand for it.
        let late = AppModel()
        late.stopAt = "flush"
        let behind = Task { await late.activate() }
        await late.reach("flush")
        late.returnToFront()
        await late.enterForeground()
        late.go()
        await behind.value
        XCTAssertEqual(late.binds, 1)
        // …and an ordinary launch: the launch's own activation is not doubled.
        let front = AppModel()
        front.returnToFront()
        front.stopAt = "dial"
        let launch = Task { await front.activate() }
        await front.reach("dial")
        await front.enterForeground()
        front.go()
        await launch.value
        XCTAssertEqual(front.binds, 1)
    }

    // MARK: Pairing

    func testPairingIsCutOffAndNotTakenUpFromBehind() async {
        for name in ["attach", "poll"] {
            let app = AppModel()
            app.returnToFront()
            let lease = FakeLease()
            app.stopAt = name
            var open = false
            let pairing = Task { @MainActor in
                let outcome = await CacheOpening(lock: app.lock, isCurrent: { !Task.isCancelled }, key: { "k" }, lease: { lease },
                                                 attach: { _ in await app.step("attach"); if lease.over { throw CancellationError() } }).run()
                if case .open = outcome { open = true } else { return }
                await app.step("poll")
            }
            await app.reach(name)
            app.store.enteredBackground()
            XCTAssertTrue(app.other.free, name); XCTAssertTrue(lease.over, name)
            app.go()
            await pairing.value
            XCTAssertTrue(app.other.free, name); XCTAssertEqual(open, name == "poll", "an open that was cut off says so")
        }
        // A pairing that only now gets to the lock, from behind.
        let app = AppModel()
        let lease = FakeLease()
        let outcome = await CacheOpening(lock: app.lock, isCurrent: { true }, key: { "k" }, lease: { lease }, attach: { _ in XCTFail("opened") }).run()
        if case .closed = outcome {} else { XCTFail("\(outcome)") }
        XCTAssertTrue(app.other.free)
    }

    // MARK: A registration on its way

    func testARegistrationIsFinishedUnderADeclaredTaskAndCutShortWhenTimeIsUp() async {
        let app = AppModel()
        app.returnToFront()
        await app.activate()
        let lease = app.clients[0].lease
        lease.busy = true
        app.store.enteredBackground()
        XCTAssertNil(app.binding.bound, "the client is taken down all the same")
        XCTAssertFalse(app.other.free); XCTAssertEqual(app.system.running.count, 1)
        XCTAssertFalse(app.lock.tryAcquire(), "nothing new is opened"); XCTAssertFalse(app.lock.lease(FakeLease()))
        lease.busy = false
        app.system.advance(0.2)
        XCTAssertTrue(lease.over); XCTAssertTrue(app.other.free); XCTAssertEqual(app.system.running.count, 0)

        // Out of time: let go before the warning returns.
        app.returnToFront()
        await app.enterForeground()
        let second = app.clients.last!.lease
        second.busy = true
        app.store.enteredBackground()
        XCTAssertFalse(app.other.free)
        app.system.expireAll()
        XCTAssertTrue(app.other.free); XCTAssertTrue(second.over); XCTAssertEqual(app.system.running.count, 0)

        // No background time is granted: at once.
        app.returnToFront()
        await app.enterForeground()
        let third = app.clients.last!.lease
        third.busy = true
        app.system.granted = nil
        app.store.enteredBackground()
        XCTAssertTrue(third.over); XCTAssertTrue(app.other.free)
    }

    func testBackInFrontNothingIsOpenedBesideARegistrationThatIsStillGoing() async {
        let app = AppModel()
        app.returnToFront()
        await app.activate()
        let old = app.clients[0].lease
        old.busy = true
        app.store.enteredBackground()
        app.returnToFront()
        XCTAssertEqual(app.system.running.count, 0, "in front: no background task")
        let back = Task { await app.enterForeground() }
        await app.settle(250)
        XCTAssertNil(app.binding.bound, "two clients never use one cache")
        old.busy = false
        await back.value
        XCTAssertTrue(old.over); XCTAssertEqual(app.binds, 2)
    }

    // MARK: A call

    func testALiveCallKeepsTheCacheAndLetsGoWhenItEndsOrTimeIsUp() async {
        // Kept while the call lives…
        let app = AppModel()
        app.returnToFront()
        await app.activate()
        app.inCall = true
        app.store.enteredBackground()
        XCTAssertNotNil(app.binding.bound); XCTAssertFalse(app.other.free); XCTAssertEqual(app.system.running.count, 1)
        app.system.advance(95)
        XCTAssertNotNil(app.binding.bound); XCTAssertEqual(app.system.running.count, 1, "renewed, never piled up")
        XCTAssertEqual(app.system.ended.count, 9)
        // …and let go with it.
        app.inCall = false
        app.store.callMayHaveEnded()
        app.assertGone("the call is over"); XCTAssertEqual(app.system.running.count, 0)

        // The call stopped without a word: found at the next renewal.
        let quiet = AppModel()
        quiet.returnToFront(); await quiet.activate(); quiet.inCall = true
        quiet.store.enteredBackground()
        quiet.inCall = false
        quiet.system.advance(StoreLifecycle.callRenewal)
        quiet.assertGone("no call any more"); XCTAssertEqual(quiet.system.running.count, 0)

        // The audio no longer keeps the process running: gone before the warning returns.
        let expired = AppModel()
        expired.returnToFront(); await expired.activate(); expired.inCall = true
        expired.store.enteredBackground()
        expired.system.expireAll()
        expired.assertGone("the system's warning"); XCTAssertEqual(expired.system.running.count, 0)

        // None is granted, or it runs out while being asked for: not kept at all.
        for expire in [false, true] {
            let none = AppModel()
            none.returnToFront(); await none.activate(); none.inCall = true
            if expire { none.system.expireWhileAsking = true } else { none.system.granted = nil }
            none.store.enteredBackground()
            none.assertGone("no background time"); XCTAssertEqual(none.system.running.count, 0)
        }
    }

    func testACallAnsweredFromBehindPutsTheClientUpAndARingingOneDoesNot() async {
        let app = AppModel()
        await app.activate()   // what a call wake does while it rings
        app.assertGone("ringing")
        XCTAssertFalse(app.store.callAnswered(), "not live: nothing is opened")
        app.inCall = true
        XCTAssertTrue(app.store.callAnswered())
        await app.activate()
        XCTAssertNotNil(app.binding.bound); XCTAssertFalse(app.other.free); XCTAssertEqual(app.system.running.count, 1)
        app.inCall = false
        app.store.callMayHaveEnded()
        app.assertGone("hung up")
    }

    func testBackInFrontDuringACallNothingIsReplaced() async {
        let app = AppModel()
        app.returnToFront(); await app.activate(); app.inCall = true
        app.store.enteredBackground()
        app.returnToFront()
        await app.enterForeground()
        XCTAssertEqual(app.binds, 1); XCTAssertEqual(app.system.running.count, 0)
        app.inCall = false
        app.store.callMayHaveEnded()
        XCTAssertNotNil(app.binding.bound, "in front a call that ends takes nothing away")
    }

    // MARK: The extension

    func testAWakeThatRunsOutOfTimeLetsGoWhateverItLeftBehind() {
        let other = OtherProcess()
        let store = StoreLock(directory: { other.directory })
        let wake = WakeHold(store)
        XCTAssertTrue(wake.acquire()); XCTAssertFalse(other.free)
        let leftBehind = FakeLease()
        leftBehind.busy = true
        var freeWhenDetached: Bool?
        leftBehind.onDetach = { freeWhenDetached = other.free }
        XCTAssertTrue(wake.lease(leftBehind))
        wake.end()   // `serviceExtensionTimeWillExpire`, or before the banner is delivered
        XCTAssertEqual(freeWhenDetached, false); XCTAssertTrue(leftBehind.over); XCTAssertTrue(other.free)
        // What the call that was left behind does next gets nothing.
        XCTAssertFalse(wake.lease(FakeLease())); XCTAssertFalse(wake.acquire()); XCTAssertTrue(other.free)
        // The next wake of the same process is its own.
        let next = WakeHold(store)
        XCTAssertTrue(next.acquire())
        XCTAssertFalse(wake.lease(FakeLease()), "not through another wake's hold either")
        wake.end()
        XCTAssertFalse(other.free, "nor does its end take the next one's away")
        XCTAssertFalse(WakeHold(store).acquire(), "one wake at a time")
        next.end()
        XCTAssertTrue(other.free)
    }

    func testAWakeThatIsOverBeforeItTookTheCacheTakesNothing() {
        let other = OtherProcess()
        let wake = WakeHold(StoreLock(directory: { other.directory }))
        wake.end()
        XCTAssertFalse(wake.acquire()); XCTAssertTrue(other.free)
    }
}
