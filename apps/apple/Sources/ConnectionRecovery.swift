import Foundation

/// Build 51: when the connection behind a p2p front is replaced.
///
/// A front is a loopback proxy in this process (stable for the life of the process) plus the
/// connection to the host behind it. After the app was suspended the OS may have taken the
/// endpoint's UDP sockets or the front's listener away. The app checks the front IN PROCESS
/// (`P2pSession.check`): a front not proved ours listens again (`ensureFront`); a host that does
/// not answer gets a fresh connection behind the same front (`reconnect`, paced in the core).
///
/// Pure, so it is tested (`Build51Tests`).
enum SessionHealthRule {
    /// How long one probe may take. A healthy session answers in well under a second; a
    /// connection being re-dialed in place usually within two or three.
    static let probeTimeout: TimeInterval = 6
    /// Probes in a row that must fail before a session is replaced when nothing in particular
    /// happened (the periodic check): one slow answer is not a dead session.
    static let failuresBeforeReplacing = 2
    /// How often the session is probed while the app is in front.
    static let foregroundInterval: TimeInterval = 20
    /// A probe that succeeded this recently stands for "healthy" when the app comes to the
    /// front again (macOS activates the scene on every window focus).
    static let freshFor: TimeInterval = 3

    enum Outcome: Equatable {
        /// It answered: the indicator follows the path again.
        case healthy
        /// It did not, but not often enough yet: "Reconnecting…", and the next probe decides.
        case degraded
        /// Tear the session down and dial again.
        case replace
    }

    /// `urgent`: the app just came to the front, the Mac woke, the network changed, or the
    /// user pressed Retry — the moments a dead session is most likely, and when the user is
    /// looking. One failed probe is enough then.
    static func next(failures: Int, proxyOK: Bool, upstreamOK: Bool, urgent: Bool) -> (failures: Int, outcome: Outcome) {
        // The loopback proxy is dead or not ours: nothing can go through it, ever again.
        guard proxyOK else { return (0, .replace) }
        if upstreamOK { return (0, .healthy) }
        let failures = failures + 1
        if urgent || failures >= failuresBeforeReplacing { return (0, .replace) }
        return (failures, .degraded)
    }

    /// Is a probe needed now? Not again within `freshFor` of one that answered (unless the user
    /// asked), and never two at once (the caller coalesces those).
    static func shouldProbe(lastOK: Date?, now: Date, userAsked: Bool) -> Bool {
        if userAsked { return true }
        guard let lastOK else { return true }
        return now.timeIntervalSince(lastOK) >= freshFor
    }
}

/// Build 51: when every conversation catches up with the host. Become-active, wake, a network
/// that came back and a connection that was re-established all ask for one; they often arrive
/// together (foreground = scene active + network re-probe + socket up), so requests are
/// coalesced: one runs at a time, a request during a run makes exactly one more run after it,
/// and runs are at least `minGap` apart. Pure state, so it is tested (`Build51Tests`).
struct CatchUpGate {
    static let minGap: TimeInterval = 2

    private(set) var running = false
    private(set) var again = false
    private(set) var lastStart: Date?

    enum Decision: Equatable {
        /// Start a run now.
        case start
        /// Start one after waiting this long (the previous run started too recently).
        case startAfter(TimeInterval)
        /// A run is going: it will run once more when it ends.
        case queued
    }

    mutating func request(now: Date) -> Decision {
        if running { again = true; return .queued }
        running = true
        if let lastStart, now.timeIntervalSince(lastStart) < Self.minGap {
            return .startAfter(Self.minGap - now.timeIntervalSince(lastStart))
        }
        return .start
    }

    /// Every joined channel is swept when the live socket came (back) up since the last sweep —
    /// events may have been missed — and otherwise at most once a `sweepFloor`. (macOS makes
    /// the scene active on every window focus; with the socket live all along nothing was
    /// missed, and the host is not asked about every channel each time.)
    static let sweepFloor: TimeInterval = 60
    static func sweepDue(lastSweep: Date?, now: Date, socketCameUpSince: Bool) -> Bool {
        guard let lastSweep, !socketCameUpSince else { return true }
        return now.timeIntervalSince(lastSweep) >= sweepFloor
    }

    /// The run is starting (after any wait).
    mutating func started(now: Date) { lastStart = now }

    /// The run ended. True: run again (something asked meanwhile) — `request` was already taken.
    mutating func finished() -> Bool {
        if again { again = false; return true }
        running = false
        return false
    }
}

/// Build 51: a conversation whose catch-up failed is retried — with backoff, a bounded number
/// of times — and the user is told, never left looking at a silently empty or stale list.
enum FetchRetryRule {
    /// Seconds before retry `attempt` (1-based); nil = stop retrying and offer "Retry".
    static func delay(afterFailure attempt: Int) -> TimeInterval? {
        guard attempt >= 1, attempt <= maxAttempts else { return nil }
        return min(2 * pow(2, Double(attempt - 1)), 30)
    }
    static let maxAttempts = 5

    /// What the list shows above the messages.
    enum Status: Equatable {
        case ok
        /// A fetch failed and another is on its way ("Reconnecting…").
        case retrying
        /// The retries ran out ("Couldn't load new messages · Retry").
        case failed
    }

    /// `stripShowing`: the strip across the top already says the skwod can't be reached; the list
    /// does not say it a second time.
    static func status(failures: Int, stripShowing: Bool = false) -> Status {
        if failures == 0 || stripShowing { return .ok }
        return failures > maxAttempts ? .failed : .retrying
    }
}

/// Build 51: where the message list goes. A conversation opens at its NEWEST message (the
/// "N new messages since…" bar jumps up to the first unread, and the "New" divider stays). A
/// message that arrives follows the reader down only if they were at (or near) the bottom, or
/// if it is their own; someone reading history is not yanked down — the "↓ N new" pill says
/// what came in instead.
enum ChatScrollRule {
    enum Arrival: Equatable { case follow, pill, nothing }

    static func onArrival(atBottom: Bool, newestIsMine: Bool, justSent: Bool, newFromOthers: Int) -> Arrival {
        if atBottom || newestIsMine || justSent { return .follow }
        return newFromOthers > 0 ? .pill : .nothing
    }

    /// Where a conversation opens: always the newest message.
    static let opensAtNewest = true

    /// Is the reader still "at the bottom"? Reaching the end always is. Leaving it takes the
    /// reader (or a jump) MOVING the list: rows that arrive, a window or safe area that changes,
    /// or a return from the background move only the end — and a reader who was at the bottom
    /// still is, so the next arrival follows them down instead of showing the pill.
    static func stillAtBottom(was: Bool, offsetMoved: Bool, nowAtEnd: Bool) -> Bool {
        if nowAtEnd { return true }
        return offsetMoved ? false : was
    }
}

/// Build 51: what an open conversation's loading is keyed on — the conversation, and the client
/// that is up (its bind turn). A new client means a reload from its cache and a catch-up through it.
struct ConversationLoadKey: Hashable {
    let id: String
    let clientTurn: Int?
}

/// Build 51: a dial is used only under the settings it was started with. The relay setting
/// changing in between (relays turned OFF) makes it unusable however it ends.
enum DialRule {
    static func usable(dialGeneration: Int, currentGeneration: Int, dialFallback: Bool, currentFallback: Bool) -> Bool {
        dialGeneration == currentGeneration && dialFallback == currentFallback
    }
}

/// Build 51: which moments count as URGENT for a health check (one failed probe replaces the
/// connection then). A real event — back from the background, a wake, a network change, Retry —
/// is; a window merely getting focus (macOS makes the scene active on every focus) is not.
enum UrgencyRule {
    enum Trigger: Equatable { case foreground, windowFocus, wake, networkChange, userRetry, timer }
    static func isUrgent(_ t: Trigger) -> Bool {
        switch t {
        case .foreground, .wake, .networkChange, .userRetry: return true
        case .windowFocus, .timer: return false
        }
    }
}

/// Build 51: how a session is ended — by what it is bound through.
enum SignOutRoute: Equatable {
    /// An https server: told directly (logout + push unregister there).
    case server
    /// A p2p front: through the core over the member connection (`P2pSession.endSession`).
    case front
    /// Nothing reachable to tell.
    case none

    static func of(boundBase: String?, boundIsFront: Bool, isP2P: Bool) -> SignOutRoute {
        if let b = boundBase, !b.isEmpty { return boundIsFront ? .front : .server }
        return isP2P ? .front : .none
    }
}

/// Build 51 (review): what asking a front to prove itself came to. A call may delay a re-key (in
/// the core: `ensureFrontDeferring`); it never turns a proof that failed into a trusted front.
enum FrontProof: Equatable {
    /// Proved ours, as it was.
    case proved
    /// Re-keyed: every client is bound again.
    case moved
    /// Not proved (or not asked): suspect, nothing is sent; ask again.
    case unproved

    static func of(relistened: Bool, failed: Bool, stillSuspect: Bool) -> FrontProof {
        if failed || (stillSuspect && !relistened) { return .unproved }
        return relistened ? .moved : .proved
    }

    /// Does this, with what may be sent to the front now, stand for a healthy connection?
    static func isHealthy(_ proof: FrontProof, maySend: Bool) -> Bool { proof == .proved && maySend }
}

/// Build 51 (review): back in front, EVERY front is suspect until proved. The one exemption: the
/// front carrying a call that is connected with a live audio session — the app was never suspended
/// with it — and that one is challenged at once all the same.
enum ForegroundRule {
    static func exempt(callWorkspace: String?, connected: Bool, audioLive: Bool) -> String? {
        connected && audioLive ? callWorkspace : nil
    }
}

/// Build 51 (review): the relay setting, in order and failing closed. Off: the core confirms that
/// nothing relay-allowed is left first; only then is anything dialed again — otherwise every
/// session is disconnected and the user told (false). On: the core allows it first.
enum RelayOptOut {
    @MainActor
    /// `current`: is this still the newest change? Superseded, the later run does the rest.
    static func apply(relaysOn: Bool, current: () -> Bool = { true }, turnOn: () -> Void, turnOff: () async throws -> Void, redial: () async -> Void,
                      disconnectAll: () async -> Void) async -> Bool {
        guard current() else { return true }
        if relaysOn { turnOn() } else {
            do { try await turnOff() } catch {
                await disconnectAll()
                return false
            }
        }
        guard current() else { return true }
        await redial()
        return true
    }
}

/// Build 51: the front base a loopback request URL is under (`http://127.0.0.1:<port>/<secret>`),
/// nil for any other URL (an https server, a gateway).
enum FrontURL {
    static func base(of url: String) -> String? {
        let prefix = "http://127.0.0.1:"
        guard url.hasPrefix(prefix) else { return nil }
        let rest = url.dropFirst(prefix.count)
        let parts = rest.split(separator: "/", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, UInt16(parts[0]) != nil else { return nil }
        let secret = parts[1].split(whereSeparator: { $0 == "?" || $0 == "#" }).first.map(String.init) ?? ""
        return prefix + parts[0] + "/" + secret
    }
}

/// Build 51: is `url` a request to the proxy at `base` (same scheme, host, port AND secret)?
enum URLScope {
    static func isUnder(_ url: String?, base: String) -> Bool {
        guard let url, !base.isEmpty else { return false }
        let b = base.hasSuffix("/") ? String(base.dropLast()) : base
        return url == b || url.hasPrefix(b + "/") || url.hasPrefix(b + "?")
    }
}

/// Build 51: what a client presents for a base. Through a front ONLY its credential (none: nil —
/// nothing is sent); to an https server the account token. Never the token to a front.
enum WireRule {
    static func of(baseIsFront: Bool, credential: String?, token: String) -> String? {
        if baseIsFront { return (credential?.isEmpty ?? true) ? nil : credential }
        return token.isEmpty ? nil : token
    }
}

/// Build 51: after an await, is the workspace still the one we started with — present, not
/// signed out, the same token? (A sign-out meanwhile must not be undone by a bind finishing.)
enum LiveRecordRule {
    static func stillValid(liveId: String?, liveSignedOut: Bool, liveToken: String?, startId: String, startToken: String) -> Bool {
        liveId == startId && !liveSignedOut && liveToken == startToken && !startToken.isEmpty
    }
}

/// Build 51 (review): everything that signs a workspace in to its front, rotates its token or
/// asks on its behalf runs one at a time per workspace, in order.
@MainActor
final class SerialByKey {
    private var tails: [String: Task<Void, Never>] = [:]

    func run<T: Sendable>(_ key: String, _ body: @escaping @MainActor () async -> T) async -> T {
        await enqueue(key, body).value
    }

    /// Nil when it has not finished within `deadline`: the CALLER stops waiting. What was started
    /// goes on to its end, and whatever is behind it keeps waiting — never two at once.
    func run<T: Sendable>(_ key: String, deadline: Duration, _ body: @escaping @MainActor () async -> T?) async -> T? {
        let task = enqueue(key, body)
        return await withCheckedContinuation { (done: CheckedContinuation<T?, Never>) in
            var finished = false
            let finish: @MainActor (T?) -> Void = { value in
                guard !finished else { return }
                finished = true
                done.resume(returning: value)
            }
            Task { @MainActor in finish(await task.value) }
            Task { @MainActor in try? await Task.sleep(for: deadline); finish(nil) }
        }
    }

    private func enqueue<T: Sendable>(_ key: String, _ body: @escaping @MainActor () async -> T) -> Task<T, Never> {
        let before = tails[key]
        let task = Task { @MainActor in
            await before?.value
            return await body()
        }
        tails[key] = Task { _ = await task.value }
        return task
    }
}

/// Build 51 (review): the one rule for ending a session because of what a server answered.
enum SignOutRule {
    /// `confirmed`: the core says the HOST refused the CURRENT token, twice. `sameBind`: the client
    /// that asked is still the one bound. `sameRecord`: the stored record is still that session.
    static func mayEnd(confirmed: Bool, sameBind: Bool, sameRecord: Bool) -> Bool { confirmed && sameBind && sameRecord }
}

/// Build 51 (review): changes of the relay setting. OFF takes effect the moment it is chosen
/// (`revoke`), whatever an earlier change is still doing; confirming it and dialing again wait
/// their turn, and a change superseded by a later one leaves the rest to it.
@MainActor
final class RelayRuns {
    private var generation = 0
    private var last: Task<Bool, Never>?

    func changed(setting: @escaping @MainActor () -> Bool, revoke: @MainActor () -> Void, turnOn: @escaping @MainActor () -> Void,
                 turnOff: @escaping @MainActor () async throws -> Void, redial: @escaping @MainActor (Bool) async -> Void,
                 disconnectAll: @escaping @MainActor () async -> Void) async -> Bool {
        generation += 1
        let mine = generation
        if !setting() { revoke() }
        let before = last
        let run = Task { @MainActor in
            _ = await before?.value
            let on = setting()
            return await RelayOptOut.apply(relaysOn: on, current: { mine == self.generation && on == setting() },
                                           turnOn: turnOn, turnOff: turnOff, redial: { await redial(on) }, disconnectAll: disconnectAll)
        }
        last = run
        return await run.value
    }
}

/// Build 51 (review): re-binding after "this client's sign-in was replaced" (the core's typed,
/// local error). Backing off, and capped: past the cap the ordinary reconnect takes over until a
/// pass succeeds.
struct RebindPacer: Equatable {
    private var attempts: [String: Int] = [:]
    private var last: [String: Date] = [:]
    static let delays: [TimeInterval] = [0, 2, 8, 30]
    /// Past the delays: again only this long after the last one (armed again, never for good).
    static let rearm: TimeInterval = 60

    /// How long to wait before the next re-bind of `workspace`; nil: not now.
    mutating func next(_ workspace: String, now: Date = Date()) -> TimeInterval? {
        let n = attempts[workspace] ?? 0
        if n >= Self.delays.count {
            guard let at = last[workspace], now.timeIntervalSince(at) >= Self.rearm else { return nil }
            last[workspace] = now
            return 0
        }
        attempts[workspace] = n + 1
        last[workspace] = now
        return Self.delays[n]
    }
    mutating func succeeded(_ workspace: String) { attempts[workspace] = nil; last[workspace] = nil }
}

/// What a failed sync pass leads to, in this order: the session's end and a stopped device come
/// before everything — nothing a host can say puts a re-bind in front of them.
enum SyncFailureRule {
    enum Step: Equatable { case signedOut, deviceStopped, rebind, other }
    static func step(signedOut: Bool, deviceStopped: Bool, signInReplaced: Bool) -> Step {
        if signedOut { return .signedOut }
        if deviceStopped { return .deviceStopped }
        return signInReplaced ? .rebind : .other
    }
}

/// Build 51 (review): what signing a workspace in to its front is, step by step — over what the
/// app and the core provide, so that every interleaving of it is tested. Runs under `SerialByKey`.
@MainActor
struct ArmFlow<Record> {
    /// The stored record, if it is signed in.
    var stored: () -> Record?
    /// Is this exact session (same token) still the stored one?
    var isStored: (Record) -> Bool
    /// The credential the front hands out for it; nil: not right now.
    var signIn: (Record) async -> String?
    /// A fresh token from the host, PERSISTED; nil: not due, or not now.
    var rotate: (Record, String?) async -> Record?
    /// Tell the front; false: the credential is not the one signed in any more.
    var rotateToken: (String, Record) async -> Bool
    /// Take back exactly this credential.
    var clear: (String) async -> Void

    func run(throughFront: Bool, rotating: Bool) async -> (record: Record, credential: String?)? {
        guard var record = stored() else { return nil }
        var credential: String?
        if throughFront {
            guard let c = await signIn(record) else { return nil }
            guard isStored(record) else { await clear(c); return nil }
            credential = c
        }
        if rotating, let fresh = await rotate(record, credential) {
            record = fresh
            if let c = credential, !(await rotateToken(c, record)) {
                // Replaced meanwhile: signed in again with the fresh token, so that no dead
                // credential is ever bound.
                credential = await signIn(record)
                if credential == nil { return nil }
            }
        }
        guard isStored(record) else {
            if let c = credential { await clear(c) }
            return nil
        }
        return (record, credential)
    }
}

/// Build 51 (review): a skwod that moved to another address. The SAME session continues there:
/// nothing here ends it on the host. What changes is written into the record as it is stored at
/// that moment (after the proof and after the old front was closed), so that a rotation or a
/// sign-out meanwhile is never undone.
@MainActor
struct MoveFlow<Record> {
    /// The new address proves the pinned key.
    var proves: () async -> Bool
    /// The record as stored now; nil: gone, or signed out.
    var latest: () -> Record?
    /// Close the old front (its token is forgotten here only).
    var closeFront: () async -> Void
    /// Write the address fields into the stored record, and nothing else.
    var write: () -> Record?

    func run() async -> Record? {
        guard await proves(), latest() != nil else { return nil }
        await closeFront()
        guard latest() != nil else { return nil }
        return write()
    }
}

/// Build 51 (review): what tells the host that a session is over.
enum SessionEnd {
    case signOut, removed, accountEnded
    case moved, hostChanged, relaysOff, superseded

    static func tellsHost(_ why: SessionEnd) -> Bool {
        switch why {
        case .signOut, .removed, .accountEnded: true
        case .moved, .hostChanged, .relaysOff, .superseded: false
        }
    }
    /// …and even then not while another entry of this device uses the very same session.
    static func tellsHost(_ why: SessionEnd, token: String, others: [String]) -> Bool {
        tellsHost(why) && !token.isEmpty && !others.contains(token)
    }
}

/// Build 51 (review): rotating a session's token so that no interruption loses it. The key is
/// stored before the host is asked; the fresh token is used only once it is stored; until then
/// everything goes on with the old one, and the same key asks again.
@MainActor
struct RotationFlow<Record> {
    enum Outcome { case notDue, rotated(Record), again }
    /// Store a key with the record (it keeps one it has); nil: could not be written — not asked.
    var storeKey: () -> String?
    /// The fresh session from the host; nil: no answer, or refused.
    var ask: (String) async -> (userId: String, token: String, expiresAt: Int64)?
    /// The record, if it is still the one the key was stored with.
    var stillStored: () -> Bool
    /// Write token, dates, and no key — into the stored record; nil: not written (nothing changed).
    var persist: ((userId: String, token: String, expiresAt: Int64)) -> Record?

    func run() async -> Outcome {
        guard let key = storeKey() else { return .notDue }
        guard let fresh = await ask(key), !fresh.token.isEmpty else { return .again }
        guard stillStored() else { return .notDue }
        guard let record = persist(fresh) else { return .again }
        return .rotated(record)
    }
}

/// Build 51 (review): what the connection indicator lives on. On its own: the sync pass can wait
/// half a minute for a host that has gone, and "Reconnecting…" must not wait with it.
@MainActor
final class ConnectionWatch {
    private var task: Task<Void, Never>?
    /// Never from the background (an app launched there by a push was never told it is inactive),
    /// unless it carries a call.
    nonisolated static func looks(appActive: Bool, inBackground: Bool, callActive: Bool) -> Bool {
        callActive || (appActive && !inBackground)
    }
    func start(every seconds: Duration = .seconds(5), _ look: @escaping @MainActor (Int) async -> Void) {
        task?.cancel()
        task = Task { @MainActor in
            var tick = 0
            while !Task.isCancelled {
                // One look never holds up the next (a probe is bounded, but not short).
                let now = tick
                Task { @MainActor in await look(now) }
                tick += 1
                try? await Task.sleep(for: seconds)
            }
        }
    }
    func stop() { task?.cancel(); task = nil }
}

/// Build 51 (review): a little guaranteed run time while leaving the foreground. The system KILLS an
/// app that keeps such a task past its time, so it is always given back: by whoever asked for it, by
/// the system's warning — at once, on the main thread, before that returns — or after `limit`,
/// whichever comes first and whatever has become of the owner; and exactly once.
@MainActor
final class BackgroundHold {
    /// Well under the half minute the system gives.
    static let limit: TimeInterval = 20

    /// The system's background tasks: the same one the cache lock is held under (`StoreLifecycle`).
    typealias System = BackgroundTime

    private let system: System
    private var task: Int?
    private var ended = false

    init(_ name: String, limit: TimeInterval = BackgroundHold.limit, system: System) {
        self.system = system
        // (Both closures keep this alive: the owner may be gone by then.)
        guard let granted = system.begin(name, { self.end() }) else { return }
        if ended { system.end(granted); return }   // expired before it was even granted
        task = granted
        system.after(limit) { self.end() }
    }

    func end() {
        ended = true
        guard let task else { return }
        self.task = nil
        system.end(task)
    }
}

/// Build 51: relays are off and the host was not reached for a while — said as that, instead of an
/// endless "Reconnecting…". Relays are never turned on by the app itself.
struct DirectOnlyRule {
    static let after: TimeInterval = 25
    static let short = "No direct route"
    static func text(_ name: String) -> String {
        "Can't reach \(name) directly from this network. Turn on 'Use a relay when needed' to connect."
    }
    static let whatARelaySees = "A relay passes the encrypted traffic along when there is no direct way. It sees your IP address, your host's, when you are connected and how much is sent. It cannot read anything."

    private var workspace: String?
    private var since: Date?

    /// `usable`: the connection works (or there is nothing to connect to). True: say so.
    mutating func note(workspace id: String?, usable: Bool, relaysOff: Bool, now: Date) -> Bool {
        guard let id, !usable, relaysOff else { workspace = nil; since = nil; return false }
        if workspace != id { workspace = id; since = now }
        return now.timeIntervalSince(since ?? now) >= Self.after
    }
}
