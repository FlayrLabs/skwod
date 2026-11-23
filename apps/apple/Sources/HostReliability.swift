#if os(macOS)
import Foundation
import AppKit
import Combine
import CryptoKit
import Darwin
import IOKit.ps
import ServiceManagement

/// What makes "host a Skwod on this Mac" dependable: the decisions (when to restart, on which
/// port, whether to keep the Mac awake, whether to ask before quitting) as pure functions, and
/// the small system pieces that act on them — the loopback port, the sleep assertion, the login
/// item and the app delegate. `HostManager` supervises the server process itself.
enum HostReliability {

    // MARK: restarting

    /// Seconds to wait before restart number 1, 2, 3 … (the last value repeats).
    static let backoff: [TimeInterval] = [2, 5, 15, 30, 60]
    /// A server that stayed up this long has recovered: the next failure starts the backoff over.
    static let healthyReset: TimeInterval = 180
    /// How many times in a row the server may be moved to another port before giving up.
    static let maxPortMoves = 5

    static func restartDelay(failures: Int) -> TimeInterval {
        backoff[min(max(failures, 0), backoff.count - 1)]
    }

    /// The consecutive-failure count to carry into the next restart.
    static func failuresCarried(_ failures: Int, healthyFor: TimeInterval?) -> Int {
        if let healthyFor, healthyFor >= healthyReset { return 0 }
        return max(failures, 0)
    }

    enum ExitAction: Equatable {
        /// Only the user can fix it (the data folder, the disk): stop and say why.
        case giveUp
        case retry(after: TimeInterval, movePort: Bool)
    }

    /// What to do when the server process ends while hosting is on. `code` is its exit code
    /// (`server/src/problems.rs`): 75 = the API port is in use, 74 = data folder / database /
    /// disk, 78 = data folder not writable. Anything else (a crash, a signal, an unknown code)
    /// is worth another try.
    static func afterExit(code: Int32, signaled: Bool, failures: Int, portMoves: Int) -> ExitAction {
        if signaled { return .retry(after: restartDelay(failures: failures), movePort: false) }
        switch code {
        case 74, 78: return .giveUp
        case 75: return portMoves < maxPortMoves ? .retry(after: 0, movePort: true) : .giveUp
        default: return .retry(after: restartDelay(failures: failures), movePort: false)
        }
    }

    // MARK: errors as sentences

    /// The sentence in a `[skwod] <sentence>` line the server printed on stderr, if it is one.
    static func problem(in line: String) -> String? {
        let prefix = "[skwod] "
        let t = line.trimmingCharacters(in: .whitespaces)
        guard t.hasPrefix(prefix) else { return nil }
        let s = t.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)
        return s.isEmpty ? nil : s
    }

    /// Why the server stopped, for a person. The server's own last sentence wins; the exit code
    /// fills in when it said nothing.
    static func sentence(exitCode: Int32, signaled: Bool, lastProblem: String?, port: Int, portMoves: Int = 0) -> String {
        if !signaled, exitCode == 75 {
            // The server's sentence tells the user to quit the other app; the app moves instead.
            return portMoves < maxPortMoves
                ? "Port \(port) on this Mac is being used by another app, so Skwod is moving its server to another port."
                : "Skwod could not find a free port on this Mac for its server. Quit other apps that run servers (or restart this Mac), then start it again."
        }
        if let lastProblem, !lastProblem.isEmpty { return lastProblem }
        if signaled { return "The server was stopped unexpectedly (it crashed, or macOS ended it)." }
        switch exitCode {
        case 74: return "Skwod could not open its data. Check that this Mac has free disk space and that the storage folder is intact, then start the server again."
        case 78: return "Skwod cannot write to its storage folder. Check that you own that folder (or choose another one under Options), then start the server again."
        case 0: return "The server stopped by itself."
        default: return "The server stopped unexpectedly (code \(exitCode))."
        }
    }

    static let missingServer = "This copy of Skwod is missing its built-in server. Download Skwod again and replace this copy."
    static let noFreePort = "Every port Skwod can use for its server on this Mac (4820 to 4839) is taken by other apps. Quit other apps that run servers (or restart this Mac), then try again."
    static let notOurServer = "Skwod could not confirm that the server answering on this Mac is the one it started, so it did not send your login. Stop the server and start it again."
    static let healthTimeout = "The server started but did not answer in time."

    static func dataFolderFailure(path: String) -> String {
        "Skwod can't create its storage folder at \(path). Choose another folder under Options, or check that you own that location."
    }

    static func launchFailure(detail: String) -> String {
        "macOS would not let Skwod start its server (\(detail)). Download Skwod again and replace this copy; if it keeps happening, restart this Mac."
    }

    // MARK: the API port

    /// First choice, so existing installs (which always used it) do not move unless they must.
    static let firstPort = 4820
    /// The only ports this Mac's server ever listens on. Anything at such a loopback address is
    /// treated as "this Mac's own server" and gets no credential until it has proven itself.
    static let portRange = 4820...4839

    static func localURL(port: Int) -> String { "http://127.0.0.1:\(port)" }

    /// True for a loopback address on one of the host ports, however it is spelled
    /// (`127.0.0.1`, `localhost`, `[::1]`) — i.e. an address only this Mac's own server may hold.
    static func isHostLoopback(_ server: String) -> Bool {
        guard let c = URLComponents(string: server.trimmingCharacters(in: .whitespaces)),
              let scheme = c.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = c.host?.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]")),
              ["127.0.0.1", "localhost", "::1"].contains(host) else { return false }
        let port = c.port ?? (scheme == "https" ? 443 : 80)
        return portRange.contains(port)
    }

    // MARK: is the listener really our child?

    /// What our child must answer on `/api/instance/local-proof?nonce=<hex>`:
    /// HMAC-SHA256(key = the secret STRING's UTF-8 bytes, "skwod-local-proof" || 0x00 || nonce),
    /// lowercase hex (`server/src/api.rs`, `local_proof_for`). The secret is random per spawn
    /// and only ever handed to the child in its environment.
    static func localProof(secret: String, nonce: Data) -> String {
        var message = Data("skwod-local-proof".utf8)
        message.append(0)
        message.append(nonce)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: Data(secret.utf8)))
        return hex(Data(mac))
    }

    /// Is this HTTP answer a valid proof for `nonce` under `secret`? Anything else — a 404 (a
    /// server that was not handed a secret, or not a Skwod server at all), a body that is not
    /// `{"proof":"<hex>"}`, a proof for another nonce or under another secret — is an impostor.
    static func proofAccepted(status: Int, body: Data, secret: String, nonce: Data) -> Bool {
        guard status == 200, secret.utf8.count >= 32, (16...64).contains(nonce.count),
              let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let proof = object["proof"] as? String else { return false }
        return constantTimeEqual(proof.lowercased(), localProof(secret: secret, nonce: nonce))
    }

    static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<x.count { diff |= x[i] ^ y[i] }
        return diff == 0
    }

    static func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }

    /// `count` bytes from the system RNG, or nil if it fails (then nothing is started or sent).
    static func randomBytes(_ count: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else { return nil }
        return Data(bytes)
    }

    enum PortState { case free, ours, taken }
    enum PortDecision: Equatable { case use, reapThenUse, pickAnother }

    /// A port held by our own orphaned server (a previous app run that crashed) is taken back;
    /// one held by anything else is left alone.
    static func portDecision(_ state: PortState) -> PortDecision {
        switch state {
        case .free: return .use
        case .ours: return .reapThenUse
        case .taken: return .pickAnother
        }
    }

    /// The ports to try, in order: the one used last time, then 4820 upwards — never outside
    /// `portRange` (a remembered port outside it is ignored).
    static func portCandidates(preferred: Int) -> [Int] {
        var out: [Int] = []
        for p in [preferred] + Array(portRange) where portRange.contains(p) && !out.contains(p) {
            out.append(p)
        }
        return out
    }

    /// The first usable candidate, or nil when all twenty are taken (the start then fails with
    /// a sentence — there is no fallback to an arbitrary port).
    static func choosePort(preferred: Int, avoiding: Set<Int> = [], isFree: (Int) -> Bool) -> Int? {
        portCandidates(preferred: preferred).first { !avoiding.contains($0) && isFree($0) }
    }

    /// A stored workspace address that is this Mac's own server on its previous port → the same
    /// server on the new port. nil for anything else (it must not be touched).
    static func migratedServer(_ stored: String, from oldPort: Int, to newPort: Int) -> String? {
        guard oldPort != newPort, stored == localURL(port: oldPort) else { return nil }
        return localURL(port: newPort)
    }

    // MARK: staying awake

    /// Keep the Mac awake while hosting? The user's explicit choice wins; without one it is on
    /// while the Mac is plugged in and off on battery.
    static func keepAwake(explicit: Bool?, onACPower: Bool) -> Bool { explicit ?? onACPower }

    // MARK: quitting and updating

    static func shouldAskBeforeQuit(hosting: Bool, systemInitiated: Bool, installingUpdate: Bool) -> Bool {
        hosting && !systemInitiated && !installingUpdate
    }

    /// `members` = the OTHER people in the hosted skwod, nil when it could not be read.
    static func quitMessage(members: Int?) -> String {
        switch members {
        case nil: return "Everyone in your Skwod will go offline until you start it again."
        case .some(let n) where n <= 0: return "Your Skwod will be offline until you start it again."
        case .some(1): return "1 member will go offline until you start it again."
        case .some(let n): return "\(n) members will go offline until you start it again."
        }
    }

    /// An update that relaunches the app takes the server down, so it needs a yes while hosting.
    static func updateNeedsConsent(hosting: Bool, consented: Bool) -> Bool { hosting && !consented }

    static let updatePromptTitle = "An update is ready"
    static let updatePromptBody = "Installing it restarts your Skwod server — members will be offline for about a minute."

    // MARK: signing the owner in

    enum OwnerStep: Equatable {
        case alreadySignedIn
        /// Everything needed is at hand: sign in without asking.
        case signIn
        /// A brand-new server and no name chosen yet.
        case needsName
        /// The server has an owner, and this Mac holds neither its login nor a setup code.
        case needsOwnerLogin
    }

    static func ownerStep(hasWorkspace: Bool, hasSavedLogin: Bool, hasSetupCode: Bool, nameValid: Bool) -> OwnerStep {
        if hasWorkspace { return .alreadySignedIn }
        if hasSavedLogin { return .signIn }
        if hasSetupCode { return nameValid ? .signIn : .needsName }
        return .needsOwnerLogin
    }

    /// Seconds between automatic sign-in attempts after a failure that can pass by itself.
    static let signInRetryDelays: [TimeInterval] = [1, 2, 5, 10, 20]

    /// A sign-in failure that can pass by itself (the server is still settling, a rate limit) —
    /// as opposed to one that needs the user (a taken name, a dead code, a wrong password).
    static func isTransientSignInFailure(_ description: String) -> Bool {
        let d = description.lowercased()
        for permanent in ["409", "conflict", "400", "bad request", "401", "unauthorized", "403", "forbidden", "updaterequired"] where d.contains(permanent) {
            return false
        }
        for transient in ["429", "rate", "500", "502", "503", "504", "dns", "connect", "timed out", "timeout", "network", "reach", "refused"] where d.contains(transient) {
            return true
        }
        return false
    }

    // MARK: the address for friends

    /// The node id in a line of server output: `Invite: https://skwod.io/join#<node>.<code>` or
    /// `App link: skwod://join/<node>#<code>`. Validated by the same parser every invite goes
    /// through; nil when the line carries no invite.
    static func nodeId(inLine line: String) -> String? {
        for pattern in [#"skwod://join/([A-Za-z0-9]+)"#, #"https://skwod\.io/join#([A-Za-z0-9]+)"#] {
            guard let regex = try? NSRegularExpression(pattern: pattern),
                  let m = regex.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                  m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: line) else { continue }
            if let id = validNodeId(String(line[r])) { return id }
        }
        return nil
    }

    /// `candidate` if it really is a node id (the core's grammar decides), else nil.
    static func validNodeId(_ candidate: String) -> String? {
        guard let invite = try? InviteLink.parse(InviteLink.p2pPrefix + candidate) else { return nil }
        return invite.address.nodeId
    }
}

// MARK: - The loopback port

/// The loopback port this Mac's server listens on. Remembered (per `SKWOD_PROFILE`), so the
/// owner's own workspace — whose address is `http://127.0.0.1:<port>` — stays where it was.
enum HostPort {
    private static var key: String { "skwod.host.port" + Profile.suffix(".") }
    private static var movedFromKey: String { "skwod.host.port.movedFrom" + Profile.suffix(".") }

    /// The port in use (or to try first). 4820 until something else had to be chosen.
    static var current: Int {
        let v = UserDefaults.standard.integer(forKey: key)
        return HostReliability.portRange.contains(v) ? v : HostReliability.firstPort
    }

    /// Remember `port`. If it differs from the one before, the old one is kept in a list until
    /// the owner's stored workspace has been moved over (`settled`).
    static func persist(_ port: Int) {
        let old = current
        guard old != port, HostReliability.portRange.contains(port) else { return }
        var moved = movedFrom.filter { $0 != port }
        if !moved.contains(old) { moved.append(old) }
        UserDefaults.standard.set(moved, forKey: movedFromKey)
        UserDefaults.standard.set(port, forKey: key)
    }

    /// Earlier ports whose stored workspace address still has to be rewritten.
    static var movedFrom: [Int] {
        ((UserDefaults.standard.array(forKey: movedFromKey) as? [Int]) ?? []).filter { HostReliability.portRange.contains($0) }
    }

    static func settled() { UserDefaults.standard.removeObject(forKey: movedFromKey) }

    /// Nothing is listening on 127.0.0.1:`port` and it can be bound.
    static func isFree(_ port: Int) -> Bool {
        guard HostReliability.portRange.contains(port) else { return false }
        if accepts(port) { return false }
        return bound(port) != nil
    }

    private static func loopback(_ port: Int) -> sockaddr_in {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(port).bigEndian
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        return addr
    }

    /// Bind 127.0.0.1:`port` the way the server does (SO_REUSEADDR) and return the bound port.
    private static func bound(_ port: Int) -> Int? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = loopback(port)
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard ok == 0 else { return nil }
        var got = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &got) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard named == 0 else { return nil }
        let p = Int(in_port_t(bigEndian: got.sin_port))
        return p > 0 ? p : nil
    }

    /// Something answers a TCP connection on 127.0.0.1:`port` (refused at once when nothing does).
    private static func accepts(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = loopback(port)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        return r == 0
    }
}

// MARK: - Keep this Mac awake while hosting

/// Holds a "no idle system sleep" activity while the server is on, so the Mac does not doze off
/// and take the skwod offline. The display may still sleep, and closing a MacBook's lid still
/// sleeps it — nothing an app is allowed to prevent.
@MainActor
final class HostAwake: ObservableObject {
    static let shared = HostAwake()

    /// The setting as it stands now (the user's choice, or the plugged-in default).
    @Published private(set) var enabled = false
    /// Whether the Mac is being kept awake right now.
    @Published private(set) var holding = false
    @Published private(set) var onACPower = true

    private static var key: String { "skwod.host.keepAwake" + Profile.suffix(".") }
    private var hosting = false
    private var activity: NSObjectProtocol?
    private var powerSource: CFRunLoopSource?

    /// nil = never chosen: follow the power source.
    private var explicit: Bool? {
        UserDefaults.standard.object(forKey: Self.key) as? Bool
    }

    private init() {
        onACPower = Self.readOnACPower()
        enabled = HostReliability.keepAwake(explicit: explicit, onACPower: onACPower)
        // Plugging in / unplugging changes the default.
        let source = IOPSNotificationCreateRunLoopSource({ _ in
            DispatchQueue.main.async { MainActor.assumeIsolated { HostAwake.shared.refresh() } }
        }, nil)?.takeRetainedValue()
        if let source {
            CFRunLoopAddSource(CFRunLoopGetMain(), source, .defaultMode)
            powerSource = source
        }
    }

    func setEnabled(_ on: Bool) {
        UserDefaults.standard.set(on, forKey: Self.key)
        refresh()
    }

    /// Called by `HostManager` whenever hosting turns on or off.
    func hostingChanged(_ hosting: Bool) {
        self.hosting = hosting
        refresh()
    }

    func refresh() {
        onACPower = Self.readOnACPower()
        enabled = HostReliability.keepAwake(explicit: explicit, onACPower: onACPower)
        let want = hosting && enabled
        if want, activity == nil {
            activity = ProcessInfo.processInfo.beginActivity(
                options: [.idleSystemSleepDisabled], reason: "Skwod is hosting a server for its members")
        } else if !want, let held = activity {
            ProcessInfo.processInfo.endActivity(held)
            activity = nil
        }
        holding = activity != nil
    }

    /// True on a desktop Mac and on a plugged-in laptop.
    private static func readOnACPower() -> Bool {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
              let type = IOPSGetProvidingPowerSourceType(info)?.takeUnretainedValue() else { return true }
        return (type as String) == "AC Power"   // kIOPMACPowerKey
    }
}

// MARK: - Start Skwod when I log in

/// The login item (`SMAppService.mainApp`): macOS starts Skwod at login, and — when this Mac has
/// hosted before — the server comes up without a window (`HostAppDelegate`).
@MainActor
final class LoginItem: ObservableObject {
    static let shared = LoginItem()

    enum State: Equatable { case off, on, needsApproval }

    @Published private(set) var state: State = .off
    @Published private(set) var errorText = ""

    private init() { refresh() }

    func refresh() {
        switch SMAppService.mainApp.status {
        case .enabled: state = .on
        case .requiresApproval: state = .needsApproval
        default: state = .off
        }
    }

    func set(_ on: Bool) {
        errorText = ""
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            refresh()
            // Registering can "fail" into the needs-approval state; that has its own explanation.
            if state != .needsApproval {
                errorText = on
                    ? "macOS did not let Skwod add itself to your login items. Add it yourself in System Settings > General > Login Items."
                    : "macOS did not let Skwod remove itself from your login items. Remove it in System Settings > General > Login Items."
            }
            return
        }
        refresh()
    }

    func openSystemSettings() { SMAppService.openSystemSettingsLoginItems() }
}

// MARK: - App delegate: quit confirmation, launch at login

/// Quitting the app stops the server for everyone, so it asks first — for Cmd-Q, the app menu
/// and the menu-bar "Quit Skwod" alike. A logout, restart or shutdown is never held up.
@MainActor
final class HostAppDelegate: NSObject, NSApplicationDelegate {
    private var poweringOff = false
    private var asking = false
    private var launchedAtLogin = false

    func applicationWillFinishLaunching(_ notification: Notification) {
        launchedAtLogin = Self.launchIsLoginItem()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.willPowerOffNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self else { return }
                self.poweringOff = true
                if self.asking { NSApp.abortModal() }   // the question must not hold up a logout
            }
        }
        let host = HostManager.shared
        #if DEBUG
        HostE2E.start()
        #endif
        guard host.hasHostedBefore else { return }
        // The server does not wait for a window: it comes back at login, after an update
        // relaunch and after a crash relaunch alike. (`AppState.restore` awaits the same start.)
        Task { await host.ensureLocalServerRunning() }
        if launchedAtLogin {
            // Started by macOS at login: stay in the menu bar, no window in the user's face.
            NSApp.hide(nil)
            DispatchQueue.main.async { NSApp.hide(nil) }
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let host = HostManager.shared
        let ask = HostReliability.shouldAskBeforeQuit(
            hosting: host.isHosting,
            systemInitiated: poweringOff || Self.quitIsSystemInitiated(),
            installingUpdate: host.quittingForUpdate)
        guard ask, !asking else { return .terminateNow }
        asking = true
        defer { asking = false }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Quit Skwod?"
        alert.informativeText = HostReliability.quitMessage(members: host.memberCount)
        alert.addButton(withTitle: "Keep running")   // the default: an accidental Cmd-Q, Return keeps it up
        alert.addButton(withTitle: "Quit")
        NSApp.activate(ignoringOtherApps: true)
        let answer = alert.runModal()
        return answer == .alertFirstButtonReturn ? .terminateCancel : .terminateNow
    }

    // MARK: Apple events

    private static func code(_ s: String) -> UInt32 {
        s.utf8.reduce(0) { ($0 << 8) | UInt32($1) }
    }

    /// A quit sent by the system for a logout, restart or shutdown carries a reason ('why?').
    private static func quitIsSystemInitiated() -> Bool {
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventClass == code("aevt"), event.eventID == code("quit") else { return false }   // kCoreEventClass / kAEQuitApplication
        let why = code("why?")   // kAEQuitReason
        let reason = event.attributeDescriptor(forKeyword: why) ?? event.paramDescriptor(forKeyword: why)
        return reason != nil
    }

    /// macOS launched the app as a login item (the open event says so).
    private static func launchIsLoginItem() -> Bool {
        #if DEBUG
        // Lets a test run exercise the no-window start without logging out.
        if ProcessInfo.processInfo.environment["SKWOD_FAKE_LOGIN_LAUNCH"] == "1" { return true }
        #endif
        guard let event = NSAppleEventManager.shared().currentAppleEvent,
              event.eventClass == code("aevt"), event.eventID == code("oapp") else { return false }   // kAEOpenApplication
        return event.paramDescriptor(forKeyword: code("prdt"))?.enumCodeValue == code("lgit")   // keyAEPropData / keyAELaunchedAsLogInItem
    }
}

// MARK: - Self-checks (DEBUG)

#if DEBUG
/// Cases for the pure decisions above, for the app's `selfcheck` (Sources/E2EHooks.swift) to run.
enum HostReliabilityChecks {
    static func run() -> [(String, Bool)] {
        typealias R = HostReliability
        var out: [(String, Bool)] = []
        func check(_ name: String, _ ok: Bool) { out.append(("host: " + name, ok)) }

        // Backoff.
        check("backoff is 2, 5, 15, 30, 60 and then stays at 60",
              (0...7).map { R.restartDelay(failures: $0) } == [2, 5, 15, 30, 60, 60, 60, 60])
        check("a negative failure count is the first delay", R.restartDelay(failures: -3) == 2)
        check("a server healthy for 3 minutes starts the backoff over", R.failuresCarried(4, healthyFor: 180) == 0)
        check("a server that fell over quickly keeps its backoff", R.failuresCarried(4, healthyFor: 20) == 4)
        check("a server that never got healthy keeps its backoff", R.failuresCarried(2, healthyFor: nil) == 2)

        // Exit codes.
        check("74 (data) gives up", R.afterExit(code: 74, signaled: false, failures: 0, portMoves: 0) == .giveUp)
        check("78 (not writable) gives up", R.afterExit(code: 78, signaled: false, failures: 0, portMoves: 0) == .giveUp)
        check("75 (port in use) moves port at once",
              R.afterExit(code: 75, signaled: false, failures: 3, portMoves: 0) == .retry(after: 0, movePort: true))
        check("75 over and over gives up",
              R.afterExit(code: 75, signaled: false, failures: 0, portMoves: R.maxPortMoves) == .giveUp)
        check("a crash retries with backoff",
              R.afterExit(code: 101, signaled: false, failures: 2, portMoves: 0) == .retry(after: 15, movePort: false))
        check("a signal retries even when its number looks like 74",
              R.afterExit(code: 74, signaled: true, failures: 0, portMoves: 0) == .retry(after: 2, movePort: false))
        check("a clean exit while hosting is restarted",
              R.afterExit(code: 0, signaled: false, failures: 0, portMoves: 0) == .retry(after: 2, movePort: false))

        // Sentences.
        check("a [skwod] line is a sentence", R.problem(in: "[skwod] Skwod's data file is damaged.") == "Skwod's data file is damaged.")
        check("a log line is not a sentence", R.problem(in: "2026-01-01 INFO listening") == nil)
        check("an empty [skwod] line is not a sentence", R.problem(in: "[skwod]   ") == nil)
        check("the server's sentence wins",
              R.sentence(exitCode: 74, signaled: false, lastProblem: "Out of disk space.", port: 4820) == "Out of disk space.")
        check("74 without a sentence still says what to do",
              R.sentence(exitCode: 74, signaled: false, lastProblem: nil, port: 4820).contains("disk space"))
        check("78 without a sentence names the folder",
              R.sentence(exitCode: 78, signaled: false, lastProblem: nil, port: 4820).contains("storage folder"))
        check("75 says the app is moving, not 'quit the other app'", {
            let s = R.sentence(exitCode: 75, signaled: false, lastProblem: "Port 4820 on this computer is already in use — quit that one.", port: 4820)
            return s.contains("4820") && s.contains("another port") && !s.contains("quit that one")
        }())
        check("no sentence ever shows an error kind", {
            let all = [R.sentence(exitCode: 1, signaled: false, lastProblem: nil, port: 4820),
                       R.sentence(exitCode: 9, signaled: true, lastProblem: nil, port: 4820),
                       R.missingServer, R.noFreePort, R.healthTimeout,
                       R.dataFolderFailure(path: "/x"), R.launchFailure(detail: "x")]
            return all.allSatisfy { !$0.isEmpty && !$0.contains("Error") && !$0.contains("unexpectedly. Open the log") }
        }())

        // Port.
        check("the first choice is 4820", R.choosePort(preferred: 4820, isFree: { _ in true }) == 4820)
        check("a remembered port is tried first", R.choosePort(preferred: 4833, isFree: { _ in true }) == 4833)
        check("a taken port is skipped", R.choosePort(preferred: 4820, isFree: { $0 != 4820 }) == 4821)
        check("a port that just failed is avoided", R.choosePort(preferred: 4820, avoiding: [4820, 4821], isFree: { _ in true }) == 4822)
        check("all twenty taken → no port (the start fails with a sentence)", R.choosePort(preferred: 4820, isFree: { _ in false }) == nil)
        check("a privileged remembered port is never a candidate", !R.portCandidates(preferred: 80).contains(80))
        check("the port choice never leaves 4820–4839", {
            for preferred in [0, 80, 4819, 4820, 4830, 4839, 4840, 51234, 65535] {
                let candidates = R.portCandidates(preferred: preferred)
                guard candidates.count == 20, candidates.allSatisfy({ R.portRange.contains($0) }) else { return false }
                if let p = R.choosePort(preferred: preferred, isFree: { _ in true }), !R.portRange.contains(p) { return false }
                if R.choosePort(preferred: preferred, isFree: { !R.portRange.contains($0) }) != nil { return false }
            }
            return true
        }())
        check("a remembered port outside the range falls back to 4820", R.choosePort(preferred: 51234, isFree: { _ in true }) == 4820)
        check("host loopback addresses are recognised however spelled",
              R.isHostLoopback("http://127.0.0.1:4820") && R.isHostLoopback("http://localhost:4839") && R.isHostLoopback("http://[::1]:4825"))
        check("other addresses are not host loopback",
              !R.isHostLoopback("http://127.0.0.1:38411") && !R.isHostLoopback("https://chat.example.com")
              && !R.isHostLoopback("http://127.0.0.1:4840") && !R.isHostLoopback("skwod://join/abc"))

        // The listener must be our child.
        let secret = "4f1c0d7e9a2b48c6b3e5d1a07f9c2e8451b6a3d0c7e9f2a4"
        let nonce = Data((0..<16).map { UInt8($0) })
        let proof = R.localProof(secret: secret, nonce: nonce)
        func body(_ p: String) -> Data { Data("{\"proof\":\"\(p)\"}".utf8) }
        check("the proof matches an independent HMAC-SHA256", proof == plainHMAC(key: Data(secret.utf8), message: Data("skwod-local-proof".utf8) + [0] + nonce) && proof.count == 64)
        check("a wrong secret gives another proof", R.localProof(secret: String(secret.reversed()), nonce: nonce) != proof)
        check("a wrong nonce gives another proof", R.localProof(secret: secret, nonce: Data((1...16).map { UInt8($0) })) != proof)
        check("our child's proof is accepted", R.proofAccepted(status: 200, body: body(proof), secret: secret, nonce: nonce))
        check("an impostor with another secret is refused",
              !R.proofAccepted(status: 200, body: body(R.localProof(secret: String(secret.reversed()), nonce: nonce)), secret: secret, nonce: nonce))
        check("a replayed proof for an old nonce is refused",
              !R.proofAccepted(status: 200, body: body(proof), secret: secret, nonce: Data((16..<32).map { UInt8($0) })))
        check("a 404 is refused", !R.proofAccepted(status: 404, body: body(proof), secret: secret, nonce: nonce))
        check("a malformed body is refused",
              !R.proofAccepted(status: 200, body: Data("ok".utf8), secret: secret, nonce: nonce)
              && !R.proofAccepted(status: 200, body: Data("{\"proof\":7}".utf8), secret: secret, nonce: nonce)
              && !R.proofAccepted(status: 200, body: Data("{}".utf8), secret: secret, nonce: nonce)
              && !R.proofAccepted(status: 200, body: body(""), secret: secret, nonce: nonce)
              && !R.proofAccepted(status: 200, body: body(String(proof.dropLast())), secret: secret, nonce: nonce))
        check("a short secret or nonce is never accepted",
              !R.proofAccepted(status: 200, body: body(R.localProof(secret: "short", nonce: nonce)), secret: "short", nonce: nonce)
              && !R.proofAccepted(status: 200, body: body(R.localProof(secret: secret, nonce: Data([1, 2]))), secret: secret, nonce: Data([1, 2])))
        check("the comparison is exact", R.constantTimeEqual("abc", "abc") && !R.constantTimeEqual("abc", "abd") && !R.constantTimeEqual("abc", "abcd"))
        check("free → use, ours → reap, taken → another",
              R.portDecision(.free) == .use && R.portDecision(.ours) == .reapThenUse && R.portDecision(.taken) == .pickAnother)
        check("the owner's workspace follows the port",
              R.migratedServer("http://127.0.0.1:4820", from: 4820, to: 4823) == "http://127.0.0.1:4823")
        check("another loopback server is not touched", R.migratedServer("http://127.0.0.1:38411", from: 4820, to: 4823) == nil)
        check("a p2p workspace is not touched", R.migratedServer("skwod://join/abc", from: 4820, to: 4823) == nil)
        check("no move, no migration", R.migratedServer("http://127.0.0.1:4820", from: 4820, to: 4820) == nil)

        // Awake.
        check("awake by default on AC power", R.keepAwake(explicit: nil, onACPower: true))
        check("not by default on battery", !R.keepAwake(explicit: nil, onACPower: false))
        check("on battery when the user said so", R.keepAwake(explicit: true, onACPower: false))
        check("off on AC when the user said so", !R.keepAwake(explicit: false, onACPower: true))

        // Quit / update.
        check("ask before quitting while hosting", R.shouldAskBeforeQuit(hosting: true, systemInitiated: false, installingUpdate: false))
        check("never ask when not hosting", !R.shouldAskBeforeQuit(hosting: false, systemInitiated: false, installingUpdate: false))
        check("never hold up a logout", !R.shouldAskBeforeQuit(hosting: true, systemInitiated: true, installingUpdate: false))
        check("do not ask twice for an agreed update", !R.shouldAskBeforeQuit(hosting: true, systemInitiated: false, installingUpdate: true))
        check("quit message counts members",
              R.quitMessage(members: 3).hasPrefix("3 members") && R.quitMessage(members: 1).hasPrefix("1 member ")
              && R.quitMessage(members: nil).hasPrefix("Everyone in your Skwod") && !R.quitMessage(members: 0).contains("0"))
        check("an update needs a yes while hosting", R.updateNeedsConsent(hosting: true, consented: false))
        check("an agreed update goes ahead", !R.updateNeedsConsent(hosting: true, consented: true))
        check("an update is not held when not hosting", !R.updateNeedsConsent(hosting: false, consented: false))

        // Owner sign-in.
        check("signed in already", R.ownerStep(hasWorkspace: true, hasSavedLogin: false, hasSetupCode: false, nameValid: false) == .alreadySignedIn)
        check("a saved login signs in by itself", R.ownerStep(hasWorkspace: false, hasSavedLogin: true, hasSetupCode: false, nameValid: false) == .signIn)
        check("a setup code + name signs in by itself", R.ownerStep(hasWorkspace: false, hasSavedLogin: false, hasSetupCode: true, nameValid: true) == .signIn)
        check("a setup code without a name asks for one", R.ownerStep(hasWorkspace: false, hasSavedLogin: false, hasSetupCode: true, nameValid: false) == .needsName)
        check("nothing at hand asks for the owner's login", R.ownerStep(hasWorkspace: false, hasSavedLogin: false, hasSetupCode: false, nameValid: true) == .needsOwnerLogin)
        check("a connection failure is retried", R.isTransientSignInFailure("Network(\"error sending request: connection refused\")"))
        check("a rate limit is retried", R.isTransientSignInFailure("Api(status: 429)"))
        check("a taken name is not retried", !R.isTransientSignInFailure("Api(status: 409, conflict)"))
        check("a dead code is not retried", !R.isTransientSignInFailure("Api(status: 403)"))
        check("an unknown failure is not retried", !R.isTransientSignInFailure("Something"))

        // Server output.
        check("a line without an invite has no node id", R.nodeId(inLine: "[skwod] Admin page: http://127.0.0.1:4821/") == nil)
        check("a made-up key is not a node id", R.nodeId(inLine: "App link: skwod://join/notakey#SKWD-AAAA-BBBB") == nil)
        return out
    }

    /// HMAC-SHA256 written out from its definition (RFC 2104), independent of CryptoKit's HMAC.
    private static func plainHMAC(key: Data, message: Data) -> String {
        var k = key.count > 64 ? Data(SHA256.hash(data: key)) : key
        k.append(Data(repeating: 0, count: 64 - k.count))
        let inner = Data(SHA256.hash(data: Data(k.map { $0 ^ 0x36 }) + message))
        return HostReliability.hex(Data(SHA256.hash(data: Data(k.map { $0 ^ 0x5c }) + inner)))
    }
}

/// DEBUG-only hooks to drive hosting without the pointer (docs/APPLE.md "Proving it"). With
/// `SKWOD_E2E_OUT=<dir>` the app keeps `<dir>/host.json` current and runs commands from
/// `SKWOD_E2E_HOSTCMD` (comma-separated) and from `<dir>/hostcmd.txt` (one per line, consumed):
/// `selfcheck` (→ `host-selfcheck.json`) · `start:<owner name>` (Start server, then finish
/// setup as the wizard does) · `stop` · `signin` (one owner sign-in attempt, now) · `activate`
/// (re-activate the owner's workspace) · `rings` · `signedout` (what a 401 on the owner's
/// session triggers) · `quitmsg` (what the quit question would say) · `awake:on|off` · `shot`.
@MainActor
enum HostE2E {
    private static var results: [[String: Any]] = []
    private static var ownerName: String?

    static func start() {
        guard let path = E2E.env("SKWOD_E2E_OUT") else { return }
        let out = URL(fileURLWithPath: path, isDirectory: true)
        try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        Task { @MainActor in
            var pending = (E2E.env("SKWOD_E2E_HOSTCMD") ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            while true {
                let file = out.appendingPathComponent("hostcmd.txt")
                if let text = try? String(contentsOf: file, encoding: .utf8) {
                    try? FileManager.default.removeItem(at: file)
                    pending += text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
                }
                for command in pending where !command.isEmpty { await run(command, out: out) }
                pending = []
                await finishOwnerSetup()
                if let data = try? JSONSerialization.data(withJSONObject: await state(), options: [.prettyPrinted, .sortedKeys]) {
                    try? data.write(to: out.appendingPathComponent("host.json"), options: .atomic)
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private static func note(_ command: String, _ outcome: String) {
        results.append(["command": command, "result": outcome, "at": Int(Date().timeIntervalSince1970 * 1000)])
    }

    private static func run(_ command: String, out: URL) async {
        let host = HostManager.shared
        let app = host.debugApp
        switch command {
        case "selfcheck":
            let checks = HostReliabilityChecks.run()
            let failed = checks.filter { !$0.1 }.map(\.0)
            let report: [String: Any] = ["total": checks.count, "passed": checks.count - failed.count, "failed": failed,
                                         "checks": checks.map { ["name": $0.0, "ok": $0.1] }]
            if let data = try? JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys]) {
                try? data.write(to: out.appendingPathComponent("host-selfcheck.json"), options: .atomic)
            }
            note(command, "\(checks.count - failed.count)/\(checks.count)")
        case let c where c.hasPrefix("export:") || c.hasPrefix("import:") || c.hasPrefix("movedata:"):
            // export:<file>:<passphrase> · import:<file>:<passphrase> · movedata:<folder>
            let bits = c.split(separator: ":", maxSplits: 2).map(String.init)
            let failure: String?
            switch bits[0] {
            case "export" where bits.count == 3: failure = await host.exportServer(to: URL(fileURLWithPath: bits[1]), passphrase: bits[2])
            case "import" where bits.count == 3: failure = await host.importServer(from: URL(fileURLWithPath: bits[1]), passphrase: bits[2], replace: false)
            case "movedata" where bits.count >= 2: failure = await host.moveStorage(to: URL(fileURLWithPath: bits[1], isDirectory: true))
            default: failure = "usage"
            }
            note(bits[0], failure.map { "failed: \($0)" } ?? "ok data=\(host.dataDir.path)")
        case "stop":
            host.stop(); note(command, "ok")
        case "signin":
            guard let app else { return note(command, "no app") }
            do { try await app.signInAsHostOwner(username: ownerName ?? "owner"); note(command, "signed in") }
            catch let e as HostError { note(command, "refused: \(e.message)") }
            catch { note(command, "failed: \(AuthView.message(for: error, signup: true))") }
        case "activate":
            guard let app, let w = app.workspace(at: .https(HostManager.localURL)) else { return note(command, "no workspace") }
            await app.activate(w)
            note(command, app.serverURL.isEmpty ? "offline (nothing sent)" : "online")
        case "rings":
            guard let app else { return note(command, "no app") }
            note(command, "\(await app.pendingRingsEverywhere().count) ringing")
        case "signedout":
            guard let app, let w = app.workspace(at: .https(HostManager.localURL)) else { return note(command, "no workspace") }
            await app.handleSignedOut(w)
            let now = app.workspace(at: .https(HostManager.localURL))
            note(command, now?.isSignedOut == true ? "signed out (no re-login sent)" : "signed back in")
        case "quitmsg":
            let ask = HostReliability.shouldAskBeforeQuit(hosting: host.isHosting, systemInitiated: false, installingUpdate: host.quittingForUpdate)
            note(command, ask ? "Quit Skwod? " + HostReliability.quitMessage(members: host.memberCount) : "(would quit without asking)")
        case "awake:on": HostAwake.shared.setEnabled(true); note(command, "ok")
        case "awake:off": HostAwake.shared.setEnabled(false); note(command, "ok")
        case "shot":
            CallDebug.saveWindows(to: out); note(command, "ok")
        default:
            if command.hasPrefix("start:") {
                ownerName = String(command.dropFirst("start:".count))
                host.start()
                note(command, "ok")
            } else {
                note(command, "unknown")
            }
        }
    }

    /// What the wizard does by itself once the server is up.
    private static func finishOwnerSetup() async {
        let host = HostManager.shared
        guard let name = ownerName, host.phase == .running, let app = host.debugApp,
              app.workspace(at: .https(HostManager.localURL)) == nil else { return }
        do { try await app.signInAsHostOwner(username: name); note("owner-setup", "signed in") }
        catch let e as HostError { ownerName = nil; note("owner-setup", "refused: \(e.message)") }
        catch {
            let transient = HostReliability.isTransientSignInFailure(String(describing: error))
            if !transient { ownerName = nil }
            note("owner-setup", "\(transient ? "retrying" : "failed"): \(AuthView.message(for: error, signup: true))")
        }
    }

    private static func state() async -> [String: Any] {
        let host = HostManager.shared
        let app = host.debugApp
        let w = app?.workspace(at: .https(HostManager.localURL))
        var phase = "\(host.phase)"
        if case .restarting(let why) = host.phase { phase = "restarting: \(why)" }
        if case .failed(let why) = host.phase { phase = "failed: \(why)" }
        let login: String = {
            switch LoginItem.shared.state { case .on: return "on"; case .off: return "off"; case .needsApproval: return "needsApproval" }
        }()
        return [
            "phase": phase,
            "is_hosting": host.isHosting,
            "port": host.port,
            "persisted_port": HostPort.current,
            "local_url": HostManager.localURL,
            "child_pid": host.debugChildPid.map { Int($0) } ?? 0,
            "child_has_secret": host.debugHasSecret,
            "verified_now": await host.verifiedLocalURL() != nil,
            "node_id_known": host.nodeId != nil,
            "setup_code_held": host.joinCode != nil,
            "member_count": host.memberCount.map { $0 as Any } ?? NSNull(),
            "retry_in": host.retryAt.map { max(0, Int($0.timeIntervalSinceNow)) } ?? -1,
            "awake": ["enabled": HostAwake.shared.enabled, "holding": HostAwake.shared.holding, "on_ac_power": HostAwake.shared.onACPower],
            "login_item": login,
            "owner": ["attached": app != nil, "workspace": w != nil, "signed_out": w?.isSignedOut ?? false,
                      "workspace_address": w?.server ?? "", "live_base": app?.serverURL ?? "",
                      "current_is_local": (app?.current?.id != nil) && app?.current?.id == w?.id],
            "log_tail": Array(host.log.suffix(25)),
            "results": results,
        ]
    }
}
#endif
#endif
