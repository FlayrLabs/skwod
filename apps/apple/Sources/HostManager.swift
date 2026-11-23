#if os(macOS)
import Foundation
import Combine
import AppKit
import SwiftUI
import Darwin

/// Runs a self-hosted skwod on this Mac: the bundled `skwod-server` as a child process, which in
/// turn supervises the bundled `livekit-server` (voice/video) on loopback. One button, no account,
/// no domain, no tunnel and no third-party service: friends reach the server by its key
/// (`skwod://join/<node id>`, docs/P2P.md), and the publisher runs nothing.
///
/// The host's OWN app talks to its server over the local path (`http://127.0.0.1:<port>`, 4820
/// unless that was taken — `HostPort`) — never through the p2p layer — and to LiveKit directly on
/// loopback. A single shared instance lives for the app's life and brings the server back up at
/// launch if this Mac has hosted before.
///
/// While hosting is on, the server is SUPERVISED: if the process ends by itself it is started
/// again with backoff (`HostReliability`), on another port if its own was taken, and only a
/// failure the user has to fix (the data folder, the disk) ends in `.failed`. The server retries
/// its own p2p endpoint and restarts LiveKit itself; the app only restarts the server.
///
/// A LOOPBACK PORT PROVES NOTHING: any program on this Mac can listen on it once our server is
/// gone. So every spawn gets a fresh random secret in its environment, and the listener must
/// answer an HMAC challenge under it (`proves`) before it counts as running and before ANY
/// credential — the setup code, the owner's saved password, the owner's session token — is sent
/// to it (`verifiedLocalURL`, `gatedBase`). A pass is never carried over to another child.
@MainActor
final class HostManager: ObservableObject {
    static let shared = HostManager()

    enum Phase: Equatable {
        case idle, starting, running
        /// The server stopped by itself and is about to be started again; the text says why.
        case restarting(String)
        case stopped, failed(String)
    }

    @Published private(set) var phase: Phase = .idle {
        didSet { if phase != oldValue { HostAwake.shared.hostingChanged(isHosting) } }
    }
    /// The server's p2p address (its key), once it is known. nil = friends can't reach this
    /// server yet (the p2p endpoint is still coming up; the server keeps retrying by itself).
    @Published private(set) var nodeId: String?
    /// The one-time owner setup code, printed by a brand-new server. Dead once the owner signs up.
    @Published private(set) var joinCode: String?
    @Published private(set) var log: [String] = []
    /// Asks the main window to open the "invite your friends" panel (after Start, or from the menu).
    @Published var showInvitePanel = false
    /// The full owner setup (`HostWizardView`) is wanted, from anywhere — the menu bar included.
    /// Presented over whatever the window shows (`HostSetupPresenter`).
    @Published var showSetupWizard = false
    /// Open the invite panel once the setup sheet has closed (two sheets cannot swap in one step).
    var inviteAfterSetup = false
    /// When the next automatic restart happens (while `.restarting`).
    @Published private(set) var retryAt: Date?
    /// How many OTHER people are in the hosted skwod, as last read with the owner's session.
    /// nil = not known (not signed in as the owner, or not read yet).
    @Published private(set) var memberCount: Int?
    /// The loopback port the server's HTTP API binds (`HostPort`).
    @Published private(set) var port = HostPort.current

    /// Set once the user agreed to an update that relaunches the app, so quitting for it does
    /// not ask a second time (`HostAppDelegate`, `SparkleUpdater`).
    var quittingForUpdate = false

    /// The app state, once it has restored (`attach`). Used for the owner's session — to move
    /// its workspace when the port changes, read the member count and learn a late node id.
    private weak var app: AppState?

    private var serverProcess: Process?
    /// The secret handed to `serverProcess` on its standard input (`run --local-proof-stdin`) —
    /// fresh for every spawn, memory only: never in its environment (other processes of the
    /// same user can read that), on a command line, on disk or in a log.
    private var proofSecret: String?
    /// Hosting is ON: the user started it (or it came back at launch) and has not stopped it.
    private var wantsHosting = false
    /// Bumped whenever the current start attempt is superseded (stop, restart, a new start).
    private var generation = 0
    /// The first attempt of the current start (later, automatic attempts are `restartTask`).
    private var startTask: Task<Void, Never>?
    private var startSerial = 0
    private var restartTask: Task<Void, Never>?
    private var upkeepTask: Task<Void, Never>?
    private var failures = 0
    private var portMoves = 0
    private var avoidPorts: Set<Int> = []
    private var healthySince: Date?
    /// The last `[skwod] <sentence>` the server printed on stderr.
    private var lastProblem: String?

    /// The stable local address the host's own account connects to. Follows the remembered port.
    nonisolated static var localURL: String { HostReliability.localURL(port: HostPort.current) }
    /// Keychain account holding the owner login this Mac created for its own server.
    static let ownerCredentialsAccount = "host-owner-login"
    private static let dataDirKey = "skwod.host.dataDir"
    /// Set when the person pressed "Stop server"; cleared when they start it again. While set,
    /// launch, login and update relaunches do NOT bring the server back. A skwod that moved to
    /// another machine (docs/UNRAID.md, "Moving your Skwod from a Mac") must never come back
    /// here by itself: the same key on two machines splits the skwod in two.
    static let stoppedByUserKey = "skwod.host.stoppedByUser"

    /// Where the host's data (SQLite DB + encrypted blobs + the p2p key) lives. The choice is
    /// remembered, so a custom folder is found again on the next launch.
    var dataDir: URL = {
        if let custom = UserDefaults.standard.string(forKey: HostManager.dataDirKey), !custom.isEmpty {
            return URL(fileURLWithPath: custom, isDirectory: true)
        }
        return SharedContainer.privateURL.appendingPathComponent("skwod-host-data")
    }() {
        didSet { UserDefaults.standard.set(dataDir.path, forKey: Self.dataDirKey) }
    }

    /// True if this machine has hosted before (a server DB exists), so we should auto-start on launch.
    var hasHostedBefore: Bool {
        FileManager.default.fileExists(atPath: dataDir.appendingPathComponent("skwod.db").path)
    }

    /// Hosting is on — running, coming up, or between two automatic restarts.
    var isHosting: Bool {
        switch phase {
        case .starting, .running, .restarting: return true
        case .idle, .stopped, .failed: return false
        }
    }

    /// Whether the bundle carries the SFU, i.e. whether a hosted skwod gets voice + video.
    var voiceBundled: Bool { tool("livekit-server") != nil }

    private func tool(_ name: String) -> URL? {
        Bundle.main.url(forResource: name, withExtension: nil, subdirectory: "host-tools")
            ?? Bundle.main.url(forResource: name, withExtension: nil)
    }

    // MARK: lifecycle

    init() {
        // Terminate our child server if the app quits, so it doesn't orphan and squat the port.
        NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [weak self] _ in MainActor.assumeIsolated { self?.killChildren() } }
    }

    /// Bring the server back at launch when this Mac has hosted before. Idempotent: a second
    /// caller waits for the start already under way. Returns once the first attempt has settled
    /// (running, failed, or waiting to retry) — never blocks on the retry loop.
    func ensureLocalServerRunning() async {
        if let startTask { await startTask.value; return }
        guard serverProcess == nil, !isHosting, hasHostedBefore else { return }
        guard !UserDefaults.standard.bool(forKey: Self.stoppedByUserKey) else { return }
        await begin().value
    }

    /// The one button.
    func start() {
        guard !isHosting else { return }
        UserDefaults.standard.set(false, forKey: Self.stoppedByUserKey)
        begin()
    }

    @discardableResult
    private func begin() -> Task<Void, Never> {
        wantsHosting = true
        failures = 0; portMoves = 0; avoidPorts = []
        restartTask?.cancel(); restartTask = nil
        log = []
        phase = .starting
        startSerial += 1
        let serial = startSerial
        let task = Task {
            await self.run()
            if serial == self.startSerial { self.startTask = nil }
        }
        startTask = task
        return task
    }

    func stop() {
        UserDefaults.standard.set(true, forKey: Self.stoppedByUserKey)
        halt()
        if case .failed = phase {} else { phase = .stopped }
    }

    /// Hosting off: no restart pending, no child left.
    private func halt() {
        wantsHosting = false
        generation += 1
        restartTask?.cancel(); restartTask = nil
        upkeepTask?.cancel(); upkeepTask = nil
        retryAt = nil
        healthySince = nil
        killChildren()
        dropChild()
    }

    /// The child is gone (or about to be): its secret dies with it, and the owner's session
    /// stops talking to the port — whatever listens there next is not our server.
    private func dropChild() {
        serverProcess = nil
        proofSecret = nil
        cutLocalSession()
    }

    private func killChildren() {
        if let sp = serverProcess, sp.isRunning {
            // The server supervises LiveKit as ITS child, and a terminated server does not take
            // it down — it would linger and keep its ports. Stop it too, but only a direct child
            // of our server that really is our bundled binary.
            let sfu = tool("livekit-server")?.resolvingSymlinksInPath().path
            for pid in Self.children(of: sp.processIdentifier) where Self.executablePath(of: pid) == sfu {
                kill(pid, SIGTERM)
            }
            sp.terminate()
        }
        try? FileManager.default.removeItem(at: pidFile)
    }

    private static func children(of parent: pid_t) -> [pid_t] {
        var pids = [pid_t](repeating: 0, count: 64)
        guard proc_listchildpids(parent, &pids, Int32(pids.count * MemoryLayout<pid_t>.size)) > 0 else { return [] }
        return pids.filter { $0 > 1 }   // the buffer is zero-filled past the last child
    }

    private static func executablePath(of pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
        return URL(fileURLWithPath: String(cString: buf)).resolvingSymlinksInPath().path
    }

    /// Stop hosting and delete the hosted skwod's entire data directory (server DB + blobs + its
    /// key). Part of the app-wide factory reset — destroys the server this Mac runs.
    func wipeHostData() {
        halt()
        try? FileManager.default.removeItem(at: dataDir)
        Keychain.delete("beacon-secret")   // left behind by builds that published an address beacon
        joinCode = nil
        nodeId = nil
        memberCount = nil
        phase = .stopped
    }

    // MARK: one start attempt

    private func run() async {
        generation += 1
        let gen = generation
        phase = .starting
        retryAt = nil
        lastProblem = nil
        healthySince = nil

        guard let server = tool("skwod-server") else { return fail(HostReliability.missingServer) }
        do {
            try FileManager.default.createDirectory(
                at: dataDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch {
            return fail(HostReliability.dataFolderFailure(path: dataDir.path))
        }
        // Our own server left over from a crashed app run still holds the port: take it back.
        await reapOrphan(server)
        guard gen == generation else { return }
        joinCode = loadStashedCode()

        // The port used last time if it is free; otherwise another one, remembered from now on.
        // Only ever one of 4820–4839: no arbitrary port, so "this Mac's own server" stays a
        // small, recognisable set of addresses.
        guard let chosen = HostReliability.choosePort(preferred: HostPort.current, avoiding: avoidPorts, isFree: HostPort.isFree) else {
            return fail(HostReliability.noFreePort)
        }
        guard let secret = HostReliability.randomBytes(32).map(HostReliability.hex) else {
            return fail(HostReliability.launchFailure(detail: "no random numbers available"))
        }
        if chosen != HostPort.current { append("[app] port \(HostPort.current) is in use; using \(chosen)") }
        HostPort.persist(chosen)
        port = chosen

        // `skwod run` initializes a fresh data folder itself (and prints the one-time owner
        // code), starts the p2p endpoint (and prints the invite), and supervises LiveKit.
        let sp = Process()
        sp.executableURL = server
        sp.arguments = [
            "run", "--data", dataDir.path, "--listen", "127.0.0.1:\(chosen)",
            "--public-fallback", P2PManager.publicFallback ? "true" : "false",
            "--local-proof-stdin",
        ]
        var env = ProcessInfo.processInfo.environment
        if let livekit = tool("livekit-server") { env["SKWOD_LIVEKIT_BIN"] = livekit.path }
        env["SKWOD_P2P_DEBUG"] = nil   // never let an inherited debug flag turn address logging on
        // How this child proves it is ours (`proves`) goes over a pipe only it reads, never the
        // environment; an inherited value is dropped so it cannot shadow the one sent.
        env["SKWOD_LOCAL_PROOF_SECRET"] = nil
        sp.environment = env
        // Separate pipes: only stderr carries the `[skwod] <sentence>` that explains a failure.
        let out = Pipe(), err = Pipe(), input = Pipe()
        sp.standardOutput = out; sp.standardError = err; sp.standardInput = input
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty, let text = String(data: d, encoding: .utf8) else { return }
            Task { @MainActor in self?.ingest(text, fromStderr: false) }
        }
        err.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty, let text = String(data: d, encoding: .utf8) else { return }
            Task { @MainActor in self?.ingest(text, fromStderr: true) }
        }
        sp.terminationHandler = { [weak self] p in
            Task { @MainActor in self?.childExited(p) }
        }
        do {
            try sp.run()
        } catch {
            return fail(HostReliability.launchFailure(detail: error.localizedDescription))
        }
        // The server reads exactly one line before it listens; closing the pipe afterwards means
        // nothing else ever arrives on its standard input.
        input.fileHandleForWriting.write(Data((secret + "\n").utf8))
        try? input.fileHandleForWriting.close()
        serverProcess = sp
        proofSecret = secret
        try? "\(sp.processIdentifier)".write(to: pidFile, atomically: true, encoding: .utf8)

        // Ready = the HTTP API answers on loopback AND the one answering proves it is the child
        // just started (another program on that port answers /health too, but cannot do this).
        // First start includes database setup and LiveKit's own start-up check, so allow it a while.
        let deadline = Date().addingTimeInterval(90)
        var up = false
        while Date() < deadline {
            guard gen == generation else { return }             // stopped, or superseded
            guard sp.isRunning else { return childExited(sp) }  // it explains itself there
            if await Self.healthy(port: chosen), await proves(sp, port: chosen) { up = true; break }
            try? await Task.sleep(for: .milliseconds(300))
        }
        guard gen == generation else { return }
        guard sp.isRunning else { return childExited(sp) }
        guard up else {
            // Still running but not answering: end it and try again like any other failure.
            killChildren()
            dropChild()
            let delay = HostReliability.restartDelay(failures: failures)
            failures += 1
            scheduleRestart(reason: HostReliability.healthTimeout, after: delay)
            return
        }
        healthySince = Date()
        phase = .running
        Log.host.info("local server running")
        await settleAddress()
        await resumeLocalSession()
        startUpkeep()
    }

    private func fail(_ sentence: String) {
        halt()
        phase = .failed(sentence)
    }

    private func childExited(_ p: Process) {
        guard p === serverProcess else { return }
        dropChild()
        try? FileManager.default.removeItem(at: pidFile)
        upkeepTask?.cancel(); upkeepTask = nil
        guard wantsHosting else { return }
        let gen = generation
        Task {
            // Its last words may still be in the pipe; let them land before reading them.
            try? await Task.sleep(for: .milliseconds(250))
            guard gen == self.generation, self.wantsHosting else { return }
            self.decideAfterExit(p)
        }
    }

    /// The server ended by itself while hosting is on: restart it, or stop and say why.
    private func decideAfterExit(_ p: Process) {
        let signaled = p.terminationReason == .uncaughtSignal
        let code = p.terminationStatus
        let healthyFor = healthySince.map { Date().timeIntervalSince($0) }
        healthySince = nil
        if let healthyFor, healthyFor >= HostReliability.healthyReset { portMoves = 0; avoidPorts = [] }
        failures = HostReliability.failuresCarried(failures, healthyFor: healthyFor)
        let action = HostReliability.afterExit(code: code, signaled: signaled, failures: failures, portMoves: portMoves)
        let sentence = HostReliability.sentence(
            exitCode: code, signaled: signaled, lastProblem: lastProblem, port: port, portMoves: portMoves)
        Log.host.info("local server ended by itself")
        switch action {
        case .giveUp:
            fail(sentence)
        case .retry(let delay, let movePort):
            if movePort {
                portMoves += 1
                avoidPorts.insert(port)
            } else {
                failures += 1
            }
            scheduleRestart(reason: sentence, after: delay)
        }
    }

    private func scheduleRestart(reason: String, after delay: TimeInterval) {
        generation += 1
        let gen = generation
        phase = .restarting(reason)
        retryAt = Date().addingTimeInterval(delay)
        append("[app] \(reason) Starting the server again in \(Int(delay)) s.")
        restartTask?.cancel()
        restartTask = Task {
            if delay > 0 { try? await Task.sleep(for: .seconds(delay)) }
            guard !Task.isCancelled, gen == self.generation, self.wantsHosting else { return }
            await self.run()
        }
    }

    /// Challenge the listener on `port` with a fresh nonce: true only if `sp` is the child this
    /// app started, it is still running, and the answer is the HMAC under ITS secret. Checked
    /// again after the answer, so a child that died meanwhile never counts.
    private func proves(_ sp: Process, port: Int) async -> Bool {
        guard sp === serverProcess, sp.isRunning, let secret = proofSecret,
              let nonce = HostReliability.randomBytes(32),
              let url = URL(string: HostReliability.localURL(port: port) + "/api/instance/local-proof?nonce=" + HostReliability.hex(nonce))
        else { return false }
        var req = URLRequest(url: url); req.timeoutInterval = 3
        req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              let status = (resp as? HTTPURLResponse)?.statusCode,
              HostReliability.proofAccepted(status: status, body: data, secret: secret, nonce: nonce) else { return false }
        return sp === serverProcess && sp.isRunning && proofSecret == secret
    }

    /// The local server's address — but only if the child this app started is running and has
    /// JUST proven itself (a fresh challenge every call). nil = send nothing there.
    func verifiedLocalURL() async -> String? {
        guard phase == .running, let sp = serverProcess, port == HostPort.current,
              await proves(sp, port: port) else { return nil }
        return HostReliability.localURL(port: port)
    }

    /// The base URL to use for a plain (non-p2p) stored address. An address that can only be
    /// this Mac's own server is handed out only once that server has proven itself; any other
    /// address passes through untouched.
    func gatedBase(_ server: String) async -> String? {
        guard HostReliability.isHostLoopback(server) else { return server }
        guard server == Self.localURL else { return nil }   // an old port: not ours any more
        return await verifiedLocalURL()
    }

    /// The owner's workspace on this Mac's server, if it is the one on screen.
    private var localWorkspaceOnScreen: Workspace? {
        guard let app, let w = app.current, w.nodeId == nil, HostReliability.isHostLoopback(w.server) else { return nil }
        return w
    }

    /// The child is gone: rebind the owner's workspace (it resolves to "offline" now), so its
    /// session token is not sent to whatever takes the port next.
    private func cutLocalSession() {
        guard let app, let w = localWorkspaceOnScreen, !app.serverURL.isEmpty else { return }
        Task {
            // Re-read it: the stored copy may have changed (a rotated token) since.
            if let now = app.current, now.id == w.id { await app.activate(now) }
        }
    }

    /// The child is up and proven: bring the owner's workspace back online.
    private func resumeLocalSession() async {
        guard let app, let w = localWorkspaceOnScreen, app.serverURL.isEmpty else { return }
        await app.activate(w)
    }

    private static func healthy(port: Int) async -> Bool {
        guard let url = URL(string: HostReliability.localURL(port: port) + "/health") else { return false }
        var req = URLRequest(url: url); req.timeoutInterval = 2
        guard let (_, resp) = try? await URLSession.shared.data(for: req) else { return false }
        return (resp as? HTTPURLResponse)?.statusCode == 200
    }

    // MARK: orphan handling

    private var pidFile: URL { dataDir.appendingPathComponent(".server.pid") }

    /// A server left over from a crashed app still holds the port. Stop it — but only if the
    /// recorded pid really is OUR bundled server binary (never a blind kill by name or pid) —
    /// and wait for it to let go of the port.
    private func reapOrphan(_ server: URL) async {
        defer { try? FileManager.default.removeItem(at: pidFile) }
        guard let text = try? String(contentsOf: pidFile, encoding: .utf8),
              let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 1 else { return }
        guard Self.executablePath(of: pid) == server.resolvingSymlinksInPath().path else { return }
        let sfu = tool("livekit-server")?.resolvingSymlinksInPath().path
        for child in Self.children(of: pid) where Self.executablePath(of: child) == sfu { kill(child, SIGTERM) }
        kill(pid, SIGTERM)
        for _ in 0..<30 {
            if kill(pid, 0) != 0 { break }   // gone
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    // MARK: the owner's session (port moves, member count, a late node id)

    /// Called by `AppState.restore` once the stored workspaces are loaded.
    func attach(_ app: AppState) async {
        self.app = app
        await settleAddress()
    }

    /// The server came up on another port than before: move the owner's stored workspace to the
    /// new address, so this Mac stays signed in. Only once the server really answers there.
    private func settleAddress() async {
        guard phase == .running, let app else { return }
        let moved = HostPort.movedFrom
        guard !moved.isEmpty else { return }
        for old in moved {
            await app.hostAddressMoved(from: HostReliability.localURL(port: old), to: Self.localURL)
        }
        HostPort.settled()
    }

    // MARK: where Start and Invite lead (`HostSetupRoute`)

    /// This Mac holds an account on its own server: owner setup has run.
    var hasOwnerWorkspace: Bool { app?.workspace(at: .https(Self.localURL)) != nil }

    private var serverUp: Bool {
        switch phase {
        case .running, .starting, .restarting: return true
        case .idle, .stopped, .failed: return false
        }
    }

    /// "Start server" outside the wizard (the menu bar). On a Mac that has no owner account
    /// yet, starting alone leaves a server nobody can invite into — so it opens the setup too.
    func requestStart() { follow(HostSetupRoute.decide(.startServer, hasOwnerWorkspace: hasOwnerWorkspace, serverUp: serverUp)) }

    /// "Invite friends…" from the menu bar, the profile, or anywhere else.
    func requestInvite() { follow(HostSetupRoute.decide(.inviteFriends, hasOwnerWorkspace: hasOwnerWorkspace, serverUp: serverUp)) }

    private func follow(_ decision: HostSetupRoute.Decision) {
        if decision.startServer { start() }
        switch decision.screen {
        case .none: break
        case .invitePanel:
            bringWindowForward()
            showInvitePanel = true
        case .setupWizard:
            bringWindowForward()
            showInvitePanel = false
            showSetupWizard = true
        }
    }

    /// The setup and the invite are sheets of the main window. Started at login, Skwod can be
    /// running with no window at all: ask the system to reopen the app, which makes one.
    private func bringWindowForward() {
        NSApplication.shared.activate(ignoringOtherApps: true)
        let hasWindow = NSApplication.shared.windows.contains { $0.isVisible && $0.canBecomeMain }
        if !hasWindow {
            let config = NSWorkspace.OpenConfiguration()
            config.activates = true
            NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: config)
        }
    }

    // MARK: the per-file upload limit (owner only)

    /// What the running server allows per file, in megabytes (nil: not running, not the owner,
    /// or a bundled server older than this setting).
    func uploadLimitMB() async -> Int? {
        guard phase == .running, let session = ownerSession, let base = await verifiedLocalURL(),
              let info = await getJSON(base, "/api/instance/limits", token: session.token),
              let mb = (info["max_upload_mb"] as? NSNumber)?.intValue else { return nil }
        return mb
    }

    /// Set it. Returns nil when the server took it, else a sentence saying why not. The owner's
    /// token only ever goes to the child this app started, freshly challenged.
    func setUploadLimit(mb: Int) async -> String? {
        guard phase == .running, let session = ownerSession else { return "Start the server and finish setup first." }
        guard let base = await verifiedLocalURL(), let url = URL(string: base + "/api/instance/limits") else { return HostReliability.notOurServer }
        var req = URLRequest(url: url); req.timeoutInterval = 8
        req.httpMethod = "PUT"
        req.setValue("Bearer \(session.token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["max_upload_mb": mb])
        guard let (data, resp) = try? await URLSession.shared.data(for: req) else { return "Couldn't reach the server. Try again." }
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if status == 200 { return nil }
        if status == 404 || status == 405 { return "The server bundled with this build is older than this setting. Update Skwod, then try again." }
        let sentence = ((try? JSONSerialization.jsonObject(with: data)) as? [String: Any])?["error"] as? String
        if let sentence, !sentence.isEmpty, sentence.count < 300 { return sentence.prefix(1).uppercased() + sentence.dropFirst() + (sentence.hasSuffix(".") ? "" : ".") }
        return "The server didn't accept that limit."
    }

    /// The owner's session on the local server, if this Mac is signed in as its owner.
    private var ownerSession: (token: String, userId: String)? {
        guard let w = app?.workspace(at: .https(Self.localURL)), !w.isSignedOut else { return nil }
        return (w.token, w.userId)
    }

    /// While running: learn the node id if the server's output did not carry it (the p2p
    /// endpoint came up late), and keep the member count fresh for the quit question.
    private func startUpkeep() {
        upkeepTask?.cancel()
        let gen = generation
        upkeepTask = Task {
            var tick = 0
            while !Task.isCancelled, gen == self.generation, self.phase == .running {
                // The owner's token goes out below: challenge the listener first, every round.
                if let base = await self.verifiedLocalURL() {
                    if self.nodeId == nil { await self.refreshNodeId(base) }
                    if tick % 6 == 0 || self.memberCount == nil { await self.refreshMemberCount(base) }
                }
                tick += 1
                try? await Task.sleep(for: .seconds(self.nodeId == nil ? 5 : 10))
            }
        }
    }

    /// `base` is always a `verifiedLocalURL()` obtained for this round.
    private func getJSON(_ base: String, _ path: String, token: String) async -> [String: Any]? {
        guard let url = URL(string: base + path) else { return nil }
        var req = URLRequest(url: url); req.timeoutInterval = 5
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    /// `GET /api/instance/p2p` (members only): `{ enabled, node_id, … }` once the endpoint is up.
    private func refreshNodeId(_ base: String) async {
        guard let session = ownerSession,
              let info = await getJSON(base, "/api/instance/p2p", token: session.token),
              info["enabled"] as? Bool == true, let raw = info["node_id"] as? String,
              let id = HostReliability.validNodeId(raw) else { return }
        if nodeId == nil { nodeId = id }
    }

    /// Everyone in the owner's servers on this Mac's skwod, minus the owner.
    private func refreshMemberCount(_ base: String) async {
        guard let session = ownerSession else { memberCount = nil; return }
        guard let list = await getJSON(base, "/api/servers", token: session.token),
              let servers = list["servers"] as? [[String: Any]] else { return }
        var people = Set<String>()
        for s in servers {
            guard let id = s["server_id"] as? String,
                  let safe = id.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-_"))),
                  let body = await getJSON(base, "/api/servers/\(safe)/members", token: session.token),
                  let members = body["members"] as? [[String: Any]] else { return }   // incomplete: keep the last count
            for m in members { if let uid = m["user_id"] as? String { people.insert(uid) } }
        }
        people.remove(session.userId)
        memberCount = people.count
    }

    // MARK: server output

    /// Parse the server's output: the one-time owner code, the invite (→ node id) and, on stderr,
    /// the sentence that explains a failure. Lines go to the in-app log with codes redacted — the
    /// log is shown on screen and can be copied.
    private func ingest(_ text: String, fromStderr: Bool) {
        for raw in text.split(whereSeparator: \.isNewline) {
            var line = String(raw)
            if let r = line.range(of: #"SKWD-[A-Z0-9]{4}-[A-Z0-9]{4}"#, options: .regularExpression) {
                if line.contains("Join code:") {
                    joinCode = String(line[r])
                    stashCode(String(line[r]))
                }
                line.replaceSubrange(r, with: "SKWD-····-····")
            }
            // The local admin page's one-time token is a credential too.
            if let r = line.range(of: "admin token: ") {
                line.replaceSubrange(r.upperBound..., with: "····")
            }
            // `Invite: https://skwod.io/join#<node>.<code>` and `App link: skwod://join/<node>#<code>`.
            if let id = HostReliability.nodeId(inLine: line) { nodeId = id }
            if fromStderr, let problem = HostReliability.problem(in: line) { lastProblem = problem }
            append(line)
        }
    }

    private func append(_ line: String) {
        guard !line.isEmpty else { return }
        log.append(line)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }

    // MARK: owner setup code

    private var codeStash: URL { dataDir.appendingPathComponent(".join-code") }
    private func stashCode(_ code: String) {
        try? code.write(to: codeStash, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: codeStash.path)
    }
    private func loadStashedCode() -> String? {
        (try? String(contentsOf: codeStash, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The owner setup code is a one-time bootstrap credential: once ownership is claimed the server
    /// kills it, so the plaintext `.join-code` stash must not linger. Idempotent.
    func clearSetupCode() {
        try? FileManager.default.removeItem(at: codeStash)
        joinCode = nil
    }

    // MARK: owner login

    struct OwnerLogin: Codable { var username: String; var password: String }

    var ownerLogin: OwnerLogin? {
        guard let json = Keychain.get(Self.ownerCredentialsAccount), let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode(OwnerLogin.self, from: data)
    }

    fileprivate func saveOwnerLogin(_ login: OwnerLogin) {
        if let data = try? JSONEncoder().encode(login), let json = String(data: data, encoding: .utf8) {
            Keychain.set(json, for: Self.ownerCredentialsAccount)
        }
    }

    /// A 24-character password from the system RNG, in an unambiguous alphabet (~119 bits).
    fileprivate static func generatePassword() -> String? {
        let alphabet = Array("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        var bytes = [UInt8](repeating: 0, count: 48)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        // Rejection sampling keeps the distribution uniform.
        let limit = UInt8(256 - 256 % alphabet.count)
        let chars = bytes.filter { $0 < limit }.prefix(24).map { alphabet[Int($0) % alphabet.count] }
        return chars.count == 24 ? String(chars) : nil
    }
}

#if DEBUG
/// What the DEBUG host hooks (`HostE2E`) may look at.
extension HostManager {
    var debugChildPid: Int32? { serverProcess.map { $0.processIdentifier } }
    var debugApp: AppState? { app }
    var debugHasSecret: Bool { proofSecret != nil }
}
#endif

struct HostError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

extension AppState {
    /// Sign this Mac in to the server it hosts, as its owner, over the local path — no typing a
    /// password, no pasting a link.
    ///
    /// First time: creates the owner account with the one-time setup code the server printed and a
    /// generated password, which is kept in the Keychain (and can be revealed from the host panel
    /// to sign in on a phone). Afterwards: reuses the saved workspace, or logs in again with the
    /// saved login if the session expired.
    func signInAsHostOwner(username: String) async throws {
        let host = HostManager.shared
        let address = SkwodAddress.https(HostManager.localURL)
        if let existing = workspace(at: address) {
            await activate(existing)
            return
        }
        // From here on a credential leaves this app (the saved password, or the setup code and
        // a new password). It goes ONLY to the child this app started, freshly challenged.
        if let saved = host.ownerLogin {
            guard let local = await host.verifiedLocalURL() else { throw HostError(HostReliability.notOurServer) }
            let s = try await login(baseUrl: local, username: saved.username, password: saved.password)
            await signIn(s, address: address, liveBase: local)
            return
        }
        guard let code = host.joinCode else {
            throw HostError("This server already has an owner, but this Mac has no saved login for it. Log in with the owner's username and password, choosing “This Mac”.")
        }
        guard let password = HostManager.generatePassword() else {
            throw HostError("Couldn't generate a password. Try again.")
        }
        let name = username.trimmingCharacters(in: .whitespaces).lowercased()
        guard let local = await host.verifiedLocalURL() else { throw HostError(HostReliability.notOurServer) }
        let s = try await signup(baseUrl: local, username: name, password: password, joinCode: code)
        host.saveOwnerLogin(.init(username: name, password: password))
        host.clearSetupCode()
        await signIn(s, address: address, liveBase: local)
    }
}

/// The menu-bar icon itself: a filled + green box while hosting, a faded box while starting, and a
/// plain outline when off — so you can tell at a glance whether this Mac is serving.
struct HostMenuBarLabel: View {
    @ObservedObject private var host = HostManager.shared

    var body: some View {
        // The skwod squid in the menu bar, dimmed unless hosting.
        // MenuBarExtra labels can't rasterize resized SwiftUI asset images (they render blank),
        // so the logo is pre-drawn into fixed-size NSImages. MenuBarIcon is a monochrome template
        // asset, so the system tints it to match the menu bar in light and dark mode.
        let live: Bool = { if case .running = host.phase { return true }; return false }()
        Image(nsImage: live ? Self.iconLive : Self.iconIdle)
    }

    private static let iconLive = menuIcon(live: true)
    private static let iconIdle = menuIcon(live: false)

    private static func menuIcon(live: Bool) -> NSImage {
        let size = NSSize(width: 24, height: 24)
        let out = NSImage(size: size)
        out.lockFocus()
        NSGraphicsContext.current?.imageInterpolation = .high
        NSImage(named: "MenuBarIcon")?.draw(
            in: NSRect(origin: .zero, size: size),
            from: .zero, operation: .sourceOver, fraction: live ? 1 : 0.55
        )
        out.unlockFocus()
        // Re-drawing strips the asset's template flag; restore it so the tinting applies.
        out.isTemplate = true
        return out
    }
}

/// The menu-bar dropdown: whether this Mac's server is running, a shortcut to the invite panel,
/// and a start/stop toggle. No invite or code is ever placed in the menu itself.
struct HostStatusMenu: View {
    @ObservedObject private var host = HostManager.shared

    var body: some View {
        switch host.phase {
        case .running:
            // NSMenu ignores SwiftUI text color, so the status dot is a baked colored image.
            Label { Text("Server is live") } icon: { Image(nsImage: Self.dot(.systemGreen)) }
            // Without an owner account on this Mac there is nobody to make an invite: this
            // leads to the setup instead (`HostSetupRoute`).
            Button("Invite friends…") { host.requestInvite() }
            Divider()
            Button("Stop server") { host.stop() }
        case .starting:
            Label { Text("Starting server…") } icon: { Image(nsImage: Self.dot(.systemYellow)) }
            Button("Stop server") { host.stop() }
        case .restarting:
            Label { Text("Server stopped — restarting…") } icon: { Image(nsImage: Self.dot(.systemOrange)) }
            Button("Stop server") { host.stop() }
        case .failed:
            Label { Text("Server couldn't start") } icon: { Image(nsImage: Self.dot(.systemRed)) }
            Button("Start server") { host.requestStart() }
        case .idle, .stopped:
            Label { Text("Server is off") } icon: { Image(nsImage: Self.dot(.systemGray)) }
            Button("Start server") { host.requestStart() }
        }
        Divider()
        Button("Quit Skwod") { NSApplication.shared.terminate(nil) }
    }

    /// A small colored status dot as a non-template NSImage, so menus keep its color.
    private static func dot(_ color: NSColor) -> NSImage {
        let size = NSSize(width: 14, height: 14)
        let out = NSImage(size: size)
        out.lockFocus()
        color.setFill()
        NSBezierPath(ovalIn: NSRect(x: 3, y: 3, width: 8, height: 8)).fill()
        out.unlockFocus()
        out.isTemplate = false
        return out
    }
}
#endif
