import Foundation
import Network
import SwiftUI

/// How we are reaching the active skwod right now, in words a person can act on.
enum ConnectionQuality: Equatable {
    /// A classic https server — nothing to report.
    case server
    /// Dialing the host (first connect of this launch).
    case connecting
    /// Straight to the host's machine.
    case direct(rttMs: UInt32)
    /// Through a relay, because no direct route exists right now.
    case relayed(rttMs: UInt32)
    /// We had a connection and lost it; it is being re-dialed (`SessionHealthRule`).
    case reconnecting
    /// The host could not be reached at all (their machine is off, asleep or offline).
    case offline

    var title: String {
        switch self {
        case .server: return "Connected"
        case .connecting: return "Connecting…"
        case .direct: return "Connected directly"
        case .relayed: return "Connected through a relay"
        case .reconnecting: return "Reconnecting…"
        case .offline: return "Host is offline"
        }
    }

    /// One plain sentence explaining the state and what, if anything, it means for privacy.
    var detail: String {
        switch self {
        case .server:
            return "You're connected to this Skwod's server. Messages are end-to-end encrypted."
        case .connecting:
            return "Looking for your host's computer…"
        case .direct:
            return "Your device talks straight to your host's computer. Nothing sits in between."
        case .relayed:
            return "A direct route to your host isn't available right now, so a relay passes the traffic along. The relay can see that your two devices are talking, but never what is said — everything stays end-to-end encrypted. It switches to direct by itself when it can."
        case .reconnecting:
            return "The connection dropped. Skwod is trying again."
        case .offline:
            return "Your host's computer can't be reached. It may be off, asleep or offline. Skwod keeps trying, and your messages on this device are still here."
        }
    }

    var symbol: String {
        switch self {
        case .server, .direct: return "checkmark.circle.fill"
        case .relayed: return "arrow.triangle.swap"
        case .connecting, .reconnecting: return "arrow.triangle.2.circlepath"
        case .offline: return "wifi.slash"
        }
    }

    var color: Color {
        switch self {
        case .server, .direct: return .green
        case .relayed: return .yellow
        case .connecting, .reconnecting: return .orange
        case .offline: return .red
        }
    }

    var isUsable: Bool {
        switch self {
        case .server, .direct, .relayed: return true
        default: return false
        }
    }
}

/// Owns the live p2p sessions — one per host key — and the loopback URL each one exposes.
///
/// The loopback URL (`http://127.0.0.1:<port>/<secret>`) is a per-launch value: it is never
/// persisted, never shown and never logged. What is persisted is the host's node id; this class
/// turns that into a usable base URL on launch and keeps the session healthy across foreground
/// and network changes.
@MainActor
final class P2PManager: ObservableObject {
    static let shared = P2PManager()

    /// Connection state per host key, for the indicator.
    @Published private(set) var quality: [String: ConnectionQuality] = [:]

    private var sessions: [String: P2pSession] = [:]
    private var inflight: [String: Task<P2pSession, Error>] = [:]
    private let monitor = NWPathMonitor()
    private var lastPathSignature: String?

    private static let fallbackKey = "skwod.p2p.publicFallback"

    /// (A change is applied with `applyRelaySetting`.)
    /// Whether a relay may carry the connection when no direct route exists (default on: it is
    /// what makes joining work behind almost any router). Off = direct connections only.
    static var publicFallback: Bool {
        get { UserDefaults.standard.object(forKey: fallbackKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: fallbackKey) }
    }

    private init() {
        // The core refuses relay-allowed dials until it knows the stored setting; every dial of
        // the app goes through this object.
        p2pRelaysInit(allowed: Self.publicFallback)
        monitor.pathUpdateHandler = { [weak self] path in
            // Interface set + reachability is all we look at — never an address.
            let signature = "\(path.status)|" + path.availableInterfaces.map { "\($0.type)" }.joined(separator: ",")
            Task { @MainActor in
                guard let self else { return }
                defer { self.lastPathSignature = signature }
                guard self.lastPathSignature != nil, self.lastPathSignature != signature else { return }
                await self.networkChanged()
                NotificationCenter.default.post(name: .skwodNetworkChanged, object: nil)
            }
        }
        monitor.start(queue: DispatchQueue(label: "io.skwod.netmonitor"))
    }

    // Build 51: one stable loopback FRONT per (host, account) — keyed by the workspace id once
    // there is one (by the host's node id before sign-in, until a workspace adopts it). Its port
    // and base URL never change while the app runs: a dead connection is replaced INSIDE the core
    // (`P2pSession.reconnect`), and a listener the OS took away comes back on the same port
    // (`ensureFront`). The session token never crosses loopback: clients present an opaque
    // credential from `signIn`, and the front injects the token.

    /// The front's base URL for `key` if one is up.
    func liveBase(for key: String, nodeId: String? = nil) -> String? {
        guard let s = sessions[key], nodeId == nil || s.nodeId() == nodeId else { return nil }
        return s.baseUrl()
    }

    /// The session behind `key` (sign-in, logout, push requests over the member connection) —
    /// only if it is for `nodeId` (when given): a front never serves another host's workspace.
    func session(for key: String, nodeId: String? = nil) -> P2pSession? {
        guard let s = sessions[key], nodeId == nil || s.nodeId() == nodeId else { return nil }
        return s
    }

    /// Sign-out: the front is taken out of the map AT ONCE (a new sign-in dials its own) and
    /// handed back to be ended and closed by the caller.
    func detach(key: String) -> P2pSession? {
        inflight[key]?.cancel(); inflight[key] = nil
        probeFailures[key] = nil; lastProbeOK[key] = nil
        quality[key] = nil
        return sessions.removeValue(forKey: key)
    }

    /// A workspace takes over the pre-sign-in front of its host (dialed by the log-in screen),
    /// unless it has its own already — and only a front of that host.
    func adopt(nodeId: String, as key: String) {
        guard sessions[key] == nil, key != nodeId, sessions[nodeId]?.nodeId() == nodeId,
              let s = sessions.removeValue(forKey: nodeId) else { return }
        sessions[key] = s
        quality[key] = quality.removeValue(forKey: nodeId)
    }

    /// Bumped by `applyRelaySetting`: a dial started before it is never used (`DialRule`).
    private var dialGeneration = 0

    /// Dial the host for `key` (or reuse its front) and return the base URL to use wherever a
    /// server URL goes. Concurrent callers share one dial.
    func connect(nodeId: String, key: String? = nil) async throws -> String {
        let key = key ?? nodeId
        if let s = sessions[key] {
            if s.nodeId() == nodeId { return s.baseUrl() }
            // The workspace now names another host: its old front is closed first (its token is
            // forgotten here only — nothing is ended on any host).
            _ = detach(key: key)
            await s.disconnect()
        }
        if let pending = inflight[key] { return try await pending.value.baseUrl() }
        if quality[key] == nil || quality[key] == .offline { quality[key] = .connecting }
        let fallback = Self.publicFallback
        let generation = dialGeneration
        // The home relay from the invite or an earlier session: dial through it at once instead
        // of waiting for the DHT / n0 lookup (the core ignores it without public fallback).
        let hint = RelayHintStore.get(nodeId)
        let routes = DirectRoutes.load(key)
        let task = Task { try await Self.withDeadline(Self.connectDeadline) {
            try await p2pConnectHinted(nodeId: nodeId, publicFallback: fallback, relayUrl: hint, routes: routes)
        } }
        inflight[key] = task
        defer { if inflight[key] == task { inflight[key] = nil } }
        do {
            let session = try await task.value
            // Dialed under a relay setting that no longer holds (relays turned off meanwhile):
            // never used.
            guard DialRule.usable(dialGeneration: generation, currentGeneration: dialGeneration,
                                  dialFallback: fallback, currentFallback: Self.publicFallback) else {
                Task.detached { await session.disconnect() }
                throw P2PStaleDial()
            }
            sessions[key] = session
            watchProxy(session, key: key)
            await refresh(key: key)
            return session.baseUrl()
        } catch {
            quality[key] = .offline
            // A stale hint only costs a lookup, but the next attempt need not repeat it.
            RelayHintStore.clear(nodeId)
            throw error
        }
    }

    /// The core gives up after `p2pConnectTimeoutSecs()` (20 s); this is the app's own backstop
    /// a little later, so the login screen can never spin forever even if the core stalls.
    nonisolated static var connectDeadline: Duration { ConnectDeadline.backstop(coreSeconds: p2pConnectTimeoutSecs()) }

    /// Run `body`, or throw `P2PConnectTimeout` once `limit` has passed (see `ConnectDeadline`).
    nonisolated static func withDeadline<T: Sendable>(_ limit: Duration, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
        try await ConnectDeadline.run(limit, body)
    }

    /// Re-read direct/relayed + latency for one front (cheap; local only).
    func refresh(key: String) async {
        guard let s = sessions[key] else { return }
        if DirectRoutes.mayKeep(key), let new = s.takeRoutes() { DirectRoutes.save(new, for: key) }
        // The host did not answer the last probe: the path the transport still remembers is
        // not a connection (`SessionHealthRule`) — the pill says "Reconnecting…" until it does.
        if (probeFailures[key] ?? 0) > 0 { quality[key] = .reconnecting; return }
        let p = await s.path()
        switch p.kind {
        case "direct": quality[key] = .direct(rttMs: p.rttMs)
        case "relay": quality[key] = .relayed(rttMs: p.rttMs)
        default: quality[key] = .reconnecting
        }
    }

    private var probeFailures: [String: Int] = [:]
    private var lastProbeOK: [String: Date] = [:]
    private var probing: Set<String> = []

    /// What a health check did, for the caller.
    enum HealthOutcome: Equatable {
        /// Nothing the app has to do (healthy, degraded, or the connection was replaced behind
        /// the front — invisible to the app).
        case unchanged
        /// The front moved to a new port (rare): re-bind to `base` with `credential`.
        case moved(base: String, credential: String?)
        /// Not proved ours, or being checked right now: never "healthy" — nothing is sent to it
        /// until it is (`FrontProof`).
        case unproved
    }

    /// Is the front for `key` still usable? `P2pSession.check` answers two things, judged
    /// differently (`SessionHealthRule.next`): the front's listener alive and PROVED ours (a
    /// one-time nonce reached our handler, checked in process) — if not, it listens again
    /// (`ensureFront`); and the host answering over the connection — if not (one failure when
    /// urgent, two in a row otherwise) the connection is replaced inside the core, paced there.
    /// Neither changes the base URL, except a move. One check per front at a time; errors count
    /// as failures (fail closed).
    /// `callActive`: only DELAYS a re-key (`ensureFront`); a proof that failed leaves the front
    /// suspect either way.
    func checkHealth(key: String, urgent: Bool, userAsked: Bool = false, callActive: Bool = false) async -> HealthOutcome {
        guard let s = sessions[key] else { return .unchanged }
        guard probing.insert(key).inserted else { return .unproved }
        defer { probing.remove(key) }
        // Still SUSPECT (back from the background): proved ours — or re-keyed — first.
        if isFrontSuspect(baseUrl: s.baseUrl()) {
            let r = await ensureFront(key: key, callActive: callActive)
            if r != .unchanged { return r }
        }
        let proxyDead = s.proxyClosed()
        if !proxyDead {
            guard SessionHealthRule.shouldProbe(lastOK: lastProbeOK[key], now: Date(), userAsked: userAsked) else { return .unchanged }
        }
        let health = proxyDead ? P2pHealth(proxyOk: false, upstreamOk: false)
                               : await s.check(timeoutMs: UInt32(SessionHealthRule.probeTimeout * 1000))
        guard sessions[key] === s else { return .unchanged }
        if !health.proxyOk {
            // (SUSPECT already, in the core. The host was not asked: the check stopped here.)
            let r = await ensureFront(key: key, callActive: callActive)
            return r == .unchanged ? .unproved : r
        }
        let step = SessionHealthRule.next(failures: probeFailures[key] ?? 0, proxyOK: true,
                                          upstreamOK: health.upstreamOk, urgent: urgent)
        probeFailures[key] = step.failures
        switch step.outcome {
        case .healthy:
            lastProbeOK[key] = Date()
            await refresh(key: key)
        case .degraded:
            quality[key] = .reconnecting
        case .replace:
            Log.app.info("p2p connection did not answer; dialing a fresh one behind the same front")
            quality[key] = .reconnecting
            lastProbeOK[key] = nil
            if (try? await s.reconnect(publicFallback: nil)) != nil {
                probeFailures[key] = 0
                await refresh(key: key)
            }
        }
        return .unchanged
    }

    /// Prove the front ours, or re-key it. `.unchanged` only when it IS proved. `callActive`: a
    /// challenge merely unanswered waits with the re-key (and stays suspect); a port that is not
    /// ours re-keys all the same.
    func ensureFront(key: String, callActive: Bool = false) async -> HealthOutcome {
        guard let s = sessions[key] else { return .unchanged }
        let state = callActive ? await s.ensureFrontDeferring() : await s.ensureFront()
        guard sessions[key] === s else { return .unproved }
        switch FrontProof.of(relistened: state.relistened, failed: state.failed, stillSuspect: isFrontSuspect(baseUrl: s.baseUrl())) {
        case .proved: return .unchanged
        // ANY re-listen re-keys (a new secret): every client is bound again.
        case .moved: return .moved(base: state.baseUrl, credential: state.credential)
        case .unproved: return .unproved
        }
    }

    /// Going to the background, and back in front: every front is SUSPECT (the OS may take its
    /// listener away and another process its port) — nothing is sent to it until `ensureFront`
    /// proves it ours. `except`: `ForegroundRule.exempt`.
    func suspendAll(except: String? = nil) {
        for (key, s) in sessions where key != except { s.suspend() }
    }

    /// The relay setting changed: every connection is replaced under the new setting, behind
    /// its front (turning relays OFF closes the relayed ones at once, in the core). Dials in
    /// flight were started under the old setting: discarded.
    /// False: turning relays off failed in the core — every session is disconnected (fail closed).
    /// Off takes effect at once; the rest is in order (`RelayRuns`).
    func applyRelaySetting() async -> Bool {
        dialGeneration += 1
        for t in inflight.values { t.cancel() }
        inflight.removeAll()
        return await relayRuns.changed(
            setting: { Self.publicFallback },
            revoke: { p2pRelaysRevoke() },
            turnOn: { p2pRelaysOn() },
            // Confirmed by the core: nothing in this process may use a relay any more.
            turnOff: { try await p2pRelaysOff() },
            redial: { fallback in
                let all = self.sessions
                for key in all.keys { self.quality[key] = .reconnecting }
                await withTaskGroup(of: Void.self) { group in
                    for s in all.values { group.addTask { _ = try? await s.reconnect(publicFallback: fallback) } }
                }
                for key in all.keys { await self.refresh(key: key) }
            },
            disconnectAll: {
                for s in self.sessions.values { RawSink.cancel(base: s.baseUrl()) }
                await self.disconnectAll()
            })
    }
    private let relayRuns = RelayRuns()

    /// The front's listener failed for good: listen again now, not at the next probe.
    private func watchProxy(_ session: P2pSession, key: String) {
        Task { [weak self] in
            await session.waitProxyClosed()
            guard let self, self.sessions[key] === session else { return }
            NotificationCenter.default.post(name: .skwodSessionProxyClosed, object: key)
        }
    }

    /// Wi-Fi ↔ cellular, or back from the background: tell every session so it re-probes its path.
    func networkChanged() async {
        for (key, s) in sessions {
            await s.networkChanged()
            await refresh(key: key)
        }
    }

    /// Close one front (leaving a skwod, signing out — after its logout went out).
    func disconnect(key: String) async {
        inflight[key]?.cancel()
        probeFailures[key] = nil; lastProbeOK[key] = nil
        if let s = sessions.removeValue(forKey: key) { await s.disconnect() }
        quality[key] = nil
    }

    /// Close everything (sign-out of every skwod).
    func disconnectAll() async {
        for key in Array(sessions.keys) { await disconnect(key: key) }
    }
}

/// Build 51: where a skwod's host was last reached directly (the core's, opaque), for dialing it with
/// relays off. It says where the host is: this device's Keychain only, deleted on sign-out and erase.
@MainActor
enum DirectRoutes {
    /// Only for a skwod that is signed in.
    static var mayKeep: (String) -> Bool = { _ in false }
    static func load(_ workspaceId: String) -> String? { mayKeep(workspaceId) ? Keychain.get(KeyAccess.routesPrefix + workspaceId) : nil }
    static func save(_ routes: String, for workspaceId: String) { Keychain.set(routes, for: KeyAccess.routesPrefix + workspaceId) }
    static func forget(_ workspaceId: String) { Keychain.delete(KeyAccess.routesPrefix + workspaceId) }
}

/// A dial that finished after the relay setting changed: it is not used.
struct P2PStaleDial: Error {}

/// Build 51: THE one check every raw request of the app passes ("may I send to this base right
/// now?"): never to a retired front URL, never to a SUSPECT front (back from the background, not
/// yet proved ours). And what is still in flight to a base whose front moved is cancelled.
enum RawSink {
    static func allows(_ base: String) -> Bool {
        !base.isEmpty && !isRetiredBase(baseUrl: base) && !isFrontSuspect(baseUrl: base)
    }

    /// The same check for a full request URL, made right before it is sent (after any await):
    /// a loopback URL must be under a front that is allowed now; any other URL is not a front's.
    static func allowsURL(_ url: URL?) -> Bool {
        guard let s = url?.absoluteString else { return false }
        guard let base = FrontURL.base(of: s) else { return !s.hasPrefix("http://127.0.0.1:") || !isFrontSuspect(baseUrl: s) }
        return allows(base)
    }

    /// `URLSession.shared.data(for:)`, through the one check (refused: an error, nothing sent).
    static func data(for req: URLRequest) async throws -> (Data, URLResponse) {
        guard allowsURL(req.url) else { throw URLError(.cancelled) }
        return try await URLSession.shared.data(for: req)
    }

    /// Cancel every `URLSession.shared` task to `base` (its front moved or closed).
    static func cancel(base: String) {
        guard !base.isEmpty else { return }
        URLSession.shared.getAllTasks { tasks in
            for t in tasks where URLScope.isUnder(t.originalRequest?.url?.absoluteString, base: base) { t.cancel() }
        }
    }
}

extension Notification.Name {
    /// The device's network changed (interface set / reachability). Posted on the main actor.
    static let skwodNetworkChanged = Notification.Name("skwod.networkChanged")
    /// Build 51: a front's listener failed for good. `object` is the front's key.
    static let skwodSessionProxyClosed = Notification.Name("skwod.sessionProxyClosed")
}

/// The always-visible connection indicator: a coloured dot + a few words; tap for the one-sentence
/// explanation. Deliberately free of jargon — "directly" vs "through a relay" is the whole story.
struct ConnectionPill: View {
    @EnvironmentObject private var app: AppState
    @State private var showDetail = false
    var compact = false

    var body: some View {
        let q = app.connection
        Button { showDetail = true } label: {
            HStack(spacing: 6) {
                Circle().fill(q.color).frame(width: 8, height: 8)
                if !compact {
                    Text(app.cannotReachDirectly ? DirectOnlyRule.short : q.title).font(.caption2.weight(.medium)).foregroundStyle(.white.opacity(0.75)).lineLimit(1)
                }
            }
            .padding(.horizontal, compact ? 6 : 10).padding(.vertical, 5)
            .background(.white.opacity(0.07), in: Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(q.title)
        .popover(isPresented: $showDetail) {
            VStack(alignment: .leading, spacing: 10) {
                Label(q.title, systemImage: q.symbol).font(.headline).foregroundStyle(q.color)
                if app.cannotReachDirectly { DirectOnlyNotice() }
                Text(q.detail).font(.subheadline).fixedSize(horizontal: false, vertical: true)
                if case .direct(let rtt) = q, rtt > 0 { Text("Response time: \(rtt) ms").font(.caption).foregroundStyle(.secondary) }
                if case .relayed(let rtt) = q, rtt > 0 { Text("Response time: \(rtt) ms").font(.caption).foregroundStyle(.secondary) }
            }
            .padding(16).frame(width: 300)
            .presentationCompactAdaptation(.popover)
        }
    }
}

/// Relays are off and there is no direct way to the host: what would help, at the user's tap.
struct DirectOnlyNotice: View {
    @EnvironmentObject private var app: AppState
    @State private var asking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(DirectOnlyRule.text(app.current?.displayName ?? "your host")).font(.system(size: 13, weight: .semibold))
                .foregroundStyle(.white).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 16) {
                Button("Turn on") { asking = true }.accessibilityIdentifier("connection.useRelay")
                Button("Retry") { Task { await app.retryConnection() } }.accessibilityIdentifier("connection.retry")
            }
            .buttonStyle(.plain).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color.skAccent)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .alert("Use a relay when needed?", isPresented: $asking) {
            Button("Turn on") { Task { await app.useRelayWhenNeeded() } }
            Button("Cancel", role: .cancel) {}
        } message: { Text(DirectOnlyRule.whatARelaySees) }
    }
}

/// A strip across the top of the app while the active skwod can't be reached — so a message that
/// isn't sending is never a mystery. Hidden whenever the connection is usable.
struct ConnectionBanner: View {
    @EnvironmentObject private var app: AppState

    /// The height of the header every screen draws at its top (`ChatHeader`).
    static let headerHeight: CGFloat = 48

    /// Whether the strip is up. (The Mac has none: its titlebar pill says it.)
    static func shows(_ app: AppState) -> Bool {
        #if os(iOS)
        app.current != nil && !app.connection.isUsable
        #else
        false
        #endif
    }

    var body: some View {
        let q = app.connection
        if app.cannotReachDirectly {
            DirectOnlyNotice()
                .padding(.horizontal, 14).padding(.vertical, 9)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 18))
                .padding(.horizontal, 12).padding(.top, 8)
        } else if app.current != nil, !q.isUsable {
            HStack(spacing: 8) {
                Image(systemName: q.symbol).foregroundStyle(q.color)
                VStack(alignment: .leading, spacing: 1) {
                    Text(q.title).font(.system(size: 13, weight: .semibold)).foregroundStyle(.white)
                    if q == .offline {
                        Text("Their computer may be off or asleep. Skwod keeps trying.")
                            .font(.caption2).foregroundStyle(.white.opacity(0.6))
                    }
                }
                Spacer(minLength: 0)
                if q == .offline {
                    Button("Retry") { Task { await app.retryConnection() } }
                        .font(.system(size: 13, weight: .semibold))
                        .buttonStyle(.plain)
                        .foregroundStyle(Color.skAccent)
                        .accessibilityIdentifier("connection.retry")
                }
            }
            .padding(.horizontal, 14).padding(.vertical, 9)
            .background(.ultraThinMaterial, in: Capsule())
            .overlay(Capsule().stroke(.white.opacity(0.12)))
            .padding(.horizontal, 12).padding(.top, 8)
        }
    }
}
