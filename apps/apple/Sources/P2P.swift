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
    /// We had a connection and lost it; the next request re-dials.
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

    /// Whether a relay may carry the connection when no direct route exists (default on: it is
    /// what makes joining work behind almost any router). Off = direct connections only.
    static var publicFallback: Bool {
        get { UserDefaults.standard.object(forKey: fallbackKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: fallbackKey) }
    }

    private init() {
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

    /// The loopback base URL for `nodeId` if a session is already up.
    func liveBase(for nodeId: String) -> String? {
        sessions[nodeId]?.baseUrl()
    }

    /// Dial the host (or reuse the live session) and return the loopback base URL to use wherever
    /// a server URL goes. Concurrent callers share one dial.
    func connect(nodeId: String) async throws -> String {
        if let s = sessions[nodeId] { return s.baseUrl() }
        if let pending = inflight[nodeId] { return try await pending.value.baseUrl() }
        if quality[nodeId] == nil || quality[nodeId] == .offline { quality[nodeId] = .connecting }
        let fallback = Self.publicFallback
        let task = Task { try await p2pConnect(nodeId: nodeId, publicFallback: fallback) }
        inflight[nodeId] = task
        defer { inflight[nodeId] = nil }
        do {
            let session = try await task.value
            sessions[nodeId] = session
            await refresh(nodeId: nodeId)
            return session.baseUrl()
        } catch {
            quality[nodeId] = .offline
            throw error
        }
    }

    /// Re-read direct/relayed + latency for one host (cheap; local only).
    func refresh(nodeId: String) async {
        guard let s = sessions[nodeId] else { return }
        let p = await s.path()
        switch p.kind {
        case "direct": quality[nodeId] = .direct(rttMs: p.rttMs)
        case "relay": quality[nodeId] = .relayed(rttMs: p.rttMs)
        default: quality[nodeId] = .reconnecting
        }
    }

    /// Wi-Fi ↔ cellular, or back from the background: tell every session so it re-probes its path.
    func networkChanged() async {
        for (id, s) in sessions {
            await s.networkChanged()
            await refresh(nodeId: id)
        }
    }

    /// Close one session (leaving a skwod).
    func disconnect(nodeId: String) async {
        inflight[nodeId]?.cancel()
        if let s = sessions.removeValue(forKey: nodeId) { await s.disconnect() }
        quality[nodeId] = nil
    }

    /// Close everything (sign-out, or the relay setting changed and sessions must be re-dialed).
    func disconnectAll() async {
        for id in Array(sessions.keys) { await disconnect(nodeId: id) }
    }
}

extension Notification.Name {
    /// The device's network changed (interface set / reachability). Posted on the main actor.
    static let skwodNetworkChanged = Notification.Name("skwod.networkChanged")
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
                    Text(q.title).font(.caption2.weight(.medium)).foregroundStyle(.white.opacity(0.75)).lineLimit(1)
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
                Text(q.detail).font(.subheadline).fixedSize(horizontal: false, vertical: true)
                if case .direct(let rtt) = q, rtt > 0 { Text("Response time: \(rtt) ms").font(.caption).foregroundStyle(.secondary) }
                if case .relayed(let rtt) = q, rtt > 0 { Text("Response time: \(rtt) ms").font(.caption).foregroundStyle(.secondary) }
            }
            .padding(16).frame(width: 300)
            .presentationCompactAdaptation(.popover)
        }
    }
}

/// A strip across the top of the app while the active skwod can't be reached — so a message that
/// isn't sending is never a mystery. Hidden whenever the connection is usable.
struct ConnectionBanner: View {
    @EnvironmentObject private var app: AppState

    var body: some View {
        let q = app.connection
        if app.current != nil, !q.isUsable {
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
            }
            .padding(.horizontal, 14).padding(.vertical, 9)
            .background(.ultraThinMaterial, in: Capsule())
            .overlay(Capsule().stroke(.white.opacity(0.12)))
            .padding(.horizontal, 12).padding(.top, 8)
        }
    }
}
