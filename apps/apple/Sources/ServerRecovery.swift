import Foundation

// Build 51: the servers of this account that this device does not show yet (newly linked, restored,
// reinstalled), and when to look for them again. Foundation only; ServerRecovery.kt is the twin.

struct ServerRecovery: Equatable {
    /// What an empty server list says.
    enum State: Equatable {
        /// This device is not one of the account's yet.
        case notSetUp
        case loading
        /// A member, but nobody has handed this device the keys yet.
        case waitingForKeys
        /// The keys are here; there is no text channel to show.
        case noChannels
        /// The skwod answered, completely: none.
        case none
        case failed
    }

    /// The account's servers as last answered, successfully and completely; nil: never.
    private(set) var servers: Set<String>?
    /// Asked in vain since the last answer.
    private(set) var failures = 0
    /// Passes since something gave reason to look again at once.
    private(set) var passes = 0
    /// Missing servers whose name this device can read (it holds their key).
    private(set) var keyed: Set<String> = []
    private var asked: [String: (count: Int, at: TimeInterval)] = [:]

    static func == (a: Self, b: Self) -> Bool {
        a.servers == b.servers && a.failures == b.failures && a.passes == b.passes && a.keyed == b.keyed
    }

    /// The skwod's list (nil: it could not be asked, refused, or did not answer completely).
    mutating func answered(_ list: Set<String>?) {
        guard let list else { failures += 1; return }
        servers = list
        failures = 0
        keyed.formIntersection(list)
    }

    /// Back in front, reconnected, linked, Retry: look now, and often again for a while.
    mutating func nudged() { passes = 0 }
    mutating func passed() { passes += 1 }
    mutating func found(_ server: String, keyed holds: Bool) { if holds { keyed.insert(server) } else { keyed.remove(server) } }

    /// In the list, not on screen, and not left or removed here.
    func missing(shown: Set<String>, hidden: Set<String>) -> Set<String> { (servers ?? []).subtracting(shown).subtracting(hidden) }

    /// Nothing left to look for.
    func settled(shown: Set<String>, hidden: Set<String>) -> Bool {
        servers != nil && failures == 0 && missing(shown: shown, hidden: hidden).isEmpty
    }

    /// Never less than this between two passes, whatever happens meanwhile.
    static let spacing: TimeInterval = 2
    private static let steps: [TimeInterval] = [2, 4, 8, 15, 30]
    /// Until the next pass: it backs off to one a minute and keeps on.
    func delay(active: Bool) -> TimeInterval {
        active && passes > 0 && passes <= Self.steps.count ? Self.steps[passes - 1] : passes == 0 ? Self.spacing : 60
    }

    /// May members be asked for `server`'s keys (again)? At 10 s, 20 s, … up to every 5 minutes.
    func mayAsk(_ server: String, now: TimeInterval) -> Bool {
        guard let last = asked[server] else { return true }
        return now - last.at >= min(10 * pow(2, Double(min(last.count, 10) - 1)), 300)
    }
    mutating func didAsk(_ server: String, now: TimeInterval) { asked[server] = ((asked[server]?.count ?? 0) + 1, now) }

    /// What to say while the list is empty.
    func state(setUp: Bool, shown: Set<String>, hidden: Set<String>) -> State {
        guard setUp else { return .notSetUp }
        let gone = missing(shown: shown, hidden: hidden)
        if !gone.isEmpty { return gone.isSubset(of: keyed) ? .noChannels : .waitingForKeys }
        if failures >= 2 { return .failed }
        return servers == nil || failures > 0 ? .loading : .none
    }
}

extension ServerRecovery.State {
    var title: String {
        switch self {
        case .notSetUp: return "This device isn't set up yet"
        case .loading: return "Loading your servers…"
        case .waitingForKeys: return "Waiting for keys from your other device or a member who is online"
        case .noChannels: return "No channels to show yet"
        case .none: return "You're not in any server here yet"
        case .failed: return "Couldn't load your servers"
        }
    }
    var detail: String {
        switch self {
        case .notSetUp: return "Link it from another device, or restore your account, to see your servers."
        case .loading, .failed: return ""
        case .waitingForKeys: return "Your servers appear here by themselves as soon as the keys arrive."
        case .noChannels: return "Your servers here have no text channel you can read."
        case .none: return "Create one or join with an invite."
        }
    }
}

/// Work that must outlive the screen that started it: a sheet that closes itself ends its own task,
/// and everything still awaited in it (each request to the skwod) fails as cancelled.
enum OutlivingWork {
    @MainActor static func run(_ work: @escaping @MainActor () async -> Void) async { await Task { @MainActor in await work() }.value }
}
