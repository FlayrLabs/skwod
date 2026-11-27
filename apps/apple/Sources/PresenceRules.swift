import Foundation

// Who shows as online (build 51). Foundation only; PresenceRules.kt is the twin. Presence is what
// the HOST reports: it colours a dot and nothing else. Every time here is this device's own
// monotonic clock (`PresenceClock`), so neither side's wall clock matters.

struct PresenceBook: Equatable {
    /// The host counts someone silent for this long as offline.
    static let window: TimeInterval = 180
    /// Nothing heard from the host for this long (it is asked every 30 s): the connection on THIS
    /// side is gone, and what is known about others is only what was last seen.
    static let silence: TimeInterval = 90

    struct Seen: Equatable { var status: String; var at: TimeInterval }
    struct View: Equatable {
        /// The status to list someone under: the current one, or the last one seen.
        var status: String
        /// False: not known now (never reported, or this device has lost the host).
        var current: Bool
        /// What the dot shows.
        var dot: String { current ? status : "unknown" }
    }

    private(set) var seen: [String: Seen] = [:]
    private(set) var heardAt: TimeInterval?
    private(set) var polledAt: TimeInterval?

    /// A live event, as it arrives.
    mutating func event(_ userId: String, _ status: String, at now: TimeInterval) {
        guard !userId.isEmpty, Self.known(status) else { return }
        heard(now)
        seen[userId] = Seen(status: status, at: now)
    }

    /// A member list, asked for at `askedAt`: it says nothing newer than that, so an event (or a
    /// later question) that came while it was on its way stands.
    mutating func polled(_ statuses: [String: String], askedAt: TimeInterval) {
        heard(askedAt)
        polledAt = max(polledAt ?? askedAt, askedAt)
        for (userId, status) in statuses where Self.known(status) {
            if let have = seen[userId], have.at > askedAt { continue }
            seen[userId] = Seen(status: status, at: askedAt)
        }
    }

    mutating func forget(_ userId: String) { seen[userId] = nil }

    func view(_ userId: String, now: TimeInterval) -> View {
        let connected = heardAt.map { now - $0 < Self.silence } ?? false
        guard let have = seen[userId] else { return View(status: "offline", current: false) }
        guard now - have.at >= Self.window else { return View(status: have.status, current: connected) }
        // Old news: silent for that long (the lists since then no longer name them) is offline;
        // with nothing asked since (just back from the background) it is not known.
        if connected, let polledAt, polledAt > have.at { return View(status: "offline", current: true) }
        return View(status: have.status, current: false)
    }

    private mutating func heard(_ at: TimeInterval) { heardAt = max(heardAt ?? at, at) }
    private static func known(_ status: String) -> Bool { ["online", "idle", "dnd", "offline"].contains(status) }
}

/// What this device says about its own account. The host keeps ONE status per account and the
/// last device to speak sets it, so a device that is merely not in front says nothing about the
/// account (its closing socket does: the host goes offline with the LAST one).
enum PresenceAnnounce {
    /// Nil: say nothing.
    static func status(active: Bool, chosen: String) -> String? { active ? chosen : nil }

    /// Once a minute. Being invisible needs no repeating.
    static func periodic(active: Bool, chosen: String) -> String? {
        status(active: active, chosen: chosen).flatMap { $0 == "offline" ? nil : $0 }
    }

    /// At most one correction in this long.
    static let gap: TimeInterval = 15

    /// Another device of this account (0.50 and older say "offline" whenever they are not in
    /// front) just took the account offline while it is in use here: say so again.
    static func corrects(eventUser: String, status: String, me: String, announced: String?, lastSentAt: TimeInterval?, now: TimeInterval) -> Bool {
        guard !me.isEmpty, eventUser == me, status == "offline", let announced, announced != "offline" else { return false }
        return lastSentAt.map { now - $0 >= gap } ?? true
    }
}

/// Who is presented as online while THIS device is, or is not, connected to the host (build 51). With
/// its own connection down (Reconnecting…, Opening…) it knows nothing current about anyone: no
/// "N online", nobody listed as online, no green dot — what was last seen is stale, not live.
enum PresenceRoster {
    /// The header's "N online" — nil (not shown) while not connected.
    static func onlineCount(_ ids: [String], me: String?, live: Bool, status: (String) -> String) -> Int? {
        guard live else { return nil }
        return ids.filter { $0 == me || status($0) != "offline" }.count
    }

    struct Groups<T> {
        var online: [T] = []
        var offline: [T] = []
        /// Not connected: everyone, listed without a claim about who is online.
        var unknown: [T] = []
    }

    static func groups<T>(_ members: [T], live: Bool, status: (T) -> String) -> Groups<T> {
        guard live else { return Groups(unknown: members) }
        return Groups(online: members.filter { status($0) != "offline" }, offline: members.filter { status($0) == "offline" })
    }

    /// The dot while not connected: never live.
    static func dot(_ dot: String, live: Bool) -> String { live ? dot : "unknown" }

    static func unknownTitle(_ count: Int) -> String { "Members — \(count) · not connected" }
}

enum PresenceClock {
    /// Seconds since boot, sleep included.
    static var now: TimeInterval { TimeInterval(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)) / 1_000_000_000 }
}
