import Foundation

// The values the app stores as JSON in a workspace's encrypted cache, apart from the
// conversation lists (ConversationStore.swift): the joined spaces, the contact book and the
// Security activity log. Foundation only — no UI, no core bindings — so the unit tests compile
// this file by itself and decode what earlier builds stored with the same types the app uses
// (Tests/StoredDataCompatibilityTests.swift).

/// A real end-to-end encrypted space (server + one channel) the user created or joined.
struct RealSpace: Identifiable, Hashable, Codable {
    var id = UUID()
    var name: String
    var channelName: String
    var serverId: String
    var channelId: String
    var inviteCode: String
    var spaceKeyHex: String
}

/// How far this device can stand behind a person's NAME.
///
/// An account is authenticated by its keys; its name is not — every name the app is handed
/// (member lists, `findUser`, `listDms`) is the server's claim, and a hostile host can put a
/// friend's name on a ghost account. So names carry a level, and only something the USER did on
/// this device raises it.
enum TrustLevel: String, Codable, Comparable {
    /// Only the server says so. Shown with an "unverified" marker. Server data — however many
    /// lists agree — never yields more than this.
    case unverified
    /// Pinned by an explicit action of the user on this device: they started the conversation,
    /// tapped "Let in", or accepted the contact.
    case known
    /// The user compared safety numbers with this person.
    case verified

    private var rank: Int { self == .unverified ? 0 : (self == .known ? 1 : 2) }
    static func < (a: TrustLevel, b: TrustLevel) -> Bool { a.rank < b.rank }
}

/// One entry of the local contact book.
struct Contact: Codable, Equatable {
    var name: String
    /// Absent in anything stored without it (an older build, a hand-written entry): unverified.
    var level: TrustLevel
    /// Build 49: the user made them KNOWN by an action of their own (started a conversation, let
    /// them in, accepted them) — what un-verifying falls back to. Absent (older entries): known
    /// exactly when the stored level was at least KNOWN.
    var known: Bool?

    init(name: String, level: TrustLevel, known: Bool? = nil) { self.name = name; self.level = level; self.known = known }

    /// Was KNOWN by the user's own action.
    var explicitlyKnown: Bool { known ?? (level >= .known) }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        level = (try? c.decodeIfPresent(TrustLevel.self, forKey: .level)).flatMap { $0 } ?? .unverified
        known = try? c.decodeIfPresent(Bool.self, forKey: .known)
    }
}

/// One row of Profile → Encryption → Security activity.
struct SecurityEvent: Codable, Identifiable, Equatable {
    var kind: String
    var title: String
    var message: String
    var atMs: Int64
    var id: String { "\(kind)-\(atMs)-\(title.hashValue)" }

    /// `events` with `more` added: no event twice, newest first, at most 100 kept.
    static func merged(_ events: [SecurityEvent], adding more: [SecurityEvent]) -> [SecurityEvent] {
        var all = events
        for e in more where !all.contains(where: { $0.kind == e.kind && $0.atMs == e.atMs && $0.title == e.title }) { all.append(e) }
        all.sort { $0.atMs > $1.atMs }
        return Array(all.prefix(100))
    }

    /// The events of a stored list that does not decode as a whole, one by one.
    static func salvage(_ json: String) -> [SecurityEvent] {
        guard let top = try? JSONSerialization.jsonObject(with: Data(json.utf8)), let elements = top as? [Any] else { return [] }
        return elements.compactMap { element in
            guard JSONSerialization.isValidJSONObject(element), let data = try? JSONSerialization.data(withJSONObject: element) else { return nil }
            return try? JSONDecoder().decode(SecurityEvent.self, from: data)
        }
    }
}
