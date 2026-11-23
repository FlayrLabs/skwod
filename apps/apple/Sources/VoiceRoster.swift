import Foundation

/// One person in a server's voice room, as the server says (build 47, `voice_state`).
struct VoiceParticipant: Equatable, Identifiable {
    let userId: String
    /// No unmuted microphone.
    let muted: Bool
    let video: Bool
    let screen: Bool
    /// Unix seconds; orders the list (0 = unknown).
    let joinedAt: Int64
    var id: String { userId }
}

/// Who is in each server's voice room right now — the list under the voice channel in the
/// sidebar. Fed only by `voice_state` events on a `server:<id>` topic: each one
/// carries the FULL roster of one room, so applying it replaces that room (a lost or late event
/// is corrected by the next). Kept in memory; emptied when the connection comes back (the
/// server hands every room's roster again on subscribing).
///
/// What is NOT here: who is speaking (the call this device is in knows that itself) and
/// "deafened" (a local setting no server sees). Names are never taken from the event: the
/// sidebar shows the label this device has for the user id (`ContactTrust`).
struct VoiceRoster: Equatable {
    /// Listed per room at most (the server sends no more).
    static let maxListed = 64
    /// Non-empty rooms kept per server at most: what a host sends is bounded here, not by trust.
    static let maxRooms = 64

    /// server id → voice channel id → participants in join order.
    private(set) var rooms: [String: [String: [VoiceParticipant]]] = [:]

    /// A `voice_state` event. Accepted only on the topic of the server it names. Returns
    /// whether anything changed.
    @discardableResult
    mutating func apply(topic: String, payload: [String: Any]) -> Bool {
        guard let serverId = payload["server_id"] as? String, !serverId.isEmpty, topic == "server:\(serverId)",
              let channelId = payload["channel_id"] as? String, !channelId.isEmpty, channelId.count <= 128,
              let list = payload["participants"] as? [[String: Any]] else { return false }
        var seen = Set<String>()
        var people: [VoiceParticipant] = []
        for p in list.prefix(Self.maxListed) {
            guard let uid = p["user_id"] as? String, !uid.isEmpty, uid.count <= 128, seen.insert(uid).inserted else { continue }
            people.append(VoiceParticipant(userId: uid, muted: p["muted"] as? Bool ?? false, video: p["video"] as? Bool ?? false,
                                           screen: p["screen"] as? Bool ?? false,
                                           joinedAt: (p["joined_at"] as? NSNumber)?.int64Value ?? 0))
        }
        let old = rooms[serverId]?[channelId] ?? []
        guard old != people else { return false }
        if old.isEmpty, (rooms[serverId]?.count ?? 0) >= Self.maxRooms { return false }
        if people.isEmpty {
            rooms[serverId]?[channelId] = nil
            if rooms[serverId]?.isEmpty == true { rooms[serverId] = nil }
        } else {
            rooms[serverId, default: [:]][channelId] = people
        }
        return true
    }

    /// Everyone in the server's voice room(s), in join order, without the people in `hidden`
    /// (blocked).
    func participants(serverId: String, hidden: Set<String> = []) -> [VoiceParticipant] {
        var seen = Set<String>()
        return (rooms[serverId] ?? [:]).keys.sorted().flatMap { rooms[serverId]?[$0] ?? [] }
            .sorted { ($0.joinedAt, $0.userId) < ($1.joinedAt, $1.userId) }
            .filter { !hidden.contains($0.userId) && seen.insert($0.userId).inserted }
    }

    /// How many are in the server's voice room(s) — the count shown while the list is collapsed.
    func count(serverId: String, hidden: Set<String> = []) -> Int { participants(serverId: serverId, hidden: hidden).count }

    /// The connection came back: rosters are handed again on subscribing; until then nothing
    /// stale is shown.
    mutating func reset() { rooms = [:] }

    /// "3 in voice" / nil for nobody — the collapsed row's count, spoken.
    static func countLabel(_ n: Int) -> String? { n > 0 ? "\(n) in voice" : nil }
}
