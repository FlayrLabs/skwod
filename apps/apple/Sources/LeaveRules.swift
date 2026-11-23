import Foundation

/// Build 47: leaving a server is authoritative on this device from the moment the user confirms.
///
/// Before, a server left the sidebar only after the host had answered the `DELETE` and the core
/// had forgotten its keys; and work already in flight at that moment (a channel listing, a
/// quiet discovery, a `/api/servers` read for membership recovery) could finish afterwards and
/// put it back until the next server-list refresh took it out again — the "flash back" of
/// about five seconds.
///
/// Now a TOMBSTONE is set when Leave is confirmed: the server's channels go at once, and every
/// path that adds channels asks `hides` first. The tombstone is
/// - `leaving` while the host has not answered: a refusal (or no connection) rolls it back
///   and the channels come back exactly where they were;
/// - `left` once the host confirmed (200, or 404 = not a member any more), or once the server
///   disappeared for another reason (deleted, removed, no longer listed). It stays until the
///   user joins that server again on purpose (`rejoined`), so a late answer to a request made
///   before the leave can never re-add it.
struct LeaveTombstones: Equatable {
    enum Mark: Equatable { case leaving, left }

    private(set) var marks: [String: Mark] = [:]

    /// Whether anything about `serverId` may be shown or added right now.
    func hides(_ serverId: String) -> Bool { marks[serverId] != nil }

    /// The user confirmed Leave. False when it is already being left (a second tap does nothing).
    @discardableResult
    mutating func begin(_ serverId: String) -> Bool {
        guard !serverId.isEmpty, marks[serverId] == nil else { return false }
        marks[serverId] = .leaving
        return true
    }

    /// The host confirmed the membership is gone.
    mutating func confirm(_ serverId: String) { if !serverId.isEmpty { marks[serverId] = .left } }

    /// The host refused, or could not be reached: the leave did not happen. Only a mark this
    /// leave set is lifted — a server that was meanwhile dropped for another reason stays out.
    /// Returns whether the channels should come back.
    @discardableResult
    mutating func failed(_ serverId: String) -> Bool {
        guard marks[serverId] == .leaving else { return false }
        marks[serverId] = nil
        return true
    }

    /// Servers gone for another reason (deleted, removed, no longer listed for this account).
    mutating func dropped(_ ids: Set<String>) { for id in ids where !id.isEmpty { marks[id] = .left } }

    /// The user joined this server (again) on purpose.
    mutating func rejoined(_ serverId: String) { marks[serverId] = nil }

    /// Put back what a failed leave took out, each where it was in `before`; whatever was
    /// added meanwhile stays, after them. `key` identifies an entry (a channel id).
    static func restore<T>(before: [T], now: [T], serverId: String, server: (T) -> String, key: (T) -> String) -> [T] {
        let nowKeys = Set(now.map(key))
        let beforeKeys = Set(before.map(key))
        let kept = before.filter { server($0) == serverId || nowKeys.contains(key($0)) }
        return kept + now.filter { !beforeKeys.contains(key($0)) }
    }
}
