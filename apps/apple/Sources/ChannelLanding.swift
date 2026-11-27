import Foundation

// Build 51: choosing a server opens a channel. Decided here from what this device holds, with
// nothing to wait for between deciding and opening. Foundation only; ChannelLanding.kt is the twin.

/// The channel last opened in each server of one skwod on this device, as JSON in the skwod's
/// encrypted cache: which channels someone reads is nobody else's business.
struct ChannelMemory: Codable, Equatable {
    /// The server last used.
    var server: String?
    /// server id → channel id.
    var channels: [String: String] = [:]

    static func storageKey(workspaceId: String) -> String { "\(workspaceId)|channels.last" }

    mutating func opened(_ channel: String, in id: String) { server = id; channels[id] = channel }

    /// Left or gone: nothing about it is kept.
    mutating func forget(_ id: String) {
        channels[id] = nil
        if server == id { server = nil }
    }
}

/// A text channel in the list, in the order it shows. `readable`: the server has not refused this
/// account its messages.
struct LandingChannel: Equatable {
    var id: String
    var serverId: String
    var readable = true
}

/// When a channel opens by itself: only after the user picked its server (the rail, another skwod,
/// a join they started here) or at launch, and only while nothing is open. Nothing the host sends
/// opens or replaces anything.
struct Landing: Equatable {
    struct Want: Equatable {
        /// nil: the skwod as a whole (launch, another skwod).
        var server: String?
        /// iPhone: slide to the chat as well.
        var reveal = false
    }

    enum Place: Equatable {
        case open, loading, channel(String)
        /// No text channel there that the user may read.
        case empty(server: String)
        case noServers
        /// Nothing is open and nothing was asked for.
        case closed
    }

    private(set) var want: Want?
    /// The user opened this very channel (gates `channel_opened`: where it belongs, and so whose
    /// clear may empty this device's copy).
    private(set) var byUser = false

    /// The user picked a server or skwod (or the app starts).
    mutating func asked(_ want: Want) { self.want = want }
    /// They went elsewhere: their direct messages, the list of servers.
    mutating func left() { want = nil }
    mutating func opened() { want = nil; byUser = true }
    mutating func landed() { want = nil; byUser = false }
    /// A join ended and its channels are in the list. Decided later, or resumed: only listed.
    mutating func joined(_ server: String, startedHere: Bool, open: Bool) {
        if startedHere, !open { want = Want(server: server, reveal: true) }
        else if !startedHere, want?.server == nil { want = nil }
    }

    func place(open: Bool, ready: Bool, settingUp: Bool, memory: ChannelMemory, channels: [LandingChannel]) -> Place {
        if open { return .open }
        guard let want else { return .closed }
        guard ready else { return .loading }
        func channel(in server: String) -> String? {
            let usable = channels.filter { $0.serverId == server && $0.readable }
            return (usable.first { $0.id == memory.channels[server] } ?? usable.first)?.id
        }
        var servers: [String] = []
        for c in channels where !servers.contains(c.serverId) { servers.append(c.serverId) }
        if let last = memory.server, servers.contains(last) { servers = [last] + servers.filter { $0 != last } }
        // A server that was picked: that one or nothing, never another.
        if let server = want.server { servers = [server] }
        for server in servers { if let id = channel(in: server) { return .channel(id) } }
        if settingUp { return .loading }
        return servers.first.map { .empty(server: $0) } ?? .noServers
    }

    /// A composer's conversation: its view's identity, and what a send checks.
    static func conversationKey(workspaceId: String?, serverId: String, channelId: String) -> String {
        "\(workspaceId ?? "")|\(serverId)|\(channelId)"
    }
    static func maySend(composedIn: String?, now: String) -> Bool { composedIn == now }

    /// The server's answer to reading one channel was "not allowed" or "no such channel".
    static func isReadRefusal(_ detail: String) -> Bool {
        let d = detail.lowercased()
        return (d.contains("status 403") && d.contains("forbidden")) || d.contains("status 404")
    }

    static func mayCreateChannels(isOwner: Bool, permissions: Int64) -> Bool {
        isOwner || permissions & (1 | 8192) != 0   // manage channels, administrator
    }
}
