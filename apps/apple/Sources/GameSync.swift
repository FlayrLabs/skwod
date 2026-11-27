import SwiftUI

/// Realtime, end-to-end-encrypted game state for in-channel games (chess, whiteboard).
///
/// Game moves ride the SAME Sender-Key channel path as chat: each update is a normal channel
/// message, tagged so the chat view hides it (like feed posts and attachments). Because it's the
/// proven E2EE channel, the server only ever sees ciphertext — it can't read the board or the
/// strokes — and delivery/cross-device sync are exactly what we hardened for chat.
///
/// "Realtime" is the live relay: a move is a channel message, the relay announces it to everyone
/// in the channel, and the open game view catches up at once (`GameSync.updates`). The server
/// cannot tell a move from any other message — it is the core, after decrypting, that files game
/// traffic in its own cache lane (`aux:<channel>`), so a busy board never pushes chat out of the
/// channel's history window and the games never have to sift through chat.

/// Body prefix for game traffic (\u{2} control char keeps it out of chat, same scheme as the feed).
let GAME_TAG = "\u{2}skwod/game|"

extension FeedTags {
    /// Game traffic is hidden from the conversation, just like feed/story posts.
    static func isGameContent(_ body: String) -> Bool { body.hasPrefix(GAME_TAG) }
}

/// One decoded game event off the channel, with the metadata needed to order + attribute it.
struct GameMessage<T: Decodable> {
    let id: String
    let authorId: String
    let createdAt: Int64
    let event: T
    /// True if we authored it (the core tags own messages "__me__").
    var mine: Bool { authorId == "__me__" }
}

/// Send + fetch E2EE game events on a channel. Thin wrapper over the channel message path.
@MainActor
struct GameSync {
    let app: AppState
    let channelId: String
    /// The skwod the channel is in: a move goes through its cache, or nowhere.
    let home: String?
    init(app: AppState, channelId: String) {
        self.app = app
        self.channelId = channelId
        home = app.chatModel?.spacesWorkspaceId
    }

    /// Encrypt + post a game event. Returns false when it could not be sent (the caller says
    /// so; the next sync reconciles state either way).
    @discardableResult
    func send<T: Encodable>(_ event: T) async -> Bool {
        guard let client = Outbox.client(of: home, app),
              let data = try? JSONEncoder().encode(event),
              let json = String(data: data, encoding: .utf8) else { return false }
        // Queued, like everything a person does: a move made while the connection is down is
        // delivered (once) when it is back, in the order it was made. False only when it could
        // not even be queued — which the caller shows.
        do {
            _ = try await client.queueChannelMessage(channelId: channelId, text: GAME_TAG + json, replyToId: nil, blobIds: [], uploadIds: [])
        } catch {
            return false
        }
        Outbox.kick(app)
        return true
    }

    /// Every game event on the channel we can decode as `T`, chronological — read from the
    /// game lane (`fetchAuxMessages`), not by filtering the chat history.
    func fetch<T: Decodable>(_ type: T.Type) async -> [GameMessage<T>] {
        guard let client = app.client, let me = app.session?.userId,
              let rows = try? await client.fetchAuxMessages(channelId: channelId, myUserId: me) else { return [] }
        var out: [GameMessage<T>] = []
        for m in rows {
            let content = m.content ?? ""
            guard content.hasPrefix(GAME_TAG),
                  let data = String(content.dropFirst(GAME_TAG.count)).data(using: .utf8),
                  let event = try? JSONDecoder().decode(T.self, from: data) else { continue }
            out.append(GameMessage(id: m.messageId, authorId: m.authorId ?? "", createdAt: m.createdAt, event: event))
        }
        return out.sorted { $0.createdAt < $1.createdAt }
    }

    /// Run `sync` now, then again every time the relay reports something in this channel or the
    /// connection comes back — and on a slow timer in case an event was lost. Returns when the
    /// surrounding task is cancelled (the game view went away). This replaces a 1-second poll.
    func updates(_ sync: @escaping @MainActor () async -> Void) async {
        let channelId = channelId
        await withTaskGroup(of: Void.self) { group in
            group.addTask { @MainActor in
                for await note in NotificationCenter.default.notifications(named: .skwodChannelChanged) {
                    if note.object as? String == channelId { await sync() }
                }
            }
            group.addTask { @MainActor in
                for await _ in NotificationCenter.default.notifications(named: .skwodLiveConnected) { await sync() }
            }
            group.addTask { @MainActor in
                while !Task.isCancelled {
                    await sync()
                    try? await Task.sleep(for: LiveSync.safetyInterval)
                }
            }
            await group.waitForAll()
        }
    }
}

// MARK: - Chess wire model

/// A full board snapshot — chess sends the whole state on each move (tiny, and last-write-wins by
/// `seq` makes the rare double-move race resolve deterministically). Seats carry real user ids so
/// each device knows which color it may move.
struct ChessSnapshot: Codable {
    var seq: Int
    var cells: [String]     // 64 entries row-major, "" empty or e.g. "wp","bk"
    var turn: String        // "white" | "black"
    var white: String?      // user id in the white seat (nil = open)
    var black: String?      // user id in the black seat (nil = open)
    /// Who produced this snapshot (the mover's user id) — a device-consistent tiebreak so two
    /// clients that reach the same `seq` from a simultaneous move converge on the SAME winner.
    var by: String?
}

// MARK: - Whiteboard wire model

/// A whiteboard event: an appended stroke, or a clear. Strokes are append-only and deduped by id;
/// a clear hides everything drawn before it. Points are normalized 0…1 so a sketch from a phone and
/// a Mac line up regardless of canvas size.
struct WhiteboardEvent: Codable {
    var kind: String            // "stroke" | "clear"
    var strokeId: String?
    var points: [[Double]]?     // [[x,y], …] normalized 0…1
    var colorIndex: Int?        // index into the shared palette
    var width: Double?
}
