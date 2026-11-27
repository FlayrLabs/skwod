import Foundation

/// Where this device last read a conversation up to: the newest message the reader had on screen
/// at the bottom of the list. Kept as id AND time, because the message itself may later be outside
/// the loaded page, or deleted — the time still says what is newer (Foundation only: the logic
/// tests compile it).
struct ReadMarker: Codable, Equatable {
    var messageId: String
    /// Unix ms (`ChatMessage.createdAt`).
    var createdAt: Int64
}

/// What the unread rules need to know about one row of a conversation.
struct UnreadItem: Equatable {
    var id: String
    var createdAt: Int64
    /// Sent by this account (never unread to its author).
    var mine: Bool
    /// A security / membership line the app wrote (not a message anyone sent).
    var system: Bool = false
}

/// "New since you last looked": the divider, the bar above the list, the jump pill, and where a
/// conversation opens. One rule for channels, DMs and groups.
enum UnreadRule {
    /// The encrypted-cache key a conversation's marker lives under (one skwod's cache, per
    /// conversation id).
    static func storageKey(workspaceId: String, conversationId: String) -> String {
        "\(workspaceId)|read.\(conversationId)"
    }

    /// Whether this row counts as something new to read.
    static func counts(_ item: UnreadItem) -> Bool { !item.mine && !item.system }

    /// The index of the first unread row, or nil when nothing is unread. No marker yet (never
    /// opened on this device) means nothing is unread: the conversation opens at the bottom.
    static func firstUnreadIndex(_ items: [UnreadItem], marker: ReadMarker?) -> Int? {
        guard let marker else { return nil }
        let start: Int
        if let at = items.firstIndex(where: { $0.id == marker.messageId }) {
            start = at + 1
        } else {
            // The marker's message isn't loaded (older than this page, or deleted): newer by time.
            start = items.firstIndex(where: { $0.createdAt > marker.createdAt }) ?? items.count
        }
        guard start < items.count else { return nil }
        // Anything I sent after the marker means I was here then: only what came after my last
        // message is new.
        let afterMine = items[start...].lastIndex(where: { $0.mine }).map { $0 + 1 } ?? start
        return items[afterMine...].firstIndex(where: counts)
    }

    /// Build 51: what was unread when the conversation was OPENED — against the marker as it was
    /// then, counting only rows written before that moment. Rows a catch-up brings in after the
    /// list was already showing (a cold launch opens on the cache first) were still written while
    /// the reader was away: they belong to the bar and the divider, not to "read on arrival".
    /// Returns the first such row's index and how many there are (nil: nothing).
    static func atOpen(_ items: [UnreadItem], markerAtOpen: ReadMarker?, openedAt: Int64) -> (first: Int, count: Int)? {
        let before = items.enumerated().filter { $0.element.createdAt <= openedAt }
        let rows = before.map(\.element)
        guard let first = firstUnreadIndex(rows, marker: markerAtOpen) else { return nil }
        return (before[first].offset, unreadCount(rows, marker: markerAtOpen))
    }

    /// How many rows are unread (from `firstUnreadIndex` on, mine and system lines excluded).
    static func unreadCount(_ items: [UnreadItem], marker: ReadMarker?) -> Int {
        guard let first = firstUnreadIndex(items, marker: marker) else { return 0 }
        return items[first...].filter(counts).count
    }

    /// The marker after reading up to `item`. Never moves backwards: an older row (a page loaded
    /// at the top, a late copy) leaves the marker where it is.
    static func advanced(_ marker: ReadMarker?, to item: UnreadItem) -> ReadMarker {
        let next = ReadMarker(messageId: item.id, createdAt: item.createdAt)
        guard let marker else { return next }
        return item.createdAt >= marker.createdAt ? next : marker
    }

    /// The marker for reading everything loaded (nil when there is nothing to read).
    static func readAll(_ items: [UnreadItem], marker: ReadMarker?) -> ReadMarker? {
        guard let last = items.last else { return marker }
        return advanced(marker, to: last)
    }

    /// Rows that arrived below the reader while they were scrolled up (the "↓ N new" pill): what
    /// counts after the last row they had on screen.
    static func newBelow(_ items: [UnreadItem], lastSeenId: String?) -> Int {
        guard let lastSeenId, let at = items.firstIndex(where: { $0.id == lastSeenId }) else { return 0 }
        return items[(at + 1)...].filter(counts).count
    }

    /// The line on the bar above the list: "3 new messages since 4:12 PM".
    static func barText(count: Int, since: Date, calendar: Calendar = .current, now: Date = Date()) -> String {
        let noun = count == 1 ? "new message" : "new messages"
        let f = DateFormatter()
        f.locale = Locale.current
        if calendar.isDate(since, inSameDayAs: now) {
            f.timeStyle = .short; f.dateStyle = .none
        } else {
            f.setLocalizedDateFormatFromTemplate("MMMd jmm")
        }
        return "\(count) \(noun) since \(f.string(from: since))"
    }
}
