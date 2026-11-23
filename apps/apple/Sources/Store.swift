import SwiftUI

/// A message as the chat surface renders it. Real messages come from the E2EE client (decrypted
/// channel/DM history); this is the presentation shape they map into.
struct ChatMessage: Identifiable, Hashable {
    /// Stable id — the server message id for real messages, a fresh UUID for local/demo ones — so
    /// re-rendering a polled conversation doesn't churn identity.
    var id: String = UUID().uuidString
    var author: String
    /// The author's userId, for the E2EE avatar lookup (nil for local/demo/system rows).
    var authorId: String? = nil
    var body: String
    var mine: Bool = false
    /// Interactive reaction pills (emoji + count + whether I added it).
    var reactionPills: [ReactionPill] = []
    /// Unix-ms send time, for timestamps + sender grouping.
    var createdAt: Int64 = 0
    /// An E2EE file/photo/video/audio attachment (blob id + key carried in the encrypted body).
    var attachment: ChatAttachment? = nil
    /// A shared Apple Music song, rendered as a playable card.
    var music: MusicTrack? = nil
    /// This message replies to another (quoted reply) — the parent id + a rendered preview.
    var replyToId: String? = nil
    var replyPreview: String? = nil
    /// The author edited this after sending.
    var isEdited: Bool = false
    /// Deleted (tombstone) — rendered as "message deleted".
    var isDeleted: Bool = false
    /// Set for a security / membership event the app wrote into the conversation (not a message
    /// from anyone): rendered as a system line. `body` is its text.
    var system: SystemRow? = nil
    /// Mine and not delivered yet (`Outbox`): "Sending…" or "Not delivered" with Retry / Discard.
    var sendState: SendState? = nil

    /// Convenience for demo/preview rows that only need emoji reactions.
    var reactions: [String] {
        get { reactionPills.map(\.emoji) }
        set { reactionPills = newValue.map { ReactionPill(emoji: $0, count: 1, mine: false) } }
    }
}

/// One reaction group on a message: an emoji, how many reacted, and whether I did (for toggle).
struct ReactionPill: Identifiable, Hashable {
    var emoji: String
    var count: Int
    var mine: Bool
    var id: String { emoji }
}

/// The quick-react emoji row shown in a message's long-press menu (the default set).
let quickReactions = ["👍", "❤️", "😂", "🎉", "😮", "😢", "🔥", "🙏"]

/// How a system row (see `ChatMessage.system`) looks and what it offers.
struct SystemRow: Hashable {
    /// The core's event kind: `member_joined`, `device_added`, `member_held`, `identity_changed`, …
    var kind: String
    /// Who the event is about.
    var userId: String
    var icon: String
    /// Needs the user's attention / a decision (amber) rather than being a routine event.
    var warning: Bool = false
    var actionLabel: String? = nil
}
