import Foundation

/// Who may show as typing in the conversation on screen: the DM's peer, the group's members as
/// this device holds them, or the channel's server members. The host relays a `user_id` of its
/// choosing, so anyone else is dropped — and with no audience known yet, everyone is (fail closed).
struct TypingAudience: Equatable {
    /// The channel id, or the DM / group conversation id.
    var conversationId: String
    var members: Set<String>

    /// Is `userId` typing in `topic` ("channel:<id>" / "dm:<id>") someone this audience allows?
    static func accepts(userId: String, topic: String, audience: TypingAudience?) -> Bool {
        guard let audience, !audience.conversationId.isEmpty, let colon = topic.firstIndex(of: ":"),
              topic[topic.index(after: colon)...] == audience.conversationId else { return false }
        return audience.members.contains(userId)
    }
}

/// Typing indicators (build 46), Foundation only so the logic tests compile it.
///
/// The server relays `{"type":"typing","topic":…}` from a socket into that topic (one a second
/// per connection, only into topics it may read, never a blocked user's into a DM) as a `typing`
/// event with the typer's `user_id`. Like Signal, the setting gates BOTH directions: off, this
/// device neither sends nor shows them.
struct TypingState: Equatable {
    /// How long one event keeps someone "typing".
    static let lifetime: TimeInterval = 5
    /// The open conversation's topic, and who is typing there (user id → last event).
    private(set) var topic: String?
    private(set) var typers: [String: Date] = [:]

    /// The conversation on screen changed: what was typing elsewhere is not shown here.
    mutating func focus(_ topic: String?) {
        guard topic != self.topic else { return }
        self.topic = topic
        typers = [:]
    }

    /// A `typing` event. Ignored unless it is for the open conversation, from someone else who
    /// is not blocked and is one of that conversation's people (`TypingAudience`), with the
    /// setting on.
    mutating func received(userId: String, topic: String, me: String, blocked: Set<String>,
                           audience: TypingAudience?, enabled: Bool, now: Date) {
        guard enabled, !userId.isEmpty, userId != me, !blocked.contains(userId), topic == self.topic,
              TypingAudience.accepts(userId: userId, topic: topic, audience: audience) else { return }
        typers[userId] = now
        expire(now: now)
    }

    /// Their message arrived: they are no longer typing it.
    mutating func messageArrived(from userId: String) { typers[userId] = nil }

    mutating func expire(now: Date) {
        typers = typers.filter { now.timeIntervalSince($0.value) < Self.lifetime }
    }

    /// Who is typing now, oldest first (stable order on screen).
    func active(now: Date) -> [String] {
        typers.filter { now.timeIntervalSince($0.value) < Self.lifetime }
            .sorted { ($0.value, $0.key) < ($1.value, $1.key) }.map(\.key)
    }

    /// "Sam is typing…", "Sam and Robin are typing…", "Several people are typing…".
    static func text(_ names: [String]) -> String? {
        switch names.count {
        case 0: return nil
        case 1: return "\(names[0]) is typing…"
        case 2: return "\(names[0]) and \(names[1]) are typing…"
        case 3: return "\(names[0]), \(names[1]) and \(names[2]) are typing…"
        default: return "Several people are typing…"
        }
    }
}

/// When this device says it is typing: at most once every 3 s, only with something in the
/// composer, only with the setting on; never again for a draft that was just sent.
struct TypingSendThrottle {
    static let interval: TimeInterval = 3
    private var lastSent: Date?

    mutating func shouldSend(draft: String, enabled: Bool, now: Date) -> Bool {
        guard enabled, !draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return false }
        if let lastSent, now.timeIntervalSince(lastSent) < Self.interval { return false }
        lastSent = now
        return true
    }

    /// Sent or left the conversation: the next keystroke may say so again at once.
    mutating func reset() { lastSent = nil }
}

/// The setting ("Send typing indicators", on by default).
enum TypingSetting {
    static let key = "privacy.typingIndicators"
    static func isOn(_ defaults: UserDefaults = .standard) -> Bool {
        defaults.object(forKey: key) as? Bool ?? true
    }
}
