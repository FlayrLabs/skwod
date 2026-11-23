import Foundation

/// What the app does, by itself, when a message arrives while it is running — and when one of
/// the user's own is accepted by the server. The whole rule in one place (Foundation only, so
/// it is unit-tested as shipped); `LiveSync` and `Outbox` only carry it out.
///
/// The shape is the familiar one: a chat you are looking at is silent; anything else makes one
/// sound — the app's own while it is in front, the system notification's when it is not —
/// never both, and never for a message that was already announced (`AnnouncedLedger`).
enum MessageAlert {
    struct Incoming {
        /// Written by this account (here or on another of its devices).
        var fromSelf = false
        /// The author is blocked.
        var blocked = false
        /// The conversation is muted or snoozed. (No build has such a setting yet: always
        /// false today — the rule is here so the setting only has to feed it.)
        var muted = false
        /// The user's own status is Do Not Disturb.
        var doNotDisturb = false
        /// The app is frontmost.
        var appActive = false
        /// The conversation is the one on screen (and the app is frontmost).
        var onScreen = false
        /// This process won the claim for the message id; false: something already announced it.
        var claimed = true
        /// Settings → "Sound for new messages".
        var soundOn = true
        /// When the app last played its received sound (seconds; 0 = never), and now.
        var lastSoundAt: TimeInterval = 0
        var now: TimeInterval = 0
    }

    struct Outcome: Equatable {
        /// Post a system notification (a banner; grouped by conversation).
        var banner = false
        /// …with the notification sound.
        var bannerSound = false
        /// Play the app's own received sound.
        var inAppSound = false

        static let nothing = Outcome()
    }

    /// At most one received sound per this many seconds, however many messages arrive.
    static let burst: TimeInterval = 1

    static func received(_ m: Incoming) -> Outcome {
        // Never: your own, a blocked person's, a muted conversation's, a second time.
        if m.fromSelf || m.blocked || m.muted || !m.claimed { return .nothing }
        // Do Not Disturb: it is there, unread, when you look. Nothing interrupts.
        if m.doNotDisturb { return .nothing }
        // The chat you are reading: you can see it arrive.
        if m.appActive && m.onScreen { return .nothing }
        if m.appActive {
            // In front, another chat: a (silent) banner says where; the app's own sound says
            // that — once per burst.
            let rested = m.lastSoundAt <= 0 || m.now < m.lastSoundAt || m.now - m.lastSoundAt >= burst
            return Outcome(banner: true, bannerSound: false, inAppSound: m.soundOn && rested)
        }
        // Not in front: the system notification is the alert, sound and all.
        return Outcome(banner: true, bannerSound: m.soundOn, inAppSound: false)
    }

    /// The sent sound: when the server ACCEPTED something the user composed (not on tap, and
    /// not for what the app sends by itself — likes, game moves, avatars). One per flush.
    static func sentSound(composedWaiting: Int, accepted: Int, soundOn: Bool) -> Bool {
        soundOn && composedWaiting > 0 && accepted > 0
    }
}

/// The two sound switches (Settings; on by default; this device only).
enum SoundSettings {
    private static let sentKey = "skwod.sound.sent"
    private static let receivedKey = "skwod.sound.received"

    static var sent: Bool {
        get { UserDefaults.standard.object(forKey: sentKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: sentKey) }
    }

    static var received: Bool {
        get { UserDefaults.standard.object(forKey: receivedKey) as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: receivedKey) }
    }
}

/// Where a tapped notification leads: the skwod and the conversation it was about.
struct NotificationTarget: Equatable {
    var workspaceId: String
    /// `channel:<id>` / `dm:<id>`.
    var scope: String

    static let workspaceKey = "skwod.workspace"
    static let scopeKey = "skwod.scope"

    var userInfo: [String: String] { [Self.workspaceKey: workspaceId, Self.scopeKey: scope] }

    /// From a notification's `userInfo` — only a well-formed target is followed.
    init?(userInfo: [AnyHashable: Any]) {
        guard let w = userInfo[Self.workspaceKey] as? String, !w.isEmpty,
              let s = userInfo[Self.scopeKey] as? String,
              s.hasPrefix("channel:") || s.hasPrefix("dm:"), s.count > 8, s.count < 200 else { return nil }
        workspaceId = w
        scope = s
    }

    init(workspaceId: String, scope: String) {
        self.workspaceId = workspaceId
        self.scope = scope
    }
}

/// Opaque stand-ins for a notification's target. With app lock on, or previews off, a
/// delivered notification must not carry which skwod and conversation it is about (it sits in
/// Notification Center, readable by whatever can list delivered notifications, and in
/// backups): it carries a random token instead, and the app — in memory only, for a day —
/// knows what the token stood for. A token it does not know (the app was restarted, or it
/// expired) just opens the app.
struct NotificationTokens {
    static let key = "skwod.token"
    static let lifetime: TimeInterval = 24 * 60 * 60
    static let limit = 200

    private var entries: [(token: String, target: NotificationTarget, at: TimeInterval)] = []

    /// What a notification about `target` may carry: the target itself, or — `redacted` —
    /// only a fresh token for it.
    mutating func userInfo(for target: NotificationTarget, redacted: Bool, now: TimeInterval,
                           random: () -> String = { UUID().uuidString }) -> [String: String] {
        guard redacted else { return target.userInfo }
        entries.removeAll { now - $0.at > Self.lifetime || now < $0.at }
        if entries.count >= Self.limit { entries.removeFirst(entries.count - Self.limit + 1) }
        let token = random()
        entries.append((token, target, now))
        return [Self.key: token]
    }

    /// A skwod's local data was deleted: no token of this run leads to it any more.
    mutating func forget(workspaceId: String) { entries.removeAll { $0.target.workspaceId == workspaceId } }

    /// The target a token stands for, if this process issued it and it has not expired.
    func resolve(_ token: String, now: TimeInterval) -> NotificationTarget? {
        guard !token.isEmpty, let hit = entries.last(where: { $0.token == token }),
              now >= hit.at, now - hit.at <= Self.lifetime else { return nil }
        return hit.target
    }
}

/// Everything a posted notification is made of, after the privacy rule — the ONE place the
/// rule is applied (`Realtime.notify` posts exactly this).
///
/// With app lock on, or previews off, nothing that names a skwod, server, channel or
/// conversation may be written into a delivered notification — not in its text, and not in
/// its request identifier, thread, or userInfo either (callers build those from ids:
/// `msg-<channel>`, `dm:<conversation>`, `join:<server>`…). Each such value is replaced by a
/// random stand-in that is stable for this run, so "a later notification about the same
/// thing replaces the earlier one" and grouping still work.
/// What a notification's text is made of — every caller of `Realtime.notify` has to say.
enum NotificationText {
    /// It names someone or something of the user's (a person, a channel, a skwod) or quotes
    /// a message: shown only with previews on and app lock off; "Skwod — New message" otherwise.
    case personal
    /// A sentence the app wrote that names nobody ("A new device is asking to join your
    /// account."): shown unless app lock is on.
    case fixed
}

struct NotificationShaper {
    struct Shape: Equatable {
        var title: String
        var body: String
        var thread: String
        var identifier: String
        var userInfo: [String: String]
    }

    private var standIns: [String: String] = [:]
    private(set) var tokens = NotificationTokens()

    /// The stand-in for `real` (made on first use, kept for the run).
    mutating func standIn(for real: String, random: () -> String = { UUID().uuidString }) -> String {
        if let known = standIns[real] { return known }
        let made = "skwod." + random()
        standIns[real] = made
        return made
    }

    /// The stand-in `real` already has, if any (to find delivered notifications again).
    func knownStandIn(for real: String) -> String? { standIns[real] }

    /// `appLock`: app lock is enabled. `previews`: the previews setting.
    mutating func shape(title: String, body: String, text: NotificationText, thread: String, identifier: String, target: NotificationTarget?,
                        appLock: Bool, previews: Bool, now: TimeInterval, random: () -> String = { UUID().uuidString }) -> Shape {
        let redacted = appLock || !previews
        guard redacted else {
            return Shape(title: title, body: body, thread: thread, identifier: identifier, userInfo: target?.userInfo ?? [:])
        }
        return Shape(
            // No more than that there is a message — under app lock always; with previews off
            // for anything that names someone or quotes something. Whatever the caller built.
            title: appLock || text == .personal ? "Skwod" : title,
            body: appLock || text == .personal ? "New message" : body,
            thread: appLock ? "skwod.locked" : standIn(for: "thread|" + thread, random: random),
            identifier: standIn(for: "id|" + identifier, random: random),
            userInfo: target.map { tokens.userInfo(for: $0, redacted: true, now: now, random: random) } ?? [:])
    }

    func target(forToken token: String, now: TimeInterval) -> NotificationTarget? { tokens.resolve(token, now: now) }

    mutating func forget(workspaceId: String) { tokens.forget(workspaceId: workspaceId) }
}
