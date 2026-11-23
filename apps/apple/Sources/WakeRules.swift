import Foundation

// What a contentless push wake may make this device do — decided before anything is dialed,
// opened or decrypted. Foundation only: the notification extension, the app and the logic
// tests compile this file (docs/PUSH.md).

/// Whose push a wake is, by the registration id the gateway put in it (`skwod_cred`) — decided
/// before its `tag` is even looked at (docs/PUSH.md, audit M1).
///
/// A wake for a wake credential carries the id of the registration it was minted for. This
/// install keeps the ids it registered (per skwod, dropped at sign-out, leave and erase), so a
/// wake naming one of them is from a skwod this install still registers with. A wake with no
/// id at all is a raw-token wake: from a skwod or gateway of build ≤ 44, or from a host that
/// kept the raw tokens of an earlier build and goes on using them after it was left. Build 45
/// hands no skwod raw tokens, so such a wake is not followed: never rung, never dialed — the
/// alert stays generic.
enum WakeOrigin: Equatable {
    /// Carries a registration id this install made.
    case registered
    /// Carries no registration id (the legacy raw-token shape).
    case raw
    /// Carries an id that is not one of ours, or something that is not an id.
    case stranger

    /// Does this build still follow raw-token wakes at all? `false` from build 45: nothing it
    /// registers is raw. Kept as a switch only so the tag rule below stays tested.
    static let followsRawWakes = false

    /// A registration this install made itself, as remembered for the PushKit handler and the
    /// notification extension (shared defaults, under `registrationIdsKey`).
    struct KnownId: Codable, Equatable {
        /// The workspace (skwod) it was made for.
        var workspace: String
        /// Unix seconds.
        var expiresAt: Int64
    }

    /// Where the ids live in the shared defaults. Not secret: every wake carries one.
    static let registrationIdsKey = "push.registrationIds"

    /// The ids in a stored list that are still ours: those that ran out more than a day ago
    /// are not. Unreadable data is no ids at all.
    static func knownIds(_ data: Data?, now: Int64) -> Set<String> {
        guard let data, let ids = try? JSONDecoder().decode([String: KnownId].self, from: data) else { return [] }
        return Set(ids.filter { $0.value.expiresAt + 86400 > now }.keys)
    }

    /// `credentialId`: the payload's `skwod_cred`, as it came (nil = the key is absent).
    static func of(credentialId: Any?, known: Set<String>) -> WakeOrigin {
        guard let credentialId else { return .raw }
        guard let id = credentialId as? String, !id.isEmpty, known.contains(id) else { return .stranger }
        return .registered
    }

    /// May this wake be treated as a signed-in skwod's — rung, or followed up by dialing it?
    /// A registered one: yes. A raw one: only while raw wakes are followed at all, and only
    /// with a tag one signed-in skwod owns (never untagged: an untagged raw wake could be
    /// anybody's). A stranger's: never.
    static func isOurs(_ origin: WakeOrigin, tag: String?, signedInTags: [String?], followRaw: Bool = WakeOrigin.followsRawWakes) -> Bool {
        switch origin {
        case .registered: return true
        case .stranger: return false
        case .raw:
            guard followRaw, let tag, !tag.isEmpty else { return false }
            return signedInTags.contains { $0 == tag }
        }
    }
}

/// Which skwods a wake is about, and whether it may interrupt.
///
/// A wake carries no content, only (when the install registered one) the opaque `tag` this
/// device chose for one skwod. The rules:
///
/// - **Whose wake.** A tag one signed-in skwod owns: that skwod alone. A tag nobody here owns:
///   nobody — it is not a wake this install asked any skwod for. No tag: only skwods that
///   never registered a tag (an install upgraded from a build before tags); once every skwod
///   has one, an untagged wake is nobody's. A wake that is nobody's is never a reason to dial
///   a host — someone who merely holds the push token cannot make the phone contact every
///   skwod — but it is not hidden either: the generic banner stays, with its sound.
/// - **A missed notification is worse than an extra one.** A wake goes quiet (the passive
///   line) only when EVERY skwod it could be from is muted as a whole. One muted candidate
///   among several does not silence the others; a mute that cannot be read is not a mute; and
///   a muted CONVERSATION never silences anything but itself, once a decrypted message is
///   known to be in it — where nothing may be decrypted (previews off, app lock on) the
///   skwod's banners stay audible.
/// - **Before the first unlock** after a restart nothing in the Keychain is readable, not even
///   which skwods there are. One time is kept readable for that case — until when EVERY
///   signed-in skwod is muted as a whole — and only while it runs is a wake quiet.
///
/// Every audible banner is still subject to the burst limit (`SoundBurst`).
enum WakeRule {
    struct Skwod: Equatable {
        var id: String
        var wakeTag: String?
    }

    enum Plan: Equatable {
        /// The passive "New activity" line: no banner, no sound. Nothing is dialed.
        case quiet
        /// The generic "New message" Apple delivered stays, with its sound; nothing is dialed
        /// or decrypted.
        case generic
        /// Sync and decrypt for these skwods (ids), in this order.
        case decrypt([String])
    }

    static func holds(_ until: TimeInterval?, now: TimeInterval) -> Bool {
        guard let until else { return false }
        return until == MuteList.forever || until > now
    }

    /// Until when EVERY one of these skwods is muted as a whole (`untils`: each skwod's own
    /// mute, nil = not muted): nil when there is none, or any of them is not muted now;
    /// `MuteList.forever` when all are muted without end; else the earliest end.
    static func everySkwodMutedUntil(_ untils: [TimeInterval?], now: TimeInterval) -> TimeInterval? {
        guard !untils.isEmpty, untils.allSatisfy({ holds($0, now: now) }) else { return nil }
        let finite = untils.compactMap { $0 }.filter { $0 != MuteList.forever }
        return finite.min() ?? MuteList.forever
    }

    /// The skwods a wake with this tag may be about (ids).
    static func candidates(tag: String?, signedIn: [Skwod]) -> [String] {
        let tag = tag ?? ""
        if !tag.isEmpty { return signedIn.first(where: { $0.wakeTag == tag }).map { [$0.id] } ?? [] }
        return signedIn.filter { ($0.wakeTag ?? "").isEmpty }.map(\.id)
    }

    /// - `signedIn`: the signed-in skwods, or nil when the list cannot be read (before the
    ///   first unlock, a build without the shared keychain group, a list that does not decode).
    /// - `everySkwodMutedUntil`: the one time kept readable before first unlock; nil = not all
    ///   muted.
    /// - `skwodMuted`: the skwod's own mute as stored; nil = unreadable, which is NOT a mute.
    /// - `mayDecrypt`: previews on AND app lock off.
    /// - `origin`: whose push it is by `skwod_cred` (`WakeOrigin`). One that is not ours is
    ///   shown generic and nothing is dialed, whatever its tag says.
    static func plan(tag: String?, origin: WakeOrigin = .registered, signedIn: [Skwod]?, everySkwodMutedUntil: TimeInterval?,
                     skwodMuted: (String) -> Bool?, mayDecrypt: Bool, now: TimeInterval,
                     followRaw: Bool = WakeOrigin.followsRawWakes) -> Plan {
        guard let signedIn else { return holds(everySkwodMutedUntil, now: now) ? .quiet : .generic }
        // Not a registration of this install (a host that was left, a stranger's credential, a
        // raw token kept from an earlier build): generic, never dialed (audit M1).
        guard WakeOrigin.isOurs(origin, tag: tag, signedInTags: signedIn.map(\.wakeTag), followRaw: followRaw) else { return .generic }
        // No skwod here, or skwods are here and this wake is none of theirs: shown, not dialed.
        let woken = candidates(tag: tag, signedIn: signedIn)
        guard !woken.isEmpty else { return .generic }
        let audible = woken.filter { skwodMuted($0) != true }
        // Quiet only when every skwod it could be from is muted.
        guard !audible.isEmpty else { return .quiet }
        guard mayDecrypt else { return .generic }
        // (A muted candidate among others is simply not looked at.)
        return .decrypt(audible)
    }

    /// What a wake ends in when no message could be shown. `unknown`: a skwod that is not
    /// muted could not be asked or did not answer (unreachable, out of time, its dial budget
    /// spent) — it may have a real message, so the generic banner stays, with its sound.
    /// Only when every skwod that was asked answered "nothing that needs you" is it quiet.
    static func withoutAMessage(unknown: Bool, onlyBackgroundTraffic: Bool) -> Plan {
        !unknown && onlyBackgroundTraffic ? .quiet : .generic
    }
}

/// How often a skwod's wakes may make the extension connect to its host. Every sync tells the
/// host this device's address and that it is reachable right now; a host that sends a wake
/// every few seconds while posting nothing would otherwise learn that continuously, with
/// nothing on screen. Past the budget the wake is not followed up: the generic banner stays.
enum WakeBudget {
    static let limit = 60
    static let window: TimeInterval = 3600

    /// `history`: when (unix seconds) this skwod's earlier wakes were followed up. Returns
    /// whether this one may be, and the history to store.
    static func spend(history: [TimeInterval], now: TimeInterval, limit: Int = WakeBudget.limit,
                      window: TimeInterval = WakeBudget.window) -> (allowed: Bool, history: [TimeInterval]) {
        // A clock that went backwards leaves entries "in the future": they count (never a way
        // to get more), and are dropped once the window has passed them by.
        let recent = history.filter { now - $0 < window }.suffix(limit * 2)
        guard recent.count < limit else { return (false, Array(recent)) }
        return (true, Array(recent) + [now])
    }
}

/// One wake, several new messages: which becomes the banner the push turns into, and which
/// are posted beside it. Every message a wake claims is shown — none is claimed and dropped.
enum WakePick {
    static let maxExtras = 8

    /// `ranks`: one per announceable message (`AnnounceWindow.rank`). The primary is the
    /// newest; the extras are the rest, newest first, up to `maxExtras` — what is beyond that
    /// is NOT claimed and is found again by the next wake.
    static func pick(ranks: [Int64], maxExtras: Int = WakePick.maxExtras) -> (primary: Int, extras: [Int])? {
        guard !ranks.isEmpty else { return nil }
        let order = ranks.indices.sorted { ranks[$0] != ranks[$1] ? ranks[$0] > ranks[$1] : $0 < $1 }
        return (order[0], Array(order.dropFirst().prefix(maxExtras)))
    }
}

/// Whether the conversation titles and sender sets the extension works from are kept at all:
/// only while it may decrypt for a banner. With app lock on or previews off it never reads
/// them, and a list of who the user talks to has no business being stored for nobody.
enum NotificationKeep {
    static func keepsConversationLabels(appLock: Bool, previews: Bool) -> Bool { !appLock && previews }
}

/// A call that gets a fixed time — and is LEFT when the time is up, whether or not it has
/// ended. A call into the core is not interrupted by cancelling its task, so waiting for it (as
/// a task group does) let one stalling host use the whole extension's time and left every
/// other skwod's messages generic. The call that is left behind is told so (`onAbandon`: it
/// must record and claim nothing from then on) and handed back as `lingering`, so the caller
/// can keep what the call holds (the cache lock) until it really has ended.
enum BoundedCall {
    struct Lingering {
        let task: Task<Void, Never>
        let isDone: () -> Bool
    }

    private final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        private var value: T?
        func set(_ v: T?) { lock.lock(); value = v; done = true; lock.unlock() }
        var isDone: Bool { lock.lock(); defer { lock.unlock() }; return done }
        var result: T? { lock.lock(); defer { lock.unlock() }; return value }
    }

    /// `shouldStop`: the caller wants out early (the app asked for the cache).
    static func run<T>(seconds: TimeInterval, shouldStop: @escaping () -> Bool = { false }, onAbandon: () -> Void,
                       pollNanoseconds: UInt64 = 50_000_000, _ op: @escaping () async -> T?) async -> (value: T?, lingering: Lingering?) {
        let box = Box<T>()
        let work = Task { box.set(await op()) }
        let deadline = Date().addingTimeInterval(seconds)
        while !box.isDone, Date() < deadline, !shouldStop(), !Task.isCancelled {
            try? await Task.sleep(nanoseconds: pollNanoseconds)
        }
        if box.isDone { return (box.result, nil) }
        onAbandon()
        work.cancel()
        return (nil, Lingering(task: work, isDone: { box.isDone }))
    }

    /// Give calls that were left behind until `deadline` to end. Returns the ones that have not.
    static func wait(for lingering: [Lingering], until deadline: Date, pollNanoseconds: UInt64 = 50_000_000) async -> [Lingering] {
        while Date() < deadline, lingering.contains(where: { !$0.isDone() }) {
            try? await Task.sleep(nanoseconds: pollNanoseconds)
        }
        return lingering.filter { !$0.isDone() }
    }
}
