import Foundation

// The two conversation stores (1:1 and group) and every rule about which of them owns a
// conversation id. Foundation only — no UI, no core bindings — so the unit tests compile this
// file by itself and drive the same code the app runs (Tests/ConversationStoreTests.swift).

struct DMConversation: Identifiable, Hashable, Codable {
    var id = UUID()
    var name: String
    var peerUserId: String
    var peerDeviceId: String
    var conversationId: String
    /// The user started this conversation on this device (nil in entries stored before the
    /// field existed). How far the NAME is trusted lives in the contact book, not here.
    var startedHere: Bool? = nil
    /// Does this entry CLAIM its conversation id? Only something the user did makes a claim
    /// (starting the chat, writing in it). `false` = made by something that arrived or was
    /// listed: it routes its own events, but it does not keep a group from being accepted
    /// under the same id. Absent = stored before the field existed, which counts as claimed.
    var claimed: Bool? = nil
    var isClaimed: Bool { claimed ?? true }
}

/// Group direct messages: 3–10 people, every message sealed separately to every device of every
/// member (no shared group key, no server-side group state beyond who is in the conversation).
///
/// WHO IS IN A GROUP is decided on this device, once: the people the user picked when starting
/// it, or the people shown when they accepted it. That set is stored here (in the encrypted
/// cache) and is the only set messages are sealed to. The server's listing of a conversation
/// is never adopted — a server that adds someone to a conversation would otherwise get every
/// member to encrypt to its ghost. A listing that differs is flagged and ignored; a group this
/// device has never seen is an INVITATION the user accepts (seeing its members) or not; and
/// changing who is in a group means starting a new one.
///
/// Trust and names follow the 1:1 rules. A group has no name of its own — its title is its
/// members as THIS device names them (the contact book: verified, known, or "(unverified)"),
/// never a name the server supplies. Who a message is sealed to is the member list the user
/// sees on this screen; a `DmEvent` only ever updates the group it names and never creates a
/// 1:1 conversation for its sender.
struct GroupDM: Identifiable, Hashable, Codable {
    var conversationId: String
    /// Everyone in the group except this account.
    var memberUserIds: [String]
    /// The members' names as the server listed them when this device first saw the group —
    /// claims only, shown through the contact book's rules.
    var claimedNames: [String: String] = [:]
    /// The server now lists different people for this conversation than the set this device
    /// holds. Shown as a warning; the set is NOT changed.
    var serverDisagrees: Bool? = nil
    /// Invitations only, never stored: this conversation may be a group the user HAD joined —
    /// the list that would say so could not be read (`ConversationStore.Review`). It is shown
    /// as "review this group", not as a fresh invitation.
    var needsReview: Bool? = nil
    var id: String { conversationId }

    private enum CodingKeys: String, CodingKey { case conversationId, memberUserIds, claimedNames, serverDisagrees }

    init(conversationId: String, memberUserIds: [String], claimedNames: [String: String] = [:], serverDisagrees: Bool? = nil) {
        self.conversationId = conversationId
        self.memberUserIds = memberUserIds
        self.claimedNames = claimedNames
        self.serverDisagrees = serverDisagrees
    }

    /// Only the id and the members are required of a stored group: a missing `claimedNames`
    /// is "no names heard", never a reason to call the whole list unreadable.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        conversationId = try c.decode(String.self, forKey: .conversationId)
        memberUserIds = try c.decode([String].self, forKey: .memberUserIds)
        claimedNames = try c.decodeIfPresent([String: String].self, forKey: .claimedNames) ?? [:]
        serverDisagrees = try c.decodeIfPresent(Bool.self, forKey: .serverDisagrees)
    }

    /// Fold the server's listing into what this device holds — WITHOUT ever changing an
    /// accepted group's members, and without touching anything this device already claimed.
    ///
    /// A conversation id belongs to whichever store this device put it in FIRST by its own
    /// action — a direct conversation (`direct`: the CLAIMED ones) or an accepted group. A
    /// listing can never create an entry for an id the other store holds, nor delete or modify
    /// a held entry: such an id is reported in `conflicts` and nothing changes. Returns the
    /// accepted groups (flagged where a listing differs), the listed conversations this device
    /// has not accepted (invitations; `declined` ids left out; marked `needsReview` when they
    /// may be a group whose stored entry was lost — `reviewGroups`, `reviewAll`; none at all
    /// for an id that was a lost DIRECT entry — `lostDirect`), and the conflicting ids. An id
    /// the server lists more than once makes one invitation (its first listing) and one
    /// conflict; an accepted group is flagged if ANY of its listings differs.
    static func reconcile(accepted: [GroupDM], listed: [(conversationId: String, memberUserIds: [String])],
                          declined: Set<String> = [], direct: Set<String> = [],
                          lostDirect: Set<String> = [], reviewGroups: Set<String> = [], reviewAll: Bool = false)
        -> (accepted: [GroupDM], invitations: [GroupDM], conflicts: [String]) {
        var kept = accepted
        var invitations: [GroupDM] = []
        var conflicts: [String] = []
        var flagged: Set<String> = []
        var seen: Set<String> = []
        for l in listed {
            let first = seen.insert(l.conversationId).inserted
            if let i = kept.firstIndex(where: { $0.conversationId == l.conversationId }) {
                if Set(kept[i].memberUserIds) != Set(l.memberUserIds) { flagged.insert(l.conversationId) }
                kept[i].serverDisagrees = flagged.contains(l.conversationId)
            } else if !first {
                continue
            } else if direct.contains(l.conversationId) {
                // Held as a direct conversation: the listing does not get to make it a group.
                conflicts.append(l.conversationId)
            } else if lostDirect.contains(l.conversationId) {
                // Was a direct conversation in a list that could not be fully read: no listing
                // makes it a group. (Not a conflict to report — nothing is held to compare.)
                continue
            } else if !declined.contains(l.conversationId), sizeProblem(others: Set(l.memberUserIds).count) == nil {
                var invitation = GroupDM(conversationId: l.conversationId, memberUserIds: l.memberUserIds)
                if reviewAll || reviewGroups.contains(l.conversationId) { invitation.needsReview = true }
                invitations.append(invitation)
            }
        }
        return (kept, invitations, conflicts)
    }

    static let maxOthers = 9
    static let minOthers = 2

    /// Why a group of `others` other people cannot be started (nil = it can).
    static func sizeProblem(others: Int) -> String? {
        if others < minOthers { return "Pick at least 2 people — a group is 3 to 10 people." }
        if others > maxOthers { return "A group can have at most 10 people, including you." }
        return nil
    }

    /// Does something `senderId` did in this group count? Only this account and the members
    /// this device holds for the group can post, edit, delete or react in it. Anyone else —
    /// however well authenticated as themselves, and whatever the server says about who is in
    /// the conversation — is outside the group: nothing of theirs is shown, redrawn or notified.
    func accepts(senderId: String, fromSelf: Bool) -> Bool {
        fromSelf || memberUserIds.contains(senderId)
    }

    /// Where an event for `conversationId` belongs: with whichever store holds the id (an
    /// accepted group, or a direct conversation); failing that a group the user said to ignore
    /// (nothing of it is shown), an invitation, or unknown.
    enum Route: Equatable { case group, direct, declined, invitation, unknown }

    static func route(conversationId: String, direct: Set<String>, accepted: Set<String>, invitations: Set<String>,
                      declined: Set<String> = []) -> Route {
        if accepted.contains(conversationId) { return .group }
        if direct.contains(conversationId) { return .direct }
        if declined.contains(conversationId) { return .declined }
        if invitations.contains(conversationId) { return .invitation }
        return .unknown
    }

    /// May a store take `conversationId`? Only when the OTHER store has not claimed it. First
    /// come, first served; a clash changes neither store.
    static func mayClaim(_ conversationId: String, heldByOtherStore other: Set<String>) -> Bool {
        !other.contains(conversationId)
    }

    /// The members' names joined; past `limit` names, "+n".
    static func title(memberNames: [String], limit: Int = 4) -> String {
        guard memberNames.count > limit else { return memberNames.joined(separator: ", ") }
        return memberNames.prefix(limit).joined(separator: ", ") + " +\(memberNames.count - limit)"
    }
}

/// Whose rows the notification extension may announce under a conversation's title. The app
/// writes this next to the titles (shared defaults, on-device only): for a 1:1 conversation
/// its peer(s), for a group the members this device holds. The extension has no other way to
/// know who is in a group — without this it would announce a ghost's text as the group's.
enum NotificationSenders {
    /// `"dm:<id>"` → the accounts whose rows may be announced there. A direct conversation
    /// has exactly ONE such account — the peer of the entry that holds the id
    /// (`ConversationStore.holders`) — so nobody else's text can appear under that peer's
    /// name. A group's set wins over a direct entry under the same id (an accepted group
    /// routes first).
    ///
    /// `silent`: conversation ids of which the app shows nothing — an invitation, an ignored
    /// group, a conversation held before whose entry was lost. A direct entry that exists
    /// under such an id gets NO senders, so the extension announces nothing there either.
    static func allowed(dms: [DMConversation], groups: [GroupDM], silent: Set<String> = []) -> [String: [String]] {
        var out: [String: [String]] = [:]
        for d in ConversationStore.holders(dms) where !d.peerUserId.isEmpty {
            out["dm:\(d.conversationId)"] = silent.contains(d.conversationId) ? [] : [d.peerUserId]
        }
        for g in groups { out["dm:\(g.conversationId)"] = g.memberUserIds }
        return out
    }

    /// May a row by `authorId` in `scope` be announced with its content? Channels are not
    /// decided here. A DM scope needs the author to be one of its `senders`; when the app has
    /// never written the sets (`senders == nil`, e.g. right after an update) nobody is — the
    /// caller then leaves the generic banner in place.
    static func mayAnnounce(scope: String, authorId: String?, senders: [String: [String]]?) -> Bool {
        guard scope.hasPrefix("dm:") else { return true }
        guard let authorId, let allowed = senders?[scope] else { return false }
        return allowed.contains(authorId)
    }
}

/// What the notification extension does with a wake, decided from what it could read. One
/// rule: the QUIET line ("New activity": passive — no banner, no sound, no screen wake) is
/// only for a wake that was positively about nothing the user needs to see. Anything it
/// could not read, could not check or is not sure about keeps the visible "New message".
/// (Build 44 said "quiet" whenever nothing was announceable — also when a channel could not
/// be fetched, a new row could not be decrypted, or a group member was not in the sender
/// set yet: real messages arrived with no banner and no screen wake.)
enum NotificationDecision {
    /// One new row from someone else, as the extension read it (already without deleted and
    /// system rows, the user's own, and anything from a blocked account).
    struct Row: Equatable {
        var messageId: String
        var authorId: String?
        /// A placeholder for a message this device could not decrypt. (The app itself does not
        /// notify for these while it runs; a wake that is about one still says "New message"
        /// once, rather than nothing.)
        var unreadable = false
        /// The core's rule (`messageNotifies`): chat, a post, an attachment — not a like, a
        /// comment, an avatar, a game move.
        var notifies = true
    }

    /// What one conversation's new rows come to.
    struct Scan: Equatable {
        /// Index (into the rows given) of the newest row that may be shown under the title.
        var announce: Int?
        /// Something here may be a real message and cannot be shown: keep "New message".
        var unsure = false
        /// The rows that made it unsure. The visible banner this wake ends in is their
        /// notification: the caller records them (`AnnouncedLedger`), or every later wake —
        /// a like, the trailing wake of a burst — would find them again and be a banner too.
        var unsureIds: [String] = []
    }

    enum Verdict: Equatable { case announce, generic, quiet }

    /// `rows`: oldest first, nil when the conversation could not be read at all.
    /// `announced`: message ids either process already notified about (`AnnouncedLedger`).
    static func scan(scope: String, rows: [Row]?, senders: [String: [String]]?, announced: Set<String> = []) -> Scan {
        guard let rows else { return Scan(unsure: true) }
        var out = Scan()
        // A conversation the app shows nothing of (an invitation, an ignored or declined
        // group — its sender set is there and empty): nothing in it is ever a banner, not
        // even "New message" for ciphertext that could not be read. Decided first.
        if scope.hasPrefix("dm:"), senders?[scope]?.isEmpty == true { return Scan() }
        for (i, row) in rows.enumerated() where !announced.contains(row.messageId) {
            if row.unreadable { out.unsure = true; out.unsureIds.append(row.messageId); continue }
            guard row.notifies else { continue }
            guard scope.hasPrefix("dm:") else { out.announce = i; continue }
            // The app has never written the sender sets, or not for this conversation: who
            // wrote this cannot be checked.
            guard let allowed = senders?[scope] else { out.unsure = true; out.unsureIds.append(row.messageId); continue }
            if let author = row.authorId, allowed.contains(author) {
                out.announce = i
            } else {
                // Not (yet) a member as this device holds the conversation: never shown
                // under its title, and not waved through as "nothing" either.
                out.unsure = true
                out.unsureIds.append(row.messageId)
            }
        }
        return out
    }

    /// The whole wake. `complete`: every conversation was looked at (not cut short by the
    /// time budget or by the app asking for the cache).
    static func verdict(announces: Bool, unsure: Bool, lookedAtAny: Bool, complete: Bool) -> Verdict {
        if announces { return .announce }
        return (lookedAtAny && complete && !unsure) ? .quiet : .generic
    }
}

/// Which keychain class each stored secret gets — decided here (Foundation only, tested as
/// shipped), carried out by `Keychain`.
///
/// `afterFirstUnlock` (readable while the screen is locked, once the device has been unlocked
/// after boot) is given ONLY where something has to read the item on a locked phone:
///
/// - the workspace list (addresses and session tokens): as in every build so far — a call
///   push that starts the app on a locked phone must be able to ask the skwod who is ringing;
/// - a cache key: only on iOS, and only while the notification extension is actually allowed
///   to decrypt for a banner — app lock off AND previews on. On macOS there is no extension;
///   with app lock on it never opens the cache; with previews off it shows nothing decrypted.
///   In all of those the key stays `whenUnlocked`, as it was in build 44.
///
/// Everything else is `whenUnlocked`. Both classes are `ThisDeviceOnly`; nothing is `Always`.
enum KeyAccess {
    enum Class: Equatable { case whenUnlocked, afterFirstUnlock }
    enum Platform { case iOS, macOS }

    struct Settings: Equatable {
        /// App lock is enabled.
        var appLock: Bool
        /// "Show message text in notifications".
        var previews: Bool
    }

    /// What the notification extension is told about a skwod's conversations — their titles
    /// and whose rows may be announced under them (`NotificationState`). It reads them only
    /// where it decrypts, so they follow the cache key's rule (and are not kept at all while
    /// app lock is on or previews are off).
    static let notifNamesPrefix = "notif-names-"
    static let notifSendersPrefix = "notif-senders-"
    static func followsCacheKey(_ account: String) -> Bool {
        account.hasPrefix(cacheKeyPrefix) || account.hasPrefix(mutesPrefix)
            || account.hasPrefix(notifNamesPrefix) || account.hasPrefix(notifSendersPrefix)
    }

    static let workspaces = "workspaces"
    static let cacheKeyPrefix = "cache-key-"
    /// Which conversations of a skwod are muted (`MuteList`): read by the extension only
    /// where it decrypts — the cache key's rule.
    static let mutesPrefix = "mutes-"
    /// Until when a whole skwod is muted (a time, nothing else): the extension needs it for
    /// every wake on iOS — also with app lock on — to make that skwod's banners passive.
    static let skwodMutePrefix = "mute-skwod-"

    /// Where the skwod's host was last reached directly (`DirectRoutes`).
    static let routesPrefix = "routes-"

    static func accessibility(for account: String, settings: Settings, platform: Platform) -> Class {
        if account == workspaces { return .afterFirstUnlock }
        if followsCacheKey(account) {
            return platform == .iOS && !settings.appLock && settings.previews ? .afterFirstUnlock : .whenUnlocked
        }
        if account.hasPrefix(skwodMutePrefix) { return platform == .iOS ? .afterFirstUnlock : .whenUnlocked }
        return .whenUnlocked
    }

    /// Every prefix under which an item is kept per skwod — add a new one HERE: this is the
    /// list a skwod's items are deleted by (`WorkspaceItems`).
    static let perWorkspacePrefixes = [cacheKeyPrefix, mutesPrefix, skwodMutePrefix, notifNamesPrefix, notifSendersPrefix, routesPrefix, retiredMuteConvsPrefix]
    /// A per-skwod flag an unreleased build-45 state kept ("has a muted conversation",
    /// `MuteFlagStore`). Nothing reads it; a wipe deletes whatever is left of it.
    static let retiredMuteConvsPrefix = "mute-convs-"

    /// The items whose class follows the settings (re-classified when they change).
    static func moves(_ account: String) -> Bool { followsCacheKey(account) }

    /// Does a change of settings move any item to another class (so the stored items have to
    /// be re-classified)? Only the cache keys ever move.
    static func cacheKeysMove(from old: Settings, to new: Settings, platform: Platform) -> Bool {
        accessibility(for: cacheKeyPrefix, settings: old, platform: platform) != accessibility(for: cacheKeyPrefix, settings: new, platform: platform)
    }
}

/// Everything this device keeps PER SKWOD outside the cache file and the workspace record —
/// the ONE list every path that deletes a skwod's local data goes through (erase this device,
/// forget a signed-out skwod, account deleted, factory reset: `AppState.deleteLocalData`).
/// An item that is stored under a workspace id belongs here, built from these prefixes, so a
/// wipe cannot miss it (the mutes of build 45 were kept in the Keychain after an erase).
enum WorkspaceItems {
    /// "This device was removed from the account" (shown until acknowledged).
    static let removedDevicePrefix = "skwod.removedDevice."
    /// The host's upload limit as last learned (`UploadLimit`).
    static let uploadLimitPrefix = "skwod.uploadLimit."
    /// What the notification extension is told about a skwod (`NotificationState`: names,
    /// senders, the seen mark, the announced-id ledger) — "notif.<workspace>.<what>".
    static func sharedDefaultsPrefix(_ workspaceId: String) -> String { "notif.\(workspaceId)." }
    /// When a banner last sounded, by conversation / wake tag (`NotificationState.bannerSounds`):
    /// not kept per skwod, short-lived, and names conversations — dropped whole with any skwod.
    static let soundLedgerKey = "notif.soundAt"

    /// The Keychain accounts of one skwod: the cache key, which conversations are muted and
    /// until when the skwod itself is.
    static var keychainPrefixes: [String] { KeyAccess.perWorkspacePrefixes }
    static func keychainAccounts(_ workspaceId: String) -> [String] { keychainPrefixes.map { $0 + workspaceId } }

    /// The app's own defaults of one skwod.
    static let defaultsPrefixes = [removedDevicePrefix, uploadLimitPrefix]
    static func defaultsKeys(_ workspaceId: String) -> [String] { defaultsPrefixes.map { $0 + workspaceId } }

    /// Delete all of it. `deleteSecret` is `Keychain.delete` in the app (a fake in tests);
    /// `shared` the defaults the extension reads.
    static func wipe(workspaceId: String, deleteSecret: (String) -> Void, defaults: UserDefaults, shared: UserDefaults) {
        guard !workspaceId.isEmpty else { return }
        for account in keychainAccounts(workspaceId) { deleteSecret(account) }
        for key in defaultsKeys(workspaceId) { defaults.removeObject(forKey: key) }
        let prefix = sharedDefaultsPrefix(workspaceId)
        for key in shared.dictionaryRepresentation().keys where key.hasPrefix(prefix) { shared.removeObject(forKey: key) }
        shared.removeObject(forKey: soundLedgerKey)
    }
}

/// What the user muted in ONE skwod, on this device: conversations (`channel:<id>` /
/// `dm:<id>`) and the skwod as a whole — for an hour, eight, a day, or until unmuted. Never
/// sent anywhere. A mute that has run out simply stops counting (and is dropped on the next
/// change).
struct MuteList: Equatable {
    enum Duration: CaseIterable, Equatable {
        case hour, eightHours, day, forever

        var seconds: TimeInterval? {
            switch self {
            case .hour: return 3600
            case .eightHours: return 8 * 3600
            case .day: return 24 * 3600
            case .forever: return nil
            }
        }

        var label: String {
            switch self {
            case .hour: return "For 1 hour"
            case .eightHours: return "For 8 hours"
            case .day: return "For 24 hours"
            case .forever: return "Until I turn it back on"
            }
        }
    }

    /// The key under which the whole skwod is muted.
    static let skwod = "skwod"
    /// `until` of a mute with no end.
    static let forever: TimeInterval = -1

    /// key → when the mute ends (unix seconds), or `forever`.
    private(set) var until: [String: TimeInterval] = [:]

    init(until: [String: TimeInterval] = [:]) { self.until = until }

    mutating func mute(_ key: String, for duration: Duration, now: TimeInterval) {
        guard !key.isEmpty else { return }
        until = until.filter { Self.holds($0.value, now: now) }
        until[key] = duration.seconds.map { now + $0 } ?? Self.forever
    }

    mutating func unmute(_ key: String) { until[key] = nil }

    private static func holds(_ until: TimeInterval, now: TimeInterval) -> Bool { until == forever || until > now }

    /// Is exactly this key muted right now?
    func holds(_ key: String, now: TimeInterval) -> Bool { until[key].map { Self.holds($0, now: now) } ?? false }

    /// Is a message in `scope` muted — the conversation itself, or the whole skwod?
    func isMuted(scope: String, now: TimeInterval) -> Bool { holds(scope, now: now) || holds(Self.skwod, now: now) }

    /// Does a call ring? A muted conversation does not silence calls; a muted skwod does.
    func callsRing(now: TimeInterval) -> Bool { !holds(Self.skwod, now: now) }

    /// Is a contentless wake (a message or a call push) for muted skwods only? `tag` is the
    /// push's opaque wake tag, when it carries one: it names the skwod that asked for the wake,
    /// and then only that skwod's mute counts. Without one (or with one no skwod here owns) the
    /// wake could be from any signed-in skwod, so it is quiet only when ALL of them are muted.
    /// With no skwod signed in — or the list unreadable (before the first unlock) — it is not.
    static func wakeIsMuted(tag: String?, signedIn: [(id: String, wakeTag: String?)], skwodIsMuted: (String) -> Bool) -> Bool {
        let owner = signedIn.first(where: { !(tag ?? "").isEmpty && $0.wakeTag == tag })
        let woken = owner.map { [$0] } ?? signedIn
        return !woken.isEmpty && woken.allSatisfy { skwodIsMuted($0.id) }
    }

    /// The conversation mutes alone / the skwod mute alone (they are stored apart: `KeyAccess`).
    var conversations: [String: TimeInterval] { until.filter { $0.key != Self.skwod } }
    var skwodUntil: TimeInterval? { until[Self.skwod] }
}

/// Banner sounds are coalesced only within a short burst: at most one per conversation per
/// five seconds (a banner that cannot say which conversation — app lock on, or the phone not
/// yet unlocked since boot — counts per skwod). A message in ANOTHER conversation always
/// sounds; so does the next message in the same one a few seconds later. (A wake that is
/// known to be about nothing new — a like, the trailing wake of a burst — never reaches this:
/// it is the passive line.)
enum SoundBurst {
    static let window: TimeInterval = 5

    /// `lastSoundAt`: when a banner under the same key last made a sound (0 = never).
    static func sounds(lastSoundAt: TimeInterval, now: TimeInterval, window: TimeInterval = SoundBurst.window) -> Bool {
        lastSoundAt <= 0 || now < lastSoundAt || now - lastSoundAt >= window
    }
}

/// iOS: what to tell the server about being in front (`Realtime.sendPushState`) as the scene
/// changes. "Background" makes the server push every message, so it is said when the app
/// really is away — at once on background and on screen lock, after a grace when merely
/// inactive (Control Center, the app switcher, a Face ID sheet come and go in less) — and not
/// at all during a call, which keeps the process and its socket running.
enum PushPresence {
    enum Phase { case active, inactive, background, locked }
    enum Action: Equatable { case active, background, backgroundAfter(TimeInterval), keep }

    static let inactiveGrace: TimeInterval = 1.5

    static func onPhase(_ phase: Phase, inCall: Bool) -> Action {
        switch phase {
        case .active: return .active
        case _ where inCall: return .keep
        case .inactive: return .backgroundAfter(inactiveGrace)
        case .background, .locked: return .background
        }
    }
}

/// Message ids a notification was already made for — by the app (its own banner, or the chat
/// was on screen) or by the extension — kept in the shared defaults so a push wake that races
/// an in-app delivery, or a second wake for the same message, never announces it twice.
enum AnnouncedLedger {
    static let limit = 300
    /// Ids a wake could not show (undecryptable, a sender nobody vouched for) and that its
    /// generic banner stood for. Kept in a list of their OWN: anyone can post rows that do not
    /// decrypt, and in the announced ledger 300 of them would push out the ids of real
    /// messages — which a server could then serve again and have announced as new.
    static let unsureLimit = 300

    /// The check and the write as ONE step (the caller holds a cross-process lock around
    /// it): which of `ids` nobody has announced yet, and the ledger with them added. Two
    /// processes asking about the same message get it exactly once between them.
    static func claim(_ ids: [String], in existing: [String], limit: Int = AnnouncedLedger.limit) -> (claimed: [String], ledger: [String]) {
        let seen = Set(existing)
        var fresh: [String] = []
        for id in ids where !id.isEmpty && !seen.contains(id) && !fresh.contains(id) { fresh.append(id) }
        return (fresh, adding(fresh, to: existing, limit: limit))
    }

    /// `existing` with `ids` appended (newest last), without repeats, cut to `limit`.
    static func adding(_ ids: [String], to existing: [String], limit: Int = AnnouncedLedger.limit) -> [String] {
        var seen = Set(existing)
        var out = existing
        for id in ids where !id.isEmpty && seen.insert(id).inserted { out.append(id) }
        return out.count > limit ? Array(out.suffix(limit)) : out
    }
}

/// The title the notification extension shows for a direct conversation. The app writes it to
/// the shared defaults; the extension has no contact book and shows it as it is. So it is never
/// a name the SERVER supplied: only a name this device trusts for the peer — and only for a
/// conversation the user made their own.
enum NotificationTitles {
    /// Shown instead of a name. (The conversation keeps its key in the titles, so the extension
    /// still looks in it — it only does not say who.)
    static let generic = "New message"

    /// `trustedName`: what the contact book shows for the peer, and non-nil ONLY when the book
    /// was read for this workspace and the name carries no marker (known or verified). An entry
    /// something listed or delivered (`claimed == false`), an unverified, unconfirmed or
    /// look-alike name, or a book that is not read: the generic title.
    static func direct(isClaimed: Bool, trustedName: String?) -> String {
        guard isClaimed, let trustedName, !trustedName.isEmpty else { return generic }
        return trustedName
    }
}

/// A conversation as the server lists it — claims from an untrusted party.
struct ListedDM: Equatable {
    var conversationId: String
    var peerUserId: String
    var peerUsername: String
}

/// A core client together with the workspace whose cache it has open — ONE value, so "which
/// client" and "whose" are never taken from two things that change at different moments.
struct BoundClient<Client> {
    let workspaceId: String
    let client: Client
    /// Does this client have the workspace's encrypted cache OPEN? A client can be up without
    /// it (no key right now, the notification extension holds the lock, the file would not
    /// open): it can ask the server things, but there is nothing to read the stores from and
    /// nowhere to write them. "No cache" is never "an empty cache".
    var cacheOpen = true
    /// The bind turn that put this client up (`ClientBinding`). A new turn is a new client:
    /// whatever was (or could not be) read through an earlier one is read again.
    var turn = 0
    /// Whether this client's server pin was applied.
    var pin = PinState.unchecked

    /// The client to use for `workspaceId`: only the one bound to exactly that workspace.
    /// Throws otherwise (none, or another workspace's) — a store then reads nothing and writes
    /// nothing; it never uses whichever client happens to be there.
    static func of(_ bound: BoundClient<Client>?, for workspaceId: String) throws -> Client {
        guard let bound, bound.workspaceId == workspaceId else { throw ConversationError.notReady }
        return bound.client
    }

    /// The client to read or write `workspaceId`'s cache through: bound to exactly that
    /// workspace AND with the cache open. Throws otherwise — the stores then stay unread
    /// (gate shut) and unsaved changes stay pending.
    static func withCache(_ bound: BoundClient<Client>?, for workspaceId: String) throws -> Client {
        guard let bound, bound.workspaceId == workspaceId, bound.cacheOpen else { throw ConversationError.notReady }
        return bound.client
    }
}

/// The one place a workspace's client is put up and taken down. Binding a client takes several
/// suspensions (the key, the cross-process lock, opening the cache), and a second bind — or a
/// sign-out — can start during any of them. Each bind therefore holds a TURN: `commit` puts a
/// client up only for the turn that is still the latest, and always under the workspace id the
/// caller itself captured — never one read from state another bind may have changed since.
final class ClientBinding<Client> {
    private(set) var bound: BoundClient<Client>? { didSet { onChange?() } }
    private var turn = 0
    /// Build 51: told whenever a client is put up or taken down (screens that read from the
    /// client reload from the new one — what a push-woken extension wrote is in ITS cache).
    var onChange: (() -> Void)?

    /// The pin of the client that is up could not be applied (again).
    func failPin() { bound?.pin = .failed }
    /// The client that is up is used another way from now on (it went online): a new turn, so that
    /// screens read and catch up through it again. Nil: none is up.
    @discardableResult func renew() -> Int? {
        guard var same = bound else { return nil }
        turn += 1
        same.turn = turn
        bound = same
        return turn
    }
    /// Start a bind (or take the client down): nothing is bound, and every earlier turn is over.
    @discardableResult func begin() -> Int { turn += 1; bound = nil; return turn }
    /// Is `turn` still the latest? Asked after every suspension; a bind that is not stops,
    /// discards its client and assigns nothing.
    func isCurrent(_ turn: Int) -> Bool { turn == self.turn }
    /// Put `client` up as `workspaceId`'s — unless this turn was superseded (false: nothing changed).
    /// `cacheOpen`: whether THIS bind opened the workspace's cache on the client.
    func commit(_ turn: Int, workspaceId: String, client: Client, cacheOpen: Bool, pin: PinState = .unchecked) -> Bool {
        guard turn == self.turn else { return false }
        bound = BoundClient(workspaceId: workspaceId, client: client, cacheOpen: cacheOpen, turn: turn, pin: pin)
        return true
    }
}

/// What was current when a server call was made: the workspace, the bind turn of the client
/// that was asked, and the store of that workspace. Whatever the call brings back — a batch of
/// DM events, a listing — belongs to THAT workspace only. A server that holds its answer while
/// the user switches workspaces must not get it decided in (or announced by) the other
/// workspace: the answer is used only while the same three are still current, and it is given
/// to the store that was captured, never to "the store" read again afterwards.
@MainActor
struct StoreTicket {
    let workspaceId: String
    let turn: Int
    let store: ConversationStore

    /// nil when there is nothing to decide in: no client bound, or the store is not that
    /// workspace's (mid-switch).
    init?(boundWorkspaceId: String?, turn: Int?, store: ConversationStore?) {
        guard let boundWorkspaceId, let turn, let store, store.workspaceId == boundWorkspaceId else { return nil }
        self.workspaceId = boundWorkspaceId
        self.turn = turn
        self.store = store
    }

    /// Still the same workspace, the same client and the same store?
    func isCurrent(boundWorkspaceId: String?, turn: Int?, store: ConversationStore?) -> Bool {
        boundWorkspaceId == workspaceId && turn == self.turn && store === self.store
    }
}

/// What the stores need from the core. `kvGet`/`kvSet` THROW when this workspace's cache is
/// not there to be read or written (nil means only "nothing stored"). Everything else is the
/// SERVER's word.
@MainActor
protocol ConversationBackend: AnyObject {
    func kvGet(key: String) async throws -> String?
    func kvSet(key: String, value: String) async throws
    func listDms() async throws -> [ListedDM]
    /// Each listed group with its OTHER members: the core leaves this account out of what it
    /// lists (`list_group_dms` drops a conversation this account is not in, then removes it
    /// from the members). Same on Android, which filters once more on its side
    /// (`GroupRules.others`) — so both platforms compare and store the same set.
    func listGroupDms() async throws -> [(conversationId: String, memberUserIds: [String])]
    /// The account a username leads to in the directory.
    func findUserId(username: String) async throws -> String
    func openGroupDm(memberUserIds: [String]) async throws -> String
}

enum ConversationError: Error, Equatable {
    /// The stores have not been read (or could not be): nothing may be decided yet.
    case notReady
    /// The id is held by the other store, or by a group with other people.
    case conflict
}

/// The 1:1 and group stores of ONE workspace, and the only code that changes them.
///
/// THE RULE. A conversation id belongs to whichever store this device put it in first BY THE
/// USER'S OWN ACTION: starting or writing in a direct conversation; starting or accepting a
/// group. Nothing server-driven (a listing, a delivery, an answer to "open") creates an entry
/// in the other store for a claimed id, or deletes, changes, hides or re-routes a claimed
/// entry. On a clash neither store changes, the owner keeps routing, the conflicting data is
/// dropped and it is said once (ever — the "said" set is stored).
///
/// HOW IT IS KEPT.
/// - Nothing server-driven does anything until BOTH stores (and the ignored groups, and the
///   "said" set) have been read from the cache: `ready`. A store that cannot be read keeps the
///   gate shut — it is never treated as empty.
/// - Every change is a synchronous step on the main actor that re-checks the rule against
///   the stores as they are at that moment. No decision made before an `await` is written
///   after it.
/// - Each store is written by one writer that always saves the latest state, so two saves can
///   never land out of order.
@MainActor
final class ConversationStore {
    enum Notice: Equatable {
        /// The server described a held conversation both as direct and as a group.
        case conflict(conversationId: String)
        /// Someone outside an accepted group's members sent something to it.
        case outsider(conversationId: String)
        /// A direct conversation bound to one account was described (listed, delivered into,
        /// or answered to "open") as being with a DIFFERENT account.
        case otherPeer(conversationId: String)
        /// A stored list could not be decoded. Its bytes were kept under `keptAs` (nothing is
        /// deleted) and the list starts again empty.
        case unreadable(list: String, keptAs: String)
        /// The 1:1 list held more than one entry under one conversation id (an earlier build
        /// stored them). It was reduced to one entry per id; the list as it was is kept
        /// under `keptAs`.
        case duplicates(keptAs: String)

        var key: String {
            switch self {
            case .conflict(let id): return "conflict-\(id)"
            case .outsider(let id): return "outsider-\(id)"
            case .otherPeer(let id): return "peer-\(id)"
            case .unreadable(_, let keptAs): return "unreadable-\(keptAs)"
            case .duplicates(let keptAs): return "duplicates-\(keptAs)"
            }
        }
    }

    private(set) var dms: [DMConversation] = []
    /// Accepted groups, each with the member set this device fixed for it.
    private(set) var groups: [GroupDM] = []
    /// Listed group conversations this device has not accepted.
    private(set) var invitations: [GroupDM] = []
    /// Groups the user said to ignore.
    private(set) var declined: Set<String> = []
    /// Notices already said (oldest first), so each is said once across launches.
    private(set) var noticed: [String] = []
    /// Both stores were read from the cache. Until then nothing server-driven changes anything.
    private(set) var ready = false

    /// Called around every change of `dms`, `groups` or `invitations`.
    var willChange: (() -> Void)?
    var didChange: (() -> Void)?
    /// A notice to put in Security activity. Called at most once per notice per launch, and —
    /// once the receiver has reported it stored (`stored(_:)`) — never again.
    var onNotice: ((Notice) -> Void)?
    /// Notices handed to `onNotice` in this launch (not stored anywhere).
    private var saidNow: Set<String> = []
    /// Names this device has heard for people, to show a group's members with (claims). The
    /// owner answers for THIS store's workspace only (its client, its lists) — or with nothing.
    var nameHints: (() async -> [String: String])?

    private weak var backend: ConversationBackend?
    /// The workspace these stores belong to ("" for the placeholder shown between workspaces).
    let workspaceId: String
    static let noticedLimit = 1000

    /// This account. A listing never counts it among a group's OTHER members (the core leaves
    /// it out already; this makes nothing depend on that — as on Android, `GroupRules.others`).
    let me: String?

    init(backend: ConversationBackend?, workspaceId: String, me: String? = nil) {
        self.backend = backend
        self.workspaceId = workspaceId
        self.me = me
    }

    /// The OTHER members of a listing: this account left out, each account once, order kept.
    nonisolated static func others(_ ids: [String], me: String?) -> [String] {
        var seen: Set<String> = []
        return ids.filter { $0 != me && !$0.isEmpty && seen.insert($0).inserted }
    }

    // MARK: Reading

    func group(for conversationId: String) -> GroupDM? { groups.first { $0.conversationId == conversationId } }

    /// Ids a direct conversation CLAIMS (the user started it or wrote in it).
    var claimedDirectIds: Set<String> { Set(dms.filter(\.isClaimed).map(\.conversationId)) }
    private var groupIds: Set<String> { Set(groups.map(\.conversationId)) }

    /// One entry per conversation id: a direct conversation is bound to ONE peer account.
    /// Among several entries under one id (earlier builds could store them) the holder is the
    /// one the USER made: started here before anything else, then one that claims the id
    /// before one that does not (a server-listed entry never outranks the user's own), and
    /// otherwise the oldest — entries are inserted at the front, so the LAST. Order is kept.
    nonisolated static func holders(_ dms: [DMConversation]) -> [DMConversation] {
        func rank(_ d: DMConversation) -> Int { (d.startedHere == true ? 2 : 0) + (d.isClaimed ? 1 : 0) }
        var holder: [String: Int] = [:]
        for (i, d) in dms.enumerated() {
            if let h = holder[d.conversationId], rank(dms[h]) > rank(d) { continue }
            holder[d.conversationId] = i
        }
        return dms.enumerated().filter { holder[$0.element.conversationId] == $0.offset }.map(\.element)
    }

    /// The entry holding `conversationId` in the 1:1 store, whoever it is with.
    private func holder(of conversationId: String) -> DMConversation? { dms.first { $0.conversationId == conversationId } }

    /// Where an event for `conversationId` belongs, from what this device holds. An entry that
    /// exists keeps routing its own events, claimed or not.
    func route(_ conversationId: String) -> GroupDM.Route {
        GroupDM.route(conversationId: conversationId, direct: Set(dms.map(\.conversationId)), accepted: groupIds,
                      invitations: Set(invitations.map(\.conversationId)), declined: declined)
    }

    /// What a DM event that arrived in a conversation is to this device.
    enum EventPlace: Equatable {
        /// An accepted group (as this device holds it).
        case group(GroupDM)
        /// A group this device has not accepted: "there is an invitation", nothing of its content.
        case invitation
        /// A direct conversation (held, or not known to be anything else after asking).
        case direct
        /// Nothing may be shown, listed or announced: a group the user ignored, or the stores
        /// are not read yet, or the groups could not be asked about an unknown conversation.
        case nothing
    }

    /// Where an event that arrived belongs. `mark` is `listingMark()` taken when its batch
    /// arrived: a conversation this device does not know is looked up among the account's
    /// groups first — ONE listing for the whole batch, however many unknown ids it names — and
    /// if that cannot be asked, the event is held back rather than filed as 1:1.
    func place(ofEventIn conversationId: String, since mark: Int) async -> EventPlace {
        guard ready else { return .nothing }
        var route = self.route(conversationId)
        if route == .unknown {
            guard await groupsListed(since: mark) else { return .nothing }
            route = self.route(conversationId)
        }
        switch route {
        case .group: return group(for: conversationId).map { .group($0) } ?? .nothing
        case .invitation: return .invitation
        case .declined: return .nothing
        case .direct, .unknown: return .direct
        }
    }

    /// What is done with ONE decrypted DM event — the whole decision the app's event handler
    /// acts on, so that nothing is shown, redrawn or announced that the stores did not accept.
    enum Verdict: Equatable {
        /// Nothing of it is shown, redrawn or announced.
        case drop
        /// In an accepted group, from this account or one of the group's stored members.
        case group(GroupDM)
        /// In a group this device has not accepted: "there is an invitation", none of its content.
        case invitation
        /// Direct, listed with exactly this sender. `name`: the entry's claimed name.
        case direct(name: String, isNew: Bool)
    }

    /// Decide about an event from `senderId` in `conversationId` (`place`, then the rules of
    /// the place): in an accepted group only this account and the STORED members count —
    /// anyone else's event is dropped and said once; a direct event counts only if the store
    /// lists the conversation with exactly this sender (`deliverDM`) — not when a group, an
    /// invitation or an ignored group has the id, nor when it is held with another account.
    ///
    /// `isGroup` is the core's word for the conversation (`DmEvent.is_group`, build 45): sealed
    /// by the sender inside the ciphertext and fixed on this device at first use — not the
    /// server's. A group-marked event is never filed as direct, and a bare (1:1) one never in a
    /// group or an invitation. A group-marked event under an id a direct entry holds makes that
    /// entry give way only if nothing of the user's made it (unclaimed, audit A16); a claimed
    /// direct conversation keeps its id and the event is dropped (and said once). `nil`: no
    /// marker known (a build-44 event), decided by the stores alone as before.
    func decide(conversationId: String, senderId: String, fromSelf: Bool, since mark: Int, isGroup: Bool? = nil) async -> Verdict {
        if isGroup == true, ready, holder(of: conversationId) != nil {
            guard yieldUnclaimedDirect(conversationId) else {
                notice(.conflict(conversationId: conversationId))
                return .drop
            }
        }
        switch await place(ofEventIn: conversationId, since: mark) {
        case .nothing:
            return .drop
        case .group(let held):
            guard isGroup != false else { return .drop }
            guard held.accepts(senderId: senderId, fromSelf: fromSelf) else {
                notice(.outsider(conversationId: conversationId))
                return .drop
            }
            return .group(held)
        case .invitation:
            guard isGroup != false else { return .drop }
            return .invitation
        case .direct:
            // A group's message is never shown as a 1:1 — not even when no listing names the
            // group yet (it stays in the cache and shows once the group is listed and joined).
            guard isGroup != true else { return .drop }
            guard let delivered = await deliverDM(conversationId: conversationId, peerUserId: senderId) else { return .drop }
            return .direct(name: delivered.name, isNew: delivered.isNew)
        }
    }

    /// Audit A16: the core fixed `conversationId` as a GROUP. Direct entries under it give way
    /// when none of them is the user's (unclaimed: listed or delivered, never started or written
    /// in here) — returns true, and the id is free for the group. A claimed entry stays, and
    /// nothing is removed: returns false.
    private func yieldUnclaimedDirect(_ conversationId: String) -> Bool {
        let under = dms.filter { $0.conversationId == conversationId }
        guard !under.isEmpty else { return true }
        guard !under.contains(where: \.isClaimed) else { return false }
        change { dms.removeAll { $0.conversationId == conversationId } }
        save(.dms)
        return true
    }

    /// Ids of which nothing is shown or announced, even where a direct entry exists under
    /// them: invitations, ignored groups, conversations whose entry was lost (`Review`).
    var silentIds: Set<String> { declined.union(invitations.map(\.conversationId)).union(review.direct).union(review.group) }

    // MARK: Loading

    private enum Slot: Hashable { case dms, groups, declined, noticed, review }

    /// Conversation ids this device HELD but whose stored entries could not be read back (a
    /// list was undecodable, in part or whole). Nothing is known about them any more except
    /// that they were not new — so nothing server-driven may re-create them as if they were:
    /// - `direct`: was a direct entry. No listing or delivery makes a direct entry for it, and
    ///   no listing makes it a group invitation; the user opening that chat again clears it.
    /// - `group`: was an accepted group. No direct entry is made for it; a listing shows it as
    ///   "review this group" (never a plain invitation); joining or ignoring it clears it.
    /// - `allGroups`: the groups (or ignored-groups) list could not be read AT ALL, so no ids
    ///   were recovered: every listed group this device has not accepted is shown as "review".
    /// - `allDirect`: the same for the DIRECT list — not one id of it was recovered, so every
    ///   direct conversation this device held is forgotten, claims and all. While it is set
    ///   nothing that arrives or is listed makes a direct entry (the user opening a chat still
    ///   does), and every listed group is shown as "review": one of them may sit under the id
    ///   of a direct conversation the user had.
    /// `allGroups` and `allDirect` stand until the USER says they have seen it (`clearReview`).
    struct Review: Codable, Equatable {
        var direct: Set<String> = []
        var group: Set<String> = []
        var allGroups = false
        var allDirect = false
        /// Nothing listed can be told from something this device held.
        var all: Bool { allGroups || allDirect }

        init() {}
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            direct = try c.decodeIfPresent(Set<String>.self, forKey: .direct) ?? []
            group = try c.decodeIfPresent(Set<String>.self, forKey: .group) ?? []
            allGroups = try c.decodeIfPresent(Bool.self, forKey: .allGroups) ?? false
            allDirect = try c.decodeIfPresent(Bool.self, forKey: .allDirect) ?? false
        }
        func holds(_ conversationId: String) -> Bool { direct.contains(conversationId) || group.contains(conversationId) }
    }
    private(set) var review = Review()

    /// What can still be read of a list that does not decode as a whole: the elements that
    /// decode by themselves, the conversation ids of those that do not, and whether it was a
    /// JSON array at all.
    nonisolated static func salvage<T: Decodable>(_ json: String, as: T.Type = T.self) -> (items: [T], lostIds: [String], isArray: Bool) {
        guard let top = try? JSONSerialization.jsonObject(with: Data(json.utf8), options: [.fragmentsAllowed]), let elements = top as? [Any] else { return ([], [], false) }
        var items: [T] = [], lost: [String] = []
        for element in elements {
            if let plain = element as? T, !(element is [String: Any]) { items.append(plain); continue }
            if JSONSerialization.isValidJSONObject(element), let data = try? JSONSerialization.data(withJSONObject: element),
               let item = try? JSONDecoder().decode(T.self, from: data) { items.append(item); continue }
            if let id = (element as? [String: Any])?["conversationId"] as? String, !id.isEmpty { lost.append(id) }
        }
        return (items, lost, true)
    }

    private func key(_ slot: Slot) -> String {
        switch slot {
        case .dms: return "\(workspaceId)|sidebar.dms"
        case .groups: return "sidebar.groups"
        case .declined: return "groups.declined"
        case .noticed: return "\(workspaceId)|security.noticed"
        case .review: return "\(workspaceId)|conversations.review"
        }
    }

    /// nil = unreadable. Only an absent (or empty) value means "none".
    private static func decodeList<T: Decodable>(_ json: String?) -> [T]? {
        guard let json, !json.isEmpty else { return [] }
        return try? JSONDecoder().decode([T].self, from: Data(json.utf8))
    }

    private var loading: Task<Bool, Never>?

    private func name(_ slot: Slot) -> String {
        switch slot {
        case .dms: return "direct conversations"
        case .groups: return "groups"
        case .declined: return "ignored groups"
        case .noticed: return "notices"
        case .review: return "conversations to review"
        }
    }

    /// Milliseconds now — part of a kept copy's key, so one copy never overwrites another.
    var clock: () -> Int64 = { Int64(Date().timeIntervalSince1970 * 1000) }

    /// Read both stores, the ignored groups and the "said" set from the encrypted cache — no
    /// network. Returns whether the stores are usable.
    ///
    /// - A cache that cannot be READ (no cache open, a failed read) leaves the gate shut and is
    ///   read again by the next caller. It is never taken for an empty store.
    /// - A stored list that is read but cannot be DECODED would otherwise keep the gate shut
    ///   for good. In this order, each step only after the one before is certainly written:
    ///   1. its bytes are copied, as they are, under a key of their own
    ///      (`<key>.unreadable.<ms>`, read back — nothing is deleted);
    ///   2. what can still be read is salvaged element by element, and the conversation id of
    ///      every element that cannot is recorded (`Review`) — so nothing server-driven
    ///      re-creates a conversation this device held as if it were new, and a group the user
    ///      had joined does not come back as a plain invitation with the server's members;
    ///   3. the list continues with the salvaged entries, and it is said (`Notice.unreadable`).
    ///   If a copy or the record cannot be written, the gate stays shut.
    /// - More than one entry under one conversation id (earlier builds) is reduced to the
    ///   holder — after the list as it was has been copied (`<key>.duplicates.<ms>`), and said.
    @discardableResult
    func load() async -> Bool {
        if ready { return true }
        if let loading { return await loading.value }
        let task = Task { @MainActor [weak self] () -> Bool in
            guard let self else { return false }
            let ok = await self.read()
            self.loading = nil
            // Counted, so the owner can SAY that the conversations cannot be read (and offer to
            // try again) instead of showing an empty list for ever.
            let failures = ok ? 0 : self.loadFailures + 1
            if failures != self.loadFailures { self.change { self.loadFailures = failures } }
            return ok
        }
        loading = task
        return await task.value
    }

    /// How many times in a row `load` could not make the stores usable (0 once it has).
    private(set) var loadFailures = 0

    private func read() async -> Bool {
        do {
            guard let backend = self.backend else { return false }
            var raw: [Slot: String?] = [:]
            do {
                for slot in [Slot.dms, .groups, .declined, .review] { raw[slot] = try await backend.kvGet(key: self.key(slot)) }
            } catch { return false }
            // The "said" set is a convenience: unreadable only means a notice may repeat.
            let said: [String] = Self.decodeList((try? await backend.kvGet(key: self.key(.noticed))) ?? nil) ?? []

            /// Copy a slot's bytes under a key of their own; non-nil only once they read back.
            /// ONE copy per distinct content: the key of the last copy is remembered
            /// (`<key>.latest.<kind>`), and when that copy already holds exactly these bytes it
            /// is the copy — a load that fails further on and is tried again (and again) does
            /// not fill the cache with the same bytes under a new key each time.
            @MainActor func keep(_ slot: Slot, as kind: String) async -> String? {
                guard let bytes = raw[slot] ?? nil else { return nil }
                let pointer = "\(self.key(slot)).latest.\(kind)"
                do {
                    if let last = try await backend.kvGet(key: pointer), !last.isEmpty, try await backend.kvGet(key: last) == bytes { return last }
                    let side = "\(self.key(slot)).\(kind).\(self.clock())"
                    try await backend.kvSet(key: side, value: bytes)
                    guard try await backend.kvGet(key: side) == bytes else { return nil }
                    // (If this is not written the copy is still there; the next try makes another.)
                    try? await backend.kvSet(key: pointer, value: side)
                    return side
                } catch { return nil }
            }

            var review = Review()
            var kept: [(slot: Slot, key: String)] = []
            if let json = raw[.review] ?? nil, !json.isEmpty {
                if let stored = try? JSONDecoder().decode(Review.self, from: Data(json.utf8)) {
                    review = stored
                } else {
                    // The record itself is unreadable: which ids it held is not known, so
                    // every listed group is one to review and nothing listed becomes direct.
                    guard let side = await keep(.review, as: "unreadable") else { return false }
                    kept.append((.review, side))
                    review.allGroups = true
                    review.allDirect = true
                }
            }
            var d: [DMConversation]? = Self.decodeList(raw[.dms] ?? nil)
            var g: [GroupDM]? = Self.decodeList(raw[.groups] ?? nil)
            var ignored: [String]? = Self.decodeList(raw[.declined] ?? nil)
            if d == nil {
                guard let side = await keep(.dms, as: "unreadable") else { return false }
                kept.append((.dms, side))
                let saved: (items: [DMConversation], lostIds: [String], isArray: Bool) = Self.salvage((raw[.dms] ?? nil) ?? "")
                d = saved.items
                review.direct.formUnion(saved.lostIds)
                // Not a list at all: no id was recovered, every direct claim is forgotten.
                if !saved.isArray { review.allDirect = true }
            }
            if g == nil {
                guard let side = await keep(.groups, as: "unreadable") else { return false }
                kept.append((.groups, side))
                let saved: (items: [GroupDM], lostIds: [String], isArray: Bool) = Self.salvage((raw[.groups] ?? nil) ?? "")
                g = saved.items
                review.group.formUnion(saved.lostIds)
                if !saved.isArray { review.allGroups = true }
            }
            if ignored == nil {
                guard let side = await keep(.declined, as: "unreadable") else { return false }
                kept.append((.declined, side))
                let saved: (items: [String], lostIds: [String], isArray: Bool) = Self.salvage((raw[.declined] ?? nil) ?? "")
                ignored = saved.items
                // Which groups the user said to ignore is not known any more: what is listed
                // is shown for review, not as a fresh invitation.
                if !saved.isArray { review.allGroups = true }
            }
            // An id that survived in one of the lists is not lost.
            let alive = Set((d ?? []).map(\.conversationId)).union((g ?? []).map(\.conversationId))
            review.direct.subtract(alive); review.group.subtract(alive)
            // The record is written BEFORE any salvaged list replaces an original.
            if !kept.isEmpty {
                guard let data = try? JSONEncoder().encode(review), let json = String(data: data, encoding: .utf8) else { return false }
                do {
                    try await backend.kvSet(key: self.key(.review), value: json)
                    guard try await backend.kvGet(key: self.key(.review)) == json else { return false }
                } catch { return false }
            }
            // Earlier builds could store a second entry, for another account, under an id
            // already held. One id, one peer: the holder stays. The list as it was is kept.
            let held = Self.holders(d ?? [])
            var duplicatesKeptAs: String?
            if held.count != (d ?? []).count, !kept.contains(where: { $0.slot == .dms }) {
                guard let side = await keep(.dms, as: "duplicates") else { return false }
                duplicatesKeptAs = side
            }
            guard !self.ready else { return true }
            self.change {
                self.dms = held
                self.groups = g ?? []
                self.invitations = []
                self.declined = Set(ignored ?? [])
                self.noticed = said
                self.review = review
                self.ready = true
            }
            if held.count != (d ?? []).count { self.save(.dms) }
            for (slot, side) in kept {
                // The list is written again (what was salvaged), so the next launch reads a
                // list and not the same undecodable bytes; the kept copy stays where it is.
                self.save(slot)
                self.notice(.unreadable(list: self.name(slot), keptAs: side))
            }
            if let duplicatesKeptAs { self.notice(.duplicates(keptAs: duplicatesKeptAs)) }
            return true
        }
    }

    private func change(_ body: () -> Void) {
        willChange?()
        body()
        didChange?()
    }

    // MARK: Saving (one writer per store, always the latest state)

    private var dirty: Set<Slot> = []
    private var writer: Task<Void, Never>?
    /// The slot the writer is writing right now: no longer in `dirty`, not yet known written.
    private var writing: Slot?

    private func save(_ slot: Slot) {
        dirty.insert(slot)
        guard writer == nil else { return }
        writer = Task { @MainActor [weak self] in
            while let self, let backend = self.backend, let next = self.dirty.popFirst() {
                // Encoded when it is written, not when it was asked for: a later change that
                // was already made is in this write, and nothing older can overwrite it.
                guard let json = self.encoded(next) else { continue }
                self.writing = next
                do { try await backend.kvSet(key: self.key(next), value: json) } catch {
                    // Not written (this workspace's cache is not open right now): still to
                    // be saved, by the next save or `flush`.
                    self.writing = nil
                    self.dirty.insert(next)
                    break
                }
                self.writing = nil
            }
            self?.writer = nil
        }
    }

    private func encoded(_ slot: Slot) -> String? {
        let data: Data?
        switch slot {
        case .dms: data = try? JSONEncoder().encode(dms)
        case .groups: data = try? JSONEncoder().encode(groups)
        case .declined: data = try? JSONEncoder().encode(declined.sorted())
        case .noticed: data = try? JSONEncoder().encode(noticed)
        case .review: data = try? JSONEncoder().encode(review)
        }
        return data.flatMap { String(data: $0, encoding: .utf8) }
    }

    /// Is something still to be written? (A write waits while this workspace's cache is not open.)
    var hasUnsaved: Bool { !dirty.isEmpty || writer != nil }

    /// Everything still to be written, as (key, value) pairs — and it is no longer pending
    /// here. For the one moment the store cannot write by itself any more: its client is about
    /// to be taken down by something that cannot wait (sign-out), and the caller writes these
    /// through that client before letting go of it.
    ///
    /// A slot that is being written at this very moment is included: its write may not land
    /// before the client is gone, and it may carry less than the store holds now.
    func takeUnsaved() -> [(key: String, value: String)] {
        var slots = dirty
        if let writing { slots.insert(writing) }
        dirty = []
        return slots.compactMap { slot in encoded(slot).map { (key(slot), $0) } }
    }

    /// Wait until everything asked to be saved has been written.
    func flush() async {
        if writer == nil, let pending = dirty.first { save(pending) }
        while let writer { await writer.value }
    }

    // MARK: Notices

    /// Say `notice` — once, ever. Before the stores are read nothing is said (and nothing
    /// server-driven runs that could have something to say).
    ///
    /// "Ever" starts when the notice's row is STORED: it is remembered as said only once the
    /// receiver calls `stored(_:)`. If Security activity could not write it (no cache, a
    /// failed write), it is not said twice in this launch, and it is said again in the next.
    func notice(_ notice: Notice) {
        guard ready, !noticed.contains(notice.key), saidNow.insert(notice.key).inserted else { return }
        onNotice?(notice)
    }

    /// The row for `notice` is in Security activity: never say it again.
    func stored(_ notice: Notice) {
        guard ready, !noticed.contains(notice.key) else { return }
        noticed.append(notice.key)
        if noticed.count > Self.noticedLimit { noticed.removeFirst(noticed.count - Self.noticedLimit) }
        save(.noticed)
    }

    // MARK: Server-driven — direct conversations

    /// May something that ARRIVED make a direct entry for this id? Never for an id a group
    /// holds (a conflict, said once), and never for a group the user has not accepted or said
    /// to ignore — nothing of those is shown, as a direct conversation either.
    private func mayListDirect(_ conversationId: String) -> Bool {
        guard ready else { return false }
        if groupIds.contains(conversationId) {
            notice(.conflict(conversationId: conversationId))
            return false
        }
        if declined.contains(conversationId) || invitations.contains(where: { $0.conversationId == conversationId }) { return false }
        // Held before, entry lost (`Review`): nothing that arrives re-creates it.
        if review.holds(conversationId) { return false }
        // The whole direct list was lost: nothing that arrives makes a NEW direct entry (it
        // could be for an id the user held as something else). Entries that exist go on.
        if review.allDirect, holder(of: conversationId) == nil { return false }
        return true
    }

    /// The one place a server-driven direct entry is made. Synchronous: the rule is checked
    /// against both stores as they are NOW, whatever was awaited before.
    private func insertFromServer(conversationId: String, peerUserId: String, name: String) -> DMConversation? {
        guard !peerUserId.isEmpty, mayListDirect(conversationId), !heldDirect(conversationId, with: peerUserId) else { return nil }
        let entry = DMConversation(name: name, peerUserId: peerUserId, peerDeviceId: "", conversationId: conversationId, claimed: false)
        change { dms.insert(entry, at: 0) }
        save(.dms)
        return entry
    }

    /// Is `conversationId` already in the 1:1 store? A direct conversation is bound to ONE
    /// account for good: when the entry is with someone OTHER than `peerUserId`, nothing is
    /// made, the entry is not touched, and it is said once — exactly like a group clash. (A
    /// second entry under the id would let that other account's text be announced, and
    /// answered, as the first one's.)
    private func heldDirect(_ conversationId: String, with peerUserId: String) -> Bool {
        guard let held = holder(of: conversationId) else { return false }
        if held.peerUserId != peerUserId { notice(.otherPeer(conversationId: conversationId)) }
        return true
    }

    /// A server-offered name is dropped when looking it up leads to a DIFFERENT account (it is
    /// then certainly not this account's name). A lookup that agrees adds no trust.
    private func checkedHint(_ hint: String, for peerUserId: String) async -> String {
        guard !hint.isEmpty, let backend else { return "" }
        if let found = try? await backend.findUserId(username: hint), found != peerUserId { return "" }
        return hint
    }

    /// A decrypted DM from `peerUserId` arrived in `conversationId`: make sure that sender has
    /// an entry there. Returns the entry's claimed name and whether it was just made — or nil
    /// when nothing may be listed (the stores are not read yet; a group holds the id; it is an
    /// invitation or an ignored group; the conversation is held with ANOTHER account). An
    /// existing entry is never re-keyed or renamed.
    func deliverDM(conversationId: String, peerUserId: String) async -> (name: String, isNew: Bool)? {
        guard await load(), mayListDirect(conversationId) else { return nil }
        if heldDirect(conversationId, with: peerUserId) { return sameEntry(conversationId, peerUserId) }
        var hint = ""
        if let all = try? await backend?.listDms() {
            hint = all.first(where: { $0.conversationId == conversationId && $0.peerUserId == peerUserId })?.peerUsername ?? ""
        }
        hint = await checkedHint(hint, for: peerUserId)
        if insertFromServer(conversationId: conversationId, peerUserId: peerUserId, name: hint) != nil { return (hint, true) }
        // Not made: either it appeared meanwhile, or the id may no longer be listed direct.
        return sameEntry(conversationId, peerUserId)
    }

    private func sameEntry(_ conversationId: String, _ peerUserId: String) -> (name: String, isNew: Bool)? {
        holder(of: conversationId).flatMap { $0.peerUserId == peerUserId ? ($0.name, false) : nil }
    }

    /// The account's direct conversations as the server lists them: add the ones this device
    /// does not show yet (unclaimed, names unverified). A row never renames, re-keys or removes
    /// an entry, and never makes one for an id a group holds. Returns what was added.
    @discardableResult
    func refreshDMList() async -> [DMConversation] {
        guard await load(), let all = try? await backend?.listDms() else { return [] }
        var added: [DMConversation] = []
        for c in all where !c.peerUserId.isEmpty {
            guard mayListDirect(c.conversationId), !heldDirect(c.conversationId, with: c.peerUserId) else { continue }
            let hint = await checkedHint(c.peerUsername, for: c.peerUserId)
            if let entry = insertFromServer(conversationId: c.conversationId, peerUserId: c.peerUserId, name: hint) {
                added.append(entry)
            }
        }
        return added
    }

    // MARK: Server-driven — groups

    private var listingStarted = 0
    private var listingApplied = 0
    private var listingInFlight: (number: Int, task: Task<Bool, Never>)?

    /// A point in time for `groupsListed(since:)`: listings started after it are newer.
    func listingMark() -> Int { listingStarted }

    /// Ask the server which group conversations it lists and fold that in. Returns false when
    /// it could not be asked (or the stores are not read): callers then decide NOTHING about a
    /// conversation they do not know.
    @discardableResult
    func refreshGroups() async -> Bool { await groupsListed(since: listingMark()) }

    /// Make sure a listing that STARTED after `mark` has been folded in. Any number of callers
    /// with the same mark share one request — a burst of events for unknown conversations is
    /// one listing, not one each.
    ///
    /// The listing in flight takes itself out of `listingInFlight` BEFORE it finishes, so a
    /// caller that waited for one that started too early for its mark (a mark taken while that
    /// listing was already under way) never finds it still there when it resumes: it starts —
    /// or joins — a newer one. Every pass of the loop either returns or waits for a listing
    /// with a higher number than the last, so it ends.
    func groupsListed(since mark: Int) async -> Bool {
        while true {
            guard await load() else { return false }
            if listingApplied > mark { return true }
            if let flying = listingInFlight {
                let ok = await flying.task.value
                if flying.number > mark { return ok }
                // Started too early to count for this mark. Give way once (whatever else was
                // waiting on it runs), then look again.
                await Task.yield()
                continue
            }
            listingStarted += 1
            let number = listingStarted
            let task = Task { @MainActor [weak self] () -> Bool in
                defer { if let self, self.listingInFlight?.number == number { self.listingInFlight = nil } }
                guard let self, let backend = self.backend, let listed = try? await backend.listGroupDms() else { return false }
                let hints = await self.nameHints?() ?? [:]
                return self.apply(listed: listed, hints: hints, number: number)
            }
            listingInFlight = (number, task)
            return await task.value
        }
    }

    /// Fold one listing in. Synchronous, and against the stores as they are NOW — not a copy
    /// taken before the request: a group accepted or started while it was in flight is simply
    /// an accepted group here. Per group, only the "server disagrees" flag is set and missing
    /// names are added; no accepted group is ever added, removed or re-membered by a listing.
    private func apply(listed: [(conversationId: String, memberUserIds: [String])], hints: [String: String], number: Int) -> Bool {
        guard ready, number > listingApplied else { return false }
        listingApplied = number
        // (The core leaves this account out of what it lists; nothing here depends on it.)
        let listed = listed.map { (conversationId: $0.conversationId, memberUserIds: Self.others($0.memberUserIds, me: me)) }
        let result = GroupDM.reconcile(accepted: groups, listed: listed, declined: declined, direct: claimedDirectIds,
                                       lostDirect: review.direct, reviewGroups: review.group, reviewAll: review.all)
        var merged = groups
        for folded in result.accepted {
            guard let i = merged.firstIndex(where: { $0.conversationId == folded.conversationId }) else { continue }
            merged[i].serverDisagrees = folded.serverDisagrees
            for id in merged[i].memberUserIds where merged[i].claimedNames[id] == nil {
                if let hint = hints[id] { merged[i].claimedNames[id] = hint }
            }
        }
        var invited = result.invitations
        for i in invited.indices {
            for id in invited[i].memberUserIds { if let hint = hints[id] { invited[i].claimedNames[id] = hint } }
        }
        let groupsChanged = merged != groups
        if groupsChanged || invited != invitations {
            change {
                groups = merged
                invitations = invited
            }
        }
        if groupsChanged { save(.groups) }
        for id in result.conflicts { notice(.conflict(conversationId: id)) }
        return true
    }

    // MARK: The user's own actions (these are what CLAIM an id)

    enum Opened: Equatable {
        case added(DMConversation), existing(DMConversation), refused
        /// Refused because the id is that of a group the user said to IGNORE. Nothing changes;
        /// the caller says so — the way out is to stop ignoring that group (`unignore`).
        case refusedIgnored
    }

    /// The user opened a direct conversation. Refused (and said once) when a group holds the
    /// id — the server answered "open a DM" with a group's id — or an invitation or an ignored
    /// group does; nothing changes then.
    func addDM(_ d: DMConversation) -> Opened {
        guard ready else { return .refused }
        // Also the id of a group this device was invited to, the user ignored, or held and
        // lost the entry of (`Review.group`): a direct conversation under it would be refused
        // every delivery afterwards — so it is refused here, up front, and said.
        if groupIds.contains(d.conversationId) || declined.contains(d.conversationId) || review.group.contains(d.conversationId)
            || invitations.contains(where: { $0.conversationId == d.conversationId }) {
            notice(.conflict(conversationId: d.conversationId))
            return declined.contains(d.conversationId) && !groupIds.contains(d.conversationId) ? .refusedIgnored : .refused
        }
        if let i = dms.firstIndex(where: { $0.conversationId == d.conversationId }) {
            // The server answered "open a DM with B" with the id of the conversation with A.
            guard dms[i].peerUserId == d.peerUserId else {
                notice(.otherPeer(conversationId: d.conversationId))
                return .refused
            }
            claim(at: i)
            return .existing(dms[i])
        }
        var entry = d
        entry.startedHere = true
        entry.claimed = true
        change { dms.insert(entry, at: 0) }
        save(.dms)
        // The user opened this chat again: its id is held once more.
        if review.direct.remove(d.conversationId) != nil { save(.review) }
        return .added(entry)
    }

    /// The user wrote in a direct conversation that something else had listed: it is theirs now.
    func claimDM(conversationId: String, peerUserId: String) {
        guard ready, !groupIds.contains(conversationId),
              let i = dms.firstIndex(where: { $0.conversationId == conversationId && $0.peerUserId == peerUserId }) else { return }
        claim(at: i)
    }

    private func claim(at i: Int) {
        guard !dms[i].isClaimed else { return }
        change { dms[i].claimed = true }
        save(.dms)
    }

    /// A group takes `conversationId` by the user's action: direct entries under it that
    /// nothing of the user's made (unclaimed) give way, so the id is in one store only.
    private func take(_ group: GroupDM) {
        change {
            dms.removeAll { $0.conversationId == group.conversationId && !$0.isClaimed }
            invitations.removeAll { $0.conversationId == group.conversationId }
            groups.removeAll { $0.conversationId == group.conversationId }
            groups.insert(group, at: 0)
        }
        // Looked at and taken by the user: nothing left to review about this id.
        if review.group.remove(group.conversationId) != nil { save(.review) }
        save(.groups)
        save(.dms)
    }

    /// Start (or reopen) a group with exactly these people. The server's answer is only an id:
    /// one that a direct conversation claims, or that a group with OTHER people holds, is
    /// refused — nothing is started and nothing changes.
    func startGroup(memberUserIds ids: [String], names: [String: String]) async throws -> GroupDM {
        guard await load(), let backend else { throw ConversationError.notReady }
        let ids = Self.others(ids, me: me)
        let conversationId = try await backend.openGroupDm(memberUserIds: ids)
        let held = group(for: conversationId)
        if claimedDirectIds.contains(conversationId) || review.direct.contains(conversationId) || held.map({ Set($0.memberUserIds) != Set(ids) }) == true {
            notice(.conflict(conversationId: conversationId))
            throw ConversationError.conflict
        }
        var group = held ?? GroupDM(conversationId: conversationId, memberUserIds: ids)
        for (id, name) in names where !name.isEmpty && group.memberUserIds.contains(id) { group.claimedNames[id] = name }
        take(group)
        return group
    }

    enum Joined: Equatable {
        /// The group is accepted, with exactly the members the user was shown.
        case joined(GroupDM)
        /// The invitation is no longer the one the user was shown (a later listing named
        /// other people). Nothing was accepted; here is the invitation as it is now, to be
        /// looked at again.
        case changed(GroupDM)
        case refused
    }

    /// "Join group". `invitation` is what the USER WAS SHOWN: its members, exactly, become the
    /// group's fixed set — so it is refused (`changed`) when the invitation this device holds
    /// now names other people than the ones on screen; a member set nobody looked at is never
    /// fixed. Refused as well when a direct conversation claims the id: the invitation then
    /// stays where it is, nothing changes and it is said once.
    func join(_ invitation: GroupDM) -> Joined {
        guard ready, let shown = invitations.first(where: { $0.conversationId == invitation.conversationId }),
              GroupDM.sizeProblem(others: Set(shown.memberUserIds).count) == nil else {
            // Accepted meanwhile (another tap): that group, as it was accepted.
            if ready, let held = group(for: invitation.conversationId), Set(held.memberUserIds) == Set(invitation.memberUserIds) { return .joined(held) }
            return .refused
        }
        guard Set(shown.memberUserIds) == Set(invitation.memberUserIds) else { return .changed(shown) }
        if claimedDirectIds.contains(shown.conversationId) {
            notice(.conflict(conversationId: shown.conversationId))
            return .refused
        }
        if let held = group(for: shown.conversationId) { return .joined(held) }
        var group = shown
        group.serverDisagrees = nil
        take(group)
        return .joined(group)
    }

    /// `join`, for callers that only want the accepted group.
    func accept(_ invitation: GroupDM) -> GroupDM? {
        if case .joined(let group) = join(invitation) { return group }
        return nil
    }

    /// "Ignore this group": not listed again on this device, and nothing of it is shown.
    func decline(_ invitation: GroupDM) {
        guard ready else { return }
        var added = false
        // One step: whoever is told about the change sees the id as ignored already (the
        // notification extension is handed the silent ids from there).
        change {
            invitations.removeAll { $0.conversationId == invitation.conversationId }
            added = declined.insert(invitation.conversationId).inserted
        }
        if review.group.remove(invitation.conversationId) != nil { save(.review) }
        if added { save(.declined) }
    }

    /// "Stop ignoring": the id is no longer barred. Nothing else changes here — if the server
    /// still lists the group it comes back as an invitation with the next listing, to be
    /// looked at and joined or ignored again. False when it was not ignored.
    @discardableResult
    func unignore(_ conversationId: String) -> Bool {
        guard ready, declined.contains(conversationId) else { return false }
        change { declined.remove(conversationId) }
        save(.declined)
        return true
    }

    /// Is the user still to be told that a whole list was lost (`Review.allGroups`, `.allDirect`)?
    var reviewPending: Bool { review.all }

    /// The user has seen that a whole list was lost and wants things to go on: listings and
    /// deliveries make direct entries again, and a listed group is an invitation again — except
    /// the ones known by id to have been held (`Review.group`), which stay "review".
    func clearReview() {
        guard ready, review.all else { return }
        change {
            review.allGroups = false
            review.allDirect = false
            for i in invitations.indices { invitations[i].needsReview = review.group.contains(invitations[i].conversationId) ? true : nil }
        }
        save(.review)
    }

    #if DEBUG
    /// Screenshot/demo aid only: show these rows without a cache behind them.
    func setDemo(dms demo: [DMConversation]) { change { dms = demo } }
    #endif
}
