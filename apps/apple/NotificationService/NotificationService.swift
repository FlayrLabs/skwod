import Foundation
import UserNotifications
import os

/// Step markers only — never content, names, ids or addresses.
private let nseLog = Logger(subsystem: "io.skwod.client", category: "nse")

/// Notification Service Extension for the blind push gateway (docs/PUSH.md).
///
/// What arrives from Apple is always the same generic alert — "New message", `mutable-content: 1`
/// — because the gateway is told nothing else: not which skwod, not who, not what. This extension
/// runs on the device when that alert lands and tries to make it useful *locally*: connect to the
/// user's skwod(s), sync, decrypt, and replace the text with the sender and message.
///
/// The server wakes the device for EVERY message alike — it cannot tell (and is never told)
/// chat from a like, a comment, an avatar update or a game move. What kind it was is decided
/// here, after decrypting (`messageNotifies`, the core's one rule for it):
///
/// - real chat from someone else → the notification names the conversation and (if previews
///   are on) the text;
/// - only background traffic arrived → there is nothing to tell the user. An extension cannot
///   drop a notification without the `com.apple.developer.usernotifications.filtering`
///   entitlement, which Apple grants per app and this build does not have, so the alert is
///   turned into ONE quiet line instead: "New activity", passive (no banner, no sound, no
///   screen wake), and any earlier such line is removed first — never a banner per like;
/// - the session was ended by the server → "You've been signed out of ‹skwod› — open to sign in".
///
/// It is strictly best effort, and every failure mode ends in the same safe place — the generic
/// text is shown:
///
/// - no shared container / keychain group in this build → generic;
/// - the device has not been unlocked since it was started (the cache key is readable after
///   first unlock, like Signal's — and only while app lock is off and previews are on) →
///   generic; on a phone that is merely LOCKED the banner names the sender and the text;
/// - the app is running and holds the cache → generic (the app notifies by itself);
/// - the host can't be reached, or time/memory runs out (the system kills the extension) → generic;
/// - the user turned previews off → generic.
///
/// Nothing decrypted here is ever sent anywhere: it goes into the local notification only.
final class NotificationService: UNNotificationServiceExtension {
    private var contentHandler: ((UNNotificationContent) -> Void)?
    private var original: UNMutableNotificationContent?
    private var work: Task<Void, Never>?
    private let finishLock = NSLock()
    private var finished = false
    /// The wake's tag: which skwod it is for, as far as this device can tell.
    private var tag = ""

    override func didReceive(_ request: UNNotificationRequest,
                             withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.contentHandler = contentHandler
        original = request.content.mutableCopy() as? UNMutableNotificationContent
        nseLog.notice("wake received")
        work = Task { [weak self] in
            // The wake's opaque tag (when the gateway passes one) says which skwod it is for.
            let tag = request.content.userInfo["tag"] as? String
            self?.tag = tag ?? ""
            // Whose push it is (audit M1): the registration id the gateway put in it, checked
            // against the ids this install registered. A wake with none — a raw token kept from
            // an earlier build — or with someone else's stays generic and dials nobody.
            let known = WakeOrigin.knownIds(SharedContainer.defaults.data(forKey: WakeOrigin.registrationIdsKey),
                                            now: Int64(Date().timeIntervalSince1970))
            let origin = WakeOrigin.of(credentialId: request.content.userInfo["skwod_cred"], known: known)
            let rewritten = await NotificationDecryptor.rewrite(tag: tag, origin: origin)
            self?.finish(with: rewritten)
        }
    }

    /// The system is about to kill us: deliver the generic text now.
    override func serviceExtensionTimeWillExpire() {
        work?.cancel()
        finish(with: nil)
    }

    private func finish(with rewritten: NotificationDecryptor.Result?) {
        finishLock.lock(); defer { finishLock.unlock() }
        guard !finished, let contentHandler, let content = original else { return }
        finished = true
        // The push itself carries no sound (older gateways), so a banner that should be
        // noticed gets one here: without it a sleeping phone lights up silently, with no
        // haptic, which reads as "no notification". The quiet line below takes it off again.
        if content.sound == nil { content.sound = .default }
        // One sound per conversation per burst (`SoundBurst`, 5 s) — per skwod for a banner
        // that cannot say which conversation. The quiet line below has none at all.
        if rewritten?.quiet != true, !NotificationState.bannerSounds(key: rewritten?.thread ?? "skwod:\(tag)") { content.sound = nil }
        // The other new messages this wake found and claimed: each a notification of its own
        // (no sound — the one the push turns into makes it), in its conversation's thread.
        for (i, extra) in (rewritten?.also ?? []).enumerated() {
            let more = UNMutableNotificationContent()
            more.title = extra.title
            more.body = extra.body
            more.threadIdentifier = extra.thread
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: "skwod.also.\(UUID().uuidString).\(i)", content: more, trigger: nil))
        }
        if let rewritten {
            content.title = rewritten.title
            content.body = rewritten.body
            content.threadIdentifier = rewritten.thread
            if rewritten.quiet {
                // Nothing the user needs to look at: no sound, no banner, no screen wake, and
                // only one such line in Notification Center at a time.
                content.sound = nil
                content.interruptionLevel = .passive
                content.relevanceScore = 0
                let center = UNUserNotificationCenter.current()
                center.getDeliveredNotifications { delivered in
                    let stale = delivered.filter { $0.request.content.threadIdentifier == NotificationDecryptor.activityThread }
                        .map(\.request.identifier)
                    if !stale.isEmpty { center.removeDeliveredNotifications(withIdentifiers: stale) }
                    contentHandler(content)
                }
                return
            }
        }
        contentHandler(content)
    }
}

enum NotificationDecryptor {
    struct Result {
        let title: String
        let body: String
        let thread: String
        /// Background traffic only: deliver passively and collapse (see `NotificationService`).
        var quiet = false
        /// Other new messages this same wake found, each claimed and each shown: posted as
        /// notifications of their own beside the one the push turns into (`WakePick`).
        var also: [Result] = []
    }

    static let passiveLine = Result(title: "Skwod", body: "New activity", thread: activityThread, quiet: true)

    /// Thread of the one quiet "New activity" line.
    static let activityThread = "skwod.activity"

    /// What one skwod had for us.
    private enum Found {
        /// New chat messages from someone else, not announced before: one per conversation,
        /// each already claimed in the ledger, with the rank they compete under.
        case messages([(result: Result, at: Int64)])
        /// Synced and decrypted fine, and nothing in it is worth a notification.
        case onlyBackgroundTraffic
        /// The server answered 401 for this session.
        case signedOut(name: String)
    }

    /// How long one skwod gets to answer before we move on, and how long all of them get
    /// together (the extension has ~30 s in total; what is left of it delivers the result).
    private static let perWorkspaceBudget: TimeInterval = 12
    private static let totalBudget: TimeInterval = 22
    private static let maxWorkspaces = 3

    static func rewrite(tag: String? = nil, origin: WakeOrigin = .stranger) async -> Result? {
        // Whose wake this is and whether it may interrupt at all is decided FIRST, from the
        // tag and the skwods' own mutes (`WakeRule`) — before anything is dialed, opened or
        // decrypted. It is the passive line (an extension cannot drop the alert) only when
        // EVERY skwod it could be from is muted; a wake that is nobody's keeps the generic
        // banner and contacts no host.
        let now = Date().timeIntervalSince1970
        // (A build without the shared keychain group reads nothing of the app's: unknown.)
        let readable = Keychain.sharedGroup == nil ? nil : WorkspaceStore.loadIfReadable()?.filter { !$0.isSignedOut }
        let mayDecrypt = NotificationState.showPreviews && !NotificationState.appLockEnabled
        let plan = WakeRule.plan(tag: tag, origin: origin, signedIn: readable?.map { WakeRule.Skwod(id: $0.id, wakeTag: $0.wakeTag) },
                                 everySkwodMutedUntil: MuteFlagStore.everySkwodMutedUntil(),
                                 skwodMuted: { MuteStore.skwodMuted(workspaceId: $0, now: now) },
                                 mayDecrypt: mayDecrypt, now: now)
        let wokenIds: [String]
        switch plan {
        case .quiet:
            nseLog.notice("quiet: every skwod this could be from is muted")
            return passiveLine
        case .generic:
            // Previews off or app lock on: nothing is decrypted for a banner and the cache is
            // not opened (its key is then not even readable on a locked phone — `KeyAccess`).
            // Or nothing is readable yet (not unlocked since boot), or the wake is nobody's.
            nseLog.notice("generic: nothing to decrypt for")
            return nil
        case .decrypt(let ids):
            wokenIds = ids
        }
        guard SharedContainer.groupURL != nil, Keychain.sharedGroup != nil else {
            nseLog.notice("generic: no shared container or keychain group in this build")
            return nil
        }
        // Never open the cache while the app has it — and let go of it the moment the app asks:
        // the app waits for this lock before it opens the cache, so holding on would freeze it.
        guard !StoreLock.shared.yieldRequested, StoreLock.shared.tryAcquire() else {
            nseLog.notice("generic: the app holds (or wants) the cache")
            return nil
        }
        // The lock is released only after every client this run made is gone (each lives
        // inside `newest(in:)`): when the function returns — or, for a skwod that did not
        // answer in its time and was left behind, when that call has ended too.
        var leftBehind: [BoundedCall.Lingering] = []
        defer {
            if leftBehind.isEmpty {
                StoreLock.shared.release()
            } else {
                let waiting = leftBehind
                Task { for call in waiting { await call.task.value }; StoreLock.shared.release() }
            }
        }
        let yielding = YieldFlag()
        StoreLock.shared.onYield { yielding.set() }

        var found: [(result: Result, at: Int64)] = []
        var signedOutOf: String?
        var sawOnlyBackground = false
        // A skwod that is not muted could not be asked or did not answer: it may have a real
        // message, so this wake never ends in the quiet line (`WakeRule.withoutAMessage`).
        var unknown = false
        // Only the skwods the wake may be about are contacted (a tagged wake: exactly one —
        // the others learn nothing from this push, and it costs one sync instead of several).
        let candidates = wokenIds.compactMap { id in readable?.first(where: { $0.id == id }) }
        let deadline = Date().addingTimeInterval(totalBudget)
        for w in candidates.prefix(maxWorkspaces) {
            if Task.isCancelled || yielding.isSet || StoreLock.shared.yieldRequested { nseLog.notice("yielding to the app"); unknown = true; break }
            let left = deadline.timeIntervalSinceNow
            guard left > 1 else { nseLog.notice("out of time: the remaining skwods stay generic"); unknown = true; break }
            // How often a skwod may make this device connect to it (`WakeBudget`). Past it the
            // banner stays generic — and audible.
            guard NotificationState.spendWake(workspaceId: w.id) else { nseLog.notice("skip: this skwod's wake budget is spent"); unknown = true; continue }
            let abandoned = YieldFlag()
            let outcome = await BoundedCall.run(seconds: min(perWorkspaceBudget, left), shouldStop: { yielding.isSet },
                                                onAbandon: { abandoned.set() }) {
                await newest(in: w, yielding: yielding, abandoned: abandoned)
            }
            if let lingering = outcome.lingering { leftBehind.append(lingering) }
            switch outcome.value {
            case .messages(let list)?:
                found += list
            case .onlyBackgroundTraffic?:
                sawOnlyBackground = true
            case .signedOut(let name)?:
                signedOutOf = name
            case nil:
                unknown = true
            }
        }
        if candidates.count > maxWorkspaces { unknown = true }
        // A skwod that was left behind still has the cache open: it gets what is left of the
        // wake's time to end, so the banner is not delivered (and the extension suspended)
        // with the lock held. One that has still not ended keeps the lock until it does.
        leftBehind = await BoundedCall.wait(for: leftBehind, until: deadline)
        // Every message this wake claimed is shown: the newest as the push itself, the others
        // beside it (`WakePick`; `newest(in:)` claimed no more than can be shown).
        if let pick = WakePick.pick(ranks: found.map(\.at), maxExtras: found.count) {
            nseLog.notice("rewritten on-device")
            var best = found[pick.primary].result
            best.also = pick.extras.map { found[$0].result }
            return best
        }
        if let signedOutOf {
            nseLog.notice("session ended by the server")
            return Result(title: "Signed out", body: "You've been signed out of \(signedOutOf) — open to sign in", thread: "session")
        }
        if WakeRule.withoutAMessage(unknown: unknown, onlyBackgroundTraffic: sawOnlyBackground) == .quiet {
            nseLog.notice("quiet: only background traffic")
            return passiveLine
        }
        nseLog.notice("generic: nothing could be decrypted")
        return nil
    }

    /// Sync one skwod and return its newest not-yet-announced message from someone else.
    private static func newest(in w: Workspace, yielding: YieldFlag, abandoned: YieldFlag) async -> Found? {
        // `abandoned`: this skwod did not answer in its time and the wake went on without it.
        // From then on nothing here is recorded or claimed — its result is shown by nobody.
        let stop = { Task.isCancelled || yielding.isSet || abandoned.isSet || StoreLock.shared.yieldRequested }
        // The cache key is readable after first unlock: before that (a restarted phone nobody
        // has unlocked yet) — or on an install whose key an older build stored `WhenUnlocked`
        // and that has not been opened since the update — this is nil and we stop here.
        guard let keyHex = Keychain.get("cache-key-\(w.id)"), keyHex.count == 64 else {
            nseLog.notice("skip: cache key unavailable (not unlocked since boot?)")
            return nil
        }
        var session: P2pSession?
        let base: String
        if let nodeId = w.nodeId {
            guard let s = try? await p2pConnect(nodeId: nodeId, publicFallback: NotificationState.publicFallback) else {
                nseLog.notice("skip: host unreachable")
                return nil
            }
            session = s
            base = s.baseUrl()
        } else {
            guard w.server.hasPrefix("https://") else { return nil }
            base = w.server
        }
        defer { if let session { Task { await session.disconnect() } } }

        if stop() { return nil }
        let client = SkwodClient(baseUrl: base, token: w.token)
        // `attachCache` returning false means "no usable identity here" — the extension must
        // never register a device or create keys; that is the app's job.
        guard (try? await client.attachCache(path: SharedContainer.cachePath(forWorkspace: w.id), keyHex: keyHex)) == true else {
            nseLog.notice("skip: cache could not be opened")
            return nil
        }
        if let pinned = w.pinnedKey { try? await client.setPinnedServerKey(serverPublicB64: pinned) }
        // The app asked for the cache while it was being opened: nothing was written, go.
        if stop() { return nil }
        // Only a working device syncs here. Removed, superseded or waiting for a restore: the
        // app says so when it opens; this extension changes nothing.
        guard await client.deviceState() == .active else { nseLog.notice("skip: not an active device"); return nil }
        NotificationState.storeGeneration += 1
        do {
            // Not `processControlInbox`: that also keeps this device's keys stocked (prekey
            // refill, signed-prekey and delivery-key rotation), which is the app's job. This
            // one reads the mailbox and puts the client in a mode where it creates, rotates
            // and uploads no key — in this call and in the fetches below.
            try await client.processNotificationInbox()
        } catch {
            // Not necessarily the network: a server that answers 401 has ended this session.
            // (The app marks the workspace signed out when it next runs.)
            if await client.sessionState() == .signedOut { return .signedOut(name: w.displayName) }
            return nil
        }

        let names = NotificationState.names(workspaceId: w.id)
        // Whose rows may be announced under each conversation's title: a group's members as
        // the app holds them, a direct conversation's peer. A row by anyone else — a ghost the
        // server put in the conversation — is never shown, under any title.
        let senders = NotificationState.senders(workspaceId: w.id)
        // What is new is decided by id (`AnnounceWindow`): the floor is this device's own
        // clock, left by the app, and `seen` is what earlier wakes already looked at. Nothing
        // here trusts a row's server-given date for more than picking one of several new rows.
        let floor = NotificationState.highWater(workspaceId: w.id)
        var seenIds = NotificationState.seenIds(workspaceId: w.id)
        let seenBefore = seenIds
        let seen = Set(seenIds)
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        var candidates: [(scope: String, message: Message)] = []
        var fetched = false
        var unsure = false
        var unsureIds: [String] = []
        var complete = true
        // Not again what either process already notified about (`AnnouncedLedger`).
        // Rows an earlier wake could not show are remembered apart (`AnnouncedLedger.unsureLimit`):
        // a flood of undecryptable rows cannot push real ids out of the announced ledger.
        let announced = NotificationState.announced(workspaceId: w.id).union(NotificationState.unsure(workspaceId: w.id))
        // Nobody this account blocked ever produces a banner (the core leaves their rows out of
        // what it reads back; this is the same rule, stated where the banner is made).
        let blocked = Set(client.blockedUserIds())
        // Muted conversations (`MuteList`, written by the app): looked past entirely — their
        // messages are neither announced nor a reason for the visible generic banner.
        let mutes = MuteStore.load(workspaceId: w.id)
        let wokenAt = Date().timeIntervalSince1970
        // A whole-skwod mute silences everything, mentions too. A muted conversation is still
        // read, for one thing only: a message that mentions this account always alerts
        // (`MentionAlertRule`).
        let skwodMuted = mutes.holds(MuteList.skwod, now: wokenAt)
        var mentionIds: Set<String> = []
        // scope → the mentions of me found there (each counted once on the badge, app or here).
        var mentionsByScope: [String: [String]] = [:]
        // (`person:` entries are names for mention banners, not conversations.)
        for scope in names.keys where MentionNotice.isConversation(scope) {
            if stop() { complete = false; break }
            if skwodMuted { fetched = true; continue }
            let scopeMuted = mutes.isMuted(scope: scope, now: wokenAt)
            var rows: [Message]?
            if scope.hasPrefix("channel:") {
                rows = try? await client.fetchChannelMessages(channelId: String(scope.dropFirst(8)), myUserId: w.userId)
            } else {
                rows = await client.history(scope: scope)
            }
            if rows != nil { fetched = true }
            // New rows from someone else. Whether a decrypted body deserves a notification is
            // the core's rule (`messageNotifies`): not likes, comments, avatars, game moves.
            let newRows = rows?.filter { m in
                AnnounceWindow.isNew(messageId: m.messageId, createdAt: m.createdAt, floor: floor, seen: seen)
                    && !m.isDeleted && m.authorId != w.userId && m.authorId != "__me__"
                    && !m.isSystem && !blocked.contains(m.authorId ?? "")
            }
            // A mention of me, an @everyone from someone the app found may use it in this
            // channel (`EveryoneRule`, left in the sender sets — the extension asks the server
            // nothing about roles), or a reply to one of my messages on the same page.
            let everyone = Set(senders?[EveryoneRule.sendersKey(channelId: String(scope.dropFirst(8)))] ?? [])
            let mine = Set((rows ?? []).filter { $0.authorId == w.userId || $0.authorId == "__me__" }.map(\.messageId))
            for m in newRows ?? [] where MentionRule.mentionsMe(
                MentionCodec.decode(m.content ?? "").payload, me: w.userId,
                senderMayMentionEveryone: scope.hasPrefix("channel:") && everyone.contains(m.authorId ?? ""),
                // (In a one-to-one conversation everything is to me: a reply is no mention.)
                replyToMine: (scope.hasPrefix("channel:") || (senders?[scope]?.count ?? 0) > 1)
                    && MentionNotice.replyToMine(m.replyToId, mine: mine)) {
                mentionIds.insert(m.messageId)
                mentionsByScope[scope, default: []].append(m.messageId)
            }
            let fresh = scopeMuted ? newRows?.filter { mentionIds.contains($0.messageId) } : newRows
            // Looked at now: none of it is new to a later wake, under whatever date.
            if let rows {
                seenIds = AnnounceWindow.remembering(page: rows.map(\.messageId), fresh: (fresh ?? []).map(\.messageId), in: seenIds)
            }
            // What may be shown, and whether anything here could be a real message that
            // cannot be (unreadable, a conversation that could not be fetched, a sender the
            // app has not vouched for): `NotificationDecision` — the rule, with its tests.
            let scan = NotificationDecision.scan(
                scope: scope,
                rows: fresh?.map { m -> NotificationDecision.Row in
                    let text = m.content ?? ""
                    return NotificationDecision.Row(messageId: m.messageId, authorId: m.authorId, unreadable: m.isUndecryptable,
                                 notifies: !m.isUndecryptable && !text.isEmpty && messageNotifies(text: text))
                },
                senders: senders, announced: announced)
            if scan.unsure { unsure = true }
            unsureIds += scan.unsureIds
            guard let i = scan.announce, let last = fresh?[i] else { continue }
            candidates.append((scope, last))
        }
        // Left behind (out of time) or asked to stop: whatever was found is shown by nobody,
        // so nothing is remembered as seen and nothing is claimed — the next wake finds it.
        if abandoned.isSet || Task.isCancelled { return nil }
        if stop() { complete = false }
        // The red "@ n" in the app (`MentionBadgeLedger`, in the app group): each mention once.
        for (scope, ids) in mentionsByScope {
            MentionBadgeLedger.update(SharedContainer.defaults) { $0.add(ids: ids, topic: scope, workspaceId: w.id) }
        }
        // One banner per conversation with something new, the newest first; what is beyond
        // what one wake shows is not marked as looked at, and is found again by the next.
        let picked = WakePick.pick(ranks: candidates.map { AnnounceWindow.rank(createdAt: $0.message.createdAt, now: nowMs) })
        let shown = picked.map { [$0.primary] + $0.extras } ?? []
        let notShown = Set(candidates.indices).subtracting(shown).map { candidates[$0].message.messageId }
        if !notShown.isEmpty { seenIds.removeAll(where: notShown.contains) }
        if seenIds != seenBefore { NotificationState.setSeenIds(seenIds, workspaceId: w.id) }
        // Whatever this wake ends in, it is a visible banner for the rows that could not be
        // shown: they are not found again by the next wake (which may be about a like).
        NotificationState.markUnsure(unsureIds, workspaceId: w.id)
        // Claimed now, not from the snapshot taken before the fetches: the app may have
        // announced one of these in the seconds since. Then it is not said again. An id is
        // claimed only for a banner that is about to be made.
        let claimed = Set(NotificationState.markAnnounced(shown.map { candidates[$0].message.messageId }, workspaceId: w.id))
        let results: [(result: Result, at: Int64)] = shown.compactMap { i in
            let (scope, message) = candidates[i]
            guard claimed.contains(message.messageId) else { return nil }
            let name = names[scope] ?? "New message"
            var title = scope.hasPrefix("channel:") ? "#\(name)" : name
            // A mention says so (labels exist only while previews are on and app lock is off;
            // otherwise the generic line, like every other banner).
            if mentionIds.contains(message.messageId) {
                title = MentionNotice.title(sender: MentionNotice.senderName(authorId: message.authorId, names: names),
                                            place: names[scope] != nil ? title : nil)
            }
            return (Result(title: title, body: preview(MentionCodec.visible(message.content ?? "")), thread: scope),
                    AnnounceWindow.rank(createdAt: message.createdAt, now: nowMs))
        }
        // The quiet line only when everything was read and none of it needs the user;
        // anything unread, unreadable or unchecked keeps the visible "New message".
        guard !results.isEmpty else {
            switch NotificationDecision.verdict(announces: false, unsure: unsure, lookedAtAny: fetched, complete: complete) {
            case .quiet: return .onlyBackgroundTraffic
            default: return nil
            }
        }
        return .messages(results)
    }

    private static func preview(_ body: String) -> String {
        if body.hasPrefix("\u{2}skwod/attach|") { return "Sent an attachment" }
        if body.hasPrefix("\u{2}skwod/music|") { return "Shared a song" }
        if body.hasPrefix("\u{2}skwod/feed|") { return "Posted to the feed" }
        if body.hasPrefix("\u{2}skwod/story|") { return "Added to their story" }
        if body.hasPrefix("\u{2}skwod/") { return "New activity" }
        let oneLine = body.replacingOccurrences(of: "\n", with: " ")
        return oneLine.count > 180 ? String(oneLine.prefix(180)) + "…" : oneLine
    }
}
