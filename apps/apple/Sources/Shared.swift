import Foundation
import Security

/// DEBUG-only data isolation: `SKWOD_PROFILE=<name>` makes a Debug build keep its keychain items,
/// caches and (on a Mac) hosted-server data under that name, so a test run never touches the
/// real install's data on the same machine. Always nil in Release.
enum Profile {
    static let name: String? = {
        #if DEBUG
        guard let raw = ProcessInfo.processInfo.environment["SKWOD_PROFILE"] else { return nil }
        let clean = raw.filter { $0.isASCII && ($0.isLetter || $0.isNumber) }
        return clean.isEmpty ? nil : String(clean.prefix(24))
        #else
        return nil
        #endif
    }()

    /// "" or ".<name>" / "-<name>" suffixes for names that must differ per profile.
    static func suffix(_ separator: String) -> String { name.map { separator + $0 } ?? "" }
}

/// Storage the app shares with its notification service extension (iOS). Compiled into both.
///
/// The extension can only help if it can see the same encrypted cache and the same keychain items
/// as the app. Both are optional capabilities of the *build*: without the App Group entitlement
/// (simulator builds made with code signing off, macOS) everything falls back to the app's own
/// container and the extension simply leaves notifications generic.
enum SharedContainer {
    /// The App Group id from Info.plist (`SkwodAppGroup`), if this build declares one.
    static let appGroup: String? = {
        guard let g = Bundle.main.object(forInfoDictionaryKey: "SkwodAppGroup") as? String,
              !g.isEmpty, !g.hasPrefix("$(") else { return nil }
        return g
    }()

    /// The shared container, or nil when the build isn't entitled to the group.
    static let groupURL: URL? = {
        #if os(iOS)
        guard let appGroup else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
        #else
        return nil
        #endif
    }()

    /// The cache (with its WAL/SHM siblings) and the lock files next to it are readable once
    /// the device has been unlocked after boot — `completeUntilFirstUserAuthentication`, the
    /// class Signal keeps its database in — so the notification extension can open them on a
    /// locked phone. Stated explicitly (it is also what a file in the shared container gets
    /// by default), and re-stated for files an earlier build made; a no-op where it already
    /// holds, and silently refused while the device is locked (the next unlocked call does it).
    static func protectUntilFirstUnlock(_ cachePath: String) {
        #if os(iOS)
        var paths = ["", "-wal", "-shm"].map { cachePath + $0 }
        if let groupURL { paths += ["store.lock", "store.yield", "announced.lock"].map { groupURL.appendingPathComponent($0).path } }
        let fm = FileManager.default
        for path in paths where fm.fileExists(atPath: path) {
            if (try? fm.attributesOfItem(atPath: path)[.protectionKey] as? FileProtectionType) != .completeUntilFirstUserAuthentication {
                try? fm.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: path)
            }
        }
        #endif
    }

    /// The app's own Application Support directory (where caches lived before the shared container).
    static var privateURL: URL {
        var dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        if let profile = Profile.name { dir.appendPathComponent("skwod-profile-\(profile)", isDirectory: true) }
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Where a workspace's SQLCipher cache lives. In the shared container when there is one —
    /// moving an existing cache (and its WAL/SHM siblings) there the first time.
    static func cachePath(forWorkspace id: String) -> String {
        // Never the id as written unless it is plain: it may have come from a server.
        let name = "skwod-\(WorkspaceIdRule.fileComponent(for: id)).sqlite3"
        let old = privateURL.appendingPathComponent(name)
        guard let groupURL else { return old.path }
        let new = groupURL.appendingPathComponent(name)
        let fm = FileManager.default
        defer { protectUntilFirstUnlock(new.path) }
        if !fm.fileExists(atPath: new.path), fm.fileExists(atPath: old.path) {
            for suffix in ["", "-wal", "-shm"] {
                let from = URL(fileURLWithPath: old.path + suffix)
                if fm.fileExists(atPath: from.path) {
                    try? fm.moveItem(at: from, to: URL(fileURLWithPath: new.path + suffix))
                }
            }
        }
        return new.path
    }

    /// Keep a workspace's cache (and its SQLite side files) out of iCloud and Finder backups.
    /// The cache holds this device's identity key and sessions: restored onto another device it
    /// would be a second copy of this one. What brings an account back is the recovery key.
    /// Set on every open — SQLite recreates `-wal` / `-shm`, and the flag is per file.
    static func excludeCacheFromBackup(forWorkspace id: String) {
        let base = cachePath(forWorkspace: id)
        for suffix in ["", "-wal", "-shm", "-journal", ".unreadable"] {
            var url = URL(fileURLWithPath: base + suffix)
            guard FileManager.default.fileExists(atPath: url.path) else { continue }
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? url.setResourceValues(values)
        }
    }

    /// Whether the cache file of a workspace is marked as excluded from backups (checks).
    static func cacheIsExcludedFromBackup(forWorkspace id: String) -> Bool {
        let url = URL(fileURLWithPath: cachePath(forWorkspace: id))
        return (try? url.resourceValues(forKeys: [.isExcludedFromBackupKey]))?.isExcludedFromBackup == true
    }

    /// Remove everything the app keeps for the notification extension about conversations: the
    /// scope → display-name cache and the per-workspace high-water marks ("notif.<workspace>.…").
    /// Called on sign-out: those names describe conversations whose caches were just deleted, and
    /// the shared defaults (an app-group suite on iOS) would otherwise keep them.
    static func wipeSharedState() {
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix("notif.") {
            // Settings ("notif.showPreviews", "notif.publicFallback") are preferences, not data.
            if key == "notif.showPreviews" || key == "notif.publicFallback" || key == "notif.appLockEnabled" { continue }
            defaults.removeObject(forKey: key)
        }
        // The conversation titles and sender sets are in the Keychain (`NotificationState`).
        Keychain.deleteItems { $0.hasPrefix(KeyAccess.notifNamesPrefix) || $0.hasPrefix(KeyAccess.notifSendersPrefix) }
        // The one time readable before first unlock (`MuteFlagStore`).
        MuteFlagStore.wipe()
    }

    /// Defaults visible to both processes (falls back to the app's own).
    static let defaults: UserDefaults = {
        if groupURL != nil, let appGroup, let d = UserDefaults(suiteName: appGroup) { return d }
        return .standard
    }()
}

/// One process at a time may hold the encrypted cache open: it carries the Signal session state,
/// and two processes advancing the same ratchet would corrupt it.
///
/// - The APP must actually HOLD this lock before it opens a cache (`holdForApp`). If the
///   notification extension has it, the app asks it to yield and waits; it never opens the
///   cache without the lock.
/// - The EXTENSION only ever tries (`tryAcquire`) and gives up at once if the app has it. While
///   it holds the lock it watches for the app's yield request (`onYield` / `yieldRequested`):
///   it stops what it is doing, lets go of its client, and releases.
///
/// The lock is an advisory `flock` on a file in the shared container; the yield request is a
/// marker file beside it plus a Darwin notification (so a waiting extension reacts at once and
/// one that missed the notification still sees the marker between steps).
final class StoreLock {
    static let shared = StoreLock()
    static let yieldNotification = "io.skwod.store.yield"

    private var fd: Int32 = -1
    private let queue = DispatchQueue(label: "io.skwod.storelock")
    private var yieldHandler: (() -> Void)?
    private var observing = false
    /// Overrides where the lock lives (DEBUG checks on builds with no shared container).
    var directoryOverride: URL?

    init() {}

    private var directory: URL? { directoryOverride ?? SharedContainer.groupURL }
    private var path: String? { directory?.appendingPathComponent("store.lock").path }
    private var yieldPath: String? { directory?.appendingPathComponent("store.yield").path }

    /// Whether this process holds the lock right now. True when there is no shared container:
    /// no other process can reach the cache then.
    var isHeld: Bool { queue.sync { path == nil || fd >= 0 } }

    /// One attempt, no waiting. The extension's only way in.
    func tryAcquire() -> Bool { acquire(timeout: 0) }

    /// Take the lock, waiting up to `timeout` seconds. Returns true if held (or if there is no
    /// shared container, in which case no other process can touch the cache anyway).
    @discardableResult
    func acquire(timeout: TimeInterval = 0) -> Bool {
        queue.sync {
            guard let path else { return true }
            if fd >= 0 { return true }
            let handle = open(path, O_CREAT | O_RDWR, 0o600)
            guard handle >= 0 else { return false }
            let deadline = Date().addingTimeInterval(timeout)
            while true {
                if flock(handle, LOCK_EX | LOCK_NB) == 0 { fd = handle; return true }
                if Date() >= deadline { close(handle); return false }
                usleep(100_000)
            }
        }
    }

    func release() {
        queue.sync {
            guard fd >= 0 else { return }
            flock(fd, LOCK_UN)
            close(fd)
            fd = -1
        }
    }

    // MARK: The app's side

    /// Hold the lock for the app, asking the extension to yield for as long as it takes (up to
    /// `maxWait` — longer than the system ever lets an extension run). Returns whether the lock
    /// is held; the caller opens a cache ONLY on true.
    func holdForApp(maxWait: TimeInterval = 40) async -> Bool {
        if acquire(timeout: 0) { clearYieldRequest(); return true }
        let deadline = Date().addingTimeInterval(maxWait)
        StoreLockTrace.note("app_wait_started")
        while Date() < deadline {
            requestYield()
            if acquire(timeout: 0.4) {
                clearYieldRequest()
                StoreLockTrace.note("app_acquired_after_wait")
                return true
            }
            if Task.isCancelled { break }
        }
        return false
    }

    /// Tell whoever holds the lock that the app needs the cache now.
    private func requestYield() {
        guard let yieldPath else { return }
        if !FileManager.default.fileExists(atPath: yieldPath) {
            FileManager.default.createFile(atPath: yieldPath, contents: Data(String(Date().timeIntervalSince1970).utf8))
            StoreLockTrace.note("yield_requested")
        }
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(),
                                             CFNotificationName(Self.yieldNotification as CFString), nil, nil, true)
    }

    private func clearYieldRequest() {
        if let yieldPath { try? FileManager.default.removeItem(atPath: yieldPath) }
    }

    // MARK: The extension's side

    /// The app has asked for the cache (a marker younger than a minute — an old one is debris
    /// of a run that ended, not a request).
    var yieldRequested: Bool {
        guard let yieldPath, let text = try? String(contentsOfFile: yieldPath, encoding: .utf8),
              let at = Double(text) else { return false }
        return Date().timeIntervalSince1970 - at < 60
    }

    /// Call `handler` (once, on an arbitrary thread) when the app asks for the cache.
    func onYield(_ handler: @escaping () -> Void) {
        queue.sync { yieldHandler = handler }
        guard !observing else { return }
        observing = true
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), observer, { _, observer, _, _, _ in
            guard let observer else { return }
            Unmanaged<StoreLock>.fromOpaque(observer).takeUnretainedValue().fireYield()
        }, Self.yieldNotification as CFString, nil, .deliverImmediately)
    }

    private func fireYield() {
        let handler: (() -> Void)? = queue.sync {
            let h = yieldHandler
            yieldHandler = nil
            return h
        }
        handler?()
    }
}

/// Set (from any thread) when the app asks the extension for the cache.
final class YieldFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
    func set() { lock.lock(); value = true; lock.unlock() }
}

/// Step markers for the lock hand-over (DEBUG checks read them; a no-op otherwise). Never
/// content — only which step happened and when.
enum StoreLockTrace {
    private static let lock = NSLock()
    private static var events: [(String, Double)] = []
    static var enabled = false

    static func note(_ step: String) {
        guard enabled else { return }
        lock.lock(); defer { lock.unlock() }
        events.append((step, Date().timeIntervalSince1970))
    }

    static func snapshot() -> [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return events.map { ["step": $0.0, "at_ms": Int($0.1 * 1000)] }
    }
}

/// Where a skwod's mutes are kept (`MuteList`): on this device only, in the Keychain — so
/// encrypted at rest, `ThisDeviceOnly`, never in a backup, never sent anywhere — and in the
/// group the notification extension shares, under the classes `KeyAccess` gives them: the
/// conversation mutes are readable on a locked phone only where the extension decrypts at
/// all; the skwod's own mute (a time, nothing more) wherever it runs.
enum MuteStore {
    /// The skwod's own mute as stored: true/false, or nil when the item cannot be READ right
    /// now (the Keychain is locked). `WakeRule` does not take unreadable for muted.
    static func skwodMuted(workspaceId: String, now: TimeInterval) -> Bool? {
        let (raw, status) = Keychain.getWithStatus(KeyAccess.skwodMutePrefix + workspaceId)
        guard let raw else { return status == errSecItemNotFound ? false : nil }
        return WakeRule.holds(TimeInterval(raw), now: now)
    }

    static func load(workspaceId: String) -> MuteList {
        var until: [String: TimeInterval] = [:]
        if let json = Keychain.get(KeyAccess.mutesPrefix + workspaceId), let data = json.data(using: .utf8),
           let stored = try? JSONDecoder().decode([String: TimeInterval].self, from: data) {
            until = stored.filter { $0.key != MuteList.skwod }
        }
        if let raw = Keychain.get(KeyAccess.skwodMutePrefix + workspaceId), let t = TimeInterval(raw) { until[MuteList.skwod] = t }
        return MuteList(until: until)
    }

    static func save(_ list: MuteList, workspaceId: String) {
        guard !workspaceId.isEmpty else { return }
        let conversations = KeyAccess.mutesPrefix + workspaceId
        if list.conversations.isEmpty {
            Keychain.delete(conversations)
        } else if let data = try? JSONEncoder().encode(list.conversations), let json = String(data: data, encoding: .utf8) {
            Keychain.set(json, for: conversations, accessibility: Keychain.accessibility(for: conversations))
        }
        let skwod = KeyAccess.skwodMutePrefix + workspaceId
        if let t = list.skwodUntil {
            Keychain.set(String(t), for: skwod, accessibility: Keychain.accessibility(for: skwod))
        } else {
            Keychain.delete(skwod)
        }
        #if !SKWOD_EXTENSION
        MuteFlagStore.settle(signedInWorkspaceIds: WorkspaceStore.load().filter { !$0.isSignedOut }.map(\.id))
        #endif
    }
}

/// The ONE thing about mutes that is readable BEFORE the first unlock (a file with no file
/// protection): until when EVERY signed-in skwod is muted as a whole. A restarted phone nobody
/// has unlocked yet cannot read the Keychain — not the mutes, not even which skwods there are
/// — and only if all of them are muted may a wake be quiet then. It is a single time: not
/// which skwods this install is in, not how many, nothing about conversations. Written by
/// the app alone.
enum MuteFlagStore {
    private static var url: URL { (SharedContainer.groupURL ?? SharedContainer.privateURL).appendingPathComponent("mute-until") }
    /// A per-skwod flag an unreleased build 45 state kept ("has a muted conversation"). It
    /// decides nothing any more; whatever is left of it is deleted.
    private static let retiredPrefix = KeyAccess.retiredMuteConvsPrefix

    static func everySkwodMutedUntil() -> TimeInterval? {
        guard let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) else { return nil }
        return TimeInterval(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private static func write(_ until: TimeInterval?) {
        guard until != everySkwodMutedUntil() else { return }
        guard let until else { try? FileManager.default.removeItem(at: url); return }
        try? Data(String(until).utf8).write(to: url, options: [.atomic, .noFileProtection])
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var u = url
        try? u.setResourceValues(values)
    }

    /// Everything was deleted (factory reset, account deletion).
    static func wipe() {
        Keychain.deleteItems { $0.hasPrefix(retiredPrefix) }
        try? FileManager.default.removeItem(at: url)
    }

    /// Bring the time in step with the mutes of the skwods that are signed in (the app: at
    /// launch, whenever a mute changes, and when a skwod's data is deleted).
    static func settle(signedInWorkspaceIds ids: [String], now: TimeInterval = Date().timeIntervalSince1970) {
        Keychain.deleteItems { $0.hasPrefix(retiredPrefix) }
        write(WakeRule.everySkwodMutedUntil(ids.map { MuteStore.load(workspaceId: $0).skwodUntil }, now: now))
    }
}

/// What the notification extension needs to turn "New message" into something useful, written by
/// the app as it learns it: display names for conversations/channels, and a high-water mark so
/// the same message is never announced twice. Lives in the shared defaults.
///
/// These names are the user's own local labels; they never leave the device.
enum NotificationState {
    private static func key(_ workspaceId: String, _ what: String) -> String { "notif.\(workspaceId).\(what)" }

    /// Conversation titles and sender sets are the user's social graph. They are kept in the
    /// KEYCHAIN (encrypted at rest, this device only, in no backup), under the cache key's
    /// class — not in the shared defaults, a plain plist — and only while the extension may
    /// use them at all: with app lock on or previews off it never reads them, so they are not
    /// written and what was there is removed (`NotificationKeep`).
    private static func stored<T: Decodable>(_ account: String) -> T? {
        guard let json = Keychain.get(account) else { return nil }
        return try? JSONDecoder().decode(T.self, from: Data(json.utf8))
    }

    private static var lastWritten: [String: String] = [:]
    private static func store<T: Encodable>(_ value: T, account: String, legacyKey: String) {
        // What an earlier build left in the plist goes, whatever happens next.
        if SharedContainer.defaults.object(forKey: legacyKey) != nil { SharedContainer.defaults.removeObject(forKey: legacyKey) }
        guard NotificationKeep.keepsConversationLabels(appLock: appLockEnabled, previews: showPreviews) else {
            if lastWritten[account] != "" { Keychain.delete(account); lastWritten[account] = "" }
            return
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let data = try? encoder.encode(value), let json = String(data: data, encoding: .utf8) else { return }
        // (Written on every change of the lists: only when it actually differs.)
        guard lastWritten[account] != json else { return }
        if Keychain.set(json, for: account, accessibility: Keychain.accessibility(for: account)) { lastWritten[account] = json }
    }

    /// `scope` ("dm:<id>" / "channel:<id>") → display name.
    static func names(workspaceId: String) -> [String: String] {
        stored(KeyAccess.notifNamesPrefix + workspaceId) ?? [:]
    }

    static func setNames(_ names: [String: String], workspaceId: String) {
        store(names, account: KeyAccess.notifNamesPrefix + workspaceId, legacyKey: key(workspaceId, "names"))
    }

    /// `"dm:<id>"` → the accounts whose rows may be announced under that conversation's title
    /// (`NotificationSenders`). nil = the app has never written it (an update the app has not
    /// been opened after): the extension then announces no DM content at all.
    static func senders(workspaceId: String) -> [String: [String]]? {
        stored(KeyAccess.notifSendersPrefix + workspaceId)
    }

    static func setSenders(_ senders: [String: [String]], workspaceId: String) {
        store(senders, account: KeyAccess.notifSendersPrefix + workspaceId, legacyKey: key(workspaceId, "senders"))
    }

    static let conversationLabelsWanted = Notification.Name("skwod.notif.conversationLabelsWanted")

    /// App lock was turned on or previews off: the titles and sender sets every skwod left for
    /// the extension are removed now, not at the next change of a list (`NotificationKeep`).
    /// (Turned back: the app writes them again the next time its lists load.)
    static func dropConversationLabelsIfUnused() {
        guard !NotificationKeep.keepsConversationLabels(appLock: appLockEnabled, previews: showPreviews) else {
            // Wanted (again): the app writes them now, not at the next change of a list.
            lastWritten.removeAll()
            NotificationCenter.default.post(name: conversationLabelsWanted, object: nil)
            return
        }
        Keychain.deleteItems { $0.hasPrefix(KeyAccess.notifNamesPrefix) || $0.hasPrefix(KeyAccess.notifSendersPrefix) }
        lastWritten.removeAll()
        for key in SharedContainer.defaults.dictionaryRepresentation().keys
        where key.hasPrefix("notif.") && (key.hasSuffix(".names") || key.hasSuffix(".senders")) {
            SharedContainer.defaults.removeObject(forKey: key)
        }
    }

    /// A skwod's titles and sender sets are no longer kept (its data was deleted, or it was
    /// signed out of).
    static func forgetConversationLabels(workspaceId: String) {
        for account in [KeyAccess.notifNamesPrefix + workspaceId, KeyAccess.notifSendersPrefix + workspaceId] {
            Keychain.delete(account)
            lastWritten[account] = nil
        }
    }

    /// Ids a wake could not show and its generic banner stood for (`AnnouncedLedger.unsureLimit`).
    static func unsure(workspaceId: String) -> Set<String> {
        Set(SharedContainer.defaults.stringArray(forKey: key(workspaceId, "unsure")) ?? [])
    }

    static func markUnsure(_ ids: [String], workspaceId: String) {
        guard !workspaceId.isEmpty, !ids.isEmpty else { return }
        ledgerLocked {
            let k = key(workspaceId, "unsure")
            SharedContainer.defaults.synchronize()
            let existing = SharedContainer.defaults.stringArray(forKey: k) ?? []
            let ledger = AnnouncedLedger.adding(ids, to: existing, limit: AnnouncedLedger.unsureLimit)
            if ledger != existing { SharedContainer.defaults.set(ledger, forKey: k); SharedContainer.defaults.synchronize() }
        }
    }

    /// May this wake be followed up by connecting to the skwod's host (`WakeBudget`)?
    /// Recorded if so.
    static func spendWake(workspaceId: String, now: TimeInterval = Date().timeIntervalSince1970) -> Bool {
        ledgerLocked {
            let k = key(workspaceId, "wakes")
            SharedContainer.defaults.synchronize()
            let spent = WakeBudget.spend(history: SharedContainer.defaults.array(forKey: k) as? [Double] ?? [], now: now)
            SharedContainer.defaults.set(spent.history, forKey: k)
            return spent.allowed
        }
    }

    /// When the app last left the foreground (unix ms, THIS device's clock): rows dated at or
    /// before it were on screen or in the app's own notifications. Set by the app only — never
    /// from a row's `created_at`, which the server chooses (`AnnounceWindow`).
    static func highWater(workspaceId: String) -> Int64 {
        Int64(SharedContainer.defaults.double(forKey: key(workspaceId, "seen")))
    }

    static func setHighWater(_ ms: Int64, workspaceId: String) {
        if ms > highWater(workspaceId: workspaceId) {
            SharedContainer.defaults.set(Double(ms), forKey: key(workspaceId, "seen"))
        }
    }

    /// Ids of rows a push wake already looked at (`AnnounceWindow`), oldest first. Written by
    /// the extension only.
    static func seenIds(workspaceId: String) -> [String] {
        SharedContainer.defaults.stringArray(forKey: key(workspaceId, "seen-ids")) ?? []
    }

    static func setSeenIds(_ ids: [String], workspaceId: String) {
        SharedContainer.defaults.set(ids, forKey: key(workspaceId, "seen-ids"))
    }

    /// Message ids already notified about, by either process (`AnnouncedLedger`).
    static func announced(workspaceId: String) -> Set<String> {
        Set(SharedContainer.defaults.stringArray(forKey: key(workspaceId, "announced")) ?? [])
    }

    /// Claim `ids` for this process: the ones returned were announced by nobody yet and are
    /// now recorded — announce exactly those. Read-check-write under a file lock in the app
    /// group, so the app and the extension (two processes, defaults that sync late) cannot
    /// both take the same message.
    @discardableResult
    static func markAnnounced(_ ids: [String], workspaceId: String) -> [String] {
        guard !workspaceId.isEmpty, !ids.isEmpty else { return [] }
        return ledgerLocked {
            let k = key(workspaceId, "announced")
            SharedContainer.defaults.synchronize()
            let (claimed, ledger) = AnnouncedLedger.claim(ids, in: SharedContainer.defaults.stringArray(forKey: k) ?? [])
            if !claimed.isEmpty {
                SharedContainer.defaults.set(ledger, forKey: k)
                SharedContainer.defaults.synchronize()
            }
            return claimed
        }
    }

    /// `body` under an exclusive cross-process lock (a lock file next to the caches; held for
    /// microseconds, never across anything slow). Without a shared container there is only
    /// one process to speak of.
    private static let ledgerQueue = DispatchQueue(label: "io.skwod.notif.ledger")
    private static func ledgerLocked<T>(_ body: () -> T) -> T {
        ledgerQueue.sync {
            guard let path = SharedContainer.groupURL?.appendingPathComponent("announced.lock").path else { return body() }
            let fd = open(path, O_CREAT | O_RDWR, 0o600)
            guard fd >= 0 else { return body() }
            defer { flock(fd, LOCK_UN); close(fd) }
            flock(fd, LOCK_EX)
            return body()
        }
    }

    /// May a banner under `key` (a conversation — or, for a banner that cannot say which,
    /// the skwod's wake tag) make a sound right now? One per burst (`SoundBurst`); recorded
    /// if so.
    static func bannerSounds(key: String, now: TimeInterval = Date().timeIntervalSince1970) -> Bool {
        ledgerLocked {
            SharedContainer.defaults.synchronize()
            var last = SharedContainer.defaults.dictionary(forKey: "notif.soundAt") as? [String: Double] ?? [:]
            guard SoundBurst.sounds(lastSoundAt: last[key] ?? 0, now: now) else { return false }
            last = last.filter { now - $0.value < 3600 && $0.value <= now }
            last[key] = now
            SharedContainer.defaults.set(last, forKey: "notif.soundAt")
            return true
        }
    }

    /// Bumped by the extension whenever it wrote to a cache. The app compares it when it comes
    /// back to the foreground and re-opens the cache if it changed, so it never keeps working
    /// from state the extension has moved on from.
    static var storeGeneration: Int {
        get { SharedContainer.defaults.integer(forKey: "notif.storeGeneration") }
        set { SharedContainer.defaults.set(newValue, forKey: "notif.storeGeneration") }
    }

    /// Whether a relay may be used (mirrors the app's setting for the extension).
    static var publicFallback: Bool {
        get { SharedContainer.defaults.object(forKey: "notif.publicFallback") as? Bool ?? true }
        set { SharedContainer.defaults.set(newValue, forKey: "notif.publicFallback") }
    }

    /// App lock is ON (mirrors the app's setting for the extension, and for the app's own
    /// notifications while it is unlocked but not in front). With it on, no notification —
    /// from either process — shows who wrote or what: only "New message".
    static var appLockEnabled: Bool {
        get { SharedContainer.defaults.bool(forKey: "notif.appLockEnabled") }
        set {
            let changed = newValue != appLockEnabled
            SharedContainer.defaults.set(newValue, forKey: "notif.appLockEnabled")
            // With app lock on nothing reads the cache key on a locked phone: it goes back
            // to `WhenUnlocked` (and forward again when the lock is turned off) — `KeyAccess`.
            if changed { Keychain.reclassify(); dropConversationLabelsIfUnused() }
        }
    }

    /// Whether notifications may show decrypted text at all (user setting; default on).
    static var showPreviews: Bool {
        get { SharedContainer.defaults.object(forKey: "notif.showPreviews") as? Bool ?? true }
        set {
            let changed = newValue != showPreviews
            SharedContainer.defaults.set(newValue, forKey: "notif.showPreviews")
            // Previews off: the extension shows nothing decrypted, so it gets no key to
            // decrypt with on a locked phone either (`KeyAccess`).
            if changed { Keychain.reclassify(); dropConversationLabelsIfUnused() }
        }
    }
}
