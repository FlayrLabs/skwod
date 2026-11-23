import Foundation
import Security

/// Minimal Keychain wrapper for the secrets the client persists: the auth session, the 32-byte key
/// that encrypts the on-device SQLCipher cache, and (on a Mac host) the owner login. Every item
/// is `ThisDeviceOnly` — never synced to iCloud, never leaving the device. Accessibility is chosen per
/// item by `KeyAccess` (`accessibility(for:)`): `AfterFirstUnlock` only where something must
/// read the item on a locked phone — the workspace list, and (iOS, app lock off, previews on)
/// the cache key the notification extension decrypts with; everything else `WhenUnlocked`.
enum Keychain {
    private static let service = "io.skwod.client" + Profile.suffix(".")

    /// When a stored item may be read back. Both are `ThisDeviceOnly` (non-synced).
    enum Accessibility {
        /// Readable only while the device is unlocked.
        case whenUnlocked
        /// Readable after the first post-boot unlock, even while subsequently locked — the
        /// session and the cache key, which a notification that arrives on a locked phone needs.
        case afterFirstUnlock

        var attr: CFString {
            switch self {
            case .whenUnlocked: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }
        }
    }

    /// The class an item is stored under. One rule, used when an item is made, moved or
    /// re-classified.
    static func accessibility(for account: String) -> Accessibility {
        #if os(iOS)
        let platform = KeyAccess.Platform.iOS
        #else
        let platform = KeyAccess.Platform.macOS
        #endif
        let settings = KeyAccess.Settings(appLock: NotificationState.appLockEnabled, previews: NotificationState.showPreviews)
        switch KeyAccess.accessibility(for: account, settings: settings, platform: platform) {
        case .afterFirstUnlock: return .afterFirstUnlock
        case .whenUnlocked: return .whenUnlocked
        }
    }

    // MARK: where items live

    /// Which keychain this build can use.
    ///
    /// - iOS: always the data-protection keychain (there is no other). Items go into the access
    ///   group shared with the notification extension when the build is entitled to it.
    /// - macOS: the **data-protection keychain** (`kSecUseDataProtectionKeychain`) — per-app,
    ///   honours the accessibility class, and is not readable by other processes of the same user
    ///   the way login-keychain items can be made to be. It needs the `keychain-access-groups`
    ///   entitlement, which only a properly signed build has. A build without it (local,
    ///   unsigned/ad-hoc) gets `errSecMissingEntitlement`; such a build falls back to the login
    ///   keychain so it stays usable for development, and says so in Profile → Encryption.
    enum Backing: Equatable { case dataProtection, loginKeychain }

    static let backing: Backing = {
        #if os(macOS)
        return probe(group: nil) ? .dataProtection : .loginKeychain
        #else
        return .dataProtection
        #endif
    }()

    /// The access group shared between the app and its notification service extension
    /// (`SkwodKeychainGroup` in Info.plist = `$(AppIdentifierPrefix)<group>`), or nil when the
    /// build isn't entitled to it (simulator builds without signing, macOS).
    static let sharedGroup: String? = {
        #if os(iOS)
        guard let g = Bundle.main.object(forInfoDictionaryKey: "SkwodKeychainGroup") as? String,
              !g.isEmpty, !g.hasPrefix("$("), !g.hasPrefix(".") else { return nil }
        return probe(group: g) ? g : nil
        #else
        return nil
        #endif
    }()

    /// Can we add an item with these attributes? (Adds and removes a throwaway item.)
    private static func probe(group: String?) -> Bool {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "probe",
            kSecUseDataProtectionKeychain as String: true,
        ]
        if let group { q[kSecAttrAccessGroup as String] = group }
        SecItemDelete(q as CFDictionary)
        var add = q
        add[kSecValueData as String] = Data([0])
        // AfterFirstUnlock: the notification extension asks this on a LOCKED phone too, and a
        // WhenUnlocked probe would answer "no shared keychain" there.
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        SecItemDelete(q as CFDictionary)
        return status == errSecSuccess
    }

    /// The attributes that identify one of our items in the keychain this build uses.
    private static func base(_ account: String, legacy: Bool = false) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if !legacy, backing == .dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    @discardableResult
    static func set(_ value: String, for account: String,
                    accessibility: Accessibility = .whenUnlocked) -> Bool {
        let data = Data(value.utf8)
        // An item that exists is UPDATED in place (value and class together, as `reclassify`
        // does) — never deleted first: a delete followed by an add that fails (the device
        // locked in between, the keychain busy) would lose the item, and for a cache key that
        // is the cache. Only when there is nothing to update is one added.
        let update: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: accessibility.attr]
        let updated = SecItemUpdate(base(account) as CFDictionary, update as CFDictionary)
        if updated == errSecSuccess { return true }
        guard updated == errSecItemNotFound else { return false }
        var attrs = base(account)
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = accessibility.attr
        if let sharedGroup { attrs[kSecAttrAccessGroup as String] = sharedGroup }
        return SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
    }

    static func get(_ account: String) -> String? {
        getWithStatus(account).value
    }

    /// Like `get`, but surfaces the Keychain status so callers can tell "item doesn't exist"
    /// (errSecItemNotFound) apart from transient failures (locked keychain, auth denied) — the
    /// difference matters when the caller would otherwise mint-and-overwrite a key.
    static func getWithStatus(_ account: String) -> (value: String?, status: OSStatus) {
        read(base(account))
    }

    private static func read(_ identity: [String: Any]) -> (value: String?, status: OSStatus) {
        var query = identity
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess,
              let data = out as? Data, let s = String(data: data, encoding: .utf8) else { return (nil, status) }
        return (s, status)
    }

    static func delete(_ account: String) {
        SecItemDelete(base(account) as CFDictionary)
        #if os(macOS)
        // Also sweep a copy an older build may have left in the login keychain.
        if backing == .dataProtection { SecItemDelete(base(account, legacy: true) as CFDictionary) }
        #endif
    }

    /// One-time moves, run at launch before anything is read:
    ///
    /// - macOS: builds ≤ 40 kept everything in the **login keychain**. Move each item into the
    ///   data-protection keychain and delete the original. Only when this build can use the
    ///   data-protection keychain; a failed copy leaves the original in place (nothing is lost).
    /// - iOS: re-save items into the access group shared with the notification extension.
    static func migrateLegacyItems() {
        #if os(macOS)
        guard backing == .dataProtection else { return }
        let list: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var out: AnyObject?
        guard SecItemCopyMatching(list as CFDictionary, &out) == errSecSuccess,
              let items = out as? [[String: Any]] else { return }
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String, account != "probe" else { continue }
            let legacy = base(account, legacy: true)
            guard let value = read(legacy).value else { continue }
            if read(base(account)).value != nil || set(value, for: account, accessibility: accessibility(for: account)) {
                SecItemDelete(legacy as CFDictionary)
            }
        }
        #else
        guard let sharedGroup else { return }
        let list: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var out: AnyObject?
        guard SecItemCopyMatching(list as CFDictionary, &out) == errSecSuccess,
              let items = out as? [[String: Any]] else { return }
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String,
                  (item[kSecAttrAccessGroup as String] as? String) != sharedGroup,
                  let value = get(account) else { continue }
            set(value, for: account, accessibility: accessibility(for: account))
        }
        #endif
    }

    /// Bring the cache keys to the class `accessibility(for:)` gives them NOW — in either
    /// direction: to `AfterFirstUnlock` when the notification extension may decrypt for a
    /// banner (iOS, app lock off, previews on; build 44 kept them `WhenUnlocked`, so a
    /// notification on a locked phone could never say more than "New message"), back to
    /// `WhenUnlocked` the moment app lock is turned on or previews are turned off. Run at
    /// launch and whenever one of those two settings changes. The class is changed IN PLACE
    /// (`SecItemUpdate`): the item is never deleted and re-added, so a failure — the device
    /// is locked right now, say — leaves the key exactly as it was, and the next launch tries
    /// again (a key that could not be moved to the stricter class stays readable to the
    /// extension until then — which, with app lock on or previews off, does not read it).
    /// Nothing becomes `Always`, nothing loses `ThisDeviceOnly`.
    static func reclassify() {
        var list: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        if backing == .dataProtection { list[kSecUseDataProtectionKeychain as String] = true }
        var out: AnyObject?
        guard SecItemCopyMatching(list as CFDictionary, &out) == errSecSuccess,
              let items = out as? [[String: Any]] else { return }
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String, KeyAccess.moves(account) else { continue }
            let wanted = accessibility(for: account).attr
            guard (item[kSecAttrAccessible as String] as? String) != (wanted as String) else { continue }
            SecItemUpdate(base(account) as CFDictionary, [kSecAttrAccessible as String: wanted] as CFDictionary)
        }
    }

    /// Delete every item of ours whose account `matches` (the app's own per-skwod items that
    /// are kept under a prefix; never anything of another service).
    static func deleteItems(matching matches: (String) -> Bool) {
        for account in accounts(matching: matches) { delete(account) }
    }

    /// The accounts of our items that `matches`.
    static func accounts(matching matches: (String) -> Bool) -> [String] {
        var list: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        if backing == .dataProtection { list[kSecUseDataProtectionKeychain as String] = true }
        var out: AnyObject?
        guard SecItemCopyMatching(list as CFDictionary, &out) == errSecSuccess,
              let items = out as? [[String: Any]] else { return [] }
        return items.compactMap { $0[kSecAttrAccount as String] as? String }.filter(matches)
    }

    /// The cache-encryption key (64 hex chars), generated once and reused. It is the ONLY thing
    /// protecting the SQLCipher cache, which holds the libsignal identity, sessions and sender keys
    /// as well as decrypted history. A `ThisDeviceOnly` Keychain item — never synced, never in
    /// backups — `WhenUnlocked`, except on an iPhone whose notifications may show message text
    /// (app lock off, previews on): there it is `AfterFirstUnlock`, the class Signal uses for
    /// its database key, so a notification on a locked phone can say who wrote and what
    /// (`KeyAccess`). Keyed per workspace so each self-hosted server's cache is encrypted
    /// under its own independent key.
    ///
    /// Returns nil when the Keychain read fails TRANSIENTLY (locked keychain, auth denied): minting
    /// a replacement key then would overwrite the only key that can decrypt the existing cache —
    /// silent, permanent data loss. Callers treat nil as "cache unavailable right now", not "make
    /// me a new cache". A key is minted when the item is confirmed absent, or when a read-back
    /// value is malformed — a corrupt key can't decrypt anything anyway, so re-minting loses
    /// nothing, while refusing would wedge the workspace forever.
    static func cacheKeyHex(for workspaceId: String) -> String? {
        let account = "cache-key-\(workspaceId)"
        let (existing, status) = getWithStatus(account)
        if let existing, existing.count == 64 { return existing }
        guard status == errSecItemNotFound || status == errSecSuccess else { return nil }
        var bytes = [UInt8](repeating: 0, count: 32)
        // A failed RNG call must never yield an all-zero (i.e. publicly known) database key, and a
        // key that could not be stored must never be used: the cache would be unreadable next launch.
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        guard set(hex, for: account, accessibility: accessibility(for: account)) else { return nil }
        return hex
    }
}
