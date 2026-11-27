import Foundation
import CryptoKit
import Security

/// One connected self-hosted server. skwod hosts nothing centrally — each friend runs their own
/// server, and joining it means holding a **fully isolated identity**: its own account/session, its
/// own device keypair, and its own encrypted cache. Being in three friends' servers = three
/// workspaces with three independent cryptographic identities, so a nosy host on one server learns
/// nothing that links you to another.
struct Workspace: Codable, Identifiable, Hashable {
    /// The skwod's STABLE address as persisted: `https://…` for a classic server, or
    /// `skwod://join/<node id>` for a p2p host. Never a loopback proxy URL — that changes every
    /// launch and is resolved at run time (`AppState.serverURL`).
    var server: String
    var userId: String
    var token: String
    var expiresAt: Int64
    var name: String          // display label (defaults to the server host)
    /// Stable, immutable id (cache/keys key). Set once at creation so the address can move without
    /// orphaning local data. nil for pre-pinning workspaces → falls back to the url hash on read.
    var localId: String? = nil
    /// The server's instance id (identity match key across address moves).
    var instanceId: String? = nil
    /// The server's pinned Ed25519 signing key (base64) — verified on every address change.
    var pinnedKey: String? = nil
    /// p2p hosts: the host's node id (z-base-32) — its address AND its pinned transport identity.
    /// nil for classic https servers.
    var nodeId: String? = nil
    /// p2p hosts that also have a domain (a VPS): its `https://` address — learned ONLY from the
    /// host's signed address record, fetched over the pinned p2p connection (never an invite's
    /// `?u=`). Offered when the host can't be reached by key; used only if it proves the pinned
    /// key for that address and the user agrees to switch.
    var fallbackURL: String? = nil
    /// `ts` of the last signed address record accepted for this skwod (a rollback floor). 0 =
    /// none yet — a `fallbackURL` stored before signed records existed is not trusted.
    /// (Optional so workspaces saved by earlier builds still decode.)
    var addressTs: Int64? = nil
    /// When `token` was issued or last rotated (unix ms). A token older than a week is swapped
    /// for a fresh one at launch (`rotateSession`). nil = stored by a build that did not record
    /// it, which counts as old. (Optional so earlier workspaces still decode.)
    var tokenIssuedAt: Int64? = nil
    /// The key a rotation of `token` was (or is about to be) asked with — stored BEFORE the request,
    /// dropped with the old token: with it a rotation whose answer was lost can be asked for again.
    var rotationKey: String? = nil
    /// A random tag made on this device and handed to this skwod when registering for push.
    /// The skwod passes it to the gateway, which returns it in the wake (`tag`), so the app
    /// knows WHICH skwod a contentless push is about — and no other skwod can claim the wake.
    /// It says nothing about the user or the skwod. nil until the first registration.
    var wakeTag: String? = nil
    /// The user named this entry themselves ("Rename…"): a name learned from the skwod never
    /// replaces it. (Optional so earlier workspaces still decode.)
    var nameSetByUser: Bool? = nil
    /// `name` is the skwod's own name as its owner set it on the host (`/api/instance/name`).
    /// Wins over a name guessed from its servers; a name the user set wins over both.
    var nameFromHost: Bool? = nil

    /// The server ended this workspace's session (it answered 401): the token was dropped and
    /// the user has to log in again. Everything else — keys, cache, the pinned server identity —
    /// is kept, so logging in picks up where they left off.
    var isSignedOut: Bool { token.isEmpty }

    var isP2P: Bool { nodeId != nil }

    /// This workspace's address in the shape the rest of the app passes around.
    var address: SkwodAddress {
        if let nodeId { return .p2p(nodeId: nodeId, fallbackURL: fallbackURL) }
        return .https(server)
    }

    /// Stable workspace id — the pinned localId, or (for older installs) the URL hash.
    var id: String { localId ?? Workspace.slug(for: server) }

    /// The name to show in headers/tiles. `name` is only ever the auto-default today, so always
    /// re-derive from the address — this keeps one source of truth and picks up naming fixes even
    /// for workspaces whose stored name predates them.
    ///
    /// Build 46: a name learned from the skwod itself (its first server's name, `learnName`) wins
    /// over the address-derived default — every p2p skwod used to be called "My skwod", so two
    /// entries (or two friends' skwods) were indistinguishable in the rail.
    var displayName: String {
        let learned = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !learned.isEmpty, !Workspace.isDefaultName(learned) { return learned }
        return Workspace.defaultName(for: server)
    }

    /// What no server can fake, shown beside the name: the host key's short form for a p2p
    /// skwod (as safety numbers are compared), the domain for a classic server.
    var identityCue: String {
        if let nodeId { return String(nodeId.prefix(4)).uppercased() + "…" + String(nodeId.suffix(4)).uppercased() }
        return URL(string: server)?.host ?? server
    }

    /// The names `defaultName` hands out (never a name the skwod told us).
    static func isDefaultName(_ s: String) -> Bool {
        ["my skwod", "skwod"].contains(s.lowercased())
    }


    /// A short deterministic slug for a server URL, used for the id and cache filename.
    static func slug(for server: String) -> String {
        let digest = SHA256.hash(data: Data(server.utf8))
        return digest.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// The host portion, for a friendly default name (chat.myfriend.com → "myfriend.com").
    static func defaultName(for server: String) -> String {
        // A p2p address is a key, not a name.
        if server.hasPrefix("skwod:") { return "My skwod" }
        guard let host = URL(string: server)?.host, !host.isEmpty else { return "My Skwod" }
        // This Mac hosting connects over localhost / a raw LAN IP — those have no friendly domain, so
        // taking "the last two labels" yields junk like "0.1". Give them a real name instead.
        if host == "localhost" || host.hasSuffix(".local") || host.contains(":") { return "My skwod" }
        let parts = host.split(separator: ".")
        let isIPv4 = parts.count == 4 && parts.allSatisfy { $0.allSatisfy(\.isNumber) }
        if isIPv4 { return "My Skwod" }
        return parts.count > 2 ? parts.suffix(2).joined(separator: ".") : host
    }
}

/// Persistence for the set of workspaces + which one is active. The tokens are secrets, so the whole
/// set lives in the Keychain (not UserDefaults).
enum WorkspaceStore {
    private static let account = "workspaces"
    private static let currentKey = "current-workspace"

    static func load() -> [Workspace] {
        guard let json = Keychain.get(account), let data = json.data(using: .utf8),
              let list = try? JSONDecoder().decode([Workspace].self, from: data) else { return [] }
        return list
    }

    /// The stored set, or nil when the Keychain cannot be READ right now (before the first
    /// unlock after a restart) — which is not "no workspaces". For callers that must not take
    /// "unreadable" for "nothing there" (`WakeRule`).
    static func loadIfReadable() -> [Workspace]? {
        let (json, status) = Keychain.getWithStatus(account)
        guard let json else { return status == errSecItemNotFound ? [] : nil }
        // Stored but not decodable is "unknown" too — never "no skwods".
        guard let data = json.data(using: .utf8), let list = try? JSONDecoder().decode([Workspace].self, from: data) else { return nil }
        return list
    }

    /// Whether it was written (the Keychain can refuse: locked, busy).
    @discardableResult
    static func save(_ list: [Workspace]) -> Bool {
        if let data = try? JSONEncoder().encode(list), let json = String(data: data, encoding: .utf8) {
            // The bearer/sync tokens live in this blob and the background inbox-sync loop reads them
            // while the device is backgrounded/locked, so this one item stays AfterFirstUnlock.
            return Keychain.set(json, for: account, accessibility: .afterFirstUnlock)
        }
        return false
    }

    static var currentId: String? {
        get { UserDefaults.standard.string(forKey: currentKey) }
        set { UserDefaults.standard.set(newValue, forKey: currentKey) }
    }
}

/// A skwod address the user has connected to before — NO credentials, tokens, or keys, just the
/// public address + its display name. Kept across sign-out so the login screen can offer "log back
/// into X" without re-pasting the URL. Addresses are not secret (they're what you paste to join).
struct KnownServer: Codable, Identifiable, Hashable {
    var address: String
    var name: String
    var id: String { address }
}

/// Remembers addresses the user has used, surviving sign-out. Stored in UserDefaults (not the
/// Keychain) precisely because it holds nothing sensitive — only public server addresses + names.
enum KnownServerStore {
    private static let key = "known-servers"

    static func all() -> [KnownServer] {
        guard let data = UserDefaults.standard.data(forKey: key),
              let list = try? JSONDecoder().decode([KnownServer].self, from: data) else { return [] }
        return list
    }

    /// Record an address (dedup by address; most-recent first). Called on successful sign-in.
    static func remember(address: String, name: String) {
        let addr = address.trimmingCharacters(in: .whitespaces)
        guard !addr.isEmpty else { return }
        var list = all().filter { $0.address != addr }
        list.insert(KnownServer(address: addr, name: name), at: 0)
        if let data = try? JSONEncoder().encode(Array(list.prefix(10))) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    static func forget(address: String) {
        let list = all().filter { $0.address != address }
        if let data = try? JSONEncoder().encode(list) { UserDefaults.standard.set(data, forKey: key) }
    }
}
