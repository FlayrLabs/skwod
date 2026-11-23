import Foundation

/// Which actions the long-press / right-click menus of a SERVER and of a SKWOD offer. Only what
/// the user may actually do is listed (Foundation only: the logic tests compile it).
///
/// The two levels: a **skwod** is the host (one self-hosted instance, the switcher's tiles); it
/// contains **servers** (groups of people), which contain **channels**.
enum ServerRole: Equatable {
    /// Created the server: the only one who may delete it, and who can never leave it (the
    /// server refuses "the owner cannot be removed; delete the server instead").
    case owner
    /// May manage it (roles / permissions), but not delete it.
    case admin
    case member
}

enum ServerMenuItem: Equatable, CaseIterable {
    /// `leaveUnverified`: Leave, behind a warning — no owner is pinned on this device, so it
    /// can't tell whether this account owns the server.
    case mute, invite, settings, copyLink, leave, leaveUnverified, delete
}

/// Who owns a server, as far as this device may say: the owner PINNED by the core
/// (`spaceOwner`) decides; the host's `owner_id` is only a hint, used when it agrees.
enum ServerOwnership: Equatable {
    case me, someoneElse, unknown

    static func decide(me: String, pinned: String?, hostSays: String?) -> ServerOwnership {
        guard let pinned, !pinned.isEmpty else { return .unknown }
        _ = hostSays   // a disagreeing host changes nothing: the pinned owner is the boundary
        return pinned == me ? .me : .someoneElse
    }
}

enum ServerMenuRule {
    /// `channelsKnown`: the server has a channel on this device (invites and mutes act on its
    /// channels). There is no per-channel "unread" state on this device yet, so no "Mark as read".
    static func items(role: ServerRole, channelsKnown: Bool, ownerPinned: Bool = true) -> [ServerMenuItem] {
        var out: [ServerMenuItem] = []
        if channelsKnown { out += [.mute, .invite] }
        if role != .member { out.append(.settings) }
        out.append(.copyLink)
        // The (pinned) owner deletes and never leaves (leaving forgets the keys); everyone else
        // leaves. With no pinned owner, only a Leave that warns first.
        if role == .owner { out.append(.delete) } else { out.append(ownerPinned ? .leave : .leaveUnverified) }
        return out
    }
}

enum SkwodMenuItem: Equatable, CaseIterable {
    case logInAgain, rename, renameOnHost, invite, mute, settings, devices, signOut, removeDuplicate, removeFromDevice
}

enum SkwodMenuRule {
    /// - `isCurrent`: the skwod on screen (its client is up: invite, devices, settings act on it).
    /// - `isInstanceOwner`: this account runs the skwod (its settings: accounts, clear-all).
    /// - `isDuplicate`: another entry is the same skwod and account (`WorkspaceDedupe`).
    static func items(signedOut: Bool, isCurrent: Bool, isInstanceOwner: Bool, isDuplicate: Bool) -> [SkwodMenuItem] {
        var out: [SkwodMenuItem] = []
        if signedOut { out.append(.logInAgain) }
        // "Rename…" is this device's own label; the instance owner can also name the skwod on
        // its host (build 46, device-signed), which every member then sees.
        out.append(.rename)
        if !signedOut && isCurrent && isInstanceOwner { out.append(.renameOnHost) }
        if !signedOut {
            if isCurrent { out.append(.invite) }
            out.append(.mute)
            if isCurrent && isInstanceOwner { out.append(.settings) }
            if isCurrent { out.append(.devices) }
            out.append(.signOut)
        }
        if isDuplicate { out.append(.removeDuplicate) }
        // Deleting this device's copy needs no server, so only once signed out of it (as before).
        if signedOut { out.append(.removeFromDevice) }
        return out
    }
}

/// Whose composer a paste or drop belongs to. Each is tagged with the conversation it started
/// in; a result that arrives after a switch (or from a surface with no conversation id) is
/// dropped, never staged in another conversation.
enum StagingRule {
    static func belongs(startedFor: String, current: String) -> Bool {
        !startedFor.isEmpty && startedFor == current
    }
}

/// This account's role in a server, from what the server lists: its owner id, the member's
/// role ids and the server's roles. Admin = any of its roles (or @everyone) grants
/// Administrator, Manage Server or Manage Roles. The server enforces every action itself; this
/// only decides which menu items are offered.
enum ServerRoleRule {
    static let manageRoles: Int64 = 2
    static let manageServer: Int64 = 4
    static let administrator: Int64 = 8192
    static let mentionEveryone: Int64 = 16384

    struct Role: Equatable { var id: String; var permissions: Int64; var isDefault: Bool }

    static func permissions(myRoleIds: [String], roles: [Role]) -> Int64 {
        roles.filter { $0.isDefault || myRoleIds.contains($0.id) }.reduce(0) { $0 | $1.permissions }
    }

    /// What counts for the @everyone gate (`EveryoneRule`): only roles the server ASSIGNED to
    /// the member. The default (@everyone) role is everybody's, so its bits never make anyone an
    /// admin there — a host granting it Administrator does not let every member alert everyone.
    static func everyonePermissions(memberRoleIds: [String], roles: [Role]) -> Int64 {
        roles.filter { !$0.isDefault && memberRoleIds.contains($0.id) }.reduce(0) { $0 | $1.permissions }
    }

    static func role(me: String, ownerId: String?, myRoleIds: [String], roles: [Role]) -> ServerRole {
        if let ownerId, ownerId == me { return .owner }
        let p = permissions(myRoleIds: myRoleIds, roles: roles)
        return p & (administrator | manageServer | manageRoles) != 0 ? .admin : .member
    }
}

/// `GET /api/servers` → server id → owner id. The host names each server `server_id` (Android's
/// `ServerList.owners` reads the same). Anything malformed — a row without a `server_id`, not
/// JSON — is nil, and then NOTHING is pruned: only a complete answer may drop servers.
enum ServerListRule {
    static func owners(_ data: Data) -> [String: String]? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let list = obj["servers"] as? [[String: Any]] else { return nil }
        var out: [String: String] = [:]
        for row in list {
            guard let id = row["server_id"] as? String, !id.isEmpty else { return nil }
            out[id] = row["owner_id"] as? String ?? ""
        }
        return out
    }
}
