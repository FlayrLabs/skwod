import Foundation
import CryptoKit

// One skwod never reaches into another: the rules that keep a workspace's base URL, session,
// files and server answers its own. Foundation only (the logic tests and the notification
// extension compile this file).

/// The base URL a workspace is reached through right now, held WITH the workspace it was
/// resolved for — one value, like `BoundClient`. Switching skwods changes "the current
/// workspace" first and dials the new host afterwards (seconds, for a p2p host); a base URL
/// kept on its own would, for that long, still be the PREVIOUS skwod's while the session token
/// is already the new one's, and any request built in between would hand the new skwod's
/// token to the old skwod's server.
struct LiveBase: Equatable {
    let workspaceId: String
    let url: String

    /// The base URL to use for `currentWorkspaceId`: only one resolved for exactly that
    /// workspace. Anything else is "" — "unreachable", which every caller already treats as
    /// "send nothing".
    static func url(_ live: LiveBase?, for currentWorkspaceId: String?) -> String {
        guard let live, let currentWorkspaceId, live.workspaceId == currentWorkspaceId else { return "" }
        return live.url
    }
}

/// A workspace id becomes part of a file name (the encrypted cache), and for a new skwod it is
/// the instance id the SERVER reports at sign-up. A server's string is never a path: an id is
/// used as given only if it is plain (letters, digits, hyphens — what every id this app ever
/// made looks like: a 16- or 32-hex hash, or a UUID), so it cannot name a file in another
/// directory or another skwod's cache through `..` or `/`.
enum WorkspaceIdRule {
    static let maxLength = 64

    /// ASCII letters, digits and `-` only, 1…64 characters.
    static func isSafe(_ id: String) -> Bool {
        guard !id.isEmpty, id.utf8.count <= maxLength else { return false }
        return id.utf8.allSatisfy { c in
            (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || c == 0x2D
        }
    }

    /// The instance id a server reported, if it may be kept and matched against at all.
    static func acceptedInstanceId(_ reported: String?) -> String? {
        guard let reported, isSafe(reported) else { return nil }
        return reported
    }

    /// What stands for `id` inside a file name. A plain id is itself (existing caches keep
    /// their names); anything else is replaced by a hash of it — never used as written.
    static func fileComponent(for id: String) -> String {
        if isSafe(id) { return id }
        let digest = SHA256.hash(data: Data(id.utf8))
        return "x-" + digest.prefix(16).map { String(format: "%02x", $0) }.joined()
    }
}

/// What was bound when a server was asked something: the workspace and the bind turn of the
/// client that was asked. A server may hold its answer while the user switches skwods; the
/// answer is written only while the same two are still current (the non-conversation
/// counterpart of `StoreTicket`: sidebar, roster, feed channels, avatars, device state).
struct BindTicket: Equatable {
    let workspaceId: String
    let turn: Int

    /// nil when no client is bound: there is nobody to ask and nowhere to write.
    init?(workspaceId: String?, turn: Int?) {
        guard let workspaceId, let turn else { return nil }
        self.workspaceId = workspaceId
        self.turn = turn
    }

    func isCurrent(workspaceId: String?, turn: Int?) -> Bool {
        workspaceId == self.workspaceId && turn == self.turn
    }
}

/// Which live events are listened to at all: only those on a topic this client asked for.
/// A server that pushes an event on any other topic (another user's, a channel this device
/// never subscribed to) is not obeyed.
enum RealtimeTopicRule {
    static func accepts(topic: String, wanted: Set<String>) -> Bool { wanted.contains(topic) }
}

/// What a live channel event may make this device DO. The relay is the server's word: it can
/// say "look again", and that is all. In particular `channel_cleared` never deletes anything
/// here — local, decrypted history is this device's, and an unsigned event from the server is
/// not an order to destroy it (a clear the USER makes on this device empties it directly).
enum ChannelEventRule {
    enum Action: Equatable {
        /// Refresh what is on screen, and consider a notification for the message.
        case refreshAndConsiderNotifying
        /// Refresh what is on screen. Nothing stored is changed by the event itself.
        case refresh
        case ignore
    }

    static func action(for event: String) -> Action {
        switch event {
        case "message": return .refreshAndConsiderNotifying
        case "message_update", "message_delete", "reaction", "channel_cleared": return .refresh
        default: return .ignore
        }
    }
}

/// When an invite's host may be contacted BEFORE the user submits the join form. Contacting it
/// reveals this device's IP address (and that Skwod is installed) to whoever wrote the link.
/// A link the user scanned or pasted in the app is theirs to check; a link that arrived from
/// outside — one tap on a web page or in a message — is not, until they submit.
enum InviteDialRule {
    enum Source: Equatable {
        /// A `skwod://` or https invite opened from outside the app.
        case outsideLink
        /// Scanned, pasted or picked by the user inside the app.
        case userAction
    }

    static func mayDialBeforeSubmit(_ source: Source) -> Bool { source == .userAction }

    /// The "is this a skwod you are already in?" probe of a typed https address: never for
    /// text that is still exactly what an outside link put there.
    static func mayProbe(entry: String, outsideEntry: String?) -> Bool {
        guard let outsideEntry, !outsideEntry.isEmpty else { return true }
        return entry.trimmingCharacters(in: .whitespacesAndNewlines) != outsideEntry
    }
}

/// App lock's own settings (Apple A12). They were plain preferences: on a Mac one
/// `defaults write` turned the lock off. They are now a Keychain item of the app's, and what
/// is read decides like this — failing LOCKED:
/// - the stored item: what it says;
/// - no item yet (an install from before): what the old preference said, moved into the item;
/// - an item that is there but cannot be read or understood: the lock is ON.
struct AppLockSetting: Codable, Equatable {
    var enabled: Bool
    var afterSeconds: Int

    static let defaultDelay = 60

    enum Stored: Equatable {
        case value(String)
        case absent
        case unreadable
    }

    /// `migrate`: write the result back (it came from the old preference).
    static func resolve(stored: Stored, legacyEnabled: Bool, legacyDelay: Int?) -> (setting: AppLockSetting, migrate: Bool) {
        switch stored {
        case .value(let json):
            if let setting = try? JSONDecoder().decode(AppLockSetting.self, from: Data(json.utf8)) { return (setting, false) }
            return (AppLockSetting(enabled: true, afterSeconds: 0), false)
        case .absent:
            return (AppLockSetting(enabled: legacyEnabled, afterSeconds: legacyDelay ?? defaultDelay), true)
        case .unreadable:
            return (AppLockSetting(enabled: true, afterSeconds: 0), false)
        }
    }

    var encoded: String? { (try? JSONEncoder().encode(self)).flatMap { String(data: $0, encoding: .utf8) } }

    /// Changing "Lock after" to something LATER weakens the lock, like turning it off: the
    /// user authenticates first. Making it stricter needs nothing.
    static func delayChangeNeedsAuthentication(from old: Int, to new: Int) -> Bool { new > old }
}

/// Where a decrypted attachment is kept for a while (Apple A14). The blob id and the name are
/// the SENDER's; two messages can carry the same pair with different keys and digests, and a
/// copy decrypted for one must never be handed back for the other. So the file's name also
/// carries what the message says the content is: a short hash of its digest and key.
enum AttachmentCacheName {
    static func contentTag(digestB64: String?, keyB64: String) -> String {
        let digest = SHA256.hash(data: Data(((digestB64 ?? "") + "|" + keyB64).utf8))
        return digest.prefix(6).map { String(format: "%02x", $0) }.joined()
    }

    /// `blobId` and `safeName` are already path-safe (`isSafeBlobId`, `safeFileName`).
    static func fileName(blobId: String, digestB64: String?, keyB64: String, safeName: String) -> String {
        "\(blobId)-\(contentTag(digestB64: digestB64, keyB64: keyB64))-\(safeName)"
    }
}

/// Which images someone else chose are decoded at all (Apple A15). ImageIO reads dozens of
/// formats — TIFF, PSD, camera RAW, ICNS, PDF-backed ones — each a parser fed by a stranger.
/// Only what phones and the app itself produce is decoded, and nothing above what a phone
/// camera makes.
enum InboundImageRule {
    /// Uniform type identifiers accepted from others.
    static let allowedTypes: Set<String> = [
        "public.jpeg", "public.png", "public.heic", "public.heif", "com.compuserve.gif", "org.webmproject.webp",
    ]
    /// ≈ 50 MP: a 48 MP phone photo (8064 × 6048) passes; nothing larger is opened.
    static let maxPixels = 50_000_000

    static func allowed(typeIdentifier: String?) -> Bool {
        guard let typeIdentifier else { return false }
        return allowedTypes.contains(typeIdentifier)
    }

    static func plausible(width: Int, height: Int) -> Bool {
        width > 0 && height > 0 && width <= 65_535 && height <= 65_535 && width * height <= maxPixels
    }
}
