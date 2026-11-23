import SwiftUI
import ImageIO
#if os(iOS)
import UIKit
#else
import AppKit
#endif

/// End-to-end-encrypted avatars for users, servers, and the skwod (instance) — profile pics and
/// icons. An avatar is a small square JPEG carried, base64-encoded, inside a `skwod/avatar|` tagged
/// channel message: it rides the same Sender-Key E2EE path as every other message, so the server
/// only ever sees ciphertext. Being embedded (not a blob) means zero extra round-trips and instant
/// display. The pointer is broadcast to every channel the setter is in, so wherever a member looks
/// the latest avatar is present in history; the store keeps the newest by timestamp.
///
/// Keys: `user:<userId>` · `server:<serverId>` · `skwod:<instanceId>`.
@MainActor
final class AvatarStore: ObservableObject {
    static let tag = "\u{2}skwod/avatar|"
    /// Square JPEG side + quality: small enough to embed in a message, sharp enough for 96pt tiles.
    static let side = 256
    static let quality: CGFloat = 0.6

    /// avatarKey → (image data, source timestamp). Newest wins.
    @Published private(set) var images: [String: (data: Data, ts: Int64)] = [:]
    /// The newest timestamp SEEN per key, including for cleared avatars (a tombstone). Keeps an old
    /// pointer arriving after a clear from resurrecting the removed image.
    private var seenTs: [String: Int64] = [:]
    /// Max cached avatars — bounds memory as members / ex-members accumulate. When exceeded, the
    /// least-recently-touched entries are evicted (my own + currently-referenced keys are safe
    /// because they're re-ingested constantly).
    private static let maxCached = 400

    private weak var app: AppState?
    private var loadedFor: String?

    func bind(_ app: AppState) { self.app = app }

    static func userKey(_ userId: String) -> String { "user:\(userId)" }
    static func serverKey(_ serverId: String) -> String { "server:\(serverId)" }
    /// (Through `safe_instance_id`: a stored or reported id is a key here, so it is the same
    /// plain value on every platform — a plain id is itself.)
    static func skwodKey(_ instanceId: String) -> String { "skwod:\(safeInstanceId(raw: instanceId))" }

    func data(for key: String) -> Data? { images[key]?.data }

    /// The per-workspace kv key — namespaced so avatars from different skwods never mix (the sidebar
    /// cache is namespaced the same way).
    private var kvKey: String { "\(app?.current?.id ?? "")|avatars" }

    // MARK: Persistence (per-workspace encrypted kv cache)

    /// Load cached avatars for the active workspace (survives relaunch, no re-fetch needed).
    func loadIfNeeded() async {
        guard let app, let wid = app.current?.id, loadedFor != wid,
              let bound = app.bound, bound.workspaceId == wid, bound.cacheOpen else { return }
        // STRICT read: one that fails is not "no avatars". Nothing is marked loaded then — so
        // nothing is written over what is stored — and the next call reads again.
        let key = "\(wid)|avatars"
        let read: String?
        do { read = try await bound.client.kvRead(key: key) } catch { return }
        guard app.bound?.workspaceId == wid, app.bound?.turn == bound.turn, app.current?.id == wid, loadedFor != wid else { return }
        loadedFor = wid
        images = [:]; seenTs = [:]
        guard let json = read, let data = json.data(using: .utf8),
              let stored = try? JSONDecoder().decode([String: StoredAvatar].self, from: data) else { return }
        // Bitmap decode happens lazily in the views; here we only hold the raw JPEG bytes.
        images = stored.compactMapValues { s in
            Data(base64Encoded: s.b64).flatMap { Self.acceptable($0) ? ($0, s.ts) : nil }
        }
        for (k, s) in stored { seenTs[k] = s.ts }
    }

    private struct StoredAvatar: Codable { var b64: String; var ts: Int64 }

    private func persist() async {
        // Never before the stored set was read for this workspace: it would be written over.
        guard let app, let client = app.client, let wid = app.current?.id, loadedFor == wid, app.bound?.workspaceId == wid else { return }
        let stored = images.mapValues { StoredAvatar(b64: $0.data.base64EncodedString(), ts: $0.ts) }
        guard let json = try? JSONEncoder().encode(stored),
              let str = String(data: json, encoding: .utf8) else { return }
        await client.kvSet(key: kvKey, value: str)
    }

    /// Evict oldest-by-timestamp entries when over the memory cap. Never evicts my own avatar.
    private func evictIfNeeded() {
        guard images.count > Self.maxCached else { return }
        let myKey = (app?.session?.userId).map(Self.userKey)
        let victims = images
            .filter { $0.key != myKey }
            .sorted { $0.value.ts < $1.value.ts }
            .prefix(images.count - Self.maxCached)
        for (k, _) in victims { images.removeValue(forKey: k) }   // seenTs tombstone stays
    }

    // MARK: Ingest

    private struct AvatarMessage: Codable { var key: String; var img: String?; var ts: Int64 }

    /// Where a batch of messages came from and who is in charge there — everything an avatar
    /// pointer's authority is checked against. All of it comes from pins the core holds, never
    /// from what the server lists.
    struct Authority: Equatable, Sendable {
        /// The server whose channel carried the messages.
        var serverId: String?
        /// That server's owner, pinned through a trustworthy provenance (`SkwodClient.spaceOwner`).
        var serverOwner: String?
        /// The instance id of the workspace the messages were fetched in.
        var instanceId: String?
        /// That instance's owner, pinned under the instance key (`SkwodClient.instanceOwner`).
        var instanceOwner: String?
    }

    /// May the author of a message set the avatar stored under `key`?
    /// - `user:<id>` — only that user (this device's own rows carry the "__me__" author).
    /// - `server:<id>` — only when `<id>` IS the server whose channel carried the message, and
    ///   only its pinned owner. (Checking the owner alone let the owner of server A, who shares
    ///   an instance with server B, overwrite B's icon from a channel in A.)
    /// - `skwod:<id>` — only when `<id>` is this workspace's instance, and only the instance
    ///   owner. A server owner is not the instance owner.
    /// An unknown id or an unpinned owner (nil) authorizes nobody.
    nonisolated static func mayWrite(key: String, authorId: String?, me: String?, authority: Authority) -> Bool {
        guard let authorId, !authorId.isEmpty else { return false }
        let author = authorId == "__me__" ? me : authorId
        guard let author, !author.isEmpty else { return false }
        func bound(_ prefix: String, to id: String?, owner: String?) -> Bool {
            guard let id, !id.isEmpty, let owner, !owner.isEmpty else { return false }
            return String(key.dropFirst(prefix.count)) == id && owner == author
        }
        if key.hasPrefix("user:") { return String(key.dropFirst("user:".count)) == author }
        if key.hasPrefix("server:") { return bound("server:", to: authority.serverId, owner: authority.serverOwner) }
        if key.hasPrefix("skwod:") { return bound("skwod:", to: authority.instanceId, owner: authority.instanceOwner) }
        return false
    }

    /// The authority for messages carried by a channel of `serverId` in the active workspace.
    func authority(serverId: String?) async -> Authority {
        guard let app, let client = app.client else { return Authority() }
        var a = Authority(serverId: serverId, instanceId: app.current?.instanceId)
        if let serverId, !serverId.isEmpty { a.serverOwner = await client.spaceOwner(serverId: serverId) }
        if a.instanceId != nil { a.instanceOwner = await client.instanceOwner() }
        return a
    }

    /// An embedded avatar is a 256 px JPEG of a few tens of kB. Anything much larger, or whose
    /// header claims other than a small picture, is not stored — it would be decoded on every
    /// screen that shows the sender, on every launch.
    nonisolated static let maxAvatarBytes = 512 * 1024
    nonisolated static func acceptable(_ bytes: Data) -> Bool {
        guard !bytes.isEmpty, bytes.count <= maxAvatarBytes,
              let src = CGImageSourceCreateWithData(bytes as CFData, nil),
              let size = SafeImage.pixelSize(src) else { return false }
        return size.width <= 2048 && size.height <= 2048
    }

    /// A pointer's own timestamp is the sender's claim. One dated in the future would sit above
    /// every later (honest) update forever, so anything more than a few minutes ahead is dropped.
    nonisolated static func plausible(ts: Int64, now: Int64) -> Bool { ts > 0 && ts <= now + 5 * 60 * 1000 }

    /// Scan fetched channel messages for avatar pointers and adopt any newer than what we hold.
    /// `img == nil` (or empty) is a removal — the sender cleared their avatar. `authority` says
    /// which server's channel carried these messages and who may speak for it (`authority(serverId:)`).
    func ingest(_ messages: [Message], authority: Authority) {
        var changed = false
        let me = app?.session?.userId
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        for m in messages {
            guard let body = m.content, body.hasPrefix(Self.tag),
                  let data = String(body.dropFirst(Self.tag.count)).data(using: .utf8),
                  let msg = try? JSONDecoder().decode(AvatarMessage.self, from: data) else { continue }
            guard Self.mayWrite(key: msg.key, authorId: m.authorId, me: me, authority: authority),
                  Self.plausible(ts: msg.ts, now: now) else { continue }
            // Tombstone check: ignore anything not strictly newer than the newest we've SEEN for the
            // key (including past clears), so an old pointer can't resurrect a removed avatar.
            if let seen = seenTs[msg.key], seen >= msg.ts { continue }
            seenTs[msg.key] = msg.ts
            if let img = msg.img, !img.isEmpty {
                // Oversized or not a small picture: skipped (the timestamp still advances, so an
                // older good avatar is not resurrected over a newer bad one).
                guard img.utf8.count <= Self.maxAvatarBytes * 4 / 3 + 4,
                      let bytes = Data(base64Encoded: img), Self.acceptable(bytes) else { continue }
                images[msg.key] = (bytes, msg.ts)
                changed = true
            } else if images[msg.key] != nil {
                images.removeValue(forKey: msg.key)   // cleared (tombstone kept in seenTs)
                changed = true
            }
        }
        if changed { evictIfNeeded(); Task { await persist() } }
    }

    /// True if `body` is an avatar-pointer message (so the chat view hides it from the conversation).
    static func isAvatarMessage(_ body: String) -> Bool { body.hasPrefix(tag) }

    // MARK: Set (broadcast)

    /// Set my profile picture: broadcast to every channel I'm in so all members who share a server
    /// with me pick it up.
    func setUserAvatar(_ imageData: Data) async {
        guard let app, let me = app.session?.userId else { return }
        await broadcast(key: Self.userKey(me), imageData: imageData, channelIds: allMyChannelIds())
    }

    /// Set a server's icon (owner/manage-server action): broadcast to that server's channels.
    func setServerAvatar(serverId: String, imageData: Data) async {
        await broadcast(key: Self.serverKey(serverId), imageData: imageData, channelIds: channelIds(inServer: serverId))
    }

    /// Set the skwod's (instance) icon (host action): broadcast instance-wide.
    func setSkwodAvatar(instanceId: String, imageData: Data) async {
        await broadcast(key: Self.skwodKey(instanceId), imageData: imageData, channelIds: allMyChannelIds())
    }

    /// Remove an avatar (broadcast an empty pointer so members clear it too).
    func clearAvatar(key: String, channelIds: [String]) async {
        await broadcast(key: key, imageData: nil, channelIds: channelIds)
    }

    private func broadcast(key: String, imageData: Data?, channelIds: [String]) async {
        guard let app, let client = app.client else { return }
        let ts = Int64(Date().timeIntervalSince1970 * 1000)
        let square = imageData.flatMap { squareJPEG($0) }
        let msg = AvatarMessage(key: key, img: square?.base64EncodedString(), ts: ts)
        guard let json = try? JSONEncoder().encode(msg), let body = String(data: json, encoding: .utf8) else { return }
        // Update locally first for instant feedback; advance the tombstone so a stale echo can't undo it.
        seenTs[key] = ts
        if let square { images[key] = (square, ts) } else { images.removeValue(forKey: key) }
        await persist()
        // Fan out concurrently — one message per channel, but in parallel, not N sequential RTTs.
        let text = Self.tag + body
        let targets = channelIds.filter { !$0.isEmpty && $0 != "demo" }
        await withTaskGroup(of: Void.self) { group in
            for cid in targets {
                group.addTask { _ = try? await client.sendChannelMessage(channelId: cid, text: text) }
            }
        }
    }

    private func allMyChannelIds() -> [String] {
        guard let chat = app?.chatModel else { return [] }
        return Array(Set(chat.spaces.map(\.channelId))).filter { !$0.isEmpty && $0 != "demo" }
    }

    private func channelIds(inServer serverId: String) -> [String] {
        guard let chat = app?.chatModel else { return [] }
        return chat.spaces.filter { $0.serverId == serverId }.map(\.channelId).filter { !$0.isEmpty }
    }

    /// Downscale + center-crop to a square JPEG suitable for embedding in a message.
    private func squareJPEG(_ data: Data) -> Data? {
        AvatarImageTools.squareJPEG(data, side: Self.side, quality: Self.quality)
    }
}

/// Cross-platform square center-crop → JPEG.
enum AvatarImageTools {
    static func squareJPEG(_ data: Data, side: Int, quality: CGFloat) -> Data? {
        // Bounded decode (and orientation applied) before any drawing — see `SafeImage`.
        guard let decoded = SafeImage.decode(data, maxEdge: max(side * 4, 1024)) else { return nil }
        #if os(iOS)
        let img = UIImage(cgImage: decoded)
        let s = min(img.size.width, img.size.height)
        let rect = CGRect(x: (img.size.width - s) / 2, y: (img.size.height - s) / 2, width: s, height: s)
        guard let cg = img.cgImage?.cropping(to: CGRect(x: rect.origin.x * img.scale, y: rect.origin.y * img.scale,
                                                        width: s * img.scale, height: s * img.scale)) else { return nil }
        let cropped = UIImage(cgImage: cg)
        let target = CGSize(width: side, height: side)
        let fmt = UIGraphicsImageRendererFormat(); fmt.scale = 1
        return UIGraphicsImageRenderer(size: target, format: fmt).jpegData(withCompressionQuality: quality) { _ in
            cropped.draw(in: CGRect(origin: .zero, size: target))
        }
        #else
        let img = NSImage(cgImage: decoded, size: NSSize(width: decoded.width, height: decoded.height))
        let s = min(img.size.width, img.size.height)
        let target = NSSize(width: side, height: side)
        let out = NSImage(size: target)
        out.lockFocus()
        img.draw(in: CGRect(origin: .zero, size: target),
                 from: CGRect(x: (img.size.width - s) / 2, y: (img.size.height - s) / 2, width: s, height: s),
                 operation: .copy, fraction: 1)
        out.unlockFocus()
        guard let tiff = out.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) else { return nil }
        return rep.representation(using: .jpeg, properties: [.compressionFactor: quality])
        #endif
    }
}

// MARK: - Rendering

/// A circular avatar that shows the E2EE image if we hold one, else the seeded monogram fallback —
/// a drop-in replacement for the monogram circles used across the app.
struct AvatarImage: View {
    @EnvironmentObject private var app: AppState
    /// The avatar key (user:/server:/skwod:) — nil renders the monogram only.
    let key: String?
    let name: String
    var size: CGFloat = 40
    var monospacedInitial: Bool = false

    var body: some View {
        let data = key.flatMap { app.avatars.data(for: $0) }
        Group {
            if let data, let img = Image(data: data) {
                img.resizable().scaledToFill()
            } else {
                Circle().fill(Color.seeded(name).gradient)
                    .overlay(Text(name.prefix(1).uppercased())
                        .font(.system(size: size * 0.42, weight: .bold))
                        .foregroundStyle(.white))
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
    }
}

/// The same, but a rounded-square for server/skwod rail tiles.
struct AvatarTile: View {
    @EnvironmentObject private var app: AppState
    let key: String?
    let name: String
    var size: CGFloat = 48
    var cornerRadius: CGFloat = 16

    var body: some View {
        let data = key.flatMap { app.avatars.data(for: $0) }
        Group {
            if let data, let img = Image(data: data) {
                img.resizable().scaledToFill()
            } else {
                Text(name.prefix(1).uppercased())
                    .font(.system(size: size * 0.42, weight: .bold)).foregroundStyle(.white)
                    .frame(width: size, height: size)
                    .background(Color.seeded(name).gradient)
            }
        }
        .frame(width: size, height: size)
        .clipShape(RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
    }
}
