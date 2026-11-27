import SwiftUI
import ImageIO
import UniformTypeIdentifiers

/// The Feed and Stories are REAL end-to-end-encrypted content: each post/story is a normal channel
/// message in the active space's channel, tagged so the chat view hides it and the feed shows it.
/// Because they ride the existing Sender-Key channel path, they're encrypted and synced across the
/// space's members exactly like chat — the server only ever sees ciphertext.

/// Body prefixes (\u{2} control char keeps them out of normal chat rendering).
private let FEED_TAG = "\u{2}skwod/feed|"
let STORY_TAG = "\u{2}skwod/story|"
/// A comment on a post — a normal E2EE channel message tagged + referencing the post's message id,
/// so comments are encrypted and synced across members exactly like the posts they hang off.
private let COMMENT_TAG = "\u{2}skwod/comment|"
/// Retired: a channel message is never an address announcement. Anyone in a channel could post
/// one, so a move is only ever accepted as a record signed by the pinned instance key
/// (`AppState.checkAddressRecord`). The tag is kept solely so old messages stay hidden from chat.
let ADDR_TAG = "\u{2}skwod/addr|"
let STORY_TTL_MS: Int64 = 24 * 60 * 60 * 1000
/// A "like" is a reaction whose (sealed) emoji is this marker. The server sees only a keyed tag.
private let LIKE_EMOJI = "like"

/// Whether a channel message is feed/story content (so the chat view can hide it — it belongs to the
/// Feed tab, not the conversation). Attachment/music chat messages share the \u{2}skwod/ scheme but
/// DO render in chat, so the chat filter matches only the feed tags.
enum FeedTags {
    static func isFeedContent(_ body: String) -> Bool { body.hasPrefix("\u{2}skwod/") }
    static func isHiddenFromChat(_ body: String) -> Bool {
        body.hasPrefix("\u{2}skwod/feed|") || body.hasPrefix("\u{2}skwod/story|")
            || body.hasPrefix("\u{2}skwod/game|") || body.hasPrefix("\u{2}skwod/comment|")
            || body.hasPrefix(ADDR_TAG)
    }

}

/// A decoded feed post or story, ready to render.
struct FeedItem: Identifiable, Hashable {
    var id: String            // channel message id
    var author: String
    var mine: Bool
    var text: String
    var music: MusicTrack?
    /// Which part of the song's preview a STORY plays (nil: a post, or a story from a build
    /// before 45 — the viewer then plays `MusicClip.fallback`).
    var clip: MusicClip? = nil
    /// The inline thumbnail (or, on posts from builds ≤ 42, the whole downscaled photo).
    var photoData: Data?
    var createdAt: Int64
    /// Local-only like state (reactions sync is a follow-up).
    var liked: Bool = false
    var likes: Int = 0
    var commentCount: Int = 0
    /// The full photo, to download and decrypt when the post is on screen.
    var attachment: ChatAttachment? = nil
    /// Which server's feed this is in, and that feed's channel — likes and comments go there.
    var serverId: String = ""
    var serverName: String = ""
    var channelId: String = ""
}

/// One comment on a post — E2EE channel message referencing the post's id.
struct FeedComment: Identifiable, Hashable {
    var id: String
    var postId: String
    var author: String
    var mine: Bool
    var text: String
    var createdAt: Int64
}

/// The comment on-wire payload (JSON after the tag).
private struct CommentPayload: Codable {
    var postId: String
    var text: String
    var ts: Int64
}

/// Where a post or story of mine stands on its way out.
enum FeedSendPhase: Equatable {
    /// The photo is being stripped of metadata and encrypted on this device.
    case encrypting
    /// The ciphertext is going to the host: the share that has left this device, 0…1.
    case uploading(Double)
    /// The (encrypted) post itself is being handed to the outbox.
    case sending

    /// One number for a progress ring: encrypting is the first sliver, the upload the rest.
    var fraction: Double {
        switch self {
        case .encrypting: return 0.04
        case .uploading(let f): return 0.04 + 0.92 * min(max(f, 0), 1)
        case .sending: return 0.98
        }
    }

    func label(_ what: String) -> String {
        switch self {
        case .encrypting: return "Encrypting your \(what)…"
        // Everything has left this device and the host has not confirmed the last piece yet.
        case .uploading(let f) where f >= 0.97 && f < 1: return "Finishing the upload of your \(what)…"
        case .uploading(let f): return "Uploading your \(what)… \(Int((min(max(f, 0), 1) * 100).rounded()))%"
        case .sending: return "Posting your \(what)…"
        }
    }
}

/// A post or story that did not go out, kept so "Try again" sends exactly what was made.
struct FeedDraft {
    var isStory: Bool
    var text: String
    var music: MusicTrack?
    var clip: MusicClip?
    var photo: Data?
    var serverId: String?
    var what: String { isStory ? "story" : "post" }
}

/// A server whose feed the user can read and post to.
struct FeedSource: Identifiable, Hashable {
    let serverId: String
    let name: String
    let channelId: String
    var id: String { serverId }
}

/// Client-backed Feed + Stories across the servers of the active skwod. Each server has ONE feed
/// channel (`SkwodClient.feedChannel`), the same on every member's device; posts, stories, likes
/// and comments all go through it over the E2EE channel path.
@MainActor
final class FeedModel: ObservableObject {
    @Published var posts: [FeedItem] = []
    @Published var stories: [FeedItem] = []
    @Published var loading = false
    /// postId → its comments, chronological. Populated by refresh().
    @Published var commentsByPost: [String: [FeedComment]] = [:]
    /// The servers whose feeds are shown (and can be posted to).
    @Published private(set) var sources: [FeedSource] = []
    /// Why the last post / like / comment did not go out — shown until dismissed. Never silent.
    @Published var error: String?
    /// A post or story is being encrypted, uploaded and sent. While it is, nothing else is
    /// accepted (`send` refuses), so a second tap can never post twice.
    @Published private(set) var posting = false
    /// How far along it is (nil when nothing is on its way).
    @Published private(set) var sendPhase: FeedSendPhase?
    /// What is on its way: a story (the ring in the stories row shows it) or a post.
    @Published private(set) var sendingStory = false
    /// What did not go out, until it is retried or discarded. `error` says why.
    @Published private(set) var failedDraft: FeedDraft?

    private weak var app: AppState?
    private weak var chat: ChatModel?
    /// userId → username, so posts/stories show real names instead of id prefixes.
    private var memberNames: [String: String] = [:]
    private var refreshing = false
    private var refreshAgain = false

    /// The name on a post, story or comment: the server's member list is only a claim handed
    /// to the contact book's rule (`ContactTrust.authorLabel`), never shown as given.
    private func authorLabel(_ userId: String?) -> String {
        let claimed = userId.flatMap { memberNames[$0] }
        guard let app else { return ContactTrust.authorLabel(userId: userId, claimedName: claimed, book: [:]) }
        return app.contacts.authorLabel(userId, claimedName: claimed)
    }

    func bind(app: AppState, chat: ChatModel) { self.app = app; self.chat = chat }

    var hasSpace: Bool { !(chat?.spaces.isEmpty ?? true) }

    /// Whether `channelId` is one of the feeds on screen (a live event for it → refresh).
    func shows(channelId: String) -> Bool { sources.contains { $0.channelId == channelId } }

    /// Reload every feed. `full` also re-resolves which channel each server's feed is in and
    /// the member names (the slow safety pass and the first load); an event-driven refresh
    /// only catches the channels up.
    func refresh(full: Bool = true) async {
        guard let app, let client = app.client, let me = app.session?.userId, let chat else {
            posts = []; stories = []; return
        }
        if refreshing { refreshAgain = true; return }
        refreshing = true
        loading = posts.isEmpty && stories.isEmpty
        defer { refreshing = false; loading = false }
        var full = full
        repeat {
            refreshAgain = false
            if full || chat.feedChannels.isEmpty { await chat.resolveFeedChannels() }
            sources = chat.serverGroups.compactMap { g in
                chat.feedChannels[g.serverId].map { FeedSource(serverId: g.serverId, name: g.name, channelId: $0) }
            }
            if full || memberNames.isEmpty {
                // Resolve author names so decode renders real usernames.
                for src in sources {
                    if let members = try? await client.listMembers(serverId: src.serverId) {
                        for m in members { memberNames[m.userId] = m.username }
                    }
                }
            }
            full = false
            // The server's clock, not this device's: a story is 24 hours of SERVER time old,
            // whatever the phone (or the sender) believes the time is.
            let now = await client.serverNowMs()
            var newPosts: [FeedItem] = []
            var newStories: [FeedItem] = []
            var newComments: [String: [FeedComment]] = [:]
            var failed = false
            for src in sources {
                guard var msgs = try? await client.fetchChannelMessages(channelId: src.channelId, myUserId: me) else {
                    failed = true
                    continue
                }
                // Stories past their day END: other people's leave this device's cache, mine
                // are deleted for everyone (and their photos with them).
                if await client.expireStories(channelId: src.channelId, storyTag: STORY_TAG, ttlMs: STORY_TTL_MS) > 0 {
                    msgs = await client.history(scope: "channel:\(src.channelId)")
                }
                // Likes: one read of the channel's reactions (they came with the fetch).
                var likes: [String: (count: Int, mine: Bool)] = [:]
                for r in await client.channelReactions(channelId: src.channelId) where r.emoji == LIKE_EMOJI {
                    var e = likes[r.messageId] ?? (0, false)
                    e.count += 1
                    if r.userId == me { e.mine = true }
                    likes[r.messageId] = e
                }
                for m in msgs where !m.isDeleted {
                    let body = m.content ?? ""
                    if let rest = strip(body, FEED_TAG), var item = decode(rest, m, me: me, in: src) {
                        item.likes = likes[item.id]?.count ?? 0
                        item.liked = likes[item.id]?.mine ?? false
                        newPosts.append(item)
                    } else if let rest = strip(body, STORY_TAG), let item = decode(rest, m, me: me, in: src) {
                        if now - item.createdAt < STORY_TTL_MS { newStories.append(item) }
                    } else if let rest = strip(body, COMMENT_TAG), let c = decodeComment(rest, m, me: me) {
                        newComments[c.postId, default: []].append(c)
                    }
                }
            }
            await app.drainDmEvents()
            // A feed that could not be fetched keeps what it showed (offline is not "empty").
            if failed && newPosts.isEmpty && !posts.isEmpty { break }
            for k in newComments.keys { newComments[k]?.sort { $0.createdAt < $1.createdAt } }
            commentsByPost = newComments
            posts = newPosts
                .map { var p = $0; p.commentCount = newComments[$0.id]?.count ?? 0; return p }
                .sorted { $0.createdAt > $1.createdAt }
            stories = newStories.sorted { $0.createdAt > $1.createdAt }
        } while refreshAgain
    }

    /// Post a comment on `postId` — a real E2EE channel message, synced to every member.
    func comment(on postId: String, text: String) async {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        // (The skwod this feed was read from, at the tap.)
        guard let app, !t.isEmpty, let client = Outbox.client(of: chat?.spacesWorkspaceId, app) else { if !t.isEmpty { error = Compose.opening }; return }
        guard let cid = posts.first(where: { $0.id == postId })?.channelId, !cid.isEmpty else {
            error = "That post isn't available any more."
            return
        }
        let payload = CommentPayload(postId: postId, text: t, ts: Int64(Date().timeIntervalSince1970 * 1000))
        guard let json = try? JSONEncoder().encode(payload),
              let jsonStr = String(data: json, encoding: .utf8) else { return }
        // Queued: it shows at once and goes out when the connection allows.
        do {
            _ = try await client.queueChannelMessage(channelId: cid, text: COMMENT_TAG + jsonStr, replyToId: nil, blobIds: [], uploadIds: [])
            Outbox.kick(app)
        } catch { self.error = "Your comment wasn't posted. " + sendFailureText(error) }
        await reloadLocal()
    }

    /// Delete a post, a story or a comment of mine, for everyone (queued; its photo goes too).
    func delete(messageId: String, channelId: String) async {
        guard let app, let client = app.client, !channelId.isEmpty else { return }
        do {
            try await client.queueChannelDelete(channelId: channelId, messageId: messageId)
            Outbox.kick(app)
        } catch { self.error = "Couldn't delete that. " + sendFailureText(error) }
        posts.removeAll { $0.id == messageId }
        stories.removeAll { $0.id == messageId }
        for k in commentsByPost.keys { commentsByPost[k]?.removeAll { $0.id == messageId } }
        await reloadLocal()
    }

    /// The channel a comment lives in (its post's feed channel).
    func channel(ofPost postId: String) -> String { posts.first { $0.id == postId }?.channelId ?? "" }

    /// Redraw after a local change (something queued or deleted) without waiting for the network.
    private func reloadLocal() async { await refresh(full: false) }

    private func decodeComment(_ json: String, _ m: Message, me: String) -> FeedComment? {
        guard let data = json.data(using: .utf8),
              let p = try? JSONDecoder().decode(CommentPayload.self, from: data) else { return nil }
        let mine = (m.authorId ?? "") == "__me__" || m.authorId == me
        let author = mine ? "you" : authorLabel(m.authorId)
        // The server's time for the message — not the `ts` its sender wrote into it.
        return FeedComment(id: m.messageId, postId: p.postId, author: author, mine: mine,
                           text: p.text, createdAt: m.createdAt)
    }

    /// Like/unlike a post — a real, synced reaction on its channel message. Optimistic, reverts on error.
    func toggleLike(_ item: FeedItem) async {
        guard let app, let client = app.client,
              let i = posts.firstIndex(where: { $0.id == item.id }) else { return }
        let cid = posts[i].channelId
        guard !cid.isEmpty else { return }
        let willLike = !posts[i].liked
        posts[i].liked = willLike
        posts[i].likes = max(0, posts[i].likes + (willLike ? 1 : -1))
        do {
            try await client.queueReaction(channelId: cid, messageId: item.id, emoji: LIKE_EMOJI, remove: !willLike)
            Outbox.kick(app)
        } catch {
            if let j = posts.firstIndex(where: { $0.id == item.id }) {
                posts[j].liked = !willLike
                posts[j].likes = max(0, posts[j].likes + (willLike ? -1 : 1))
            }
            self.error = "Couldn't \(willLike ? "like" : "unlike") that post — check your connection."
        }
    }

    /// Post to a server's feed. `serverId` nil = the only server (or the first, when the caller
    /// did not offer a choice). Returns whether it went out; on failure `error` says why.
    @discardableResult
    func post(text: String, music: MusicTrack?, photo: Data?, serverId: String? = nil) async -> Bool {
        await send(FeedDraft(isStory: false, text: text, music: music, clip: nil, photo: photo, serverId: serverId))
    }

    /// `clip`: which part of the song plays (ignored without a song).
    @discardableResult
    func postStory(music: MusicTrack?, clip: MusicClip? = nil, photo: Data?, serverId: String? = nil) async -> Bool {
        await send(FeedDraft(isStory: true, text: "", music: music, clip: music == nil ? nil : clip, photo: photo, serverId: serverId))
    }

    /// Send what failed again, exactly as it was made.
    @discardableResult
    func retryFailed() async -> Bool {
        guard let draft = failedDraft, !posting else { return false }
        return await send(draft)
    }

    /// Give up on what failed.
    func discardFailed() { failedDraft = nil; error = nil }

    private func uploadProgress(_ fraction: Double) {
        // Only forwards: chunks report from a background queue and can arrive out of order.
        if case .uploading(let shown)? = sendPhase, shown >= fraction { return }
        if posting { sendPhase = .uploading(fraction) }
    }

    private func send(_ draft: FeedDraft) async -> Bool {
        let (text, music, photo, serverId, what) = (draft.text, draft.music, draft.photo, draft.serverId, draft.what)
        let tag = draft.isStory ? STORY_TAG : FEED_TAG
        // One at a time: a second tap while the first is still uploading posts nothing.
        guard !posting else { return false }
        // Where it goes and through what is settled here, at the tap.
        guard let app, let chat, let client = Outbox.client(of: chat.spacesWorkspaceId, app) else {
            error = "Not connected — your \(what) wasn't sent."
            failedDraft = draft
            return false
        }
        let asked = app.bindTicket()
        let store = BlobStore(app: app)
        let target = serverId ?? chat.currentServer?.serverId ?? chat.serverGroups.first?.serverId ?? ""
        let known = sources.first(where: { $0.serverId == target })?.channelId
        posting = true
        sendingStory = draft.isStory
        sendPhase = photo == nil ? .sending : .encrypting
        defer { posting = false; sendPhase = nil }
        error = nil
        failedDraft = nil
        await UploadLimitSync.refresh(app)
        if let asked, app.holds(asked), chat.feedChannels.isEmpty { await chat.resolveFeedChannels() }
        // Ask the core for this server's feed channel now (the owner's app creates it on first
        // use) rather than trusting a value resolved a while ago.
        let cid: String
        do { cid = try await client.feedChannel(serverId: target) }
        catch {
            // Offline: the feed channel this device already knows for that server will do —
            // the post is queued and goes out later.
            guard let known, !known.isEmpty else {
                self.error = "Your \(what) wasn't sent: couldn't find this server's feed. " + sendFailureText(error)
                failedDraft = draft
                return false
            }
            cid = known
        }
        var payload = FeedPayload(text: text.isEmpty ? nil : text, music: music, photoB64: nil, att: nil, clip: draft.clip,
                                  ts: Int64(Date().timeIntervalSince1970 * 1000))
        var blobIds: [String] = []
        do {
            if let photo {
                guard let store else { throw AttachmentError.notSignedIn }
                // The photo itself: sealed and uploaded like any chat attachment…
                let out = try await AttachmentService.uploadImage(photo, to: .channel, store: store, thumbEdge: FeedMedia.thumbEdge,
                                                                  progress: { [weak self] fraction in
                    Task { @MainActor in self?.uploadProgress(fraction) }
                })
                blobIds = out.blobIds
                // …and only a small thumbnail inline, carried once (not also in the descriptor).
                var descriptor = out.attachment
                payload.photoB64 = descriptor?.thumbB64
                descriptor?.thumbB64 = nil
                payload.att = descriptor
            }
            sendPhase = .sending
            guard let jsonStr = String(data: try JSONEncoder().encode(payload), encoding: .utf8) else { throw AttachmentError.upload }
            // Sent WITH the blob ids, so the server links the photo to the post and every
            // member of the server can open it.
            // Queued, so a post written on a train is not lost: it is in the feed at once and
            // reaches everyone when the connection is back.
            _ = try await client.queueChannelMessage(channelId: cid, text: tag + jsonStr, replyToId: nil, blobIds: blobIds, uploadIds: [])
            Outbox.kick(app)
        } catch {
            self.error = "Your \(what) wasn't sent. " + sendFailureText(error)
            failedDraft = draft
            if let store { for id in blobIds { await store.delete(id) } }
            return false
        }
        await refresh(full: false)
        return true
    }

    // MARK: decode

    private func strip(_ body: String, _ tag: String) -> String? {
        body.hasPrefix(tag) ? String(body.dropFirst(tag.count)) : nil
    }

    private func decode(_ json: String, _ m: Message, me: String, in src: FeedSource) -> FeedItem? {
        guard let data = json.data(using: .utf8),
              let p = try? JSONDecoder().decode(FeedPayload.self, from: data) else { return nil }
        let mine = (m.authorId ?? "") == "__me__" || m.authorId == me
        let author = mine ? "you" : authorLabel(m.authorId)
        return FeedItem(
            id: m.messageId,
            author: author,
            mine: mine,
            text: p.text ?? "",
            music: p.music,
            clip: p.music == nil ? nil : p.clip,
            photoData: p.photoB64.flatMap { Data(base64Encoded: $0) },
            // The server's time for the message: what expiry and ordering are judged by. (`ts`
            // inside the body is the sender's claim and is ignored.)
            createdAt: m.createdAt,
            attachment: p.att?.kind == .image ? p.att : nil,
            serverId: src.serverId,
            serverName: src.name,
            channelId: src.channelId
        )
    }
}

/// A feed/story photo: the inline thumbnail, and the full picture ONLY when the reader asks for
/// it (a tap; opening a story).
///
/// Why nothing is fetched as posts scroll by: a download is a request to the host made with this
/// account's session, so fetching every picture that comes into view would tell the host who
/// looked at which post and when — a read receipt nobody agreed to. The thumbnail travels inside
/// the encrypted post itself and costs no request. (`autoLoad` is for a picture the reader has
/// already chosen to open, such as a story.)
struct FeedPhoto: View {
    let thumb: Data?
    let attachment: ChatAttachment?
    /// The reader has already asked for this picture (an opened story): fetch without a tap.
    var autoLoad = false
    @EnvironmentObject private var app: AppState
    @StateObject private var loader = AttachmentLoader()
    @State private var full: Image?
    /// The user asked for a picture that is not fetched on its own.
    @State private var requested = false

    /// Never unasked in the feed; an opened story is the reader asking — within the size gate.
    private var auto: Bool {
        guard autoLoad, let a = attachment else { return false }
        return AttachmentLimits.acceptable(declaredSize: a.size) && a.size <= Int64(AttachmentLimits.inMemoryCap)
    }

    var body: some View {
        ZStack {
            if let full {
                full.resizable().scaledToFill()
            } else if let thumb, let img = Image(data: thumb) {
                img.resizable().scaledToFill()

            } else {
                Rectangle().fill(.white.opacity(0.06))
            }
            if full == nil, attachment != nil {
                if let error = loader.error {
                    Text(error).font(.caption2).foregroundStyle(.orange).multilineTextAlignment(.center)
                        .padding(8).background(.black.opacity(0.55), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .padding(12)
                } else if loader.busy {
                    ProgressView().tint(.white)
                } else if let attachment, !auto, !requested {
                    if AttachmentLimits.acceptable(declaredSize: attachment.size) && attachment.size <= Int64(AttachmentLimits.inMemoryCap) {
                        Button { requested = true } label: {
                            Label("Show full photo · \(AttachmentService.formattedSize(attachment.size))", systemImage: "arrow.down.circle.fill")
                                .font(.caption.weight(.semibold)).foregroundStyle(.white)
                                .padding(.horizontal, 12).padding(.vertical, 7)
                                .background(.black.opacity(0.6), in: Capsule())
                        }
                        .buttonStyle(.plain)
                    } else {
                        Text("Too large to open").font(.caption2).foregroundStyle(.orange)
                            .padding(8).background(.black.opacity(0.55), in: Capsule())
                    }
                }
            }
        }
        #if DEBUG
        .onReceive(NotificationCenter.default.publisher(for: .skwodE2EShowAttachment)) { note in
            if note.object as? String != "close" { requested = true }
        }
        #endif
        .task(id: "\(attachment?.blobId ?? "")|\(requested)") {
            guard let attachment, auto || requested else { return }
            await loader.fetch(attachment, app: app)
            // Read whole to be drawn — which is why only pictures within the fixed in-memory
            // bound get here (`auto` / the button above), whatever the host's upload limit is.
            guard attachment.size <= Int64(AttachmentLimits.inMemoryCap) else { return }
            if let url = loader.localURL, let data = try? Data(contentsOf: url) { full = Image(data: data) }
            #if DEBUG
            E2E.sawFeedPhoto(blobId: attachment.blobId, opened: full != nil, error: loader.error)
            #endif
        }
    }
}

/// Media helpers: downscale a photo to a small JPEG so it fits comfortably in an E2EE message body.
enum FeedMedia {
    /// Long edge of the thumbnail carried inline in a feed post / story (a few kB as JPEG).
    static let thumbEdge = 320

    /// Downscale to `maxDimension` px on the long edge and JPEG-encode. Cross-platform via ImageIO.
    static func downscaledJPEG(_ data: Data, maxDimension: Int = 1080, quality: CGFloat = 0.5) -> Data? {
        guard let src = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        let opts: [CFString: Any] = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceThumbnailMaxPixelSize: maxDimension,
            kCGImageSourceCreateThumbnailWithTransform: true,
        ]
        guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else { return nil }
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, UTType.jpeg.identifier as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, cg, [kCGImageDestinationLossyCompressionQuality: quality] as CFDictionary)
        guard CGImageDestinationFinalize(dest) else { return nil }
        return out as Data
    }
}
