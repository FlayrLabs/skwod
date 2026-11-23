import SwiftUI
import PhotosUI

struct FeedView: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @StateObject private var feed = FeedModel()
    @State private var showCompose = false
    @State private var showStoryComposer = false
    @State private var previewStory: FeedItem?
    @State private var openPost: FeedItem?
    /// Which server's feed a new story goes to (asked first when there is more than one).
    @State private var storyServer: String?
    @State private var askStoryServer = false

    var body: some View {
        SkwodScreen(title: "Feed", detail: true) {
            Group {
                if !feed.hasSpace {
                    noSpaceState
                } else {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 18) {
                            statusRow
                            storiesRow
                            if feed.posts.isEmpty && !feed.loading { emptyPosts }
                            ForEach(feed.posts) { post in
                                FeedCard(item: post, onLike: { Task { await feed.toggleLike(post) } },
                                         onComment: { openPost = post },
                                         onDelete: { Task { await feed.delete(messageId: post.id, channelId: post.channelId) } },
                                         showServer: feed.sources.count > 1)
                            }
                        }
                        .padding()
                    }
                    .refreshable { await feed.refresh() }
                }
            }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button { showCompose = true } label: { Image(systemName: "square.and.pencil") }
                        .disabled(!feed.hasSpace || feed.posting)
                }
            }
            .sheet(isPresented: $showCompose) {
                PostComposer(sources: feed.sources, preferred: chat.currentServer?.serverId) { text, music, photo, serverId in
                    Task { await feed.post(text: text, music: music, photo: photo, serverId: serverId) }
                }
            }
            .storyEditorCover(isPresented: $showStoryComposer) {
                StoryEditorView(mode: .story) { imageData, music, clip in
                    let target = storyServer
                    Task { await feed.postStory(music: music, clip: clip, photo: imageData, serverId: target) }
                }
            }
            .confirmationDialog("Share your story with…", isPresented: $askStoryServer, titleVisibility: .visible) {
                ForEach(feed.sources) { src in
                    Button(src.name) { storyServer = src.serverId; showStoryComposer = true }
                }
            }
            .sheet(item: $previewStory) { item in
                DismissableSheet {
                    StoryViewer(item: item, onDelete: { Task { await feed.delete(messageId: item.id, channelId: item.channelId) } })
                }
            }
            .sheet(item: $openPost) { post in DismissableSheet { PostDetailSheet(post: post, feed: feed) } }
        }
        .task {
            feed.bind(app: app, chat: chat)
            // New posts, likes and comments arrive as live events for the feed channel (below);
            // this loop is only the slow safety net behind them.
            while !Task.isCancelled {
                await feed.refresh()
                try? await Task.sleep(for: LiveSync.safetyInterval)
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: .skwodChannelChanged)) { note in
            if let id = note.object as? String, feed.shows(channelId: id) { Task { await feed.refresh(full: false) } }
        }
        .onReceive(NotificationCenter.default.publisher(for: .skwodLiveConnected)) { _ in Task { await feed.refresh() } }
        // Someone was blocked or unblocked: their posts, stories and likes leave (or return).
        .onReceive(NotificationCenter.default.publisher(for: .skwodBlocksChanged)) { _ in Task { await feed.refresh(full: false) } }
        .onChange(of: chat.serverGroups.map(\.serverId)) { _, _ in Task { await feed.refresh() } }
        #if DEBUG
        .onReceive(NotificationCenter.default.publisher(for: .skwodE2EFeedPost)) { note in
            guard let info = note.object as? [String: Any] else { return }
            Task {
                // Every phase the status row was given, in order (the upload's progress among them).
                let watch = feed.$sendPhase.sink { E2E.sawFeedPhase($0) }
                defer { watch.cancel() }
                let ok: Bool
                if info["story"] as? Bool == true {
                    ok = await feed.postStory(music: nil, photo: info["photo"] as? Data, serverId: info["server"] as? String)
                } else {
                    ok = await feed.post(text: info["text"] as? String ?? "", music: nil, photo: info["photo"] as? Data,
                                         serverId: info["server"] as? String)
                }
                E2E.feedPosted(ok: ok, error: feed.error)
            }
        }
        #endif
    }

    /// What is going on with the user's own post: being sent, or why it was not.
    @ViewBuilder private var statusRow: some View {
        if feed.posting {
            let what = feed.sendingStory ? "story" : "post"
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(feed.sendPhase?.label(what) ?? "Posting your \(what)…").font(.caption).foregroundStyle(.white.opacity(0.6))
                }
                if case .uploading(let fraction)? = feed.sendPhase {
                    ProgressView(value: min(max(fraction, 0), 1)).tint(.skAccent)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("feed.sending")
        }
        if let error = feed.error {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                Text(error).font(.caption).foregroundStyle(.white.opacity(0.9)).fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 4)
                if feed.failedDraft != nil {
                    // Nothing was lost: the same story or post can go out again.
                    Button("Try again") { Task { await feed.retryFailed() } }
                        .font(.caption.weight(.semibold)).buttonStyle(.plain).foregroundStyle(.skAccent)
                        .disabled(feed.posting)
                        .accessibilityIdentifier("feed.retry")
                    Button("Discard") { feed.discardFailed() }
                        .font(.caption.weight(.semibold)).buttonStyle(.plain).foregroundStyle(.white.opacity(0.6))
                } else {
                    Button("OK") { feed.error = nil }.font(.caption.weight(.semibold)).buttonStyle(.plain).foregroundStyle(.skAccent)
                }
            }
            .padding(12)
            .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(.orange.opacity(0.35), lineWidth: 1))
            .accessibilityIdentifier("feed.error")
        }
    }

    private var storiesRow: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 14) {
                Button {
                    // A story that failed: the ring sends it again (Discard is beside the reason).
                    if feed.failedDraft?.isStory == true { Task { await feed.retryFailed() }; return }
                    // More than one server: say whose feed the story is for first.
                    if feed.sources.count > 1 { askStoryServer = true }
                    else { storyServer = feed.sources.first?.serverId; showStoryComposer = true }
                } label: { myStoryRing }.buttonStyle(.plain)
                    // One story at a time: while one is on its way up, another cannot be started.
                    .disabled(feed.posting)
                ForEach(feed.stories) { s in
                    Button { previewStory = s } label: { storyRing(s) }.buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 4)
        }
    }

    private var myStoryRing: some View {
        let uploading = feed.posting && feed.sendingStory
        let failed = !uploading && feed.failedDraft?.isStory == true
        return VStack(spacing: 6) {
            ZStack {
                if uploading {
                    // The ring fills as the story encrypts and uploads.
                    Circle().stroke(.white.opacity(0.15), lineWidth: 2.5).frame(width: 63.5, height: 63.5)
                    Circle().trim(from: 0, to: feed.sendPhase?.fraction ?? 0.04)
                        .stroke(Color.skAccent, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                        .frame(width: 63.5, height: 63.5)
                        .animation(.linear(duration: 0.2), value: feed.sendPhase?.fraction)
                } else {
                    Circle().strokeBorder(failed ? AnyShapeStyle(Color.orange)
                                                 : AnyShapeStyle(LinearGradient(colors: [.skAccent, .skAccentWash], startPoint: .top, endPoint: .bottom)),
                                          lineWidth: 2.5)
                        .frame(width: 66, height: 66)
                }
                Circle().fill(.white.opacity(0.08)).frame(width: 56, height: 56)
                    .overlay {
                        if uploading {
                            if case .uploading(let f)? = feed.sendPhase {
                                Text("\(Int((min(max(f, 0), 1) * 100).rounded()))%").font(.caption.weight(.bold).monospacedDigit()).foregroundStyle(.white)
                            } else {
                                ProgressView().controlSize(.small).tint(.white)
                            }
                        } else if failed {
                            Image(systemName: "arrow.clockwise").foregroundStyle(.orange).font(.title3.bold())
                        } else {
                            Image(systemName: "plus").foregroundStyle(.skAccent).font(.title3.bold())
                        }
                    }
            }
            Text(uploading ? "Sending…" : failed ? "Try again" : "Your story").font(.caption).foregroundStyle(.white.opacity(0.7))
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(uploading ? (feed.sendPhase?.label("story") ?? "Sending your story") : failed ? "Your story wasn't sent. Try again" : "Your story")
        .accessibilityIdentifier("feed.myStory")
    }

    private func storyRing(_ s: FeedItem) -> some View {
        VStack(spacing: 6) {
            ZStack {
                Circle().strokeBorder(LinearGradient(colors: [.skAccent, .skAccentWash], startPoint: .top, endPoint: .bottom), lineWidth: 2.5)
                    .frame(width: 66, height: 66)
                avatar(s)
                if s.music != nil {
                    Image(systemName: "music.note")
                        .font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                        .padding(5).background(.skAccent, in: Circle())
                        .overlay(Circle().strokeBorder(Color(red: 0.067, green: 0.071, blue: 0.078), lineWidth: 2))
                        .offset(x: 22, y: 22)
                }
            }
            Text(s.author).font(.caption).foregroundStyle(.white.opacity(0.7)).lineLimit(1).frame(maxWidth: 62)
        }
    }

    @ViewBuilder private func avatar(_ s: FeedItem) -> some View {
        if let data = s.photoData, let img = Image(data: data) {
            img.resizable().scaledToFill().frame(width: 56, height: 56).clipShape(Circle())
        } else {
            Circle().fill(Color.seeded(s.author).gradient).frame(width: 56, height: 56)
                .overlay(Text(s.author.prefix(1).uppercased()).font(.headline).foregroundStyle(.white))
        }
    }

    private var noSpaceState: some View {
        VStack(spacing: 14) {
            Image(systemName: "square.stack.3d.up.slash").font(.system(size: 54)).foregroundStyle(.white.opacity(0.25))
            Text("No server yet").font(.title3.weight(.semibold)).foregroundStyle(.white.opacity(0.7))
            Text("Create or join a server to share end-to-end encrypted posts and stories with your crew.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.45)).multilineTextAlignment(.center).padding(.horizontal, 40)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyPosts: some View {
        Text("No posts yet — share something with the crew.")
            .font(.subheadline).foregroundStyle(.white.opacity(0.45)).padding(.vertical, 30).frame(maxWidth: .infinity)
    }

}

/// Compose a feed post: text, an optional photo, and/or an Apple Music song.
struct PostComposer: View {
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var music: MusicTrack?
    @State private var pickerItem: PhotosPickerItem?
    @State private var imageData: Data?
    @State private var showMusic = false
    @State private var showEditor = false
    /// The servers whose feed this can go to. With more than one, the composer asks which.
    var sources: [FeedSource] = []
    var preferred: String? = nil
    @State private var target: String?
    /// (text, song, photo, server id — nil when there was nothing to choose).
    var onPost: (String, MusicTrack?, Data?, String?) -> Void

    private var chosen: String? { target ?? sources.first(where: { $0.serverId == preferred })?.serverId ?? sources.first?.serverId }

    var body: some View {
        NavigationStack {
            ZStack {
                SkwodBackground()
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        if sources.count > 1 {
                            // A post goes to ONE server's feed: say which.
                            HStack {
                                Text("Post to").font(.subheadline).foregroundStyle(.white.opacity(0.6))
                                Picker("Post to", selection: Binding(get: { chosen ?? "" }, set: { target = $0 })) {
                                    ForEach(sources) { src in Text(src.name).tag(src.serverId) }
                                }
                                .pickerStyle(.menu).labelsHidden().tint(.skAccent)
                                .accessibilityIdentifier("feed.serverPicker")
                                Spacer()
                            }
                        }
                        TextField("Share something…", text: $text, axis: .vertical)
                            .textFieldStyle(.plain).foregroundStyle(.white).font(.title3)
                            .lineLimit(3...8)
                            .padding(14)
                            .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        if let data = imageData, let img = Image(data: data) {
                            // Instagram-style 1:1 square crop preview.
                            Color.clear.aspectRatio(1, contentMode: .fit)
                                .overlay { img.resizable().scaledToFill() }
                                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                            HStack {
                                Button { showEditor = true } label: { Label("Edit", systemImage: "wand.and.stars") }
                                    .buttonStyle(.glass).controlSize(.small).tint(.skAccent)
                                Button(role: .destructive) { imageData = nil; pickerItem = nil } label: { Label("Remove photo", systemImage: "xmark") }
                                    .buttonStyle(.glass).controlSize(.small)
                            }
                        }
                        if let m = music {
                            MusicCard(track: m)
                            Button(role: .destructive) { music = nil } label: { Label("Remove song", systemImage: "xmark") }
                                .buttonStyle(.glass).controlSize(.small)
                        }
                        HStack {
                            PhotosPicker(selection: $pickerItem, matching: .images) {
                                Label("Photo", systemImage: "photo").frame(maxWidth: .infinity).padding(.vertical, 2)
                            }.buttonStyle(.glass).tint(.skAccent)
                            if music == nil {
                                Button { showMusic = true } label: {
                                    Label("Music", systemImage: "music.note").frame(maxWidth: .infinity).padding(.vertical, 2)
                                }.buttonStyle(.glass).tint(.skAccent)
                            }
                        }
                        Spacer(minLength: 0)
                    }
                    .padding()
                }
            }
            .navigationTitle("New post")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Post") { onPost(text.trimmingCharacters(in: .whitespacesAndNewlines), music, imageData, chosen); dismiss() }
                        .disabled(text.trimmingCharacters(in: .whitespaces).isEmpty && music == nil && imageData == nil)
                }
            }
            .sheet(isPresented: $showMusic) { MusicSearchSheet { music = $0 } }
            .storyEditorCover(isPresented: $showEditor) {
                // Instagram-style editor pass over the post photo: filters + draggable text,
                // flattened back into the photo (1:1 canvas).
                StoryEditorView(mode: .post, initialImage: imageData) { edited, song, _ in
                    if let edited { imageData = edited }
                    if let song { music = song }
                }
            }
            .task(id: pickerItem) {
                if let item = pickerItem, let data = try? await item.loadTransferable(type: Data.self) {
                    imageData = data
                }
            }
        }
    }
}

/// Create/update your story: pick a photo (PhotosPicker) and/or attach an Apple Music song.
struct StoryComposer: View {
    @Environment(\.dismiss) private var dismiss
    @State private var pickerItem: PhotosPickerItem?
    @State private var imageData: Data?
    @State private var music: MusicTrack?
    @State private var showMusic = false
    var onPost: (Data?, MusicTrack?) -> Void

    var body: some View {
        NavigationStack {
            ZStack {
                SkwodBackground()
                VStack(spacing: 16) {
                    PhotosPicker(selection: $pickerItem, matching: .images) {
                        photoWell
                    }.buttonStyle(.plain)

                    if let m = music {
                        MusicCard(track: m)
                        Button(role: .destructive) { music = nil } label: { Label("Remove song", systemImage: "xmark") }
                            .buttonStyle(.glass).controlSize(.small)
                    } else {
                        Button { showMusic = true } label: {
                            Label("Add music", systemImage: "music.note").frame(maxWidth: .infinity).padding(.vertical, 2)
                        }.buttonStyle(.glass).tint(.skAccent)
                    }
                    Spacer()
                }
                .padding()
            }
            .navigationTitle("Your story")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Share") { onPost(imageData, music); dismiss() }
                        .disabled(imageData == nil && music == nil)
                }
            }
            .sheet(isPresented: $showMusic) { MusicSearchSheet { music = $0 } }
            .task(id: pickerItem) {
                if let item = pickerItem, let data = try? await item.loadTransferable(type: Data.self) {
                    imageData = data
                }
            }
        }
    }

    @ViewBuilder private var photoWell: some View {
        RoundedRectangle(cornerRadius: 20, style: .continuous)
            .fill(.white.opacity(0.05))
            .frame(height: 300)
            .overlay {
                if let data = imageData, let img = Image(data: data) {
                    img.resizable().scaledToFill()
                } else {
                    VStack(spacing: 8) {
                        Image(systemName: "photo.badge.plus").font(.system(size: 40)).foregroundStyle(.skAccent)
                        Text("Add a photo").font(.subheadline).foregroundStyle(.white.opacity(0.6))
                    }
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(.white.opacity(0.1), lineWidth: 1))
    }
}

/// Story viewer: the photo (or a colored gradient) with the author and the attached song.
/// Full-screen on iOS; a fixed story-shaped card on macOS (an unconstrained sheet would size itself
/// to the photo's pixels and swallow the window). Esc or the ✕ closes it.
struct StoryViewer: View {
    let item: FeedItem
    /// Delete this story for everyone (offered on my own).
    var onDelete: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase
    /// A finger (or the pointer) is held on the story: it — and its song — pause.
    @State private var pressing = false

    /// Paused: held, or (iPhone) the app is not in front.
    private var held: Bool {
        #if os(iOS)
        return pressing || scenePhase != .active
        #else
        return pressing
        #endif
    }

    var body: some View {
        GeometryReader { geo in
            ZStack {
                Color.black
                    .contentShape(Rectangle())
                    // Never completes, so `pressing` is exactly "is it being held right now".
                    .onLongPressGesture(minimumDuration: .infinity, perform: {}, onPressingChanged: { pressing = $0 })
                if item.photoData != nil || item.attachment != nil {
                    // Opening a story is asking for its picture.
                    FeedPhoto(thumb: item.photoData, attachment: item.attachment, autoLoad: true)
                        .frame(width: geo.size.width, height: geo.size.height)
                        .clipped()
                        .allowsHitTesting(false)
                    LinearGradient(colors: [.black.opacity(0.5), .clear, .black.opacity(0.6)], startPoint: .top, endPoint: .bottom)
                        .allowsHitTesting(false)
                } else {
                    Rectangle().fill(Color.seeded(item.author).gradient).opacity(0.5).allowsHitTesting(false)
                }
                VStack {
                    HStack(spacing: 10) {
                        Circle().fill(Color.seeded(item.author).gradient).frame(width: 34, height: 34)
                            .overlay(Text(item.author.prefix(1).uppercased()).font(.subheadline.bold()).foregroundStyle(.white))
                        Text(item.author).font(.headline).foregroundStyle(.white)
                        Spacer()
                        if item.mine, let onDelete {
                            Button { onDelete(); dismiss() } label: { Image(systemName: "trash").font(.headline).foregroundStyle(.white) }
                                .buttonStyle(.plain).padding(.trailing, 14)
                                .help("Delete this story for everyone")
                                .accessibilityLabel("Delete story")
                                .accessibilityIdentifier("story.delete")
                        }
                        Button { dismiss() } label: { Image(systemName: "xmark").font(.headline).foregroundStyle(.white) }
                            .buttonStyle(.plain)
                            .keyboardShortcut(.cancelAction)
                    }
                    .padding()
                    Spacer()
                    // The song starts by itself and plays the part its author chose.
                    if let m = item.music { StoryMusicStrip(track: m, clip: item.clip, held: held).padding() }
                }
            }
        }
        #if os(macOS)
        .frame(width: 430, height: 700)
        #else
        .ignoresSafeArea()
        #endif
        .onDisappear { MusicPreviewPlayer.shared.stop(); StoryClipPlayer.shared.stop() }
    }
}

/// A post opened to read + add comments. The post card up top, its comments below, an input pinned
/// at the bottom. Comments are E2EE channel messages — the server only ever sees ciphertext.
struct PostDetailSheet: View {
    let post: FeedItem
    @ObservedObject var feed: FeedModel
    @State private var draft = ""
    @State private var sending = false
    @Environment(\.dismiss) private var dismiss

    private var comments: [FeedComment] { feed.commentsByPost[post.id] ?? [] }

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 0) {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        FeedCard(item: currentPost, onLike: { Task { await feed.toggleLike(post) } },
                                 onDelete: { Task { await feed.delete(messageId: post.id, channelId: post.channelId); dismiss() } })
                        if comments.isEmpty {
                            Text("No comments yet — say something.")
                                .font(.subheadline).foregroundStyle(.white.opacity(0.45))
                                .frame(maxWidth: .infinity).padding(.top, 8)
                        } else {
                            ForEach(comments) { c in commentRow(c) }
                        }
                    }
                    .padding(16)
                }
                composer
            }
        }
        #if os(macOS)
        .frame(minWidth: 460, minHeight: 560)
        #endif
        .navigationTitle("Post")
    }

    /// Keep the like count / comment count fresh from the model as it polls.
    private var currentPost: FeedItem {
        feed.posts.first(where: { $0.id == post.id }) ?? post
    }

    private func commentRow(_ c: FeedComment) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Circle().fill(Color.seeded(c.author).gradient).frame(width: 28, height: 28)
                .overlay(Text(c.author.prefix(1).uppercased()).font(.caption2.bold()).foregroundStyle(.white))
            VStack(alignment: .leading, spacing: 2) {
                Text(c.mine ? "You" : c.author).font(.system(size: 13, weight: .semibold)).foregroundStyle(.white)
                Text(c.text).font(.system(size: 14)).foregroundStyle(.white.opacity(0.9))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .contextMenu {
            if c.mine {
                Button(role: .destructive) {
                    Task { await feed.delete(messageId: c.id, channelId: feed.channel(ofPost: c.postId)) }
                } label: { Label("Delete comment", systemImage: "trash") }
            }
        }
    }

    private var composer: some View {
        HStack(spacing: 10) {
            TextField("Add a comment…", text: $draft, axis: .vertical)
                .textFieldStyle(.plain).foregroundStyle(.white).lineLimit(1...4)
                #if os(iOS)
                .autocorrectionDisabled()
                #endif
            Button {
                let text = draft; draft = ""; sending = true
                Task { await feed.comment(on: post.id, text: text); sending = false }
            } label: {
                Image(systemName: "arrow.up.circle.fill").font(.system(size: 26))
                    .foregroundStyle(draft.trimmingCharacters(in: .whitespaces).isEmpty ? .white.opacity(0.25) : .skAccent)
            }
            .buttonStyle(.plain)
            .disabled(sending || draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
        .background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .padding(12)
    }
}

/// One post: author, optional text, optional photo, optional song, and a like/comment/lock row.
struct FeedCard: View {
    let item: FeedItem
    var onLike: () -> Void
    var onComment: (() -> Void)? = nil
    /// Delete this post for everyone (offered on my own posts).
    var onDelete: (() -> Void)? = nil
    /// Name the server under the author (when the feed mixes several servers).
    var showServer = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Circle().fill(Color.seeded(item.author).gradient).frame(width: 36, height: 36)
                    .overlay(Text(item.author.prefix(1).uppercased()).font(.subheadline.bold()).foregroundStyle(.white))
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.author).font(.headline).foregroundStyle(.white)
                    if showServer, !item.serverName.isEmpty {
                        Text(item.serverName).font(.caption2).foregroundStyle(.white.opacity(0.45))
                    }
                }
                Spacer()
                Text(relativeTime).font(.caption).foregroundStyle(.white.opacity(0.4))
                if item.mine, let onDelete {
                    Menu {
                        Button(role: .destructive, action: onDelete) { Label("Delete post", systemImage: "trash") }
                    } label: {
                        Image(systemName: "ellipsis").foregroundStyle(.white.opacity(0.6)).frame(width: 28, height: 28)
                    }
                    .menuStyle(.button).buttonStyle(.plain).fixedSize()
                    .accessibilityLabel("Post options")
                    .accessibilityIdentifier("feed.postMenu")
                }
            }
            // Instagram order: the square photo first, then the caption beneath it.
            if item.photoData != nil || item.attachment != nil {
                Color.clear.aspectRatio(1, contentMode: .fit)
                    .overlay { FeedPhoto(thumb: item.photoData, attachment: item.attachment) }
                    .frame(maxWidth: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
            if !item.text.isEmpty {
                Text(item.text).foregroundStyle(.white.opacity(0.92))
            }
            if let m = item.music { MusicCard(track: m) }
            HStack(spacing: 18) {
                Button(action: onLike) {
                    Label("\(item.likes)", systemImage: item.liked ? "heart.fill" : "heart")
                        .foregroundStyle(item.liked ? .pink : .white.opacity(0.7))
                }.buttonStyle(.plain)
                if let onComment {
                    Button(action: onComment) {
                        Label(item.commentCount > 0 ? "\(item.commentCount)" : "Comment", systemImage: "bubble.right")
                            .foregroundStyle(.white.opacity(0.7))
                    }.buttonStyle(.plain)
                }
                Spacer()
                Image(systemName: "lock.fill").font(.caption).foregroundStyle(.skAccent.opacity(0.6))
            }
            .font(.subheadline)
        }
        .padding(16)
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    private var relativeTime: String {
        let secs = Date().timeIntervalSince1970 - Double(item.createdAt) / 1000
        return secs < 60 ? "now" : RelativeDateTimeFormatter().localizedString(fromTimeInterval: -secs)
    }
}
