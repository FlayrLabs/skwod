import SwiftUI

/// Why a send failed, as a sentence. An attachment the server refused (quota, disk, no space)
/// and a message the core refused (too big) come with their own sentence; everything else is
/// the connection.
func sendFailureText(_ error: Error) -> String {
    if let a = error as? AttachmentError, let text = a.errorDescription { return text }
    if case CoreError.Invalid(let detail) = error, !detail.isEmpty {
        return detail.prefix(1).uppercased() + detail.dropFirst()
    }
    return coreErrorText(error, fallback: "Couldn't send — check your connection and try again.")
}

/// The shared chat surface used by both channels and DMs: a header, a scrolling
/// message list with sender grouping (avatar + name + time on the first of a run, tight follow-ups),
/// and a composer. All content is end-to-end encrypted; this is purely presentation.
struct ChatSurface: View {
    let title: String            // "#general" or a person's name
    let subtitle: String?        // e.g. "end-to-end encrypted"
    let messages: [ChatMessage]
    @Binding var draft: String
    var sending: Bool
    /// Why the last send failed, in a sentence for the user (nil = it didn't).
    var sendError: String?
    var placeholder: String
    var onSend: () -> Void
    /// "Load older": shown at the top of the list while there is more history to page in.
    var onLoadOlder: (() -> Void)? = nil
    var loadingOlder: Bool = false
    var reachedStart: Bool = false
    /// Attachment hooks (nil hides the affordances): a picked file / song to send E2EE.
    var uploading: Bool = false
    var onSendFile: ((URL) -> Void)? = nil
    var onSendMusic: ((MusicTrack) -> Void)? = nil
    var onSendImage: ((Data) -> Void)? = nil
    /// Back chevron (rendered on iOS only) — slides back to the channel list.
    var onBack: (() -> Void)? = nil
    /// Long-press / right-click message actions (nil hides them — e.g. demo previews).
    var onReact: ((ChatMessage, String) -> Void)? = nil
    var onReply: ((ChatMessage) -> Void)? = nil
    var onEdit: ((ChatMessage) -> Void)? = nil
    var onDelete: ((ChatMessage) -> Void)? = nil
    var onForward: ((ChatMessage) -> Void)? = nil
    /// The button on a system row was pressed (e.g. "Review" on a held member, "View safety
    /// number" on a changed contact). Nil hides those buttons.
    var onSystemAction: ((ChatMessage) -> Void)? = nil
    /// A notice pinned above the composer (e.g. "sending is paused — safety number changed").
    var notice: AnyView? = nil
    /// A reply/edit banner shown above the composer, with a way to cancel it.
    var composingBanner: (text: String, isEdit: Bool)? = nil
    var onCancelCompose: (() -> Void)? = nil
    /// Optional trailing header actions (e.g. invite, verify).
    @ViewBuilder var headerActions: () -> AnyView

    var body: some View {
        VStack(spacing: 0) {
            ChatHeader(title: title, subtitle: subtitle, onBack: onBack, actions: headerActions)
            Divider().overlay(.white.opacity(0.08))
            messageList
            if let notice { notice }
            if let banner = composingBanner {
                ComposeBanner(text: banner.text, isEdit: banner.isEdit, onCancel: { onCancelCompose?() })
            }
            ChatComposer(draft: $draft, sending: sending, sendError: sendError,
                         placeholder: placeholder, onSend: onSend,
                         uploading: uploading, onSendFile: onSendFile, onSendMusic: onSendMusic,
                         onSendImage: onSendImage)
        }
        .background(ChatBackground())
    }

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    if messages.isEmpty {
                        emptyState
                    } else {
                        if let onLoadOlder {
                            olderControl(onLoadOlder)
                        }
                        ForEach(Array(messages.enumerated()), id: \.element.id) { i, m in
                            if let system = m.system {
                                // A security / membership event: a line of its own, never a bubble.
                                SystemRowView(row: system, text: m.body, createdAt: m.createdAt,
                                              onAction: onSystemAction.map { act in { act(m) } })
                                    .id(m.id)
                            } else {
                                MessageRow(message: m, grouped: isGrouped(i),
                                           onReact: onReact, onReply: onReply, onEdit: onEdit,
                                           onDelete: onDelete, onForward: onForward)
                                    .id(m.id)
                            }
                        }
                    }
                }
                .padding(.vertical, 16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .confirmingLinks()
            // Follow the conversation when something NEW arrives at the bottom — not when older
            // pages are added at the top, which must leave the reader where they are.
            .onChange(of: messages.last?.id) { _, _ in
                if let last = messages.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
        }
    }

    /// The top of the list: a way to page further back, or a line saying this is the start.
    @ViewBuilder private func olderControl(_ load: @escaping () -> Void) -> some View {
        HStack {
            Spacer()
            if reachedStart {
                Text("This is the start of \(title)").font(.caption).foregroundStyle(.white.opacity(0.35))
            } else if loadingOlder {
                ProgressView().controlSize(.small)
            } else {
                Button(action: load) {
                    Label("Load older messages", systemImage: "arrow.up.circle")
                        .font(.caption.weight(.semibold)).foregroundStyle(.skAccent)
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .background(.white.opacity(0.06), in: Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("chat.loadOlder")
            }
            Spacer()
        }
        .padding(.bottom, 8)
    }

    /// A follow-up from the same author within 5 minutes hides the avatar/name (message grouping).
    private func isGrouped(_ i: Int) -> Bool {
        guard i > 0 else { return false }
        let prev = messages[i - 1], cur = messages[i]
        return prev.system == nil && cur.system == nil && prev.author == cur.author && abs(cur.createdAt - prev.createdAt) < 5 * 60 * 1000
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: "lock.circle.fill").font(.system(size: 40)).foregroundStyle(.skAccent.opacity(0.6))
            Text("This is the beginning of \(title)").font(.title3.weight(.bold)).foregroundStyle(.white)
            Text("Messages here are end-to-end encrypted — only members can read them.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.5))
        }
        .padding(.horizontal, 20).padding(.top, 24)
    }
}

/// A security or membership event inside a conversation: "Sam joined (approved by you)", "Sam
/// added a device", "the server lists someone nobody approved". Centred, quiet for routine events
/// and amber for ones that need a decision, with an optional action.
struct SystemRowView: View {
    let row: SystemRow
    let text: String
    let createdAt: Int64
    var onAction: (() -> Void)? = nil

    private var tint: Color { row.warning ? .orange : .white.opacity(0.55) }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Image(systemName: row.icon).font(.system(size: 11, weight: .semibold)).foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 4) {
                Text(text).font(.system(size: 12.5)).foregroundStyle(.white.opacity(row.warning ? 0.9 : 0.6))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    if createdAt > 0 {
                        Text(Date(timeIntervalSince1970: Double(createdAt) / 1000).formatted(date: .abbreviated, time: .shortened))
                            .font(.system(size: 10)).foregroundStyle(.white.opacity(0.3))
                    }
                    if let label = row.actionLabel, let onAction {
                        Button(label, action: onAction)
                            .font(.system(size: 11, weight: .semibold)).buttonStyle(.plain)
                            .foregroundStyle(row.warning ? .orange : .skAccent)
                    }
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background((row.warning ? Color.orange.opacity(0.10) : .white.opacity(0.04)),
                    in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
            .strokeBorder(row.warning ? .orange.opacity(0.35) : .white.opacity(0.07), lineWidth: 1))
        .frame(maxWidth: 520)
        .frame(maxWidth: .infinity, alignment: .center)
        .padding(.horizontal, 16).padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }
}

/// One message row. First-in-run shows avatar + name + timestamp; grouped follow-ups are tight and
/// show the time only on hover.
private struct MessageRow: View {
    let message: ChatMessage
    let grouped: Bool
    var onReact: ((ChatMessage, String) -> Void)? = nil
    var onReply: ((ChatMessage) -> Void)? = nil
    var onEdit: ((ChatMessage) -> Void)? = nil
    var onDelete: ((ChatMessage) -> Void)? = nil
    var onForward: ((ChatMessage) -> Void)? = nil
    @Environment(\.messageExtras) private var extras
    @State private var hovering = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            if grouped {
                // Reserve the avatar gutter; show the time there on hover.
                Text(hovering ? shortTime : "")
                    .font(.system(size: 10, design: .monospaced)).foregroundStyle(.white.opacity(0.35))
                    .frame(width: 40, alignment: .trailing)
            } else {
                AvatarImage(key: message.authorId.map(AvatarStore.userKey), name: message.author, size: 40)
            }

            VStack(alignment: .leading, spacing: 2) {
                if let preview = message.replyPreview {
                    // The quoted-reply line above the message.
                    HStack(spacing: 4) {
                        Image(systemName: "arrowshape.turn.up.left.fill").font(.system(size: 9)).foregroundStyle(.white.opacity(0.35))
                        Text(preview).font(.system(size: 12)).foregroundStyle(.white.opacity(0.45)).lineLimit(1)
                    }
                }
                if !grouped {
                    HStack(spacing: 8) {
                        Text(message.mine ? "You" : message.author)
                            .font(.system(size: 15, weight: .semibold)).foregroundStyle(.white)
                        Text(fullTime).font(.system(size: 11)).foregroundStyle(.white.opacity(0.4))
                    }
                }
                messageBody
                if message.isEdited && !message.isDeleted {
                    Text("(edited)").font(.system(size: 10)).foregroundStyle(.white.opacity(0.3))
                }
                if let state = message.sendState, !message.isDeleted {
                    SendStateLine(state: state, onRetry: extras.onRetry, onDiscard: extras.onDiscard)
                }
                if !message.reactionPills.isEmpty {
                    HStack(spacing: 5) {
                        ForEach(message.reactionPills) { r in
                            Button { onReact?(message, r.emoji) } label: {
                                HStack(spacing: 3) {
                                    Text(r.emoji).font(.caption)
                                    if r.count > 1 { Text("\(r.count)").font(.caption2).foregroundStyle(.white.opacity(0.7)) }
                                }
                                .padding(.horizontal, 8).padding(.vertical, 3)
                                .background((r.mine ? Color.skAccent.opacity(0.28) : .white.opacity(0.08)), in: Capsule())
                                .overlay(Capsule().strokeBorder(r.mine ? .skAccent.opacity(0.6) : .white.opacity(0.12), lineWidth: 1))
                            }
                            .buttonStyle(.plain)
                        }
                    }.padding(.top, 3)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 16)
        .padding(.top, grouped ? 1 : 10)
        .padding(.bottom, 1)
        .background(hovering ? Color.white.opacity(0.04) : .clear)
        .onHover { hovering = $0 }
        .contextMenu { if !message.isDeleted { menuItems } }
    }

    /// Long-press / right-click actions. React row first, then copy/reply/forward, then
    /// edit/delete for your own messages.
    @ViewBuilder private var menuItems: some View {
        if onReact != nil {
            ControlGroup {
                ForEach(quickReactions, id: \.self) { e in
                    Button(e) { onReact?(message, e) }
                }
            }
        }
        if !message.body.isEmpty {
            Button { Clipboard.copy(message.body) } label: { Label("Copy Text", systemImage: "doc.on.doc") }
        }
        if onReply != nil {
            Button { onReply?(message) } label: { Label("Reply", systemImage: "arrowshape.turn.up.left") }
        }
        if onForward != nil {
            Button { onForward?(message) } label: { Label("Forward", systemImage: "arrowshape.turn.up.right") }
        }
        if message.mine {
            if onEdit != nil, message.attachment == nil, message.music == nil {
                Button { onEdit?(message) } label: { Label("Edit", systemImage: "pencil") }
            }
            if onDelete != nil {
                Button(role: .destructive) { onDelete?(message) } label: { Label("Delete", systemImage: "trash") }
            }
        } else if message.authorId != nil {
            // Someone else's message: report it (optionally with what it says) or block them.
            if extras.onReport != nil || extras.onBlock != nil { Divider() }
            if let onReport = extras.onReport {
                Button(role: .destructive) { onReport(message) } label: { Label("Report…", systemImage: "exclamationmark.bubble") }
            }
            if let onBlock = extras.onBlock {
                Button(role: .destructive) { onBlock(message) } label: { Label("Block \(message.author)…", systemImage: "hand.raised") }
            }
        }
    }

    /// Message content: attachments render as media bubbles (image/video/audio/file), shared songs
    /// as a playable MusicCard; short all-emoji messages render large; everything
    /// else renders with inline markdown (bold/italic/`code`/links), links tinted with the accent.
    @ViewBuilder private var messageBody: some View {
        if message.isDeleted {
            Text("message deleted").font(.system(size: 14)).italic().foregroundStyle(.white.opacity(0.35))
        } else if let attachment = message.attachment {
            // Still uploading (the descriptor names a placeholder, not a blob): progress, not a
            // download button.
            if StreamedUpload.uploadId(forPlaceholder: attachment.blobId) != nil {
                UploadingAttachmentView(attachment: attachment)
            } else {
                AttachmentView(attachment: attachment)
            }
            if !message.body.isEmpty {
                Text(LinkSafety.attributed(message.body)).font(.system(size: 15)).foregroundStyle(.white.opacity(0.92))
                    .tint(.skAccent)
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
        } else if let track = message.music {
            MusicCard(track: track).frame(maxWidth: 380)
        } else if isEmojiOnly(message.body) {
            Text(message.body).font(.system(size: 44)).textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text(LinkSafety.attributed(message.body)).font(.system(size: 15)).foregroundStyle(.white.opacity(0.92))
                .tint(.skAccent)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }
    }

    /// True for a short message that is only emoji (+ whitespace) — rendered oversized.
    private func isEmojiOnly(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty, t.count <= 8 else { return false }
        return t.unicodeScalars.allSatisfy {
            $0.properties.isEmojiPresentation || $0.properties.isEmojiModifier
                || $0.value == 0x200D || $0 == " "
        }
    }

    private var date: Date { Date(timeIntervalSince1970: Double(message.createdAt) / 1000) }
    private var shortTime: String { date.formatted(date: .omitted, time: .shortened) }
    private var fullTime: String {
        message.createdAt == 0 ? "now" : date.formatted(date: .omitted, time: .shortened)
    }
}

/// The channel/DM header bar: `# title` + subtitle, with trailing actions (and a back chevron on
/// iOS).
private struct ChatHeader<Actions: View>: View {
    let title: String
    let subtitle: String?
    var onBack: (() -> Void)? = nil
    @ViewBuilder let actions: () -> Actions

    var body: some View {
        HStack(spacing: 8) {
            #if os(iOS)
            if let onBack {
                Button(action: onBack) {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 17, weight: .semibold)).foregroundStyle(.white.opacity(0.85))
                        .frame(width: 32, height: 32)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
            #endif
            // Channels render as a muted `#` glyph beside the bold name.
            if title.hasPrefix("#") {
                Image(systemName: "number")
                    .font(.system(size: 17, weight: .medium)).foregroundStyle(.white.opacity(0.45))
                Text(title.dropFirst()).font(.system(size: 16, weight: .bold)).foregroundStyle(.white)
            } else {
                Text(title).font(.system(size: 16, weight: .bold)).foregroundStyle(.white)
            }
            if let subtitle {
                Text("·").foregroundStyle(.white.opacity(0.3))
                Text(subtitle).font(.system(size: 12)).foregroundStyle(.white.opacity(0.45))
            }
            Spacer()
            actions()
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .frame(height: 48)
        .background(.ultraThinMaterial)
    }
}

/// The message composer: a rounded glass field with attach (file/music) and send affordances.
private struct ChatComposer: View {
    @Binding var draft: String
    let sending: Bool
    let sendError: String?
    let placeholder: String
    let onSend: () -> Void
    var uploading: Bool = false
    var onSendFile: ((URL) -> Void)? = nil
    var onSendMusic: ((MusicTrack) -> Void)? = nil
    var onSendImage: ((Data) -> Void)? = nil
    @State private var showFilePicker = false
    @State private var showMusicPicker = false
    @State private var showCamera = false
    @State private var showLibrary = false

    var body: some View {
        VStack(spacing: 4) {
            if let sendError {
                Text(sendError)
                    .font(.caption).foregroundStyle(.orange).frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 4)
                    .accessibilityIdentifier("chat.sendError")
            }
            if uploading {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.mini)
                    Text("Encrypting and uploading…").font(.caption).foregroundStyle(.white.opacity(0.55))
                }
                .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 4)
            }
            #if os(iOS)
            // Mobile: the + sits OUTSIDE the field in its own circle; the field is a capsule.
            HStack(spacing: 10) {
                attachButton
                    .frame(width: 40, height: 40)
                    .background(.ultraThinMaterial, in: Circle())
                    .overlay(Circle().strokeBorder(.white.opacity(0.08), lineWidth: 1))
                HStack(spacing: 10) {
                    field
                    sendButton
                }
                .padding(.horizontal, 14).padding(.vertical, 10)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: 22, style: .continuous).strokeBorder(.white.opacity(0.08), lineWidth: 1))
            }
            #else
            // Desktop: the + lives inside the field, with the emoji affordance trailing.
            HStack(spacing: 10) {
                attachButton
                field
                Button { NSApp.orderFrontCharacterPalette(nil) } label: {
                    Image(systemName: "face.smiling")
                        .font(.system(size: 20)).foregroundStyle(.white.opacity(0.45))
                }
                .buttonStyle(.plain).help("Emoji")
                sendButton
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.white.opacity(0.08), lineWidth: 1))
            #endif
        }
        .padding(12)
        .fileImporter(isPresented: $showFilePicker, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result { onSendFile?(url) }
        }
        .sheet(isPresented: $showMusicPicker) {
            MusicSearchSheet { onSendMusic?($0) }
        }
        #if os(iOS)
        .fullScreenCover(isPresented: $showCamera) {
            CameraPicker { data in onSendImage?(data) }.ignoresSafeArea()
        }
        .sheet(isPresented: $showLibrary) {
            LibraryPicker { data in onSendImage?(data) }
        }
        #endif
    }

    @ViewBuilder private var attachButton: some View {
        if onSendFile != nil || onSendMusic != nil || onSendImage != nil {
            Menu {
                #if os(iOS)
                if onSendImage != nil {
                    if UIImagePickerController.isSourceTypeAvailable(.camera) {
                        Button { showCamera = true } label: { Label("Take Photo", systemImage: "camera") }
                    }
                    Button { showLibrary = true } label: { Label("Photo Library", systemImage: "photo.on.rectangle") }
                }
                #endif
                if onSendFile != nil {
                    Button { showFilePicker = true } label: { Label("Upload a file", systemImage: "doc.badge.arrow.up") }
                }
                if onSendMusic != nil {
                    Button { showMusicPicker = true } label: { Label("Share a song", systemImage: "music.note") }
                }
            } label: {
                Image(systemName: "plus").font(.system(size: 19, weight: .semibold)).foregroundStyle(.white.opacity(0.6))
                    .contentShape(Rectangle())
            }
            .menuStyle(.button).menuIndicator(.hidden).buttonStyle(.plain).fixedSize()
            .disabled(uploading)
            .help("Attach")
        } else {
            Image(systemName: "plus").font(.system(size: 19, weight: .semibold)).foregroundStyle(.white.opacity(0.35))
        }
    }

    private var field: some View {
        TextField(placeholder, text: $draft, axis: .vertical)
            .textFieldStyle(.plain).foregroundStyle(.white).lineLimit(1...6)
            .onSubmit(onSend)
    }

    private var sendButton: some View {
        Button(action: onSend) {
            Image(systemName: sending ? "hourglass" : "arrow.up.circle.fill")
                .font(.system(size: 24))
                .foregroundStyle(draft.trimmingCharacters(in: .whitespaces).isEmpty ? .white.opacity(0.25) : .skAccent)
        }
        .buttonStyle(.plain)
        .disabled(sending || draft.trimmingCharacters(in: .whitespaces).isEmpty)
    }
}

/// The banner above the composer while replying to or editing a message — shows the target and a
/// cancel (×) to back out.
private struct ComposeBanner: View {
    let text: String
    let isEdit: Bool
    let onCancel: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: isEdit ? "pencil" : "arrowshape.turn.up.left.fill")
                .font(.system(size: 12)).foregroundStyle(.skAccent)
            Text(isEdit ? "Editing message" : text)
                .font(.caption).foregroundStyle(.white.opacity(0.7)).lineLimit(1)
            Spacer(minLength: 0)
            Button(action: onCancel) {
                Image(systemName: "xmark.circle.fill").font(.system(size: 15)).foregroundStyle(.white.opacity(0.5))
            }.buttonStyle(.plain)
        }
        .padding(.horizontal, 16).padding(.vertical, 8)
        .background(.ultraThinMaterial)
    }
}

/// Deep chat-pane background: the mesh glow under a faint frosted layer.
private struct ChatBackground: View {
    var body: some View {
        // The chat is the LIGHTEST step: two lifts above the chrome (sidebar is one). Still a
        // translucent wash — the backdrop's glow reads through it.
        Rectangle().fill(.white.opacity(0.085))
            .ignoresSafeArea()
    }
}

/// A standalone preview of the chat surface with mock messages, so the design can be reviewed
/// without a live server (SKWOD_SCREEN=chatpreview).
struct ChatSurfacePreview: View {
    @State private var draft = ""
    private let now = Int64(Date().timeIntervalSince1970 * 1000)
    var body: some View {
        ChatSurface(
            title: "#general",
            subtitle: "Weekend Crew",
            messages: sample,
            draft: $draft,
            sending: false,
            sendError: nil,
            placeholder: "Message #general",
            onSend: {},
            headerActions: { AnyView(Image(systemName: "person.badge.plus").foregroundStyle(.white.opacity(0.7))) }
        )
        #if os(macOS)
        .frame(minWidth: 700, minHeight: 600)
        #endif
    }
    private var sample: [ChatMessage] {
        [
            .init(id: "1", author: "robin", body: "hey! just joined 🦑", mine: false, createdAt: now - 600_000),
            .init(id: "2", author: "robin", body: "this place is **end-to-end** encrypted right?", mine: false, createdAt: now - 590_000),
            .init(id: "3", author: "you", body: "yep — the server only ever sees `ciphertext`", mine: true, createdAt: now - 500_000),
            .init(id: "4", author: "you", body: "even *I* can't read your DMs from the host box", mine: true, createdAt: now - 495_000),
            .init(id: "5", author: "sam", body: "🎉", mine: false, createdAt: now - 200_000),
            .init(id: "6", author: "sam", body: "nice. what's the safety number thing?", mine: false, reactionPills: [ReactionPill(emoji: "🔒", count: 1, mine: false), ReactionPill(emoji: "👍", count: 2, mine: true)], createdAt: now - 190_000),
            .init(id: "7", author: "you", body: "tap the shield in a DM — compare the 60 digits with the person to be sure no one's in the middle", mine: true, createdAt: now - 60_000),
        ]
    }
}
