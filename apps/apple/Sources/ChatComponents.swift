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
    /// The conversation's stable id (channel id, DM or group conversation id). What is staged
    /// in the composer belongs to it, and only to it.
    var conversationId: String = ""
    /// Optional trailing header actions (e.g. invite, verify).
    @ViewBuilder var headerActions: () -> AnyView
    /// Pasted / dropped files and images waiting to go with the next send.
    @State private var staged: [StagedAttachment] = []
    @State private var dropTargeted = false
    @State private var intakeError: String?
    /// The conversation on screen right now (read by paste / drop results that finish later).
    @State private var activeConversation = ""
    @Environment(\.typingCenter) private var typing
    @Environment(\.messageExtras) private var surfaceExtras
    /// Who the draft mentions so far (ranges into the draft).
    @State private var mentionPayload = MentionPayload()
    @State private var mentionHighlight = 0

    var body: some View {
        VStack(spacing: 0) {
            ChatHeader(title: title, subtitle: subtitle, onBack: onBack, actions: headerActions)
            Divider().overlay(.white.opacity(0.08))
            messageList
            if let notice { notice }
            if !mentionMatches.isEmpty {
                MentionSuggestions(matches: mentionMatches, highlighted: min(mentionHighlight, mentionMatches.count - 1),
                                   onPick: pickMention)
            }
            if let typing { TypingIndicatorBar(center: typing) }
            if let banner = composingBanner {
                ComposeBanner(text: banner.text, isEdit: banner.isEdit, onCancel: { onCancelCompose?() })
            }
            ChatComposer(draft: $draft, sending: sending, sendError: intakeError ?? sendError,
                         placeholder: placeholder, onSend: sendWithMentions,
                         uploading: uploading, onSendFile: onSendFile, onSendMusic: onSendMusic,
                         onSendImage: onSendImage, staged: $staged,
                         mentionKey: mentionKey,
                         onIntake: { [conversationId] in take($0, startedFor: conversationId) })
        }
        .background(ChatBackground())
        // What waits in the composer belongs to THIS conversation: switching conversation
        // (the same surface, new content) never carries it along.
        .onAppear { activeConversation = conversationId }
        .onChange(of: conversationId) { _, now in
            staged = []; intakeError = nil
            activeConversation = now
            typing?.stoppedTyping()
            mentionPayload = MentionPayload()
        }
        // "Typing…" goes out while the user types here (throttled; nothing for an empty draft).
        .onChange(of: draft) { _, now in
            typing?.draftChanged(now)
            // Edited around a mention: keep only the ones still exactly in the text.
            let names = Dictionary(surfaceExtras.mentionable.map { ($0.userId, MentionAutocomplete.tokenSource(name: $0.name, username: $0.username)) }, uniquingKeysWith: { a, _ in a })
            mentionPayload = MentionAutocomplete.reconcile(mentionPayload, draft: now, names: names)
            mentionHighlight = 0
        }
        .onDisappear { typing?.stoppedTyping() }
        // Only this conversation's people show as typing in it.
        .onChange(of: TypingAudience(conversationId: conversationId, members: surfaceExtras.typingFrom), initial: true) { _, audience in
            typing?.setAudience(audience)
        }
        // Drop files or images (a Finder drag, the screenshot thumbnail, a picture from another
        // app, iPad drag and drop) anywhere on the chat: they wait in the composer like "Attach".
        .onDrop(of: ComposerIntake.dropTypes, isTargeted: $dropTargeted) { providers in
            guard acceptsAttachments else { return false }
            // Tagged with the conversation it was dropped on: a load that finishes after a
            // switch is discarded, never staged in the next conversation.
            let startedFor = conversationId
            return ComposerIntake.load(providers) { take([$0], startedFor: startedFor) }
        }
        .overlay {
            if dropTargeted && acceptsAttachments {
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(Color.skAccent, style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                    .background(Color.skAccent.opacity(0.06))
                    .overlay(Label("Drop to attach", systemImage: "paperclip").font(.headline).foregroundStyle(.white))
                    .padding(8)
                    .allowsHitTesting(false)
            }
        }
    }

    private var acceptsAttachments: Bool { onSendFile != nil || onSendImage != nil }

    /// Members matching the "@…" being typed (nothing when not in one, or none to mention).
    private var mentionMatches: [MentionCandidate] {
        guard !surfaceExtras.mentionable.isEmpty, let q = MentionAutocomplete.activeQuery(in: draft) else { return [] }
        return MentionAutocomplete.matches(q.query, in: surfaceExtras.mentionable)
    }

    private func pickMention(_ m: MentionCandidate) {
        guard let q = MentionAutocomplete.activeQuery(in: draft) else { return }
        draft = MentionComposer.pick(m, draft: draft, at: q.at, payload: &mentionPayload)
        mentionHighlight = 0
    }

    /// Arrow keys / Return / Tab while the popup is up (Mac). True = handled.
    private func mentionKey(_ key: KeyEquivalent) -> Bool {
        let matches = mentionMatches
        guard !matches.isEmpty else { return false }
        switch key {
        case .upArrow: mentionHighlight = max(0, mentionHighlight - 1)
        case .downArrow: mentionHighlight = min(matches.count - 1, mentionHighlight + 1)
        case .return, .tab: pickMention(matches[min(mentionHighlight, matches.count - 1)])
        default: return false
        }
        return true
    }

    /// The text goes out with who it mentions inside it (`MentionCodec`; end to end).
    private func sendWithMentions() {
        typing?.stoppedTyping()
        let names = Dictionary(surfaceExtras.mentionable.map { ($0.userId, MentionAutocomplete.tokenSource(name: $0.name, username: $0.username)) }, uniquingKeysWith: { a, _ in a })
        let payload = MentionAutocomplete.reconcile(mentionPayload, draft: draft, names: names)
        if !payload.isEmpty { draft = MentionCodec.encode(draft, payload) }
        mentionPayload = MentionPayload()
        onSend()
    }

    /// Add what came in to the waiting list, or say why it couldn't be.
    private func take(_ results: [Result<StagedAttachment, ComposerIntake.Problem>], startedFor: String) {
        guard acceptsAttachments, StagingRule.belongs(startedFor: startedFor, current: activeConversation) else { return }
        intakeError = nil
        for r in results {
            switch r {
            case .success(let item):
                if staged.count < ComposerIntake.maxStaged { staged.append(item) }
                #if DEBUG
                E2E.stagedCount = staged.count
                #endif
            case .failure(let p):
                intakeError = ComposerIntake.sentence(p)
            }
        }
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
    /// The full text in a sheet where any part of it can be selected ("Select Text…").
    @State private var selecting = false
    /// A mention in this message was tapped: that person's card.
    @State private var profileFor: String?
    @Environment(\.openURL) private var confirmedOpenURL
    #if os(macOS)
    /// A long press on the Mac opens the same actions as a right-click.
    @State private var longPressMenu = false
    #endif

    var body: some View {
        // Hover lives in `HoverRow`, so moving the pointer over a row re-renders only its
        // highlight — not the row (markdown, images, the menu) as it used to on every hover.
        HoverRow(hoverTime: grouped ? shortTime : nil) { row }
            // A message that mentions me stands out.
            .background(mentionsMe ? Color.skAccent.opacity(0.10) : .clear)
            .overlay(alignment: .leading) {
                if mentionsMe { Rectangle().fill(Color.skAccent).frame(width: 2) }
            }
            .popover(isPresented: Binding(get: { profileFor != nil }, set: { if !$0 { profileFor = nil } })) {
                if let uid = profileFor {
                    MentionProfileCard(userId: uid, label: extras.mentionLabel?(uid) ?? "Unknown contact")
                }
            }
            .contextMenu { if !message.isDeleted { menuItems } }
            #if os(macOS)
            .onLongPressGesture(minimumDuration: 0.5) { if !message.isDeleted { longPressMenu = true } }
            .popover(isPresented: $longPressMenu, arrowEdge: .top) {
                MessageActionsPopover { menuItems }
            }
            #endif
            .sheet(isPresented: $selecting) {
                DismissableSheet { SelectableTextSheet(text: message.body) }
            }
    }

    private var row: some View {
        HStack(alignment: .top, spacing: 12) {
            if grouped {
                // Reserve the avatar gutter (the time shows there on hover: `HoverRow`).
                Color.clear.frame(width: 40, height: 1)
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
            Button { selecting = true } label: { Label("Select Text…", systemImage: "selection.pin.in.out") }
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
                Text(MessageText.attributed(message.body)).font(.system(size: 15)).foregroundStyle(.white.opacity(0.92))
                    .tint(.skAccent)
                    .fixedSize(horizontal: false, vertical: true)
            }
        } else if let track = message.music {
            MusicCard(track: track).frame(maxWidth: 380)
        } else if isEmojiOnly(message.body) {
            Text(message.body).font(.system(size: 44))
                .fixedSize(horizontal: false, vertical: true)
        } else {
            // No per-row `.textSelection`: on the Mac every selectable row is a text view of its
            // own whose click-tracking hit-tests the whole text on the main thread (the build-44
            // hang: 1.4 s in NSTextSelectionNavigation), and on iOS it takes the long press the
            // message menu needs. "Copy Text" and "Select Text…" are in that menu instead.
            Text(renderedBody).font(.system(size: 15)).foregroundStyle(.white.opacity(0.92))
                .tint(.skAccent)
                .fixedSize(horizontal: false, vertical: true)
                .environment(\.openURL, OpenURLAction { url in
                    if let uid = MentionRender.userId(from: url) { profileFor = uid; return .handled }
                    confirmedOpenURL(url)   // every other link still goes through its confirmation
                    return .handled
                })
        }
    }

    private var mentionsMe: Bool {
        !message.mine && MentionRule.mentionsMe(message.mentions, me: extras.me ?? "",
                                                senderMayMentionEveryone: extras.everyoneAllowed?(message.authorId) ?? false,
                                                replyToMine: false)
    }

    private var renderedBody: AttributedString {
        let base = MessageText.attributed(message.body)
        guard !message.mentions.isEmpty, let label = extras.mentionLabel else { return base }
        return MentionRender.apply(base, visible: message.body, payload: message.mentions, label: label,
                                   everyoneAllowed: extras.everyoneAllowed?(message.authorId) ?? false)
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
    @Binding var staged: [StagedAttachment]
    var mentionKey: (KeyEquivalent) -> Bool = { _ in false }
    var onIntake: ([Result<StagedAttachment, ComposerIntake.Problem>]) -> Void = { _ in }
    @State private var showEmoji = false
    @FocusState private var fieldFocused: Bool
    #if os(macOS)
    @State private var pasteMonitor = ComposerPasteMonitor()
    #endif
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
            StagedAttachmentsTray(staged: $staged)
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
                // The picker is anchored to THIS button (the system character palette opened at
                // the text caret, i.e. the left of the bar).
                Button { showEmoji.toggle() } label: {
                    Image(systemName: "face.smiling")
                        .font(.system(size: 20)).foregroundStyle(.white.opacity(0.45))
                }
                .buttonStyle(.plain).help("Emoji")
                .accessibilityIdentifier("composer.emoji")
                .popover(isPresented: $showEmoji, arrowEdge: .top) {
                    EmojiPickerPopover { e in draft += e }
                }
                sendButton
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.white.opacity(0.08), lineWidth: 1))
            #endif
        }
        .padding(12)
        #if os(macOS)
        // ⌘V with files or an image on the clipboard attaches them (text pastes as always).
        .onAppear {
            pasteMonitor.start(isFocused: { fieldFocused && (onSendFile != nil || onSendImage != nil) },
                               deliver: { onIntake($0) })
        }
        .onDisappear { pasteMonitor.stop() }
        #endif
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
                    // The text field ignores pasted images; this takes them. (Reading the
                    // clipboard asks the user's permission the first time.)
                    if UIPasteboard.general.hasImages {
                        Button { onIntake(ComposerIntake.fromPasteboard()) } label: { Label("Paste Image", systemImage: "doc.on.clipboard") }
                    }
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

    @ViewBuilder private var field: some View {
        #if os(iOS)
        // A UITextView underneath, so the system Paste (edit menu, ⌘V) takes pictures and files.
        ComposerTextView(text: $draft, placeholder: placeholder,
                         onPasteItems: { providers in
                             _ = ComposerIntake.load(providers) { onIntake([$0]) }
                         })
            .overlay(alignment: .topLeading) {
                if draft.isEmpty {
                    Text(placeholder).foregroundStyle(.white.opacity(0.4)).allowsHitTesting(false)
                }
            }
        #else
        TextField(placeholder, text: $draft, axis: .vertical)
            .textFieldStyle(.plain).foregroundStyle(.white).lineLimit(1...6)
            .focused($fieldFocused)
            .onKeyPress(keys: [.upArrow, .downArrow, .tab, .return]) { press in
                mentionKey(press.key) ? .handled : .ignored
            }
            .onSubmit(send)
        #endif
    }

    private var hasText: Bool { !draft.trimmingCharacters(in: .whitespaces).isEmpty }

    /// Text (if any) goes as before; each waiting attachment goes exactly as "Attach" sends it.
    private func send() {
        guard !sending, hasText || !staged.isEmpty else { return }
        if hasText { onSend() }
        let items = staged
        staged = []
        for item in items {
            switch item.payload {
            case .image(let data):
                if let onSendImage { onSendImage(data) }
            case .file(let url):
                onSendFile?(url)
            }
        }
    }

    private var sendButton: some View {
        Button(action: send) {
            Image(systemName: sending ? "hourglass" : "arrow.up.circle.fill")
                .font(.system(size: 24))
                .foregroundStyle(!hasText && staged.isEmpty ? .white.opacity(0.25) : .skAccent)
        }
        .buttonStyle(.plain)
        .disabled(sending || (!hasText && staged.isEmpty))
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

/// A row's hover highlight (and, for a grouped follow-up, its time in the avatar gutter), with
/// its own state: hovering re-renders this wrapper, not the row inside it.
private struct HoverRow<Content: View>: View {
    var hoverTime: String?
    @ViewBuilder let content: Content
    @State private var hovering = false

    var body: some View {
        content
            .overlay(alignment: .topLeading) {
                if hovering, let hoverTime {
                    Text(hoverTime)
                        .font(.system(size: 10, design: .monospaced)).foregroundStyle(.white.opacity(0.35))
                        .frame(width: 40, alignment: .trailing)
                        .padding(.leading, 16).padding(.top, 3)
                        .allowsHitTesting(false)
                }
            }
            .background(hovering ? Color.white.opacity(0.04) : .clear)
            .onHover { hovering = $0 }
    }
}

/// Rendered message text, kept: parsing markdown and checking links is not free, and a list
/// re-renders rows often. Keyed by the body (bounded; evicted under memory pressure).
enum MessageText {
    private static let cache: NSCache<NSString, Box> = {
        let c = NSCache<NSString, Box>()
        c.countLimit = 2000
        return c
    }()
    private final class Box { let value: AttributedString; init(_ v: AttributedString) { value = v } }

    static func attributed(_ body: String) -> AttributedString {
        // Very long bodies are still rendered in full; only the cache key is the body itself.
        let key = body as NSString
        if let hit = cache.object(forKey: key) { return hit.value }
        let value = LinkSafety.attributed(body)
        cache.setObject(Box(value), forKey: key)
        return value
    }
}

/// The message actions as a small popover (a long press on the Mac; right-click shows the same
/// items as a context menu).
private struct MessageActionsPopover<Items: View>: View {
    @ViewBuilder let items: Items
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 2) { items }
            .buttonStyle(.borderless)
            .labelStyle(.titleAndIcon)
            .padding(10)
            .frame(minWidth: 200, alignment: .leading)
            .simultaneousGesture(TapGesture().onEnded { dismiss() })
    }
}

/// The whole message, selectable, for copying any part of it.
private struct SelectableTextSheet: View {
    let text: String
    var body: some View {
        ScrollView {
            Text(text).font(.system(size: 15)).foregroundStyle(.white)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(20)
        }
        #if os(macOS)
        .frame(minWidth: 420, minHeight: 240)
        #endif
    }
}
