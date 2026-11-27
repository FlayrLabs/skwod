import SwiftUI

struct CreateSpaceSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var channel = "general"
    @State private var busy = false
    @State private var error = ""
    var onCreate: (RealSpace) -> Void

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 16) {
                Text("Create a server").font(.title2.bold()).foregroundStyle(.white)
                Text("A server lives in your Skwod and holds its own channels and members.")
                    .font(.caption).foregroundStyle(.white.opacity(0.55)).multilineTextAlignment(.center)
                field("Server name", text: $name, icon: "person.3")
                field("First channel", text: $channel, icon: "number")
                if !error.isEmpty { Text(error).font(.caption).foregroundStyle(.red) }
                Button { Task { await create() } } label: {
                    HStack { if busy { ProgressView().controlSize(.small) }; Text("Create encrypted server") }
                        .frame(maxWidth: .infinity).padding(.vertical, 4)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black).disabled(busy || name.isEmpty || channel.isEmpty)
                Button("Cancel") { dismiss() }.buttonStyle(.glass)
            }
            .padding(28).frame(maxWidth: 400)
        }
        .presentationDetents([.medium])
    }

    private func create() async {
        guard let client = app.client else { return }
        busy = true; error = ""
        do {
            let s = try await client.createSpace(name: name, channelName: channel)
            onCreate(RealSpace(name: name, channelName: channel, serverId: s.serverId,
                               channelId: s.channelId, inviteCode: s.inviteCode, spaceKeyHex: s.spaceKeyHex))
            dismiss()
        } catch { self.error = "Couldn't create the space." }
        busy = false
    }

    @ViewBuilder private func field(_ label: String, text: Binding<String>, icon: String) -> some View {
        HStack {
            Image(systemName: icon).foregroundStyle(.skAccent).frame(width: 22)
            TextField(label, text: text).textFieldStyle(.plain).foregroundStyle(.white)
                #if os(iOS)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                #endif
        }
        .padding(14).glassEffect(.regular.interactive(), in: .capsule)
    }
}

/// A server within the skwod, as a sheet target (e.g. "new channel in this server").
struct ServerRef: Identifiable {
    let serverId: String
    let name: String
    var id: String { serverId }
}

/// Add a channel to an existing server (host holds the space key, so names stay E2EE).
struct NewChannelSheet: View {
    let server: ServerRef
    @ObservedObject var chat: ChatModel
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var busy = false
    @State private var error = ""

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 16) {
                Text("New channel in \(server.name)").font(.title2.bold()).foregroundStyle(.white)
                HStack {
                    Image(systemName: "number").foregroundStyle(.skAccent).frame(width: 22)
                    TextField("channel name", text: $name).textFieldStyle(.plain).foregroundStyle(.white)
                        #if os(iOS)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        #endif
                }
                .padding(14).glassEffect(.regular.interactive(), in: .capsule)
                if !error.isEmpty { Text(error).font(.caption).foregroundStyle(.red) }
                Button { Task { await create() } } label: {
                    HStack { if busy { ProgressView().controlSize(.small) }; Text("Create channel") }
                        .frame(maxWidth: .infinity).padding(.vertical, 4)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty)
                Button("Cancel") { dismiss() }.buttonStyle(.glass)
            }
            .padding(28).frame(maxWidth: 400)
        }
        .presentationDetents([.medium])
    }

    private func create() async {
        guard let client = app.client else { return }
        busy = true; error = ""
        do {
            let channelName = name.trimmingCharacters(in: .whitespaces)
            let channelId = try await client.createChannel(serverId: server.serverId, name: channelName)
            chat.addSpace(RealSpace(name: server.name, channelName: channelName, serverId: server.serverId,
                                    channelId: channelId, inviteCode: "", spaceKeyHex: ""))
            dismiss()
        } catch {
            self.error = "Couldn't create the channel — only members holding this server's key can."
        }
        busy = false
    }
}

/// Join a server with just an invite code. No space key, no channel id to paste:
/// the host's approval provisions you automatically and every channel appears in your sidebar.
struct JoinSpaceSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var chat: ChatModel
    @State private var invite = ""
    @State private var busy = false
    @State private var error = ""
    @State private var sent = false

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 14) {
                Text("Join a server").font(.title2.bold()).foregroundStyle(.white)
                if sent {
                    Image(systemName: "paperplane.circle.fill").font(.system(size: 40)).foregroundStyle(.skAccent)
                    Text("Request sent. Once the host approves you, the channels will appear here automatically.")
                        .font(.callout).foregroundStyle(.white.opacity(0.7)).multilineTextAlignment(.center)
                    Button("Done") { dismiss() }.controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                } else {
                    Text("Enter the invite code a friend shared with you.").font(.caption).foregroundStyle(.white.opacity(0.6))
                    field("Invite code", text: $invite, icon: "ticket")
                    if !error.isEmpty { Text(error).font(.caption).foregroundStyle(.red) }
                    Button { Task { await join() } } label: {
                        HStack { if busy { ProgressView().controlSize(.small) }; Text("Join") }
                            .frame(maxWidth: .infinity).padding(.vertical, 4)
                    }
                    .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                    .disabled(busy || invite.trimmingCharacters(in: .whitespaces).isEmpty)
                    Button("Cancel") { dismiss() }.buttonStyle(.glass)
                }
            }
            .padding(24).frame(maxWidth: 400)
        }
        .presentationDetents([.medium])
    }

    private func join() async {
        busy = true; error = ""
        // Accept a full one-paste invite link too — the code is everything after the '#'.
        var code = invite.trimmingCharacters(in: .whitespaces)
        if let hash = code.firstIndex(of: "#") { code = String(code[code.index(after: hash)...]) }
        code = InviteBeacon.strip(code)   // drop any trailing ~b.<pubkey>.<contentKey>
        if let err = await chat.joinByCode(code) {
            error = err
        } else {
            sent = true
        }
        busy = false
    }

    @ViewBuilder private func field(_ label: String, text: Binding<String>, icon: String) -> some View {
        HStack {
            Image(systemName: icon).foregroundStyle(.skAccent).frame(width: 22)
            TextField(label, text: text).textFieldStyle(.plain).foregroundStyle(.white).font(.callout)
                #if os(iOS)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                #endif
        }
        .padding(12).glassEffect(.regular.interactive(), in: .capsule)
    }
}

/// A real E2EE channel: Sender-Key-encrypted messages relayed through the server.
struct SpaceChannelView: View {
    let space: RealSpace
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var messages: [ChatMessage] = []
    @State private var draft = ""
    @State private var sending = false
    /// The skwod this conversation belongs to: what is sent here goes through its cache, or nowhere.
    @State private var home: String?
    @State private var sendError: String?
    @State private var uploading = false
    /// The newest window of the channel (what `fetchChannelMessages` returns) and the older
    /// pages the user asked for on top of it.
    @State private var latestRows: [Message] = []
    @State private var olderRows: [Message] = []
    @State private var loadingOlder = false
    @State private var reachedStart = false
    @State private var refreshing = false
    @State private var refreshAgain = false
    /// Build 51: the channel `messages` were loaded for; catch-ups that failed in a row, and the
    /// retry waiting for its turn (`FetchRetryRule`).
    @State private var loadedChannel: String?
    /// The conversation this composer was opened for: what is written here goes here, or nowhere.
    @State private var composedIn: String?
    private var maySend: Bool { Landing.maySend(composedIn: composedIn, now: chat.conversationKey(space)) }
    @State private var fetchFailures = 0
    @State private var retryTask: Task<Void, Never>?
    @State private var showInvite = false
    @State private var showChess = false
    @State private var showWhiteboard = false
    /// iOS presents the member roster as a sheet (macOS uses the side panel toggle below).
    @State private var showMembersSheet = false
    /// Members-list toggle (the people icon in the channel header). Persisted.
    @AppStorage("skwod.showMembers") private var showMembers = true
    /// A message being replied to (composer shows a banner; send links to it).
    @State private var replyingTo: ChatMessage?
    /// A message being edited (composer prefills its text; send patches it).
    @State private var editing: ChatMessage?
    /// A message being forwarded — presents the channel picker.
    @State private var forwarding: ChatMessage?
    /// Queued sends of this channel, by message id (`Outbox`).
    @State private var sendStates: [String: SendState] = [:]
    @State private var blocking: ReportTarget?
    @State private var reporting: ReportTarget?

    var body: some View {
        content
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        .navigationTitle("#\(space.channelName)")
        #endif
        .sheet(isPresented: $showInvite) { DismissableSheet { SecureJoinView(space: space) } }
        .sheet(isPresented: $showChess) { DismissableSheet { ChessView(channelId: space.channelId) } }
        .sheet(isPresented: $showWhiteboard) { DismissableSheet { WhiteboardView(channelId: space.channelId) } }
        // MembersSheetView brings its own NavigationStack + Done; don't wrap it in DismissableSheet
        // (that added a SECOND NavigationStack and a second Done button).
        .sheet(isPresented: $showMembersSheet) { MembersSheetView(serverId: space.serverId, serverName: space.name) }
        .sheet(item: $forwarding) { msg in
            ForwardPicker(message: msg, chat: chat) { target in forward(msg, to: target) }
        }
        // Keyed on the channel so switching servers/channels reloads — a plain `.task` runs once and the
        // switch statement REUSES this view across channels, so every server showed the first's messages.
        // Build 51: and on the client — a view opened before it was up (launch), or kept across a
        // re-bind (back from the background after the notification extension wrote the cache, a
        // replaced p2p session), reloads from the client that is up now and catches up through it.
        .task(id: ConversationLoadKey(id: "\(space.channelId)|\(chat.placementChosen)", clientTurn: app.clientTurn)) { await load() }
        .onAppear {
            guard composedIn == nil else { return }
            composedIn = chat.conversationKey(space)
            home = chat.spacesWorkspaceId
            draft = chat.draft(for: chat.conversationKey(space))
        }
        .onChange(of: draft) { _, now in if editing == nil, let composedIn { chat.keepDraft(now, for: composedIn) } }
        .onChange(of: app.clientTurn) { _, _ in if sendError == Compose.opening { sendError = nil } }
        .onReceive(NotificationCenter.default.publisher(for: .skwodCatchUp)) { _ in Task { await refresh() } }
        // Live: the relay says something happened in THIS channel (a message, an edit, a
        // delete, a reaction, a clear) → catch up now. No polling.
        .onReceive(NotificationCenter.default.publisher(for: .skwodChannelChanged)) { note in
            if note.object as? String == space.channelId { Task { await refresh() } }
        }
        .onReceive(NotificationCenter.default.publisher(for: .skwodLiveConnected)) { _ in
            Task { await syncMembers(); await refresh() }
        }
        // Something was queued, delivered, failed — or someone was blocked: redraw from the cache.
        .onReceive(NotificationCenter.default.publisher(for: .skwodOutboxChanged)) { _ in
            Task { await reloadLocal() }
        }
        .onReceive(app.realtime.$presence) { _ in presenceTick &+= 1 }
        .environment(\.messageExtras, MessageExtras(
            onReport: { msg in
                guard let id = msg.authorId else { return }
                reporting = ReportTarget(userId: id, name: msg.authorSpoken ?? msg.author, messageText: msg.body.isEmpty ? nil : msg.body, serverId: space.serverId,
                                           channelId: space.channelId, messageId: msg.id)
            },
            onBlock: { msg in
                guard let id = msg.authorId else { return }
                blocking = ReportTarget(userId: id, name: msg.authorSpoken ?? msg.author, serverId: space.serverId)
            },
            onRetry: { Outbox.retry(app, localId: $0) },
            onDiscard: { Outbox.discard(app, localId: $0) },
            me: app.session?.userId,
            mentionLabel: { mentionDisplay($0).label(for: .mentionChip) },
            mentionBadge: { mentionDisplay($0) },
            authorBadge: { display($0).badge },
            // @everyone counts from the server's PINNED owner and its admins (`EveryoneRule`).
            everyoneAllowed: { sender in chat.everyoneHonoured(sender, in: space.serverId) },
            mentionable: memberNames.filter { $0.key != app.session?.userId && !BlockList.shared.contains($0.key) }
                .map { (userId: $0.key, name: display($0.key).label(for: .mentionPicker), username: $0.value) }
                .sorted { $0.name.lowercased() < $1.name.lowercased() }
                + (chat.everyoneHonoured(app.session?.userId, in: space.serverId)
                   ? [(userId: MentionComposer.everyoneId, name: "everyone", username: "")] : []),
            typingFrom: memberNames))
        .safetyActions(blocking: $blocking, reporting: $reporting)
        .onReceive(NotificationCenter.default.publisher(for: .skwodServerChanged)) { note in
            if note.object as? String == space.serverId { Task { await syncMembers() } }
        }
        #if DEBUG
        .onReceive(NotificationCenter.default.publisher(for: .skwodE2ELoadOlder)) { _ in Task { await loadOlder() } }
        .onReceive(NotificationCenter.default.publisher(for: .skwodE2EShowMembers)) { _ in
            #if os(macOS)
            showMembers = true
            #else
            showMembersSheet = true
            #endif
        }
        #endif
    }

    @ViewBuilder private var content: some View {
        #if os(macOS)
        // The third column: the chat, then a members rail on the right — collapsible via the
        // people icon in the header.
        HStack(spacing: 0) {
            chatSurface
            if showMembers {
                MembersColumn(serverId: space.serverId)
                    .transition(.move(edge: .trailing))
            }
        }
        .animation(.snappy(duration: 0.22), value: showMembers)
        #else
        chatSurface
        #endif
    }

    /// "● N online": the server's members (the list this view already keeps for names and
    /// mentions, minus anyone still waiting to be let in) whose presence — seeded by the app's
    /// existing presence poll and updated live by the socket — isn't offline. No extra request.
    private var onlineCount: Int? {
        _ = presenceTick
        guard !memberNames.isEmpty else { return nil }
        let held = Set(app.waiting.waiting(in: space.serverId).map(\.userId))
        let me = app.session?.userId
        return PresenceRoster.onlineCount(memberNames.keys.filter { !held.contains($0) }, me: me, live: app.realtime.isLive) {
            app.realtime.status(userId: $0)
        }
    }

    private var chatSurface: some View {
        ChatSurface(
            title: "#\(space.channelName)",
            subtitle: space.name,
            messages: messages,
            draft: $draft,
            sending: sending,
            sendError: sendError,
            placeholder: "Message #\(space.channelName)",
            onSend: { send($0) },
            canSend: ready,
            onLoadOlder: { Task { await loadOlder() } },
            loadingOlder: loadingOlder,
            reachedStart: reachedStart,
            uploading: uploading,
            onSendFile: { url in sendAttachment(.file(url)) },
            onSendMusic: { track in sendMusic(track) },
            onSendImage: { data in sendAttachment(.image(data)) },
            onBack: { chat.reveal.send(false) },
            onReact: { msg, emoji in toggleReaction(msg, emoji) },
            onReply: { msg in editing = nil; replyingTo = msg },
            onEdit: { msg in replyingTo = nil; editing = msg; draft = msg.body },
            onDelete: { msg in deleteMessage(msg) },
            onForward: { msg in forwarding = msg },
            onSystemAction: { msg in
                // "Review" on a held member: open the member list, where "Waiting to join" is.
                guard msg.system?.kind == "member_held" else { return }
                #if os(macOS)
                showMembers = true
                #else
                showMembersSheet = true
                #endif
            },
            composingBanner: composingBanner,
            onCancelCompose: { if editing != nil { draft = "" }; replyingTo = nil; editing = nil },
            conversationId: space.channelId,
            onlineCount: onlineCount,
            syncStatus: FetchRetryRule.status(failures: fetchFailures, stripShowing: ConnectionBanner.shows(app)),
            onRetrySync: { fetchFailures = 0; Task { await refresh() } },
            onPullToRefresh: { await refresh(force: true) },
            headerActions: {
                AnyView(
                    HStack(spacing: 16) {
                        Button { showWhiteboard = true } label: {
                            Image(systemName: "scribble.variable").foregroundStyle(.white.opacity(0.7))
                        }.buttonStyle(.plain).help("Whiteboard")
                        Button { showChess = true } label: {
                            Image(systemName: "gamecontroller").foregroundStyle(.white.opacity(0.7))
                        }.buttonStyle(.plain).help("Chess")
                        Button { showInvite = true } label: {
                            Image(systemName: "person.badge.plus").foregroundStyle(.white.opacity(0.7))
                        }.buttonStyle(.plain).help("Invite")
                        #if os(macOS)
                        Button { showMembers.toggle() } label: {
                            Image(systemName: "person.2.fill")
                                .foregroundStyle(showMembers ? .white.opacity(0.9) : .white.opacity(0.45))
                                .overlay(alignment: .topTrailing) { CountBadge(count: waitingCount).offset(x: 9, y: -7) }
                        }.buttonStyle(.plain)
                            .help(waitingCount > 0 ? "\(waitingCount) waiting to join" : (showMembers ? "Hide member list" : "Show member list"))
                        #else
                        Button { showMembersSheet = true } label: {
                            Image(systemName: "person.2.fill").foregroundStyle(.white.opacity(0.7))
                                .overlay(alignment: .topTrailing) { CountBadge(count: waitingCount).offset(x: 9, y: -7) }
                        }.buttonStyle(.plain).help("Members")
                        #endif
                    }
                )
            }
        )
    }

    /// People waiting to be let into this server (badge on the members button).
    private var waitingCount: Int { app.waiting.count(in: space.serverId) }

    /// userId → username, so message authors render as real names instead of id prefixes.
    @State private var memberNames: [String: String] = [:]
    /// Bumped on every live presence event, so "● N online" follows the socket (Realtime is
    /// nested state).
    @State private var presenceTick = 0

    private func load() async {
        // No client yet: this runs again when one is up (keyed on `clientTurn`).
        guard let client = app.client else { return }
        if loadedChannel != space.channelId {
            messages = []   // clear the previous channel's messages so a switch never shows stale content
            olderRows = []; reachedStart = false
            loadedChannel = space.channelId
        }
        sendError = nil; fetchFailures = 0
        // The user opened this channel of this server (not the app, by default): that, on this device, is what confirms
        // where the channel belongs — what a later clear by that server's owner is checked
        // against (`channel_opened`). Only here, never for every channel a listing returns.
        // `false`: it is already confirmed under another server (a `channel_remap_refused`
        // notice follows and is shown with the others).
        if chat.placementChosen, !space.serverId.isEmpty, space.serverId != "demo", !space.channelId.isEmpty,
           !(await client.channelOpened(serverId: space.serverId, channelId: space.channelId)) {
            await app.surfaceSecurityNotices()
        }
        let cached = await client.history(scope: scope)
        // (A client whose cache was taken reads nothing: what is on screen stays.)
        guard app.client === client else { return }
        latestRows = cached
        messages = map(allRows)
        var tick = 0
        while !Task.isCancelled {
            // Distribute our sender key + refresh the name map on open, when the server says
            // its membership changed, and now and then — so newly joined members can decrypt
            // us (the host only relays its OWN key) and get named.
            if tick % 4 == 0 { await syncMembers() }
            tick += 1
            await Outbox.flush(app)
            await refresh()
            // The safety net behind the live events, not the mechanism: slow.
            try? await Task.sleep(for: LiveSync.safetyInterval)
        }
    }

    /// Older pages first, then the newest window; a row both hold is taken from the newest.
    private var allRows: [Message] {
        let recent = Set(latestRows.map(\.messageId))
        return olderRows.filter { !recent.contains($0.messageId) } + latestRows
    }

    /// "Load older": the previous page from this device's cache; when the cache has nothing
    /// older, the previous page from the server; when that is empty too, this is the start.
    private func loadOlder() async {
        guard let client = app.client, let me = app.session?.userId, !loadingOlder, !reachedStart else { return }
        loadingOlder = true
        defer { loadingOlder = false }
        let before = messages.count
        // A page can consist of rows chat does not show (feed posts, comments, avatars): keep
        // going until something visible turned up, within reason.
        for _ in 0..<6 {
            guard let oldest = allRows.first?.createdAt else { reachedStart = true; break }
            var page = await client.historyPage(scope: scope, beforeMs: oldest, limit: 100)
            if page.isEmpty {
                guard let fetched = try? await client.loadOlderChannelMessages(channelId: space.channelId, myUserId: me) else {
                    sendError = "Couldn't load older messages — check your connection."
                    break
                }
                await app.drainDmEvents()
                if fetched == 0 { reachedStart = true; break }
                page = await client.historyPage(scope: scope, beforeMs: oldest, limit: 100)
                if page.isEmpty { reachedStart = true; break }
            }
            olderRows = page + olderRows
            messages = map(allRows)
            if messages.count > before { break }
        }
    }

    /// Learn the member list (for author names) and make sure every member can read us.
    ///
    /// One core call does all the key work: it rotates our channel sender key if anyone holding it
    /// was kicked/banned/left (or one of their devices was removed), then hands the current key —
    /// over sealed libsignal sessions — to EVERY device of EVERY member that doesn't hold it yet,
    /// including a member's second device and our own other devices. Devices it couldn't reach are
    /// retried on the next pass.
    private func syncMembers() async {
        guard let client = app.client, let me = app.session?.userId else { return }
        _ = try? await client.syncChannelMembership(channelId: space.channelId, serverId: space.serverId, myUserId: me)
        // Whoever that sync left without keys is waiting for someone to let them in.
        await app.waiting.refresh(serverId: space.serverId)
        guard let members = try? await client.listMembers(serverId: space.serverId) else { return }
        for m in members { memberNames[m.userId] = m.username }
        // The names on screen are looked up now, not at the next minute's roster pass.
        app.contacts.checkSoon(members.map { ($0.userId, $0.username) })
    }

    private var scope: String { "channel:\(space.channelId)" }

    /// The name beside what a member wrote or did here. `memberNames` is the SERVER's list, so
    /// it is only ever a claim handed to the contact book's rule (`ContactTrust.authorLabel`):
    /// a known or verified contact keeps the name this device has for them, anyone else's
    /// name carries its marker, and a look-alike is not shown as a name.
    private func authorLabel(_ userId: String?) -> String {
        app.contacts.authorLabel(userId, claimedName: userId.flatMap { memberNames[$0] })
    }

    private func display(_ userId: String) -> ContactTrust.Display {
        app.contacts.display(userId, claimedName: memberNames[userId])
    }

    /// A mention: me as myself (no marker), anyone else as `display`.
    private func mentionDisplay(_ userId: String) -> ContactTrust.Display {
        // Me as "you" — never under the server's name for me (a host could make it a contact's).
        ContactTrust.mentionDisplay(userId: userId, me: app.session?.userId, myName: nil, other: display)
    }

    /// A message author's name: plain, with the trust badge beside it (`authorBadge`).
    private func headerName(_ userId: String?) -> String {
        guard let userId, !userId.isEmpty else { return authorLabel(userId) }
        return display(userId).label(for: .messageHeader)
    }

    private func map(_ rows: [Message]) -> [ChatMessage] {
        let waitingIds = Set(app.waiting.waiting(in: space.serverId).map(\.userId))
        // Index bodies by id so a reply can render a one-line preview of its parent.
        var bodyById: [String: (author: String, text: String)] = [:]
        for m in rows where !m.isDeleted && !m.isSystem && !m.isUndecryptable {
            let content = m.content ?? ""
            if FeedTags.isHiddenFromChat(content) || AvatarStore.isAvatarMessage(content) { continue }
            // "Mine" = my local echo ("__me__") OR any message from MY account on another device
            // (same userId, e.g. my phone) — all render as "you", not my username.
            let mine = m.authorId == "__me__" || (m.authorId != nil && m.authorId == app.session?.userId)
            // A reply preview draws no badge: the name in words.
            let author = mine ? "you" : authorLabel(m.authorId)
            bodyById[m.messageId] = (author, ChatTags.parse(content).text)
        }
        return rows.compactMap { m in
            let content = m.content ?? ""
            // A security / membership event the app itself wrote into this channel ("X joined
            // (approved by Y)", "X added a device"): shown as a system line, not as a message.
            if m.isSystem {
                let me = app.session?.userId
                guard var row = SecurityAlert.systemMessage(m, name: { id in
                    id == me ? "You" : authorLabel(id)
                }) else { return nil }
                // "X is waiting to join" stays in history after it is settled (let in, declined
                // or gone): then it is a past event, not a warning with something to do.
                if let system = row.system, system.kind == "member_held", !waitingIds.contains(system.userId) {
                    row.system?.warning = false
                    row.system?.actionLabel = nil
                    let who = authorLabel(system.userId)
                    row.body = "\(who) was listed by the server before anyone had let them in. They got no keys from this device while that was so."
                }
                return row
            }
            // A message this device could not decrypt: the core's stand-in row, until its author's
            // device sends it again.
            if m.isUndecryptable {
                return SecurityAlert.placeholderMessage(m, name: { id in authorLabel(id) })
            }
            // Feed/story posts + avatar pointers ride this channel too (E2EE) — hide from the conversation.
            if !m.isDeleted, FeedTags.isHiddenFromChat(content) || AvatarStore.isAvatarMessage(content) { return nil }
            // "Mine" = my local echo ("__me__") OR any message from MY account on another device
            // (same userId, e.g. my phone) — all render as "you", not my username.
            let mine = m.authorId == "__me__" || (m.authorId != nil && m.authorId == app.session?.userId)
            let author = mine ? "you" : headerName(m.authorId)
            // My own rows carry "__me__"; use my real userId so my avatar renders too.
            let authorId = mine ? app.session?.userId : m.authorId
            let parsed = ChatTags.parse(content)
            let replyPreview = m.replyToId.flatMap { bodyById[$0] }.map { "\($0.author): \($0.text.prefix(60))" }
            return ChatMessage(id: m.messageId, author: author, authorId: authorId,
                               authorSpoken: mine ? nil : authorLabel(m.authorId), body: parsed.text, mine: mine,
                               reactionPills: reactionsByMessage[m.messageId] ?? [],
                               createdAt: m.createdAt, attachment: parsed.attachment, music: parsed.music,
                               replyToId: m.replyToId, replyPreview: replyPreview,
                               isEdited: m.isEdited, isDeleted: m.isDeleted,
                               sendState: mine ? sendStates[m.messageId] : nil, mentions: ChatTags.mentions(content))
        }
    }

    /// Redraw from this device's cache and the outbox — no network. What a queued send, a
    /// delivery, a failure or a block changes is all local.
    private func reloadLocal() async {
        guard let client = app.client, let me = app.session?.userId else { return }
        let channelId = space.channelId
        let rows = await client.history(scope: scope)
        let queued = await Outbox.states(client, scope: scope)
        let reactions = Self.pills(await client.channelReactions(channelId: channelId), me: me)
        guard channelId == space.channelId, app.client === client else { return }
        latestRows = rows
        sendStates = queued.byMessage
        reactionsByMessage = reactions
        if let problem = queued.problem { sendError = problem }
        messages = map(allRows)
    }

    /// Cached reaction pills per message id, hydrated by `hydrateReactions` after each fetch.
    @State private var reactionsByMessage: [String: [ReactionPill]] = [:]

    /// Can something be handed over right now? Only to the cache of the skwod this conversation is
    /// in; while that is being opened nothing is taken from the composer, and it says so.
    private func ready() -> Bool {
        guard maySend else { return false }
        if Outbox.client(of: home, app) == nil { sendError = Compose.opening; return false }
        if sendError == Compose.opening { sendError = nil }
        return true
    }

    /// Send, reply or edit. Everything about it is settled here, at the tap (`SendOrder`): what comes
    /// after — another conversation, another skwod — changes nothing about where it goes. Nothing
    /// waits for the network: it is queued in the core (shown at once as "Sending…").
    private func send(_ written: String) -> Bool {
        guard maySend else { return false }
        let (replyTarget, editTarget, key) = (replyingTo, editing, composedIn)
        let taken = Compose.take(text: written, home: home, bound: app.bound.flatMap { $0.cacheOpen ? $0.workspaceId : nil },
                                 place: .channel(space.channelId), replyTo: replyTarget?.id, editing: editTarget?.id)
        guard case .send(let order) = taken, let client = Outbox.client(of: home, app) else {
            if taken != .nothing { sendError = Compose.opening }
            return false
        }
        draft = ""; sendError = nil; replyingTo = nil; editing = nil
        Task {
            do {
                try await Outbox.queue(order, through: client)
                Outbox.kick(app, composed: true)
            } catch {
                // Could not even be queued (too long, the outbox is full, the cache was just taken):
                // the text goes back to this conversation's composer.
                draft = Compose.givenBack(order.text, to: draft)
                replyingTo = replyTarget; editing = editTarget
                if editTarget == nil, let key { chat.keepDraft(Compose.givenBack(order.text, to: chat.draft(for: key)), for: key) }
                sendError = sendFailureText(error)
            }
        }
        return true
    }

    private func sendMusic(_ track: MusicTrack) {
        guard ready(), let client = Outbox.client(of: home, app), let home else { return }
        let order: SendOrder
        do { order = SendOrder(workspaceId: home, place: .channel(space.channelId), text: try AttachmentService.musicBody(track).body) }
        catch { sendError = sendFailureText(error); return }
        Task {
            do {
                try await Outbox.queue(order, through: client)
                Outbox.kick(app, composed: true)
            } catch { sendError = sendFailureText(error) }
        }
    }

    /// A file or photo: encrypted file-to-file, queued, uploaded in resumable chunks by the outbox
    /// (`StreamedUpload`). In a channel the server links the blob to the message when the queued send
    /// goes out, which is what lets members download it.
    private func sendAttachment(_ source: StreamedUpload.Source) {
        guard ready(), let client = Outbox.client(of: home, app), let home else { return }
        let target = StreamedUpload.Target.channel(channelId: space.channelId)
        uploading = true; sendError = nil
        Task {
            do { try await StreamedUpload.queue(source, to: target, through: client, workspace: home, app: app) }
            catch { sendError = sendFailureText(error) }
            uploading = false
        }
    }

    /// The reply/edit banner text above the composer (nil hides it).
    private var composingBanner: (text: String, isEdit: Bool)? {
        if editing != nil { return ("Editing message", true) }
        if let r = replyingTo { return ("Replying to \(r.author)", false) }
        return nil
    }

    private func toggleReaction(_ msg: ChatMessage, _ emoji: String) {
        guard ready(), let client = Outbox.client(of: home, app) else { return }
        let channelId = space.channelId
        let mineAlready = msg.reactionPills.first(where: { $0.emoji == emoji })?.mine ?? false
        Task { do {
            // The core seals the emoji under the space key; the server only gets a keyed tag.
            try await client.queueReaction(channelId: channelId, messageId: msg.id, emoji: emoji, remove: mineAlready)
            // Shown at once; the next sync confirms it.
            var pills = reactionsByMessage[msg.id] ?? []
            if let i = pills.firstIndex(where: { $0.emoji == emoji }) {
                pills[i].count += mineAlready ? -1 : 1
                pills[i].mine = !mineAlready
                if pills[i].count <= 0 { pills.remove(at: i) }
            } else if !mineAlready {
                pills.append(ReactionPill(emoji: emoji, count: 1, mine: true))
            }
            reactionsByMessage[msg.id] = pills
            messages = map(allRows)
            await Outbox.flush(app)
            await refresh()
        } catch { sendError = sendFailureText(error) } }
    }

    private func deleteMessage(_ msg: ChatMessage) {
        guard ready(), let client = Outbox.client(of: home, app) else { return }
        let channelId = space.channelId
        Task { do {
            try await client.queueChannelDelete(channelId: channelId, messageId: msg.id)
            Outbox.kick(app)
        } catch { sendError = sendFailureText(error) } }
    }

    /// Forward a message's text to another channel (a fresh, queued send in the target).
    private func forward(_ msg: ChatMessage, to target: RealSpace) {
        forwarding = nil
        // (The picker lists the channels of the skwod that is shown.)
        guard ready(), chat.spacesWorkspaceId == home, let home, let client = Outbox.client(of: home, app) else { return }
        let body = msg.body.isEmpty ? "(forwarded message)" : msg.body
        let order = SendOrder(workspaceId: home, place: .channel(target.channelId), text: body)
        Task { do {
            try await Outbox.queue(order, through: client)
            Outbox.kick(app)
        } catch { sendError = "Couldn't forward: " + sendFailureText(error) } }
    }

    /// Catch the channel up (cursor-driven: everything that changed since the last call — new
    /// messages, edits, deletes — and cheap when nothing did) and redraw. Called when the relay
    /// reports an event for this channel, on (re)connect, after our own actions and on the slow
    /// safety timer. A burst of events makes one pass, then one more.
    /// `force` (pull-to-refresh): wait for a catch-up already running instead of only queuing one.
    private func refresh(force: Bool = false) async {
        guard let client = app.client, let me = app.session?.userId else { return }
        if refreshing {
            refreshAgain = true
            if force { while refreshing { try? await Task.sleep(for: .milliseconds(100)) } }
            return
        }
        refreshing = true
        defer { refreshing = false }
        let channelId = space.channelId
        let asked = app.bindTicket()
        repeat {
            refreshAgain = false
            let hist: [Message]
            do { hist = try await client.fetchChannelMessages(channelId: channelId, myUserId: me) } catch {
                if let asked, app.holds(asked) { chat.noteRead(space, refusedWith: error) }
                // Never a silent stale list: say so, and try again with backoff (`FetchRetryRule`).
                if channelId == space.channelId, let asked, app.holds(asked) { noteFetchFailed() }
                break
            }
            if let asked, app.holds(asked) { chat.noteRead(space, refusedWith: nil) }
            if channelId == space.channelId { fetchFailures = 0; retryTask?.cancel(); retryTask = nil }
            // What one skwod's server answered is shown (and its avatars kept) only there.
            guard let asked, app.holds(asked) else { return }
            // The fetch may have drained direct messages from the mailbox on its way.
            await app.drainDmEvents()
            guard channelId == space.channelId, !Task.isCancelled, app.holds(asked) else { return }
            // Pick up profile/server/skwod avatar pointers — each only from whoever may set it.
            app.avatars.ingest(hist, authority: await app.avatars.authority(serverId: space.serverId))
            reactionsByMessage = Self.pills(await client.channelReactions(channelId: channelId), me: me)
            let queued = await Outbox.states(client, scope: scope)
            sendStates = queued.byMessage
            if let problem = queued.problem { sendError = problem }
            // A clear empties the channel: nothing older is left to page through either.
            if hist.isEmpty { olderRows = [] }
            latestRows = hist
            messages = map(allRows)
        } while refreshAgain
    }

    /// A catch-up of this channel failed: retry after `FetchRetryRule`'s backoff, a bounded number
    /// of times; after that the list says "Couldn't load new messages · Retry".
    private func noteFetchFailed() {
        fetchFailures += 1
        retryTask?.cancel()
        guard let wait = FetchRetryRule.delay(afterFailure: fetchFailures) else { return }
        let channelId = space.channelId
        retryTask = Task {
            try? await Task.sleep(for: .seconds(wait))
            guard !Task.isCancelled, channelId == space.channelId else { return }
            await refresh()
        }
    }

    /// Group the channel's reactions (one cache read for the whole channel) into pills per
    /// message: emoji, count, mine.
    static func pills(_ rows: [MessageReaction], me: String) -> [String: [ReactionPill]] {
        var counts: [String: [String: (count: Int, mine: Bool)]] = [:]
        // `emoji` is nil when this device could not open the sealed emoji (no space key yet):
        // there is nothing to show for that row, so it is skipped rather than rendered as a hash.
        for r in rows {
            guard let emoji = r.emoji else { continue }
            var e = counts[r.messageId]?[emoji] ?? (0, false)
            e.count += 1
            if r.userId == me { e.mine = true }
            counts[r.messageId, default: [:]][emoji] = e
        }
        return counts.mapValues { byEmoji in
            byEmoji.map { ReactionPill(emoji: $0.key, count: $0.value.count, mine: $0.value.mine) }.sorted { $0.emoji < $1.emoji }
        }
    }
}

/// A compact picker to forward a message into one of your channels.
struct ForwardPicker: View {
    let message: ChatMessage
    let chat: ChatModel
    let onPick: (RealSpace) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                ForEach(chat.spaces) { space in
                    Button {
                        onPick(space); dismiss()
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "number").foregroundStyle(.white.opacity(0.5))
                            VStack(alignment: .leading, spacing: 1) {
                                Text(space.channelName).foregroundStyle(.white)
                                Text(space.name).font(.caption).foregroundStyle(.white.opacity(0.5))
                            }
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(SkwodBackground())
            .navigationTitle("Forward to…")
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
    }
}

#if os(macOS)
/// The right-hand members rail: the people in this server, over a frosted panel. Usernames are
/// the public login identity, so no key is needed to render them. Right-clicking a member offers
/// host moderation: kick (membership only) or delete the account entirely (server enforces that
/// only the instance owner may do either).
private struct MembersColumn: View {
    let serverId: String
    @EnvironmentObject private var app: AppState
    @State private var members: [PresenceMember] = []
    @State private var roles: [RoleInfo] = []
    @State private var confirmKick: PresenceMember?
    @State private var blocking: ReportTarget?
    @State private var reporting: ReportTarget?
    @State private var confirmBan: PresenceMember?
    @State private var confirmDelete: PresenceMember?
    /// "Verify safety number…" for this member (build 49: reachable from the member list).
    @State private var verifying: PresenceMember?
    @State private var status = ""
    /// Bumped on every live presence event so SwiftUI recomputes `live` (Realtime is nested state).
    @State private var liveTick = 0

    /// Poll results overlaid with live socket presence, so flips are instant (no 10s poll wait).
    private var live: [PresenceMember] {
        members.map { m in
            var m = m
            m.status = app.realtime.status(userId: m.userId)
            return m
        }
    }
    /// Someone the server lists but who is still waiting to be let in is not shown as a member.
    private var accepted: [PresenceMember] {
        let held = Set(app.waiting.waiting(in: serverId).map(\.userId))
        return live.filter { !held.contains($0.userId) }
    }
    private var groups: PresenceRoster.Groups<PresenceMember> { PresenceRoster.groups(accepted, live: app.realtime.isLive) { $0.status } }
    private var online: [PresenceMember] { groups.online }
    private var offline: [PresenceMember] { groups.offline }
    private var unknown: [PresenceMember] { groups.unknown }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    WaitingToJoinSection(serverId: serverId, compact: true, room: app.waiting)
                    if !online.isEmpty {
                        groupHeader("Online — \(online.count)")
                        ForEach(online) { m in memberRow(m) }
                    }
                    if !offline.isEmpty {
                        groupHeader("Offline — \(offline.count)")
                        ForEach(offline) { m in memberRow(m).opacity(0.45) }
                    }
                    if !unknown.isEmpty {
                        groupHeader(PresenceRoster.unknownTitle(unknown.count))
                        ForEach(unknown) { m in memberRow(m) }
                    }
                }
                .padding(8).padding(.top, 8)
            }
            if !status.isEmpty {
                Text(status).font(.caption2).foregroundStyle(.orange)
                    .padding(.horizontal, 12).padding(.bottom, 8)
            }
        }
        .frame(width: 210)
        .frame(maxHeight: .infinity)
        .background(.ultraThinMaterial)
        .overlay(Rectangle().fill(.white.opacity(0.06)).frame(width: 1), alignment: .leading)
        // Realtime is a nested object (app.realtime) — rerender on live presence events.
        .onReceive(app.realtime.$presence) { _ in liveTick &+= 1 }
        .task(id: serverId) {
            // Presence poll: keep the online/offline groups fresh while the panel shows.
            while !Task.isCancelled {
                await load()
                try? await Task.sleep(for: .seconds(10))
            }
        }
        .safetyActions(blocking: $blocking, reporting: $reporting)
        .sheet(item: $verifying) { m in
            DismissableSheet { SafetyNumberView(peerName: app.contacts.display(m.userId, claimedName: m.username).text, peerUserId: m.userId) }
        }
        .confirmationDialog("Kick \(confirmKick?.username ?? "")?",
                            isPresented: Binding(get: { confirmKick != nil }, set: { if !$0 { confirmKick = nil } }),
                            titleVisibility: .visible) {
            Button("Kick", role: .destructive) {
                if let m = confirmKick { Task { await kick(m) } }
                confirmKick = nil
            }
        } message: {
            Text("Removes them from this server. Their account survives — they can rejoin with a new invite.")
        }
        .confirmationDialog("Ban \(confirmBan?.username ?? "")?",
                            isPresented: Binding(get: { confirmBan != nil }, set: { if !$0 { confirmBan = nil } }),
                            titleVisibility: .visible) {
            Button("Ban", role: .destructive) {
                if let m = confirmBan { Task { await ban(m) } }
                confirmBan = nil
            }
        } message: {
            Text("Removes them AND blocks every invite from readmitting them until you unban. Their account survives.")
        }
        .confirmationDialog("Delete \(confirmDelete?.username ?? "")'s account?",
                            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                            titleVisibility: .visible) {
            Button("Delete account", role: .destructive) {
                if let m = confirmDelete { Task { await deleteAccount(m) } }
                confirmDelete = nil
            }
            Button("Delete and ban", role: .destructive) {
                if let m = confirmDelete { Task { await deleteAccount(m, ban: true) } }
                confirmDelete = nil
            }
        } message: {
            Text("Wipes their account, devices, and memberships — the username is freed so they can sign up fresh (e.g. after a forgotten password). “Delete and ban” also keeps that username and their devices from signing up on this skwod again, and revokes the invite they used.")
        }
    }

    private func groupHeader(_ title: String) -> some View {
        Text(title)
            .font(.system(size: 12, weight: .semibold)).foregroundStyle(.white.opacity(0.55))
            .textCase(.uppercase)
            .padding(.horizontal, 8).padding(.top, 10).padding(.bottom, 4)
    }

    private func memberRow(_ m: PresenceMember) -> some View {
        let shown = app.contacts.display(m.userId, claimedName: m.username)
        let isMe = m.userId == app.session?.userId
        return MemberRow(username: isMe ? m.username : shown.label(for: .memberRow), userId: m.userId, status: app.realtime.dot(userId: m.userId),
                         badge: isMe ? nil : shown.badge)
            .contextMenu {
                if !roles.isEmpty {
                    Menu("Roles") {
                        ForEach(roles.filter { !$0.isDefault }, id: \.roleId) { r in
                            let has = m.roleIds.contains(r.roleId)
                            Button {
                                Task { await toggleRole(m, r, grant: !has) }
                            } label: {
                                Label(r.name ?? "role", systemImage: has ? "checkmark" : "circle")
                            }
                        }
                    }
                }
                if m.userId != app.session?.userId {
                    Button { verifying = m } label: { Label("Verify safety number…", systemImage: "checkmark.shield") }
                    SafetyMenuItems(userId: m.userId, name: m.username, serverId: serverId, blocking: $blocking, reporting: $reporting)
                    Divider()
                    Button { confirmKick = m } label: { Label("Kick from server", systemImage: "person.badge.minus") }
                    Button { confirmBan = m } label: { Label("Ban from server…", systemImage: "hand.raised") }
                    Button(role: .destructive) { confirmDelete = m } label: { Label("Delete account…", systemImage: "trash") }
                }
            }
    }

    private func toggleRole(_ m: PresenceMember, _ r: RoleInfo, grant: Bool) async {
        guard let client = app.client else { return }
        do {
            if grant {
                try await client.assignRole(serverId: serverId, userId: m.userId, roleId: r.roleId)
            } else {
                try await client.removeRole(serverId: serverId, userId: m.userId, roleId: r.roleId)
            }
        } catch { status = "Couldn't change roles — you need Manage Roles." }
        await load()
    }

    /// Members with live presence, straight over HTTP (the core binding predates the status field).
    private func load() async {
        guard !serverId.isEmpty, serverId != "demo",
              let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/servers/\(serverId)/members"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let askedAt = PresenceClock.now
        guard let (data, resp) = try? await RawSink.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let parsed = try? JSONDecoder().decode(PresenceMemberList.self, from: data) else { app.realtime.presenceUnheard(); return }
        members = parsed.members
        app.realtime.seedPresence(parsed.statuses, askedAt: askedAt)
        app.contacts.checkSoon(parsed.members.map { ($0.userId, $0.username) })
        await app.waiting.refresh(serverId: serverId)
        if let client = app.client {
            roles = (try? await client.listRoles(serverId: serverId)) ?? []
        }
    }

    private func kick(_ m: PresenceMember) async {
        await moderate("api/servers/\(serverId)/members/\(m.userId)", failure: "Couldn't kick — only the server owner can.")
    }

    /// Ban = kick + a server-side ban row every rejoin path checks (a kicked user can rejoin
    /// with any invite; a banned one can't until unbanned).
    private func ban(_ m: PresenceMember) async {
        await moderate("api/servers/\(serverId)/bans/\(m.userId)", method: "POST", failure: "Couldn't ban — you need Ban Members.")
    }

    private func deleteAccount(_ m: PresenceMember, ban: Bool = false) async {
        // Signed by this device, through the core (a session token alone is refused).
        guard let client = app.client else { return }
        let deleted = (try? await (ban ? client.deleteAccountAndBan(userId: m.userId) : client.deleteAccount(userId: m.userId))) != nil
        status = deleted ? "" : "Couldn't delete — only the server owner can."
        // As after any removal: fresh sender keys the moment someone is out (see `moderate`).
        if deleted, let me = app.session?.userId { _ = try? await client.syncServerMembership(serverId: serverId, myUserId: me) }
        await load()
    }

    /// Owner moderation calls go straight over HTTP (same bearer token the E2EE client uses).
    private func moderate(_ path: String, method: String = "DELETE", failure: String) async {
        guard let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let code = ((try? await RawSink.data(for: req))?.1 as? HTTPURLResponse)?.statusCode ?? 0
        status = code == 200 ? "" : failure
        // Removing a member must immediately rotate EVERY channel's sender key on this server, so
        // the removed member can't decrypt anything sent after this point (chat or voice). Other
        // members rotate on their own next membership sync.
        if code == 200, let client = app.client, let me = app.session?.userId {
            _ = try? await client.syncServerMembership(serverId: serverId, myUserId: me)
        }
        await load()
    }
}

/// One member: E2EE avatar (or monogram fallback) with a presence dot + username.
private struct MemberRow: View {
    let username: String
    var userId: String? = nil
    var status: String = "offline"
    /// How far the name is trusted (nil for yourself): a small badge, not words after the name.
    var badge: ContactTrust.Badge? = nil
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 9) {
            ZStack(alignment: .bottomTrailing) {
                AvatarImage(key: userId.map(AvatarStore.userKey), name: username, size: 28)
                // Always show the dot (`PresenceStyle.color`).
                Circle().fill(PresenceStyle.color(status)).frame(width: 9, height: 9)
                    .overlay(Circle().strokeBorder(.black.opacity(0.7), lineWidth: 1.5))
                    .offset(x: 1, y: 1)
            }
            Text(username).font(.system(size: 13)).foregroundStyle(.white.opacity(0.85)).lineLimit(1)
            if let badge, let userId { TrustBadgeButton(userId: userId, name: username, badge: badge) }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .background(hovering ? Color.white.opacity(0.05) : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .onHover { hovering = $0 }
    }
}
#endif

/// A member with live presence from `GET /servers/:id/members` (status is staled server-side).
struct PresenceMember: Decodable, Identifiable {
    let userId: String
    let username: String
    var status: String   // mutable: live socket presence overlays the polled value
    var roleIds: [String] = []
    var id: String { userId }
    enum CodingKeys: String, CodingKey { case userId = "user_id", username, status, roleIds = "role_ids" }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        userId = try c.decode(String.self, forKey: .userId)
        username = try c.decode(String.self, forKey: .username)
        status = try c.decodeIfPresent(String.self, forKey: .status) ?? "offline"
        roleIds = try c.decodeIfPresent([String].self, forKey: .roleIds) ?? []
    }
}

struct PresenceMemberList: Decodable {
    let members: [PresenceMember]
    var statuses: [String: String] { Dictionary(members.map { ($0.userId, $0.status) }, uniquingKeysWith: { first, _ in first }) }
}

/// The member roster as a sheet — the iOS peer of the macOS `MembersColumn`. Online/Offline groups
/// with presence dots; tapping a member opens host moderation (toggle roles, kick, delete account),
/// the same actions the Mac exposes via right-click. Uses the same HTTP endpoints.
struct MembersSheetView: View {
    let serverId: String
    let serverName: String
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var members: [PresenceMember] = []
    @State private var roles: [RoleInfo] = []
    @State private var confirmKick: PresenceMember?
    @State private var blocking: ReportTarget?
    @State private var reporting: ReportTarget?
    @State private var confirmBan: PresenceMember?
    @State private var confirmDelete: PresenceMember?
    /// "Verify safety number…" for this member (build 49: reachable from the member list).
    @State private var verifying: PresenceMember?
    @State private var status = ""
    /// Bumped on every live presence event so SwiftUI recomputes `live` (Realtime is nested state).
    @State private var liveTick = 0

    /// Poll results overlaid with live socket presence (matches the macOS members column).
    private var live: [PresenceMember] {
        members.map { m in
            var m = m
            m.status = app.realtime.status(userId: m.userId)
            return m
        }
    }
    /// Someone the server lists but who is still waiting to be let in is not shown as a member.
    private var accepted: [PresenceMember] {
        let held = Set(app.waiting.waiting(in: serverId).map(\.userId))
        return live.filter { !held.contains($0.userId) }
    }
    private var groups: PresenceRoster.Groups<PresenceMember> { PresenceRoster.groups(accepted, live: app.realtime.isLive) { $0.status } }
    private var online: [PresenceMember] { groups.online }
    private var offline: [PresenceMember] { groups.offline }
    private var unknown: [PresenceMember] { groups.unknown }

    var body: some View {
        NavigationStack {
            ZStack {
                SkwodBackground()
                List {
                    if app.waiting.count(in: serverId) > 0 {
                        WaitingToJoinSection(serverId: serverId, room: app.waiting)
                            .listRowBackground(Color.clear).listRowSeparator(.hidden)
                            .listRowInsets(EdgeInsets(top: 6, leading: 0, bottom: 6, trailing: 0))
                    }
                    if !online.isEmpty {
                        Section("Online — \(online.count)") { ForEach(online) { row($0) } }
                    }
                    if !offline.isEmpty {
                        Section("Offline — \(offline.count)") { ForEach(offline) { row($0).opacity(0.5) } }
                    }
                    if !unknown.isEmpty {
                        Section(PresenceRoster.unknownTitle(unknown.count)) { ForEach(unknown) { row($0) } }
                    }
                }
                .scrollContentBackground(.hidden)
            }
            .navigationTitle("Members — \(serverName)")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Done") { dismiss() } } }
        }
        .onReceive(app.realtime.$presence) { _ in liveTick &+= 1 }
        .task(id: serverId) {
            while !Task.isCancelled { await load(); try? await Task.sleep(for: .seconds(10)) }
        }
        .safetyActions(blocking: $blocking, reporting: $reporting)
        .sheet(item: $verifying) { m in
            DismissableSheet { SafetyNumberView(peerName: app.contacts.display(m.userId, claimedName: m.username).text, peerUserId: m.userId) }
        }
        .confirmationDialog("Kick \(confirmKick?.username ?? "")?",
                            isPresented: Binding(get: { confirmKick != nil }, set: { if !$0 { confirmKick = nil } }),
                            titleVisibility: .visible) {
            Button("Kick", role: .destructive) { if let m = confirmKick { Task { await kick(m) } }; confirmKick = nil }
        } message: { Text("Removes them from this server. Their account survives — they can rejoin with a new invite.") }
        .confirmationDialog("Ban \(confirmBan?.username ?? "")?",
                            isPresented: Binding(get: { confirmBan != nil }, set: { if !$0 { confirmBan = nil } }),
                            titleVisibility: .visible) {
            Button("Ban", role: .destructive) { if let m = confirmBan { Task { await ban(m) } }; confirmBan = nil }
        } message: { Text("Removes them AND blocks every invite from readmitting them until you unban. Their account survives.") }
        .confirmationDialog("Delete \(confirmDelete?.username ?? "")'s account?",
                            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } }),
                            titleVisibility: .visible) {
            Button("Delete account", role: .destructive) { if let m = confirmDelete { Task { await deleteAccount(m) } }; confirmDelete = nil }
            Button("Delete and ban", role: .destructive) { if let m = confirmDelete { Task { await deleteAccount(m, ban: true) } }; confirmDelete = nil }
        } message: { Text("Wipes their account, devices, and memberships — the username is freed for a fresh sign-up. “Delete and ban” keeps that username and their devices from coming back to this skwod.") }
    }

    private func row(_ m: PresenceMember) -> some View {
        Menu {
            if !roles.filter({ !$0.isDefault }).isEmpty {
                ForEach(roles.filter { !$0.isDefault }, id: \.roleId) { r in
                    let has = m.roleIds.contains(r.roleId)
                    Button { Task { await toggleRole(m, r, grant: !has) } } label: {
                        Label(r.name ?? "role", systemImage: has ? "checkmark" : "circle")
                    }
                }
                Divider()
            }
            if m.userId != app.session?.userId {
                if let why = ContactTrust.explanation(app.contacts.display(m.userId, claimedName: m.username).badge) { Section { Text(why) } }
                Button { verifying = m } label: { Label("Verify safety number…", systemImage: "checkmark.shield") }
                SafetyMenuItems(userId: m.userId, name: m.username, serverId: serverId, blocking: $blocking, reporting: $reporting)
                Divider()
                Button { confirmKick = m } label: { Label("Kick from server", systemImage: "person.badge.minus") }
                Button { confirmBan = m } label: { Label("Ban from server…", systemImage: "hand.raised") }
                Button(role: .destructive) { confirmDelete = m } label: { Label("Delete account…", systemImage: "trash") }
            }
        } label: {
            HStack(spacing: 10) {
                ZStack(alignment: .bottomTrailing) {
                    Circle().fill(Color.seeded(m.username)).frame(width: 32, height: 32)
                        .overlay(Text(m.username.prefix(1).uppercased()).font(.caption.bold()).foregroundStyle(.white))
                    Circle().fill(PresenceStyle.color(app.realtime.dot(userId: m.userId))).frame(width: 11, height: 11)
                        .overlay(Circle().strokeBorder(.black.opacity(0.6), lineWidth: 2))
                }
                // A member-list name is the server's claim: marked unless the user knows them.
                let shown = app.contacts.display(m.userId, claimedName: m.username)
                Text(shown.text).foregroundStyle(.white).lineLimit(1)
                if m.userId != app.session?.userId { TrustBadge(badge: shown.badge, compact: true) }
                Spacer()
            }
        }
        .listRowBackground(Color.clear)
    }

    private func load() async {
        guard !serverId.isEmpty, serverId != "demo",
              let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/servers/\(serverId)/members"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let askedAt = PresenceClock.now
        if let (data, resp) = try? await RawSink.data(for: req),
           (resp as? HTTPURLResponse)?.statusCode == 200,
           let parsed = try? JSONDecoder().decode(PresenceMemberList.self, from: data) {
            members = parsed.members
            app.realtime.seedPresence(parsed.statuses, askedAt: askedAt)
            app.contacts.checkSoon(parsed.members.map { ($0.userId, $0.username) })
        } else { app.realtime.presenceUnheard() }
        await app.waiting.refresh(serverId: serverId)
        if let client = app.client { roles = (try? await client.listRoles(serverId: serverId)) ?? [] }
    }

    private func toggleRole(_ m: PresenceMember, _ r: RoleInfo, grant: Bool) async {
        guard let client = app.client else { return }
        do {
            if grant { try await client.assignRole(serverId: serverId, userId: m.userId, roleId: r.roleId) }
            else { try await client.removeRole(serverId: serverId, userId: m.userId, roleId: r.roleId) }
        } catch { status = "Couldn't change roles — you need Manage Roles." }
        await load()
    }

    private func kick(_ m: PresenceMember) async { await moderate("api/servers/\(serverId)/members/\(m.userId)") }
    private func ban(_ m: PresenceMember) async { await moderate("api/servers/\(serverId)/bans/\(m.userId)", method: "POST") }
    private func deleteAccount(_ m: PresenceMember, ban: Bool = false) async {
        // Signed by this device, through the core (a session token alone is refused).
        guard let client = app.client else { return }
        let deleted = (try? await (ban ? client.deleteAccountAndBan(userId: m.userId) : client.deleteAccount(userId: m.userId))) != nil
        if deleted, let me = app.session?.userId { _ = try? await client.syncServerMembership(serverId: serverId, myUserId: me) }
        await load()
    }

    private func moderate(_ path: String, method: String = "DELETE") async {
        guard let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let code = ((try? await RawSink.data(for: req))?.1 as? HTTPURLResponse)?.statusCode ?? 0
        // Same rotation-on-removal as the macOS panel: fresh sender keys the moment someone is out.
        if code == 200, let client = app.client, let me = app.session?.userId {
            _ = try? await client.syncServerMembership(serverId: serverId, myUserId: me)
        }
        await load()
    }
}

