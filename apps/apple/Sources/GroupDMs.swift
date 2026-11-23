import SwiftUI

// `GroupDM` itself, and every rule about which store owns a conversation id, is in
// `ConversationStore.swift`. This file is the group screens and `ChatModel`'s side of them.

@MainActor
extension ChatModel {
    /// The group's title as this device names its members.
    func title(of group: GroupDM, limit: Int = 4) -> String {
        guard let app else { return "Group" }
        let names = group.memberUserIds.map { app.contacts.display($0, claimedName: group.claimedNames[$0]).text }
        return GroupDM.title(memberNames: names, limit: limit)
    }

    func group(for conversationId: String) -> GroupDM? { store.group(for: conversationId) }

    /// Name hints for people this device already knows something about — in the workspace
    /// `origin` belongs to, asked of that workspace's own client. A listing that comes back
    /// after the user has switched gets no names from the workspace they are in now: nothing
    /// (not even a claimed name) crosses from one workspace into another.
    func nameHints(for origin: ConversationStore) async -> [String: String] {
        guard let app, origin === store, loadedFor == origin.workspaceId,
              let client = try? BoundClient.of(app.bound, for: origin.workspaceId) else { return [:] }
        var usernames: [String: String] = [:]
        for d in origin.dms where !d.name.isEmpty { usernames[d.peerUserId] = d.name }
        for sid in Set(spaces.map(\.serverId)) where !sid.isEmpty && sid != "demo" {
            let members = (try? await client.listMembers(serverId: sid)) ?? []
            guard origin === store, app.bound?.workspaceId == origin.workspaceId else { return [:] }
            for m in members { usernames[m.userId] = m.username }
        }
        return usernames
    }

    /// Ask the server which group conversations it lists for this account, and fold that in:
    /// accepted groups keep their members (a differing listing is flagged), conversations
    /// this device has not accepted become invitations. False when it could not be asked.
    @discardableResult
    func refreshGroups() async -> Bool {
        guard let ticket = ticket() else { return false }
        let asked = await ticket.store.refreshGroups()
        if holds(ticket) { noteInvitedPeople() }
        return asked
    }

    /// The people of an invitation are in the contact book (unverified) before it is shown.
    private func noteInvitedPeople() {
        guard let app else { return }
        for invitation in pendingGroups {
            for id in invitation.memberUserIds where app.contacts.entries[id] == nil {
                app.contacts.note(id, name: invitation.claimedNames[id] ?? "", level: .unverified)
            }
        }
    }

    /// Start (or reopen) a group with these people and show it. The member set is the one the
    /// user just picked, and stays that.
    func startGroup(with members: [(userId: String, name: String)]) async throws {
        guard let app else { return }
        // What is current is captured before the server is asked for the group's id
        // (`StoreTicket`): the group is started in THAT workspace's store, and shown and noted
        // only if it is still the current one when the answer comes.
        guard let ticket = ticket() else { throw CoreError.Invalid(detail: "Skwod is still loading your conversations — try again in a moment.") }
        let group: GroupDM
        do {
            group = try await ticket.store.startGroup(memberUserIds: members.map(\.userId),
                                                 names: Dictionary(members.map { ($0.userId, $0.name) }, uniquingKeysWith: { a, _ in a }))
        } catch ConversationError.conflict {
            // The server answered with an id this device holds as a direct conversation, or
            // as a group with other people: neither is touched, and nothing is started.
            throw CoreError.Invalid(detail: "This conversation's server data conflicts, so the group was not started.")
        } catch ConversationError.notReady {
            throw CoreError.Invalid(detail: "Skwod is still loading your conversations — try again in a moment.")
        }
        guard holds(ticket) else { return }
        for m in members where app.contacts.entries[m.userId] == nil { app.contacts.note(m.userId, name: m.name, level: .unverified) }
        selection = .group(group)
    }

    /// The user looked at an invitation's members and accepted it: from now on this device
    /// seals to exactly those people. Refused when a direct conversation claims the id: the
    /// invitation stays, nothing changes, and it is said once.
    ///
    /// `invitation` must be the one that is ON SCREEN. Returns the invitation as it is now when
    /// it is no longer that one (nothing was accepted: show it again), else nil.
    @discardableResult
    func accept(_ invitation: GroupDM) async -> GroupDM? {
        switch store.join(invitation) {
        case .joined(let group): selection = .group(group); return nil
        case .changed(let now): return now
        case .refused: return nil
        }
    }

    /// Not now / never: the conversation is not listed again on this device.
    func decline(_ invitation: GroupDM) async {
        store.decline(invitation)
    }

    /// `startGroup` for the new-group sheet: nil on success, else a sentence to show.
    func startGroupReportingProblem(with members: [(userId: String, name: String)]) async -> String? {
        do {
            try await startGroup(with: members)
            return nil
        } catch {
            return coreErrorText(error, fallback: "Couldn't start the group — check your connection.")
        }
    }

    /// What to do with a DM event, for `AppState.handle` — decided by the store
    /// (`ConversationStore.decide`). `mark` is `store.listingMark()` taken when the event's
    /// batch arrived.
    /// Decided in `ticket.store` — the store of the workspace whose client the event came
    /// from — and `.drop` if that is no longer the current one when the decision is made.
    func decide(conversationId: String, senderId: String, fromSelf: Bool, isGroup: Bool? = nil, since mark: Int, in ticket: StoreTicket) async -> ConversationStore.Verdict {
        let store = ticket.store
        let unknown = store.ready && store.route(conversationId) == .unknown
        let verdict = await store.decide(conversationId: conversationId, senderId: senderId, fromSelf: fromSelf, since: mark, isGroup: isGroup)
        guard holds(ticket) else { return .drop }
        // The groups were just listed for it: the people of any new invitation are noted.
        if unknown { noteInvitedPeople() }
        #if DEBUG
        if verdict == .drop, let held = group(for: conversationId), !held.accepts(senderId: senderId, fromSelf: fromSelf) {
            E2E.sawEvent("group_outsider_dropped")
        }
        #endif
        return verdict
    }

    /// Put a store's notice in Security activity. The store calls this once per notice, ever.
    func say(_ notice: ConversationStore.Notice, from origin: ConversationStore) {
        guard let app else { return }
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        Task {
            // Logged in the Security activity of the workspace the notice is about — not in
            // whichever one is active by the time this runs.
            guard self.store === origin, app.bound?.workspaceId == origin.workspaceId else { return }
            var stored = false
            // Remembered as said only once its row is actually in Security activity.
            defer { if stored, self.store === origin { origin.stored(notice) } }
            switch notice {
            case .conflict:
                stored = await app.logSecurity(kind: "conversation_conflict", title: "This conversation's server data conflicts",
                                      message: "The server described one of your conversations in two different ways — as a direct conversation and as a group. Skwod kept it as it was and ignored the rest.",
                                      atMs: now)
                #if DEBUG
                E2E.sawEvent("conversation_conflict")
                #endif
            case .otherPeer:
                stored = await app.logSecurity(kind: "conversation_peer_conflict", title: "This conversation's server data conflicts",
                                      message: "The server described one of your direct conversations as being with a different account than the one you hold it with. Skwod kept it as it was and ignored the rest.",
                                      atMs: now)
            case .unreadable(let list, let keptAs):
                stored = await app.logSecurity(kind: "conversation_list_unreadable", title: "A saved list could not be read",
                                      message: "The list of your \(list) that Skwod keeps on this device could not be fully read. Skwod kept what it could read and continues with that. Nothing was deleted: the data as it was is kept on this device (as “\(keptAs)”). A group you had joined may be shown as “Review this group” — check who is in it before joining again.",
                                      atMs: now)
                #if DEBUG
                E2E.sawEvent("conversation_list_unreadable")
                #endif
            case .duplicates(let keptAs):
                stored = await app.logSecurity(kind: "conversation_duplicates", title: "Duplicate conversations were tidied",
                                      message: "An earlier version of Skwod had listed more than one account under the same direct conversation. Skwod now keeps one account per conversation — the one you started, or the first. Nothing was deleted: the list as it was is kept on this device (as “\(keptAs)”).",
                                      atMs: now)
            case .outsider(let conversationId):
                let title = self.group(for: conversationId).map { self.title(of: $0) } ?? "a group"
                stored = await app.logSecurity(kind: "group_outsider", title: "Someone outside a group tried to post in it",
                                      message: "An account that is not one of the people you joined “\(title)” with sent something to it. Skwod did not show it.",
                                      atMs: now)
            }
        }
    }
}

/// A group this device has not accepted: who is in it (as this device names them), and the
/// choice. Accepting fixes the member set this device seals to.
struct GroupInviteSheet: View {
    @State var invitation: GroupDM
    /// The invitation changed while it was on screen: nothing was joined, look again.
    @State private var changed = false
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "person.3.fill").font(.system(size: 34)).foregroundStyle(.skAccent)
            Text(invitation.needsReview == true ? "Review this group" : "Join this group?").font(.title2.bold()).foregroundStyle(.white).accessibilityAddTraits(.isHeader)
            Text(invitation.needsReview == true
                 ? "Skwod could not read part of what it had saved about your groups on this device, and this may be a group you had joined. These are the people the server lists in it NOW — they may not be the people you joined it with. If you join, your messages in it are sealed to exactly these people."
                 : "You were added to a group with the people below. If you join, your messages in it are sealed to exactly these people — nobody the server adds later.")
                .font(.caption).foregroundStyle(.white.opacity(0.65)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 6) {
                ForEach(invitation.memberUserIds, id: \.self) { id in
                    let shown = app.contacts.display(id, claimedName: invitation.claimedNames[id])
                    HStack(spacing: 10) {
                        AvatarImage(key: AvatarStore.userKey(id), name: shown.text, size: 32)
                        Text(shown.text).foregroundStyle(.white).lineLimit(1)
                        TrustBadge(badge: shown.badge)
                        Spacer()
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                }
            }
            .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            if changed {
                Text("This invitation changed while you were looking at it. Nothing was joined — review who is in it again.")
                    .font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("group.invitationChanged")
            }
            Button {
                Task {
                    // Only the members that are on screen can be accepted.
                    if let now = await chat.accept(invitation) { invitation = now; changed = true } else { dismiss() }
                }
            } label: {
                Text("Join group").fontWeight(.semibold).frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .accessibilityIdentifier("group.accept")
            Button("Ignore this group", role: .destructive) { Task { await chat.decline(invitation); dismiss() } }
                .buttonStyle(.plain).font(.caption).foregroundStyle(.red.opacity(0.9))
            Button("Not now") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(24).frame(minWidth: 360, maxWidth: 460)
        .background(SkwodBackground())
    }
}

/// A group invitation's row in the conversation lists.
struct GroupInviteRow: View {
    let invitation: GroupDM
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "person.3.fill").font(.system(size: 13)).foregroundStyle(.black)
                .frame(width: 30, height: 30).background(Color.skAccent, in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text("Group invitation").font(.system(size: 14, weight: .semibold)).foregroundStyle(.white)
                Text("\(invitation.memberUserIds.count + 1) people · tap to see who").font(.caption2).foregroundStyle(.white.opacity(0.55))
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8).padding(.vertical, 5).contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

/// The invitations of the active skwod, as rows that open the accept sheet. Used by every
/// conversation list.
struct GroupInvitations: View {
    @EnvironmentObject private var chat: ChatModel
    @State private var showing: GroupDM?
    @State private var showIgnored = false
    var body: some View {
        Group {
            ConversationNotices(showIgnored: $showIgnored)
            ForEach(chat.pendingGroups) { g in
                Button { showing = g } label: { GroupInviteRow(invitation: g) }.buttonStyle(.plain)
            }
        }
        .sheet(item: $showing) { GroupInviteSheet(invitation: $0) }
        .sheet(isPresented: $showIgnored) { IgnoredGroupsSheet() }
    }
}

/// What the user has to be TOLD about their conversation lists, where the lists are: they
/// cannot be read (try again); a saved list was lost and server-listed conversations are held
/// back until the user says so; a chat that was refused; and the groups they ignored.
struct ConversationNotices: View {
    @EnvironmentObject private var chat: ChatModel
    @Binding var showIgnored: Bool
    var body: some View {
        if chat.conversationsUnreadable {
            row("Skwod could not read your conversations on this device, so none are shown. Nothing was deleted.",
                action: "Try again", id: "conversations.retry") { Task { await chat.retryConversations() } }
        }
        if chat.reviewPending {
            row("A saved list of your conversations could not be read (see Security activity). Until you continue, conversations the server lists are not added here, and every group it lists is shown as “Review this group”.",
                action: "I’ve seen this — continue", id: "conversations.clearReview") { Task { await chat.clearReview() } }
        }
        if let problem = chat.conversationProblem {
            row(problem, action: "Dismiss", id: "conversations.dismissProblem") { chat.conversationProblem = nil }
        }
        if !chat.ignoredGroups.isEmpty {
            Button { showIgnored = true } label: {
                HStack(spacing: 8) {
                    Image(systemName: "eye.slash").font(.caption).foregroundStyle(.white.opacity(0.45)).accessibilityHidden(true)
                    Text("Ignored groups (\(chat.ignoredGroups.count))").font(.caption).foregroundStyle(.white.opacity(0.55))
                    Spacer(minLength: 0)
                }
                .padding(.horizontal, 8).padding(.vertical, 5).contentShape(Rectangle())
            }
            .buttonStyle(.plain).accessibilityIdentifier("conversations.ignored")
        }
    }

    private func row(_ text: String, action: String, id: String, run: @escaping () -> Void) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(text, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
            Button(action, action: run).buttonStyle(.plain).font(.caption.weight(.semibold)).foregroundStyle(.skAccent)
                .accessibilityIdentifier(id)
        }
        .padding(.horizontal, 8).padding(.vertical, 6)
    }
}

/// The groups the user said to ignore. Only their conversation ids are kept, so that is what
/// can be shown. "Stop ignoring" frees the id: if the server still lists the group it comes
/// back as an invitation, to be looked at again.
struct IgnoredGroupsSheet: View {
    @EnvironmentObject private var chat: ChatModel
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(spacing: 14) {
            Text("Ignored groups").font(.title2.bold()).foregroundStyle(.white).accessibilityAddTraits(.isHeader)
            Text("Nothing of these groups is shown on this device, and their conversation ids cannot be used for anything else. If you stop ignoring one and the server still lists it, it comes back as an invitation.")
                .font(.caption).foregroundStyle(.white.opacity(0.65)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 6) {
                ForEach(chat.ignoredGroups, id: \.self) { id in
                    HStack(spacing: 10) {
                        Text("Group \(id.prefix(8))").foregroundStyle(.white).lineLimit(1)
                        Spacer()
                        Button("Stop ignoring") { Task { await chat.unignore(id); if chat.ignoredGroups.isEmpty { dismiss() } } }
                            .buttonStyle(.plain).font(.caption.weight(.semibold)).foregroundStyle(.skAccent)
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                }
            }
            .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            Button("Done") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(24).frame(minWidth: 360, maxWidth: 460)
        .background(SkwodBackground())
    }
}

// MARK: - New group

struct NewGroupSheet: View {
    /// Members already chosen (when adding to / removing from an existing group).
    var preselected: [String] = []
    var note: String? = nil
    var onStart: ([(userId: String, name: String)]) async -> String?
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var people: [(userId: String, name: String)] = []
    @State private var chosen: Set<String> = []
    @State private var busy = false
    @State private var message = ""
    @State private var loading = true

    init(preselected: [String] = [], note: String? = nil, onStart: @escaping ([(userId: String, name: String)]) async -> String?) {
        self.preselected = preselected
        self.note = note
        self.onStart = onStart
    }

    var body: some View {
        VStack(spacing: 14) {
            Text("New group").font(.title2.bold()).foregroundStyle(.white).accessibilityAddTraits(.isHeader)
            Text(note ?? "Pick 2 to 9 people. Messages are sealed separately to every device of every member.")
                .font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Text("\(chosen.count) of \(GroupDM.maxOthers)").font(.caption.weight(.semibold)).foregroundStyle(.skAccent)
                .accessibilityIdentifier("group.count")
            ScrollView {
                LazyVStack(spacing: 6) {
                    if loading { ProgressView().tint(.skAccent).padding() }
                    if !loading && people.isEmpty {
                        Text("Nobody to add yet — people in your servers and your direct messages appear here.")
                            .font(.caption).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center).padding()
                    }
                    ForEach(people, id: \.userId) { p in
                        let shown = app.contacts.display(p.userId, claimedName: p.name)
                        Button {
                            if chosen.contains(p.userId) { chosen.remove(p.userId) }
                            else if chosen.count < GroupDM.maxOthers { chosen.insert(p.userId) }
                        } label: {
                            HStack(spacing: 10) {
                                AvatarImage(key: AvatarStore.userKey(p.userId), name: shown.text, size: 32)
                                Text(shown.text).foregroundStyle(.white).lineLimit(1)
                                TrustBadge(badge: shown.badge)
                                Spacer()
                                Image(systemName: chosen.contains(p.userId) ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(chosen.contains(p.userId) ? Color.skAccent : .white.opacity(0.35))
                            }
                            .padding(.horizontal, 12).padding(.vertical, 8).contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(chosen.contains(p.userId) ? .isSelected : [])
                    }
                }
            }
            .frame(minHeight: 180, maxHeight: 320)
            .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            if !message.isEmpty {
                Label(message, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
            }
            Button { Task { await start() } } label: {
                HStack(spacing: 8) {
                    if busy { ProgressView().controlSize(.small) }
                    Text("Start group").fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .disabled(busy || GroupDM.sizeProblem(others: chosen.count) != nil)
            Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(24)
        .frame(minWidth: 360, maxWidth: 460)
        .background(SkwodBackground())
        .task { await load() }
    }

    /// People the user could add: their DM contacts and the members of their servers — never
    /// someone they blocked, never themselves.
    private func load() async {
        defer { loading = false }
        chosen = Set(preselected)
        guard let client = app.client, let chat = app.chatModel else { return }
        let me = app.session?.userId
        var byId: [String: String] = [:]
        for d in chat.dms { byId[d.peerUserId] = d.name }
        for g in chat.groups { for id in g.memberUserIds where byId[id] == nil { byId[id] = g.claimedNames[id] ?? "" } }
        for sid in Set(chat.spaces.map(\.serverId)) where !sid.isEmpty && sid != "demo" {
            for m in (try? await client.listMembers(serverId: sid)) ?? [] { byId[m.userId] = m.username }
        }
        people = byId.filter { $0.key != me && !$0.key.isEmpty && !BlockList.shared.contains($0.key) }
            .map { (userId: $0.key, name: $0.value) }
            .sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    private func start() async {
        if let problem = GroupDM.sizeProblem(others: chosen.count) { message = problem; return }
        busy = true; message = ""; defer { busy = false }
        let members = people.filter { chosen.contains($0.userId) }
        if let problem = await onStart(members) { message = problem } else { dismiss() }
    }
}

// MARK: - The conversation

struct GroupChatView: View {
    let group: GroupDM
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @Environment(\.dismiss) private var dismiss
    @State private var messages: [ChatMessage] = []
    @State private var rows: [Message] = []
    @State private var olderRows: [Message] = []
    @State private var draft = ""
    @State private var sendError: String?
    @State private var uploading = false
    @State private var loadingOlder = false
    @State private var reachedStart = false
    @State private var sendStates: [String: SendState] = [:]
    @State private var reactionsByMessage: [String: [ReactionPill]] = [:]
    @State private var replyingTo: ChatMessage?
    @State private var editing: ChatMessage?
    @State private var showPeople = false
    @State private var blocking: ReportTarget?
    @State private var reporting: ReportTarget?

    private var scope: String { "dm:\(group.conversationId)" }
    /// Who a message of this group is sealed to: the members shown on this screen.
    private var peers: [String] { group.memberUserIds }
    private func name(_ userId: String) -> String { app.contacts.display(userId, claimedName: group.claimedNames[userId]).text }
    private var anyUnverified: Bool {
        group.memberUserIds.contains { id in
            let badge = app.contacts.display(id, claimedName: group.claimedNames[id]).badge
            return badge != .none && badge != .verified
        }
    }

    var body: some View {
        ChatSurface(
            title: chat.title(of: group),
            subtitle: "\(group.memberUserIds.count + 1) people · end-to-end encrypted" + (anyUnverified ? " · some names not verified" : ""),
            messages: messages,
            draft: $draft,
            sending: false,
            sendError: sendError,
            placeholder: "Message the group",
            onSend: { Task { await send() } },
            onLoadOlder: rows.count >= 200 || !olderRows.isEmpty ? { Task { await loadOlder() } } : nil,
            loadingOlder: loadingOlder,
            reachedStart: reachedStart,
            uploading: uploading,
            onSendFile: { url in Task { await sendAttachment(.file(url)) } },
            onSendMusic: { track in Task { await sendBody { try AttachmentService.musicBody(track).body } } },
            onSendImage: { data in Task { await sendAttachment(.image(data)) } },
            onBack: { chat.selection = nil; dismiss() },
            onReact: { msg, emoji in Task { await toggleReaction(msg, emoji) } },
            onReply: { msg in editing = nil; replyingTo = msg },
            onEdit: { msg in replyingTo = nil; editing = msg; draft = msg.body },
            onDelete: { msg in Task { await deleteMessage(msg) } },
            composingBanner: composingBanner,
            onCancelCompose: { if editing != nil { draft = "" }; replyingTo = nil; editing = nil },
            headerActions: {
                AnyView(
                    Button { showPeople = true } label: {
                        Image(systemName: "person.2.fill").foregroundStyle(.white.opacity(0.7))
                    }
                    .buttonStyle(.plain).help("People").accessibilityLabel("People")
                )
            }
        )
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .sheet(isPresented: $showPeople) { GroupPeopleSheet(group: group) }
        .safetyActions(blocking: $blocking, reporting: $reporting)
        .environment(\.messageExtras, MessageExtras(
            onReport: { msg in
                guard let id = msg.authorId, !msg.mine else { return }
                reporting = ReportTarget(userId: id, name: msg.author, messageText: msg.body.isEmpty ? nil : msg.body, serverId: nil)
            },
            onBlock: { msg in
                guard let id = msg.authorId, !msg.mine else { return }
                blocking = ReportTarget(userId: id, name: msg.author)
            },
            onRetry: { Outbox.retry(app, localId: $0) },
            onDiscard: { Outbox.discard(app, localId: $0) }))
        .task(id: group.conversationId) { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .skwodOutboxChanged)) { _ in Task { await reloadFromCache() } }
        .onReceive(NotificationCenter.default.publisher(for: .skwodDMChanged)) { note in
            if note.object as? String == group.conversationId { Task { await reloadFromCache() } }
        }
        .onReceive(NotificationCenter.default.publisher(for: .skwodLiveConnected)) { _ in Task { await app.syncMailbox() } }
    }

    private var composingBanner: (text: String, isEdit: Bool)? {
        if editing != nil { return ("Editing message", true) }
        if let r = replyingTo { return ("Replying to \(r.mine ? "yourself" : r.author)", false) }
        return nil
    }

    private func load() async {
        olderRows = []; reachedStart = false
        await reloadFromCache()
        while !Task.isCancelled {
            await Outbox.flush(app)
            // A group's messages arrive in the sealed mailbox like any DM's.
            await app.syncMailbox()
            await reloadFromCache()
            try? await Task.sleep(for: LiveSync.safetyInterval)
        }
    }

    private func reloadFromCache() async {
        guard let client = app.client else { return }
        rows = await client.history(scope: scope)
        let me = app.session?.userId ?? ""
        // Reactions count only from this account and the group's members (as rows do, below).
        let members = Set(group.memberUserIds)
        let reactions = await client.dmReactions(conversationId: group.conversationId).filter { ContactTrust.reactionCounts(from: $0.userId, me: me, participants: members) }
        reactionsByMessage = SpaceChannelView.pills(reactions, me: me)
        let queued = await Outbox.states(client, scope: scope)
        sendStates = queued.byMessage
        if let problem = queued.problem { sendError = problem }
        messages = map(allRows)
    }

    private var allRows: [Message] {
        let recent = Set(rows.map(\.messageId))
        return olderRows.filter { !recent.contains($0.messageId) } + rows
    }

    private func loadOlder() async {
        guard let client = app.client, !loadingOlder, !reachedStart, let oldest = allRows.first?.createdAt else { return }
        loadingOlder = true
        defer { loadingOlder = false }
        let page = await client.historyPage(scope: scope, beforeMs: oldest, limit: 100)
        if page.isEmpty { reachedStart = true; return }
        olderRows = page + olderRows
        messages = map(allRows)
    }

    /// Rows by this account or by a MEMBER of the group as this device holds it. A row some
    /// other account got filed under this conversation id is not shown as part of it.
    private func map(_ rows: [Message]) -> [ChatMessage] {
        let me = app.session?.userId
        let members = Set(group.memberUserIds)
        func mine(_ m: Message) -> Bool { m.authorId == "__me__" || (m.authorId != nil && m.authorId == me) }
        func shown(_ m: Message) -> Bool { mine(m) || (m.authorId.map(members.contains) ?? false) }
        var bodyById: [String: (author: String, text: String)] = [:]
        for m in rows where !m.isDeleted && !m.isSystem && !m.isUndecryptable && shown(m) {
            bodyById[m.messageId] = (mine(m) ? "you" : name(m.authorId ?? ""), ChatTags.parse(m.content ?? "").text)
        }
        return rows.compactMap { m in
            if m.isSystem { return SecurityAlert.systemMessage(m, name: { name($0) }) }
            if m.isUndecryptable { return SecurityAlert.placeholderMessage(m, name: { name($0) }) }
            guard shown(m) else { return nil }
            let isMine = mine(m)
            let parsed = ChatTags.parse(m.content ?? "")
            let replyPreview = m.replyToId.flatMap { bodyById[$0] }.map { "\($0.author): \($0.text.prefix(60))" }
            return ChatMessage(id: m.messageId, author: isMine ? "you" : name(m.authorId ?? ""), authorId: isMine ? me : m.authorId,
                               body: parsed.text, mine: isMine, reactionPills: reactionsByMessage[m.messageId] ?? [],
                               createdAt: m.createdAt, attachment: parsed.attachment, music: parsed.music,
                               replyToId: m.replyToId, replyPreview: replyPreview,
                               isEdited: m.isEdited, isDeleted: m.isDeleted,
                               sendState: isMine ? sendStates[m.messageId] : nil)
        }
    }

    private func send() async {
        guard let client = app.client else { return }
        let text = draft.trimmingCharacters(in: .whitespaces); guard !text.isEmpty else { return }
        let (replyTarget, editTarget) = (replyingTo, editing)
        draft = ""; sendError = nil; replyingTo = nil; editing = nil
        do {
            if let editTarget {
                try await client.queueDmEdit(conversationId: group.conversationId, peerUserIds: peers, messageId: editTarget.id, text: text)
            } else {
                _ = try await client.queueDm(conversationId: group.conversationId, peerUserIds: peers, text: text, replyToId: replyTarget?.id, uploadIds: [])
            }
            Outbox.kick(app, composed: true)
        } catch {
            draft = draft.isEmpty ? text : "\(text)\n\(draft)"
            replyingTo = replyTarget; editing = editTarget
            sendError = sendFailureText(error)
        }
    }

    private func sendBody(_ make: () throws -> String) async {
        guard let client = app.client else { sendError = "Not connected — try again in a moment."; return }
        do {
            _ = try await client.queueDm(conversationId: group.conversationId, peerUserIds: peers, text: try make(), replyToId: nil, uploadIds: [])
            Outbox.kick(app, composed: true)
        } catch { sendError = sendFailureText(error) }
    }

    private func sendAttachment(_ source: StreamedUpload.Source) async {
        uploading = true; sendError = nil
        defer { uploading = false }
        do {
            try await StreamedUpload.queue(source, to: .dm(conversationId: group.conversationId, peers: peers), app: app)
        } catch { sendError = sendFailureText(error) }
    }

    private func toggleReaction(_ msg: ChatMessage, _ emoji: String) async {
        guard let client = app.client else { return }
        let mineAlready = msg.reactionPills.first(where: { $0.emoji == emoji })?.mine ?? false
        do {
            try await client.queueDmReaction(conversationId: group.conversationId, peerUserIds: peers, messageId: msg.id, emoji: emoji, remove: mineAlready)
            Outbox.kick(app)
        } catch { sendError = sendFailureText(error) }
    }

    private func deleteMessage(_ msg: ChatMessage) async {
        guard let client = app.client else { return }
        do {
            try await client.queueDmDelete(conversationId: group.conversationId, peerUserIds: peers, messageId: msg.id)
            Outbox.kick(app)
        } catch { sendError = sendFailureText(error) }
    }
}

// MARK: - People

/// The group's members with each one's trust marker and safety number, and the two ways its
/// membership "changes": the server cannot add to or remove from a group, so both start a NEW
/// group with the changed set — said plainly before it happens.
struct GroupPeopleSheet: View {
    let group: GroupDM
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @Environment(\.dismiss) private var dismiss
    @State private var verifying: (userId: String, name: String)?
    @State private var adding = false
    @State private var removing: String?
    @State private var message = ""

    private func name(_ userId: String) -> String { app.contacts.display(userId, claimedName: group.claimedNames[userId]).text }

    var body: some View {
        VStack(spacing: 14) {
            Text("People").font(.title2.bold()).foregroundStyle(.white).accessibilityAddTraits(.isHeader)
            Text("Messages are sealed separately to every device of every member.")
                .font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
            if chat.group(for: group.conversationId)?.serverDisagrees == true {
                Label("The server now lists different people for this group than the ones you joined it with. Skwod ignores that: your messages go only to the people shown here.",
                      systemImage: "exclamationmark.shield.fill")
                    .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("group.serverDisagrees")
            }
            VStack(spacing: 6) {
                ForEach(group.memberUserIds, id: \.self) { id in
                    let shown = app.contacts.display(id, claimedName: group.claimedNames[id])
                    HStack(spacing: 10) {
                        AvatarImage(key: AvatarStore.userKey(id), name: shown.text, size: 32)
                        Text(shown.text).foregroundStyle(.white).lineLimit(1)
                        TrustBadge(badge: shown.badge)
                        Spacer()
                        Menu {
                            Button("View safety number") { verifying = (id, shown.text) }
                            if group.memberUserIds.count > GroupDM.minOthers {
                                Button("Remove \(shown.text)…", role: .destructive) { removing = id }
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle").foregroundStyle(.white.opacity(0.7))
                        }
                        .menuStyle(.button).buttonStyle(.plain).fixedSize()
                    }
                    .padding(.horizontal, 12).padding(.vertical, 8)
                }
            }
            .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            if !message.isEmpty {
                Label(message, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
            }
            if group.memberUserIds.count < GroupDM.maxOthers {
                Button { adding = true } label: {
                    Label("Add people…", systemImage: "person.badge.plus").frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .controlSize(.large).buttonStyle(.glass).tint(.skAccent)
            }
            Button("Done") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(24)
        .frame(minWidth: 360, maxWidth: 460)
        .background(SkwodBackground())
        .sheet(isPresented: Binding(get: { verifying != nil }, set: { if !$0 { verifying = nil } })) {
            if let v = verifying { SafetyNumberView(peerName: v.name, peerUserId: v.userId, onAccepted: {}) }
        }
        .sheet(isPresented: $adding) {
            NewGroupSheet(preselected: group.memberUserIds,
                          note: "This starts a new group with the people you pick. Messages already sent stay in the old one.") { members in
                await start(members)
            }
        }
        .confirmationDialog("Start a new group without \(removing.map(name) ?? "them")?",
                            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("Start new group") {
                guard let gone = removing else { return }
                let rest = group.memberUserIds.filter { $0 != gone }.map { (userId: $0, name: group.claimedNames[$0] ?? "") }
                Task { if let problem = await start(rest) { message = problem } }
            }
        } message: {
            Text("This starts a new group with \(GroupDM.title(memberNames: group.memberUserIds.filter { $0 != removing }.map(name))). Messages already sent stay in the old one.")
        }
    }

    private func start(_ members: [(userId: String, name: String)]) async -> String? {
        do {
            try await chat.startGroup(with: members)
            dismiss()
            return nil
        } catch {
            return coreErrorText(error, fallback: "Couldn't start the group — check your connection.")
        }
    }
}

/// A group's row in the conversation lists.
struct GroupRow: View {
    let group: GroupDM
    var selected = false
    @EnvironmentObject private var chat: ChatModel

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "person.3.fill").font(.system(size: 13)).foregroundStyle(.white.opacity(0.85))
                .frame(width: 30, height: 30).background(Color.skAccent.opacity(0.25), in: Circle())
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(chat.title(of: group)).font(.system(size: 14, weight: selected ? .semibold : .regular))
                    .foregroundStyle(.white).lineLimit(1)
                Text("\(group.memberUserIds.count + 1) people").font(.caption2).foregroundStyle(.white.opacity(0.45))
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .background(selected ? Color.white.opacity(0.10) : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Group: \(chat.title(of: group, limit: 9))")
    }
}
