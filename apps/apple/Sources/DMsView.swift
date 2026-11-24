import SwiftUI

struct NewDMSheet: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @Environment(\.dismiss) private var dismiss
    @State private var username = ""
    @State private var busy = false
    @State private var error = ""

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 18) {
                Text("New chat").font(.title2.bold()).foregroundStyle(.white)
                HStack {
                    Image(systemName: "at").foregroundStyle(.skAccent)
                    TextField("username", text: $username).textFieldStyle(.plain).foregroundStyle(.white)
                        #if os(iOS)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        #endif
                }
                .padding(14).glassEffect(.regular.interactive(), in: .capsule)
                if !error.isEmpty {
                    Text(error).font(.caption).foregroundStyle(.red).multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Button { Task { await start() } } label: {
                    HStack { if busy { ProgressView().controlSize(.small) }; Text("Start encrypted chat") }
                        .frame(maxWidth: .infinity).padding(.vertical, 4)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                .disabled(busy || username.isEmpty)
                Button("Cancel") { dismiss() }.buttonStyle(.glass)
            }
            .padding(28).frame(maxWidth: 380)
        }
        .presentationDetents([.medium])
    }

    private func start() async {
        busy = true; error = ""
        // Asked, and stored, in the workspace that is current NOW (`ChatModel.openDM`). A
        // refusal is said here — the sheet stays up — instead of closing as if it had worked.
        let outcome = await chat.openDM(username: username.lowercased())
        busy = false
        if let problem = outcome.problem { error = problem } else { dismiss() }
    }
}

/// A real end-to-end encrypted 1:1 chat, backed by the Rust core + server.
struct DMChatView: View {
    let convo: DMConversation
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @Environment(\.dismiss) private var dismiss
    @State private var messages: [ChatMessage] = []
    @State private var draft = ""
    @State private var sending = false
    @State private var sendError: String?
    @State private var uploading = false
    @State private var olderRows: [Message] = []
    @State private var latestRows: [Message] = []
    @State private var loadingOlder = false
    @State private var reachedStart = false
    @State private var showVerify = false
    @ObservedObject private var blocks = BlockList.shared
    @State private var blocking: ReportTarget?
    @State private var reporting: ReportTarget?
    /// Queued sends of this conversation, by message id (`Outbox`).
    @State private var sendStates: [String: SendState] = [:]
    @State private var reactionsByMessage: [String: [ReactionPill]] = [:]
    @State private var replyingTo: ChatMessage?
    @State private var editing: ChatMessage?
    private var isBlocked: Bool { blocks.ids.contains(convo.peerUserId) }
    /// Where this contact's keys stand (`IdentityHold`): sends on hold (`ContactStatus`, or a
    /// send that failed on their keys), or a device of theirs waiting to be accepted.
    @State private var hold: IdentityHold = .none
    private var sendsHeld: Bool { hold == .onHold }
    /// Whether I have verified this contact's account (shield in the header).
    @State private var verified = false
    @State private var accepting = false
    /// The device set the hold banner was drawn for (`ContactStatus.acceptFingerprint`): what
    /// "Continue" accepts, and nothing listed after it (audit L2).
    @State private var acceptShown = ""

    var body: some View {
        ChatSurface(
            title: shown.text,
            subtitle: shown.badge == .verified ? "verified · end-to-end encrypted"
                : (shown.badge == .none ? "end-to-end encrypted" : "name not verified · end-to-end encrypted"),
            messages: messages,
            draft: $draft,
            sending: sending,
            sendError: sendError,
            placeholder: "Message \(shown.text)",
            onSend: { Task { await send() } },
            onLoadOlder: latestRows.count >= 200 || !olderRows.isEmpty ? { Task { await loadOlder() } } : nil,
            loadingOlder: loadingOlder,
            reachedStart: reachedStart,
            uploading: uploading,
            // A DM attachment carries its own download token: a sealed DM leaves no row on the
            // server that access to the file could hang on.
            onSendFile: { url in Task { await sendAttachment(.file(url)) } },
            onSendMusic: { track in Task { await sendTagged { _ in try AttachmentService.musicBody(track) } } },
            onSendImage: { data in Task { await sendAttachment(.image(data)) } },
            // Back works from both contexts: clears the drawer selection (no-op when pushed) and
            // pops the navigation stack (no-op in the drawer).
            onBack: { chat.selection = nil; dismiss() },
            // The same menu a channel message has: react, reply, edit and delete (for
            // everyone) — sealed to every device of both people, like the message itself.
            onReact: { msg, emoji in Task { await toggleReaction(msg, emoji) } },
            onReply: { msg in editing = nil; replyingTo = msg },
            onEdit: { msg in replyingTo = nil; editing = msg; draft = msg.body },
            onDelete: { msg in Task { await deleteMessage(msg) } },
            // "View safety number" on a system row about this contact's devices.
            onSystemAction: { _ in showVerify = true },
            notice: hold != .none ? AnyView(heldBanner) : (shown.badge == .none || shown.badge == .verified ? nil : AnyView(unverifiedBanner)),
            composingBanner: composingBanner,
            onCancelCompose: { if editing != nil { draft = "" }; replyingTo = nil; editing = nil },
            conversationId: convo.conversationId,
            headerActions: {
                AnyView(
                    HStack(spacing: 10) {
                        Button { showVerify = true } label: {
                            Image(systemName: sendsHeld ? "exclamationmark.shield.fill" : (verified ? "checkmark.shield.fill" : "shield.lefthalf.filled"))
                                .foregroundStyle(sendsHeld ? Color.orange : (verified ? Color.green : .white.opacity(0.7)))
                        }.buttonStyle(.plain)
                            .help(sendsHeld ? "Safety number changed" : (verified ? "Verified — view safety number" : "View safety number"))
                            .accessibilityLabel("Safety number")
                        // User-safety actions for this peer: block (server-enforced, symmetric)
                        // and report to the instance operator (E2EE-preserving, see safety.rs).
                        Menu {
                            SafetyMenuItems(userId: convo.peerUserId, name: convo.name, serverId: nil, blocking: $blocking, reporting: $reporting)
                        } label: {
                            Image(systemName: "ellipsis.circle").foregroundStyle(.white.opacity(0.7))
                        }
                        .menuStyle(.button).buttonStyle(.plain).fixedSize()
                    }
                )
            }
        )
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        .navigationTitle(shown.text)
        #endif
        .sheet(isPresented: $showVerify) {
            SafetyNumberView(peerName: shown.text, peerUserId: convo.peerUserId,
                             onAccepted: { Task { if let c = app.client { await retryHeldSends(c) }; await refreshStatus() } })
        }
        // Verified (or accepted) on the safety-number screen: what was held goes out now.
        .onChange(of: showVerify) { _, open in if !open { Task { if let c = app.client { await retryHeldSends(c) }; await refreshStatus() } } }
        .safetyActions(blocking: $blocking, reporting: $reporting)
        .environment(\.messageExtras, MessageExtras(
            onReport: { msg in reporting = ReportTarget(userId: convo.peerUserId, name: convo.name, messageText: msg.body.isEmpty ? nil : msg.body, serverId: nil) },
            onBlock: { _ in blocking = ReportTarget(userId: convo.peerUserId, name: convo.name) },
            onRetry: { Outbox.retry(app, localId: $0) },
            onDiscard: { Outbox.discard(app, localId: $0) },
            // Build 46: "@" suggests the peer here too (no @everyone in a direct conversation);
            // mentions render with the contact book's label and open the person's card.
            me: app.session?.userId,
            mentionLabel: { uid in uid == convo.peerUserId ? shown.text
                : ContactTrust.mentionDisplay(userId: uid, me: app.session?.userId, myName: nil) { app.contacts.display($0, claimedName: nil) }.label(for: .mentionChip) },
            mentionBadge: { uid in ContactTrust.mentionDisplay(userId: uid, me: app.session?.userId, myName: nil) {
                app.contacts.display($0, claimedName: $0 == convo.peerUserId ? convo.name : nil) } },
            everyoneAllowed: { _ in false },
            mentionable: BlockList.shared.contains(convo.peerUserId) || convo.peerUserId.isEmpty
                ? [] : [(userId: convo.peerUserId, name: shown.text, username: convo.name)],
            typingFrom: convo.peerUserId.isEmpty ? [] : [convo.peerUserId]))
        .task(id: convo.conversationId) { await load() }
        // Queued / delivered / failed, or a block: redraw from the cache.
        .onReceive(NotificationCenter.default.publisher(for: .skwodOutboxChanged)) { _ in Task { await reloadFromCache() } }
        // Live: a DM for this conversation was just filed into the cache (`AppState.syncMailbox`
        // runs when the relay says the mailbox has something) → show it. No polling.
        .onReceive(NotificationCenter.default.publisher(for: .skwodDMChanged)) { note in
            if note.object as? String == convo.conversationId { Task { await reloadFromCache() } }
        }
        .onReceive(NotificationCenter.default.publisher(for: .skwodLiveConnected)) { _ in Task { await refresh() } }
        #if DEBUG
        .onReceive(NotificationCenter.default.publisher(for: .skwodE2EShowSafety)) { _ in showVerify = true }
        #endif
    }

    /// The peer's name as this device may show it (`ContactTrust`).
    private var shown: ContactTrust.Display { app.contacts.display(convo.peerUserId, claimedName: convo.name) }

    /// Shown above the composer while the peer's name is only the server's claim — or looks
    /// like someone the user knows but is a different account. "Accept" is the explicit action
    /// that makes them a known contact under that name; verifying the safety number does more.
    private var unverifiedBanner: some View {
        let strong = shown.badge == .impersonation
        return VStack(alignment: .leading, spacing: 8) {
            Label(strong ? "Possible impersonation" : "Skwod can't confirm who this is",
                  systemImage: strong ? "exclamationmark.octagon.fill" : "person.crop.circle.badge.questionmark")
                .font(.subheadline.weight(.semibold)).foregroundStyle(strong ? .red : .orange)
            Text(strong
                 ? "The server gives this account a name that looks like someone you know — or one with characters no Skwod name has — and it is a DIFFERENT account. Don't trust it because of the name."
                 : "This conversation's name comes from the server, not from the person. Check with them another way — or compare safety numbers — before trusting it.")
                .font(.caption).foregroundStyle(.white.opacity(0.75)).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                Button { showVerify = true } label: { Label("View safety number", systemImage: "shield.lefthalf.filled") }
                    .buttonStyle(DecisionButtonStyle(primary: true))
                // Offered for a name that is merely unverified/unconfirmed; never while the
                // strong warning stands (`ContactBook.accept` refuses that too).
                if ContactTrust.mayAccept(shown: shown, name: convo.name) {
                    Button("I know them — accept") { app.contacts.accept(convo.peerUserId, name: convo.name) }
                        .buttonStyle(DecisionButtonStyle())
                }
            }
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background((strong ? Color.red : .orange).opacity(0.10))
        .accessibilityIdentifier("dm.unverified")
    }

    /// Shown above the composer while sends are held, or a device of the contact waits to be
    /// accepted. It says what happened, what it means and offers the two ways forward —
    /// verify (the safety number), or accept and deliver what was held.
    private var heldBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(hold.headline(name: shown.text) ?? "", systemImage: "exclamationmark.shield.fill")
                .font(.subheadline.weight(.semibold)).foregroundStyle(.orange)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("dm.keyChanged")
            Text("That is usually a new phone or a reinstall, but it is also what someone intercepting the conversation would look like. Check with \(shown.text) another way, or compare safety numbers, before you accept.")
                .font(.caption).foregroundStyle(.white.opacity(0.75)).fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 10) {
                Button { showVerify = true } label: { Label("Verify", systemImage: "shield.lefthalf.filled") }
                    .buttonStyle(DecisionButtonStyle(primary: true))
                Button { Task { await acceptAndSend() } } label: {
                    Text(draft.trimmingCharacters(in: .whitespaces).isEmpty ? "Accept" : "Accept & send")
                }
                .buttonStyle(DecisionButtonStyle()).disabled(accepting)
                .accessibilityIdentifier("dm.acceptKey")
                if accepting { ProgressView().controlSize(.small) }
            }
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10))
        .overlay(Rectangle().fill(.orange.opacity(0.35)).frame(height: 1), alignment: .top)
    }

    /// Continue without verifying: accept the devices listed now (the contact becomes
    /// unverified), deliver the messages that were held, then send whatever was waiting in the
    /// composer.
    private func acceptAndSend() async {
        guard let client = app.client else { return }
        accepting = true
        defer { accepting = false }
        do {
            try await client.acceptIdentityChange(userId: convo.peerUserId, deviceId: "", shown: acceptShown)
        } catch CoreError.IdentityChanged {
            // The server listed something else since the banner was drawn: nothing was
            // accepted. Show the banner for what is listed now; the user decides again.
            await refreshStatus()
            sendError = "Their devices changed again while you were deciding. Check the banner and decide again."
            return
        } catch {
            sendError = "Couldn't accept the new devices — check your connection."
            return
        }
        await retryHeldSends(client)
        await refreshStatus()
        if !sendsHeld, !draft.trimmingCharacters(in: .whitespaces).isEmpty { await send() }
    }

    /// The contact's keys were accepted (here or on the safety-number screen): what failed
    /// because of them is queued again and delivered now — marked "Sending…" until it is.
    private func retryHeldSends(_ client: SkwodClient) async {
        // Only once the core sends to them again — a retry while still held fails the same way.
        let status = await client.contactStatus(userId: convo.peerUserId)
        guard IdentityHold.decide(sendsHeld: status.sendsHeld, devices: status.devices,
                                  unvouchedDevices: status.unvouchedDevices, failedOnIdentity: false) != .onHold else { return }
        let queued = await Outbox.states(client, scope: scope)
        var retried = false
        for case .failed(let localId, let reason) in queued.byMessage.values where IdentityHold.isIdentityFailure(reason) {
            await client.retrySend(localId: localId)
            retried = true
        }
        guard retried else { return }
        await loadOverlays(client)
        messages = map(allRows)
        await Outbox.flush(app)
    }

    private func refreshStatus() async {
        guard let client = app.client else { return }
        let status = await client.contactStatus(userId: convo.peerUserId)
        // This workspace's answer is only for this workspace's contact book.
        guard app.client === client else { return }
        hold = IdentityHold.decide(sendsHeld: status.sendsHeld, devices: status.devices,
                                   unvouchedDevices: status.unvouchedDevices, failedOnIdentity: failedOnIdentity)
        acceptShown = status.acceptFingerprint
        verified = status.verified
        // Verifying the safety number is what makes a contact VERIFIED (and losing it, not).
        // A read of the core's state: it may only demote (raising is the safety-number screen's).
        app.contacts.noteStatusRead(convo.peerUserId, verified: status.verified)
    }

    private var scope: String { "dm:\(convo.conversationId)" }

    /// A queued send of this conversation failed on the contact's keys (shown "Not delivered").
    private var failedOnIdentity: Bool {
        sendStates.values.contains { if case .failed(_, let why) = $0 { return IdentityHold.isIdentityFailure(why) } else { return false } }
    }

    /// Seed instantly from the local encrypted cache (works offline), then sync once. After
    /// that the view follows live events; the loop is only the slow safety net behind them.
    private func load() async {
        guard app.client != nil else { return }
        olderRows = []; reachedStart = false
        await reloadFromCache()
        while !Task.isCancelled {
            await Outbox.flush(app)
            await refresh()
            try? await Task.sleep(for: LiveSync.safetyInterval)
        }
    }

    private func reloadFromCache() async {
        guard let client = app.client else { return }
        latestRows = await client.history(scope: scope)
        await loadOverlays(client)
        messages = map(allRows)
    }

    /// Reactions and queued-send states of this conversation (both local).
    private func loadOverlays(_ client: SkwodClient) async {
        let me = app.session?.userId ?? ""
        // Only this account's and the bound peer's: a third account's sealed reaction to a
        // message here is not shown as if the peer had reacted.
        let reactions = await client.dmReactions(conversationId: convo.conversationId)
            .filter { ContactTrust.reactionCounts(from: $0.userId, me: me, participants: [convo.peerUserId]) }
        reactionsByMessage = SpaceChannelView.pills(reactions, me: me)
        let queued = await Outbox.states(client, scope: scope)
        sendStates = queued.byMessage
        if let problem = queued.problem { sendError = problem }
    }

    private var allRows: [Message] {
        let recent = Set(latestRows.map(\.messageId))
        return olderRows.filter { !recent.contains($0.messageId) } + latestRows
    }

    /// "Load older": the previous page of this conversation from the local cache. (A DM is
    /// delivered once, to this device's mailbox; there is no server copy to page through.)
    private func loadOlder() async {
        guard let client = app.client, !loadingOlder, !reachedStart, let oldest = allRows.first?.createdAt else { return }
        loadingOlder = true
        defer { loadingOlder = false }
        let page = await client.historyPage(scope: scope, beforeMs: oldest, limit: 100)
        if page.isEmpty { reachedStart = true; return }
        olderRows = page + olderRows
        messages = map(allRows)
    }

    private func map(_ rows: [Message]) -> [ChatMessage] {
        // What a reply may quote: ONLY messages this conversation shows — written by me or by
        // the one peer it is bound to. A row some other account got filed under this
        // conversation id (it is not rendered, see below) must not surface through a reply
        // preview either, under the peer's name.
        let me = app.session?.userId
        let quotable = DMReplySources.quotable(rows.filter { !$0.isSystem && !$0.isUndecryptable }.map { ($0.messageId, $0.authorId, $0.isDeleted, $0.content ?? "") },
                                               me: me, peer: convo.peerUserId)
        let bodyById = quotable.mapValues { q in (author: q.mine ? "you" : shown.text, text: ChatTags.parse(q.content).text) }
        return rows.compactMap { m in
            // This conversation is bound to ONE peer account. A row some other account sent
            // under this conversation id (a server pairing the wrong people) is not shown here
            // as if the peer had written it — that sender has an entry of its own.
            if !m.isSystem, let author = m.authorId, author != "__me__", author != app.session?.userId,
               author != convo.peerUserId { return nil }
            // A security notice about this contact, kept in the conversation itself.
            if m.isSystem {
                return SecurityAlert.systemMessage(m, name: { id in
                    id == convo.peerUserId ? shown.text : "A member (\(id.prefix(6))…)"
                })
            }
            if m.isUndecryptable {
                return SecurityAlert.placeholderMessage(m, name: { _ in shown.text })
            }
            let mine = m.authorId == "__me__" || (m.authorId != nil && m.authorId == app.session?.userId)
            let parsed = ChatTags.parse(m.content ?? "")
            // A DM has two participants: my rows use my userId, the rest are the peer.
            let authorId = mine ? app.session?.userId : convo.peerUserId
            let replyPreview = m.replyToId.flatMap { bodyById[$0] }.map { "\($0.author): \($0.text.prefix(60))" }
            return ChatMessage(id: m.messageId, author: mine ? "you" : shown.text, authorId: authorId, body: parsed.text,
                               mine: mine, reactionPills: reactionsByMessage[m.messageId] ?? [], createdAt: m.createdAt,
                               attachment: parsed.attachment, music: parsed.music,
                               replyToId: m.replyToId, replyPreview: replyPreview,
                               isEdited: m.isEdited, isDeleted: m.isDeleted,
                               sendState: mine ? sendStates[m.messageId] : nil, mentions: ChatTags.mentions(m.content ?? ""))
        }
    }

    private var composingBanner: (text: String, isEdit: Bool)? {
        if editing != nil { return ("Editing message", true) }
        if let r = replyingTo { return ("Replying to \(r.mine ? "yourself" : r.author)", false) }
        return nil
    }

    /// Who a message of this conversation is sealed to.
    private var peers: [String] { [convo.peerUserId] }

    /// A file or photo: encrypted file-to-file, queued, uploaded in resumable chunks by the
    /// outbox (`StreamedUpload`). Returns as soon as it is queued.
    private func sendAttachment(_ source: StreamedUpload.Source) async {
        uploading = true; sendError = nil
        defer { uploading = false }
        do {
            try await StreamedUpload.queue(source, to: .dm(conversationId: convo.conversationId, peers: peers), app: app)
        } catch {
            sendError = sendFailureText(error)
        }
    }

    /// Build a tagged body (encrypted attachment upload or music card) and queue it in the DM.
    private func sendTagged(_ make: @escaping (BlobStore) async throws -> AttachmentService.Outgoing) async {
        guard let client = app.client, let store = BlobStore(app: app) else {
            sendError = "Not connected — try again in a moment."
            return
        }
        uploading = true; sendError = nil
        var uploaded: [String] = []
        do {
            let out = try await make(store)
            uploaded = out.blobIds
            _ = try await client.queueDm(conversationId: convo.conversationId, peerUserIds: peers, text: out.body, replyToId: nil, uploadIds: [])
            // Writing in a conversation is the user taking it: it now claims its id.
            app.chatModel?.claimDM(convo)
            Outbox.kick(app, composed: true)
        } catch {
            sendError = sendFailureText(error)
            for id in uploaded { await store.delete(id) }
        }
        uploading = false
    }

    /// Send, reply or edit — queued in the core (shown at once as "Sending…"), delivered to
    /// every device of both people when the connection allows.
    private func send() async {
        guard let client = app.client else { return }
        let text = draft.trimmingCharacters(in: .whitespaces); guard !text.isEmpty else { return }
        let (replyTarget, editTarget) = (replyingTo, editing)
        draft = ""; sendError = nil; replyingTo = nil; editing = nil
        do {
            if let editTarget {
                try await client.queueDmEdit(conversationId: convo.conversationId, peerUserIds: peers, messageId: editTarget.id, text: text)
            } else {
                _ = try await client.queueDm(conversationId: convo.conversationId, peerUserIds: peers, text: text, replyToId: replyTarget?.id, uploadIds: [])
                // Writing in a conversation is the user taking it: it now claims its id.
                app.chatModel?.claimDM(convo)
            }
            Outbox.kick(app, composed: true)
        } catch {
            draft = draft.isEmpty ? text : "\(text)\n\(draft)"
            replyingTo = replyTarget; editing = editTarget
            sendError = sendFailureText(error)
        }
    }

    private func toggleReaction(_ msg: ChatMessage, _ emoji: String) async {
        guard let client = app.client else { return }
        let mineAlready = msg.reactionPills.first(where: { $0.emoji == emoji })?.mine ?? false
        do {
            try await client.queueDmReaction(conversationId: convo.conversationId, peerUserIds: peers, messageId: msg.id, emoji: emoji, remove: mineAlready)
            Outbox.kick(app)
        } catch { sendError = sendFailureText(error) }
    }

    private func deleteMessage(_ msg: ChatMessage) async {
        guard let client = app.client else { return }
        do {
            try await client.queueDmDelete(conversationId: convo.conversationId, peerUserIds: peers, messageId: msg.id)
            Outbox.kick(app)
        } catch { sendError = sendFailureText(error) }
    }

    private func refresh() async {
        guard let client = app.client, let me = app.session?.userId else { return }
        if let hist = try? await client.fetchDm(conversationId: convo.conversationId, userId: convo.peerUserId, deviceId: convo.peerDeviceId, myUserId: me) {
            latestRows = hist
            await loadOverlays(client)
            // A send the core refused because this contact's keys changed holds the
            // conversation (`refreshStatus` below decides the banner with it).
            messages = map(allRows)
        }
        // Syncing the mailbox may have brought DMs for OTHER conversations too.
        await app.drainDmEvents()
        await refreshStatus()
    }
}

/// Which rows of a DM conversation a reply preview may quote. Pure, so it is checked by
/// `selfcheck` (`E2EHooks`).
enum DMReplySources {
    /// Is a row by `authorId` one this conversation shows as a message — mine, or the bound peer's?
    static func isParticipant(_ authorId: String?, me: String?, peer: String) -> Bool {
        guard let authorId else { return false }
        return authorId == "__me__" || authorId == peer || (me != nil && authorId == me)
    }

    /// message id → (mine, content) for every live message of mine or the peer's. Rows by
    /// anyone else (a third account filed under this conversation id, system rows) are left out.
    static func quotable(_ rows: [(id: String, authorId: String?, deleted: Bool, content: String)],
                         me: String?, peer: String) -> [String: (mine: Bool, content: String)] {
        var out: [String: (mine: Bool, content: String)] = [:]
        for r in rows where !r.deleted && isParticipant(r.authorId, me: me, peer: peer) {
            out[r.id] = (r.authorId != peer || r.authorId == me, r.content)
        }
        return out
    }
}
