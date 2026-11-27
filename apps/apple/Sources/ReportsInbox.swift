import SwiftUI

/// The reports inbox of a skwod's owner.
///
/// A report's note and quoted message are sealed (like a DM) to the owner's devices; the server
/// only ever held who reported whom and why. EVERYTHING in a report except who sent it is the
/// reporter's claim: the quote, the person it names, the server, the message id. So nothing the
/// owner can do from here acts on those claims:
///
/// - "Remove message", and kicking or banning from a report, act on what THIS device can
///   confirm — the message it holds under that id, that message's real author, and the server
///   that channel belongs to on this device. A report that names a different person or server
///   than the message it points at is shown as a mismatch and offers no action on it.
/// - With no message to confirm against, kicking or banning needs the owner to pick the server
///   and the person themselves, and to confirm both by name.

/// What a report points at, as this device can confirm it — or why it cannot.
struct ReportResolution: Equatable {
    /// The message this device holds under the reported id, and where it really is.
    struct Target: Equatable {
        var channelId: String
        var messageId: String
        /// Who wrote it (the authenticated author of the cached row) — never the report's subject.
        var authorId: String
        /// The server that channel belongs to on this device — never the report's server.
        var serverId: String
        /// The message as this device decrypted it.
        var content: String
    }

    enum Quote: Equatable { case unchecked, matches, differs }

    var target: Target?
    /// The reporter named a different person than the one who wrote the message.
    var subjectMismatch = false
    /// The reporter named a different server than the one the message is in.
    var serverMismatch = false
    var quote: Quote = .unchecked

    var hasMismatch: Bool { subjectMismatch || serverMismatch }
    /// The message may be removed: it is on this device and the report does not contradict it.
    var mayRemove: Bool { target != nil && !hasMismatch }
    /// Its author may be kicked or banned from its server straight from the card.
    var mayModerate: Bool { target != nil && !hasMismatch }

    var warnings: [String] {
        var out: [String] = []
        if subjectMismatch { out.append("The reporter named a different person than the one who wrote this message.") }
        if serverMismatch { out.append("The reporter named a different server than the one this message is in.") }
        return out
    }

    /// A cached row as the resolution needs it.
    struct Row: Equatable {
        var authorId: String?
        var content: String?
        var isDeleted = false
        var isCoreRow = false
    }

    /// Resolve a report against this device's own data. Pure: `cached` is the row this device
    /// holds under (`channelId`, `messageId`), `channelServer` maps the channels this device
    /// knows to their servers, `me` is this account (its own messages are never a target).
    static func resolve(subjectUserId: String?, serverId: String?, channelId: String?, messageId: String?, excerpt: String?,
                        cached: Row?, channelServer: [String: String], me: String?) -> ReportResolution {
        var out = ReportResolution()
        guard let channelId, let messageId, !channelId.isEmpty, !messageId.isEmpty,
              let cached, !cached.isDeleted, !cached.isCoreRow,
              let author = cached.authorId, !author.isEmpty, author != "__me__", author != me,
              let realServer = channelServer[channelId], !realServer.isEmpty else { return out }
        out.target = Target(channelId: channelId, messageId: messageId, authorId: author, serverId: realServer, content: cached.content ?? "")
        if let subjectUserId, !subjectUserId.isEmpty, subjectUserId != author { out.subjectMismatch = true }
        if let serverId, !serverId.isEmpty, serverId != realServer { out.serverMismatch = true }
        out.quote = compare(excerpt: excerpt, local: cached.content)
        return out
    }

    /// How the quote compares with this device's own copy.
    static func compare(excerpt: String?, local: String?) -> Quote {
        guard let local, let excerpt, !excerpt.isEmpty else { return .unchecked }
        // The reporter's app quotes the text it showed (an attachment's caption, say) or the
        // whole body; the core cuts a long quote at a byte limit.
        let shown = ChatTags.parse(local).text
        for candidate in [local, shown] where !candidate.isEmpty {
            if excerpt == candidate { return .matches }
            if excerpt.count >= 512, candidate.hasPrefix(excerpt) { return .matches }
        }
        return .differs
    }

    static func quoteCaption(_ quote: Quote) -> String {
        switch quote {
        case .unchecked: return "This is what the reporter says was written. Skwod can't prove who wrote it."
        case .matches: return "Matches the message on this device."
        case .differs: return "Differs from the message on this device."
        }
    }
}

/// A report plus what this device could confirm about it.
struct ReportItem: Identifiable, Equatable {
    let report: AbuseReport
    var resolution = ReportResolution()
    var id: String { report.reportId + "|" + report.reporterUserId }
}

@MainActor
extension AppState {
    /// Re-read the reports sealed to this account from the cache (they arrive with the mailbox).
    func refreshReports() async {
        guard let client else { reports = []; return }
        let fresh = await client.receivedReports()
        if fresh != reports {
            let grew = fresh.count > reports.count
            reports = fresh
            NotificationCenter.default.post(name: .skwodAccountChanged, object: nil)
            if grew, !appActive {
                realtime.notify(title: "New report", body: "Someone in your skwod sent you a report. Open Skwod to review it.",
                                privacy: .fixed, thread: "reports", id: "reports")
            }
        }
    }

    /// The channels this device knows, each with the server it belongs to — from the app's own
    /// space list (and each server's feed channel), never from a report.
    var channelServers: [String: String] {
        var out: [String: String] = [:]
        for s in chatModel?.spaces ?? [] where !s.channelId.isEmpty && !s.serverId.isEmpty { out[s.channelId] = s.serverId }
        for (serverId, channelId) in chatModel?.feedChannels ?? [:] where out[channelId] == nil { out[channelId] = serverId }
        return out
    }

    /// The report with what this device can confirm about it.
    func reportItem(_ r: AbuseReport) async -> ReportItem {
        var row: ReportResolution.Row?
        if let client, let channelId = r.channelId, let messageId = r.messageId,
           let local = await client.cachedMessage(scope: "channel:\(channelId)", messageId: messageId) {
            row = ReportResolution.Row(authorId: local.authorId, content: local.content, isDeleted: local.isDeleted,
                                       isCoreRow: local.isSystem || local.isUndecryptable)
        }
        let resolution = ReportResolution.resolve(subjectUserId: r.subjectUserId, serverId: r.serverId, channelId: r.channelId,
                                                  messageId: r.messageId, excerpt: r.excerpt, cached: row,
                                                  channelServer: channelServers, me: session?.userId)
        return ReportItem(report: r, resolution: resolution)
    }

    func dismiss(_ item: ReportItem) async {
        await client?.dismissReport(reportId: item.report.reportId, reporterUserId: item.report.reporterUserId)
        await refreshReports()
    }

    /// Delete the message a report points at — the one THIS device confirmed. Returns a
    /// sentence when it could not.
    func removeReportedMessage(_ item: ReportItem) async -> String? {
        guard let client else { return "Not connected — try again in a moment." }
        guard item.resolution.mayRemove, let target = item.resolution.target else {
            return "Skwod couldn't confirm which message this report is about, so nothing was removed."
        }
        do {
            try await client.deleteChannelMessage(channelId: target.channelId, messageId: target.messageId)
            NotificationCenter.default.post(name: .skwodChannelChanged, object: target.channelId)
            await refreshReports()
            return nil
        } catch {
            return coreErrorText(error, fallback: "Couldn't remove the message — you need to be able to manage messages there.")
        }
    }

    /// Kick or ban `userId` from `serverId` — a pair the caller got from this device's own
    /// data or from the owner's explicit choice, never from a report's fields.
    func moderate(ban: Bool, userId: String, serverId: String, reason: String) async -> String? {
        guard let client else { return "Not connected — try again in a moment." }
        guard !userId.isEmpty, !serverId.isEmpty, userId != session?.userId else { return "Pick a person and a server first." }
        do {
            if ban {
                try await client.banMember(serverId: serverId, userId: userId, reason: reason)
            } else {
                try await moderationDelete("api/servers/\(serverId)/members/\(userId)")
            }
        } catch {
            return coreErrorText(error, fallback: ban ? "Couldn't ban — you need Ban Members there." : "Couldn't kick — only the server's owner or a moderator can.")
        }
        // A removed member must not be able to read what is sent next: rotate every channel's
        // sender key on that server now.
        if let me = session?.userId { _ = try? await client.syncServerMembership(serverId: serverId, myUserId: me) }
        NotificationCenter.default.post(name: .skwodServerChanged, object: serverId)
        return nil
    }

    private struct ModerationError: Error {}

    private func moderationDelete(_ path: String) async throws {
        guard let token = session?.token, let base = URL(string: serverURL), !serverURL.isEmpty else { throw ModerationError() }
        var req = URLRequest(url: base.appendingPathComponent(path))
        req.httpMethod = "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let code = ((try? await RawSink.data(for: req))?.1 as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw ModerationError() }
    }
}

struct ReportsInboxView: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var items: [ReportItem] = []
    @State private var names: [String: String] = [:]
    @State private var message = ""
    @State private var busy = false
    @State private var confirming: Pending?
    @State private var choosing: ReportItem?

    /// An action waiting for the owner's yes. Its target is spelled out — a person and a
    /// server this device resolved, or the owner picked — never taken from the report.
    private struct Pending: Identifiable {
        enum Kind { case remove, kick, ban, dismiss }
        let kind: Kind
        let item: ReportItem
        var userId = ""
        var serverId = ""
        let id = UUID()
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Image(systemName: "flag.fill").font(.system(size: 36)).foregroundStyle(.skAccent)
                Text("Reports").font(.title2.bold()).foregroundStyle(.white).accessibilityAddTraits(.isHeader)
                Text("Sent to you because you run this skwod. Notes and quoted messages were encrypted to your devices; the server never saw them.")
                    .font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                if items.isEmpty {
                    Text("No reports.").font(.subheadline).foregroundStyle(.white.opacity(0.6)).padding(.top, 8)
                        .accessibilityIdentifier("reports.empty")
                }
                if !message.isEmpty {
                    Label(message, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                }
                ForEach(items.reversed()) { item in card(item) }
                Button("Done") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
            }
            .padding(24).frame(maxWidth: 520).frame(maxWidth: .infinity)
        }
        .frame(minWidth: 380, minHeight: 320)
        .background(SkwodBackground())
        .task { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .skwodAccountChanged)) { _ in Task { await load() } }
        .confirmationDialog(confirmTitle, isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
                            titleVisibility: .visible) {
            if let c = confirming {
                Button(confirmButton(c.kind), role: c.kind == .dismiss ? nil : .destructive) { Task { await run(c) } }
            }
        } message: {
            Text(confirmMessage)
        }
        .sheet(item: $choosing) { item in
            ModerationChoiceSheet(hint: hint(item.report), names: names) { ban, userId, serverId in
                confirming = Pending(kind: ban ? .ban : .kick, item: item, userId: userId, serverId: serverId)
            }
        }
    }

    private func name(_ userId: String?) -> String {
        guard let userId, !userId.isEmpty else { return "someone" }
        return app.contacts.display(userId, claimedName: names[userId]).text
    }

    private func serverName(_ serverId: String?) -> String {
        guard let serverId, !serverId.isEmpty else { return "a server" }
        return app.chatModel?.spaces.first(where: { $0.serverId == serverId })?.name ?? "a server this device doesn't know"
    }

    /// What the reporter claims, as a hint beside the owner's own choice.
    private func hint(_ r: AbuseReport) -> String? {
        guard r.subjectUserId != nil || r.serverId != nil else { return nil }
        return "The reporter says: \(name(r.subjectUserId)) in \(serverName(r.serverId))"
    }

    private func card(_ item: ReportItem) -> some View {
        let r = item.report
        let res = item.resolution
        return VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                Text("\(name(r.reporterUserId)) reported \(r.subjectUserId == nil ? "a message" : name(r.subjectUserId))")
                    .font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                Spacer(minLength: 8)
                Text(AccountDates.relative(r.receivedAt)).font(.caption2).foregroundStyle(.white.opacity(0.45))
            }
            Text(r.category).font(.caption2.weight(.semibold)).foregroundStyle(.black)
                .padding(.horizontal, 8).padding(.vertical, 3).background(.skAccent, in: Capsule())
            if let note = r.note, !note.isEmpty {
                Text("Their note").font(.caption2).foregroundStyle(.white.opacity(0.5))
                Text(note).font(.subheadline).foregroundStyle(.white).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let target = res.target {
                // What this device itself holds — the thing any action here is about.
                Text("The message on this device").font(.caption2).foregroundStyle(.white.opacity(0.5))
                quoteBlock(target.content)
                Text("Written by \(name(target.authorId)) in \(serverName(target.serverId))")
                    .font(.caption2).foregroundStyle(.white.opacity(0.6))
                    .accessibilityIdentifier("reports.resolved")
            }
            if let excerpt = r.excerpt, !excerpt.isEmpty {
                Text("Quoted message").font(.caption2).foregroundStyle(.white.opacity(0.5))
                quoteBlock(excerpt)
                Text(ReportResolution.quoteCaption(res.quote)).font(.caption2)
                    .foregroundStyle(res.quote == .matches ? Color.green : (res.quote == .differs ? .orange : .white.opacity(0.5)))
            }
            ForEach(res.warnings, id: \.self) { warning in
                Label(warning, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("reports.mismatch")
            }
            HStack(spacing: 8) {
                if res.mayRemove {
                    Button("Remove message") { confirming = Pending(kind: .remove, item: item) }.tint(.red)
                }
                if res.mayModerate, let target = res.target {
                    Button("Kick \(name(target.authorId))") { confirming = Pending(kind: .kick, item: item, userId: target.authorId, serverId: target.serverId) }.tint(.red)
                    Button("Ban \(name(target.authorId))") { confirming = Pending(kind: .ban, item: item, userId: target.authorId, serverId: target.serverId) }.tint(.red)
                } else if res.target == nil {
                    // Nothing to confirm against: the owner chooses who and where, by hand.
                    Button("Kick or ban someone…") { choosing = item }.tint(.red)
                }
                Spacer(minLength: 0)
                Button("Dismiss") { confirming = Pending(kind: .dismiss, item: item) }.tint(.skAccent)
            }
            .buttonStyle(.glass).controlSize(.small).disabled(busy)
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
        .accessibilityIdentifier("reports.card")
    }

    private func quoteBlock(_ body: String) -> some View {
        let text = ChatTags.parse(body).text
        return Text(text.isEmpty ? "(an attachment)" : text)
            .font(.subheadline).foregroundStyle(.white.opacity(0.9)).textSelection(.enabled)
            .padding(.leading, 10)
            .overlay(Rectangle().fill(.white.opacity(0.3)).frame(width: 3), alignment: .leading)
            .fixedSize(horizontal: false, vertical: true)
    }

    private var confirmTitle: String {
        guard let c = confirming else { return "" }
        switch c.kind {
        case .remove: return "Remove this message?"
        case .kick: return "Kick \(name(c.userId)) from \(serverName(c.serverId))?"
        case .ban: return "Ban \(name(c.userId)) from \(serverName(c.serverId))?"
        case .dismiss: return "Dismiss this report?"
        }
    }

    private var confirmMessage: String {
        guard let c = confirming else { return "" }
        switch c.kind {
        case .remove: return "It is deleted for everyone in the channel."
        case .kick: return "They are removed from the server and its keys are changed. They can come back with a new invite."
        case .ban: return "They are removed from the server and can't rejoin until you unban them."
        case .dismiss: return "It is removed from this device's list. Nothing else changes."
        }
    }

    private func confirmButton(_ kind: Pending.Kind) -> String {
        switch kind {
        case .remove: return "Remove message"
        case .kick: return "Kick"
        case .ban: return "Ban"
        case .dismiss: return "Dismiss"
        }
    }

    private func load() async {
        await app.refreshReports()
        var out: [ReportItem] = []
        for r in app.reports { out.append(await app.reportItem(r)) }
        items = out
        // Names as the servers list them — shown through the contact book's rules.
        guard let client = app.client else { return }
        for serverId in Set(app.chatModel?.spaces.map(\.serverId) ?? []) where !serverId.isEmpty && serverId != "demo" {
            for m in (try? await client.listMembers(serverId: serverId)) ?? [] { names[m.userId] = m.username }
        }
        for d in app.chatModel?.dms ?? [] where names[d.peerUserId] == nil { names[d.peerUserId] = d.name }
    }

    private func run(_ c: Pending) async {
        busy = true; message = ""; defer { busy = false }
        let problem: String?
        switch c.kind {
        case .dismiss: await app.dismiss(c.item); problem = nil
        case .remove: problem = await app.removeReportedMessage(c.item)
        case .kick, .ban:
            problem = await app.moderate(ban: c.kind == .ban, userId: c.userId, serverId: c.serverId, reason: "reported: \(c.item.report.category)")
        }
        if let problem { message = problem }
        await load()
    }
}

/// Kick or ban with no message to confirm against: the owner picks the server and the person
/// from this device's own lists. The report's claim is shown as a hint, never preselected.
private struct ModerationChoiceSheet: View {
    let hint: String?
    let names: [String: String]
    var onChoose: (_ ban: Bool, _ userId: String, _ serverId: String) -> Void
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var serverId = ""
    @State private var userId = ""
    @State private var members: [MemberInfo] = []

    private var servers: [ServerGroup] { (app.chatModel?.serverGroups ?? []).filter { !$0.serverId.isEmpty && $0.serverId != "demo" } }

    var body: some View {
        VStack(spacing: 14) {
            Text("Kick or ban someone").font(.title3.bold()).foregroundStyle(.white).accessibilityAddTraits(.isHeader)
            Text("This report doesn't point at a message this device can check, so choose the server and the person yourself.")
                .font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            if let hint {
                Text(hint).font(.caption).foregroundStyle(.orange.opacity(0.9)).multilineTextAlignment(.center)
            }
            Picker("Server", selection: $serverId) {
                Text("Choose a server").tag("")
                ForEach(servers) { Text($0.name).tag($0.serverId) }
            }
            Picker("Person", selection: $userId) {
                Text("Choose a person").tag("")
                ForEach(members, id: \.userId) { m in
                    Text(app.contacts.display(m.userId, claimedName: m.username).text).tag(m.userId)
                }
            }
            .disabled(serverId.isEmpty)
            HStack(spacing: 10) {
                Button("Kick…", role: .destructive) { dismiss(); onChoose(false, userId, serverId) }
                Button("Ban…", role: .destructive) { dismiss(); onChoose(true, userId, serverId) }
            }
            .buttonStyle(.glass).tint(.red).disabled(serverId.isEmpty || userId.isEmpty)
            Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(24).frame(minWidth: 340, maxWidth: 440)
        .background(SkwodBackground())
        .task(id: serverId) {
            userId = ""
            members = []
            guard !serverId.isEmpty, let client = app.client else { return }
            let me = app.session?.userId
            members = ((try? await client.listMembers(serverId: serverId)) ?? []).filter { $0.userId != me }
        }
    }
}
