import SwiftUI

/// Someone who is not (yet) accepted into a server and needs a member's decision.
struct WaitingMember: Identifiable, Hashable {
    enum Source: Hashable {
        /// Asked to join with an invite that needs approval. The server has not admitted them.
        case request
        /// The server already lists them as a member — they used an auto-join link, or the server
        /// simply added them — but nobody this device trusts has let them in. This device gives
        /// them no keys until someone does.
        case held
    }
    let userId: String
    /// The name the SERVER gives this account. It is a claim until `trust` says it checks out.
    let username: String
    let source: Source
    /// Whether that name really belongs to this account (see `WaitingTrust`).
    var trust: WaitingTrust.Verdict = .unchecked
    /// The account's key fingerprint as the directory shows it right now
    /// (`SkwodClient.peekAccountFingerprint` — a read that never pins): independent of any name,
    /// the thing to read out to the person if in doubt.
    var fingerprint: String? = nil
    /// Whether this device has already pinned that fingerprint (by an explicit action: letting
    /// them in, messaging them, verifying them). Merely being listed never pins, so a newcomer's
    /// fingerprint is shown as "unverified".
    var fingerprintPinned = false
    /// Nobody the user has history with: no conversation with this account, never verified.
    var isNew = false
    var id: String { userId }

    /// "Let in" is offered only for an entry whose name checked out.
    var canLetIn: Bool { trust == .ok }
    /// A short, readable form of the fingerprint: the first two blocks.
    var shortFingerprint: String? {
        guard let f = fingerprint, f.count >= 10 else { return nil }
        return "\(f.prefix(5)) \(f.dropFirst(5).prefix(5))"
    }
}

// `WaitingTrust` (is a waiting member's name trustworthy enough to act on?) is in `NameTrust.swift`.

/// Who is waiting to join each server: join requests that need approval plus members the core is
/// holding. This replaces the alert that used to pop up per person; it feeds the "Waiting to
/// join" section of the members view and the badge on the members button.
@MainActor
final class WaitingRoom: ObservableObject {
    @Published private(set) var byServer: [String: [WaitingMember]] = [:]
    /// A decision that did not go through, shown under the list.
    @Published var problem: String?
    /// People with a decision in flight (their buttons are disabled).
    @Published private(set) var busy: Set<String> = []

    private weak var app: AppState?
    func bind(_ app: AppState) { self.app = app }

    func waiting(in serverId: String) -> [WaitingMember] { byServer[serverId] ?? [] }
    func count(in serverId: String) -> Int { byServer[serverId]?.count ?? 0 }
    var total: Int { byServer.values.reduce(0) { $0 + $1.count } }

    /// Forget everything (workspace switch / sign-out).
    func reset() {
        byServer = [:]; problem = nil; busy = []
        for task in handOffs.values { task.cancel() }
        handOffs = [:]
    }

    /// Re-read who is waiting in `serverId` from the core (held members) and the server (join
    /// requests — only people allowed to approve them get a list; for everyone else it is empty).
    func refresh(serverId: String) async {
        guard let app, let client = app.client, !serverId.isEmpty, serverId != "demo" else { return }
        var held = await client.heldMembers(serverId: serverId)
        let requests = (try? await client.listJoinRequests(serverId: serverId)) ?? []
        guard !held.isEmpty || !requests.isEmpty else {
            if byServer[serverId] != nil { byServer[serverId] = nil }
            return
        }
        // Only someone the server STILL lists is waiting. A held user who was removed
        // (declined, kicked, left) is not; without the list we cannot tell, so change nothing.
        guard let members = try? await client.listMembers(serverId: serverId) else { return }
        var names: [String: String] = [:]
        for m in members { names[m.userId] = m.username }
        held = held.filter { names[$0] != nil }

        var out = requests.map { WaitingMember(userId: $0.userId, username: $0.username, source: .request) }
        let requested = Set(out.map(\.userId))
        let me = app.session?.userId
        for id in held.sorted() where !requested.contains(id) && id != me {
            out.append(WaitingMember(userId: id, username: names[id] ?? "", source: .held))
        }
        // Who the user already knows by name: the server's ACCEPTED members and DM contacts.
        let waitingIds = Set(out.map(\.userId))
        let known = knownPeople(members: members, excluding: waitingIds)
        for i in out.indices { out[i] = await checked(out[i], client: client, known: known) }
        if byServer[serverId] != out { byServer[serverId] = out.isEmpty ? nil : out }
    }

    /// The verdict for ONE person asking to join, for the other screens that can approve a
    /// request (invites, the host panel): the same check "Waiting to join" makes — never an
    /// approval on the server's name alone.
    func verdict(serverId: String, userId: String, username: String) async -> WaitingTrust.Verdict {
        guard let app, let client = app.client, let asked = app.bindTicket(),
              let members = try? await client.listMembers(serverId: serverId) else { return .unchecked }
        let requests = (try? await client.listJoinRequests(serverId: serverId)) ?? []
        let waitingIds = Set(requests.map(\.userId)).union(await client.heldMembers(serverId: serverId)).union([userId])
        guard app.holds(asked) else { return .unchecked }
        let known = knownPeople(members: members, excluding: waitingIds)
        let checked = await checked(WaitingMember(userId: userId, username: username, source: .request), client: client, known: known)
        return app.holds(asked) ? checked.trust : .unchecked
    }

    /// Why "Let in" was refused for a verdict, in the words "Waiting to join" uses.
    static func refusal(_ verdict: WaitingTrust.Verdict) -> String? {
        var w = WaitingMember(userId: "", username: "", source: .request)
        w.trust = verdict
        return WaitingToJoinSection.warning(for: w)?.text
    }

    /// Accounts the user already knows under a name: accepted members of the server (everyone it
    /// lists who is not waiting) and the people they have DMs with.
    private func knownPeople(members: [MemberInfo], excluding waiting: Set<String>) -> [(userId: String, name: String)] {
        var known = members.filter { !waiting.contains($0.userId) }.map { (userId: $0.userId, name: $0.username) }
        known += (app?.chatModel?.dms ?? []).map { (userId: $0.peerUserId, name: $0.name) }
        // …and everyone in the contact book the user pinned or verified, under the name they
        // know them by.
        known += (app?.contacts.entries ?? [:]).filter { $0.value.level >= .known }.map { (userId: $0.key, name: $0.value.name) }
        return known
    }

    /// Fill in the trust verdict, fingerprint and "new" marker for one entry.
    private func checked(_ entry: WaitingMember, client: SkwodClient, known: [(userId: String, name: String)]) async -> WaitingMember {
        var w = entry
        // "New" = nobody the user has history with: no conversation with this account, and
        // never verified. (An existing friend joining one more server is not marked.)
        let hasConversation = app?.chatModel?.dms.contains(where: { $0.peerUserId == w.userId }) ?? false
        let verified = await client.contactStatus(userId: w.userId).verified
        w.isNew = !hasConversation && !verified
        // A read that never pins: being LISTED must not make this device trust a key. Pinning
        // happens on explicit actions only (Let in, starting a DM, verifying).
        if let peek = try? await client.peekAccountFingerprint(userId: w.userId) {
            w.fingerprint = peek.fingerprint
            w.fingerprintPinned = peek.pinned
        }
        // The directory's answer for the NAME: this account, another one, nobody, or no answer.
        var lookup: String?? = nil
        if !w.username.isEmpty {
            do { lookup = .some(try await client.findUser(username: w.username).userId) }
            catch CoreError.Engine(let detail) where detail.contains("404") || detail.contains("user not found") { lookup = .some(nil) }
            catch { lookup = nil }
        }
        w.trust = WaitingTrust.assess(userId: w.userId, username: w.username, lookup: lookup, known: known)
        return w
    }

    /// "Let in": this is the explicit decision the core signs as a member approval. For a join
    /// request the server admits them first; then they are provisioned (space + channel keys)
    /// when this device can.
    func letIn(_ w: WaitingMember, serverId: String) async {
        guard let client = app?.client, busy.insert(w.userId).inserted else { return }
        defer { busy.remove(w.userId) }
        problem = nil
        // The decision is about to be SIGNED: check the label again, now, rather than trusting
        // what was on screen a moment ago. Anything but a clean match stops here.
        guard let members = try? await client.listMembers(serverId: serverId) else {
            problem = "Couldn't check \(w.username) just now, so nothing was signed. Try again."
            return
        }
        let waitingIds = Set(waiting(in: serverId).map(\.userId)).union([w.userId])
        let fresh = await checked(w, client: client, known: knownPeople(members: members, excluding: waitingIds))
        guard fresh.canLetIn else {
            problem = "Not let in: the name \"\(w.username)\" does not check out for this account."
            await refresh(serverId: serverId)
            return
        }
        do {
            switch w.source {
            case .request:
                try await client.approveJoinRequest(serverId: serverId, userId: w.userId)
                // They are a member now; without the server's keys they still see nothing.
                // Hand the keys over — and if that does not go through, SAY so and keep trying.
                await handOver(serverId: serverId, userId: w.userId, username: w.username)
            case .held:
                try await client.approveMember(serverId: serverId, userId: w.userId)
            }
            // "Let in" is the user vouching for this account under this name, on this device —
            // in the contact book of the workspace it was done in (not one switched to since).
            if app?.client === client { app?.contacts.note(w.userId, name: w.username, level: .known) }
            // Hand them the channel keys now rather than on the next periodic sync.
            if let me = app?.session?.userId {
                _ = try? await client.syncServerMembership(serverId: serverId, myUserId: me)
            }
        } catch {
            problem = "Couldn't let \(w.username) in. \(describe(error))"
        }
        await refresh(serverId: serverId)
    }

    /// "Decline": a join request is denied; a held member is removed from the server (which
    /// needs the right to kick — otherwise they simply stay held, with no keys from this device).
    func decline(_ w: WaitingMember, serverId: String) async {
        guard let app, let client = app.client, busy.insert(w.userId).inserted else { return }
        defer { busy.remove(w.userId) }
        problem = nil
        switch w.source {
        case .request:
            do { try await client.denyJoinRequest(serverId: serverId, userId: w.userId) }
            catch { problem = "Couldn't decline \(w.username). \(describe(error))" }
        case .held:
            var removed = false
            if let token = app.session?.token, let base = URL(string: app.serverURL) {
                var req = URLRequest(url: base.appendingPathComponent("api/servers/\(serverId)/members/\(w.userId)"))
                req.httpMethod = "DELETE"
                req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
                removed = ((try? await URLSession.shared.data(for: req))?.1 as? HTTPURLResponse)?.statusCode == 200
            }
            if removed, let me = app.session?.userId {
                _ = try? await client.syncServerMembership(serverId: serverId, myUserId: me)
            } else {
                problem = "\(w.username) is still listed by the server — removing them needs the owner or a moderator. They get no keys from this device either way."
            }
        }
        await refresh(serverId: serverId)
    }

    // MARK: Key hand-off

    /// People who were let in but whose key hand-off has not gone through: user id → the retry.
    private var handOffs: [String: Task<Void, Never>] = [:]

    /// One attempt to provision `userId` (space key + channel keys). nil = done; otherwise why not.
    private func tryHandOver(serverId: String, userId: String, username: String) async -> String? {
        guard let client = app?.client else { return "not connected" }
        do {
            // The username lookup must resolve to the SAME account that was approved.
            let found = try await client.findUser(username: username)
            guard found.userId == userId else { return "the name no longer leads to this account" }
            try await client.provisionMember(serverId: serverId, userId: found.userId, deviceId: found.deviceId)
            return nil
        } catch {
            return coreErrorText(error, fallback: "the connection dropped")
        }
    }

    /// Hand the server's keys to someone just let in. A failure is shown under the list and
    /// retried with backoff (5 s, 15 s, 45 s, 2 min, 5 min) — it used to be swallowed, which
    /// left a member staring at an empty server with nobody the wiser. (Their own app also asks
    /// again, and this device answers such requests whenever it syncs its mailbox.)
    func handOver(serverId: String, userId: String, username: String) async {
        handOffs[userId]?.cancel()
        handOffs[userId] = nil
        guard let why = await tryHandOver(serverId: serverId, userId: userId, username: username) else { return }
        let prefix = "\(username) was let in, but their keys couldn't be handed over yet"
        problem = "\(prefix) (\(why)). Skwod will keep trying."
        handOffs[userId] = Task { [weak self] in
            for delay in [5, 15, 45, 120, 300] {
                try? await Task.sleep(for: .seconds(delay))
                guard !Task.isCancelled, let self else { return }
                if let why = await self.tryHandOver(serverId: serverId, userId: userId, username: username) {
                    self.problem = "\(prefix) (\(why)). Skwod will keep trying."
                    continue
                }
                if self.problem?.hasPrefix(prefix) == true { self.problem = nil }
                if let me = self.app?.session?.userId {
                    _ = try? await self.app?.client?.syncServerMembership(serverId: serverId, myUserId: me)
                }
                self.handOffs[userId] = nil
                return
            }
            guard let self, !Task.isCancelled else { return }
            self.problem = "\(prefix). They will get them the next time both of you have Skwod open."
            self.handOffs[userId] = nil
        }
    }

    private func describe(_ error: Error) -> String {
        if case CoreError.Engine(let detail) = error, detail.contains("403") { return "You don't have permission." }
        return "Check your connection and try again."
    }
}

/// The "Waiting to join" block at the top of a server's member list. Renders nothing when
/// nobody is waiting.
struct WaitingToJoinSection: View {
    let serverId: String
    /// Narrow layout for the macOS members rail; the iOS sheet uses the roomier one.
    var compact = false
    @EnvironmentObject private var app: AppState
    @ObservedObject var room: WaitingRoom

    var body: some View {
        let people = room.waiting(in: serverId)
        if !people.isEmpty {
            VStack(alignment: .leading, spacing: compact ? 6 : 10) {
                HStack(spacing: 6) {
                    Image(systemName: "person.crop.circle.badge.clock").foregroundStyle(.orange)
                    Text("Waiting to join — \(people.count)")
                        .font(.system(size: 12, weight: .semibold)).foregroundStyle(.orange).textCase(.uppercase)
                }
                Text("Let someone in only if you know them and expected them. Until then they get none of this server's keys from you.")
                    .font(.system(size: 11)).foregroundStyle(.white.opacity(0.55))
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(people) { w in row(w) }
                if let problem = room.problem {
                    Text(problem).font(.system(size: 11)).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(compact ? 10 : 14)
            .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(.orange.opacity(0.3), lineWidth: 1))
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Waiting to join")
        }
    }

    @ViewBuilder private func row(_ w: WaitingMember) -> some View {
        let busy = room.busy.contains(w.userId)
        let trusted = w.trust == .ok
        // An unverified label is never shown as a plain name.
        let title = trusted ? w.username : (w.username.isEmpty ? "Unnamed account" : "“\(w.username)”")
        let who = VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 5) {
                Text(title).font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(trusted ? Color.white : .orange).lineLimit(1)
                // Even a name that checks out is only what the server says, until the user
                // lets them in (or already knows them).
                if trusted { TrustBadge(badge: app.contacts.display(w.userId, claimedName: w.username).badge, compact: true) }
                if w.isNew {
                    Text("NEW").font(.system(size: 8.5, weight: .bold)).foregroundStyle(.black)
                        .padding(.horizontal, 4).padding(.vertical, 1).background(.white.opacity(0.75), in: Capsule())
                        .accessibilityLabel("New to you")
                }
            }
            Text(w.source == .request ? "Asked to join" : "Added by the server")
                .font(.system(size: 10.5)).foregroundStyle(.white.opacity(0.5)).lineLimit(1)
        }
        // Its own full-width line: these identify the ACCOUNT whatever it is called.
        // A fingerprint this device has not pinned is only what the server says today.
        let keyNote = w.shortFingerprint == nil ? "" : (w.fingerprintPinned ? "" : " (unverified)")
        let identity = Text("ID \(w.userId.prefix(8)) · key \(w.shortFingerprint ?? "unknown")\(keyNote)")
            .font(.system(size: 10, design: .monospaced)).foregroundStyle(.white.opacity(0.55))
            .lineLimit(1).minimumScaleFactor(0.8)
            .accessibilityLabel("Account \(String(w.userId.prefix(8))), key fingerprint \(w.shortFingerprint ?? "unknown")\(w.fingerprintPinned ? "" : ", unverified")")
        let buttons = HStack(spacing: 8) {
            Button("Let in") { Task { await room.letIn(w, serverId: serverId) } }
                .buttonStyle(DecisionButtonStyle(primary: true))
                .disabled(!w.canLetIn)
                .accessibilityLabel("Let in \(w.username)")
            Button("Decline") { Task { await room.decline(w, serverId: serverId) } }
                .buttonStyle(DecisionButtonStyle())
                .accessibilityLabel("Decline \(w.username)")
            if busy { ProgressView().controlSize(.small) }
        }
        .disabled(busy)
        VStack(alignment: .leading, spacing: 6) {
            if compact {
                HStack(spacing: 8) { AvatarImage(key: nil, name: trusted ? w.username : "?", size: 26); who }
                identity
                buttons
            } else {
                HStack(spacing: 10) {
                    AvatarImage(key: nil, name: trusted ? w.username : "?", size: 32)
                    who
                    Spacer(minLength: 8)
                    buttons
                }
                identity
            }
            if let warning = Self.warning(for: w) {
                Label(warning.text, systemImage: warning.strong ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 11, weight: warning.strong ? .semibold : .regular))
                    .foregroundStyle(warning.strong ? Color.red : .orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, 2)
    }

    /// What to say under an entry whose name did not check out.
    static func warning(for w: WaitingMember) -> (text: String, strong: Bool)? {
        switch w.trust {
        case .ok: return nil
        case .unchecked:
            return ("Couldn't check this name against the account yet. Let in is off until it has been checked.", false)
        case .nameMismatch:
            return ("This name doesn't match this account: looking the name up does not lead to it. Don't let them in on the strength of the name.", false)
        case .unusualCharacters:
            return ("This name contains unusual or invisible characters, which a Skwod username cannot have. It may be made to look like someone else's name. Let in is off.", true)
        case .impersonation:
            return ("Possible impersonation. You already know someone whose name looks like this one, and this is a DIFFERENT account. Do not let it in.", true)
        }
    }
}

/// A small count badge (e.g. on the members button when people are waiting to join).
struct CountBadge: View {
    let count: Int
    var body: some View {
        if count > 0 {
            Text(count > 9 ? "9+" : "\(count)")
                .font(.system(size: 9, weight: .bold)).foregroundStyle(.black)
                .padding(.horizontal, 4).frame(minWidth: 15, minHeight: 15)
                .background(.orange, in: Capsule())
                .accessibilityLabel("\(count) waiting to join")
        }
    }
}

/// The buttons of a security decision ("Let in" / "Decline", "View safety number" / "Accept &
/// send"). Solid rather than glass on purpose: these must stay legible when the window is not
/// frontmost and on top of the amber notice background.
struct DecisionButtonStyle: ButtonStyle {
    var primary = false
    @Environment(\.isEnabled) private var enabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12, weight: .semibold))
            .foregroundStyle(primary ? Color.black : Color.white)
            .padding(.horizontal, 12).padding(.vertical, 6)
            .background(primary ? Color.white : Color.white.opacity(0.14), in: Capsule())
            .overlay(Capsule().strokeBorder(.white.opacity(primary ? 0 : 0.25), lineWidth: 1))
            .opacity(!enabled ? 0.45 : (configuration.isPressed ? 0.7 : 1))
            .contentShape(Capsule())
    }
}
