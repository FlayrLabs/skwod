import SwiftUI

/// Host-side membership control for a space (server). Three ways in, per the security model:
/// - **One-time link** (token): auto-joins one person, single-use.
/// - **Reserve a username**: auto-joins only that exact name.
/// - **Shareable code**: anyone with it lands in the approval queue; the host approves each.
///
/// Below the invite tools is the live approval queue (pending join requests).
struct SecureJoinView: View {
    let space: RealSpace
    @EnvironmentObject private var app: AppState

    @State private var generated: (kind: String, code: String)?
    @State private var reserveName = ""
    @State private var busy = false
    @State private var status = ""
    @State private var pending: [JoinRequest] = []
    @State private var invites: [InviteInfo] = []
    /// The skwod's p2p address (host key), once known — invite links are built on it.
    @State private var hostNodeId: String?
    @State private var showQR: String?

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Invite to \(space.name)").font(.title2.bold()).foregroundStyle(.white)

                    // No key-sharing here: approving a member auto-provisions the space key +
                    // channel keys to their device over an E2EE DM. The invite link is everything.
                    inviteToolsCard
                    activeInvitesCard
                    approvalQueueCard
                }
                .padding(24).frame(maxWidth: 520)
            }
        }
        .task { await loadNodeId(); await refreshQueue(); await refreshInvites() }
        .sheet(isPresented: Binding(get: { showQR != nil }, set: { if !$0 { showQR = nil } })) {
            DismissableSheet {
                ZStack {
                    SkwodBackground()
                    ShareableCodeCard(title: "Scan to join", value: showQR ?? "", qrSize: 240).padding(28)
                }
                .frame(minWidth: 360, minHeight: 440)
            }
        }
    }

    // MARK: cards

    private var inviteToolsCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionHeader(title: "Create an invite", systemImage: "person.badge.plus")

            Button { Task { await mint(kind: "token") } } label: {
                Label("One-time link (auto-join)", systemImage: "link").frame(maxWidth: .infinity)
            }.controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black).disabled(busy)

            HStack {
                Image(systemName: "at").foregroundStyle(.skAccent)
                TextField("reserve a username", text: $reserveName).textFieldStyle(.plain).foregroundStyle(.white)
                    #if os(iOS)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    #endif
                Button("Reserve") { Task { await mint(kind: "username") } }
                    .buttonStyle(.glass).tint(.skAccent).disabled(busy || reserveName.isEmpty)
            }.padding(10).glassEffect(.regular.interactive(), in: .capsule)

            Button { Task { await mint(kind: "code") } } label: {
                Label("Shareable code (needs your approval)", systemImage: "number").frame(maxWidth: .infinity)
            }.controlSize(.large).buttonStyle(.glass).disabled(busy)

            if let g = generated {
                VStack(alignment: .leading, spacing: 4) {
                    Text("\(kindLabel(g.kind)) — one tap or paste; the link says where the Skwod is too")
                        .font(.caption2).foregroundStyle(.white.opacity(0.5))
                    copyRow(inviteLink(g.code))
                }
            }
            if !status.isEmpty { Text(status).font(.caption).foregroundStyle(.skAccent) }
        }
        .padding(16).glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
    }

    private var activeInvitesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                SectionHeader(title: "Active invites", systemImage: "ticket")
                Spacer()
                Button { Task { await refreshInvites() } } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.glass)
            }
            let active = invites.filter { $0.status == "active" }
            if active.isEmpty {
                Text("No active invites. Create one above to let friends in.")
                    .font(.caption).foregroundStyle(.white.opacity(0.45))
            } else {
                Text("Revoke any code to cut off access immediately. To rotate, revoke then create a fresh one.")
                    .font(.caption).foregroundStyle(.white.opacity(0.55))
                ForEach(active, id: \.code) { inv in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(inv.code).font(.system(.footnote, design: .monospaced)).foregroundStyle(.white)
                                .lineLimit(1).truncationMode(.middle)
                            Text(subtitle(for: inv)).font(.caption2).foregroundStyle(.white.opacity(0.5))
                        }
                        Spacer()
                        CopyButton(inviteLink(inv.code), compact: true, sensitive: true)
                        Button("Revoke") { Task { await revoke(inv) } }
                            .buttonStyle(.glass).tint(.red).disabled(busy)
                    }
                    .padding(10).glassEffect(.regular, in: .rect(cornerRadius: 12, style: .continuous))
                }
            }
        }
        .padding(16).glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
    }

    /// "expires in 6d · 0/1 used" — the at-a-glance state of an invite.
    private func subtitle(for inv: InviteInfo) -> String {
        var parts: [String] = []
        if let exp = inv.expiresAt {
            let secs = Double(exp) / 1000 - Date().timeIntervalSince1970
            parts.append(secs <= 0 ? "expired" : "expires \(RelativeDateTimeFormatter().localizedString(fromTimeInterval: secs))")
        } else {
            parts.append("no expiry")
        }
        if let max = inv.maxUses {
            parts.append("\(inv.useCount)/\(max) used")
        } else if inv.useCount > 0 {
            parts.append("\(inv.useCount) used")
        }
        // People who signed up with this invite and are in no Skwod yet. At the host's limit
        // the server refuses further signups with it, so say what to do, not just a number.
        if inv.waitingFull {
            parts.append("\(inv.waiting) waiting — nobody else can join with this invite until you approve them or revoke it")
        } else if inv.waiting > 0 {
            parts.append("\(inv.waiting) waiting")
        }
        return parts.joined(separator: " · ")
    }

    private var approvalQueueCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                SectionHeader(title: "Pending requests", systemImage: "person.crop.circle.badge.questionmark")
                Spacer()
                Button { Task { await refreshQueue() } } label: { Image(systemName: "arrow.clockwise") }
                    .buttonStyle(.glass)
            }
            if pending.isEmpty {
                Text("No one waiting to join.").font(.caption).foregroundStyle(.white.opacity(0.45))
            } else {
                ForEach(pending, id: \.userId) { req in
                    HStack {
                        Circle().fill(Color.seeded(req.username).gradient).frame(width: 30, height: 30)
                            .overlay(Text(req.username.prefix(1).uppercased()).font(.caption.bold()).foregroundStyle(.white))
                        Text(req.username).foregroundStyle(.white)
                        Spacer()
                        Button { Task { await decide(req, approve: true) } } label: { Image(systemName: "checkmark") }
                            .buttonStyle(.glassProminent).tint(.green)
                        Button { Task { await decide(req, approve: false) } } label: { Image(systemName: "xmark") }
                            .buttonStyle(.glass).tint(.red)
                    }
                }
            }
        }
        .padding(16).glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
    }

    // MARK: actions

    private func mint(kind: String) async {
        guard let client = app.client else { return }
        busy = true; status = ""
        do {
            let code = try await client.inviteToSpace(
                serverId: space.serverId, kind: kind,
                reservedUsername: kind == "username" ? reserveName.lowercased() : nil)
            generated = (kind, code)
            status = kind == "code" ? "Share this link. You'll approve each person below." : "Share this link — whoever opens it is in."
            await refreshInvites()
        } catch { status = "Couldn't create the invite." }
        busy = false
    }

    private func refreshQueue() async {
        guard let client = app.client else { return }
        pending = (try? await client.listJoinRequests(serverId: space.serverId)) ?? []
    }

    private func refreshInvites() async {
        guard let client = app.client else { return }
        invites = (try? await client.listInvites(serverId: space.serverId)) ?? []
    }

    private func revoke(_ inv: InviteInfo) async {
        guard let client = app.client else { return }
        busy = true
        do { try await client.revokeInvite(code: inv.code); status = "Invite revoked." }
        catch { status = "Couldn't revoke that invite." }
        await refreshInvites()
        busy = false
    }

    private func decide(_ req: JoinRequest, approve: Bool) async {
        guard let client = app.client else { return }
        do {
            if approve {
                // The same name check as "Waiting to join": never let in on the server's name alone.
                let verdict = await app.waiting.verdict(serverId: space.serverId, userId: req.userId, username: req.username)
                guard WaitingTrust.mayLetIn(verdict) else {
                    status = WaitingRoom.refusal(verdict) ?? "This name could not be checked. Nobody was let in."
                    return
                }
                try await client.approveJoinRequest(serverId: space.serverId, userId: req.userId)
                // Provision the new member so they auto-discover the whole server: relay the space key
                // + every channel's sender key to their device over an E2EE DM. Resolve their device
                // from their username (the server never sees any of these keys).
                // A failed hand-off is shown in "Waiting to join" and retried (`WaitingRoom.handOver`).
                await app.waiting.handOver(serverId: space.serverId, userId: req.userId, username: req.username)
                if let problem = app.waiting.problem { status = problem }
            } else {
                try await client.denyJoinRequest(serverId: space.serverId, userId: req.userId)
            }
        } catch {
            status = approve ? "Couldn't approve \(req.username) — check your connection and try again."
                             : "Couldn't decline \(req.username) — check your connection and try again."
        }
        await refreshQueue()
    }

    // MARK: helpers

    /// The one-paste invite. For a skwod reached by key it is the share link
    /// `https://skwod.io/join#<node id>.<code>` (plus `&u=https://…` when the host also has a
    /// domain); for a classic https server whose
    /// p2p endpoint is off it is the older `<https address>#<code>`. The loopback URL this app
    /// talks through is never part of a link.
    private func inviteLink(_ code: String) -> String {
        if let nodeId = hostNodeId,
           let link = InviteLink.shareLink(nodeId: nodeId, joinCode: code, fallbackURL: httpsAddress) {
            return link
        }
        if let https = httpsAddress { return "\(https)#\(code)" }
        return code
    }

    /// The https address of this skwod, if it has one that other people can reach.
    private var httpsAddress: String? {
        guard let w = app.current else { return nil }
        if let fallback = w.fallbackURL { return fallback }
        return w.server.hasPrefix("https://") ? w.server : nil
    }

    /// Ask the server for its p2p address (members only). A workspace joined by key already
    /// knows it; the Mac that hosts it reads it from its own server; a VPS reports it here.
    private func loadNodeId() async {
        if let known = app.current?.nodeId { hostNodeId = known }
        guard let token = app.session?.token, let base = URL(string: app.serverURL), !app.serverURL.isEmpty else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/instance/p2p"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await RawSink.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj["enabled"] as? Bool == true, let id = obj["node_id"] as? String,
              (try? InviteLink.parse(InviteLink.p2pPrefix + id)) != nil else { return }
        // The host's home relay goes into the links handed out from here (`&r=`).
        RelayHintStore.set(obj["relay_url"] as? String, for: id)
        if hostNodeId == nil { hostNodeId = id }
    }

    private func kindLabel(_ kind: String) -> String {
        switch kind {
        case "token": return "One-time link"
        case "username": return "Reserved for @\(reserveName.lowercased())"
        default: return "Shareable code (approval required)"
        }
    }

    private func copyRow(_ value: String) -> some View {
        HStack(spacing: 8) {
            Text(value).font(.system(.footnote, design: .monospaced)).foregroundStyle(.white)
                .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
            Spacer()
            // Native share sheet — send the link straight to Messages/etc. Also how a host re-shares
            // the CURRENT address after a move (the link always carries the live address).
            ShareLink(item: value) {
                Image(systemName: "square.and.arrow.up").font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.8))
            }
            .labelStyle(.iconOnly)
            Button { showQR = value } label: {
                Image(systemName: "qrcode").font(.system(size: 14, weight: .semibold)).foregroundStyle(.white.opacity(0.8))
            }
            .buttonStyle(.plain)
            CopyButton(value, compact: true, sensitive: true)
        }
        .padding(10).glassEffect(.regular, in: .rect(cornerRadius: 12, style: .continuous))
    }
}
