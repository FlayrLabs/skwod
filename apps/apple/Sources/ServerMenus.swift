import SwiftUI

/// The SERVER menu (long-press on iOS, right-click / control-click on the Mac): what
/// `ServerMenuRule` allows for this account's role, wired to the existing sheets and to
/// `ChatModel.leaveServer` / `deleteServer`. Confirmations and sheets live in
/// `ServerActionsHost`, attached once per screen.
@MainActor
final class ServerActions: ObservableObject {
    @Published var invite: RealSpace?
    @Published var settings: ServerRef?
    @Published var rename: ServerRef?
    @Published var renameText = ""
    @Published var confirmLeave: ServerRef?
    @Published var confirmDelete: ServerRef?
    @Published var outcome: String?
    /// The Leave being confirmed is for a server with no owner pinned on this device.
    @Published var unverifiedLeave = false
}

struct ServerMenuItems: View {
    let group: ServerGroup
    @ObservedObject var chat: ChatModel
    @ObservedObject var actions: ServerActions
    @EnvironmentObject private var app: AppState
    @ObservedObject private var mutes = MuteCenter.shared

    private var ref: ServerRef { ServerRef(serverId: group.serverId, name: group.name) }
    private var channelKeys: [String] { group.channels.map { "channel:\($0.channelId)" } }

    var body: some View {
        let items = ServerMenuRule.items(role: chat.role(in: group.serverId), channelsKnown: !group.channels.isEmpty,
                                         ownerPinned: chat.ownership(of: group.serverId) != .unknown)
        ForEach(items, id: \.self) { item in
            switch item {
            case .mute: muteItems
            case .invite:
                Button { actions.invite = group.channels.first } label: { Label("Invite people", systemImage: "person.badge.plus") }
            case .rename:
                Button { actions.renameText = group.name; actions.rename = ref } label: { Label("Rename server…", systemImage: "pencil") }
            case .settings:
                Button { actions.settings = ref } label: { Label("Server settings", systemImage: "gearshape") }
            case .copyLink:
                if let link = skwodLink {
                    Button { Clipboard.copy(link, sensitive: true) } label: { Label("Copy Skwod link", systemImage: "link") }
                }
            case .leave:
                Button(role: .destructive) { actions.unverifiedLeave = false; actions.confirmLeave = ref } label: { Label("Leave server…", systemImage: "rectangle.portrait.and.arrow.right") }
            case .leaveUnverified:
                Button(role: .destructive) { actions.unverifiedLeave = true; actions.confirmLeave = ref } label: { Label("Leave server…", systemImage: "exclamationmark.triangle") }
            case .delete:
                Button(role: .destructive) { actions.confirmDelete = ref } label: { Label("Delete server…", systemImage: "trash") }
            }
        }
    }

    /// Muting a server mutes each of its channels (the build-45 mute store), all for the same time.
    @ViewBuilder private var muteItems: some View {
        let wid = MuteCenter.shared.currentWorkspaceId
        if !channelKeys.isEmpty, channelKeys.allSatisfy({ mutes.holds(workspaceId: wid, key: $0) }) {
            Button { channelKeys.forEach { mutes.unmute(workspaceId: wid, key: $0) } } label: { Label("Unmute server", systemImage: "bell") }
        } else {
            Menu {
                ForEach(MuteList.Duration.allCases, id: \.self) { d in
                    Button(d.label) { channelKeys.forEach { mutes.mute(workspaceId: wid, key: $0, for: d) } }
                }
            } label: { Label("Mute server", systemImage: "bell.slash") }
        }
    }

    /// The skwod's address (no code: it lets nobody in by itself) — servers have no address of
    /// their own; people join one with an invite.
    private var skwodLink: String? {
        guard let w = app.current else { return nil }
        if let nodeId = w.nodeId { return InviteLink.shareLink(nodeId: nodeId, joinCode: nil) }
        return w.server
    }
}

/// The sheets and confirmations behind `ServerMenuItems`.
struct ServerActionsHost: ViewModifier {
    @ObservedObject var actions: ServerActions
    @ObservedObject var chat: ChatModel

    func body(content: Content) -> some View {
        content
            .sheet(item: $actions.invite) { s in DismissableSheet { SecureJoinView(space: s) } }
            .sheet(item: $actions.settings) { srv in DismissableSheet { RolesSheet(server: srv) } }
            .modifier(ServerRenameAlert(target: $actions.rename, text: $actions.renameText, chat: chat) { actions.outcome = $0 })
            .confirmationDialog("Leave \(actions.confirmLeave?.name ?? "this server")?",
                                isPresented: Binding(get: { actions.confirmLeave != nil }, set: { if !$0 { actions.confirmLeave = nil } }),
                                titleVisibility: .visible) {
                Button("Leave server", role: .destructive) {
                    guard let srv = actions.confirmLeave else { return }
                    Task { actions.outcome = await chat.leaveServer(srv.serverId) }
                }
            } message: {
                Text(actions.unverifiedLeave
                     ? "This device can't confirm who owns this server. If it's yours, leaving can't be undone by you — delete it from a device that knows it's yours instead. Otherwise: you'll stop getting its messages, and this device forgets its keys."
                     : "You'll stop getting its messages, and this device forgets its keys. To come back you'll need a new invite.")
            }
            .confirmationDialog("Delete \(actions.confirmDelete?.name ?? "this server") for everyone?",
                                isPresented: Binding(get: { actions.confirmDelete != nil }, set: { if !$0 { actions.confirmDelete = nil } }),
                                titleVisibility: .visible) {
                Button("Delete server for everyone", role: .destructive) {
                    guard let srv = actions.confirmDelete else { return }
                    Task { actions.outcome = await chat.deleteServer(srv.serverId) }
                }
            } message: {
                Text("Every channel and message in it is deleted on the host, for every member. This can't be undone.")
            }
            .alert("Couldn't do that", isPresented: Binding(get: { actions.outcome != nil }, set: { if !$0 { actions.outcome = nil } })) {
                Button("OK", role: .cancel) { actions.outcome = nil }
            } message: { Text(actions.outcome ?? "") }
    }
}

/// "Rename server…": the name field, then `ChatModel.renameServer`. The new name is sealed under
/// the server's key (the host only ever stores ciphertext) and every member's sidebar picks it up.
struct ServerRenameAlert: ViewModifier {
    @Binding var target: ServerRef?
    @Binding var text: String
    @ObservedObject var chat: ChatModel
    /// A sentence when it failed.
    var onOutcome: (String) -> Void

    func body(content: Content) -> some View {
        content.alert("Rename \(target?.name ?? "server")",
                      isPresented: Binding(get: { target != nil }, set: { if !$0 { target = nil } })) {
            TextField("Server name", text: $text)
                .accessibilityIdentifier("server.renameField")
            Button("Save") {
                guard let srv = target else { return }
                let name = text
                Task { if let problem = await chat.renameServer(srv.serverId, to: name) { onOutcome(problem) } }
            }
            Button("Cancel", role: .cancel) { target = nil }
        } message: {
            Text("Everyone in the server sees the new name. It's end-to-end encrypted, like the old one.")
        }
    }
}

// (Here, not in Workspace.swift: that file is also compiled into the notification extension.)
extension Workspace {
    var dedupeEntry: WorkspaceDedupe.Entry {
        .init(id: id, userId: userId, server: server, nodeId: nodeId, instanceId: instanceId,
              pinnedKey: pinnedKey, signedOut: isSignedOut, tokenIssuedAt: tokenIssuedAt)
    }
}

/// Setting the skwod's name on the host (the instance owner; the core's device-signed
/// `setInstanceName`, op `instance-name`). The name is held to the same rule every member's app
/// applies to it (`SkwodNameRule`), so the owner never sets a name members would refuse.
enum InstanceNameSetter {
    /// Why `raw` cannot be the skwod's name, or nil when it can (empty = clear it).
    static func problem(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        guard let accepted = SkwodNameRule.acceptLearned(trimmed, otherNames: []) else {
            return "A skwod name uses letters, digits, spaces, - _ ' & and emoji, and can't look like an address or a reserved name."
        }
        return accepted == SkwodNameRule.collapseSpaces(trimmed) ? nil : "A skwod name is at most \(SkwodNameRule.maxLength) characters."
    }

    @MainActor static func set(_ raw: String, app: AppState) async -> String? {
        guard let client = app.client else { return "Not connected — try again in a moment." }
        if let problem = problem(raw) { return problem }
        let name = SkwodNameRule.collapseSpaces(raw.trimmingCharacters(in: .whitespacesAndNewlines))
        do {
            _ = try await client.setInstanceName(name: name)
        } catch {
            // (A refusal is the core's `Engine` error naming the status.)
            let text = "\(error)"
            if text.contains("status 403") { return "Only the person who runs this skwod can rename it." }
            if text.contains("status 400") { return "The host refused that name — try letters, digits and emoji." }
            return sendFailureText(error)
        }
        await app.refreshInstanceName()
        return nil
    }
}

extension Workspace {
    var nameSource: SkwodNameRule.Named.Source {
        if nameSetByUser == true { return .user }
        if nameFromHost == true { return .host }
        if !Workspace.isDefaultName(name), name != Workspace.defaultName(for: server) { return .learned }
        return .address
    }

    /// The list with every host-supplied / learned name re-checked (`SkwodNameRule.revalidate`).
    static func revalidatingNames(_ list: [Workspace]) -> [Workspace] {
        let reset = SkwodNameRule.revalidate(list.map { .init(id: $0.id, name: $0.displayName, source: $0.nameSource) })
        guard !reset.isEmpty else { return list }
        return list.map { w in
            guard reset.contains(w.id) else { return w }
            var fixed = w
            fixed.name = Workspace.defaultName(for: w.server)
            fixed.nameFromHost = nil
            return fixed
        }
    }
}
