import SwiftUI

/// The far-left server rail: a Home/DMs square (skwod icon) at the top, one rounded-square
/// avatar per connected server (workspace), and an add-server square at the bottom. A selection pill
/// hugs the left edge of the active item. Every item is centered on the same vertical axis.
struct ServerRailView: View {
    @EnvironmentObject private var app: AppState
    @ObservedObject var chat: ChatModel
    @State private var showAdd = false
    @State private var showCreate = false
    /// A signed-out skwod whose "Log in again" sheet is open.
    @State private var relogin: Workspace?
    @StateObject private var serverActions = ServerActions()
    @State private var renaming: Workspace?
    @State private var renameText = ""
    /// "Rename on host…" (the instance owner): the name every member sees.
    @State private var hostRenaming = false
    @State private var hostNameText = ""
    @State private var hostRenameOutcome: String?
    @State private var forgetting: Workspace?
    @State private var skwodInvite: RealSpace?
    @State private var showSkwodSettings = false
    @State private var showDevices = false
    @State private var confirmSignOut: Workspace?

    var body: some View {
        VStack(spacing: 8) {
            // Home / DMs — the skwod icon: shows your Direct Messages.
            RailItem(isActive: chat.homeMode) {
                chat.showHome()
            } content: {
                SkwodLogoTile(size: 48)
            }

            // The E2EE Feed (posts + stories) — a first-class destination on the rail.
            RailItem(isActive: chat.selection == .feed) {
                chat.homeMode = false
                chat.selection = .feed
            } content: {
                Image(systemName: "newspaper.fill").font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.85))
                    .frame(width: 48, height: 48)
                    .background(.white.opacity(0.06))
            }
            .help("Feed")

            RailDivider()

            // SERVERS (top): one square per server in the CURRENT skwod. Tapping one jumps into it —
            // its channels in the middle column, chat in the main pane (the classic server view).
            ForEach(chat.serverGroups) { g in
                RailItem(isActive: chat.isServerActive(g)) {
                    chat.openServer(g)
                } content: {
                    AvatarTile(key: AvatarStore.serverKey(g.serverId), name: g.name, size: 48, cornerRadius: 16)
                        .overlay(alignment: .bottomTrailing) { ServerMentionBadge(channelIds: g.channels.map(\.channelId)).offset(x: 4, y: 4) }
                }
                .help("Server: \(g.name)")
                .contextMenu { ServerMenuItems(group: g, chat: chat, actions: serverActions) }
            }
            if app.current != nil && app.canCreateServers {
                addTile("plus", help: "Create a server") { showCreate = true }
            }

            RailDivider()

            // SKWODS (bottom): one square per connected skwod (a self-hosted instance you have an
            // account on). Tapping a skwod opens its OVERVIEW: servers list in the middle, boxes in main.
            ForEach(app.workspaces) { w in
                RailItem(isActive: w.id == app.current?.id && !chat.homeMode) {
                    // A skwod whose session ended: "Log in again" for THAT skwod, in a sheet —
                    // the skwod on screen stays signed in and on screen.
                    if w.isSignedOut, w.id != app.current?.id {
                        relogin = w
                        return
                    }
                    chat.homeMode = false
                    chat.railServerId = nil
                    chat.selection = nil
                    // Tapping the skwod already open only shows its overview: re-activating it
                    // rebuilt the client and re-checked the session on every tap.
                    guard w.id != app.current?.id else { return }
                    Task { await app.activate(w) }
                } content: {
                    AvatarTile(key: w.instanceId.map(AvatarStore.skwodKey), name: w.displayName, size: 48, cornerRadius: 16)
                        .opacity(w.isSignedOut ? 0.45 : 1)
                        .overlay(alignment: .bottomTrailing) {
                            if w.isSignedOut {
                                Image(systemName: "person.crop.circle.badge.exclamationmark")
                                    .font(.system(size: 14, weight: .bold)).foregroundStyle(.orange)
                                    .padding(2).background(.black.opacity(0.6), in: Circle())
                            }
                        }
                }
                .help(w.isSignedOut ? "Skwod: \(w.displayName) (\(w.identityCue)) — signed out. Click to log in again."
                                    : "Skwod: \(w.displayName) (\(w.identityCue))")
                .contextMenu { skwodMenu(w) }
            }
            addTile("square.stack.3d.up", help: "Join or host a Skwod") { showAdd = true }

            Spacer()
        }
        .padding(.top, 12)
        .frame(width: 72)
        .frame(maxHeight: .infinity)
        // No backing of its own: the rail sits directly on the window backdrop, so it's exactly the
        // same glass as the titlebar strip above it.
        .sheet(isPresented: $showAdd) { DismissableSheet { AuthView(onConnected: { showAdd = false }) } }
        .sheet(isPresented: $showCreate) { CreateSpaceSheet { chat.addSpace($0) } }
        .modifier(ServerActionsHost(actions: serverActions, chat: chat))
        .sheet(item: $skwodInvite) { s in DismissableSheet { SecureJoinView(space: s) } }
        .sheet(isPresented: $showSkwodSettings) { DismissableSheet { ServerSettingsSheet() } }
        .sheet(isPresented: $showDevices) { DismissableSheet { DevicesView() } }
        .alert("Rename this Skwod", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField("Name", text: $renameText)
            Button("Rename") { if let w = renaming { app.renameLocally(w.id, to: renameText) }; renaming = nil }
            Button("Cancel", role: .cancel) { renaming = nil }
        } message: {
            Text("The name is only on this device. Its host key \(renaming?.identityCue ?? "") stays beside it.")
        }
        .alert("Rename on host", isPresented: $hostRenaming) {
            TextField("Skwod name", text: $hostNameText)
            Button("Rename") {
                let name = hostNameText
                hostRenaming = false
                Task { hostRenameOutcome = await app.setInstanceName(name) }
            }
            Button("Cancel", role: .cancel) { hostRenaming = false }
        } message: {
            Text("Every member sees this name, with the host key beside it. Letters, digits, spaces, - _ ' & and emoji; up to 32. Leave it empty to clear it.")
        }
        .alert("Couldn't rename the skwod", isPresented: Binding(get: { hostRenameOutcome != nil }, set: { if !$0 { hostRenameOutcome = nil } })) {
            Button("OK", role: .cancel) { hostRenameOutcome = nil }
        } message: { Text(hostRenameOutcome ?? "") }
        .confirmationDialog("Remove \(forgetting?.displayName ?? "this Skwod") from this device?",
                            isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
                            titleVisibility: .visible) {
            Button("Delete its messages and keys here", role: .destructive) { if let w = forgetting { app.forgetLocally(w) }; forgetting = nil }
        } message: {
            Text("You're signed out of it, so only this device's copy is deleted. Without a recovery key or another device, its messages can't be brought back.")
        }
        .confirmationDialog("Sign out of \(confirmSignOut?.displayName ?? "this Skwod")?",
                            isPresented: Binding(get: { confirmSignOut != nil }, set: { if !$0 { confirmSignOut = nil } }),
                            titleVisibility: .visible) {
            Button("Sign out") { if let w = confirmSignOut { app.signOut(w) }; confirmSignOut = nil }
        } message: {
            Text("Your messages and keys stay on this device, locked. Log in again with your password to carry on — no relinking.")
        }
        .sheet(item: $relogin) { w in
            DismissableSheet { AuthView(onConnected: { relogin = nil }, relogin: w) }
        }
        // What the skwod calls itself (its oldest server) becomes its tile's name.
        .task(id: chat.serverGroups.last?.name) {
            if let id = chat.spacesWorkspaceId, id == app.current?.id, let name = chat.serverGroups.last?.name { app.learnName(name, for: id) }
        }
    }

    /// The SKWOD menu (the host): what `SkwodMenuRule` allows for this entry.
    @ViewBuilder private func skwodMenu(_ w: Workspace) -> some View {
        let isCurrent = w.id == app.current?.id
        let items = SkwodMenuRule.items(signedOut: w.isSignedOut, isCurrent: isCurrent,
                                        isInstanceOwner: isCurrent && app.isInstanceOwner,
                                        isDuplicate: app.duplicateWorkspaceIds.contains(w.id))
        Text("Skwod: \(w.displayName) · \(w.identityCue)")
        ForEach(items, id: \.self) { item in
            switch item {
            case .logInAgain:
                Button { relogin = w } label: { Label("Log in again…", systemImage: "person.crop.circle") }
            case .rename:
                Button { renameText = w.displayName; renaming = w } label: { Label("Rename…", systemImage: "pencil") }
            case .renameOnHost:
                Button { hostNameText = w.nameFromHost == true ? w.displayName : ""; hostRenaming = true } label: {
                    Label("Rename on host…", systemImage: "character.cursor.ibeam")
                }
            case .invite:
                if let first = chat.spaces.first {
                    Button { skwodInvite = first } label: { Label("Invite people", systemImage: "person.badge.plus") }
                }
            case .mute:
                MuteMenuItems(key: MuteList.skwod, workspaceId: w.id)
            case .settings:
                Button { showSkwodSettings = true } label: { Label("Skwod settings", systemImage: "gearshape") }
            case .devices:
                Button { showDevices = true } label: { Label("Devices and security", systemImage: "lock.shield") }
            case .signOut:
                Button { confirmSignOut = w } label: { Label("Sign out of this Skwod", systemImage: "rectangle.portrait.and.arrow.right") }
            case .removeDuplicate:
                Button(role: .destructive) { Task { await app.removeDuplicate(w) } } label: {
                    Label("Remove this duplicate", systemImage: "minus.circle")
                }
            case .removeFromDevice:
                Button(role: .destructive) { forgetting = w } label: { Label("Remove from this device…", systemImage: "trash") }
            }
        }
    }

    /// A rail "+" tile (create a server / join-host a skwod), sized like the other rail slots.
    private func addTile(_ system: String, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: system).font(.system(size: 20, weight: .semibold))
                .foregroundStyle(.skAccent)
                .frame(width: 48, height: 48)
                .background(.white.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.plain).frame(width: 72, height: 52).contentShape(Rectangle()).help(help)
    }
}

/// A rail slot: a fixed 72-wide row with a left selection pill and a centered 48×48 tile. The pill is
/// overlaid so it never shifts the tile — keeping every item aligned on the same axis.
private struct RailItem<Content: View>: View {
    let isActive: Bool
    var tint: Color = .white
    let action: () -> Void
    @ViewBuilder let content: Content
    @State private var hovering = false

    var body: some View {
        ZStack(alignment: .leading) {
            // Selection pill, pinned to the left edge (doesn't affect the tile's centering).
            Capsule()
                .fill(.white)
                .frame(width: 4, height: isActive ? 40 : (hovering ? 20 : 0))
                .padding(.leading, 0)

            Button(action: action) {
                content
                    .clipShape(RoundedRectangle(cornerRadius: railCorner, style: .continuous))
                    .frame(maxWidth: .infinity)   // center the 48pt tile in the 72pt rail
            }
            .buttonStyle(.plain)
        }
        .frame(width: 72, height: 52)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .animation(.snappy(duration: 0.2), value: isActive)
        .animation(.snappy(duration: 0.2), value: hovering)
    }

    /// Rounded-square tiles on every platform (matches the desktop app and the squircle logo).
    private var railCorner: CGFloat { 16 }
}

private struct RailDivider: View {
    var body: some View {
        Rectangle().fill(.white.opacity(0.12)).frame(width: 32, height: 2).padding(.vertical, 2)
    }
}
