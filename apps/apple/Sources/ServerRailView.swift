import SwiftUI

/// The far-left server rail: a Home/DMs square (skwod icon) at the top, one rounded-square
/// avatar per connected server (workspace), and an add-server square at the bottom. A selection pill
/// hugs the left edge of the active item. Every item is centered on the same vertical axis.
struct ServerRailView: View {
    @EnvironmentObject private var app: AppState
    @ObservedObject var chat: ChatModel
    @State private var showAdd = false
    @State private var showCreate = false

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
                }
                .help(g.name)
            }
            if app.current != nil && app.canCreateServers {
                addTile("plus", help: "Create a server") { showCreate = true }
            }

            RailDivider()

            // SKWODS (bottom): one square per connected skwod (a self-hosted instance you have an
            // account on). Tapping a skwod opens its OVERVIEW: servers list in the middle, boxes in main.
            ForEach(app.workspaces) { w in
                RailItem(isActive: w.id == app.current?.id && !chat.homeMode) {
                    chat.homeMode = false
                    chat.railServerId = nil
                    chat.selection = nil
                    Task { await app.activate(w) }
                } content: {
                    AvatarTile(key: w.instanceId.map(AvatarStore.skwodKey), name: w.displayName, size: 48, cornerRadius: 16)
                }
                .help(w.displayName)
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
