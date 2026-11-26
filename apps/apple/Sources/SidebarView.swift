import SwiftUI

/// The left column. On a server: the server header (a dropdown menu) over
/// collapsible channel categories. On Home (the skwod rail icon): your Direct Messages. The
/// user panel is pinned to the bottom in both modes. Translucent sidebar material — the native
/// macOS/iOS look.
struct SidebarView: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var showCreate = false
    @State private var showJoin = false
    @State private var showNewDM = false
    @State private var showNewGroup = false
    @State private var showServerSettings = false
    @State private var showRestoreBackup = false
    /// Voice/video: setup panel (host), the call view (once configured), a note (non-host), and an
    /// in-flight check so the row can spin while it asks the server whether voice is set up.
    @State private var showVoiceSetup = false
    @State private var voiceNote: String?
    @State private var voiceChecking = false
    /// Servers whose voice list is folded (the row then shows how many are in it).
    @State private var voiceFolded: Set<String> = []
    /// Item-driven sheets: the space being invited into / configured (from header or row actions).
    @State private var inviteTarget: RealSpace?
    @State private var settingsTarget: RealSpace?
    @State private var newChannelTarget: ServerRef?
    @State private var rolesTarget: ServerRef?
    @State private var serverIconTarget: ServerRef?
    @StateObject private var serverActions = ServerActions()
    /// Bumped on live presence events so the DM rows' dots recompute (Realtime is nested state).
    @State private var presenceTick = 0

    var body: some View {
        VStack(spacing: 0) {
            if chat.homeMode {
                homeHeader
                dmList
            } else if chat.inChannelsMode {
                serverHeader
                channelList        // inside a server: its channels
            } else {
                serverHeader
                serverList         // skwod overview: the list of servers
            }
        }
        .background { SidebarGlass() }
        // Presence dots (DM rows) live-update: rerender on relay events (nested state).
        .onReceive(app.realtime.$presence) { _ in presenceTick &+= 1 }
        .sheet(isPresented: $showCreate) { CreateSpaceSheet { chat.addSpace($0) } }
        .sheet(isPresented: $showJoin) { JoinSpaceSheet(chat: chat) }
        .sheet(isPresented: $showNewDM) { NewDMSheet() }
        .sheet(isPresented: $showNewGroup) { NewGroupSheet { await chat.startGroupReportingProblem(with: $0) } }
        .sheet(isPresented: $showRestoreBackup) { RestoreWithKeySheet() }
        .sheet(isPresented: $showServerSettings) { DismissableSheet { ServerSettingsSheet() } }
        .sheet(isPresented: $showVoiceSetup) { DismissableSheet { VoiceSetupSheet() } }
        .alert("Voice & video", isPresented: Binding(get: { voiceNote != nil }, set: { if !$0 { voiceNote = nil } })) {
            Button("OK", role: .cancel) { voiceNote = nil }
        } message: { Text(voiceNote ?? "") }
        .sheet(item: $inviteTarget) { s in DismissableSheet { SecureJoinView(space: s) } }
        .sheet(item: $settingsTarget) { s in DismissableSheet { ChannelSettingsSheet(space: s, chat: chat) } }
        .sheet(item: $newChannelTarget) { srv in NewChannelSheet(server: srv, chat: chat) }
        .sheet(item: $rolesTarget) { srv in DismissableSheet { RolesSheet(server: srv) } }
        .modifier(ServerActionsHost(actions: serverActions, chat: chat))
        .sheet(item: $serverIconTarget) { srv in
            AvatarPickerSheet(
                title: "Server icon",
                currentKey: AvatarStore.serverKey(srv.serverId),
                name: srv.name,
                onPick: { await app.avatars.setServerAvatar(serverId: srv.serverId, imageData: $0) },
                onRemove: {
                    let cids = chat.spaces.filter { $0.serverId == srv.serverId }.map(\.channelId)
                    await app.avatars.clearAvatar(key: AvatarStore.serverKey(srv.serverId), channelIds: cids)
                }
            )
        }
    }

    /// Voice row tapped: ask the server whether voice is set up, then route — configured opens the
    /// call view; otherwise the host gets the setup panel and everyone else a "ask the host" note.
    private func handleVoiceTap() async {
        guard let client = app.client, let asked = app.bindTicket() else { return }
        let serverId = chat.currentServer?.serverId
        voiceChecking = true
        defer { voiceChecking = false }
        let cfg: VoiceConfig
        // A host that did not answer says nothing about voice (it used to open the setup panel).
        do { cfg = try await client.voiceConfig() } catch { voiceNote = VoiceFailure(error).message; return }
        let owner = cfg.configured || cfg.bundled ? false : await isInstanceOwner()
        guard app.holds(asked) else { return }   // (another skwod meanwhile)
        switch VoiceGate.decide(configured: cfg.configured, status: cfg.status, bundled: cfg.bundled, owner: owner) {
        case .join: if let serverId { app.activeCall = CallTarget(serverId: serverId) }
        case .setUp: showVoiceSetup = true
        case .say(let text): voiceNote = text
        }
    }

    /// True if this account is the skwod's host (owner) — the owner-only accounts endpoint answers 200.
    private func isInstanceOwner() async -> Bool {
        guard let token = app.session?.token, let base = URL(string: app.serverURL) else { return false }
        var req = URLRequest(url: base.appendingPathComponent("api/auth/users"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let code = ((try? await RawSink.data(for: req))?.1 as? HTTPURLResponse)?.statusCode ?? 0
        return code == 200
    }

    /// The space to invite people into from the header: the selected one, else the first.
    private var headerInviteSpace: RealSpace? {
        if case .space(let s) = chat.selection { return s }
        return chat.spaces.first
    }

    /// Server header: name + chevron form the dropdown, with the invite-friends
    /// affordance beside it, over a hairline + drop shadow separating it from the channel list.
    private var serverHeader: some View {
        HoverBar(highlights: false) {
            HStack(spacing: 6) {
                if chat.inChannelsMode {
                    Button { chat.showServers() } label: {
                        Image(systemName: "chevron.left").font(.system(size: 13, weight: .bold))
                            .foregroundStyle(Color(white: 0.71))
                    }
                    .buttonStyle(.plain).help("Back to servers")
                }
                Menu {
                    if headerInviteSpace != nil {
                        Button { inviteTarget = headerInviteSpace } label: { Label("Invite people", systemImage: "person.badge.plus") }
                    }
                    Button { showServerSettings = true } label: { Label("Skwod settings", systemImage: "gearshape") }
                    if let sp = headerInviteSpace {
                        Button { rolesTarget = ServerRef(serverId: sp.serverId, name: sp.name) } label: {
                            Label("Manage permissions", systemImage: "checkmark.shield")
                        }
                        Button { serverIconTarget = ServerRef(serverId: sp.serverId, name: sp.name) } label: {
                            Label("Change server icon", systemImage: "photo.circle")
                        }
                    }
                    if chat.inChannelsMode, let g = chat.currentServer {
                        Divider()
                        ServerMenuItems(group: g, chat: chat, actions: serverActions)
                    }
                    Divider()
                    Button { showCreate = true } label: { Label("Create a server", systemImage: "plus") }
                    Button { showJoin = true } label: { Label("Join with a code", systemImage: "ticket") }
                } label: {
                    HStack(spacing: 6) {
                        // Which level this is: the Skwod (the host) holds servers; a server holds
                        // channels.
                        Text(chat.inChannelsMode ? "Server" : "Skwod")
                            .font(.system(size: 10, weight: .semibold)).textCase(.uppercase)
                            .foregroundStyle(Color(white: 0.6))
                        Text(chat.inChannelsMode ? (chat.currentServer?.name ?? app.current?.displayName ?? "Skwod")
                                                 : (app.current?.displayName ?? "Skwod"))
                            .font(.system(size: 15, weight: .bold))
                            .foregroundStyle(Color(white: 0.95))            // #f2f3f5
                            .lineLimit(1)
                        Image(systemName: "chevron.down")
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(Color(white: 0.71))            // #b5bac1
                    }
                    .contentShape(Rectangle())
                }
                .menuStyle(.button).menuIndicator(.hidden).buttonStyle(.plain).fixedSize()
                Spacer()
                Button { inviteTarget = headerInviteSpace } label: {
                    Image(systemName: "person.badge.plus")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Color(white: 0.71))
                }
                .buttonStyle(.plain).disabled(headerInviteSpace == nil).help("Invite friends")
            }
        }
        .background(
            // Same glass as the whole column — just a hairline + shadow to separate from the list.
            Rectangle().fill(.clear)
                .overlay(alignment: .bottom) { Divider().overlay(Color.black.opacity(0.35)) }
                .shadow(color: .black.opacity(0.22), radius: 3, y: 1)
        )
    }

    /// Home-mode header: mirrors the server header's bar for the Direct Messages surface.
    private var homeHeader: some View {
        HoverBar(highlights: false) {
            HStack {
                Text("Direct Messages")
                    .font(.system(size: 15, weight: .bold))
                    .foregroundStyle(Color(white: 0.95))
                Spacer()
                Button { showNewDM = true } label: {
                    Image(systemName: "square.and.pencil")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Color(white: 0.71))
                }
                .buttonStyle(.plain).help("New message")
            }
        }
        .background(
            Rectangle().fill(.clear)
                .overlay(alignment: .bottom) { Divider().overlay(Color.black.opacity(0.35)) }
                .shadow(color: .black.opacity(0.22), radius: 3, y: 1)
        )
    }

    /// The skwod's servers, each a collapsible category with its channels beneath
    /// (skwod → servers → channels). Collapsing keeps the selected channel visible. Plain buttons —
    /// no `List` — so macOS never paints its own accent-colored selection behind the rows.
    /// Inside a server: its channels (the classic server view). A plain list — selecting a channel
    /// opens its chat in the main pane.
    private var channelList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 1) {
                if let group = chat.currentServer {
                    HStack {
                        Text("Channels").font(.system(size: 11, weight: .semibold)).textCase(.uppercase)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Button { newChannelTarget = ServerRef(serverId: group.serverId, name: group.name) } label: {
                            Image(systemName: "plus").font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(Color(white: 0.71))
                        }
                        .buttonStyle(.plain).help("New channel in \(group.name)")
                    }
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    ForEach(group.channels) { s in
                        Button { chat.selection = .space(s) } label: {
                            ChannelRow(name: s.channelName, selected: chat.selection == .space(s),
                                       onInvite: { inviteTarget = s },
                                       onSettings: { settingsTarget = s })
                        }
                        .buttonStyle(.plain)
                    }

                    // Voice Channels — one E2EE room for the skwod. The host wires up LiveKit once
                    // (setup panel) and it turns on for everyone; until then it's gated.
                    Text("Voice Channels").font(.system(size: 11, weight: .semibold)).textCase(.uppercase)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 8).padding(.top, 12).padding(.bottom, 4)
                    let inVoice = app.voiceRoster.participants(serverId: group.serverId, hidden: BlockList.shared.ids)
                    let folded = voiceFolded.contains(group.serverId)
                    HStack(spacing: 0) {
                        Button { Task { await handleVoiceTap() } } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "speaker.wave.2.fill").font(.system(size: 13))
                                    .foregroundStyle(Color(white: inVoice.isEmpty ? 0.6 : 0.85)).frame(width: 20)
                                Text("General").font(.system(size: 14)).foregroundStyle(Color(white: 0.78))
                                Spacer()
                                if voiceChecking { ProgressView().controlSize(.small) }
                            }
                            .padding(.leading, 8).padding(.trailing, inVoice.isEmpty ? 8 : 2).padding(.vertical, 7)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        if !inVoice.isEmpty {
                            // Who is in it folds away; the count stays. (Beside the join button,
                            // not inside it: folding never starts a call.)
                            Button {
                                if folded { voiceFolded.remove(group.serverId) } else { voiceFolded.insert(group.serverId) }
                            } label: {
                                HStack(spacing: 3) {
                                    if folded {
                                        Image(systemName: "person.2.fill").font(.system(size: 10))
                                        Text("\(inVoice.count)").font(.system(size: 11, weight: .semibold)).monospacedDigit()
                                    }
                                    Image(systemName: folded ? "chevron.right" : "chevron.down").font(.system(size: 9, weight: .bold))
                                }
                                .foregroundStyle(Color(white: 0.6))
                                .padding(.horizontal, 6).padding(.vertical, 7)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .help(folded ? "Show who's in voice" : "Hide who's in voice")
                            .accessibilityLabel(VoiceRoster.countLabel(inVoice.count) ?? "")
                        }
                    }
                    if !folded {
                        ForEach(inVoice) { p in
                            VoiceParticipantRow(participant: p, serverId: group.serverId)
                        }
                    }
                }
            }
            .padding(.horizontal, 8).padding(.top, 10).padding(.bottom, listBottomInset)
        }
        .frame(maxHeight: .infinity)
    }

    /// The skwod's servers as a list — the middle column of the overview. Selecting one shows its
    /// channels as boxes in the main pane (skwod → servers → channels). "All channels" shows every
    /// server's channels at once.
    private var serverList: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 1) {
                HStack {
                    Text("Servers in this Skwod").font(.system(size: 11, weight: .semibold)).textCase(.uppercase)
                        .foregroundStyle(.secondary)
                    Spacer()
                    createJoinMenu
                }
                .padding(.horizontal, 8).padding(.vertical, 4)

                if chat.spaces.isEmpty {
                    if chat.provisioning {
                        HStack(spacing: 8) {
                            ProgressView().controlSize(.small)
                            Text("Setting up your channels…").font(.caption).foregroundStyle(.secondary)
                        }
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        // Waiting on another member to come online — a passphrase backup skips that.
                        Button { showRestoreBackup = true } label: {
                            Label("Restore from key backup", systemImage: "key.horizontal.fill").font(.caption)
                        }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                        .padding(.horizontal, 12).padding(.vertical, 2)
                    } else {
                        ServersEmptyNote(chat: chat) { showRestoreBackup = true }
                    }
                } else {
                    Button { chat.showServers() } label: {
                        ServerListRow(name: "All channels", channels: chat.spaces.count,
                                      selected: chat.overview && chat.selection == nil, glyph: "square.grid.2x2")
                    }
                    .buttonStyle(.plain)
                    ForEach(chat.serverGroups) { g in
                        Button { chat.openServer(g) } label: {
                            ServerListRow(name: g.name, channels: g.channels.count, selected: chat.isServerActive(g),
                                          inVoice: app.voiceRoster.count(serverId: g.serverId, hidden: BlockList.shared.ids))
                        }
                        .buttonStyle(.plain)
                        .contextMenu {
                            Button { newChannelTarget = ServerRef(serverId: g.serverId, name: g.name) } label: {
                                Label("New channel", systemImage: "plus")
                            }
                            Divider()
                            ServerMenuItems(group: g, chat: chat, actions: serverActions)
                        }
                    }
                }
            }
            .padding(.horizontal, 8).padding(.top, 10).padding(.bottom, listBottomInset)
        }
        .frame(maxHeight: .infinity)
    }

    private var createJoinMenu: some View {
        Menu {
            Button { showCreate = true } label: { Label("Create a server", systemImage: "plus") }
            Button { showJoin = true } label: { Label("Join with a code", systemImage: "ticket") }
        } label: {
            Image(systemName: "plus").font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Color(white: 0.71))
        }
        .menuStyle(.button).menuIndicator(.hidden).buttonStyle(.plain).fixedSize()
        .help("Create or join a server")
    }

    /// Clearance for the floating user panel that overlays the sidebar's bottom on macOS.
    private var listBottomInset: CGFloat {
        #if os(macOS)
        return 66
        #else
        return 12
        #endif
    }


    /// Home mode: your DM conversations (DMs live behind the home button, not in servers).
    private var dmList: some View {
        ScrollView {
            let _ = presenceTick   // read the tick so live presence events re-evaluate the rows
            VStack(alignment: .leading, spacing: 1) {
                HStack {
                    Text("Direct Messages").font(.system(size: 11, weight: .semibold)).textCase(.uppercase)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button { showNewGroup = true } label: {
                        Image(systemName: "person.3.fill").font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(Color(white: 0.71))
                    }
                    .buttonStyle(.plain).help("New group").accessibilityLabel("New group")
                    Button { showNewDM = true } label: {
                        Image(systemName: "plus").font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(Color(white: 0.71))
                    }
                    .buttonStyle(.plain).help("New message")
                }
                .padding(.horizontal, 10).padding(.top, 4).padding(.bottom, 4)

                GroupInvitations()
                ForEach(chat.groups) { g in
                    Button { chat.selection = .group(g) } label: { GroupRow(group: g, selected: chat.selection == .group(g)) }
                        .buttonStyle(.plain)
                        .muteMenu(scope: "dm:\(g.conversationId)")
                }
                if chat.dms.isEmpty && chat.groups.isEmpty {
                    Text("No conversations yet").font(.caption).foregroundStyle(.secondary)
                        .padding(.horizontal, 12).padding(.vertical, 6)
                } else {
                    ForEach(chat.dms) { d in
                        Button { chat.selection = .dm(d) } label: {
                            DMRow(name: app.contacts.display(d.peerUserId, claimedName: d.name).label(for: .dmRow), selected: chat.selection == .dm(d),
                                  badge: app.contacts.display(d.peerUserId, claimedName: d.name).badge,
                                  status: app.realtime.dot(userId: d.peerUserId),
                                  peerUserId: d.peerUserId)
                        }
                        .buttonStyle(.plain)
                        .muteMenu(scope: "dm:\(d.conversationId)")
                    }
                }
            }
            .padding(.horizontal, 8).padding(.top, 10).padding(.bottom, listBottomInset)
        }
        .frame(maxHeight: .infinity)
    }

}

/// A 46pt header bar with a hover highlight (used by the server dropdown).
private struct HoverBar<Content: View>: View {
    var highlights = true
    @ViewBuilder let content: Content
    @State private var hovering = false
    var body: some View {
        content
            .padding(.horizontal, 14)
            .frame(height: 46)
            .contentShape(Rectangle())
            .background(highlights && hovering ? Color.white.opacity(0.06) : .clear)
            .onHover { hovering = $0 }
    }
}

/// A collapsible category header: tiny chevron that points right when collapsed,
/// uppercase 11px label that brightens on hover, and a trailing accessory (e.g. the + menu).
private struct CategoryHeader<Trailing: View>: View {
    let title: String
    @Binding var collapsed: Bool
    @ViewBuilder let trailing: () -> Trailing
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 2) {
            Button {
                withAnimation(.snappy(duration: 0.18)) { collapsed.toggle() }
            } label: {
                HStack(spacing: 2) {
                    Image(systemName: "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                        .rotationEffect(.degrees(collapsed ? -90 : 0))
                    Text(title).font(.system(size: 11, weight: .semibold)).textCase(.uppercase)
                        .lineLimit(1)
                }
                .foregroundStyle(hovering ? Color(white: 0.87) : Color(white: 0.58))
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            Spacer()
            trailing()
        }
        .padding(.horizontal, 8).padding(.top, 4).padding(.bottom, 4)
        .onHover { hovering = $0 }
    }
}

/// Backing for the sidebar: a translucent lift over the dark chrome — one step LIGHTER, the
/// middle column. The lift is white-on-glass (not paint), so the backdrop's glow still reads.
struct SidebarGlass: View {
    var body: some View {
        Rectangle().fill(.white.opacity(0.05)).ignoresSafeArea()
    }
}

/// A channel row: `# name`, muted until hovered/selected, with a rounded highlight.
/// When hovered or selected it shows the per-channel actions: invite (person+) and settings.
struct ChannelRow: View {
    let name: String
    let selected: Bool
    var onInvite: (() -> Void)? = nil
    var onSettings: (() -> Void)? = nil
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "number")
                .font(.system(size: 15, weight: .medium))
                .foregroundStyle(selected ? .white : .secondary)
                .frame(width: 20)
            Text(name)
                .font(.system(size: 15, weight: selected ? .semibold : .regular))
                .foregroundStyle(selected ? .white : (hovering ? .white.opacity(0.9) : .white.opacity(0.65)))
                .lineLimit(1)
            Spacer()
            if hovering || selected {
                if let onInvite {
                    Button(action: onInvite) {
                        Image(systemName: "person.badge.plus")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(.white.opacity(0.65))
                    }
                    .buttonStyle(.plain).help("Add to channel")
                }
                if let onSettings {
                    Button(action: onSettings) {
                        Image(systemName: "gearshape.fill")
                            .font(.system(size: 12))
                            .foregroundStyle(.white.opacity(0.65))
                    }
                    .buttonStyle(.plain).help("Channel settings")
                }
            }
        }
        .padding(.horizontal, 8).padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(selected ? .white.opacity(0.14) : (hovering ? .white.opacity(0.06) : .clear))
        )
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .listRowInsets(EdgeInsets(top: 1, leading: 6, bottom: 1, trailing: 6))
    }
}

/// A server row in the middle overview column: monogram + name + channel count. Selecting it shows
/// the server's channels as boxes in the main pane.
/// One person in a voice room, under the voice channel (build 47): a small avatar (a green ring
/// while they speak — known only for the call this device is in), the name this device has for
/// them, and muted / camera / screen-share marks. Tapping it shows their card.
struct VoiceParticipantRow: View {
    @EnvironmentObject private var app: AppState
    @ObservedObject private var speaking = VoiceSpeaking.shared
    let participant: VoiceParticipant
    let serverId: String
    @State private var showCard = false

    private var label: String {
        if participant.userId == app.session?.userId { return "You" }
        return app.contacts.authorLabel(participant.userId, claimedName: app.contacts.roster[participant.userId])
    }

    var body: some View {
        let talking = speaking.isSpeaking(participant.userId, in: serverId)
        Button { showCard = true } label: {
            HStack(spacing: 7) {
                AvatarImage(key: AvatarStore.userKey(participant.userId), name: label, size: 20)
                    .overlay(Circle().strokeBorder(talking ? Color.green : .clear, lineWidth: 2))
                Text(label).font(.system(size: 13)).foregroundStyle(Color(white: talking ? 0.95 : 0.72)).lineLimit(1)
                Spacer(minLength: 0)
                if participant.screen { Image(systemName: "rectangle.on.rectangle").font(.system(size: 10)).foregroundStyle(Color(white: 0.6)) }
                if participant.video { Image(systemName: "video.fill").font(.system(size: 10)).foregroundStyle(Color(white: 0.6)) }
                if participant.muted { Image(systemName: "mic.slash.fill").font(.system(size: 10)).foregroundStyle(Color(white: 0.5)) }
            }
            .padding(.leading, 36).padding(.trailing, 8).padding(.vertical, 3)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(label)\(participant.muted ? ", muted" : "")\(participant.video ? ", camera on" : "")\(participant.screen ? ", sharing screen" : "")\(talking ? ", speaking" : "")")
        .popover(isPresented: $showCard) { MentionProfileCard(userId: participant.userId, label: label) }
    }
}

private struct ServerListRow: View {
    let name: String
    let channels: Int
    var selected: Bool = false
    var glyph: String? = nil
    /// People in the server's voice room (shown while its channels are folded away).
    var inVoice: Int = 0
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            if let glyph {
                Image(systemName: glyph).font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.white.opacity(0.85)).frame(width: 30, height: 30)
                    .background(.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            } else {
                Text(name.prefix(1).uppercased()).font(.system(size: 13, weight: .bold)).foregroundStyle(.white)
                    .frame(width: 30, height: 30)
                    .background(Color.seeded(name).gradient, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            }
            VStack(alignment: .leading, spacing: 1) {
                Text(name).font(.system(size: 14, weight: .medium))
                    .foregroundStyle(Color(white: selected ? 0.98 : 0.82)).lineLimit(1)
                Text("\(channels) channel\(channels == 1 ? "" : "s")").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer()
            if inVoice > 0 {
                HStack(spacing: 3) {
                    Image(systemName: "speaker.wave.2.fill").font(.system(size: 10))
                    Text("\(inVoice)").font(.system(size: 11, weight: .semibold)).monospacedDigit()
                }
                .foregroundStyle(Color.green.opacity(0.85))
                .accessibilityLabel(VoiceRoster.countLabel(inVoice) ?? "")
            }
        }
        .padding(.horizontal, 8).padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(selected ? .white.opacity(0.12) : (hovering ? .white.opacity(0.06) : .clear))
        )
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
    }
}

/// Channel settings (the per-channel gear): channel info, invite entry point, and removal.
/// All honest surfaces — everything here maps to a real capability.
struct ChannelSettingsSheet: View {
    let space: RealSpace
    @ObservedObject var chat: ChatModel
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var showInvite = false
    @State private var confirmRemove = false
    @State private var confirmClear = false
    @State private var clearing = false
    @State private var clearError = ""

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(alignment: .leading, spacing: 18) {
                HStack(spacing: 10) {
                    Image(systemName: "number").font(.title2.weight(.semibold)).foregroundStyle(.white.opacity(0.5))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(space.channelName).font(.title2.bold()).foregroundStyle(.white)
                        Text(space.name).font(.subheadline).foregroundStyle(.white.opacity(0.5))
                    }
                }
                GlassCard {
                    VStack(alignment: .leading, spacing: 10) {
                        Label("End-to-end encrypted", systemImage: "lock.fill")
                            .font(.callout).foregroundStyle(.white.opacity(0.85))
                        Text("The server only ever sees ciphertext for this channel.")
                            .font(.caption).foregroundStyle(.white.opacity(0.5))
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                Button { showInvite = true } label: {
                    Label("Invite people", systemImage: "person.badge.plus")
                        .frame(maxWidth: .infinity).padding(.vertical, 4)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                Button(role: .destructive) { confirmClear = true } label: {
                    HStack(spacing: 6) {
                        if clearing { ProgressView().controlSize(.small) }
                        Label("Clear all messages", systemImage: "trash.slash")
                    }
                    .frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .buttonStyle(.glass).disabled(clearing)
                if !clearError.isEmpty {
                    Text(clearError).font(.caption).foregroundStyle(.red.opacity(0.9))
                }
                Button(role: .destructive) { confirmRemove = true } label: {
                    Label("Remove from sidebar", systemImage: "trash")
                        .frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .buttonStyle(.glass)
            }
            .padding(26).frame(maxWidth: 420)
        }
        .sheet(isPresented: $showInvite) { DismissableSheet { SecureJoinView(space: space) } }
        .confirmationDialog("Clear all messages in #\(space.channelName)?",
                            isPresented: $confirmClear, titleVisibility: .visible) {
            Button("Clear messages", role: .destructive) { Task { await clearChannel() } }
        } message: {
            Text("Permanently deletes every message in this channel, for everyone. Members, roles, and the channel itself stay. This can't be undone.")
        }
        .confirmationDialog("Remove #\(space.channelName) from your sidebar?",
                            isPresented: $confirmRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { chat.removeSpace(space); dismiss() }
        } message: {
            Text("This only hides it for you — you can join again with an invite.")
        }
    }

    /// Owner/moderator action: wipe every message in this channel (server-enforced). On success the
    /// open chat view's poll reloads it empty; on failure (e.g. a non-moderator) show why.
    private func clearChannel() async {
        guard let client = app.client else { return }
        clearing = true; clearError = ""
        defer { clearing = false }
        do {
            try await client.clearChannelMessages(channelId: space.channelId)
            dismiss()
        } catch {
            clearError = "Couldn't clear — only a moderator can clear this channel."
        }
    }
}

/// Server settings (from the server-name dropdown): the workspace's address + identity, the
/// owner's account list (every sign-up, member or stranded, with delete), and leaving the server.
struct ServerSettingsSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var confirmLeave = false
    @State private var confirmWipe = false
    @State private var confirmClearServer = false
    @State private var clearingServer = false
    @State private var accounts: [AccountInfo] = []
    @State private var isOwner = false
    @State private var pendingDelete: AccountInfo?
    @State private var status = ""
    /// User ids the owner has granted server-creation to (host-only + grantable).
    @State private var creators: Set<String> = []
    @State private var showIconPicker = false

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    // Skwod icon — the instance owner (host) can set it; everyone sees it read-only.
                    HStack(spacing: 14) {
                        AvatarTile(key: (app.current?.instanceId).map(AvatarStore.skwodKey),
                                   name: app.current?.displayName ?? "Skwod", size: 60, cornerRadius: 18)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(app.current?.displayName ?? "Server").font(.title2.bold()).foregroundStyle(.white)
                            if isOwner {
                                Button("Change Skwod icon") { showIconPicker = true }
                                    .font(.caption).buttonStyle(.plain).foregroundStyle(.skAccent)
                            }
                        }
                        Spacer()
                    }
                    GlassCard {
                        VStack(alignment: .leading, spacing: 12) {
                            // The STABLE address only — never the per-launch loopback URL.
                            if let nodeId = app.current?.nodeId {
                                row("Host key", InviteLink.shortKey(nodeId))
                            } else {
                                row("Address", app.current?.server ?? "—")
                            }
                            Divider().overlay(.white.opacity(0.08))
                            HStack {
                                Text("Connection").font(.caption).foregroundStyle(.white.opacity(0.5))
                                Spacer()
                                ConnectionPill()
                            }
                            Divider().overlay(.white.opacity(0.08))
                            row("Your user id", app.session?.userId ?? "—")
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if let address = app.current?.server, !address.isEmpty {
                        // The address alone lets nobody in (joining needs an invite code), but it
                        // does identify the host — treat the copy as short-lived.
                        HStack {
                            Spacer()
                            CopyButton(address, sensitive: true)
                            Spacer()
                        }
                    }

                    if isOwner {
                        VoiceServerCard { accountsCard }
                        Button(role: .destructive) { confirmClearServer = true } label: {
                            HStack(spacing: 6) {
                                if clearingServer { ProgressView().controlSize(.small) }
                                Label("Clear all messages in this Skwod", systemImage: "trash.slash")
                            }
                            .frame(maxWidth: .infinity).padding(.vertical, 2)
                        }
                        .buttonStyle(.glass).disabled(clearingServer)
                    }

                    Spacer().frame(height: 4)
                    Button { confirmLeave = true } label: {
                        Label("Sign out of this Skwod", systemImage: "rectangle.portrait.and.arrow.right")
                            .frame(maxWidth: .infinity).padding(.vertical, 2)
                    }
                    .buttonStyle(.glass)

                    dataCard
                }
                .padding(26).frame(maxWidth: 460)
            }
        }
        .task { await loadAccounts() }
        .sheet(isPresented: $showIconPicker) {
            if let iid = app.current?.instanceId {
                AvatarPickerSheet(
                    title: "Skwod icon",
                    currentKey: AvatarStore.skwodKey(iid),
                    name: app.current?.displayName ?? "Skwod",
                    onPick: { await app.avatars.setSkwodAvatar(instanceId: iid, imageData: $0) },
                    onRemove: {
                        await app.avatars.clearAvatar(key: AvatarStore.skwodKey(iid),
                                                      channelIds: app.chatModel?.spaces.map(\.channelId) ?? [])
                    }
                )
            }
        }
        .confirmationDialog("Sign out of \(app.current?.displayName ?? "this skwod")?",
                            isPresented: $confirmLeave, titleVisibility: .visible) {
            Button("Sign out") { app.leaveCurrent(); dismiss() }
        } message: {
            Text("Your messages and keys stay on this device, locked. Sign in again with your password to carry on where you left off — no relinking.")
        }
        .confirmationDialog("Erase all Skwod data on this Mac?",
                            isPresented: $confirmWipe, titleVisibility: .visible) {
            Button("Erase everything", role: .destructive) { app.wipeAllLocalData(); dismiss() }
        } message: {
            Text(wipeWarning)
        }
        .confirmationDialog("Clear all messages in \(app.current?.displayName ?? "this skwod")?",
                            isPresented: $confirmClearServer, titleVisibility: .visible) {
            Button("Clear all messages", role: .destructive) { Task { await clearServerMessages() } }
        } message: {
            Text("Permanently deletes every message, story, and post across all of this Skwod's channels, for everyone. Channels, members, and roles stay. This can't be undone.")
        }
        .confirmationDialog("Delete \(pendingDelete?.username ?? "")'s account?",
                            isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }),
                            titleVisibility: .visible) {
            Button("Delete account", role: .destructive) {
                if let a = pendingDelete { Task { await deleteAccount(a) } }
                pendingDelete = nil
            }
            Button("Delete and ban", role: .destructive) {
                if let a = pendingDelete { Task { await deleteAccount(a, ban: true) } }
                pendingDelete = nil
            }
        } message: {
            Text("Wipes the account, devices, and memberships — the username is freed for a fresh sign-up. “Delete and ban” also keeps that username and the account's devices from signing up on this skwod again, and revokes the invite it used.")
        }
    }

    /// Owner-only: every account on this server, member or stranded, with delete.
    private var accountsCard: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Accounts on this Skwod", systemImage: "person.text.rectangle")
                Text("Everyone who has signed up here — including accounts that never joined a server. Deleting frees the username.")
                    .font(.caption).foregroundStyle(.white.opacity(0.5))
                ForEach(accounts) { a in
                    HStack(spacing: 10) {
                        Circle().fill(Color.seeded(a.username).gradient).frame(width: 26, height: 26)
                            .overlay(Text(a.username.prefix(1).uppercased()).font(.caption2.bold()).foregroundStyle(.white))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(a.username).font(.system(size: 13, weight: .semibold)).foregroundStyle(.white)
                            Text(a.userId == app.session?.userId ? "you · owner" : (a.isMember ? "member" : "never joined a server"))
                                .font(.caption2).foregroundStyle(.white.opacity(0.45))
                        }
                        Spacer()
                        if a.userId != app.session?.userId {
                            // Grant/revoke server creation (host-only + grantable).
                            let granted = creators.contains(a.userId)
                            Button { Task { await toggleCreator(a, grant: !granted) } } label: {
                                Text(granted ? "Can create ✓" : "Grant create")
                                    .font(.caption2)
                                    .foregroundStyle(granted ? Color.green : .skAccent)
                            }
                            .buttonStyle(.plain).help(granted ? "Revoke server creation" : "Allow this member to create servers")
                            Button { pendingDelete = a } label: {
                                Image(systemName: "trash").font(.system(size: 12)).foregroundStyle(.red.opacity(0.85))
                            }
                            .buttonStyle(.plain).help("Delete account")
                        }
                    }
                    .padding(.vertical, 2)
                }
                if !status.isEmpty { Text(status).font(.caption2).foregroundStyle(.orange) }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// Storage + factory-reset for this Mac's whole skwod install.
    private var dataCard: some View {
        GlassCard {
            VStack(alignment: .leading, spacing: 10) {
                SectionHeader(title: "Data on this device", systemImage: "internaldrive")
                Text("Skwod stores your encrypted message caches, your logins and keys (in the Keychain), and — if you host — the server database.")
                    .font(.caption).foregroundStyle(.white.opacity(0.5))
                #if os(macOS)
                // Host-only: the folder is meaningful mainly on the machine running the server (a
                // member's Mac holds only their opaque encrypted cache). `isOwner` = this account
                // owns the skwod, i.e. the host.
                if isOwner {
                    Button { revealDataInFinder() } label: {
                        Label("See your data in Finder", systemImage: "folder")
                            .frame(maxWidth: .infinity).padding(.vertical, 2)
                    }
                    .buttonStyle(.glass).tint(.skAccent)
                }
                #endif
                Button(role: .destructive) { confirmWipe = true } label: {
                    Label("Erase all Skwod data on this device", systemImage: "trash")
                        .frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .buttonStyle(.glass).tint(.red)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    #if os(macOS)
    /// Open Finder on the folder that holds skwod's on-disk data (the encrypted caches and, if you
    /// host, the server database), selecting the skwod items so they're easy to spot. The Keychain
    /// items live in Keychain Access under "io.skwod.client"; those aren't browsable in Finder.
    private func revealDataInFinder() {
        let appSupport = SharedContainer.privateURL
        let items = (try? FileManager.default.contentsOfDirectory(at: appSupport, includingPropertiesForKeys: nil))?
            .filter { $0.lastPathComponent.hasPrefix("skwod") } ?? []
        if items.isEmpty {
            NSWorkspace.shared.activateFileViewerSelecting([appSupport])
        } else {
            NSWorkspace.shared.activateFileViewerSelecting(items)
        }
    }
    #endif

    private var wipeWarning: String {
        #if os(macOS)
        return "Deletes every trace of Skwod from this Mac: your message caches, your logins and keys in the Keychain, all preferences, AND — because this Mac can host — the server database itself. If you host a Skwod, this destroys it for everyone on it. This cannot be undone; you'll return to sign-in."
        #else
        return "Deletes every trace of Skwod from this device: your message caches, logins, keys, and preferences. Your account on the server is untouched — you can sign back in. This cannot be undone."
        #endif
    }

    private func loadAccounts() async {
        guard let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/auth/users"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await RawSink.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let parsed = try? JSONDecoder().decode(AccountList.self, from: data) else {
            isOwner = false
            return
        }
        accounts = parsed.users
        isOwner = true
        await loadCreators()
    }

    /// Owner-only: which accounts currently hold the server-creation grant.
    private func loadCreators() async {
        guard let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/instance/server-creators"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await RawSink.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let list = obj["creators"] as? [[String: Any]] else { return }
        creators = Set(list.compactMap { $0["user_id"] as? String })
    }

    private func toggleCreator(_ a: AccountInfo, grant: Bool) async {
        guard let token = app.session?.token, let base = URL(string: app.serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/instance/server-creators/\(a.userId)"))
        req.httpMethod = grant ? "PUT" : "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let code = ((try? await RawSink.data(for: req))?.1 as? HTTPURLResponse)?.statusCode ?? 0
        if code == 200 { if grant { creators.insert(a.userId) } else { creators.remove(a.userId) } }
        else { status = "Couldn't change that grant." }
    }

    private func deleteAccount(_ a: AccountInfo, ban: Bool = false) async {
        // Signed by this device, through the core (a session token alone is refused).
        guard let client = app.client else { return }
        let deleted = (try? await (ban ? client.deleteAccountAndBan(userId: a.userId) : client.deleteAccount(userId: a.userId))) != nil
        status = deleted ? "" : "Couldn't delete that account."
        await loadAccounts()
    }

    /// Owner action: clear every message/story/post across each server on this skwod (server-enforced).
    /// Open chat views reload empty via their poll; channels, members, and roles are kept.
    private func clearServerMessages() async {
        guard let client = app.client else { return }
        clearingServer = true
        defer { clearingServer = false }
        let serverIds = Set((app.chatModel?.spaces ?? []).map(\.serverId)).filter { !$0.isEmpty && $0 != "demo" }
        for sid in serverIds {
            try? await client.clearServerMessages(serverId: sid)
        }
        dismiss()
    }

    private func row(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundStyle(.white.opacity(0.45))
            Text(value.isEmpty ? "—" : value).font(.system(size: 13, design: .monospaced))
                .foregroundStyle(.white.opacity(0.85)).lineLimit(1).truncationMode(.middle)
        }
    }
}

/// One account row from the owner's `/api/auth/users` listing.
struct AccountInfo: Identifiable, Decodable {
    let userId: String
    let username: String
    let isMember: Bool
    var id: String { userId }
    enum CodingKeys: String, CodingKey { case userId = "user_id", username, isMember = "is_member" }
}

private struct AccountList: Decodable {
    let users: [AccountInfo]
}

/// A DM row: avatar + name.
struct DMRow: View {
    let name: String
    let selected: Bool
    /// The name's trust (build 49): a small badge beside the plain name.
    var badge: ContactTrust.Badge = .none
    /// The peer's live status ("online"/"idle"/"dnd"/"offline") — drives the presence dot.
    var status: String = "offline"
    /// The peer's userId — drives the E2EE avatar lookup.
    var peerUserId: String? = nil
    @State private var hovering = false

    var body: some View {
        HStack(spacing: 10) {
            ZStack(alignment: .bottomTrailing) {
                AvatarImage(key: peerUserId.map(AvatarStore.userKey), name: name, size: 30)
                Circle().fill(PresenceStyle.color(status)).frame(width: 10, height: 10)
                    .overlay(Circle().strokeBorder(.black.opacity(0.7), lineWidth: 1.5))
                    .offset(x: 1, y: 1)
            }
            Text(name)
                .font(.system(size: 15, weight: selected ? .semibold : .regular))
                .foregroundStyle(selected ? .white : (hovering ? .white.opacity(0.9) : .white.opacity(0.7)))
                .lineLimit(1)
            if badge != .none { TrustBadge(badge: badge, compact: true) }
            Spacer()
        }
        .padding(.horizontal, 8).padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(selected ? .white.opacity(0.14) : (hovering ? .white.opacity(0.06) : .clear))
        )
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
        .listRowInsets(EdgeInsets(top: 1, leading: 6, bottom: 1, trailing: 6))
    }
}


/// The permission bitmask, mirrored from the server's spec (perms.rs / the original shared package).
enum Perm {
    static let entries: [(name: String, bit: Int64)] = [
        ("Administrator (everything)", 8192),
        ("Manage channels", 1),
        ("Manage roles", 2),
        ("Manage server", 4),
        ("Kick members", 8),
        ("Ban members", 16),
        ("Manage messages", 32),
        ("Manage invites", 1024),
        ("Send messages", 64),
        ("Attach files", 256),
        ("Add reactions", 512),
        ("Mention everyone", 16384),
    ]

    static func summary(_ mask: Int64) -> String {
        if mask & 8192 != 0 { return "Administrator" }
        let names = entries.filter { $0.bit != 8192 && mask & $0.bit != 0 }.map(\.name)
        return names.isEmpty ? "No permissions" : names.prefix(3).joined(separator: ", ") + (names.count > 3 ? " +\(names.count - 3)" : "")
    }
}

/// Manage a server's roles + their permission bitmasks (role names stay E2EE via the space key).
/// Assign roles to people from the members panel's right-click menu.
struct RolesSheet: View {
    let server: ServerRef
    @EnvironmentObject private var app: AppState
    @State private var roles: [RoleInfo] = []
    @State private var showCreate = false
    @State private var status = ""

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("Permissions — \(server.name)").font(.title2.bold()).foregroundStyle(.white)
                    Text("Roles gate what members can do (create channels, invite, moderate…). Assign them by right-clicking a member in the members panel.")
                        .font(.caption).foregroundStyle(.white.opacity(0.55))
                    ForEach(roles, id: \.roleId) { r in
                        HStack {
                            Image(systemName: r.isDefault ? "person.3.fill" : "checkmark.shield.fill")
                                .foregroundStyle(.skAccent.opacity(0.8))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(r.name ?? "everyone").font(.system(size: 14, weight: .semibold)).foregroundStyle(.white)
                                Text(Perm.summary(r.permissions)).font(.caption2).foregroundStyle(.white.opacity(0.5))
                            }
                            Spacer()
                            if !r.isDefault {
                                Button { Task { await remove(r) } } label: {
                                    Image(systemName: "trash").font(.system(size: 12)).foregroundStyle(.red.opacity(0.85))
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        .padding(12).glassEffect(.regular, in: .rect(cornerRadius: 12, style: .continuous))
                    }
                    Button { showCreate = true } label: {
                        Label("New role", systemImage: "plus").frame(maxWidth: .infinity).padding(.vertical, 2)
                    }
                    .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                    if !status.isEmpty { Text(status).font(.caption).foregroundStyle(.orange) }
                }
                .padding(24).frame(maxWidth: 480)
            }
        }
        .task { await load() }
        .sheet(isPresented: $showCreate) { NewRoleSheet(server: server) { Task { await load() } } }
    }

    private func load() async {
        guard let client = app.client else { return }
        roles = (try? await client.listRoles(serverId: server.serverId)) ?? []
    }

    private func remove(_ r: RoleInfo) async {
        guard let client = app.client else { return }
        do { try await client.deleteRole(roleId: r.roleId); await load() }
        catch { status = "Couldn't delete that role." }
    }
}

/// Create a role: an E2EE name + permission toggles.
struct NewRoleSheet: View {
    let server: ServerRef
    var onDone: () -> Void
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var mask: Int64 = 64 | 128 | 256 | 512   // send/read/attach/react defaults
    @State private var busy = false
    @State private var error = ""

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("New role in \(server.name)").font(.title3.bold()).foregroundStyle(.white)
                    HStack {
                        Image(systemName: "checkmark.shield").foregroundStyle(.skAccent).frame(width: 22)
                        TextField("role name", text: $name).textFieldStyle(.plain).foregroundStyle(.white)
                    }
                    .padding(12).glassEffect(.regular.interactive(), in: .capsule)
                    ForEach(Perm.entries, id: \.bit) { entry in
                        Toggle(isOn: Binding(
                            get: { mask & entry.bit != 0 },
                            set: { on in if on { mask |= entry.bit } else { mask &= ~entry.bit } }
                        )) {
                            Text(entry.name).font(.system(size: 13)).foregroundStyle(.white.opacity(0.85))
                        }
                        .toggleStyle(.switch).controlSize(.small).tint(.skAccent)
                    }
                    if !error.isEmpty { Text(error).font(.caption).foregroundStyle(.red) }
                    Button { Task { await create() } } label: {
                        HStack { if busy { ProgressView().controlSize(.small) }; Text("Create role") }
                            .frame(maxWidth: .infinity).padding(.vertical, 4)
                    }
                    .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                    .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty)
                    Button("Cancel") { dismiss() }.buttonStyle(.glass)
                }
                .padding(24).frame(maxWidth: 440)
            }
        }
        .presentationDetents([.large])
    }

    private func create() async {
        guard let client = app.client else { return }
        busy = true; error = ""
        do {
            _ = try await client.createRole(serverId: server.serverId,
                                            name: name.trimmingCharacters(in: .whitespaces),
                                            permissions: mask)
            onDone()
            dismiss()
        } catch { self.error = "Couldn't create the role — you need Manage Roles." }
        busy = false
    }
}
