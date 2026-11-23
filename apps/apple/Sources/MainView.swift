import SwiftUI

/// The authenticated shell — a native split view (sidebar · chat · members), the familiar
/// three-column chat layout. Selecting a channel or DM in the sidebar drives the chat detail pane.
/// On iPhone the columns collapse into a drill-down; on Mac all three show side by side.
struct MainView: View {
    @EnvironmentObject private var app: AppState
    @StateObject private var chat = ChatModel()
    #if os(macOS)
    @ObservedObject private var host = HostManager.shared
    #endif

    var body: some View {
        #if os(macOS)
        // Layout: the native titlebar as the full-width top strip (workspace name centered,
        // via .navigationTitle), then server rail | channels sidebar | chat. The sidebar+chat form a
        // rounded "sheet" inset against the darker chrome, and the user panel floats bottom-left
        // spanning the rail + sidebar.
        HStack(spacing: 0) {
            ServerRailView(chat: chat)
            // One content sheet against the chrome, rounded only at its top-leading corner.
            HStack(spacing: 0) {
                SidebarView()
                    .environmentObject(chat)
                    .frame(width: 252)
                DetailPane()
                    .environmentObject(chat)
                    .frame(maxWidth: .infinity)
            }
            .clipShape(UnevenRoundedRectangle(topLeadingRadius: 10, style: .continuous))
        }
        // The glowing glass backdrop spans the whole window, with a dark chrome veil over it: the
        // titlebar + rail strip is the DARKEST layer (the chrome), and the sidebar/chat panes
        // step lighter on top of it — translucent washes, so the glass reads through every step.
        .background {
            ZStack {
                SkwodBackground()
                Color.black.opacity(0.28)
            }
            .ignoresSafeArea()
        }
        .overlay(alignment: .bottomLeading) {
            UserPanel().environmentObject(chat)
        }
        .navigationTitle(app.current?.displayName ?? "Skwod")
        .toolbar {
            // Titlebar: back/forward beside the traffic lights, workspace icon + name centered.
            ToolbarItemGroup(placement: .navigation) {
                Button { chat.goBack() } label: { Image(systemName: "arrow.left") }
                    .disabled(!chat.canGoBack).help("Back")
                Button { chat.goForward() } label: { Image(systemName: "arrow.right") }
                    .disabled(!chat.canGoForward).help("Forward")
            }
            .sharedBackgroundVisibility(.hidden)
            ToolbarItem(placement: .principal) {
                HStack(spacing: 7) {
                    SkwodLogoTile(size: 18)
                    Text(app.current?.displayName ?? "Skwod")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Color(white: 0.92))
                    ConnectionPill()
                }
            }
            .sharedBackgroundVisibility(.hidden)
        }
        .toolbarBackground(.hidden, for: .windowToolbar)
        .frame(minWidth: 940, minHeight: 640)
        .overlay(alignment: .top) {
            VStack(spacing: 6) {
                UpdateBanner()
                JoinStatusBanner(chat: chat)
            }
        }
        // Someone is calling: banner + ring sound, in this window only (never a notification).
        .overlay(alignment: .top) { IncomingCallBanner().animation(.snappy, value: app.incomingCall) }
        .sheet(item: $app.activeCall) { target in
            DismissableSheet(doneTitle: "Leave") { CallView(serverId: target.serverId) }
                .environmentObject(chat).environmentObject(app)
        }
        .task { await setup() }
        .task(id: app.pendingJoinTick) { await runPendingJoin() }
        .onChange(of: app.current?.id) { _, _ in Task { await chat.loadIfNeeded(); await UploadLimitSync.refresh(app, force: true) } }
        // The host's limit is asked once the skwod is REACHABLE (its base URL is empty while a
        // switch is still dialing, and nothing is asked of anyone then).
        .onChange(of: app.serverURL) { _, base in if !base.isEmpty { Task { await UploadLimitSync.refresh(app, force: true) } } }
        .onChange(of: chat.selection) { old, _ in chat.recordNavigation(from: old) }
        .tint(.skAccent)
        // Right after "Start server" (and from the menu bar): the invite to send friends.
        .sheet(isPresented: $host.showInvitePanel) {
            DismissableSheet { HostInvitePanel().environmentObject(chat).environmentObject(app) }
        }
        #else
        // iPhone: NO tab bar. The channel page carries the server
        // rail and the floating you-bar; the chat page is full-screen (rail slides away with it).
        // DMs live behind the skwod rail icon, the Feed behind its rail icon, You behind the you-bar.
        DrawerPager()
            .environmentObject(chat)
            .tint(.skAccent)
            .overlay(alignment: .top) {
                VStack(spacing: 6) {
                    UpdateBanner()
                    ConnectionBanner()
                    JoinStatusBanner(chat: chat)
                }
            }
            .task { await setup() }
            .task(id: app.pendingJoinTick) { await runPendingJoin() }
            .onChange(of: app.current?.id) { _, _ in Task { await chat.loadIfNeeded(); await UploadLimitSync.refresh(app, force: true) } }
            .onChange(of: app.serverURL) { _, base in if !base.isEmpty { Task { await UploadLimitSync.refresh(app, force: true) } } }
            // A call push woke the app and several skwods say they are ringing: the user says
            // which call this is. The app never picks one for them.
            .confirmationDialog("Who's calling?", isPresented: Binding(get: { !app.ringChoices.isEmpty }, set: { if !$0 { app.ringChoices = [] } }),
                                titleVisibility: .visible) {
                ForEach(app.ringChoices) { choice in
                    Button(choice.skwod) { Task { await CallCoordinator.shared.chose(choice) } }
                }
                Button("None of these", role: .cancel) { CallCoordinator.shared.decline() }
            } message: {
                Text("More than one of your Skwods reports an incoming call. Pick the one you expect.")
            }
            // The call: opened from the Voice row, or by answering on the system call screen.
            .sheet(item: $app.activeCall) { target in
                DismissableSheet(doneTitle: "Leave") { CallView(serverId: target.serverId) }
                    .environmentObject(chat).environmentObject(app)
            }
        #endif
    }

    /// Join a server with the invite code carried over from sign-up — or from an invite opened
    /// while already a member of that skwod. Clears the code first, so it runs at most once.
    private func runPendingJoin() async {
        guard let code = app.pendingJoinCode else { return }
        app.pendingJoinCode = nil
        for _ in 0..<60 where app.client == nil {
            try? await Task.sleep(for: .milliseconds(250))
        }
        _ = await chat.joinByCode(code, afterSignup: true)
    }

    /// A join that was started earlier and never finished — the app was closed between sign-up
    /// and joining, or before the host let us in. The code was kept; carry on from where it was.
    private func resumeJoin() async {
        for _ in 0..<60 where app.client == nil {
            try? await Task.sleep(for: .milliseconds(250))
        }
        await chat.resumePendingJoin()
    }

    private func setup() async {
        chat.bind(app)
        await chat.loadIfNeeded(openLastChannel: true)   // launch → land on your last channel
        Task { await UploadLimitSync.refresh(app, force: true) }   // the host's per-file limit
        #if DEBUG
        let driver = Task { await E2E.drive(app: app, chat: chat) }
        defer { driver.cancel() }
        #endif
        // Fresh sign-up: run the actual server join with the invite code the user signed up with —
        // membership, host-provisioned keys, and channel discovery all hang off this. The E2EE
        // client is still attaching in the background right after sign-in, so wait for it first
        // (the silent race here is exactly what left joiners with an empty sidebar).
        await runPendingJoin()
        await resumeJoin()
        // Returning member with an empty sidebar (re-login / reinstall): recover memberships —
        // no invite code needed, the host just re-provisions this device. Same client-attach race
        // as the join path above: recovery needs the E2EE client, so wait for it first.
        if chat.spaces.isEmpty {
            for _ in 0..<60 where app.client == nil {
                try? await Task.sleep(for: .milliseconds(250))
            }
            await chat.recoverMemberships()
        }
        // Keep discovering channels the host adds to our servers after we joined.
        // Screenshot/demo aid: seed a space so the drawer has a channel to show. The short wait lets
        // the mock workspace's loadIfNeeded settle first (it resets the lists on activate).
        // SKWOD_DEMO_SPACE=1 → list page; =chat → start on the chat page.
        if let demo = ProcessInfo.processInfo.environment["SKWOD_DEMO_SPACE"] {
            try? await Task.sleep(for: .milliseconds(400))
            let s = RealSpace(name: "Weekend Crew", channelName: "general", serverId: "demo",
                              channelId: "demo", inviteCode: "", spaceKeyHex: "")
            chat.spaces = [s]
            #if DEBUG
            chat.setDemo(dms: [
                DMConversation(name: "bailey", peerUserId: "u1", peerDeviceId: "d1", conversationId: "c1"),
                DMConversation(name: "cove", peerUserId: "u2", peerDeviceId: "d2", conversationId: "c2"),
                DMConversation(name: "río", peerUserId: "u3", peerDeviceId: "d3", conversationId: "c3"),
            ])
            #endif
            if demo == "home" { chat.showHome() }
            else { chat.selection = demo == "chat" ? .space(s) : nil }
            return
        }
        // Periodic channel discovery, LAST so it owns the rest of setup()'s task lifetime — SwiftUI
        // cancels the enclosing `.task` on view teardown / workspace switch, so this loop stops with
        // it (a detached Task here would leak and spin forever after sign-out).
        // The server announces channel and membership changes (`channels_changed`,
        // `member_joined` → `AppState.realtimeEvent`), so this is only the slow safety net.
        while !Task.isCancelled {
            await chat.syncServerChannels()
            try? await Task.sleep(for: .seconds(60))
        }
    }
}

#if os(macOS)
/// The floating bottom-left user panel, spanning the rail + sidebar: avatar with presence
/// dot, username + Online, then mic / deafen / settings. Mic + deafen are local toggles (voice
/// isn't wired yet) so the affordances are in place without pretending to transmit.
private struct UserPanel: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var showProfile = false
    @State private var myName = "You"
    @AppStorage("skwod.myStatus") private var myStatus = "online"
    @AppStorage("skwod.micMuted") private var micMuted = false
    @AppStorage("skwod.deafened") private var deafened = false

    var body: some View {
        HStack(spacing: 4) {
            Menu {
                StatusMenuItems(current: $myStatus)
                Divider()
                Button { showProfile = true } label: { Label("Profile", systemImage: "person.crop.circle") }
            } label: {
                HStack(spacing: 9) {
                    ZStack(alignment: .bottomTrailing) {
                        AvatarImage(key: (app.session?.userId).map(AvatarStore.userKey), name: myName, size: 32)
                        Circle().fill(PresenceStyle.color(myStatus))
                            .frame(width: 10, height: 10)
                            .overlay(Circle().strokeBorder(.black.opacity(0.7), lineWidth: 2))
                            .offset(x: 1, y: 1)
                    }
                    VStack(alignment: .leading, spacing: 1) {
                        Text(myName).font(.system(size: 13, weight: .semibold)).foregroundStyle(Color(white: 0.95))
                            .lineLimit(1)
                        Text(PresenceStyle.label(myStatus)).font(.system(size: 10)).foregroundStyle(Color(white: 0.55))
                    }
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .menuStyle(.button).menuIndicator(.hidden).buttonStyle(.plain)
            PanelIcon(system: micMuted ? "mic.slash.fill" : "mic.fill", active: micMuted,
                      help: micMuted ? "Unmute" : "Mute") { micMuted.toggle() }
            PanelIcon(system: "headphones", active: deafened,
                      help: deafened ? "Undeafen" : "Deafen") { deafened.toggle() }
            PanelIcon(system: "gearshape.fill", active: false, help: "Settings") { showProfile = true }
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .onChange(of: myStatus) { _, _ in Task { await app.heartbeatPresence() } }
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(.white.opacity(0.07), lineWidth: 1))
        .shadow(color: .black.opacity(0.35), radius: 8, y: 2)
        .frame(width: 72 + 252 - 16)   // span the rail + sidebar, inset by the margins
        .padding(8)
        .sheet(isPresented: $showProfile) { DismissableSheet { ProfileView() } }
        .task(id: chat.spaces.map(\.serverId)) { await loadMyName() }
    }

    /// Resolve my public username from the member list of any space I'm in.
    private func loadMyName() async {
        guard let client = app.client, let me = app.session?.userId else { return }
        for sid in Set(chat.spaces.map(\.serverId)) where !sid.isEmpty {
            if let members = try? await client.listMembers(serverId: sid),
               let mine = members.first(where: { $0.userId == me }) {
                myName = mine.username
                return
            }
        }
    }
}

/// One hoverable icon button in the user panel; `active` renders red (muted/deafened state).
private struct PanelIcon: View {
    let system: String
    let active: Bool
    let help: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Image(systemName: system)
                .font(.system(size: 14))
                .foregroundStyle(active ? Color(red: 0.95, green: 0.35, blue: 0.35) : Color(white: hovering ? 0.9 : 0.62))
                .frame(width: 30, height: 30)
                .background(hovering ? Color.white.opacity(0.07) : .clear, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help(help)
    }
}
#endif

/// Where an unfinished join stands: waiting for the host, setting up keys (and why that is
/// slow), declined, or failed. Shown over the shell until the channels appear — a join used to
/// be invisible between "request sent" and the sidebar filling in.
struct JoinStatusBanner: View {
    @ObservedObject var chat: ChatModel

    var body: some View {
        if let status = chat.joinStatus {
            HStack(alignment: .top, spacing: 10) {
                switch status {
                case .waitingForApproval, .settingUp:
                    ProgressView().controlSize(.small).tint(.white).padding(.top, 2)
                case .denied, .failed:
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(title(status)).font(.system(size: 13, weight: .semibold)).foregroundStyle(.white)
                    Text(detail(status)).font(.system(size: 11.5)).foregroundStyle(.white.opacity(0.7))
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 6)
                Button(dismissLabel(status)) {
                    switch status {
                    case .waitingForApproval, .settingUp: chat.dismissJoinStatus(forget: true)
                    case .denied, .failed: chat.dismissJoinStatus(forget: false)
                    }
                }
                .font(.system(size: 11.5, weight: .semibold)).buttonStyle(.plain).foregroundStyle(.skAccent)
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.white.opacity(0.12), lineWidth: 1))
            .frame(maxWidth: 520)
            .padding(.horizontal, 12).padding(.top, 6)
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("join.status")
        }
    }

    private func title(_ s: ChatModel.JoinStatus) -> String {
        switch s {
        case .waitingForApproval: return "Waiting for the host to let you in"
        case .settingUp: return "You're in — setting up your channels"
        case .denied: return "The host declined your request"
        case .failed: return "Couldn't join"
        }
    }

    private func detail(_ s: ChatModel.JoinStatus) -> String {
        switch s {
        case .waitingForApproval:
            return "Your request was sent. The channels appear here as soon as they approve it — no need to restart."
        case .settingUp(let problem):
            return problem ?? "Fetching this server's encryption keys from a member who is online."
        case .denied:
            return "Ask them for a new invite if you think that was a mistake."
        case .failed(let why):
            return why
        }
    }

    private func dismissLabel(_ s: ChatModel.JoinStatus) -> String {
        switch s {
        case .waitingForApproval, .settingUp: return "Stop waiting"
        case .denied, .failed: return "OK"
        }
    }
}

/// The chat detail pane: shows the selected space channel or DM, or a friendly empty state.
private struct DetailPane: View {
    @EnvironmentObject private var chat: ChatModel

    var body: some View {
        Group {
            switch chat.selection {
            case .home: DMHomeView()
            case .feed: FeedView().environmentObject(chat)
            case .space(let s): SpaceChannelView(space: s)
            case .dm(let d): DMChatView(convo: d)
        case .group(let g): GroupChatView(group: g)
            case .group(let g): GroupChatView(group: g)
            case .none:
                // Home → DMs; in a skwod → the overview (channel boxes for the selected server / all).
                if chat.homeMode { DMHomeView() } else { ChannelBoxesView() }
            }
        }
    }
}

/// The skwod overview's main pane: the selected server's channels as clickable boxes (or every
/// server's, grouped, when "All channels" is chosen). Clicking a box opens that channel's chat.
private struct ChannelBoxesView: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var showCreate = false

    private var groups: [ServerGroup] {
        chat.railServerId == nil ? chat.serverGroups : chat.serverGroups.filter { $0.serverId == chat.railServerId }
    }

    var body: some View {
        ZStack {
            DetailGlass()
            if chat.serverGroups.isEmpty {
                emptyState
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        ForEach(groups) { g in
                            VStack(alignment: .leading, spacing: 12) {
                                Text(g.name).font(.title3.bold()).foregroundStyle(.white)
                                LazyVGrid(columns: [GridItem(.adaptive(minimum: 200), spacing: 14)], alignment: .leading, spacing: 14) {
                                    ForEach(g.channels) { s in
                                        Button { chat.openChannel(s) } label: { ChannelBox(name: s.channelName) }
                                            .buttonStyle(.plain)
                                    }
                                }
                            }
                        }
                    }
                    .padding(28).frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .sheet(isPresented: $showCreate) { CreateSpaceSheet { chat.addSpace($0) } }
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Image(systemName: "square.grid.2x2").font(.system(size: 42)).foregroundStyle(.white.opacity(0.5))
            Text("No servers yet").font(.title2.bold()).foregroundStyle(.white)
            Text("Create your first server to add channels your friends can join.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
            if app.canCreateServers {
                Button { showCreate = true } label: {
                    Label("Create a server", systemImage: "plus").padding(.horizontal, 8).padding(.vertical, 2)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            }
        }
        .padding(40).frame(maxWidth: 360)
    }
}

/// A single channel card in the overview grid.
private struct ChannelBox: View {
    let name: String
    @State private var hovering = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "number").font(.system(size: 14, weight: .semibold)).foregroundStyle(.white.opacity(0.55))
                Text(name).font(.system(size: 15, weight: .semibold)).foregroundStyle(.white).lineLimit(1)
            }
            Spacer(minLength: 0)
            Text("Open channel").font(.caption).foregroundStyle(.skAccent)
        }
        .padding(14).frame(height: 92, alignment: .topLeading).frame(maxWidth: .infinity, alignment: .leading)
        .background(.white.opacity(hovering ? 0.09 : 0.05), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(.white.opacity(0.08)))
        .onHover { hovering = $0 }
    }
}

/// The DMs / Friends home behind the skwod rail icon: a warm landing that lists your direct
/// conversations and lets you start a new one. DMs are per-server identities (each workspace is a
/// separate self-hosted server), so this shows the active workspace's conversations.
private struct DMHomeView: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var showNewDM = false
    @State private var showNewGroup = false
    @State private var people: [MemberInfo] = []
    @State private var opening: String?
    /// Bumped on live presence events so the people strip's dots recompute (Realtime is nested).
    @State private var presenceTick = 0

    var body: some View {
        ZStack {
            let _ = presenceTick
            DetailGlass()
            VStack(alignment: .leading, spacing: 0) {
                header
                Divider().overlay(.white.opacity(0.08))
                ScrollView {
                    if !people.isEmpty { peopleStrip }
                    if chat.dms.isEmpty && chat.groups.isEmpty && chat.pendingGroups.isEmpty && !chat.hasConversationNotices {
                        emptyState
                    } else {
                        LazyVStack(spacing: 6) {
                            GroupInvitations()
                            ForEach(chat.groups) { g in
                                Button { chat.selection = .group(g) } label: { GroupRow(group: g) }
                                    .buttonStyle(.plain)
                                    .muteMenu(scope: "dm:\(g.conversationId)")
                            }
                            ForEach(chat.dms) { dm in
                                Button { chat.selection = .dm(dm) } label: { DMHomeRow(dm: dm) }
                                    .buttonStyle(.plain)
                                    .muteMenu(scope: "dm:\(dm.conversationId)")
                            }
                        }
                        .padding(16)
                    }
                }
            }
        }
        .task { await loadPeople() }
        .onReceive(app.realtime.$presence) { _ in presenceTick &+= 1 }
        .sheet(isPresented: $showNewDM) { DismissableSheet { NewDMSheet() } }
        .sheet(isPresented: $showNewGroup) { NewGroupSheet { await chat.startGroupReportingProblem(with: $0) } }
    }

    /// A horizontal strip of people you share a space with — tap to open (or start) a DM. Mirrors the
    /// reference app's member avatars above the conversation list.
    private var peopleStrip: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("People").font(.caption.weight(.semibold)).textCase(.uppercase)
                .foregroundStyle(.secondary).padding(.horizontal, 16).padding(.top, 12)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 16) {
                    ForEach(people, id: \.userId) { m in
                        Button { Task { await openDM(with: m) } } label: {
                            VStack(spacing: 6) {
                                ZStack(alignment: .bottomTrailing) {
                                    AvatarImage(key: AvatarStore.userKey(m.userId), name: app.contacts.display(m.userId, claimedName: m.username).text, size: 54)
                                    if opening == m.userId {
                                        Circle().fill(.black.opacity(0.4)).frame(width: 54, height: 54)
                                        ProgressView().tint(.white)
                                    }
                                    Circle().fill(PresenceStyle.color(app.realtime.status(userId: m.userId)))
                                        .frame(width: 14, height: 14)
                                        .overlay(Circle().strokeBorder(.black.opacity(0.7), lineWidth: 2))
                                        .offset(x: -1, y: -1)
                                }
                                // The name as the contact book allows it, with its marker — not
                                // whatever the server's member list says.
                                let shown = app.contacts.display(m.userId, claimedName: m.username)
                                Text(shown.text).font(.caption).foregroundStyle(.white.opacity(0.7)).lineLimit(1)
                                TrustBadge(badge: shown.badge, compact: true)
                            }
                            .frame(width: 74)
                        }.buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 16)
            }
        }
    }

    /// Gather the members of every space you're in (deduped, excluding yourself).
    private func loadPeople() async {
        guard let client = app.client else { return }
        let me = app.session?.userId
        let serverIds = Set(chat.spaces.map(\.serverId)).filter { !$0.isEmpty }
        var byId: [String: MemberInfo] = [:]
        for sid in serverIds {
            if let members = try? await client.listMembers(serverId: sid) {
                for m in members where m.userId != me { byId[m.userId] = m }
            }
        }
        people = byId.values.sorted { $0.username < $1.username }
    }

    /// Open (or create) a DM with a person, resolving their device via a username lookup.
    private func openDM(with m: MemberInfo) async {
        guard app.client != nil, opening == nil else { return }
        opening = m.userId
        defer { opening = nil }
        // If we already have this conversation, just select it.
        // Matched by ACCOUNT, never by name — and an existing conversation is only shown:
        // tapping someone in the strip must not make them a trusted contact.
        if let existing = chat.dms.first(where: { $0.peerUserId == m.userId }) {
            chat.selection = .dm(existing); return
        }
        // Asked and stored in the workspace that is current now; a refusal is said in the
        // list (`ConversationNotices`) — a lookup that simply fails stays quiet, as before.
        let outcome = await chat.openDM(username: m.username, expecting: m.userId)
        if outcome == .refused || outcome == .ignoredGroup { chat.conversationProblem = outcome.problem }
    }

    private var header: some View {
        HStack {
            Image(systemName: "bubble.left.and.text.bubble.right.fill").font(.title3).foregroundStyle(.skAccent)
            Text("Direct Messages").font(.system(size: 18, weight: .bold)).foregroundStyle(.white)
            Spacer()
            Button { showNewGroup = true } label: {
                Image(systemName: "person.3.fill").font(.system(size: 14, weight: .semibold))
            }.buttonStyle(.glass).tint(.skAccent).help("New group").accessibilityLabel("New group")
            Button { showNewDM = true } label: {
                Image(systemName: "square.and.pencil").font(.system(size: 16, weight: .semibold))
            }.buttonStyle(.glass).tint(.skAccent).help("New message")
        }
        .padding(.horizontal, 20).padding(.vertical, 14)
    }

    private var emptyState: some View {
        VStack(spacing: 14) {
            Spacer()
            Image(systemName: "person.2.circle").font(.system(size: 56)).foregroundStyle(.white.opacity(0.25))
            Text("No conversations yet").font(.title3.weight(.semibold)).foregroundStyle(.white.opacity(0.7))
            Text("Start an end-to-end encrypted DM with anyone on this server.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.45)).multilineTextAlignment(.center)
            Button { showNewDM = true } label: {
                Label("Start a message", systemImage: "square.and.pencil").padding(.horizontal, 6).padding(.vertical, 2)
            }.controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black).padding(.top, 4)
            Spacer()
        }
        .frame(maxWidth: .infinity).padding(40)
    }
}

/// A single conversation row in the DM home: avatar, name, and an encrypted hint.
private struct DMHomeRow: View {
    let dm: DMConversation
    @EnvironmentObject private var app: AppState
    @State private var presenceTick = 0

    var body: some View {
        let status = app.realtime.status(userId: dm.peerUserId)
        // The name as this device may show it: plain for a known contact, marked otherwise.
        let shown = app.contacts.display(dm.peerUserId, claimedName: dm.name)
        HStack(spacing: 12) {
            ZStack(alignment: .bottomTrailing) {
                AvatarImage(key: AvatarStore.userKey(dm.peerUserId), name: shown.text, size: 40)
                Circle().fill(PresenceStyle.color(status)).frame(width: 12, height: 12)
                    .overlay(Circle().strokeBorder(.black.opacity(0.7), lineWidth: 2))
                    .offset(x: 1, y: 1)
            }
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(shown.text).font(.system(size: 15, weight: .semibold)).foregroundStyle(.white).lineLimit(1)
                    TrustBadge(badge: shown.badge)
                }
                Text(status == "offline" ? "end-to-end encrypted" : PresenceStyle.label(status))
                    .font(.caption)
                    .foregroundStyle(status == "offline" ? .white.opacity(0.4) : PresenceStyle.color(status).opacity(0.9))
            }
            Spacer()
            Image(systemName: "chevron.right").font(.caption).foregroundStyle(.white.opacity(0.25))
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .onReceive(app.realtime.$presence) { _ in presenceTick &+= 1 }
    }
}

/// Shown in the detail pane before anything is selected.
private struct EmptyChatState: View {
    var body: some View {
        ZStack {
            DetailGlass()
            VStack(spacing: 14) {
                Image(systemName: "bubble.left.and.bubble.right")
                    .font(.system(size: 54)).foregroundStyle(.white.opacity(0.25))
                Text("Pick a channel or DM").font(.title3.weight(.semibold)).foregroundStyle(.white.opacity(0.7))
                Text("Your conversations are end-to-end encrypted.")
                    .font(.subheadline).foregroundStyle(.white.opacity(0.4))
            }
        }
    }
}

#if os(iOS)
/// The reference app's signature horizontal drawer: page 0 is the channel/DM list, page 1 is the
/// chat. Selecting a channel slides to the chat; swiping right reveals the list again. Uses native
/// paging so the gesture feels like the RN app's `pagingEnabled` ScrollView.
/// Dismiss the software keyboard (iOS) by resigning first responder app-wide. No-op on macOS.
private func dismissKeyboard() {
    #if os(iOS)
    UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
    #endif
}

private struct DrawerPager: View {
    @EnvironmentObject private var chat: ChatModel
    /// The page currently under the viewport — bound to the scroll so a swipe (not just a tap)
    /// updates it. Selecting a channel drives it to `.chat`. Selection is left intact on swipe-back
    /// so the chat stays loaded behind the list. The rail + you-bar belong to the LIST page only —
    /// the chat page is full-screen.
    @State private var page: DrawerPage? = .list

    var body: some View {
        GeometryReader { geo in
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 0) {
                    ZStack(alignment: .bottom) {
                        HStack(spacing: 0) {
                            ServerRailView(chat: chat)
                            DrawerList()
                        }
                        MobileYouBar()
                    }
                    .frame(width: geo.size.width).id(DrawerPage.list)
                    DrawerChat().frame(width: geo.size.width).id(DrawerPage.chat)
                }
                .scrollTargetLayout()
            }
            .scrollTargetBehavior(.paging)
            .scrollPosition(id: $page)
            .onChange(of: chat.selection) { _, sel in
                withAnimation(.snappy(duration: 0.28)) { page = sel == nil ? .list : .chat }
            }
            // Both pages stay mounted for the paging swipe, so the chat's composer field can keep
            // the keyboard up behind the channel list. Whenever the visible page isn't the chat,
            // resign first responder — the keyboard only belongs to the open conversation.
            .onChange(of: page) { _, p in
                if p != .chat { dismissKeyboard() }
            }
        }
        // One shared glass backdrop under both pages, with the dark chrome veil over it — the same
        // three contrast steps as macOS (rail bare on chrome, drawer +1 lift, chat lightest).
        .background {
            ZStack {
                SkwodBackground()
                Color.black.opacity(0.28)
            }
            .ignoresSafeArea()
        }
    }
}

/// The floating user pill at the bottom of the channel page: your avatar with the
/// presence dot, name + Online, and a bell — tap anywhere to open your profile/settings.
private struct MobileYouBar: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var showProfile = false
    @State private var myName = "You"

    @AppStorage("skwod.myStatus") private var myStatus = "online"

    var body: some View {
        Menu {
            StatusMenuItems(current: $myStatus)
            Divider()
            Button { showProfile = true } label: { Label("Profile", systemImage: "person.crop.circle") }
        } label: {
            HStack(spacing: 10) {
                ZStack(alignment: .bottomTrailing) {
                    AvatarImage(key: (app.session?.userId).map(AvatarStore.userKey), name: myName, size: 36)
                    Circle().fill(PresenceStyle.color(myStatus)).frame(width: 11, height: 11)
                        .overlay(Circle().strokeBorder(.black.opacity(0.7), lineWidth: 2))
                        .offset(x: 1, y: 1)
                }
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 4) {
                        Text(myName).font(.system(size: 15, weight: .semibold)).foregroundStyle(.white)
                        Image(systemName: "chevron.down").font(.system(size: 10, weight: .bold)).foregroundStyle(.white.opacity(0.5))
                    }
                    Text(PresenceStyle.label(myStatus)).font(.caption2).foregroundStyle(.white.opacity(0.5))
                }
                Spacer()
                // How we're connected, at a glance (green = direct, yellow = via a relay, red =
                // host offline). The full explanation is in Profile → Privacy.
                HStack(spacing: 5) {
                    Circle().fill(app.connection.color).frame(width: 8, height: 8)
                    Text(app.connection.title).font(.caption2).foregroundStyle(.white.opacity(0.6)).lineLimit(1)
                }
                .accessibilityElement(children: .combine)
                Image(systemName: "bell").font(.system(size: 17)).foregroundStyle(.white.opacity(0.75))
                    .frame(width: 38, height: 38)
                    .background(.white.opacity(0.07), in: Circle())
            }
            .padding(.horizontal, 14).padding(.vertical, 10)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(.white.opacity(0.08), lineWidth: 1))
            .padding(.horizontal, 10).padding(.bottom, 4)
        }
        .menuStyle(.button).menuIndicator(.hidden).buttonStyle(.plain)
        .onChange(of: myStatus) { _, _ in Task { await app.heartbeatPresence() } }
        .sheet(isPresented: $showProfile) { DismissableSheet { ProfileView() } }
        .task(id: chat.spaces.map(\.serverId)) { await loadMyName() }
    }

    private func loadMyName() async {
        guard let client = app.client, let me = app.session?.userId else { return }
        for sid in Set(chat.spaces.map(\.serverId)) where !sid.isEmpty {
            if let members = try? await client.listMembers(serverId: sid),
               let mine = members.first(where: { $0.userId == me }) {
                myName = mine.username
                return
            }
        }
    }
}

private enum DrawerPage: Hashable { case list, chat }

/// Page 1 of the drawer: the selected chat/DM/home, or an empty prompt. No NavigationStack, so the
/// chat surface's own header shows (no double bar); back is the horizontal swipe.
private struct DrawerChat: View {
    @EnvironmentObject private var chat: ChatModel
    var body: some View {
        switch chat.selection {
        case .home: DMHomeView().environmentObject(chat)
        case .feed: FeedView().environmentObject(chat)
        case .space(let s): SpaceChannelView(space: s)
        case .dm(let d): DMChatView(convo: d)
        case .group(let g): GroupChatView(group: g)
        case .none: EmptyChatState()
        }
    }
}

/// Page 0 of the drawer: the workspace's channels — server-name dropdown with
/// an invite affordance, then a collapsible TEXT CHANNELS category. DMs live behind the home rail
/// icon and the Messages tab, not in the server list. Mobile is JOIN-only: hosting (and therefore
/// creating spaces) is a Mac capability, so the only affordances here are invite + join-with-code.
private struct DrawerList: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var showJoin = false
    @State private var showRestoreBackup = false
    @State private var showInvite = false
    @State private var showSkwodSettings = false
    @State private var showCreate = false
    @State private var query = ""
    @State private var newChannelTarget: ServerRef?
    @State private var rolesTarget: ServerRef?

    var body: some View {
        Group {
            if chat.homeMode {
                // Home (skwod icon) → your Direct Messages.
                DMHomeView()
            } else {
                channelList
            }
        }
        .sheet(isPresented: $showJoin) { JoinSpaceSheet(chat: chat) }
        .sheet(isPresented: $showRestoreBackup) { RestoreWithKeySheet() }
        .sheet(isPresented: $showInvite) {
            if let s = inviteSpace { DismissableSheet { SecureJoinView(space: s) } }
        }
        .sheet(isPresented: $showSkwodSettings) { DismissableSheet { ServerSettingsSheet() } }
        .sheet(isPresented: $showCreate) { CreateSpaceSheet { chat.addSpace($0) } }
        .sheet(item: $newChannelTarget) { srv in NewChannelSheet(server: srv, chat: chat) }
        .sheet(item: $rolesTarget) { srv in DismissableSheet { RolesSheet(server: srv) } }
    }

    /// The space to invite people into: the selected one, else the first.
    private var inviteSpace: RealSpace? {
        if case .space(let s) = chat.selection { return s }
        return chat.spaces.first
    }

    private var channelList: some View {
        ZStack {
            SidebarGlass()
            VStack(spacing: 0) {
                // Header: a back-to-servers chevron when inside a server, then a
                // "Name ›" dropdown (server name in a server, skwod name in the overview). Pinned
                // above the scroll on the same frosted glass as the panel — no separate color band.
                HStack(spacing: 8) {
                    if chat.inChannelsMode {
                        Button { chat.showServerBoxes(nil) } label: {
                            Image(systemName: "chevron.left").font(.system(size: 16, weight: .bold))
                                .foregroundStyle(.white.opacity(0.85))
                        }.buttonStyle(.plain)
                    }
                    Menu {
                        if inviteSpace != nil {
                            Button { showInvite = true } label: { Label("Invite people", systemImage: "person.badge.plus") }
                        }
                        Button { showSkwodSettings = true } label: { Label("Skwod settings", systemImage: "gearshape") }
                        if let sp = inviteSpace {
                            Button { rolesTarget = ServerRef(serverId: sp.serverId, name: sp.name) } label: {
                                Label("Manage permissions", systemImage: "checkmark.shield")
                            }
                        }
                        Divider()
                        if app.canCreateServers {
                            Button { showCreate = true } label: { Label("Create a server", systemImage: "plus") }
                        }
                        Button { showJoin = true } label: { Label("Join with a code", systemImage: "ticket") }
                    } label: {
                        HStack(spacing: 7) {
                            Text(chat.inChannelsMode ? (chat.currentServer?.name ?? app.current?.displayName ?? "Skwod")
                                                     : (app.current?.displayName ?? "Skwod"))
                                .font(.title2.bold()).foregroundStyle(.white).lineLimit(1)
                            Image(systemName: "chevron.right")
                                .font(.system(size: 14, weight: .semibold)).foregroundStyle(.white.opacity(0.5))
                        }
                    }
                    Spacer()
                }
                .padding(.horizontal, 12).padding(.top, 8).padding(.bottom, 8)

                ScrollView {
                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 10) {
                        HStack(spacing: 7) {
                            Image(systemName: "magnifyingglass").foregroundStyle(.white.opacity(0.5))
                            TextField("Search", text: $query)
                                .textFieldStyle(.plain).foregroundStyle(.white)
                                .textInputAutocapitalization(.never).autocorrectionDisabled()
                        }
                        .padding(.horizontal, 12).padding(.vertical, 9)
                        .background(.white.opacity(0.07), in: Capsule())
                        Button { showInvite = true } label: {
                            Image(systemName: "person.badge.plus")
                                .font(.system(size: 15, weight: .semibold)).foregroundStyle(.white.opacity(0.8))
                                .frame(width: 38, height: 38)
                                .background(.white.opacity(0.07), in: Circle())
                        }
                        .disabled(inviteSpace == nil)
                    }
                    .padding(.horizontal, 12).padding(.top, 10).padding(.bottom, 14)

                    // skwod → servers → channels. Overview lists the servers; tapping one drills into
                    // its channels (mobile uses a list, not the desktop boxes grid).
                    if chat.spaces.isEmpty {
                        if chat.provisioning {
                            HStack(spacing: 8) {
                                ProgressView().controlSize(.small).tint(.white)
                                Text("Setting up your channels…").font(.caption).foregroundStyle(.secondary)
                            }
                            .padding(.horizontal, 12).padding(.vertical, 10)
                            // Waiting on another member to come online — a passphrase backup skips that.
                            Button { showRestoreBackup = true } label: {
                                Label("Restore from key backup", systemImage: "key.horizontal.fill").font(.caption)
                            }
                            .buttonStyle(.plain).foregroundStyle(.skAccent)
                            .padding(.horizontal, 12).padding(.vertical, 2)
                        } else {
                            // No servers yet: a clear call-to-action, not a buried "+".
                            VStack(spacing: 12) {
                                Image(systemName: "person.3.fill").font(.system(size: 36)).foregroundStyle(.white.opacity(0.4))
                                Text("No servers yet").font(.title3.bold()).foregroundStyle(.white)
                                Text("Join one with an invite code from a friend who hosts a Skwod.")
                                    .font(.caption).foregroundStyle(.white.opacity(0.55)).multilineTextAlignment(.center)
                                Button { showJoin = true } label: {
                                    Label("Join with a code", systemImage: "ticket").padding(.horizontal, 6).padding(.vertical, 2)
                                }
                                .buttonStyle(.glassProminent).tint(.white).foregroundStyle(.black)
                                // Kept in the settled empty state too: the provisioning wait times
                                // out, and a returning member must still be able to restore.
                                Button { showRestoreBackup = true } label: {
                                    Label("Restore from key backup", systemImage: "key.horizontal.fill").font(.caption)
                                }
                                .buttonStyle(.plain).foregroundStyle(.skAccent)
                            }
                            .frame(maxWidth: .infinity).padding(.horizontal, 16).padding(.vertical, 24)
                        }
                    } else if chat.inChannelsMode, let group = chat.currentServer {
                        // Inside a server: its channels.
                        HStack {
                            Text(group.name).font(.subheadline).foregroundStyle(.white.opacity(0.55))
                            Spacer()
                            Button { newChannelTarget = ServerRef(serverId: group.serverId, name: group.name) } label: {
                                Image(systemName: "plus").font(.system(size: 15, weight: .semibold)).foregroundStyle(.white.opacity(0.55))
                            }
                        }
                        .padding(.horizontal, 12).padding(.top, 4).padding(.bottom, 6)
                        ForEach(filteredChannels(group)) { s in
                            Button { chat.openChannel(s) } label: {
                                ChannelCard(name: s.channelName, selected: chat.highlightedChannelId == s.channelId)
                            }.buttonStyle(.plain)
                            .overlay(alignment: .trailing) { MutedMark(key: "channel:\(s.channelId)") }
                            .contextMenu {
                                MuteMenuItems(key: "channel:\(s.channelId)")
                                Button { showInvite = true } label: { Label("Invite people", systemImage: "person.badge.plus") }
                                Button(role: .destructive) { chat.removeSpace(s) } label: {
                                    Label("Remove from list", systemImage: "eye.slash")
                                }
                            }
                        }
                    } else {
                        // Skwod overview: the list of servers. Tapping one opens its channels.
                        HStack {
                            Text("Servers").font(.subheadline).foregroundStyle(.white.opacity(0.55))
                            Spacer()
                        }
                        .padding(.horizontal, 12).padding(.top, 4).padding(.bottom, 6)
                        ForEach(chat.serverGroups) { g in
                            Button { chat.openServer(g) } label: {
                                ServerCard(name: g.name, channels: g.channels.count)
                            }.buttonStyle(.plain)
                        }
                    }
                }
                .padding(.horizontal, 8).padding(.bottom, 90)   // clearance for the floating you-bar
                }
            }
        }
    }

    /// The search pill filters channels across every server.
    private func filteredChannels(_ group: ServerGroup) -> [RealSpace] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return group.channels }
        return group.channels.filter { $0.channelName.localizedCaseInsensitiveContains(q) }
    }
}

/// Mobile channel row: a rounded card with the muted `#` and the channel name.
private struct ChannelCard: View {
    let name: String
    let selected: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "number")
                .font(.system(size: 17, weight: .medium))
                .foregroundStyle(selected ? .white : .white.opacity(0.5))
            Text(name)
                .font(.system(size: 16, weight: selected ? .semibold : .regular))
                .foregroundStyle(selected ? .white : .white.opacity(0.8))
                .lineLimit(1)
            Spacer()
        }
        .padding(.horizontal, 14).padding(.vertical, 13)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(selected ? Color.white.opacity(0.11) : Color.white.opacity(0.045))
        )
        .padding(.horizontal, 4).padding(.vertical, 2)
        .contentShape(Rectangle())
    }
}

/// A server row in the mobile skwod overview: monogram + name + channel count. Tapping it opens the
/// server's channels.
private struct ServerCard: View {
    let name: String
    let channels: Int

    var body: some View {
        HStack(spacing: 12) {
            Text(name.prefix(1).uppercased()).font(.system(size: 15, weight: .bold)).foregroundStyle(.white)
                .frame(width: 36, height: 36)
                .background(Color.seeded(name).gradient, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                Text(name).font(.system(size: 16, weight: .semibold)).foregroundStyle(.white).lineLimit(1)
                Text("\(channels) channel\(channels == 1 ? "" : "s")").font(.caption).foregroundStyle(.white.opacity(0.5))
            }
            Spacer()
            Image(systemName: "chevron.right").font(.system(size: 13, weight: .semibold)).foregroundStyle(.white.opacity(0.35))
        }
        .padding(.horizontal, 14).padding(.vertical, 11)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.white.opacity(0.045)))
        .padding(.horizontal, 4).padding(.vertical, 2)
        .contentShape(Rectangle())
    }
}

/// The Messages tab: your DM conversations, pushing into the E2EE chat.
private struct DMListPage: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @State private var showNewDM = false
    @State private var showNewGroup = false

    var body: some View {
        ZStack {
            DetailGlass()
            ScrollView {
                LazyVStack(spacing: 6) {
                    GroupInvitations()
                    ForEach(chat.groups) { g in
                        NavigationLink {
                            GroupChatView(group: g).toolbar(.hidden, for: .navigationBar)
                        } label: { GroupRow(group: g) }
                            .buttonStyle(.plain)
                            .muteMenu(scope: "dm:\(g.conversationId)")
                    }
                    if chat.dms.isEmpty && chat.groups.isEmpty {
                        Text("No conversations yet — start an encrypted DM.")
                            .font(.subheadline).foregroundStyle(.white.opacity(0.5)).padding(.top, 48)
                    } else {
                        ForEach(chat.dms) { dm in
                            // The chat brings its own header (with back), so the
                            // system navigation bar stays hidden on the pushed screen.
                            NavigationLink {
                                DMChatView(convo: dm).toolbar(.hidden, for: .navigationBar)
                            } label: { DMHomeRow(dm: dm) }
                                .buttonStyle(.plain)
                                .muteMenu(scope: "dm:\(dm.conversationId)")
                        }
                    }
                }
                .padding(16)
            }
        }
        .navigationTitle("Messages")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showNewDM = true } label: { Image(systemName: "square.and.pencil") }
            }
            ToolbarItem(placement: .primaryAction) {
                Button { showNewGroup = true } label: { Image(systemName: "person.3.fill") }
                    .accessibilityLabel("New group")
            }
        }
        .sheet(isPresented: $showNewDM) { NewDMSheet() }
        .sheet(isPresented: $showNewGroup) { NewGroupSheet { await chat.startGroupReportingProblem(with: $0) } }
    }
}
#endif

/// A screen scaffold kept for the non-split views (host wizard, secure-join, etc.) that still push
/// their own navigation stack + large title. `detail: true` for screens hosted in the shell's main
/// pane (e.g. the Feed) — they get the light detail lift instead of a second dark backdrop.
struct SkwodScreen<Content: View>: View {
    let title: String
    var detail = false
    @ViewBuilder var content: Content
    var body: some View {
        NavigationStack {
            ZStack {
                if detail { AnyView(DetailGlass()) } else { AnyView(SkwodBackground()) }
                content
            }
            .navigationTitle(title)
            #if os(iOS)
            .toolbarBackground(.hidden, for: .navigationBar)
            #endif
        }
    }
}


/// Presence palette + labels shared by the user panels and status menus.
enum PresenceStyle {
    /// Green = available, yellow = away, red = DND **and** offline (the dot is always shown).
    static func color(_ status: String) -> Color {
        switch status {
        case "online": return .green
        case "idle": return .yellow
        default: return .red
        }
    }
    static func label(_ status: String) -> String {
        switch status {
        case "online": return "Online"
        case "idle": return "Idle"
        case "dnd": return "Do Not Disturb"
        default: return "Invisible"
        }
    }
}

/// The four presence statuses as menu picks.
struct StatusMenuItems: View {
    @Binding var current: String
    var body: some View {
        ForEach(["online", "idle", "dnd", "offline"], id: \.self) { s in
            Button {
                current = s
            } label: {
                Label(PresenceStyle.label(s), systemImage: current == s ? "checkmark.circle.fill" : "circle.fill")
            }
        }
    }
}
