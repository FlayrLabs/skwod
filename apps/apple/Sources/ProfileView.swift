import SwiftUI
import MusicKit

struct ProfileView: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var updater: Updater
    #if os(macOS)
    @ObservedObject private var sparkle = SparkleUpdater.shared
    #endif
    #if os(iOS)
    /// Which hosts refused wake credentials (too old for push from build 45 on).
    @ObservedObject private var push = PushManager.shared
    #endif
    @State private var showAdd = false
    @State private var showHost = false
    @State private var confirmDeleteAll = false
    @State private var confirmSignOut = false
    @State private var deleteError = ""
    @State private var showAvatarPicker = false
    @State private var backupEnabled = false
    @State private var showLicenses = false
    @State private var showLinkApprove = false
    @State private var showBackupSetup = false
    @State private var showPin = false
    @State private var previewsTick = 0
    @State private var confirmDisableBackup = false
    @State private var showDevices = false
    @State private var showReports = false
    @State private var showErase = false
    @State private var showActivity = false
    @State private var confirmCompromised = false
    @State private var confirmSignOutOne = false
    @State private var forgetting: Workspace?
    @State private var deviceCount: (count: Int, max: Int)?
    @State private var instantFrom: Int64?
    @State private var accountError = ""
    @AppStorage(PrivacySettings.screenSecurityKey) private var screenSecurity = false
    @AppStorage(PrivacySettings.hideInSwitcherKey) private var hideInSwitcher = true
    @AppStorage("skwod.p2p.publicFallback") private var publicFallback = true
    @AppStorage(StoryMusicPolicy.tapToPlayKey) private var storyMusicTapToPlay = false
    @AppStorage(StoryMusicPolicy.fullSongsKey) private var fullSongs = false
    @State private var fullSongsNote = ""

    /// Delete my account server-side ("delete all my data"), then wipe everything locally.
    /// The server cascades: profile, messages, devices, memberships, sessions.
    private func deleteAllData() async {
        // Through the core: the server wants the request signed by this device — a session
        // token alone no longer deletes an account (build 45).
        guard let client = app.client, let me = app.session?.userId else { return }
        do {
            try await client.deleteAccount(userId: me)
            // The account is gone from the server: nothing kept here can be used again.
            app.accountDeleted()
        } catch {
            deleteError = "Couldn't delete your data. The owner of a Skwod can't delete their own account; otherwise check your connection and try again."
        }
    }

    var body: some View {
        SkwodScreen(title: "You") {
            ScrollView {
                VStack(spacing: 18) {
                    header
                    workspacesCard
                    #if os(macOS)
                    hostCard
                    #endif
                    if app.isInstanceOwner || !app.reports.isEmpty { reportsCard }
                    e2eeCard
                    privacyCard
                    aboutCard
                    if let current = app.current {
                        Button { confirmSignOutOne = true } label: {
                            Text("Sign out of \(current.displayName)").frame(maxWidth: .infinity).padding(.vertical, 4)
                        }
                        .controlSize(.large).buttonStyle(.glass).tint(.white.opacity(0.8))
                        .accessibilityIdentifier("profile.signout")
                    }
                    if app.workspaces.filter({ !$0.isSignedOut }).count > 1 {
                        Button { confirmSignOut = true } label: {
                            Text("Sign out of all Skwods").frame(maxWidth: .infinity).padding(.vertical, 4)
                        }
                        .controlSize(.large).buttonStyle(.glass).tint(.white.opacity(0.8))
                    }
                    Button(role: .destructive) { showErase = true } label: {
                        Text("Erase this device…").frame(maxWidth: .infinity).padding(.vertical, 4)
                    }
                    .controlSize(.large).buttonStyle(.glass).tint(.red)
                    .accessibilityIdentifier("profile.erase")

                    Button(role: .destructive) { confirmDeleteAll = true } label: {
                        Text("Delete my account & all data").frame(maxWidth: .infinity).padding(.vertical, 4)
                    }
                    .controlSize(.large).buttonStyle(.glass).tint(.red)
                    if !deleteError.isEmpty {
                        Text(deleteError).font(.caption).foregroundStyle(.orange)
                    }
                }
                .padding()
            }
            .confirmationDialog("Sign out of all Skwods?",
                                isPresented: $confirmSignOut, titleVisibility: .visible) {
                Button("Sign out") { app.signOut() }
            } message: {
                Text("Your messages and keys stay on this device, locked. Sign in again with your password to carry on where you left off — no relinking.")
            }
            .confirmationDialog("Sign out of \(app.current?.displayName ?? "this Skwod")?",
                                isPresented: $confirmSignOutOne, titleVisibility: .visible) {
                Button("Sign out") { app.leaveCurrent() }
            } message: {
                Text("Your messages and keys stay on this device, locked. Sign in again with your password to carry on where you left off — no relinking.")
            }
            .confirmationDialog("Remove \(forgetting?.displayName ?? "this Skwod") from this device?",
                                isPresented: Binding(get: { forgetting != nil }, set: { if !$0 { forgetting = nil } }),
                                titleVisibility: .visible) {
                Button("Delete its messages and keys here", role: .destructive) { if let w = forgetting { app.forgetLocally(w) } }
            } message: {
                Text("You're signed out of it, so only this device's copy is deleted. This device stays listed on your account there until you remove it from another device. Without a recovery key or another device, its messages can't be brought back.")
            }
            .sheet(isPresented: $showErase) { EraseDeviceSheet() }
            .confirmationDialog("Delete your account and all data?",
                                isPresented: $confirmDeleteAll, titleVisibility: .visible) {
                Button("Delete everything", role: .destructive) { Task { await deleteAllData() } }
            } message: {
                Text("Removes your account, messages, devices, and memberships from the active server, then wipes this device's local data. This cannot be undone. (A server owner must transfer or shut down their Skwod instead.)")
            }
            .sheet(isPresented: $showAdd) { AddWorkspaceSheet() }
            #if os(macOS)
            .sheet(isPresented: $showHost) { DismissableSheet { HostWizardView(onSignedIn: { showHost = false }) } }
            #endif
        }
    }

    #if os(macOS)
    /// Hosting is a Mac-only capability: run a server for your friends from this machine.
    private var hostCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Your own server", systemImage: "server.rack")
            Text("Run your own Skwod on this Mac so friends can join. One click — no account, no domain, and this Mac only ever stores ciphertext.")
                .font(.caption).foregroundStyle(.white.opacity(0.55))
            if HostManager.shared.phase == .running {
                Button {
                    // No owner account on this Mac yet (the server was started from the menu
                    // bar): the invite needs the setup first — the same wizard, opened here.
                    if HostManager.shared.hasOwnerWorkspace { HostManager.shared.requestInvite() } else { showHost = true }
                } label: {
                    Label("Invite friends", systemImage: "person.badge.plus").frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            }
            Button { showHost = true } label: {
                Label(HostManager.shared.phase == .running ? "Server settings" : "Start a server", systemImage: "play.circle.fill")
                    .frame(maxWidth: .infinity).padding(.vertical, 2)
            }
            .controlSize(.large).buttonStyle(.glass).tint(.skAccent)
        }
        .padding(16).glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }
    #endif

    private var header: some View {
        VStack(spacing: 10) {
            // Tap your avatar to set/change your profile picture (E2EE — only members who share a
            // server with you can see it).
            Button { showAvatarPicker = true } label: {
                ZStack(alignment: .bottomTrailing) {
                    AvatarImage(key: (app.session?.userId).map(AvatarStore.userKey), name: myName, size: 88)
                    Image(systemName: "camera.fill")
                        .font(.system(size: 13, weight: .semibold)).foregroundStyle(.white)
                        .frame(width: 30, height: 30)
                        .background(.skAccent, in: Circle())
                        .overlay(Circle().strokeBorder(Color.black.opacity(0.5), lineWidth: 2))
                        .offset(x: 3, y: 3)
                }
            }
            .buttonStyle(.plain)
            Text(app.current?.name ?? "Signed in").font(.title3.bold()).foregroundStyle(.white)
        }
        .padding(.top, 8)
        .sheet(isPresented: $showAvatarPicker) {
            AvatarPickerSheet(
                title: "Profile photo",
                currentKey: (app.session?.userId).map(AvatarStore.userKey),
                name: myName,
                onPick: { await app.avatars.setUserAvatar($0) },
                onRemove: {
                    guard let me = app.session?.userId else { return }
                    await app.avatars.clearAvatar(key: AvatarStore.userKey(me),
                                                  channelIds: app.chatModel?.spaces.map(\.channelId) ?? [])
                }
            )
        }
    }

    /// My display name for the monogram fallback — the workspace label is a decent proxy pre-fetch.
    private var myName: String { app.current?.displayName ?? "You" }


    /// The connected self-hosted servers (workspaces) — switch, add, or leave.
    private var workspacesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "Your Skwods", systemImage: "server.rack")
            ForEach(app.workspaces) { w in
                Button { Task { await app.activate(w) } } label: {
                    HStack(spacing: 12) {
                        Circle().fill(Color.seeded(w.name).gradient).frame(width: 34, height: 34)
                            .overlay(Text(w.name.prefix(1).uppercased()).font(.subheadline.bold()).foregroundStyle(.white))
                        VStack(alignment: .leading, spacing: 1) {
                            Text(w.name).foregroundStyle(.white)
                            Text(w.nodeId.map { "Host key \(InviteLink.shortKey($0))" } ?? w.server)
                                .font(.caption2).foregroundStyle(.white.opacity(0.45)).lineLimit(1)
                        }
                        Spacer()
                        if w.isSignedOut {
                            Text("Signed out").font(.caption2).foregroundStyle(.white.opacity(0.5))
                        } else if w.id == app.current?.id {
                            Image(systemName: "checkmark.circle.fill").foregroundStyle(.skAccent)
                        }
                    }
                }
                .buttonStyle(.plain)
                .overlay(alignment: .trailing) { MutedMark(key: MuteList.skwod, workspaceId: w.id).padding(.trailing, 22) }
                .contextMenu {
                    if w.isSignedOut {
                        Button("Remove from this device…", role: .destructive) { forgetting = w }
                    } else {
                        // Mutes every conversation of this skwod, and its calls.
                        MuteMenuItems(key: MuteList.skwod, workspaceId: w.id)
                    }
                }
            }
            HStack {
                Button { showAdd = true } label: { Label("Add a skwod", systemImage: "plus") }
                    .buttonStyle(.glass).tint(.skAccent)
                Spacer()
                if app.current != nil {
                    Button { confirmSignOutOne = true } label: { Label("Sign out of this one", systemImage: "rectangle.portrait.and.arrow.right") }
                        .buttonStyle(.glass).tint(.white.opacity(0.8))
                }
            }
            .controlSize(.regular).font(.subheadline)
        }
        .padding(16)
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    /// The owner's reports inbox (reports are sealed to whoever runs the skwod).
    private var reportsCard: some View {
        Button { showReports = true } label: {
            HStack(spacing: 12) {
                Image(systemName: "flag.fill").foregroundStyle(.skAccent)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Reports").foregroundStyle(.white)
                    Text(app.reports.isEmpty ? "Nothing waiting" : "\(app.reports.count) waiting for you")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                }
                Spacer()
                if !app.reports.isEmpty {
                    Text("\(app.reports.count)").font(.caption.weight(.bold)).foregroundStyle(.black)
                        .padding(.horizontal, 8).padding(.vertical, 2).background(.skAccent, in: Capsule())
                        .accessibilityLabel("\(app.reports.count) reports")
                }
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.white.opacity(0.4))
            }
            .font(.subheadline).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(16).glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
        .sheet(isPresented: $showReports) { ReportsInboxView() }
        .task { await app.refreshReports() }
        .accessibilityIdentifier("profile.reports")
    }

    private var e2eeCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "Encryption", systemImage: "lock.shield.fill")
            row("User ID", app.session?.userId ?? "—")
            row("Device", app.deviceId ?? "registering…")
            row("Protocol", "Signal Protocol · PQXDH")
            row("Server", app.current.map { Workspace.defaultName(for: $0.server) } ?? "—")
            row("Key storage", Keychain.backing == .dataProtection ? "Protected keychain" : "Login keychain")
            if Keychain.backing != .dataProtection {
                Text("This build isn't signed for the protected keychain, so keys are in your login keychain. Release builds use the protected one.")
                    .font(.caption2).foregroundStyle(.orange.opacity(0.85))
            }
            Divider().overlay(.white.opacity(0.1))
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Devices").foregroundStyle(.white.opacity(0.55))
                    if let deviceCount {
                        Text("\(deviceCount.count) of \(deviceCount.max)").font(.caption2).foregroundStyle(.white.opacity(0.4))
                    }
                }
                Spacer()
                Button { showDevices = true } label: { Text("Manage…").font(.subheadline) }
                    .buttonStyle(.glass).controlSize(.small).tint(.skAccent)
                    .accessibilityIdentifier("profile.devices")
            }
            .font(.subheadline)
            Divider().overlay(.white.opacity(0.1))
            keyBackupRow
            Divider().overlay(.white.opacity(0.1))
            HStack {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Account PIN").foregroundStyle(.white.opacity(0.55))
                    Text("Recover faster if you lose every device").font(.caption2).foregroundStyle(.white.opacity(0.4))
                }
                Spacer()
                Button { showPin = true } label: { Text("Set or change…").font(.subheadline) }
                    .buttonStyle(.glass).controlSize(.small).tint(.skAccent)
            }
            .font(.subheadline)
            Divider().overlay(.white.opacity(0.1))
            Button { showActivity = true } label: {
                HStack {
                    Text("Security activity").foregroundStyle(.white.opacity(0.55))
                    Spacer()
                    if !app.securityActivity.isEmpty {
                        Text("\(app.securityActivity.count)").font(.caption).foregroundStyle(.white.opacity(0.45))
                    }
                    Image(systemName: "chevron.right").font(.caption).foregroundStyle(.white.opacity(0.4))
                }
                .font(.subheadline).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if !accountError.isEmpty {
                Text(accountError).font(.caption2).foregroundStyle(.orange.opacity(0.9))
            }
        }
        .sheet(isPresented: $showDevices, onDismiss: { Task { await refreshAccountRows() } }) { DevicesView() }
        .sheet(isPresented: $showActivity) { SecurityActivityView() }
        .confirmationDialog("Retire your recovery key?", isPresented: $confirmCompromised, titleVisibility: .visible) {
            Button("Retire it", role: .destructive) { Task { await reportCompromised() } }
        } message: {
            Text("It stops working at once, on every device, and can't be brought back. You'll make a new one next.")
        }
        .onReceive(NotificationCenter.default.publisher(for: .skwodAccountChanged)) { _ in Task { await refreshAccountRows() } }
        .sheet(isPresented: $showLinkApprove) { DeviceLinkApproveSheet() }
        .sheet(isPresented: $showPin) { RegistrationPinSheet() }
        .confirmationDialog("Turn off key backup?", isPresented: $confirmDisableBackup, titleVisibility: .visible) {
            Button("Delete the backup from the server", role: .destructive) {
                Task {
                    if (try? await app.client?.disableKeyBackup()) != nil { backupEnabled = false }
                }
            }
        } message: {
            Text("The encrypted copy of your keys is deleted from your Skwod's server and your recovery key stops being yours to restore with. After that, losing every device means losing your messages.")
        }
        .padding(16)
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
        // Re-check whenever the bound device changes — at first render the client is often still
        // attaching, and a restore swaps the device identity under us.
        .task(id: app.deviceId) { await refreshAccountRows() }
        .sheet(isPresented: $showBackupSetup) {
            KeyBackupSetupSheet { backupEnabled = true }
        }
    }

    /// The rows that mirror the account: recovery key on/off (and from when it is instant),
    /// how many devices.
    private func refreshAccountRows() async {
        guard let client = app.client, app.deviceId != nil else { backupEnabled = false; deviceCount = nil; return }
        backupEnabled = await client.keyBackupEnabled()
        instantFrom = await client.recoveryKeyInstantFrom()
        if let list = await app.refreshDeviceNames() { deviceCount = (list.devices.count, Int(list.maxDevices)) }
    }

    /// "My recovery key is compromised": retired at once, everywhere; then make a new one.
    private func reportCompromised() async {
        guard let client = app.client else { accountError = "Not connected."; return }
        do {
            try await client.reportRecoveryKeyCompromised()
            accountError = ""
            backupEnabled = false
            await app.logSecurity(kind: "recovery_key_retired", title: "You retired your recovery key",
                                  message: "You reported it compromised. It no longer works on any device.",
                                  atMs: Int64(Date().timeIntervalSince1970 * 1000))
            app.recoveryKeyPrompt = .compromised
        } catch {
            if await app.routeIfDeviceError(error) { return }
            accountError = coreErrorText(error, fallback: "Couldn't retire the key — check your connection.")
        }
    }

    /// The recovery key: what brings the account back when every device is gone.
    @ViewBuilder private var keyBackupRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text("Recovery key").foregroundStyle(.white.opacity(0.55))
                if backupEnabled {
                    Text(instantFrom.map { Double($0) / 1000 > Date().timeIntervalSince1970 ? "Instant from \(AccountDates.day($0))" : "Instant restore ready" } ?? "Instant restore ready")
                        .font(.caption2).foregroundStyle(.white.opacity(0.4))
                }
            }
            Spacer()
            if backupEnabled {
                Label("On", systemImage: "checkmark.seal.fill")
                    .font(.subheadline).foregroundStyle(.green)
            } else {
                Text("Not set").font(.subheadline).foregroundStyle(.orange)
                Button { app.recoveryKeyPrompt = .manual } label: {
                    Text("Save a recovery key…").font(.subheadline)
                }
                .buttonStyle(.glass).controlSize(.small).tint(.skAccent)
                .accessibilityIdentifier("profile.recoverykey")
            }
        }
        .font(.subheadline)
        if backupEnabled {
            HStack(spacing: 14) {
                Button("Replace…") { app.recoveryKeyPrompt = .manual }
                Button("My recovery key is compromised…") { confirmCompromised = true }
                Spacer()
                Button("Turn off…") { confirmDisableBackup = true }.foregroundStyle(.white.opacity(0.5))
            }
            .buttonStyle(.plain).font(.caption).foregroundStyle(.skAccent)
        } else {
            Text("Without one, losing every device means losing your messages.")
                .font(.caption2).foregroundStyle(.orange.opacity(0.85))
        }
    }

    /// Privacy switches: what other people (and other apps) can see of skwod on this device, and
    /// whether a relay may carry the connection.
    private var privacyCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "Privacy", systemImage: "eye.slash.fill")
            AppLockSettings()
            Toggle(isOn: $hideInSwitcher) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Hide Skwod in the app switcher").foregroundStyle(.white)
                    Text("Shows the logo instead of your chats when Skwod isn't in front.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                }
            }
            Toggle(isOn: $screenSecurity) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Block screenshots and screen recording").foregroundStyle(.white)
                    Text("Keeps Skwod out of screenshots, recordings and screen sharing on this device. It can't stop someone photographing the screen.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                }
            }
            Toggle(isOn: Binding(get: { SoundSettings.received }, set: { SoundSettings.received = $0; previewsTick += 1 })) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Sound for new messages").foregroundStyle(.white)
                    Text("A short sound when a message arrives in a chat you're not looking at. Never under Do Not Disturb.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                }
            }
            Toggle(isOn: Binding(get: { SoundSettings.sent }, set: { SoundSettings.sent = $0; previewsTick += 1 })) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Sound when a message is sent").foregroundStyle(.white)
                    Text("A soft sound once your message has been delivered to the skwod.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                }
            }
            #if os(macOS)
            Toggle(isOn: Binding(get: { NotificationState.showPreviews },
                                 set: { NotificationState.showPreviews = $0; previewsTick += 1 })) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Show message text in notifications").foregroundStyle(.white)
                    Text("Off: notifications only say “New message”.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                }
            }
            #endif
            Toggle(isOn: $storyMusicTapToPlay) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Play story music only when I tap").foregroundStyle(.white)
                    Text("A story's song is fetched for you by this Skwod's host, never straight from Apple — so Apple doesn't see you, but the host sees which song you played and when. Off: it starts when you open the story. On: nothing is fetched until you tap the song. Song cards in chats and posts follow it too: on, not even their cover loads until you tap play.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45)).fixedSize(horizontal: false, vertical: true)
                }
            }
            .accessibilityIdentifier("privacy.storyMusicTapToPlay")
            Toggle(isOn: Binding(get: { fullSongs }, set: { want in
                fullSongsNote = ""
                guard want else { fullSongs = false; return }
                // The only place Apple Music access is asked for: the moment the user chooses this.
                Task {
                    if await MusicAuthorization.request() == .authorized { fullSongs = true }
                    else {
                        fullSongs = false
                        fullSongsNote = "Skwod doesn't have access to Apple Music on this device. Allow it in Settings, then switch this on again."
                    }
                }
            })) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Play full songs with my Apple Music account").foregroundStyle(.white)
                    Text("Uses your Apple Music subscription on this device, so Apple sees which songs you play. For song cards in chats and posts; without a subscription they play the short preview as before. Stories always play the part their author chose.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45)).fixedSize(horizontal: false, vertical: true)
                    if !fullSongsNote.isEmpty {
                        Text(fullSongsNote).font(.caption2).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .accessibilityIdentifier("privacy.fullSongs")
            #if os(iOS)
            if PushManager.enabled {
                Toggle(isOn: Binding(get: { NotificationState.showPreviews },
                                     set: { NotificationState.showPreviews = $0; previewsTick += 1 })) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Show message text in notifications").foregroundStyle(.white)
                        Text("Decrypted on this device after the notification arrives. Off: notifications only say “New message”.")
                            .font(.caption2).foregroundStyle(.white.opacity(0.45))
                    }
                }
                .id(previewsTick)
                if let current = app.current, push.hostNeedsUpdate.contains(current.id) {
                    // A host older than build 45 is given no push registration (it would need
                    // this phone's raw push tokens, which cannot be taken back).
                    Text("This skwod's host needs updating before it can send notifications to this phone. Until then you'll see messages and calls only while Skwod is open.")
                        .font(.caption2).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("privacy.pushHostNeedsUpdate")
                }
            }
            #endif
            Toggle(isOn: Binding(get: { publicFallback }, set: { v in
                publicFallback = v
                Task { await app.reconnectAfterTransportSettingChange() }
            })) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Use a relay when needed").foregroundStyle(.white)
                    Text("On: if a direct connection to your host isn't possible, an independent relay passes the encrypted traffic along and can see that your two devices are talking — never what is said. Off: direct connections only; some networks won't be able to reach your host.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45)).fixedSize(horizontal: false, vertical: true)
                }
            }
            HStack {
                Text("Connection").foregroundStyle(.white.opacity(0.55))
                Spacer()
                ConnectionPill()
            }
            .font(.subheadline)
        }
        .tint(.skAccent).font(.subheadline)
        .padding(16)
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    private var aboutCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "About", systemImage: "info.circle.fill")
            row("Version", AppVersion.display)
            row("License", "AGPL-3.0 · open source")
            updateRow
            HStack {
                Text("Keys never leave this device").foregroundStyle(.white.opacity(0.55))
                Spacer()
                Image(systemName: "checkmark.seal.fill").foregroundStyle(.green)
            }
            .font(.subheadline)
            Divider().overlay(.white.opacity(0.1))
            Button { showLicenses = true } label: {
                HStack {
                    Text("Licenses & acknowledgements").foregroundStyle(.white.opacity(0.55))
                    Spacer()
                    Image(systemName: "chevron.right").font(.caption).foregroundStyle(.white.opacity(0.4))
                }
                .font(.subheadline).contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .padding(16)
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
        .sheet(isPresented: $showLicenses) { AcknowledgementsSheet() }
    }

    /// "Check for updates". On macOS this hands off to Sparkle (its standard signed-update UI). On
    /// iOS it checks the JSON manifest and, if behind, the top banner offers a TestFlight hand-off.
    @ViewBuilder private var updateRow: some View {
        #if os(macOS)
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Updates").foregroundStyle(.white.opacity(0.55))
                Spacer()
                Button { sparkle.checkForUpdates() } label: {
                    Text("Check for updates").font(.subheadline).foregroundStyle(.skAccent)
                }
                .buttonStyle(.plain)
                .disabled(!sparkle.canCheckForUpdates)
            }
            if SparkleUpdater.enabled {
                Toggle(isOn: Binding(get: { sparkle.automaticChecks }, set: { sparkle.setAutomaticChecks($0) })) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Check for updates automatically").foregroundStyle(.white)
                        Text("Once a day Skwod asks GitHub, where its releases are published, whether a new version is out, and installs it when you quit. While this Mac is hosting a Skwod it asks before any install that would restart the server. GitHub sees your IP address and nothing else.")
                            .font(.caption2).foregroundStyle(.white.opacity(0.45))
                    }
                }
            }
        }
        .font(.subheadline)
        #else
        HStack {
            Text("Updates").foregroundStyle(.white.opacity(0.55))
            Spacer()
            if updater.available != nil {
                Button {
                    Task { await updater.install(serverURL: app.serverURL) }
                } label: {
                    Label("Update available", systemImage: "arrow.down.circle.fill")
                        .font(.subheadline).foregroundStyle(.skAccent)
                }
                .buttonStyle(.plain)
            } else if case .checking = updater.phase {
                ProgressView().controlSize(.small)
            } else {
                Button {
                    Task { await updater.check(serverURL: app.serverURL, manual: true) }
                } label: {
                    Text(updater.lastCheckWasManual ? "Up to date" : "Check for updates")
                        .font(.subheadline).foregroundStyle(.skAccent)
                }
                .buttonStyle(.plain)
            }
        }
        .font(.subheadline)
        #endif
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundStyle(.white.opacity(0.55))
            Spacer()
            Text(value.count > 22 ? value.prefix(22) + "…" : value)
                .font(.system(.subheadline, design: .monospaced)).foregroundStyle(.white)
        }
        .font(.subheadline)
    }
}

/// Add another self-hosted server (workspace) without signing out of the current ones. Reuses the
/// connect form; on success the new workspace becomes active.
struct AddWorkspaceSheet: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            AuthView(onConnected: { dismiss() })
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    }
                }
        }
    }
}
