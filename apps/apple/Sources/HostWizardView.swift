#if os(macOS)
import SwiftUI
import AppKit

/// "Start server" (macOS only): one button turns this Mac into a skwod for your friends.
///
/// It runs the bundled server (+ the bundled SFU for voice and video), signs this Mac in as the
/// owner over the local path, and then hands over to `HostInvitePanel` in the main window — the
/// invite to send friends. No account, no domain, no tunnel, nothing hosted by anyone else.
struct HostWizardView: View {
    /// Opened to get a server running AND set up (the menu bar's Start / Invite on a Mac with
    /// no owner account): start it at once if it is off, without waiting for the button.
    var autoStart = false
    /// Called once this Mac is signed in to its own server (the presenting sheet should close).
    var onSignedIn: (() -> Void)? = nil
    @EnvironmentObject private var app: AppState
    @ObservedObject private var host = HostManager.shared
    @State private var movingFolder = false
    @State private var moveFailure: String?
    @State private var showLog = false
    @State private var ownerName = ""
    @State private var signingIn = false
    @State private var errorText = ""
    /// Why the automatic owner sign-in is waiting before its next attempt ("" = it is not).
    @State private var retryNote = ""
    /// Start was pressed in THIS wizard, so finishing means: sign in, open the invite panel, close.
    @State private var startedHere = false
    @ObservedObject private var awake = HostAwake.shared
    @ObservedObject private var loginItem = LoginItem.shared
    @ObservedObject private var sparkle = SparkleUpdater.shared
    @AppStorage("skwod.p2p.publicFallback") private var publicFallback = true
    /// The per-file upload limit the running server reports (MB); nil until asked.
    @State private var uploadLimitMB: Int?
    @State private var uploadLimitNote = ""
    @State private var savingUploadLimit = false

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(spacing: 20) {
                    header
                    switch host.phase {
                    case .idle, .stopped: startCard
                    case .starting: startingCard
                    case .restarting(let reason): restartingCard(reason)
                    case .running: runningCard
                    case .failed(let msg): failedCard(msg)
                    }
                    settingsCard
                    if !host.log.isEmpty { logDisclosure }
                }
                .frame(maxWidth: 560)
                .padding(28)
            }
        }
        .frame(minWidth: 620, minHeight: 640)
        .onAppear {
            if ownerName.isEmpty { ownerName = host.ownerLogin?.username ?? "" }
            loginItem.refresh()
            awake.refresh()
            if autoStart {
                switch host.phase {
                case .idle, .stopped, .failed: startedHere = true; host.start()
                case .starting, .restarting, .running: startedHere = true
                }
            }
        }
        // As soon as the server is up — just started here, restarted by itself, or already
        // running when this opens — finish the setup: sign in as its owner without being asked.
        .task(id: host.phase) {
            if host.phase == .running { await finishSetup() }
        }
        // The owner's own setting: read it once the server is up and this Mac is its owner.
        .task(id: "\(host.phase == .running)|\(host.hasOwnerWorkspace)|\(signingIn)") {
            uploadLimitMB = await host.uploadLimitMB()
        }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Image(systemName: "server.rack").font(.system(size: 46)).foregroundStyle(.skAccent)
            Text("Start a server").font(.largeTitle.bold()).foregroundStyle(.white)
            Text("Run your own Skwod on this Mac. Your friends join with an invite you send them. Messages and calls stay end-to-end encrypted — this Mac only ever stores ciphertext, and nobody else runs anything.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
        }
    }

    /// The username this Mac's owner account gets. Only needed the very first time.
    private var needsOwnerName: Bool {
        host.ownerLogin == nil && app.workspace(at: .https(HostManager.localURL)) == nil
    }

    private var ownerNameValid: Bool {
        (3...32).contains(ownerName.count) && ownerName.allSatisfy {
            ($0.isASCII && $0.isLowercase && $0.isLetter) || ($0.isASCII && $0.isNumber) || $0 == "_"
        }
    }

    private var startCard: some View {
        VStack(spacing: 16) {
            if needsOwnerName {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Your name in this Skwod").font(.caption).foregroundStyle(.white.opacity(0.5))
                    TextField("e.g. sam", text: $ownerName)
                        .textFieldStyle(.plain).foregroundStyle(.white)
                        .padding(.horizontal, 14).padding(.vertical, 10)
                        .glassEffect(.regular, in: .capsule)
                        .onChange(of: ownerName) { _, v in
                            let lowered = v.lowercased()
                            if lowered != v { ownerName = lowered }
                        }
                    if !ownerName.isEmpty && !ownerNameValid {
                        Text("3–32 characters: a–z, 0–9, underscore.").font(.caption2).foregroundStyle(.orange.opacity(0.9))
                    }
                }
            }
            Button { startedHere = true; host.start() } label: {
                Label("Start server", systemImage: "play.fill").frame(maxWidth: .infinity).padding(.vertical, 4)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .disabled(needsOwnerName && !ownerNameValid)

            firewallNote

            DisclosureGroup("Options") {
                VStack(alignment: .leading, spacing: 12) {
                    dataFolderRow
                    HostBackupRow(host: host)
                    Toggle(isOn: $publicFallback) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Use a relay when a direct connection isn't possible").foregroundStyle(.white)
                            Text("On: friends can connect through almost any router. When no direct route exists, an independent relay passes the (still end-to-end encrypted) traffic along and sees that the two devices are talking. Off: direct connections only — more private, but friends behind some routers won't be able to reach you.")
                                .font(.caption2).foregroundStyle(.white.opacity(0.5)).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    // The same setting as in Profile: applied the same way (an opt-out closes what
                    // this app's own connections relay, not only what the server will).
                    .onChange(of: publicFallback) { _, v in
                        NotificationState.publicFallback = v
                        Task { await app.reconnectAfterTransportSettingChange() }
                    }
                    .tint(.skAccent)
                }
                .padding(.top, 8)
            }
            .font(.caption).foregroundStyle(.white.opacity(0.6))
        }
        .padding(20).glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    /// Shown BEFORE the button is pressed: macOS may put up its firewall question the moment the
    /// server starts listening, and a dialog nobody was told about gets denied.
    private var firewallNote: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "shield.lefthalf.filled").foregroundStyle(.skAccent)
            VStack(alignment: .leading, spacing: 3) {
                Text("macOS may ask one question").font(.caption.weight(.semibold)).foregroundStyle(.white)
                Text("When the server starts, macOS can ask whether “skwod-server” (and “livekit-server”) may accept incoming connections. Click **Allow** — that is what lets your friends connect straight to this Mac. If you click Deny, Skwod still works, but connections take the slower relay route. You can change it later in System Settings → Network → Firewall.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.6)).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(.white.opacity(0.05), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    private var dataFolderRow: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Storage folder").font(.caption).foregroundStyle(.white.opacity(0.5))
                Text(host.dataDir.path).font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.white).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            Button(movingFolder ? "Moving…" : (host.hasHostedBefore ? "Move…" : "Choose…")) { chooseFolder() }.buttonStyle(.glass).disabled(movingFolder)
        }
        .alert("The folder was not changed", isPresented: Binding(get: { moveFailure != nil }, set: { if !$0 { moveFailure = nil } })) {
            Button("OK", role: .cancel) {}
        } message: { Text(moveFailure ?? "") }
    }

    private var startingCard: some View {
        VStack(spacing: 14) {
            ProgressView().controlSize(.large).tint(.skAccent)
            Text("Starting your Skwod…").font(.subheadline).foregroundStyle(.white.opacity(0.7))
            Text("If macOS asks about incoming connections, click Allow.")
                .font(.caption).foregroundStyle(.white.opacity(0.5))
        }
        .padding(28).glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    private var runningCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Circle().fill(.green).frame(width: 10, height: 10)
                Text("Your Skwod is running").font(.headline).foregroundStyle(.white)
                Spacer()
                Button { host.stop() } label: { Label("Stop", systemImage: "stop.fill") }.buttonStyle(.glass).tint(.red)
            }
            if signingIn {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Signing you in as the owner…").font(.subheadline).foregroundStyle(.white.opacity(0.7))
                }
            } else if !retryNote.isEmpty {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text(retryNote).font(.caption).foregroundStyle(.white.opacity(0.7)).fixedSize(horizontal: false, vertical: true)
                }
            } else if !errorText.isEmpty {
                Label(errorText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                Button("Try again") { Task { await finishSetup() } }.buttonStyle(.glass).tint(.skAccent)
            } else if ownerStep == .needsName {
                // The one thing only the user can supply: what to be called in their own Skwod.
                VStack(alignment: .leading, spacing: 6) {
                    Text("One thing left: your name in this Skwod").font(.caption).foregroundStyle(.white.opacity(0.6))
                    HStack {
                        TextField("e.g. sam", text: $ownerName)
                            .textFieldStyle(.plain).foregroundStyle(.white)
                            .padding(.horizontal, 14).padding(.vertical, 10)
                            .glassEffect(.regular, in: .capsule)
                            .onChange(of: ownerName) { _, v in
                                let lowered = v.lowercased()
                                if lowered != v { ownerName = lowered }
                            }
                            .onSubmit { if ownerNameValid { Task { await finishSetup() } } }
                        Button("Finish setup") { Task { await finishSetup() } }
                            .buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                            .disabled(!ownerNameValid)
                    }
                    if !ownerName.isEmpty && !ownerNameValid {
                        Text("3–32 characters: a–z, 0–9, underscore.").font(.caption2).foregroundStyle(.orange.opacity(0.9))
                    }
                }
            } else if app.workspace(at: .https(HostManager.localURL)) != nil {
                Button {
                    host.showInvitePanel = true
                    onSignedIn?()
                } label: {
                    Label("Invite friends", systemImage: "person.badge.plus").frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            }
            if !host.voiceBundled {
                Label("This build has no voice/video server bundled, so calls are off for this Skwod.", systemImage: "phone.down")
                    .font(.caption).foregroundStyle(.white.opacity(0.5))
            }
            if host.nodeId == nil {
                Label("Your Skwod's address for friends is still coming up. Skwod keeps trying by itself and this updates when it is ready — if it takes more than a minute, check this Mac's internet connection.", systemImage: "wifi.exclamationmark")
                    .font(.caption).foregroundStyle(.orange.opacity(0.9)).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(20).glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    /// The server stopped by itself and is being started again — say why, and when.
    private func restartingCard(_ reason: String) -> some View {
        VStack(spacing: 14) {
            ProgressView().controlSize(.large).tint(.skAccent)
            Text("Restarting…").font(.headline).foregroundStyle(.white)
            Text(reason).font(.caption).foregroundStyle(.white.opacity(0.7))
                .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
            if let at = host.retryAt, at > Date() {
                Text("Trying again in \(at, style: .relative). Members reconnect by themselves once it is back.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center)
            } else {
                Text("Starting it again now. Members reconnect by themselves once it is back.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center)
            }
            Button { host.stop() } label: { Label("Stop", systemImage: "stop.fill") }.buttonStyle(.glass).tint(.red)
        }
        .padding(24).frame(maxWidth: .infinity)
        .glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    /// Keeping the server up when nobody is looking: stay awake, start at login, updates.
    private var settingsCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionHeader(title: "Keep it running", systemImage: "bolt.horizontal.circle")
            Toggle(isOn: Binding(get: { awake.enabled }, set: { awake.setEnabled($0) })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Keep this Mac awake while hosting").foregroundStyle(.white)
                    Text(awakeCaption)
                        .font(.caption2).foregroundStyle(.white.opacity(0.5)).fixedSize(horizontal: false, vertical: true)
                }
            }
            .tint(.skAccent)
            Toggle(isOn: Binding(get: { loginItem.state != .off }, set: { loginItem.set($0) })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Start Skwod when I log in").foregroundStyle(.white)
                    Text("After a restart of this Mac your Skwod comes back by itself, in the menu bar, without opening a window.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.5)).fixedSize(horizontal: false, vertical: true)
                }
            }
            .tint(.skAccent)
            if loginItem.state == .needsApproval {
                HStack(alignment: .top, spacing: 8) {
                    Label("macOS is waiting for you to allow it: open System Settings > General > Login Items and switch Skwod on.", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    Spacer()
                    Button("Open Login Items") { loginItem.openSystemSettings() }.buttonStyle(.glass)
                }
            }
            if !loginItem.errorText.isEmpty {
                Label(loginItem.errorText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
            if let version = sparkle.pendingUpdateVersion {
                HStack(alignment: .top, spacing: 8) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Skwod \(version) is ready to install").foregroundStyle(.white)
                        Text(HostReliability.updatePromptBody + " It also installs the next time you quit Skwod.")
                            .font(.caption2).foregroundStyle(.white.opacity(0.5)).fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Button("Install now") { sparkle.installPendingUpdate() }.buttonStyle(.glass).tint(.skAccent)
                }
            }
            if let current = uploadLimitMB {
                uploadLimitRow(current)
            }
            if host.isHosting {
                Text("This Mac reaches its own server at 127.0.0.1:\(String(host.port)). Friends never use that — they connect with your invite.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.4)).fixedSize(horizontal: false, vertical: true)
            }
        }
        .font(.caption)
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            loginItem.refresh()   // the user may be coming back from System Settings
        }
    }

    /// The host's per-file upload limit: a menu of sizes, applied at once (no restart).
    private func uploadLimitRow(_ current: Int) -> some View {
        // What is in force is always one of the choices shown (it may have been set elsewhere).
        let choices = Array(Set(UploadLimit.hostChoicesMB + [current])).sorted()
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Largest file a member can send").foregroundStyle(.white)
                    Text("Per file. Bigger files take more of this Mac's disk; each member's total storage is capped separately.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.5)).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Picker("Largest file a member can send", selection: Binding(get: { current }, set: { mb in
                    guard mb != current, !savingUploadLimit else { return }
                    savingUploadLimit = true
                    Task {
                        let problem = await host.setUploadLimit(mb: mb)
                        uploadLimitNote = problem ?? ""
                        uploadLimitMB = await host.uploadLimitMB() ?? current
                        savingUploadLimit = false
                    }
                })) {
                    ForEach(choices, id: \.self) { mb in Text(UploadLimit.label(Int64(mb) * UploadLimit.mib)).tag(mb) }
                }
                .pickerStyle(.menu).labelsHidden().fixedSize().tint(.skAccent)
                .disabled(savingUploadLimit)
                .accessibilityIdentifier("host.uploadLimit")
            }
            if !uploadLimitNote.isEmpty {
                Label(uploadLimitNote, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption2).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var awakeCaption: String {
        if awake.holding { return "On now: this Mac will not go to sleep by itself while your Skwod is up. The screen can still turn off; closing a MacBook's lid still puts it to sleep." }
        if awake.enabled { return "While the server is running, this Mac will not go to sleep by itself. The screen can still turn off; closing a MacBook's lid still puts it to sleep." }
        return awake.onACPower
            ? "Off: when this Mac goes to sleep, your Skwod is offline until it wakes."
            : "Off while on battery unless you switch it on. When this Mac goes to sleep, your Skwod is offline until it wakes."
    }

    private func failedCard(_ msg: String) -> some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill").font(.title).foregroundStyle(.orange)
            Text("Couldn't start the server").font(.headline).foregroundStyle(.white)
            Text(msg).font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
            Button("Try again") { startedHere = true; host.start() }.controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
        }
        .padding(24).glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
    }

    private var logDisclosure: some View {
        DisclosureGroup(isExpanded: $showLog) {
            ScrollView {
                Text(host.log.suffix(40).joined(separator: "\n"))
                    .font(.system(.caption2, design: .monospaced)).foregroundStyle(.white.opacity(0.6))
                    .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
            }
            .frame(height: 140)
        } label: {
            Text("Server log").font(.caption).foregroundStyle(.white.opacity(0.5))
        }
        .padding(12).glassEffect(.regular, in: .rect(cornerRadius: 12, style: .continuous))
    }

    /// Where owner setup stands, from what this Mac holds right now.
    private var ownerStep: HostReliability.OwnerStep {
        HostReliability.ownerStep(
            hasWorkspace: app.workspace(at: .https(HostManager.localURL)) != nil,
            hasSavedLogin: host.ownerLogin != nil,
            hasSetupCode: host.joinCode != nil,
            nameValid: ownerNameValid)
    }

    /// The server is up: make this Mac its signed-in owner. Runs by itself, retries failures that
    /// pass on their own (the server still settling, a rate limit) with backoff, and only stops
    /// to ask when it needs something from the user — a name, or the owner's own login.
    private func finishSetup() async {
        // One attempt at a time: a second sign-up with the same one-time code would fail.
        while signingIn {
            try? await Task.sleep(for: .milliseconds(200))
            if Task.isCancelled { return }
        }
        errorText = ""; retryNote = ""
        var attempt = 0
        while !Task.isCancelled, host.phase == .running {
            switch ownerStep {
            case .alreadySignedIn:
                // Opened as "Server settings" on a Mac that is already in: nothing to do. Right
                // after Start, go on (it only activates the workspace) so the invite panel opens.
                guard startedHere else { return }
            case .needsName:
                return   // the running card shows the name field
            case .needsOwnerLogin:
                errorText = "This server already has an owner, but this Mac has no saved login for it. Close this, choose Log in → “This Mac”, and enter the owner's username and password."
                return
            case .signIn:
                break
            }
            signingIn = true
            do {
                try await app.signInAsHostOwner(username: ownerName)
                signingIn = false
                startedHere = false
                host.showInvitePanel = true
                onSignedIn?()
                return
            } catch let e as HostError {
                signingIn = false
                errorText = e.message
                return
            } catch {
                signingIn = false
                let message = AuthView.message(for: error, signup: host.ownerLogin == nil)
                guard HostReliability.isTransientSignInFailure(String(describing: error)),
                      attempt < HostReliability.signInRetryDelays.count else {
                    errorText = message
                    return
                }
                let delay = HostReliability.signInRetryDelays[attempt]
                attempt += 1
                retryNote = "\(message) Trying again in \(Int(delay)) s…"
                try? await Task.sleep(for: .seconds(delay))
                retryNote = ""
            }
        }
    }

    private func chooseFolder() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.allowsMultipleSelection = false
        // With a skwod already here this MOVES it (same skwod, new place) — it never starts
        // a second, empty one.
        panel.prompt = host.hasHostedBefore ? "Move the skwod here" : "Use this folder"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        movingFolder = true
        Task {
            moveFailure = await host.moveStorage(to: url)
            movingFolder = false
        }
    }
}

/// "Invite your friends": the invite link for the skwod this Mac hosts — QR, Copy, Share — plus
/// the people waiting to be let in. Opens by itself right after Start server.
struct HostInvitePanel: View {
    @EnvironmentObject private var app: AppState
    @EnvironmentObject private var chat: ChatModel
    @ObservedObject private var host = HostManager.shared
    @Environment(\.dismiss) private var dismiss

    @State private var invite: String?
    @State private var instantInvite: String?
    @State private var serverId: String?
    @State private var pending: [JoinRequest] = []
    @State private var busy = false
    @State private var errorText = ""
    @State private var showPassword = false

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(spacing: 18) {
                    VStack(spacing: 6) {
                        Text("Invite your friends").font(.title.bold()).foregroundStyle(.white)
                        Text("Send this to the people you want in. They tap it (or scan it), pick a name, and ask to join — you let them in below.")
                            .font(.subheadline).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                    }
                    if let invite {
                        ShareableCodeCard(
                            title: "Invite link · works for 7 days · you approve each person",
                            value: invite,
                            caption: "Anyone with this link can ask to join, so send it privately. Revoke it any time from the server's Invite screen.")
                            .padding(18).glassEffect(.regular, in: .rect(cornerRadius: 20, style: .continuous))
                    } else if errorText.isEmpty {
                        ProgressView().tint(.skAccent).padding(40)
                    }
                    if !errorText.isEmpty {
                        Label(errorText, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                        Button("Try again") { Task { await prepare() } }.buttonStyle(.glass).tint(.skAccent)
                    }
                    if invite != nil {
                        instantCard
                        pendingCard
                        ownerCard
                    }
                }
                .padding(28).frame(maxWidth: 520)
            }
        }
        .frame(minWidth: 560, minHeight: 700)
        // The address for friends can come up after the server (the p2p endpoint retries by
        // itself): build the invite as soon as it is known.
        .onChange(of: host.nodeId) { _, id in
            if id != nil, invite == nil { Task { await prepare() } }
        }
        .task {
            await prepare()
            while !Task.isCancelled {
                await refreshPending()
                try? await Task.sleep(for: .seconds(4))
            }
        }
    }

    private var instantCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "One-time link (joins instantly)", systemImage: "bolt.fill")
            Text("For one person you trust: whoever opens it first is in straight away, then it stops working.")
                .font(.caption).foregroundStyle(.white.opacity(0.55))
            if let instantInvite {
                HStack {
                    Text(instantInvite).font(.system(.caption, design: .monospaced)).foregroundStyle(.white)
                        .lineLimit(1).truncationMode(.middle)
                    Spacer()
                    ShareLink(item: instantInvite) { Image(systemName: "square.and.arrow.up") }.buttonStyle(.plain)
                    CopyButton(instantInvite, compact: true, sensitive: true)
                }
                .padding(10).glassEffect(.regular, in: .rect(cornerRadius: 12, style: .continuous))
            }
            Button { Task { await mintInstant() } } label: {
                Label(instantInvite == nil ? "Create a one-time link" : "Create another", systemImage: "link.badge.plus")
            }
            .buttonStyle(.glass).tint(.skAccent).disabled(busy)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
    }

    private var pendingCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            SectionHeader(title: "Waiting to join", systemImage: "person.crop.circle.badge.questionmark")
            if pending.isEmpty {
                Text("Nobody yet. Requests show up here as soon as a friend uses your invite.")
                    .font(.caption).foregroundStyle(.white.opacity(0.45))
            } else {
                ForEach(pending, id: \.userId) { req in
                    HStack {
                        Circle().fill(Color.seeded(req.username).gradient).frame(width: 30, height: 30)
                            .overlay(Text(req.username.prefix(1).uppercased()).font(.caption.bold()).foregroundStyle(.white))
                        Text(req.username).foregroundStyle(.white)
                        Spacer()
                        Button("Let in") { Task { await decide(req, approve: true) } }
                            .buttonStyle(.glassProminent).tint(.green)
                        Button("Decline") { Task { await decide(req, approve: false) } }
                            .buttonStyle(.glass).tint(.red)
                    }
                }
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
    }

    /// The owner account was created with a generated password; to sign in to the same account on
    /// a phone (and then link it as a device) the host needs to see it once.
    @ViewBuilder private var ownerCard: some View {
        if let login = host.ownerLogin {
            VStack(alignment: .leading, spacing: 8) {
                SectionHeader(title: "Your own login", systemImage: "person.badge.key")
                Text("To use this account on your phone: open your invite there, choose Log in, and enter these. Then link the phone from Profile → Encryption.")
                    .font(.caption).foregroundStyle(.white.opacity(0.55)).fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text("Username").font(.caption).foregroundStyle(.white.opacity(0.5))
                    Spacer()
                    Text(login.username).font(.system(.callout, design: .monospaced)).foregroundStyle(.white)
                }
                HStack {
                    Text("Password").font(.caption).foregroundStyle(.white.opacity(0.5))
                    Spacer()
                    Text(showPassword ? login.password : "••••••••••••")
                        .font(.system(.callout, design: .monospaced)).foregroundStyle(.white)
                    // The owner's password is shown — and copied — only to whoever can unlock
                    // this Mac (Touch ID or its password), not to anyone at an open window.
                    Button(showPassword ? "Hide" : "Show") {
                        if showPassword { showPassword = false; return }
                        Task { if await OwnerSecretGate.passes("Show the owner password") { showPassword = true } }
                    }.buttonStyle(.plain).foregroundStyle(.skAccent)
                    if showPassword { CopyButton(login.password, compact: true, sensitive: true) }
                }
            }
            .padding(16).frame(maxWidth: .infinity, alignment: .leading)
            .glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
        }
    }

    // MARK: actions

    /// Make sure there is a server to invite into, then mint the reusable (approval) invite.
    private func prepare() async {
        errorText = ""
        // No owner account on this Mac (the server was started without the setup): there is
        // nobody to make an invite. Never wait here for one — hand over to the setup.
        guard host.hasOwnerWorkspace else {
            dismiss()
            host.showInvitePanel = false
            try? await Task.sleep(for: .milliseconds(450))   // let this sheet go first
            host.requestInvite()
            return
        }
        // The E2EE client attaches a moment after sign-in.
        for _ in 0..<60 where !app.clientIsOnline || app.deviceId == nil {
            try? await Task.sleep(for: .milliseconds(250))
        }
        guard let client = app.client, app.deviceId != nil else {
            errorText = "Still setting up encryption on this Mac. Try again in a moment."
            return
        }
        guard let nodeId = host.nodeId else {
            errorText = "Your Skwod's address for friends is still coming up. Skwod keeps trying by itself and the invite appears here when it is ready — if it takes more than a minute, check this Mac's internet connection."
            return
        }
        do {
            await chat.loadIfNeeded()
            var sid = chat.spaces.first?.serverId
            if sid == nil {
                let name = (host.ownerLogin?.username).map { "\($0)'s Skwod" } ?? "My Skwod"
                let s = try await client.createSpace(name: name, channelName: "general")
                chat.addSpace(RealSpace(name: name, channelName: "general", serverId: s.serverId,
                                        channelId: s.channelId, inviteCode: s.inviteCode, spaceKeyHex: s.spaceKeyHex))
                sid = s.serverId
            }
            guard let sid else { return }
            serverId = sid
            // Reuse a still-valid approval invite rather than minting one per open.
            let existing = (try? await client.listInvites(serverId: sid))?.first {
                $0.status == "active" && $0.maxUses == nil
                    && ($0.expiresAt.map { Double($0) / 1000 > Date().timeIntervalSince1970 + 86_400 } ?? true)
            }
            let code: String
            if let existing { code = existing.code }
            else { code = try await client.inviteToSpace(serverId: sid, kind: "code", reservedUsername: nil) }
            invite = InviteLink.shareLink(nodeId: nodeId, joinCode: code)
            if invite == nil { errorText = "Couldn't build the invite link." }
        } catch {
            errorText = "Couldn't create the invite. Try again."
        }
    }

    private func mintInstant() async {
        guard let client = app.client, let sid = serverId, let nodeId = host.nodeId else { return }
        busy = true; defer { busy = false }
        if let code = try? await client.inviteToSpace(serverId: sid, kind: "token", reservedUsername: nil) {
            instantInvite = InviteLink.shareLink(nodeId: nodeId, joinCode: code)
        }
    }

    private func refreshPending() async {
        guard let client = app.client, let sid = serverId else { return }
        if let list = try? await client.listJoinRequests(serverId: sid) { pending = list }
    }

    private func decide(_ req: JoinRequest, approve: Bool) async {
        guard let client = app.client, let sid = serverId else { return }
        if approve {
            // The same name check as "Waiting to join": never let in on the server's name alone.
            let verdict = await app.waiting.verdict(serverId: sid, userId: req.userId, username: req.username)
            guard WaitingTrust.mayLetIn(verdict) else {
                errorText = WaitingRoom.refusal(verdict) ?? "This name could not be checked. Nobody was let in."
                return
            }
            // Only hand out keys once the server has actually admitted this exact user.
            guard (try? await client.approveJoinRequest(serverId: sid, userId: req.userId)) != nil else {
                await refreshPending()
                busy = false
                return
            }
            // Hand the new member the space key + channel keys, end to end (the server never
            // sees them), so their channels appear without anything else to paste. The username
            // lookup must resolve to the SAME account we just approved, never a different one.
            if let found = try? await client.findUser(username: req.username), found.userId == req.userId {
                try? await client.provisionMember(serverId: sid, userId: found.userId, deviceId: found.deviceId)
            }
        } else {
            try? await client.denyJoinRequest(serverId: sid, userId: req.userId)
        }
        await refreshPending()
    }
}

/// Presents the owner setup over whatever the main window shows, when it is asked for from
/// outside a screen that has its own button for it (the menu bar; an invite with no owner).
struct HostSetupPresenter: ViewModifier {
    /// Handed over explicitly: this sits outside the window's own environment.
    let app: AppState
    @ObservedObject private var host = HostManager.shared
    @ObservedObject private var lock = AppLock.shared

    func body(content: Content) -> some View {
        // Never over the lock screen: while the app is locked nothing of it is presented; the
        // request stays and the sheet opens once the app is unlocked.
        content.sheet(isPresented: Binding(get: { host.showSetupWizard && !lock.isLocked },
                                           set: { if !lock.isLocked { host.showSetupWizard = $0 } }), onDismiss: {
            // The invite panel is a sheet of the same window: it opens once this one is gone.
            if host.inviteAfterSetup {
                host.inviteAfterSetup = false
                host.showInvitePanel = true
            }
        }) {
            DismissableSheet {
                HostWizardView(autoStart: true, onSignedIn: {
                    // The wizard asked for the invite panel; it has to wait for this sheet.
                    if host.showInvitePanel { host.showInvitePanel = false; host.inviteAfterSetup = true }
                    host.showSetupWizard = false
                })
            }
            .environmentObject(app)
        }
    }
}
#else
import SwiftUI

/// Hosting is a Mac capability: nothing to present elsewhere.
struct HostSetupPresenter: ViewModifier {
    let app: AppState
    func body(content: Content) -> some View { content }
}
#endif
