import SwiftUI

/// Connect to a friend's skwod: open (or paste, or scan) their invite, then sign up / log in.
/// skwod hosts nothing — every skwod is run by a friend, and the invite is both where it lives
/// (`skwod://join/<host key>`) and how they let you in (`#<code>`). Classic `https://` servers
/// (a VPS on a domain) keep working with the same form.
struct AuthView: View {
    @EnvironmentObject private var app: AppState
    /// Called after a successful connect (used when adding a workspace from a sheet).
    var onConnected: (() -> Void)? = nil
    /// "Log in again" for one signed-out skwod (from its rail tile): opens on Log in with its
    /// address filled in.
    var relogin: Workspace? = nil
    /// Create account (needs the invite's code) vs Log in (an existing account: the skwod's
    /// address, username and password — never a code). Set on appear: a device that already
    /// knows a skwod opens on Log in.
    @State private var isSignup = true
    /// The user picked "Log in" themselves: a pasted or scanned link never flips it back.
    @State private var userChoseLogIn = false
    /// Create account with an address that carries no code: the code, typed on its own.
    @State private var typedCode = ""
    @State private var server = ""
    /// What we're doing while the button spins ("Finding your host…").
    @State private var statusText = ""
    @State private var showScanner = false
    /// Sign-up takes ONE paste: the host's invite link, validated and split at submit.
    @State private var inviteLink = ""
    @State private var username = ""
    @State private var password = ""
    @State private var busy = false
    @State private var errorText = ""
    /// The last attempt could not reach a p2p host: the button says "Try again" and tips show.
    @State private var hostUnreachable = false
    /// A device pairing by a scanned QR (build 48).
    @State private var pairing: NewDevicePairing?
    @State private var showHost = false
    /// If the pasted address is a skwod you already belong to (it just moved), its name — for a
    /// credential-free Reconnect instead of making you sign in again.
    @State private var reconnectName: String?
    /// Addresses (no credentials) the user has signed into before — kept across sign-out for a
    /// one-tap log back in. Loaded on appear.
    @State private var knownServers: [KnownServer] = []
    /// What the host said about the invite in the link field — asked the moment a link is
    /// opened, scanned or pasted, BEFORE anyone picks a name and a password for it.
    @State private var inviteState: InviteState = .unknown
    @FocusState private var focus: Field?

    private enum InviteState: Equatable {
        case unknown, checking
        case valid(requiresApproval: Bool)
        /// Expired, used up / revoked, or not a code this skwod knows. The sentence to show.
        case invalid(String)
        /// The host did not answer, so nothing is known yet (signing up will ask again).
        case unreachable
    }

    private enum Field { case server, joinCode, code, username, password }

    var body: some View {
        ZStack {
            AuthBackground()
            ScrollView {
                GlassEffectContainer(spacing: 18) {
                    VStack(spacing: 22) {
                        header
                        controls
                    }
                    .frame(maxWidth: 400)
                    .padding(28)
                    .frame(maxWidth: .infinity)   // center the 400-wide form in the window
                }
            }
        }
        #if os(macOS)
        .frame(minWidth: 560, idealWidth: 620, minHeight: 720, idealHeight: 800)
        #endif
        .task(id: entry) {
            // "You're already in X — it just moved": only probed for https addresses. A p2p host is
            // never dialed just because text was typed; that happens when the user submits.
            reconnectName = nil
            // Nor for an address that only ARRIVED (a tapped link): nothing is dialed for it
            // until the user submits, or changes the field themselves.
            guard InviteDialRule.mayProbe(entry: entry, outsideEntry: outsideEntry) else { return }
            guard case .https(let a)? = (try? InviteLink.parse(entry))?.address, a.count > 10 else { return }
            try? await Task.sleep(for: .milliseconds(600))
            reconnectName = await app.knownSkwodName(a)
        }
        .onAppear {
            knownServers = KnownServerStore.all()
            // Someone who has used Skwod on this device before is most likely logging in.
            if !knownServers.isEmpty || !app.workspaces.isEmpty { isSignup = false }
            if let relogin {
                isSignup = false; userChoseLogIn = true
                server = relogin.server
                focus = .username
            }
            adoptSignedOut()
            adoptIncomingInvite()
            #if DEBUG
            if let invite = E2E.env("SKWOD_E2E_INVITE"), inviteLink.isEmpty, server.isEmpty { adopt(invite) }
            if let qr = E2E.env("SKWOD_E2E_PAIR_QR"), pairing == nil, app.workspaces.isEmpty { adopt(qr) }
            #endif
        }
        .onChange(of: app.incomingInvite) { _, _ in adoptIncomingInvite() }
        .sheet(item: $pairing) { p in NewDevicePairingSheet(pairing: p).environmentObject(app) }
        .onChange(of: app.signedOut) { _, _ in adoptSignedOut() }
        .onChange(of: inviteLink) { _, _ in if !checkingLink { inviteState = .unknown } }
        #if os(iOS)
        .sheet(isPresented: $showScanner) {
            QRScannerSheet(prompt: "Point the camera at your host's invite, or at “Add a device” on your other device.") { scanned in
                showScanner = false
                // After the scanner has gone: a pairing QR opens a sheet of its own.
                Task { try? await Task.sleep(for: .milliseconds(600)); adopt(scanned) }
            }
        }
        #endif
    }

    /// True when this Mac runs its own skwod server, so log-in can pin a "This Mac" chip.
    private var hostsThisMac: Bool {
        #if os(macOS)
        return HostManager.shared.hasHostedBefore
        #else
        return false
        #endif
    }

    /// The host's own stable localhost address ("" on platforms that can't host).
    private static var localHostURL: String {
        #if os(macOS)
        return HostManager.localURL
        #else
        return ""
        #endif
    }

    /// A one-tap server-address chip under the log-in field.
    private func serverChip(icon: String, name: String, accented: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: icon).font(.system(size: 11))
                Text(name).font(.system(size: 13, weight: .medium)).lineLimit(1)
            }
            .foregroundStyle(accented ? AnyShapeStyle(Color.skAccent) : AnyShapeStyle(.white.opacity(0.85)))
            .padding(.horizontal, 11).padding(.vertical, 6)
            .background(accented ? AnyShapeStyle(Color.skAccent.opacity(0.15)) : AnyShapeStyle(.white.opacity(0.08)), in: Capsule())
        }
        .buttonStyle(.plain)
    }

    /// The text currently in the address field (invite link on sign-up, address on log-in).
    private var entry: String { isSignup ? inviteLink : server }

    /// The entry parsed, if it is valid so far. A bare 52-character host key counts.
    private var parsedEntry: ParsedInvite? { try? InviteLink.parse(LoginEntry.canonical(entry)) }

    /// Take an invite that arrived from outside (deep link). Shown in the form; nothing is sent
    /// anywhere until the user fills in credentials and submits.
    private func adoptIncomingInvite() {
        guard let raw = app.incomingInvite else { return }
        // A tapped link is whatever its author wrote. Its host is NOT contacted to "check the
        // invite" on arrival — that would tell the author this device's IP address and that
        // Skwod is installed, for one tap. The check runs when the user submits the form.
        outsideEntry = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        adopt(raw, source: .outsideLink)
        // On the signed-out root screen the invite has been consumed; in the add-a-skwod sheet it
        // stays set (it is what keeps the sheet open) and is cleared when the sheet closes.
        if onConnected == nil { app.incomingInvite = nil }
    }

    /// The server ended this skwod's session: open on "Log in", with its address filled in.
    private func adoptSignedOut() {
        guard onConnected == nil, let notice = app.signedOut, inviteLink.isEmpty, server.isEmpty else { return }
        isSignup = false
        server = notice.address
        #if DEBUG
        // End-to-end automation: after a `signout` command, log back in with the test account
        // (the same form, the same `authenticate()`), a little later so the signed-out screen
        // can be observed first. `SKWOD_E2E_RELOGIN=any` also logs back in when the session was
        // ended for the user (a superseded install after "Set up this device again").
        let relogin = E2E.env("SKWOD_E2E_RELOGIN")
        if (notice.byUser && relogin == "1") || relogin == "any",
           let u = E2E.env("SKWOD_E2E_USER"), let p = E2E.env("SKWOD_E2E_PASSWORD") {
            username = u; password = p
            Task {
                try? await Task.sleep(for: .seconds(Double(E2E.env("SKWOD_E2E_RELOGIN_DELAY") ?? "") ?? 8))
                guard app.signedOut != nil else { return }
                await authenticate()
                if !errorText.isEmpty {
                    try? errorText.write(to: E2E.outDir.appendingPathComponent("auth-error.txt"), atomically: true, encoding: .utf8)
                }
            }
        }
        #endif
    }

    /// True while `adopt` is putting a link into the field (so the change does not reset the
    /// check that is about to run for that very link).
    @State private var checkingLink = false

    /// The link a tap outside the app put into the form, while it is still what the field
    /// holds (`InviteDialRule`).
    @State private var outsideEntry: String?

    /// Ask the host whether this invite still lets someone in. Runs when the USER scans or
    /// pastes a link — not while typing, and not for a link that merely arrived from outside
    /// — and again when the form is submitted.
    /// Returns false only when the host said the invite is no good.
    @discardableResult
    private func checkInviteNow(_ invite: ParsedInvite) async -> Bool {
        guard let code = invite.joinCode else { return true }
        inviteState = .checking
        guard let base = try? await app.liveBase(for: invite.address),
              let check = try? await checkInvite(baseUrl: base, joinCode: code) else {
            inviteState = .unreachable
            return true
        }
        #if DEBUG
        E2E.noteInviteCheck(valid: check.valid, reason: check.reason, requiresApproval: check.requiresApproval)
        #endif
        if check.valid {
            inviteState = .valid(requiresApproval: check.requiresApproval)
            return true
        }
        inviteState = .invalid(Self.inviteProblem(check.reason))
        return false
    }

    static func inviteProblem(_ reason: String?) -> String {
        switch reason {
        case "expired": return "This invite has expired. Ask your host to send a new one."
        case "used": return "This invite has already been used or was cancelled. Ask your host to send a new one."
        default: return "This Skwod doesn't recognise that invite. Check that you have the whole link, or ask your host for a new one."
        }
    }

    /// Put a link (deep link, QR scan, pasteboard) into the right field. Invalid input is shown
    /// as an error and never placed in a field.
    private func adopt(_ raw: String, source: InviteDialRule.Source = .userAction) {
        if raw.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("skwod-pair:") {
            adoptPairing(raw)
            return
        }
        do {
            let parsed = try InviteLink.parse(LoginEntry.canonical(raw))
            errorText = ""
            let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            // A link with a code suggests a new member — unless the user chose "Log in" (a
            // second device pasting the invite it once joined with).
            let mode = LoginEntry.modeAfterAdopting(hasCode: parsed.joinCode != nil,
                                                     userChoseLogIn: userChoseLogIn && !isSignup)
            if mode == .createAccount {
                isSignup = true
                checkingLink = true
                inviteLink = text
                // Before the name and password are even asked for: is this invite still good?
                // (Asked only when the user brought the link in; see `adoptIncomingInvite`.)
                let precheck = Task { () -> Bool in
                    guard InviteDialRule.mayDialBeforeSubmit(source) else {
                        inviteState = .unknown
                        checkingLink = false
                        return true
                    }
                    let ok = await checkInviteNow(parsed)
                    checkingLink = false
                    return ok
                }
                #if DEBUG
                if E2E.env("SKWOD_E2E_USER") != nil {
                    Task {
                        guard !(await precheck.value), case .invalid(let why) = inviteState else { return }
                        try? FileManager.default.createDirectory(at: E2E.outDir, withIntermediateDirectories: true)
                        try? why.write(to: E2E.outDir.appendingPathComponent("auth-error.txt"), atomically: true, encoding: .utf8)
                    }
                }
                #endif
            } else {
                isSignup = false
                server = text
            }
            focus = .username
            #if DEBUG
            // End-to-end automation (E2EHooks.swift): fill in the test account and submit.
            if let u = E2E.env("SKWOD_E2E_USER"), let p = E2E.env("SKWOD_E2E_PASSWORD") {
                username = u; password = p; focus = nil
                Task {
                    try? await Task.sleep(for: .seconds(E2E.submitDelay))
                    // An invite the host already refused never reaches the form's submit.
                    if case .invalid = inviteState { return }
                    await authenticate()
                    if !errorText.isEmpty {
                        try? FileManager.default.createDirectory(at: E2E.outDir, withIntermediateDirectories: true)
                        try? errorText.write(to: E2E.outDir.appendingPathComponent("auth-error.txt"), atomically: true, encoding: .utf8)
                    }
                }
            }
            #endif
        } catch {
            errorText = error.localizedDescription
        }
    }

    private func pasteFromClipboard() {
        if let text = Clipboard.string() { adopt(text) }
    }

    private var header: some View {
        VStack(spacing: 12) {
            SkwodLogoTile(size: 96)
            Text("Skwod").font(.system(size: 36, weight: .bold, design: .rounded)).foregroundStyle(.white)
            Text("end-to-end encrypted").font(.subheadline).foregroundStyle(.white.opacity(0.55))
        }
        .padding(.bottom, 6)
    }

    private var controls: some View {
        VStack(spacing: 16) {
            if let notice = app.signedOut, onConnected == nil {
                VStack(alignment: .leading, spacing: 8) {
                    Label(notice.byUser ? "You signed out of \(notice.name)" : "You've been signed out of \(notice.name)",
                          systemImage: notice.byUser ? "person.crop.circle.badge.checkmark" : "person.crop.circle.badge.exclamationmark")
                        .font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                    Text(notice.byUser
                         ? "Your messages and keys are still on this device, locked. Log in again to carry on where you left off — no relinking."
                         : "Your session there ended — it expired, or it was closed from another device. Log in again to carry on; your messages and keys on this device are still here.")
                        .font(.caption).foregroundStyle(.white.opacity(0.7)).fixedSize(horizontal: false, vertical: true)
                    ForEach(app.workspaces.filter { !$0.isSignedOut && $0.id != notice.workspaceId }) { other in
                        Button("Open \(other.displayName) instead") { Task { await app.activate(other) } }
                            .font(.caption.weight(.semibold)).buttonStyle(.plain).foregroundStyle(.skAccent)
                    }
                }
                .padding(14).frame(maxWidth: .infinity, alignment: .leading)
                .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
                .accessibilityIdentifier("auth.signedOut")
            }
            #if os(iOS)
            // Build 48: signing in on a new phone is one scan of the QR your other device shows
            // (Profile → Devices → Add a device). The link field below stays as the fallback.
            do {
                VStack(spacing: 6) {
                    Button { showScanner = true } label: {
                        Label("Scan from your other device", systemImage: "qrcode.viewfinder")
                            .fontWeight(.semibold).frame(maxWidth: .infinity).padding(.vertical, 6)
                    }
                    .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                    .accessibilityIdentifier("auth.scanPairing")
                    Text("Have a link instead? Paste it below.")
                        .font(.caption2).foregroundStyle(.white.opacity(0.45))
                }
            }
            #endif
            Picker("", selection: Binding(get: { isSignup }, set: { new in
                withAnimation(.smooth) { isSignup = new }
                userChoseLogIn = !new
                // The same link serves both modes: carry it across instead of starting over.
                if new, inviteLink.isEmpty, !server.isEmpty { inviteLink = server }
                if !new, server.isEmpty, !inviteLink.isEmpty { server = inviteLink }
            })) {
                Text("Log in").tag(false)
                Text("Create account").tag(true)
            }
            .pickerStyle(.segmented).labelsHidden()
            .accessibilityIdentifier("auth.mode")

            if isSignup {
                // Joining = one paste (or one tap on the link). It carries where the skwod is AND the code.
                glassField(icon: "link", placeholder: "Invite link from your host", text: $inviteLink, field: .joinCode)
                entryTools
                // An address without a code (or a bare host key): the code on its own.
                if let p = parsedEntry, p.joinCode == nil {
                    glassField(icon: "number", placeholder: "Invite code (e.g. SKWD-AB12-CD34)", text: $typedCode, field: .code)
                        .onChange(of: typedCode) { _, v in
                            // Upper case as they type; spaces and dashes are tolerated.
                            let upper = v.uppercased()
                            if upper != v { typedCode = upper }
                        }
                }
                inviteStatus
                // A second account on a skwod this device is already in is a second entry in the
                // rail (it has its own keys): almost always a mistake — say so before it happens.
                if let node = parsedEntry?.address.nodeId, let known = app.workspaces.first(where: { $0.nodeId == node }) {
                    HStack(spacing: 8) {
                        Text("You already have an account on \(known.displayName) on this device.")
                            .font(.caption2).foregroundStyle(.orange.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 4)
                        Button("Log in instead") {
                            withAnimation(.smooth) { isSignup = false }
                            userChoseLogIn = true
                            if server.isEmpty { server = inviteLink }
                        }
                        .font(.caption2.weight(.semibold)).buttonStyle(.plain).foregroundStyle(.skAccent)
                    }
                    .padding(.horizontal, 8)
                    .accessibilityIdentifier("auth.alreadyMember")
                }
            } else {
                // A full invite link works here too (its code is simply not used), and so do a
                // skwod:// link and the bare host key. The text is never cut at "#": in the share
                // link the host key itself is after the "#".
                glassField(icon: "server.rack", placeholder: "Invite link, skwod:// link or host key", text: $server, field: .server)
                entryTools
                if parsedEntry?.joinCode != nil {
                    fieldHint("Logging in doesn't need the invite code — only your username and password.")
                }
                // One-tap "log back into a skwod you've used" — addresses only, kept across sign-out.
                // When this Mac hosts a skwod, a pinned "This Mac" chip comes first so the host never
                // faces a blank address field, even with an empty history.
                if hostsThisMac || !knownServers.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 8) {
                            if hostsThisMac {
                                serverChip(icon: "desktopcomputer", name: "This Mac", accented: true) {
                                    server = Self.localHostURL
                                    focus = .username
                                }
                            }
                            ForEach(knownServers.filter { !hostsThisMac || $0.address != Self.localHostURL }) { known in
                                serverChip(icon: "clock.arrow.circlepath", name: known.name) {
                                    server = known.address
                                    focus = .username
                                }
                            }
                        }
                        .padding(.horizontal, 2)
                    }
                }
            }
            glassField(icon: "at", placeholder: "Username", text: $username, field: .username)
                .onChange(of: username) { _, v in
                    // Usernames are lowercase on the server — normalize as they type.
                    let lowered = v.lowercased()
                    if lowered != v { username = lowered }
                }
            if let hint = usernameHint {
                fieldHint(hint)
            }
            glassField(icon: "lock.fill", placeholder: "Password", text: $password, field: .password, secure: true)
            if let hint = passwordHint {
                fieldHint(hint)
            }

            if let name = reconnectName {
                VStack(alignment: .leading, spacing: 8) {
                    Text("You're already in “\(name)” — it just moved.")
                        .font(.subheadline).foregroundStyle(.white)
                    Button(action: { Task { await reconnect(name) } }) {
                        HStack(spacing: 8) {
                            if busy { ProgressView().controlSize(.small) }
                            Image(systemName: "link"); Text("Reconnect to \(name)").fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity).padding(.vertical, 6)
                    }
                    .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                    .disabled(busy)
                }
                .padding(14)
                .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            }

            if !errorText.isEmpty {
                Label(errorText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red.opacity(0.9))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                if hostUnreachable {
                    Text(HostUnreachableHint.tips)
                        .font(.caption2).foregroundStyle(.white.opacity(0.6))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                    // The relay setting lives in Profile, which a signed-out device can't open.
                    if !P2PManager.publicFallback {
                        Text(HostUnreachableHint.relaysOff)
                            .font(.caption2).foregroundStyle(.orange.opacity(0.9))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Use a relay when needed, and try again") {
                            P2PManager.publicFallback = true
                            NotificationState.publicFallback = true
                            Task {
                                _ = await P2PManager.shared.applyRelaySetting()
                                await authenticate()
                            }
                        }
                        .font(.caption.weight(.semibold)).buttonStyle(.glass).tint(.skAccent)
                        .accessibilityIdentifier("auth.enableRelays")
                    }
                }
            }

            Button(action: { Task { await authenticate() } }) {
                HStack(spacing: 8) {
                    if busy { ProgressView().controlSize(.small).tint(.white) }
                    Text(busy && !statusText.isEmpty ? statusText
                         : hostUnreachable ? "Try again"
                         : (isSignup ? "Create account" : "Log in")).fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .disabled(busy || !formValid)

            Text(footerText)
                .font(.caption2).foregroundStyle(.white.opacity(0.4)).multilineTextAlignment(.center)

            #if os(macOS)
            Divider().overlay(.white.opacity(0.12)).padding(.vertical, 4)
            VStack(spacing: 6) {
                Text("Want to host your own Skwod?").font(.caption).foregroundStyle(.white.opacity(0.5))
                Button { showHost = true } label: {
                    Label("Start a server", systemImage: "server.rack").frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .controlSize(.large).buttonStyle(.glass).tint(.skAccent)
            }
            #endif
        }
        #if os(macOS)
        .sheet(isPresented: $showHost) {
            NavigationStack {
                // The wizard starts the server AND signs this Mac in as its owner over the local
                // path, so when it's done there is nothing left to fill in here.
                HostWizardView(onSignedIn: {
                    showHost = false
                    onConnected?()
                })
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Done") { showHost = false }
                    }
                }
            }
            .frame(minWidth: 640, minHeight: 680)
        }
        #endif
    }

    /// nil = fine so far; shown live under the field.
    private var usernameHint: String? {
        guard !username.isEmpty else { return nil }
        let valid = (3...32).contains(username.count)
            && username.allSatisfy { ($0.isASCII && $0.isLowercase && $0.isLetter) || ($0.isASCII && $0.isNumber) || $0 == "_" }
        return valid ? nil : "Usernames are 3–32 characters: a–z, 0–9, underscore."
    }

    private var passwordHint: String? {
        guard isSignup, !password.isEmpty, password.count < 8 else { return nil }
        return "Passwords need at least 8 characters."
    }

    /// Under the link field: paste / scan shortcuts, and — once the link parses as a p2p invite —
    /// the host's key in short form, so "is this really my friend's skwod?" has something to compare.
    @ViewBuilder private var entryTools: some View {
        HStack(spacing: 10) {
            Button { pasteFromClipboard() } label: { Label("Paste", systemImage: "doc.on.clipboard") }
            #if os(iOS)
            Button { showScanner = true } label: { Label("Scan QR", systemImage: "qrcode.viewfinder") }
            #else
            Button { if let text = QRCode.readFromImageFile() { adopt(text) } } label: {
                Label("QR from image…", systemImage: "qrcode.viewfinder")
            }
            #endif
            Spacer()
        }
        .font(.caption).buttonStyle(.plain).foregroundStyle(.skAccent)
        .padding(.horizontal, 8)
        if let nodeId = parsedEntry?.address.nodeId {
            Label("Host key \(InviteLink.shortKey(nodeId))", systemImage: "key.fill")
                .font(.caption2.monospaced()).foregroundStyle(.white.opacity(0.5))
                .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 8)
        }
    }

    /// Under the invite field: what the host said about this invite.
    @ViewBuilder private var inviteStatus: some View {
        switch inviteState {
        case .unknown:
            EmptyView()
        case .checking:
            HStack(spacing: 6) {
                ProgressView().controlSize(.mini)
                Text("Checking this invite with the host…").font(.caption2).foregroundStyle(.white.opacity(0.6))
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 8)
        case .valid(let requiresApproval):
            Label(requiresApproval ? "Invite is valid. The host will need to let you in after you sign up."
                                   : "Invite is valid.", systemImage: "checkmark.circle.fill")
                .font(.caption2).foregroundStyle(.green.opacity(0.9))
                .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 8)
        case .invalid(let why):
            Label(why, systemImage: "xmark.octagon.fill")
                .font(.caption).foregroundStyle(.red.opacity(0.95))
                .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 8)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("auth.inviteInvalid")
        case .unreachable:
            Label("Couldn't reach the host to check this invite yet. You can still try — their computer may be asleep.", systemImage: "wifi.exclamationmark")
                .font(.caption2).foregroundStyle(.orange.opacity(0.9))
                .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 8)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var inviteRefused: Bool {
        if isSignup, case .invalid = inviteState { return true }
        return false
    }

    private var formValid: Bool {
        usernameHint == nil && !username.isEmpty && !password.isEmpty && !inviteRefused
            && (!isSignup || (password.count >= 8 && !inviteLink.isEmpty
                              && (parsedEntry?.joinCode != nil || !JoinCode.normalize(typedCode).isEmpty)))
            && (isSignup || !server.isEmpty)
    }

    private func fieldHint(_ text: String) -> some View {
        Text(text).font(.caption2).foregroundStyle(.orange.opacity(0.9))
            .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 8)
    }

    private var footerText: String {
        isSignup
            ? "New here? Open or paste your host's invite — it already says where their Skwod is."
            : "Already have an account? Paste the invite link or address you joined with, or pick a skwod above — no code needed."
    }

    private func glassField(icon: String, placeholder: String, text: Binding<String>, field: Field, secure: Bool = false) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon).foregroundStyle(.skAccent.opacity(0.8)).frame(width: 20)
            Group {
                if secure { SecureField(placeholder, text: text) } else { TextField(placeholder, text: text) }
            }
            .textFieldStyle(.plain).foregroundStyle(.white)
            #if os(iOS)
            .textInputAutocapitalization(.never).autocorrectionDisabled()
            .keyboardType(field == .server ? .URL : .default)
            #endif
            .focused($focus, equals: field)
        }
        .padding(.horizontal, 16).padding(.vertical, 14)
        .glassEffect(.regular, in: .capsule)
        .contentShape(Capsule())
        // One tap on the capsule's padding focuses the field. A plain `.onTapGesture` here also
        // sat over the text field itself, where it could take the click meant for the field.
        .simultaneousGesture(TapGesture().onEnded { if focus != field { focus = field } })
    }

    /// A scanned "Add a device" QR (build 48): it names a skwod (by key), a relay and an account,
    /// and carries a one-time code and a commitment. Nothing here touches the network: the next
    /// screen first asks "Join … as …?", and only then dials and pairs (`NewDevicePairing`).
    ///
    /// Security: anyone can print a QR, so a scanned one is never a reason to type a password, and
    /// pairing needs none. The skwod is named by a workspace this device already has, otherwise by
    /// the host's short key — never by anything the QR says — and the person picks the matching
    /// emoji on the device they already use.
    private func adoptPairing(_ raw: String) {
        do {
            let offer = try pairingQrDecode(text: raw, now: UInt64(Date().timeIntervalSince1970))
            let mine = app.workspaces.first { $0.nodeId == offer.nodeId }
            errorText = ""
            pairing = NewDevicePairing(offer: offer, known: mine != nil, knownName: mine?.name)
        } catch {
            errorText = coreErrorText(error, fallback: "That QR code isn't from Skwod's “Add a device”.")
            #if DEBUG
            E2E.pairingErrorDetail = String(describing: error)
            E2E.notePairing(.failed(errorText))
            #endif
        }
    }

    /// Credential-free reconnect to a skwod you already belong to whose address moved.
    private func reconnect(_ name: String) async {
        busy = true; errorText = ""; focus = nil
        var ok = false
        if let address = parsedEntry?.address, let base = try? await app.liveBase(for: address) {
            ok = await app.reconnectIfKnown(address, liveBase: base)
        }
        busy = false
        if ok { onConnected?() } else { errorText = "Couldn't verify that address is really “\(name).”" }
    }

    private func authenticate() async {
        busy = true; errorText = ""; statusText = ""; hostUnreachable = false; focus = nil
        defer { busy = false; statusText = "" }
        // 1) Validate what was entered. Nothing touches the network before this passes.
        let invite: ParsedInvite
        do { invite = try InviteLink.parse(LoginEntry.canonical(entry)) } catch {
            errorText = error.localizedDescription
            return
        }
        // Only a NEW account needs the code — from the link, or typed on its own.
        let joinCode = LoginEntry.codeToSend(invite.joinCode ?? typedCode, mode: isSignup ? .createAccount : .logIn)
        if isSignup && joinCode == nil {
            errorText = "Creating an account needs the invite code. Paste the full invite link, or type the code. Already have an account? Choose Log in."
            return
        }
        // 2) Reach the skwod. For a p2p host this finds the host by its key and connects — the
        //    connection only succeeds if the other end holds that key.
        let base: String
        if let nodeId = invite.address.nodeId {
            statusText = "Finding your host…"
            RelayHintStore.set(invite.relayHint, for: nodeId)
        }
        // Bounded: the core gives up after ~20 s and P2PManager has its own backstop, so this
        // always ends in either a connection or the error below — never an endless spinner.
        do { base = try await app.liveBase(for: invite.address) } catch {
            hostUnreachable = invite.address.nodeId != nil
            errorText = invite.address.nodeId != nil
                ? HostUnreachableHint.message
                : "Can't reach that Skwod. Check the address."
            return
        }
        statusText = ""
        // A typed link was never checked: ask now, before an account is created for nothing.
        if isSignup, let code = joinCode, let check = try? await checkInvite(baseUrl: base, joinCode: code) {
            #if DEBUG
            E2E.noteInviteCheck(valid: check.valid, reason: check.reason, requiresApproval: check.requiresApproval)
            #endif
            if !check.valid {
                inviteState = .invalid(Self.inviteProblem(check.reason))
                return
            }
            inviteState = .valid(requiresApproval: check.requiresApproval)
        }
        // If this is a skwod you're already in (it moved, or you now have its skwod:// address),
        // reconnect silently — no re-login.
        if await app.reconnectIfKnown(invite.address, liveBase: base) { onConnected?(); return }
        // If the address CLAIMS to be a skwod you're in (instanceId match) but failed the pinned-key
        // proof, it is an impostor echoing public identity values — refuse rather than fall through
        // to sending username+password there (credential-phishing defense).
        if await app.impersonatesKnownSkwod(base) {
            errorText = "That address claims to be a Skwod you're in but failed its security check — don't enter your password."
            return
        }
        do {
            let s: AuthSession = isSignup
                ? try await signup(baseUrl: base, username: username, password: password, joinCode: joinCode ?? "")
                : try await login(baseUrl: base, username: username, password: password)
            // Sign-up only creates the account — the shell joins the server with the same code
            // (membership + auto-provisioned keys + channel discovery) once the workspace is live.
            if isSignup {
                app.pendingJoinCode = joinCode
                // …and remember it on disk until the join is finished: if the app is closed
                // before then, the next launch carries on instead of leaving an account that
                // is in no server.
                if let code = joinCode { PendingJoinStore.set(PendingJoin(code: code), address: invite.address.stored) }
            }
            await app.signIn(s, address: invite.address, liveBase: base)
            // When the shell is already up (adding a second skwod), nothing re-runs its setup —
            // nudge it to run the join now.
            if isSignup { app.pendingJoinTick += 1 }
            onConnected?()
        } catch {
            errorText = AuthView.message(for: error, signup: isSignup)
        }
    }

    /// A human sentence for a failed signup/login. Works off the error's shape only.
    static func message(for error: Error, signup: Bool) -> String {
        if case CoreError.UpdateRequired = error {
            return "This Skwod needs a newer version of the app (or the host needs to update their server)."
        }
        let d = String(describing: error).lowercased()
        return d.contains("409") || d.contains("conflict") ? "That username is taken."
            : d.contains("password too short") || d.contains("400") || d.contains("bad request") ? "Check the username (a–z, 0–9, _) and password (at least 8 characters)."
            : d.contains("429") || d.contains("rate") ? "Too many attempts — wait a minute and try again."
            : d.contains("invite full") ? "This invite already has a lot of people waiting to be let in. Ask your host to approve them (or send you a new invite), then try again."
            : d.contains("403") || d.contains("forbidden") ? (signup ? "That invite isn't valid any more. Ask your host for a fresh one." : "This account can't sign in here.")
            : d.contains("401") || d.contains("unauthorized") ? "Wrong username or password."
            : d.contains("dns") || d.contains("connect") || d.contains("timed out") || d.contains("network") || d.contains("reach") ? "Can't reach that Skwod right now."
            : "Something went wrong. Try again."
    }
}
