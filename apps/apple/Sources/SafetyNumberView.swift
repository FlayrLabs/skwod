import SwiftUI

/// Out-of-band verification of a contact, Signal-style.
///
/// There is ONE safety number per pair of accounts: 60 digits derived from every device identity
/// key on both sides. If the number on this screen matches the one on theirs, nobody is sitting
/// between the two of you, on any of your devices. That is the real trust boundary in a
/// self-hosted world: a hostile host can relay keys, but it cannot make the two numbers agree.
///
/// Three rules this screen enforces:
///
/// - **Verification is bound to what was compared.** The number the user confirmed is handed to
///   the core (`verifyContact`), which re-reads the directory, recomputes it and refuses if it is
///   no longer that number. A device added between showing the number and confirming it can
///   never end up "verified".
/// - **The comparison must happen outside the conversation.** Whoever controls the conversation
///   also controls any number, screenshot or code sent through it. So the only automatic check
///   is a LIVE camera scan of the other person's screen; there is no "check a picture". On a Mac
///   (no camera pointed at anything) the digits are compared by eye and confirmed explicitly.
/// - **The QR code is directional** (`safetyQr`): it carries the presenter's fingerprint, then
///   the scanner's. Scanning your own screen, or a picture of your own code, does not match.
struct SafetyNumberView: View {
    let peerName: String
    let peerUserId: String
    /// Called after the contact's state changed from this screen (verified, or a changed device
    /// set accepted) so a held send can go.
    var onAccepted: (() -> Void)? = nil
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss

    /// The number ON SCREEN. Verification is requested for exactly this value.
    @State private var number: String?
    /// The (directional) QR payload shown with it.
    @State private var qr: String?
    @State private var failed = false
    @State private var status: ContactStatus?
    @State private var scan: ScanResult?
    @State private var showScanner = false
    @State private var confirmManual = false
    @State private var problem: String?

    enum ScanResult: Equatable { case match, mismatch, notASafetyNumber }

    var body: some View {
        ZStack {
            SkwodBackground()
            ScrollView {
                VStack(spacing: 18) {
                    header
                    if let status, status.sendsHeld || status.unvouchedDevices > 0 { changedCard(status) }
                    if let number {
                        if let qr {
                            QRCodeView(text: qr, size: 190).accessibilityLabel("Safety number QR code")
                        }
                        Text(SafetyNumber.grouped(number))
                            .font(.system(.body, design: .monospaced)).foregroundStyle(.white)
                            .multilineTextAlignment(.center).lineSpacing(4)
                            .padding(16)
                            .glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
                            .accessibilityLabel("Safety number")
                            .accessibilityValue(number)
                        outOfBandWarning
                        if let scan { scanBanner(scan) }
                        verifyControls
                    } else if failed {
                        Text("Couldn't work out a safety number. \(peerName) may not have set up a device yet, or you're offline.")
                            .font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
                    } else {
                        ProgressView().tint(.skAccent)
                    }
                    if let problem {
                        Text(problem).font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Button("Done") { dismiss() }
                        .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                }
                .padding(26).frame(maxWidth: 460)
                .frame(maxWidth: .infinity)
            }
        }
        #if os(iOS)
        .sheet(isPresented: $showScanner) {
            QRScannerSheet(prompt: "Point the camera at the code on \(peerName)'s own screen — not at a picture of it.") { text in
                showScanner = false
                Task { await check(scanned: text) }
            }
        }
        #endif
        .confirmationDialog("Did all 60 digits match?", isPresented: $confirmManual, titleVisibility: .visible) {
            Button("Yes — they match, mark \(peerName) verified") { Task { await verify() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Only confirm if you read the number on \(peerName)'s own screen — in person, or read aloud over a phone or video call that does not go through this Skwod. A number or screenshot sent in this conversation does not count: whoever could be in the middle would have chosen it.")
        }
        .task { await compute() }
    }

    private var header: some View {
        VStack(spacing: 10) {
            Image(systemName: status?.verified == true ? "checkmark.shield.fill" : "shield.lefthalf.filled")
                .font(.system(size: 48))
                .foregroundStyle(status?.verified == true ? Color.green : .skAccent)
            Text(status?.verified == true ? "\(peerName) is verified" : "Verify \(peerName)")
                .font(.title2.bold()).foregroundStyle(.white)
            Text("This is the one safety number you share with \(peerName) — it covers all of their devices and all of yours\(deviceNote). If it is the same number on their screen, nobody is in the middle.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var deviceNote: String {
        guard let n = status?.devices, n > 0 else { return "" }
        return n == 1 ? " (they have 1 device)" : " (they have \(n) devices)"
    }

    /// The comparison only means something if it bypasses the thing being checked.
    private var outOfBandWarning: some View {
        Label {
            Text("Compare in person, or over a channel that is not this Skwod. Never compare using a number, screenshot or code sent in this conversation — that is exactly what someone in the middle could replace.")
                .fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "person.2.wave.2.fill")
        }
        .font(.caption).foregroundStyle(.white.opacity(0.75))
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(.white.opacity(0.06), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    /// A verified contact's devices changed, or the server lists a device nobody vouched for.
    private func changedCard(_ s: ContactStatus) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(s.sendsHeld ? "Sending to \(peerName) is paused" : "Unconfirmed device",
                  systemImage: "exclamationmark.shield.fill")
                .font(.subheadline.weight(.semibold)).foregroundStyle(.orange)
            Text(changedText(s))
                .font(.caption).foregroundStyle(.white.opacity(0.8)).fixedSize(horizontal: false, vertical: true)
            Button { Task { await accept() } } label: {
                Text(s.sendsHeld ? "Accept the change without verifying" : "Accept this device")
            }
            .buttonStyle(DecisionButtonStyle())
        }
        .padding(14)
        .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.orange.opacity(0.35), lineWidth: 1))
    }

    private func changedText(_ s: ContactStatus) -> String {
        var parts: [String] = []
        if s.sendsHeld {
            parts.append("You verified \(peerName), and since then their devices changed — one was added, removed or reinstalled. The safety number below is the NEW one. Until you check it, nothing you write is sent to them.")
        }
        if s.unvouchedDevices > 0 {
            parts.append("The server lists \(s.unvouchedDevices == 1 ? "a device" : "\(s.unvouchedDevices) devices") for \(peerName) that none of their own devices vouched for. That is what an impostor's device would look like. It is not part of the number below, gets nothing from you, and what it sends is held.")
        }
        parts.append("Compare the number with \(peerName) and mark it verified, or — if you would rather not check — accept the change. Accepting leaves \(peerName) unverified.")
        return parts.joined(separator: "\n\n")
    }

    private func scanBanner(_ r: ScanResult) -> some View {
        let (icon, tint, text): (String, Color, String) = switch r {
        case .match: ("checkmark.circle.fill", .green, "The codes match. This is \(peerName), and nobody is in the middle.")
        case .mismatch: ("xmark.octagon.fill", .red, "The code DOES NOT match. Don't mark \(peerName) verified. Make sure you scanned the code on \(peerName)'s screen for their conversation with you (your own code never matches). If you did, someone may be intercepting this conversation.")
        case .notASafetyNumber: ("questionmark.circle.fill", .orange, "That isn't a current Skwod safety number code. Ask \(peerName) to open this same screen and scan the code shown there.")
        }
        return Label(text, systemImage: icon)
            .font(.caption).foregroundStyle(tint)
            .padding(12).frame(maxWidth: .infinity, alignment: .leading)
            .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }

    /// Verify (camera scan where there is one, otherwise digits + explicit confirmation) or, for
    /// an already verified contact, remove the mark.
    @ViewBuilder private var verifyControls: some View {
        let blockedByDevice = (status?.unvouchedDevices ?? 0) > 0
        if status?.verified == true {
            VStack(spacing: 8) {
                Label("You verified \(peerName) for the devices they have now.", systemImage: "checkmark.seal.fill")
                    .font(.subheadline).foregroundStyle(.green)
                Text("If their devices ever change, Skwod pauses sending and asks you to check again.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center)
                Button("Remove verification") { Task { await unverify() } }
                    .buttonStyle(DecisionButtonStyle())
            }
        } else {
            VStack(spacing: 10) {
                #if os(iOS)
                Button { scan = nil; showScanner = true } label: {
                    Label("Scan the code on \(peerName)'s screen", systemImage: "qrcode.viewfinder")
                }
                .buttonStyle(DecisionButtonStyle(primary: true)).disabled(blockedByDevice)
                #endif
                Button { confirmManual = true } label: {
                    Label("I compared the digits myself…", systemImage: "eye")
                }
                .buttonStyle(DecisionButtonStyle()).disabled(blockedByDevice)
                Text(blockedByDevice
                     ? "Decide about the unconfirmed device above before verifying."
                     : "Verifying covers every device \(peerName) has now.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center)
            }
        }
    }

    // MARK: -

    private func compute() async {
        guard let client = app.client, let me = app.session?.userId else { failed = true; return }
        do {
            number = try await client.safetyNumber(myUserId: me, userId: peerUserId, deviceId: "")
            qr = try? await client.safetyQr(userId: peerUserId)
            await reconcile(client, after: .read)
            failed = false
        } catch {
            failed = true
        }
    }

    /// A live scan of the other person's screen.
    private func check(scanned text: String) async {
        guard let client = app.client, let shown = number else { return }
        do {
            guard let matched = try await client.checkSafetyQr(userId: peerUserId, scanned: text) else {
                scan = .notASafetyNumber
                return
            }
            // The code matched the number the core holds NOW; it must also be the one on screen.
            guard matched == shown else { await changedUnderneath(); return }
            scan = .match
            await verify()
        } catch CoreError.IdentityChanged {
            scan = .mismatch
        } catch {
            problem = "Couldn't check that code. Check your connection and try again."
        }
    }

    /// Ask the core to mark the account verified FOR THE NUMBER ON SCREEN. It recomputes the
    /// number and refuses if the device set is no longer the one that number covers.
    private func verify() async {
        guard let client = app.client, let shown = number else { return }
        problem = nil
        do {
            try await client.verifyContact(userId: peerUserId, safetyNumber: shown)
            await reconcile(client, after: .verified)
            if status?.verified == true { onAccepted?() }
        } catch CoreError.IdentityChanged {
            await changedUnderneath()
        } catch {
            problem = "Couldn't mark \(peerName) verified. Check your connection and try again."
        }
    }

    /// The device set changed while this screen was open: nothing was marked. Show the new
    /// number and say so — the comparison has to be done again, with the new number.
    private func changedUnderneath() async {
        scan = nil
        await compute()
        problem = (status?.unvouchedDevices ?? 0) > 0
            ? "Not verified: the server now lists a device for \(peerName) that none of their devices vouched for. Decide about it first."
            : "Not verified: the safety number changed while you were comparing — a device was added or removed. The number above is the new one; compare it again."
    }

    private func unverify() async {
        guard let client = app.client else { return }
        try? await client.unverifyContact(userId: peerUserId)
        await reconcile(client, after: .unverified)
    }

    /// Build 49: after anything here changed (or was read), the core's verification state for
    /// this person goes into the contact book — from every entry point (DM, member list, group
    /// people) alike — and only while the same skwod's client is the active one.
    private enum Step { case read, verified, unverified }

    /// A READ only demotes; a pinned name is raised only after an explicit, successful
    /// verification here, and never for a flagged name (unconfirmed, look-alike).
    private func reconcile(_ client: SkwodClient, after step: Step) async {
        let read = await client.contactStatus(userId: peerUserId)
        guard app.client === client else { return }
        status = read
        switch step {
        case .verified where read.verified:
            // Gated in the store (`noteVerification`): a flagged name is not pinned.
            app.contacts.noteVerification(peerUserId, name: peerName, verified: true)
        case .unverified:
            if read.verified { app.contacts.noteStatusRead(peerUserId, verified: true) }
            else { app.contacts.noteVerification(peerUserId, name: peerName, verified: false) }
        default:
            app.contacts.noteStatusRead(peerUserId, verified: read.verified)
        }
    }

    /// Continue with the devices the directory lists now (clears "verified").
    private func accept() async {
        guard let client = app.client else { return }
        problem = nil
        do {
            // Exactly the set this screen showed (audit L2).
            try await client.acceptIdentityChange(userId: peerUserId, deviceId: "", shown: status?.acceptFingerprint ?? "")
            scan = nil
            await compute()
            onAccepted?()
        } catch CoreError.IdentityChanged {
            await compute()
            problem = "Their devices changed while you were deciding. Nothing was accepted — look again and decide."
        } catch {
            problem = "Couldn't accept the change. Check your connection and try again."
        }
    }
}

/// How the safety number is written out.
enum SafetyNumber {
    /// 12 blocks of 5 digits, four to a line.
    static func grouped(_ s: String) -> String {
        let blocks = stride(from: 0, to: s.count, by: 5).map { i -> String in
            let start = s.index(s.startIndex, offsetBy: i)
            let end = s.index(start, offsetBy: 5, limitedBy: s.endIndex) ?? s.endIndex
            return String(s[start..<end])
        }
        return stride(from: 0, to: blocks.count, by: 4)
            .map { blocks[$0..<min($0 + 4, blocks.count)].joined(separator: " ") }
            .joined(separator: "\n")
    }
}
