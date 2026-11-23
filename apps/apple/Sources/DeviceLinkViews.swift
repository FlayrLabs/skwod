import SwiftUI

/// Shown on a device that signed in to an account which already has a device.
///
/// A password (or a stolen session) must not be enough to read someone's messages, so a new device
/// has to be **linked**: it shows a one-time code, the user types that code into a device already on
/// the account, and that device signs this one's identity key. The server only relays public values
/// and cannot link a device by itself.
struct DeviceLinkSheet: View {
    /// Back to "Set up this device" (nil when shown on its own).
    var onBack: (() -> Void)? = nil
    @EnvironmentObject private var app: AppState
    @State private var code: String?
    @State private var errorText = ""
    @State private var confirmReset = false
    @State private var busy = false

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "link.badge.plus").font(.system(size: 40)).foregroundStyle(.skAccent)
            Text("Link this device").font(.title2.bold()).foregroundStyle(.white)
            Text("Your account is already set up on another device. Open Skwod there, go to Profile → Encryption → Devices → “Link a device…”, and scan this — or type the code:")
                .font(.subheadline).foregroundStyle(.white.opacity(0.65)).multilineTextAlignment(.center)
            if let code {
                // The QR carries exactly the code below, nothing else. It is one-time, expires in
                // 10 minutes, and is useless without a device that is already on the account.
                QRCodeView(text: DeviceLinkCode.qrPayload(code), size: 170)
                Text(code)
                    .font(.system(.title3, design: .monospaced).weight(.semibold)).foregroundStyle(.white)
                    .textSelection(.enabled)
                    .padding(.horizontal, 20).padding(.vertical, 12)
                    .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Waiting for the other device…").font(.caption).foregroundStyle(.white.opacity(0.5))
                }
            } else if errorText.isEmpty {
                ProgressView().tint(.skAccent)
            }
            if !errorText.isEmpty {
                Label(errorText, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.red.opacity(0.9)).multilineTextAlignment(.center)
                Button("Try again") { Task { await start() } }.buttonStyle(.glass).tint(.skAccent)
            }
            Text("The code only works once and never leaves your two devices.")
                .font(.caption2).foregroundStyle(.white.opacity(0.45))
            Divider().overlay(.white.opacity(0.1))
            if let onBack {
                Text("No other device any more? Go back and restore with your recovery key.")
                    .font(.caption).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center)
                Button("Back") { onBack() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
            } else {
                Button(role: .destructive) { confirmReset = true } label: {
                    Text("Reset encryption for this account…").font(.caption)
                }
                .buttonStyle(.plain).foregroundStyle(.red.opacity(0.85)).disabled(busy)
                Button("Not now") { app.needsDeviceLink = false }
                    .buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
            }
        }
        .padding(28)
        .frame(minWidth: 380, maxWidth: 460)
        .background(SkwodBackground())
        .interactiveDismissDisabled()
        .task { await start() }
        .confirmationDialog("Reset encryption?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset and sign out my other devices", role: .destructive) { Task { await reset() } }
        } message: {
            Text("This removes every other device from your account and gives this one new keys. Your contacts will see your safety number change, and anything only your old devices could read stays unreadable here.")
        }
    }

    /// Show the code, then poll until an existing device approves (or the request expires).
    private func start() async {
        guard let client = app.client else { errorText = "Not connected."; return }
        errorText = ""
        do {
            code = try await client.beginDeviceLink()
            while !Task.isCancelled {
                if try await client.completeDeviceLink() != nil {
                    app.needsDeviceLink = false
                    await app.deviceBecameActive()
                    return
                }
                try? await Task.sleep(for: .seconds(2))
            }
        } catch {
            code = nil
            errorText = coreErrorText(error)
        }
    }

    private func reset() async {
        guard let client = app.client else { return }
        busy = true
        defer { busy = false }
        do {
            _ = try await client.resetDevices(pin: nil)
            app.needsDeviceLink = false
            await app.deviceBecameActive()
        } catch CoreError.PinRequired {
            app.needsDeviceLink = false
            app.pinPrompt = PinPrompt(purpose: .reset)
        } catch CoreError.PinIncorrect(_, let left) {
            app.needsDeviceLink = false
            app.pinPrompt = PinPrompt(purpose: .reset, attemptsLeft: Int(left))
        } catch CoreError.ResetPending(let detail) {
            // No PIN was given, so the reset is on its 7-day hold. Explain it on its own screen
            // (which also takes the PIN) instead of as an error line here.
            app.needsDeviceLink = false
            app.resetPending = detail
        } catch {
            errorText = coreErrorText(error)
        }
    }
}

/// On a device already on the account: type the code a new device is showing to link it.
struct DeviceLinkApproveSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var code = ""
    @State private var busy = false
    @State private var message = ""
    @State private var done = false
    @State private var showScanner = false

    var body: some View {
        VStack(spacing: 18) {
            Image(systemName: "laptopcomputer.and.iphone").font(.system(size: 40)).foregroundStyle(.skAccent)
            Text("Link a device").font(.title2.bold()).foregroundStyle(.white)
            Text("1. On the new device, open Skwod and log in to this Skwod with your username and password. 2. It then shows a code. Scan it here, or type it. Only link a device you are holding: it will be able to read your new messages.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.65)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            // A p2p skwod gets its share link, which carries the host's home relay (`&r=`) so the
            // new device can dial at once instead of waiting on a lookup.
            if let address = app.current.map({ w in w.nodeId.flatMap { InviteLink.shareLink(nodeId: $0, joinCode: nil) } ?? w.server }), !done {
                // Step 1 made easy: the new device scans this to land on the right skwod's log-in
                // screen. It is the skwod's address only — no code, no credentials.
                DisclosureGroup("Show this Skwod's address for the new device") {
                    QRCodeView(text: address, size: 150).padding(.top, 8)
                }
                .font(.caption).foregroundStyle(.white.opacity(0.6))
            }
            HStack(spacing: 8) {
                TextField("XXXX-XXXX-XXXX-XXXX", text: $code)
                    .textFieldStyle(.plain).font(.system(.body, design: .monospaced))
                    .autocorrectionDisabled()
                    #if os(iOS)
                    .textInputAutocapitalization(.characters)
                    #endif
                    .onSubmit { Task { await approve() } }
                #if os(iOS)
                Button { showScanner = true } label: { Image(systemName: "qrcode.viewfinder").font(.title3) }
                    .buttonStyle(.plain).foregroundStyle(.skAccent)
                #endif
            }
            .padding(12).glassEffect(.regular, in: .capsule)
            if !message.isEmpty {
                Label(message, systemImage: done ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(done ? .green : .orange).multilineTextAlignment(.center)
            }
            Button {
                Task { await approve() }
            } label: {
                HStack(spacing: 8) {
                    if busy { ProgressView().controlSize(.small) }
                    Text(done ? "Done" : "Link device").fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .disabled(busy || (!done && code.filter(\.isLetter).count + code.filter(\.isNumber).count < 16))
            Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(28)
        .frame(minWidth: 380, maxWidth: 440)
        .background(SkwodBackground())
        #if os(iOS)
        .sheet(isPresented: $showScanner) {
            QRScannerSheet(prompt: "Point the camera at the code on your new device.") { scanned in
                showScanner = false
                // A scanned payload is untrusted: accept only something shaped like a link code.
                if let c = DeviceLinkCode.fromQR(scanned) {
                    code = c
                    Task { await approve() }
                } else {
                    message = "That isn't a Skwod device-link code."
                }
            }
        }
        #endif
    }

    private func approve() async {
        if done { dismiss(); return }
        guard let client = app.client else { message = "Not connected."; return }
        busy = true
        defer { busy = false }
        do {
            if try await client.approveDeviceLink(code: code) {
                done = true
                message = "Linked. The new device will finish setting up in a moment."
            } else {
                message = "No device is waiting with that code. Check the code on the new device — it expires after 10 minutes."
            }
        } catch {
            message = coreErrorText(error)
        }
    }
}

/// The device-link code as it travels in a QR: `skwod-link:<code>`. The prefix only tells the
/// scanner what it is looking at; the code is the same 80-bit one-time value shown as text.
enum DeviceLinkCode {
    static let prefix = "skwod-link:"

    static func qrPayload(_ code: String) -> String { prefix + code }

    /// Extract a code from a scanned payload, or nil if it isn't one. Letters, digits and dashes
    /// only, and no longer than a code can be — nothing else ever reaches the core.
    static func fromQR(_ payload: String) -> String? {
        let text = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix(prefix) else { return nil }
        let code = String(text.dropFirst(prefix.count))
        guard (16...40).contains(code.count),
              code.unicodeScalars.allSatisfy({ $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-") })
        else { return nil }
        return code
    }
}
