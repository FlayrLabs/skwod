import SwiftUI

/// Pulls the human sentence out of a `CoreError` (`… { detail: "…" }`) without ever showing the
/// raw enum dump. Falls back to a generic line.
func coreErrorText(_ error: Error, fallback: String = "Something went wrong — check your connection.") -> String {
    switch error {
    case CoreError.UpdateRequired(let detail): return detail.isEmpty ? "This Skwod needs a newer version of the app." : detail
    case CoreError.LinkRequired: return "This account already has a device. Link this one from it."
    case CoreError.ResetPending(let detail): return detail.prefix(1).uppercased() + detail.dropFirst() + "."
    case CoreError.IdentityChanged: return "A verified contact's safety number changed. Check it before sending."
    case CoreError.PinRequired: return "This account is protected by a PIN."
    case CoreError.PinIncorrect(_, let left): return PinEntrySheet.attemptsText(Int(left))
    case CoreError.DeviceRemoved: return "This device was removed from your account."
    case CoreError.DeviceSuperseded: return "Your account was restored on another device, so this copy has stopped."
    case CoreError.RecoveryPending: return "The restore on this device is still waiting."
    case CoreError.RecoveryChanged: return "That request was replaced by a newer one. Nothing was approved."
    case CoreError.DeviceLimit(let detail): return detail.isEmpty ? "This account already has the most devices it can have." : detail
    default: break
    }
    let s = String(describing: error)
    if let r = s.range(of: "detail: \"") {
        let tail = s[r.upperBound...]
        if let end = tail.firstIndex(of: "\"") {
            let detail = String(tail[..<end])
            // Server errors arrive as "… 4xx: {json}" — never show those raw.
            if !detail.contains("{") && detail.count < 160 { return detail }
        }
    }
    return fallback
}

/// Registration PIN: a second lock on the account itself. Without it, someone who learns the
/// password can ask to reset the account's devices and only has to wait out a 7-day hold (which
/// any of your devices cancels). With a PIN that has been in place for 7 days, *you* can skip
/// that wait after losing every device — and nobody without the PIN can.
struct RegistrationPinSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    /// Whether this device believes a PIN is set (it remembers its own changes; another device
    /// may have changed it since, which is why "current PIN" is always offered).
    @State private var hasPin = false
    @State private var currentPin = ""
    @State private var pin = ""
    @State private var confirm = ""
    @State private var busy = false
    @State private var message = ""
    @State private var done = false

    private var valid: Bool { pin.count >= 6 && pin.count <= 128 && pin == confirm }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.rectangle.stack.fill").font(.system(size: 40)).foregroundStyle(.skAccent)
            Text(hasPin ? "Change your account PIN" : "Set an account PIN").font(.title2.bold()).foregroundStyle(.white)
            Text("If you ever lose every device, the PIN lets you reset your account's encryption straight away. Without one, a reset waits 7 days so your devices can stop it. A new PIN starts counting after 7 days in place. It protects the account, not your messages — those are protected by your devices' keys.")
                .font(.subheadline).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            SecureField(hasPin ? "Current PIN" : "Current PIN (only if you set one before)", text: $currentPin)
                .textFieldStyle(.plain).padding(12).glassEffect(.regular, in: .capsule)
            SecureField("New PIN (6 or more characters)", text: $pin)
                .textFieldStyle(.plain).padding(12).glassEffect(.regular, in: .capsule)
            SecureField("Repeat new PIN", text: $confirm)
                .textFieldStyle(.plain).padding(12).glassEffect(.regular, in: .capsule)
            if !confirm.isEmpty && pin != confirm {
                Text("The two PINs don't match.").font(.caption2).foregroundStyle(.orange.opacity(0.9))
            }
            if !message.isEmpty {
                Label(message, systemImage: done ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(done ? .green : .orange).multilineTextAlignment(.center)
            }

            Button { Task { await save() } } label: {
                HStack(spacing: 8) {
                    if busy { ProgressView().controlSize(.small) }
                    Text(done ? "Done" : "Save PIN").fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .disabled(busy || (!done && !valid))

            if hasPin && !done {
                Button(role: .destructive) { Task { await remove() } } label: { Text("Remove the PIN").font(.caption) }
                    .buttonStyle(.plain).foregroundStyle(.red.opacity(0.85)).disabled(busy || currentPin.isEmpty)
            }
            Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(28)
        .frame(minWidth: 380, maxWidth: 460)
        .background(SkwodBackground())
        .task { hasPin = await app.client?.kvGet(key: Self.flagKey) == "1" }
    }

    static let flagKey = "account.registrationPinSet"

    private func save() async {
        if done { dismiss(); return }
        guard let client = app.client else { message = "Not connected."; return }
        busy = true; defer { busy = false }
        do {
            try await client.setRegistrationPin(pin: pin, currentPin: currentPin.isEmpty ? nil : currentPin)
            await client.kvSet(key: Self.flagKey, value: "1")
            pin = ""; confirm = ""; currentPin = ""
            done = true
            message = "PIN saved. It can skip the reset wait once it has been in place for 7 days."
        } catch {
            message = coreErrorText(error, fallback: "Couldn't save the PIN. If you already have one, enter it as the current PIN.")
        }
    }

    private func remove() async {
        guard let client = app.client else { return }
        busy = true; defer { busy = false }
        do {
            try await client.setRegistrationPin(pin: nil, currentPin: currentPin)
            await client.kvSet(key: Self.flagKey, value: "0")
            hasPin = false; currentPin = ""
            done = true
            message = "PIN removed. A reset now always waits 7 days."
        } catch {
            message = coreErrorText(error, fallback: "Couldn't remove the PIN — check the current PIN.")
        }
    }
}

/// Shown on a device that asked to reset the account's devices and is now in the 7-day hold.
///
/// The hold is the safety net: for those 7 days every device still on the account cancels the
/// reset automatically and warns its owner. So this screen is honest about the wait, and offers
/// the two ways not to wait — the account PIN, or linking from a device you still have.
struct ResetPendingSheet: View {
    @EnvironmentObject private var app: AppState
    @State private var pin = ""
    @State private var busy = false
    @State private var message = ""

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "hourglass").font(.system(size: 40)).foregroundStyle(.skAccent)
            Text("Reset is waiting").font(.title2.bold()).foregroundStyle(.white)
            Text(detail)
                .font(.subheadline).foregroundStyle(.white.opacity(0.75)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Text("Why the wait: a password alone must not be enough to take over an account. For 7 days, any device still signed in to this account stops the reset and warns its owner. If that's you on another device, link this one from there instead.")
                .font(.caption).foregroundStyle(.white.opacity(0.5)).multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)

            Divider().overlay(.white.opacity(0.1))
            Text("Have an account PIN? It finishes the reset now (if the PIN is at least 7 days old).")
                .font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
            SecureField("Account PIN", text: $pin)
                .textFieldStyle(.plain).padding(12).glassEffect(.regular, in: .capsule)
            if !message.isEmpty {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange).multilineTextAlignment(.center)
            }
            Button { Task { await retry(usingPin: true) } } label: {
                HStack(spacing: 8) {
                    if busy { ProgressView().controlSize(.small) }
                    Text("Reset now with PIN").fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity).padding(.vertical, 6)
            }
            .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
            .disabled(busy || pin.count < 6)

            Button("Check again") { Task { await retry(usingPin: false) } }
                .buttonStyle(.glass).tint(.skAccent).disabled(busy)
            Button("Link from another device instead") {
                app.resetPending = nil
                app.needsDeviceLink = true
            }
            .buttonStyle(.plain).foregroundStyle(.skAccent).font(.caption)
            Button("Close") { app.resetPending = nil }
                .buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .padding(28)
        .frame(minWidth: 380, maxWidth: 460)
        .background(SkwodBackground())
        .interactiveDismissDisabled()
    }

    private var detail: String {
        let d = app.resetPending ?? ""
        return d.isEmpty ? "The reset was requested and is on hold." : d.prefix(1).uppercased() + d.dropFirst() + "."
    }

    private func retry(usingPin: Bool) async {
        guard let client = app.client else { message = "Not connected."; return }
        busy = true; message = ""; defer { busy = false }
        do {
            _ = try await client.resetDevices(pin: usingPin ? pin : nil)
            pin = ""
            app.resetPending = nil
            app.needsDeviceLink = false
            await app.deviceBecameActive()
        } catch CoreError.PinIncorrect(_, let left) {
            pin = ""
            message = PinEntrySheet.attemptsText(Int(left))
        } catch CoreError.PinRequired {
            message = "This account has a PIN. Enter it to reset now, or keep waiting."
        } catch CoreError.ResetPending(let d) {
            app.resetPending = d
            message = usingPin ? "That PIN can't skip the wait yet (wrong PIN, or it was set less than 7 days ago)." : "Still waiting."
        } catch {
            message = coreErrorText(error, fallback: usingPin ? "That PIN wasn't accepted." : "Couldn't check — try again.")
        }
    }
}
