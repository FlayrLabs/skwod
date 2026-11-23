import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

// Build 44a screens: devices, erase, the recovery key, restore, the PIN, approvals.
// The words are shared with the Android app (same flows, same copy).

// MARK: - Shared pieces

/// The frame every account sheet uses (the same as the PIN and link sheets).
private struct AccountSheet<Content: View>: View {
    let icon: String
    let title: String
    var tint: Color = .skAccent
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Image(systemName: icon).font(.system(size: 40)).foregroundStyle(tint)
                Text(title).font(.title2.bold()).foregroundStyle(.white).multilineTextAlignment(.center)
                    .accessibilityAddTraits(.isHeader)
                content
            }
            .padding(28)
            .frame(maxWidth: 460)
            .frame(maxWidth: .infinity)
        }
        .frame(minWidth: 380)
        .background(SkwodBackground())
    }
}

private func bodyText(_ text: String) -> some View {
    Text(text).font(.subheadline).foregroundStyle(.white.opacity(0.7)).multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
}

private func warningBox(_ text: String) -> some View {
    Label(text, systemImage: "exclamationmark.triangle.fill")
        .font(.caption).foregroundStyle(.orange)
        .fixedSize(horizontal: false, vertical: true)
        .padding(12).frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
}

private func statusLine(_ text: String, ok: Bool) -> some View {
    Label(text, systemImage: ok ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
        .font(.caption).foregroundStyle(ok ? .green : .orange).multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
}

/// The prominent button of a sheet.
private struct PrimaryButton: View {
    let title: String
    var busy = false
    var destructive = false
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if busy { ProgressView().controlSize(.small) }
                Text(title).fontWeight(.semibold)
            }
            .frame(maxWidth: .infinity).padding(.vertical, 6)
        }
        .controlSize(.large).buttonStyle(.glassProminent)
        .tint(destructive ? .red : .skAccent).foregroundStyle(destructive ? .white : .black)
    }
}

/// A short code (`XXXX-XXXX`) shown large, for comparing across two devices.
private struct BigCode: View {
    let code: String
    var body: some View {
        Text(code.isEmpty ? "—" : code)
            .font(.system(.title, design: .monospaced).weight(.semibold)).foregroundStyle(.white)
            .textSelection(.enabled)
            .padding(.horizontal, 22).padding(.vertical, 12)
            .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            .accessibilityLabel("Code \(code.map(String.init).joined(separator: " "))")
            .accessibilityIdentifier("account.code")
    }
}

// MARK: - Devices

// MARK: - Restore requests put off ("Decide later")

/// Restore requests this device was asked to approve and the user put off. The core announces
/// each request once, so one that merely left the prompt queue could not be answered again
/// until the app was restarted. They are kept here instead — per skwod, in memory like the
/// queue itself (a restart makes the core announce what is still pending again) — and the
/// Devices screen offers them until they are approved, blocked or replaced.
@MainActor
final class DeferredRecoveries: ObservableObject {
    static let shared = DeferredRecoveries()

    struct Entry: Equatable {
        let workspaceId: String
        let request: RecoveryRequest
    }

    @Published private(set) var entries: [Entry] = []

    func put(_ request: RecoveryRequest, workspaceId: String) {
        entries = Self.adding(request, workspaceId: workspaceId, to: entries)
    }

    func remove(requestId: String) {
        entries.removeAll { $0.request.requestId == requestId }
    }

    /// What the Devices screen of `workspaceId` offers, given what is in the prompt queue now.
    func requests(workspaceId: String?, queued: [RecoveryRequest]) -> [RecoveryRequest] {
        Self.visible(entries, workspaceId: workspaceId, queued: queued)
    }

    /// One put-off request per device: a request that replaced another has a new id and its
    /// own code, and the one it replaced can no longer be approved.
    nonisolated static func adding(_ request: RecoveryRequest, workspaceId: String, to entries: [Entry]) -> [Entry] {
        var next = entries.filter { !($0.workspaceId == workspaceId && $0.request.deviceId == request.deviceId) }
        next.append(Entry(workspaceId: workspaceId, request: request))
        return next
    }

    /// The put-off requests of this skwod, minus any whose device has a request in the prompt
    /// queue (that one is being asked about right now, or replaced the one put off).
    nonisolated static func visible(_ entries: [Entry], workspaceId: String?, queued: [RecoveryRequest]) -> [RecoveryRequest] {
        guard let workspaceId else { return [] }
        return entries.filter { $0.workspaceId == workspaceId }.map(\.request)
            .filter { r in !queued.contains { $0.deviceId == r.deviceId } }
    }
}

/// Profile → Encryption → Devices: every device of this account, what each is called, when it
/// was added and last active — and Rename / Remove.
struct DevicesView: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var list: DeviceList?
    @State private var erased: [ErasedDevice] = []
    @State private var loading = true
    @State private var message = ""
    @State private var renaming = false
    @State private var newName = ""
    @State private var removing: DeviceInfo?
    @State private var markingLost: ErasedDevice?
    /// Devices a backup restore brought back that no other device has confirmed yet (M2).
    @State private var unconfirmed: [String] = []
    @State private var showLink = false
    @State private var busy = false
    @ObservedObject private var deferred = DeferredRecoveries.shared
    @State private var reviewing: RecoveryRequest?

    private var putOff: [RecoveryRequest] { deferred.requests(workspaceId: app.current?.id, queued: app.recoveryRequests) }

    private var devices: [DeviceInfo] {
        (list?.devices ?? []).sorted { a, b in
            if a.isThisDevice != b.isThisDevice { return a.isThisDevice }
            return a.createdAt < b.createdAt
        }
    }
    private var max: Int { Int(list?.maxDevices ?? 5) }
    private var atLimit: Bool { devices.count >= max }

    var body: some View {
        AccountSheet(icon: "laptopcomputer.and.iphone", title: "Devices") {
            if let list {
                Text("\(list.devices.count) of \(list.maxDevices) devices")
                    .font(.subheadline).foregroundStyle(.white.opacity(0.7))
                    .accessibilityIdentifier("devices.count")
            } else if loading {
                ProgressView().tint(.skAccent)
            }
            if atLimit {
                warningBox("You've reached the \(max)-device limit. Remove one to link another.")
            }
            // A restore the user said "Decide later" to: still theirs to answer, from here.
            ForEach(putOff) { request in
                HStack(spacing: 12) {
                    Image(systemName: "person.crop.circle.badge.questionmark.fill").font(.title3).foregroundStyle(.orange)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("A restore is waiting for your answer").font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                        Text("Code \(request.fingerprint)").font(.caption).foregroundStyle(.white.opacity(0.55))
                    }
                    Spacer()
                    Button("Review") { reviewing = request }
                        .buttonStyle(.plain).font(.caption.weight(.semibold)).foregroundStyle(.orange)
                        .accessibilityIdentifier("devices.reviewRestore")
                }
                .padding(14).glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            }
            VStack(spacing: 10) {
                ForEach(devices, id: \.deviceId) { d in row(d) }
            }
            if !erased.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    SectionHeader(title: "Erased devices", systemImage: "trash")
                    ForEach(erased, id: \.identityKeyHex) { e in
                        HStack {
                            Text("Erased \(AccountDates.day(e.erasedAt))").foregroundStyle(.white)
                            Spacer()
                            Button("It was lost or stolen…") { markingLost = e }
                                .buttonStyle(.plain).font(.caption.weight(.semibold)).foregroundStyle(.orange)
                        }
                        .font(.subheadline)
                    }
                }
                .padding(14).glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
            }
            if !message.isEmpty { statusLine(message, ok: false) }
            Button { showLink = true } label: {
                Label("Link a device…", systemImage: "link.badge.plus").frame(maxWidth: .infinity).padding(.vertical, 2)
            }
            .controlSize(.large).buttonStyle(.glass).tint(.skAccent).disabled(atLimit || list == nil)
            Button("Done") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .task { await load() }
        .onReceive(NotificationCenter.default.publisher(for: .skwodAccountChanged)) { _ in Task { await load() } }
        .sheet(isPresented: $showLink, onDismiss: { Task { await load() } }) { DeviceLinkApproveSheet() }
        .sheet(item: $reviewing) { request in
            RecoveryApprovalSheet(request: request, onClose: { reviewing = nil }).environmentObject(app)
        }
        .alert("Rename this device", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Save") { Task { await rename() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Only your own devices can see this name.")
        }
        .confirmationDialog("Remove \(removing.map(name(of:)) ?? "this device")?",
                            isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } }),
                            titleVisibility: .visible) {
            Button("Remove device", role: .destructive) { if let d = removing { Task { await remove(d) } } }
        } message: {
            Text("It is signed out and can no longer read new messages. Removing a device also retires your recovery key, so you'll make a new one next.")
        }
        .confirmationDialog("Mark it lost or stolen?",
                            isPresented: Binding(get: { markingLost != nil }, set: { if !$0 { markingLost = nil } }),
                            titleVisibility: .visible) {
            Button("Mark as lost", role: .destructive) { if let e = markingLost { Task { await markLost(e) } } }
        } message: {
            Text("That device can never be restored, and your recovery key is retired now. You'll make a new one next.")
        }
    }

    private func name(of d: DeviceInfo) -> String { d.name.flatMap { $0.isEmpty ? nil : $0 } ?? "Unnamed device" }

    private func row(_ d: DeviceInfo) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: d.verified ? "desktopcomputer.and.arrow.down" : "exclamationmark.shield.fill")
                .font(.title3).foregroundStyle(d.verified ? Color.skAccent : .orange).frame(width: 28)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(name(of: d)).font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                    if d.isThisDevice {
                        Text("This device").font(.caption2.weight(.semibold)).foregroundStyle(.black)
                            .padding(.horizontal, 7).padding(.vertical, 2).background(.skAccent, in: Capsule())
                    }
                }
                Text("Added \(AccountDates.day(d.createdAt)) · \(AccountDates.active(d.lastActiveAt))")
                    .font(.caption).foregroundStyle(.white.opacity(0.55))
                if unconfirmed.contains(d.deviceId) {
                    // Restored from a backup that may be older than the account (audit M2):
                    // it gets nothing until the user, or a device they confirmed, says so.
                    Text("From your backup. Is this still your device? Until you say so, nothing is synced to it.")
                        .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                    Button("Yes, it's mine") { Task { await confirmRestored(d.deviceId) } }
                        .buttonStyle(.plain).font(.caption.weight(.semibold)).foregroundStyle(.orange).disabled(busy)
                        .accessibilityIdentifier("devices.confirmRestored")
                } else if !d.verified {
                    Text("Not approved by any of your devices").font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer(minLength: 8)
            if d.isThisDevice {
                Button("Rename") { newName = d.name ?? ""; renaming = true }
                    .buttonStyle(.glass).controlSize(.small).tint(.skAccent)
            } else {
                Button("Remove", role: .destructive) { removing = d }
                    .buttonStyle(.glass).controlSize(.small).tint(.red).disabled(busy)
            }
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(d.verified ? .clear : Color.orange.opacity(0.6)))
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("devices.row")
    }

    private func load() async {
        defer { loading = false }
        guard let client = app.client else { message = "Not connected."; return }
        if let fresh = await app.refreshDeviceNames() {
            list = fresh
            message = ""
        } else if list == nil {
            message = "Couldn't load your devices — check your connection."
        }
        erased = (try? await client.erasedDevices()) ?? []
        unconfirmed = await client.unconfirmedRestoredDevices()
    }

    private func confirmRestored(_ deviceId: String) async {
        guard let client = app.client else { return }
        busy = true
        defer { busy = false }
        do {
            try await client.confirmRestoredDevice(deviceId: deviceId)
            await load()
        } catch {
            message = coreErrorText(error, fallback: "Couldn't confirm that device — check your connection.")
        }
    }

    private func rename() async {
        guard let client = app.client else { return }
        let name = DeviceLabel.cleaned(newName)
        guard !name.isEmpty else { return }
        do {
            try await client.renameDevice(name: name)
            await load()
        } catch {
            message = coreErrorText(error, fallback: "Couldn't rename this device.")
        }
    }

    private func remove(_ d: DeviceInfo) async {
        guard let client = app.client else { return }
        busy = true; defer { busy = false }
        do {
            try await client.unregisterDevice(deviceId: d.deviceId)
            await app.logSecurity(kind: "device_removed_here", title: "You removed a device",
                                  message: "\(name(of: d)) was removed from your account.", atMs: Int64(Date().timeIntervalSince1970 * 1000))
            await load()
            await app.surfaceSecurityNotices()
            // Removing a device retires the recovery key: make the new one now.
            dismiss()
            app.recoveryKeyPrompt = .deviceRemoved
        } catch {
            if await app.routeIfDeviceError(error) { dismiss(); return }
            message = coreErrorText(error, fallback: "Couldn't remove that device — check your connection.")
        }
    }

    private func markLost(_ e: ErasedDevice) async {
        guard let client = app.client else { return }
        busy = true; defer { busy = false }
        do {
            try await client.markErasedDeviceRemoved(identityKeyHex: e.identityKeyHex)
            await load()
            dismiss()
            app.recoveryKeyPrompt = .deviceRemoved
        } catch {
            message = coreErrorText(error, fallback: "Couldn't mark that device — check your connection.")
        }
    }
}

// MARK: - Erase this device

/// "Erase this device…": separate from signing out, and gated — without a recovery key or
/// another device, erasing leaves only the 7-day reset and the history is gone for good.
struct EraseDeviceSheet: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var check: EraseCheck?
    @State private var checkFailed = false
    @State private var asLost = false
    @State private var busy = false
    @State private var message = ""
    @State private var offerOffline = false
    @State private var confirmUnsafe = false
    @State private var unsafeAccepted = false
    @State private var showLink = false

    private var thing: String {
        #if os(iOS)
        return "iPhone"
        #else
        return "Mac"
        #endif
    }
    private var mayErase: Bool { check?.safe == true || unsafeAccepted }

    var body: some View {
        AccountSheet(icon: "trash.fill", title: "Erase this device", tint: .red) {
            bodyText("Removes this device from your account and deletes its messages and keys from this \(thing). Your account and your other devices are not touched.")
            if check == nil && !checkFailed { ProgressView().tint(.skAccent) }
            if checkFailed {
                warningBox("Couldn't check whether erasing is safe — your Skwod isn't answering. Try again when you're connected.")
                Button("Check again") { Task { await load() } }.buttonStyle(.glass).tint(.skAccent)
            }
            if let check, !check.safe, !unsafeAccepted {
                warningBox("You need a recovery key or another device first. Without one, erasing leaves only a 7-day account reset — and nothing can bring your message history back.")
                    .accessibilityIdentifier("erase.unsafe")
                PrimaryButton(title: "Save a recovery key") {
                    dismiss()
                    app.recoveryKeyPrompt = .manual
                }
                Button { showLink = true } label: {
                    Text("Link another device").frame(maxWidth: .infinity).padding(.vertical, 2)
                }
                .controlSize(.large).buttonStyle(.glass).tint(.skAccent)
                Button("Erase anyway…", role: .destructive) { confirmUnsafe = true }
                    .buttonStyle(.plain).font(.caption).foregroundStyle(.red.opacity(0.9))
            }
            if mayErase {
                Toggle(isOn: $asLost) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("This device is lost, stolen or being given away").foregroundStyle(.white)
                        Text("Erases it as lost: it can never be restored, and your recovery key is retired at once. You'll make a new one on another device.")
                            .font(.caption2).foregroundStyle(.white.opacity(0.5)).fixedSize(horizontal: false, vertical: true)
                    }
                }
                .tint(.red).font(.subheadline)
                if !message.isEmpty { statusLine(message, ok: false) }
                PrimaryButton(title: "Erase this device", busy: busy, destructive: true) { Task { await erase(offline: false) } }
                    .disabled(busy)
                    .accessibilityIdentifier("erase.confirm")
                if offerOffline {
                    Button("Erase anyway (offline)", role: .destructive) { Task { await erase(offline: true) } }
                        .buttonStyle(.plain).font(.caption).foregroundStyle(.red.opacity(0.9)).disabled(busy)
                }
            }
            Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .task { await load() }
        .sheet(isPresented: $showLink, onDismiss: { Task { await load() } }) { DeviceLinkApproveSheet() }
        .confirmationDialog("Erase without a way back?", isPresented: $confirmUnsafe, titleVisibility: .visible) {
            Button("Erase anyway", role: .destructive) { unsafeAccepted = true }
        } message: {
            Text("Your message history will be gone for good, and getting back into your account will take a 7-day reset.")
        }
    }

    private func load() async {
        guard let client = app.client else { checkFailed = true; return }
        checkFailed = false
        do { check = try await client.eraseCheck() } catch { checkFailed = true }
    }

    private func erase(offline: Bool) async {
        busy = true; message = ""; defer { busy = false }
        do {
            try await app.eraseCurrentDevice(asLost: asLost, evenIfOffline: offline)
            dismiss()
        } catch {
            offerOffline = true
            message = coreErrorText(error, fallback: "Couldn't reach your Skwod to take this device off your account.")
        }
    }
}

// MARK: - Recovery key

/// Save a recovery key: shown once (copy, QR, print), confirmed by typing part of it back,
/// then turned on — with the date from which a restore with it is instant.
struct RecoveryKeySheet: View {
    let reason: RecoveryKeyReason
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var step = 1
    @State private var key = generateRecoveryKey()
    @State private var typed = ""
    @State private var showQR = false
    @State private var copied = false
    @State private var busy = false
    @State private var message = ""
    @State private var instantFrom: Int64?
    @State private var ownPassphrase = false

    var body: some View {
        Group {
            switch step {
            case 1: save
            case 2: confirm
            default: done
            }
        }
        .interactiveDismissDisabled(step == 2 || busy)
        .sheet(isPresented: $ownPassphrase) {
            KeyBackupSetupSheet { dismiss() }
        }
    }

    private var save: some View {
        AccountSheet(icon: "key.horizontal.fill", title: "Save your recovery key") {
            if let header = reason.header { statusLine(header, ok: false) }
            bodyText("Your recovery key brings your account back if you lose this device: your identity, your skwods and your direct messages. Skwod can't recover it for you — nobody can.")
            Text(key)
                .font(.system(.callout, design: .monospaced).weight(.semibold)).foregroundStyle(.white)
                .textSelection(.enabled).multilineTextAlignment(.center)
                .padding(14).frame(maxWidth: .infinity)
                .glassEffect(.regular, in: .rect(cornerRadius: 14, style: .continuous))
                .accessibilityIdentifier("recovery.key")
            HStack(spacing: 10) {
                Button { Clipboard.copy(key, sensitive: true); copied = true } label: {
                    Label(copied ? "Copied" : "Copy", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
                Button { showQR.toggle() } label: { Label(showQR ? "Hide QR" : "Show QR", systemImage: "qrcode") }
                Button { RecoveryKeyPrinter.print(key) } label: { Label("Print", systemImage: "printer") }
            }
            .buttonStyle(.glass).controlSize(.small).tint(.skAccent)
            if showQR { QRCodeView(text: key, size: 170) }
            Text("Write it down or keep it in a password manager. It is shown only once.")
                .font(.caption).foregroundStyle(.orange.opacity(0.9)).multilineTextAlignment(.center)
            PrimaryButton(title: "I've saved it") { step = 2 }
            Button("Use my own passphrase instead") { ownPassphrase = true }
                .buttonStyle(.plain).font(.caption).foregroundStyle(.skAccent)
            if reason == .firstRun {
                Button("Not now") {
                    Task { await app.snoozeRecoveryKeyPrompt() }
                    dismiss()
                }
                .buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
            } else {
                Button("Cancel") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
            }
        }
    }

    private var confirm: some View {
        AccountSheet(icon: "checkmark.shield.fill", title: "Check your recovery key") {
            bodyText("Type the last 6 characters of your recovery key.")
            TextField("Last 6 characters", text: $typed)
                .textFieldStyle(.plain).font(.system(.body, design: .monospaced)).multilineTextAlignment(.center)
                .autocorrectionDisabled()
                #if os(iOS)
                .textInputAutocapitalization(.characters)
                #endif
                .padding(12).glassEffect(.regular, in: .capsule)
                .onSubmit { Task { await enable() } }
                .accessibilityIdentifier("recovery.confirm")
            if !message.isEmpty { statusLine(message, ok: false) }
            PrimaryButton(title: "Turn on recovery", busy: busy) { Task { await enable() } }
                .disabled(busy || RecoveryKeyCheck.normalized(typed).count < 6)
            Button("Back") { message = ""; step = 1 }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5)).disabled(busy)
        }
    }

    private var done: some View {
        AccountSheet(icon: "checkmark.seal.fill", title: "Recovery key saved", tint: .green) {
            bodyText(Self.instantText(instantFrom))
                .accessibilityIdentifier("recovery.instant")
            PrimaryButton(title: "Done") { dismiss() }
        }
    }

    /// What the last step says about when a restore with this key is instant.
    static func instantText(_ instantFrom: Int64?, now: Date = Date()) -> String {
        guard let at = instantFrom, Double(at) / 1000 > now.timeIntervalSince1970 else {
            return "Restoring with this key is instant."
        }
        return "From \(AccountDates.day(at)), restoring with this key is instant. Until then a restore also needs an approval from one of your devices, your account PIN, or a 7-day wait — so a key somebody just planted can't take your account."
    }

    private func enable() async {
        guard RecoveryKeyCheck.matches(typed, key: key) else {
            message = "That doesn't match. Go back and check what you saved."
            return
        }
        guard let client = app.client else { message = "Not connected."; return }
        busy = true; message = ""; defer { busy = false }
        do {
            try await client.enableKeyBackup(passphrase: key)
            instantFrom = await client.recoveryKeyInstantFrom()
            await app.logSecurity(kind: "recovery_key_saved", title: "You saved a recovery key",
                                  message: Self.instantText(instantFrom), atMs: Int64(Date().timeIntervalSince1970 * 1000))
            NotificationCenter.default.post(name: .skwodAccountChanged, object: nil)
            step = 3
        } catch {
            message = coreErrorText(error, fallback: "Couldn't turn recovery on — check your connection.")
        }
    }
}

/// Paper copy of a recovery key, through the system print panel.
enum RecoveryKeyPrinter {
    static func page(_ key: String) -> String {
        "Skwod recovery key\n\n\(key)\n\nKeep this somewhere safe. Anyone who has it can restore your Skwod account.\nSkwod cannot recover it for you."
    }

    @MainActor
    static func print(_ key: String) {
        #if os(iOS)
        let controller = UIPrintInteractionController.shared
        let info = UIPrintInfo(dictionary: nil)
        info.jobName = "Skwod recovery key"
        info.outputType = .grayscale
        controller.printInfo = info
        let formatter = UISimpleTextPrintFormatter(text: page(key))
        formatter.font = .monospacedSystemFont(ofSize: 14, weight: .regular)
        controller.printFormatter = formatter
        controller.present(animated: true)
        #else
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: 480, height: 300))
        view.string = page(key)
        view.font = .monospacedSystemFont(ofSize: 13, weight: .regular)
        let op = NSPrintOperation(view: view)
        op.jobTitle = "Skwod recovery key"
        op.run()
        #endif
    }
}

// MARK: - Set up this device (link / restore / reset)

/// Shown on a device that signed in to an account which already has a device, and has no
/// identity of its own here: link from another device, restore with the recovery key, or reset.
struct DeviceSetupSheet: View {
    @EnvironmentObject private var app: AppState
    private enum Route { case choose, link, restore }
    @State private var route: Route = .choose
    @State private var confirmReset = false
    @State private var busy = false
    @State private var message = ""

    var body: some View {
        switch route {
        case .choose: chooser
        case .link: DeviceLinkSheet(onBack: { route = .choose })
        case .restore: RestoreWithKeySheet(onBack: { route = .choose })
        }
    }

    private var chooser: some View {
        AccountSheet(icon: "person.badge.key.fill", title: "Set up this device") {
            bodyText("Your account already has a device. Choose how to bring this one in.")
            choice(icon: "link.badge.plus", title: "Link from another device",
                   caption: "Scan or type a code on a device you're signed in on.", id: "setup.link") { route = .link }
            choice(icon: "key.horizontal.fill", title: "Restore with your recovery key",
                   caption: "Brings back your identity, skwods and direct messages.", id: "setup.restore") { route = .restore }
            choice(icon: "arrow.counterclockwise.circle.fill", title: "Reset encryption",
                   caption: "Removes your other devices. Use only if you have nothing else.", id: "setup.reset", tint: .red) { confirmReset = true }
            if !message.isEmpty { statusLine(message, ok: false) }
            if busy { ProgressView().controlSize(.small) }
            Button("Not now") { app.needsDeviceLink = false }
                .buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .interactiveDismissDisabled()
        .confirmationDialog("Reset encryption?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset and sign out my other devices", role: .destructive) { Task { await reset() } }
        } message: {
            Text("This removes every other device from your account and gives this one new keys. Your contacts will see your safety number change, and anything only your old devices could read stays unreadable here.")
        }
    }

    private func choice(icon: String, title: String, caption: String, id: String, tint: Color = .skAccent,
                        action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: icon).font(.title2).foregroundStyle(tint).frame(width: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(tint == .red ? .red : .white)
                    Text(caption).font(.caption).foregroundStyle(.white.opacity(0.55))
                        .fixedSize(horizontal: false, vertical: true).multilineTextAlignment(.leading)
                }
                Spacer(minLength: 4)
                Image(systemName: "chevron.right").font(.caption).foregroundStyle(.white.opacity(0.35))
            }
            .padding(14).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.interactive(), in: .rect(cornerRadius: 16, style: .continuous))
        .disabled(busy)
        .accessibilityIdentifier(id)
    }

    private func reset() async {
        guard let client = app.client else { message = "Not connected."; return }
        busy = true; message = ""; defer { busy = false }
        do {
            _ = try await client.resetDevices(pin: nil)
            app.needsDeviceLink = false
            await app.deviceBecameActive()
        } catch CoreError.ResetPending(let detail) {
            // No PIN on the account: the reset is on its 7-day hold, explained on its own screen.
            app.needsDeviceLink = false
            app.resetPending = detail
        } catch CoreError.PinRequired {
            app.needsDeviceLink = false
            app.pinPrompt = PinPrompt(purpose: .reset)
        } catch CoreError.PinIncorrect(_, let left) {
            app.needsDeviceLink = false
            app.pinPrompt = PinPrompt(purpose: .reset, attemptsLeft: Int(left))
        } catch {
            message = coreErrorText(error)
        }
    }
}

/// Restore this account onto this device with the recovery key (or a backup passphrase).
struct RestoreWithKeySheet: View {
    var onBack: (() -> Void)? = nil
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var key = ""
    @State private var busy = false
    @State private var message = ""

    var body: some View {
        AccountSheet(icon: "key.horizontal.fill", title: "Restore with your recovery key") {
            bodyText("Enter the recovery key you saved (or your backup passphrase). It brings back your identity, your skwods and your direct messages.")
            SecureField("Recovery key or passphrase", text: $key)
                .textFieldStyle(.plain).padding(12).glassEffect(.regular, in: .capsule)
                .onSubmit { if !key.isEmpty { Task { await restore() } } }
                .accessibilityIdentifier("restore.key")
            if !message.isEmpty { statusLine(message, ok: false) }
            PrimaryButton(title: "Restore", busy: busy) { Task { await restore() } }
                .disabled(busy || key.isEmpty)
            Button(onBack == nil ? "Cancel" : "Back") { if let onBack { onBack() } else { dismiss() } }
                .buttonStyle(.plain).foregroundStyle(.white.opacity(0.5)).disabled(busy)
        }
        .interactiveDismissDisabled(busy)
    }

    private func restore() async {
        guard let client = app.client else { message = "Not connected."; return }
        busy = true; message = ""; defer { busy = false }
        switch await AccountRestore.run(app: app, client: client, key: key) {
        case .restored:
            key = ""
            dismiss()
        case .waiting, .pin:
            key = ""
            dismiss()
        case .noBackup:
            message = "No backup exists for this account."
        case .wrongKey:
            message = "That recovery key doesn't match."
        case .failed(let why):
            message = why
        }
    }
}

/// One restore attempt and where it leads — shared by the sheet and the DEBUG hook, so both
/// take exactly the same path.
@MainActor
enum AccountRestore {
    enum Outcome: Equatable { case restored, waiting, pin, noBackup, wrongKey, failed(String) }

    static func run(app: AppState, client: SkwodClient, key: String) async -> Outcome {
        do {
            guard try await client.restoreKeyBackup(passphrase: key.trimmingCharacters(in: .whitespacesAndNewlines)) else { return .noBackup }
            app.needsDeviceLink = false
            await app.deviceBecameActive()
            return .restored
        } catch {
            return await route(error, app: app)
        }
    }

    /// Complete a waiting restore (`pin` when the user has one).
    static func retry(app: AppState, client: SkwodClient, pin: String?) async -> Outcome {
        do {
            guard try await client.retryRestore(pin: pin) else { return .waiting }
            app.recoveryWaiting = false
            await app.deviceBecameActive()
            return .restored
        } catch {
            return await route(error, app: app)
        }
    }

    private static func route(_ error: Error, app: AppState) async -> Outcome {
        switch error {
        case CoreError.RecoveryPending:
            // The restored state is kept; this install waits for an approval, the PIN or the hold.
            app.needsDeviceLink = false
            app.recoveryWaiting = true
            return .waiting
        case CoreError.PinRequired:
            app.needsDeviceLink = false
            app.pinPrompt = PinPrompt(purpose: .restore)
            return .pin
        case CoreError.PinIncorrect(_, let left):
            app.needsDeviceLink = false
            app.pinPrompt = PinPrompt(purpose: .restore, attemptsLeft: Int(left))
            return .pin
        default:
            if String(describing: error).contains("wrong passphrase") { return .wrongKey }
            if await app.routeIfDeviceError(error) { return .failed("This device can't be restored right now.") }
            return .failed(coreErrorText(error, fallback: "Couldn't restore — check your connection."))
        }
    }
}

/// On the install whose restore is waiting: the code another device has to approve, the PIN
/// shortcut, and how long until it completes by itself.
struct RecoveryWaitingSheet: View {
    @EnvironmentObject private var app: AppState
    @State private var code = ""
    @State private var completesAt: Int64?
    @State private var contested = false
    @State private var pin = ""
    @State private var busy = false
    @State private var message = ""
    @State private var now = Date()

    var body: some View {
        AccountSheet(icon: "hourglass", title: "Waiting to restore") {
            bodyText("This restore needs one more check. Approve it on another of your devices — it will show this code:")
            BigCode(code: code)
            if let line = RestoreWaitLine.text(completesAt: completesAt, contested: contested, now: now) {
                Text(line)
                    .font(.caption).foregroundStyle(.white.opacity(0.6)).multilineTextAlignment(.center)
                    .accessibilityIdentifier("restore.countdown")
            }
            Divider().overlay(.white.opacity(0.1))
            SecureField("Account PIN (optional)", text: $pin)
                .textFieldStyle(.plain).padding(12).glassEffect(.regular, in: .capsule)
            if !message.isEmpty { statusLine(message, ok: false) }
            Button { Task { await retry(usingPin: true) } } label: {
                Text("Use PIN").frame(maxWidth: .infinity).padding(.vertical, 2)
            }
            .controlSize(.large).buttonStyle(.glass).tint(.skAccent).disabled(busy || pin.count < 6)
            PrimaryButton(title: "Check again", busy: busy) { Task { await retry(usingPin: false) } }
                .disabled(busy)
            Button("Close") { app.recoveryWaiting = false }
                .buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .interactiveDismissDisabled()
        .task {
            await refresh()
            // Ask once so the server says when the hold ends; then keep looking.
            await retry(usingPin: false, quiet: true)
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(15))
                now = Date()
                if !busy { await retry(usingPin: false, quiet: true) }
            }
        }
    }

    private func refresh() async {
        guard let client = app.client else { return }
        code = await client.recoveryFingerprint()
        completesAt = await client.recoveryCompletesAt()
        contested = await client.recoveryContested()
        now = Date()
    }

    private func retry(usingPin: Bool, quiet: Bool = false) async {
        guard let client = app.client else { if !quiet { message = "Not connected." }; return }
        busy = true; defer { busy = false }
        if !quiet { message = "" }
        switch await AccountRestore.retry(app: app, client: client, pin: usingPin ? pin : nil) {
        case .restored:
            pin = ""
        case .waiting:
            await refresh()
            if !quiet { message = usingPin ? "That PIN can't finish this restore yet." : "Still waiting." }
        case .pin:
            pin = ""
        case .failed(let why):
            await refresh()
            if !quiet { message = why }
        case .noBackup, .wrongKey:
            break
        }
    }
}

// MARK: - Approve / block a restore (on a device already on the account)

/// A restore of this account without the recovery key is waiting for one of its devices.
/// Shows the request's code; Approve and Block answer THAT request (by id).
struct RecoveryApprovalSheet: View {
    let request: RecoveryRequest
    /// Set when the sheet was opened from the Devices screen (a request that had been put
    /// off): it is not in the prompt queue, so leaving the queue does not close it.
    var onClose: (() -> Void)?
    @EnvironmentObject private var app: AppState
    @State private var busy = false
    @State private var failure = ""

    var body: some View {
        AccountSheet(icon: "person.crop.circle.badge.questionmark.fill", title: "Restore your account on another device?", tint: .orange) {
            bodyText("Someone signed in to your account is restoring it on a new device without your recovery key. Only approve if that is you, right now, and the new device shows this code:")
            BigCode(code: request.fingerprint)
            if !failure.isEmpty { statusLine(failure, ok: false) }
            PrimaryButton(title: "Approve", busy: busy) { Task { await answer(true) } }.disabled(busy)
                .accessibilityIdentifier("recovery.approve")
            Button(role: .destructive) { Task { await answer(false) } } label: {
                Text("Block").frame(maxWidth: .infinity).padding(.vertical, 2)
            }
            .controlSize(.large).buttonStyle(.glass).tint(.red).disabled(busy)
            .accessibilityIdentifier("recovery.block")
            // Put off, not dropped: it stays on the Devices screen until it is answered.
            Button("Decide later") {
                if let workspace = app.current?.id { DeferredRecoveries.shared.put(request, workspaceId: workspace) }
                app.recoveryRequests.removeAll { $0.requestId == request.requestId }
                onClose?()
            }
                .buttonStyle(.plain).foregroundStyle(.white.opacity(0.5)).disabled(busy)
        }
        .interactiveDismissDisabled()
    }

    private func answer(_ approve: Bool) async {
        busy = true; defer { busy = false }
        let outcome = await app.answer(request, approve: approve)
        if case .failed(let why) = outcome {
            failure = why
        } else {
            // The request has left the queue (this sheet closes); say what happened. A request
            // that replaced it gets a prompt of its own, with its own code.
            DeferredRecoveries.shared.remove(requestId: request.requestId)
            onClose?()
            app.recoveryOutcome = RecoveryOutcome(answer: outcome)
        }
    }
}

/// What the user is told after answering a restore request (the request itself is gone from
/// the queue by then, and a newer one may already be next).
struct RecoveryOutcome: Identifiable, Equatable {
    let answer: AppState.RecoveryAnswer
    let id = UUID()

    var title: String {
        switch answer {
        case .approved: return "Approved"
        case .blocked: return "Blocked"
        case .changed: return "That request was replaced"
        case .failed: return "Couldn't answer"
        }
    }

    var message: String {
        switch answer {
        case .approved: return "Approved. The new device will finish in a moment."
        case .blocked: return "Blocked. If that wasn't you, change your password."
        case .changed: return "That request was replaced by a newer one. Nothing was approved."
        case .failed(let why): return why
        }
    }
}

// MARK: - PIN

/// The account PIN, asked for by a reset or a waiting restore (`PinRequired` / `PinIncorrect`).
struct PinEntrySheet: View {
    let prompt: PinPrompt
    @EnvironmentObject private var app: AppState
    @State private var pin = ""
    @State private var busy = false
    @State private var message = ""
    @State private var attemptsLeft: Int?
    @State private var confirmForgot = false

    private var locked: Bool { attemptsLeft == 0 }

    var body: some View {
        AccountSheet(icon: "lock.rectangle.stack.fill", title: "Enter your account PIN") {
            bodyText("This account is protected by a PIN.")
            SecureField("Account PIN", text: $pin)
                .textFieldStyle(.plain).padding(12).glassEffect(.regular, in: .capsule)
                .onSubmit { if pin.count >= 6 && !locked { Task { await submit() } } }
                .accessibilityIdentifier("pin.field")
            if let attemptsLeft {
                statusLine(Self.attemptsText(attemptsLeft), ok: false).accessibilityIdentifier("pin.attempts")
            }
            if !message.isEmpty { statusLine(message, ok: false) }
            PrimaryButton(title: "Continue", busy: busy) { Task { await submit() } }
                .disabled(busy || pin.count < 6 || locked)
            Button("Forgot PIN?") { confirmForgot = true }
                .buttonStyle(.plain).font(.caption).foregroundStyle(.skAccent).disabled(busy)
            Button("Close") { app.pinPrompt = nil }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .interactiveDismissDisabled()
        .onAppear { attemptsLeft = prompt.attemptsLeft }
        .confirmationDialog("Reset without the PIN?", isPresented: $confirmForgot, titleVisibility: .visible) {
            Button("Start the 7-day wait", role: .destructive) { Task { await forgot() } }
        } message: {
            Text("The reset waits 7 days so your other devices can stop it. There is no shortcut.")
        }
    }

    static func attemptsText(_ left: Int) -> String {
        left <= 0 ? "Too many wrong PINs. Try again in 15 minutes." : "Wrong PIN. \(left) \(left == 1 ? "try" : "tries") left."
    }

    private func submit() async {
        guard let client = app.client else { message = "Not connected."; return }
        busy = true; message = ""; defer { busy = false }
        do {
            switch prompt.purpose {
            case .reset:
                _ = try await client.resetDevices(pin: pin)
            case .restore:
                guard try await client.retryRestore(pin: pin) else { message = "Still waiting."; return }
                app.recoveryWaiting = false
            }
            pin = ""
            app.pinPrompt = nil
            await app.deviceBecameActive()
        } catch CoreError.PinIncorrect(_, let left) {
            pin = ""
            attemptsLeft = Int(left)
        } catch CoreError.PinRequired {
            message = "Enter your PIN."
        } catch CoreError.ResetPending(let detail) {
            app.pinPrompt = nil
            app.resetPending = detail
        } catch CoreError.RecoveryPending {
            app.pinPrompt = nil
            app.recoveryWaiting = true
        } catch {
            message = coreErrorText(error, fallback: "That PIN wasn't accepted.")
        }
    }

    /// "Forgot PIN?": the reset falls back to the 7-day hold — there is no shortcut.
    private func forgot() async {
        guard let client = app.client else { message = "Not connected."; return }
        busy = true; message = ""; defer { busy = false }
        if prompt.purpose == .restore {
            // A waiting restore already has its own hold: go back to its screen.
            app.pinPrompt = nil
            app.recoveryWaiting = true
            return
        }
        do {
            _ = try await client.resetDevicesForgotPin()
            app.pinPrompt = nil
            await app.deviceBecameActive()
        } catch CoreError.ResetPending(let detail) {
            app.pinPrompt = nil
            app.resetPending = detail
        } catch {
            message = coreErrorText(error, fallback: "Couldn't start the reset — check your connection.")
        }
    }
}

// MARK: - A stopped install

/// In place of the app when this install is no longer a device of the account: removed by
/// another device, or stopped because the account was restored elsewhere.
struct DeviceStoppedView: View {
    let state: AppState.StoppedState
    @EnvironmentObject private var app: AppState
    @State private var busy = false

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 18) {
                Image(systemName: state == .removed ? "xmark.shield.fill" : "arrow.triangle.2.circlepath.circle.fill")
                    .font(.system(size: 54)).foregroundStyle(.orange)
                Text(state == .removed ? "This device was removed" : "Your account was restored on another device")
                    .font(.title2.bold()).foregroundStyle(.white).multilineTextAlignment(.center)
                    .accessibilityAddTraits(.isHeader)
                    .accessibilityIdentifier("stopped.title")
                Text(state == .removed
                     ? "Another of your devices removed this one from your account. Nothing here can be read by it any more."
                     : "This copy has stopped. If that wasn't you, restore here with your recovery key and change your password.")
                    .font(.subheadline).foregroundStyle(.white.opacity(0.7)).multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                PrimaryButton(title: "Set up this device again", busy: busy) {
                    Task { busy = true; await app.setUpAgain(); busy = false }
                }
                .disabled(busy)
                if app.session == nil {
                    Text("You've also been signed out here. Log in to set this device up again.")
                        .font(.caption).foregroundStyle(.white.opacity(0.55)).multilineTextAlignment(.center)
                } else {
                    Button("Sign out") { app.leaveCurrent() }
                        .buttonStyle(.glass).controlSize(.large).tint(.white.opacity(0.7))
                }
                if app.workspaces.contains(where: { !$0.isSignedOut && $0.id != app.current?.id }) {
                    ForEach(app.workspaces.filter { !$0.isSignedOut && $0.id != app.current?.id }) { other in
                        Button("Open \(other.displayName) instead") { Task { await app.activate(other) } }
                            .buttonStyle(.plain).font(.caption.weight(.semibold)).foregroundStyle(.skAccent)
                    }
                }
            }
            .padding(32).frame(maxWidth: 440)
        }
    }
}

// MARK: - Security activity

/// Profile → Encryption → Security activity: every security notice this device has shown,
/// newest first. Kept in the encrypted cache.
struct SecurityActivityView: View {
    @EnvironmentObject private var app: AppState
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        AccountSheet(icon: "list.bullet.rectangle.portrait.fill", title: "Security activity") {
            if app.securityActivity.isEmpty {
                bodyText("Nothing yet. Changes to your devices, your recovery key and your contacts' devices are listed here.")
            }
            VStack(spacing: 10) {
                ForEach(app.securityActivity) { e in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(alignment: .firstTextBaseline) {
                            Text(e.title).font(.subheadline.weight(.semibold)).foregroundStyle(.white)
                            Spacer(minLength: 8)
                            Text(AccountDates.relative(e.atMs)).font(.caption2).foregroundStyle(.white.opacity(0.45))
                        }
                        Text(e.message).font(.caption).foregroundStyle(.white.opacity(0.65))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(12).frame(maxWidth: .infinity, alignment: .leading)
                    .glassEffect(.regular, in: .rect(cornerRadius: 14, style: .continuous))
                    .accessibilityElement(children: .combine)
                }
            }
            Button("Done") { dismiss() }.buttonStyle(.plain).foregroundStyle(.white.opacity(0.5))
        }
        .task { await app.loadSecurityActivity() }
    }
}
