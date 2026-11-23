import SwiftUI
import LocalAuthentication
import Security
#if os(macOS)
import AppKit
#endif

/// Optional app lock: Face ID / Touch ID — or the device passcode — to open Skwod, at launch and
/// after it has been in the background for a while.
///
/// It guards the screen, not the data: the encrypted cache is protected by its Keychain key
/// (readable only while the device is unlocked) whether or not this is on. What the lock adds is
/// that someone holding the UNLOCKED device still cannot open the app. While locked, the root
/// view is replaced by the lock screen — nothing of the app (sheets included) is mounted. And
/// while the lock is ENABLED — locked right now or not — notifications say only "New message":
/// a banner is read on the lock screen and in Notification Center, outside the app's gate. The
/// notification extension follows the same switch (`NotificationState.appLockEnabled`).
@MainActor
final class AppLock: ObservableObject {
    static let shared = AppLock()

    static let enabledKey = "skwod.lock.enabled"
    static let delayKey = "skwod.lock.afterSeconds"
    /// "Lock after" choices, in seconds, with the words the picker shows.
    static let delays: [(seconds: Int, label: String)] = [
        (0, "Immediately"), (60, "1 minute"), (300, "5 minutes"), (900, "15 minutes"), (3600, "1 hour"),
    ]
    static let defaultDelay = 60

    @Published private(set) var isLocked: Bool
    @Published private(set) var enabled: Bool
    @Published var lastError = ""
    private var backgroundedAt: Date?
    /// How authentication is performed. Replaced in DEBUG runs driven by hooks, where no
    /// person is there to look at the phone; the gate itself is the same code either way.
    var authenticator: (String) async -> Bool = AppLock.systemAuthenticate

    /// Where the two settings live: a Keychain item of the app's (`AppLockSetting`) — not
    /// the preferences, which anything running as the user can rewrite.
    static let settingAccount = "applock-setting"
    private var setting: AppLockSetting

    private static func readSetting() -> AppLockSetting {
        let (value, status) = Keychain.getWithStatus(settingAccount)
        let stored: AppLockSetting.Stored = value.map { .value($0) } ?? (status == errSecItemNotFound ? .absent : .unreadable)
        let defaults = UserDefaults.standard
        let resolved = AppLockSetting.resolve(stored: stored, legacyEnabled: defaults.bool(forKey: enabledKey),
                                              legacyDelay: defaults.object(forKey: delayKey) as? Int)
        if resolved.migrate, let json = resolved.setting.encoded { Keychain.set(json, for: settingAccount) }
        return resolved.setting
    }

    private func storeSetting() {
        if let json = setting.encoded { Keychain.set(json, for: Self.settingAccount) }
        // The old preferences are kept in step for nothing but an older build reading them.
        UserDefaults.standard.set(setting.enabled, forKey: Self.enabledKey)
        UserDefaults.standard.set(setting.afterSeconds, forKey: Self.delayKey)
    }

    private init() {
        let stored = Self.readSetting()
        setting = stored
        let on = stored.enabled
        enabled = on
        isLocked = on   // locked at launch, always
        NotificationState.appLockEnabled = on   // what the notification extension reads
        #if DEBUG
        if E2E.env("SKWOD_E2E_APPLOCK") == "1" {
            enabled = true
            isLocked = true
            setting.enabled = true
            storeSetting()
            NotificationState.appLockEnabled = true
        }
        installDebugHooks()
        #endif
        #if os(macOS)
        // On a Mac "in the background" is "not the active app": a window that merely lost focus
        // never reaches the scene's background phase.
        let center = NotificationCenter.default
        center.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.didEnterBackground() }
        }
        center.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.didBecomeActive() }
        }
        #endif
    }

    var delaySeconds: Int { setting.afterSeconds }

    /// Change "Lock after". A LATER lock weakens it, like turning it off, so the user
    /// authenticates first (`AppLockSetting.delayChangeNeedsAuthentication`).
    @discardableResult
    func setDelay(_ seconds: Int) async -> Bool {
        guard seconds != setting.afterSeconds else { return true }
        if AppLockSetting.delayChangeNeedsAuthentication(from: setting.afterSeconds, to: seconds) {
            guard await authenticate("Change when Skwod locks") else {
                lastError = "“Lock after” was not changed."
                settleAfterPrompt()
                objectWillChange.send()
                return false
            }
            settleAfterPrompt()
        }
        lastError = ""
        objectWillChange.send()
        setting.afterSeconds = seconds
        storeSetting()
        return true
    }

    /// What this device can unlock with, for the setting's caption.
    static var methodName: String {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else { return "your device passcode" }
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        case .opticID: return "Optic ID"
        default: return "your device passcode"
        }
    }

    /// Whether the device has anything to authenticate with at all (a passcode, at least).
    static var available: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    /// Biometrics, falling back to the device passcode / login password.
    nonisolated static func systemAuthenticate(_ reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }

    /// Turn the lock on or off. Either way the user authenticates first: nobody turns on a lock
    /// they cannot pass, and nobody holding the unlocked app turns it off.
    func setEnabled(_ on: Bool) async -> Bool {
        guard on != enabled else { return true }
        guard await authenticate(on ? "Turn on app lock for Skwod" : "Turn off app lock for Skwod") else {
            lastError = on ? "App lock was not turned on." : "App lock is still on."
            settleAfterPrompt()
            return false
        }
        lastError = ""
        enabled = on
        setting.enabled = on
        storeSetting()
        NotificationState.appLockEnabled = on
        if !on { isLocked = false; backgroundedAt = nil } else { settleAfterPrompt() }
        return true
    }

    /// The scene went to the background.
    ///
    /// The time is recorded whatever else is going on — also while one of this app's own
    /// authentication prompts is up (a prompt that is cancelled, or fails, must not leave the
    /// app counting as "never left"). The one exception is the unlock prompt of an app that is
    /// ALREADY locked: it stays locked whatever the clock says.
    func didEnterBackground(now: Date = Date()) {
        guard enabled, !isLocked else { return }
        if backgroundedAt == nil { backgroundedAt = now }
        // "Immediately": locked before the app is seen again, also in the app switcher.
        if delaySeconds == 0 { isLocked = true }
    }

    /// The scene is active again: lock if it was away at least as long as the setting says.
    func didBecomeActive(now: Date = Date()) {
        guard enabled, let since = backgroundedAt else { return }
        // While a prompt of ours is up the app is "inactive" for as long as the prompt takes:
        // decide when it has finished (see `authenticate`), not now.
        guard !authenticating(now: now) else { return }
        backgroundedAt = nil
        if Self.shouldLock(awaySeconds: now.timeIntervalSince(since), delaySeconds: delaySeconds) { isLocked = true }
    }

    /// When one of this app's own prompts went up (nil = none). A prompt that never reports
    /// back stops counting after a minute, so a stuck flag cannot hold the lock open.
    private var promptStartedAt: Date?
    static let promptTimeout: TimeInterval = 60

    private func authenticating(now: Date = Date()) -> Bool {
        guard let started = promptStartedAt else { return false }
        if now.timeIntervalSince(started) > Self.promptTimeout { promptStartedAt = nil; return false }
        return true
    }

    /// Run one prompt. Whatever its outcome, the background time recorded while it was up
    /// is kept and judged afterwards — a cancelled or failed prompt never clears it.
    private func authenticate(_ reason: String) async -> Bool {
        promptStartedAt = Date()
        let ok = await authenticator(reason)
        promptStartedAt = nil
        return ok
    }

    /// After a prompt that did NOT unlock: if the app left the foreground while it was up (or
    /// before), apply the usual rule now.
    private func settleAfterPrompt(now: Date = Date()) {
        guard enabled, !isLocked, let since = backgroundedAt else { return }
        #if os(macOS)
        let active = NSApp?.isActive ?? true
        #else
        let active = true
        #endif
        guard active else { return }   // still away: judged when it comes back
        backgroundedAt = nil
        if Self.shouldLock(awaySeconds: now.timeIntervalSince(since), delaySeconds: delaySeconds) { isLocked = true }
    }

    /// The rule, on its own so it can be checked: away for at least the delay → lock.
    nonisolated static func shouldLock(awaySeconds: TimeInterval, delaySeconds: Int) -> Bool {
        awaySeconds >= Double(delaySeconds)
    }

    func lockNow() { if enabled { isLocked = true } }

    /// Ask the user to authenticate; unlocks on success.
    @discardableResult
    func unlock() async -> Bool {
        guard isLocked else { return true }
        if await authenticate("Unlock Skwod") {
            lastError = ""
            isLocked = false
            backgroundedAt = nil
            return true
        }
        lastError = "Skwod is still locked."
        return false
    }

    #if DEBUG
    /// Hooks for the end-to-end checks (the lock screen replaces the app, so the usual command
    /// loop is not running while locked): `<out>/lock-cmd.txt`, one command per line —
    /// `on`, `off`, `lock`, `unlock`, `deny` (the next authentications fail), `allow`,
    /// `background:<seconds>` (as if the app had been away that long). State goes to
    /// `<out>/applock.json`. Only when `SKWOD_E2E_OUT` is set; authentication is then answered
    /// by the hook (`allow` by default) instead of the system prompt.
    private func installDebugHooks() {
        guard E2E.env("SKWOD_E2E_OUT") != nil else { return }
        var allow = E2E.env("SKWOD_E2E_APPLOCK_DENY") != "1"
        var attempts = 0
        authenticator = { _ in attempts += 1; return allow }
        Task { @MainActor [weak self] in
            let dir = E2E.outDir
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            var log: [String] = []
            while let self {
                let file = dir.appendingPathComponent("lock-cmd.txt")
                if let text = try? String(contentsOf: file, encoding: .utf8) {
                    try? FileManager.default.removeItem(at: file)
                    for command in text.split(whereSeparator: \.isNewline).map({ $0.trimmingCharacters(in: .whitespaces) }) {
                        switch command {
                        case "on": log.append("on:\(await self.setEnabled(true))")
                        case "off": log.append("off:\(await self.setEnabled(false))")
                        case "lock": self.lockNow(); log.append("lock")
                        case "unlock": log.append("unlock:\(await self.unlock())")
                        case "cancelthenaway":
                            // A prompt to turn the lock OFF is cancelled, then the app is away
                            // for an hour: it must be locked on return.
                            allow = false
                            _ = await self.setEnabled(false)
                            allow = true
                            let now = Date()
                            self.didEnterBackground(now: now.addingTimeInterval(-3600))
                            self.didBecomeActive(now: now)
                            log.append("cancelthenaway:locked=\(self.isLocked)")
                        case "deny": allow = false; log.append("deny")
                        case "allow": allow = true; log.append("allow")
                        default:
                            if command.hasPrefix("background:"), let secs = Double(command.dropFirst("background:".count)) {
                                let now = Date()
                                self.didEnterBackground(now: now.addingTimeInterval(-secs))
                                self.didBecomeActive(now: now)
                                log.append("background:\(Int(secs))")
                            }
                        }
                    }
                }
                let state: [String: Any] = ["enabled": self.enabled, "locked": self.isLocked, "delay_seconds": self.delaySeconds,
                                            "auth_attempts": attempts, "commands": log, "screen_security": PrivacySettings.screenSecurity,
                                            "at": Int(Date().timeIntervalSince1970 * 1000)]
                if let data = try? JSONSerialization.data(withJSONObject: state, options: [.prettyPrinted, .sortedKeys]) {
                    try? data.write(to: dir.appendingPathComponent("applock.json"), options: .atomic)
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }
    #endif
}

/// What is on screen while the app is locked. Nothing of the app is mounted behind it.
struct AppLockScreen: View {
    var onUnlock: () -> Void
    @ObservedObject private var lock = AppLock.shared
    @State private var asking = false

    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 18) {
                SkwodLogoTile(size: 96)
                Text("Skwod is locked").font(.title2.bold()).foregroundStyle(.white)
                    .accessibilityAddTraits(.isHeader)
                    .accessibilityIdentifier("applock.title")
                if !lock.lastError.isEmpty {
                    Text(lock.lastError).font(.caption).foregroundStyle(.orange)
                }
                Button { Task { await ask() } } label: {
                    Label("Unlock", systemImage: "lock.open.fill").frame(maxWidth: 220).padding(.vertical, 6)
                }
                .controlSize(.large).buttonStyle(.glassProminent).tint(.skAccent).foregroundStyle(.black)
                .disabled(asking)
                .accessibilityIdentifier("applock.unlock")
            }
            .padding(32)
        }
        // Asked once by itself when the lock screen appears; after a refusal it waits for the button.
        .task { await ask() }
    }

    private func ask() async {
        guard !asking else { return }
        asking = true
        defer { asking = false }
        if await lock.unlock() { onUnlock() }
    }
}

/// The App lock rows of Profile → Privacy.
struct AppLockSettings: View {
    @ObservedObject private var lock = AppLock.shared
    @State private var busy = false

    var body: some View {
        Toggle(isOn: Binding(get: { lock.enabled }, set: { on in
            busy = true
            Task { _ = await lock.setEnabled(on); busy = false }
        })) {
            VStack(alignment: .leading, spacing: 1) {
                Text("App lock").foregroundStyle(.white)
                Text("Ask for \(AppLock.methodName == "your device passcode" ? "your device passcode" : "\(AppLock.methodName) or your device passcode") to open Skwod.")
                    .font(.caption2).foregroundStyle(.white.opacity(0.45))
                if !AppLock.available {
                    Text("Set a device passcode first.").font(.caption2).foregroundStyle(.orange.opacity(0.9))
                }
            }
        }
        .disabled(busy || (!AppLock.available && !lock.enabled))
        .accessibilityIdentifier("applock.toggle")
        if lock.enabled {
            Picker(selection: Binding(get: { lock.delaySeconds }, set: { seconds in Task { await lock.setDelay(seconds) } })) {
                ForEach(AppLock.delays, id: \.seconds) { Text($0.label).tag($0.seconds) }
            } label: {
                Text("Lock after").foregroundStyle(.white)
            }
        }
        if !lock.lastError.isEmpty, !lock.isLocked {
            Text(lock.lastError).font(.caption2).foregroundStyle(.orange.opacity(0.9))
        }
    }
}

/// A secret of the host's shown on screen (the owner password): only to someone who can
/// unlock this device. Where the device has nothing to authenticate with, there is no gate
/// to pass — as for the app lock itself.
enum OwnerSecretGate {
    static func passes(_ reason: String) async -> Bool {
        guard await MainActor.run(body: { AppLock.available }) else { return true }
        return await AppLock.systemAuthenticate(reason)
    }
}
