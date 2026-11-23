import SwiftUI
import os
#if os(iOS)
import UIKit
#else
import AppKit
#endif

// MARK: - Logging

/// The app's only logging channel. Rules (docs/SECURITY.md, invariant "no content in logs"):
///
/// - Never log message content, usernames, user/device ids, join codes, tokens, node ids,
///   server addresses or IPs.
/// - Interpolated values are `.private` unless they are a fixed enum-like word or a count.
/// - Nothing is sent anywhere: this is the unified log on the device, and there is no telemetry
///   or crash-reporting SDK in the app.
enum Log {
    static let app = Logger(subsystem: "io.skwod.client", category: "app")
    static let net = Logger(subsystem: "io.skwod.client", category: "net")
    static let host = Logger(subsystem: "io.skwod.client", category: "host")
    static let push = Logger(subsystem: "io.skwod.client", category: "push")
}

// MARK: - App-switcher privacy screen + screen security

/// User-facing privacy switches (Profile → Privacy).
enum PrivacySettings {
    static let screenSecurityKey = "skwod.privacy.screenSecurity"
    static let hideInSwitcherKey = "skwod.privacy.hideInSwitcher"

    /// Block screenshots / screen recording / screen sharing of skwod's windows. ON for a new
    /// install; an install from before build 44 keeps what it had (off, unless its user had
    /// turned it on) — see `settleDefaults`.
    static var screenSecurity: Bool {
        UserDefaults.standard.bool(forKey: screenSecurityKey)
    }

    /// Decide the defaults that depend on whether this is a new install, once, at launch —
    /// BEFORE any view reads them. "New" = no stored choice and no skwod on this device yet.
    /// An existing install with no stored choice is pinned to what it has been running with.
    static func settleDefaults(hasWorkspaces: Bool) {
        let defaults = UserDefaults.standard
        guard defaults.object(forKey: screenSecurityKey) == nil else { return }
        defaults.set(screenSecurityDefault(storedChoice: nil, hasWorkspaces: hasWorkspaces), forKey: screenSecurityKey)
    }

    /// The rule on its own (checked by `selfcheck`).
    static func screenSecurityDefault(storedChoice: Bool?, hasWorkspaces: Bool) -> Bool {
        storedChoice ?? !hasWorkspaces
    }

    /// Cover the app's content whenever it isn't the active app (app switcher, Mission Control,
    /// the snapshot iOS takes when backgrounding). On by default.
    static var hideInSwitcher: Bool {
        UserDefaults.standard.object(forKey: hideInSwitcherKey) as? Bool ?? true
    }
}

/// Covers the whole window with the app's splash whenever the scene is not active, so the
/// system's app-switcher snapshot (iOS) and inactive-window previews never show a conversation.
/// Also applies the optional screen-security setting to the platform window.
struct PrivacyShield: ViewModifier {
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage(PrivacySettings.hideInSwitcherKey) private var hideInSwitcher = true
    @AppStorage(PrivacySettings.screenSecurityKey) private var screenSecurity = false

    func body(content: Content) -> some View {
        content
            .overlay {
                if hideInSwitcher && shouldCover {
                    ZStack {
                        SkwodBackground()
                        SkwodLogoTile(size: 96)
                    }
                    .ignoresSafeArea()
                    .transition(.identity)   // must be on screen before the snapshot, not fading in
                }
            }
            .background(ScreenSecurityApplier(enabled: screenSecurity))
    }

    private var shouldCover: Bool {
        #if os(iOS)
        // .inactive covers the app-switcher and the control-centre pull; .background covers the
        // snapshot taken as the app is suspended.
        return scenePhase != .active
        #else
        // On macOS a window that merely lost focus is still in plain view next to other apps;
        // blanking it would make the app unusable side by side. Cover only when hidden/minimised.
        return scenePhase == .background
        #endif
    }
}

#if os(macOS)
/// macOS: `NSWindow.sharingType = .none` keeps the window out of screenshots, screen recording
/// and screen sharing.
private struct ScreenSecurityApplier: NSViewRepresentable {
    let enabled: Bool
    func makeNSView(context: Context) -> NSView { NSView() }
    func updateNSView(_ view: NSView, context: Context) {
        DispatchQueue.main.async {
            view.window?.sharingType = enabled ? .none : .readOnly
        }
    }
}
#else
/// iOS has no public "block screenshots" switch. The supported technique is to host the content
/// inside the secure container of a `UITextField` with `isSecureTextEntry`: the system omits
/// that layer from screenshots, screen recordings and AirPlay mirroring. We re-parent the
/// window's root layer into that container while the setting is on.
private struct ScreenSecurityApplier: UIViewRepresentable {
    let enabled: Bool
    func makeUIView(context: Context) -> UIView { UIView() }
    func updateUIView(_ view: UIView, context: Context) {
        DispatchQueue.main.async {
            guard let window = view.window else { return }
            ScreenSecurity.apply(enabled, to: window)
        }
    }
}

@MainActor
enum ScreenSecurity {
    private static var fields: [ObjectIdentifier: UITextField] = [:]

    static func apply(_ enabled: Bool, to window: UIWindow) {
        let key = ObjectIdentifier(window)
        if enabled {
            guard fields[key] == nil else { return }
            let field = UITextField()
            field.isSecureTextEntry = true
            field.isUserInteractionEnabled = false
            window.addSubview(field)
            // The secure container is the text field's first sublayer; hosting the window's layer
            // inside it makes the whole window "secure content".
            guard let container = field.layer.sublayers?.last, let superlayer = window.layer.superlayer else {
                field.removeFromSuperview()
                return
            }
            superlayer.addSublayer(field.layer)
            container.addSublayer(window.layer)
            fields[key] = field
        } else if let field = fields.removeValue(forKey: key) {
            // Put the window's layer back where it was and drop the secure field.
            if let superlayer = field.layer.superlayer { superlayer.addSublayer(window.layer) }
            field.layer.removeFromSuperlayer()
            field.removeFromSuperview()
        }
    }
}
#endif

// MARK: - Decrypted attachment cache

/// Where decrypted attachments live while they are being viewed.
///
/// A player / Quick Look needs a real file, so a decrypted copy has to exist for a while. It is
/// kept as short-lived and as locked-down as the platform allows:
///
/// - in the app's Caches directory, in a folder excluded from backups;
/// - iOS: `NSFileProtectionComplete` on the folder and every file — unreadable while the device
///   is locked;
/// - macOS: owner-only permissions (0700 / 0600); at-rest protection is FileVault's;
/// - emptied at every launch, on sign-out / leaving a skwod / factory reset, and anything older
///   than a day is removed whenever the cache is touched.
///
/// The ciphertext on the server and the keys in the SQLCipher cache are untouched by a wipe, so
/// an attachment simply decrypts again the next time it is opened.
enum AttachmentCache {
    static let maxAge: TimeInterval = 24 * 60 * 60

    static var directory: URL {
        let base = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("skwod-attachments" + Profile.suffix("-"), isDirectory: true)
    }

    /// The cache folder, created and locked down. Call before writing.
    static func prepared() -> URL {
        var dir = directory
        let fm = FileManager.default
        if !fm.fileExists(atPath: dir.path) {
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: directoryAttributes)
        }
        try? fm.setAttributes(directoryAttributes, ofItemAtPath: dir.path)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }

    private static var directoryAttributes: [FileAttributeKey: Any] {
        #if os(iOS)
        return [.protectionKey: FileProtectionType.complete, .posixPermissions: 0o700]
        #else
        return [.posixPermissions: 0o700]
        #endif
    }

    /// Write one decrypted file with the strongest protection the platform offers.
    static func write(_ data: Data, to url: URL) throws {
        #if os(iOS)
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: url, options: [.atomic])
        #endif
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        #if os(macOS)
        quarantine(url)
        #endif
    }

    /// Move a decrypted file that is already on disk into place, with the same protection
    /// `write` gives one (file protection on iOS, owner-only, quarantine on macOS).
    static func adopt(_ file: URL, as url: URL) throws {
        try? FileManager.default.removeItem(at: url)
        try FileManager.default.moveItem(at: file, to: url)
        #if os(iOS)
        try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete, .posixPermissions: 0o600], ofItemAtPath: url.path)
        #else
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        quarantine(url)
        #endif
    }

    #if os(macOS)
    /// Mark a decrypted attachment as downloaded from someone else, exactly as a browser marks a
    /// download. Without it Gatekeeper never looks at the file: a `.app`, `.command`, `.pkg` or
    /// script a member sent would run straight from "Show in Finder" with no warning.
    ///
    /// The app is not sandboxed, so the system does not add this for us. The value is the
    /// standard `flags;hex time;agent;uuid` record with flags 0083 (downloaded by an app, user
    /// has not approved it), the same one `LSQuarantine`-aware apps write.
    static func quarantine(_ url: URL) {
        let stamp = String(Int(Date().timeIntervalSince1970), radix: 16)
        let value = "0083;\(stamp);Skwod;\(UUID().uuidString)"
        let bytes = Array(value.utf8)
        _ = url.withUnsafeFileSystemRepresentation { path in
            setxattr(path, "com.apple.quarantine", bytes, bytes.count, 0, 0)
        }
    }

    /// Whether `url` carries the quarantine mark (DEBUG self-check and tests).
    static func isQuarantined(_ url: URL) -> Bool {
        url.withUnsafeFileSystemRepresentation { path in getxattr(path, "com.apple.quarantine", nil, 0, 0, 0) > 0 }
    }
    #endif

    /// Remove decrypted copies older than `maxAge`.
    static func purgeExpired() {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: [.contentModificationDateKey]) else { return }
        let cutoff = Date().addingTimeInterval(-maxAge)
        for f in files {
            let modified = (try? f.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
            if (modified ?? .distantPast) < cutoff { try? fm.removeItem(at: f) }
        }
    }

    /// Remove every decrypted copy — and the folder older builds used under the temp directory.
    static func wipe() {
        let fm = FileManager.default
        try? fm.removeItem(at: directory)
        guard Profile.name == nil else { return }
        try? fm.removeItem(at: fm.temporaryDirectory.appendingPathComponent("skwod-attachments", isDirectory: true))
    }
}
