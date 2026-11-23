#if os(macOS)
import Foundation
import AppKit
import Sparkle

/// macOS self-update via Sparkle. Updates are EdDSA-signed; Sparkle verifies the signature (against
/// `SUPublicEDKey` in Info.plist) before installing, and handles the download → verify → atomic swap
/// → relaunch dance natively.
///
/// ONE FEED FOR EVERYONE. skwod is decentralized and most skwods are p2p, with no https address to
/// serve a feed from — so the feed is not per-server. Every release is published to the public
/// GitHub repo `FlayrLabs/skwod-releases` (binaries + feeds only) and every install reads
/// `SUFeedURL` from Info.plist (build setting `SKWOD_UPDATE_FEED`):
/// `https://github.com/FlayrLabs/skwod-releases/releases/latest/download/appcast.xml`.
///
/// GitHub is a distribution channel, not a trust anchor: Sparkle follows GitHub's redirects to its
/// asset hosts, and that is fine because every archive must carry an EdDSA signature that verifies
/// against `SUPublicEDKey` (`SUVerifyUpdateBeforeExtraction`). Whoever controls the repo, the CDN
/// or the network can at most withhold an update, never install one.
///
/// THE FEED IS SIGNED TOO (`SURequireSignedFeed`, Sparkle 2.10.1 `SUAppcastDriver.m`): the
/// appcast must end in a `sparkle-signatures` block whose EdDSA signature, by the same key,
/// covers everything before it — version numbers, release notes, links, the "critical" flag.
/// An unsigned or altered feed is an error and nothing in it is shown.
/// `SUSignedFeedFailureExpirationInterval` is 0, which switches off Sparkle's fallback (by
/// default, after 20 days of failures it would accept an unsigned feed in a reduced "safe"
/// mode). What Sparkle does NOT offer is a signed expiry: an old, validly signed feed can be
/// replayed, so a freeze on an older-but-newer signed build is not detectable on the Mac
/// (RELEASE-SIGNING.md, "What the feeds do and do not guarantee").
///
/// THE FEED URL IS FIXED (`feedURLString(for:)`): Sparkle also honours an `SUFeedURL` value in
/// the app's user defaults, which any process running as the user can write. The delegate
/// answer takes precedence over it (Sparkle 2.10.1 `SPUUpdater.m`, "Delegate gets first
/// priority"), and a stray default is cleared at start.
///
/// SCHEDULE (Info.plist): a background check once a day (`SUScheduledCheckInterval`), and updates
/// download by themselves and install when the app quits (`SUAutomaticallyUpdate`). The user can
/// switch the automatic check off in Profile; "Check for Updates…" keeps working either way. A
/// check is one anonymous GET of a public file, but GitHub sees the Mac's IP address
/// (docs/SECURITY.md).
///
/// WHILE THIS MAC HOSTS A SKWOD an install is never silent: relaunching the app stops the server
/// for every member. A downloaded update is held (`pendingUpdateVersion`) and the user is asked —
/// "Install now" or "Later" — and so is an "Install and Relaunch" chosen in Sparkle's own window.
/// Quitting still installs a downloaded update (the quit itself is confirmed, `HostAppDelegate`),
/// and after an update relaunch the server comes back by itself (`ensureLocalServerRunning`).
///
/// RELEASE-KEY HYGIENE: the EdDSA private key that signs the appcast
/// (`apps/apple/sparkle_private_key.pem`, consumed by `package-release.sh`) is a signing secret and
/// is gitignored — it must NEVER be committed. It lives in the maintainers' secret store and is
/// restored into the working tree with `fetch-signing-keys.sh`; it is NOT on a hardware token or
/// an offline machine yet (RELEASE-SIGNING.md, "Known operational risks"). Only the PUBLIC key belongs in the
/// repo/app (as `SUPublicEDKey` in the Info.plist).
final class SparkleUpdater: NSObject, ObservableObject, SPUUpdaterDelegate {
    static let shared = SparkleUpdater()

    // Created right after `super.init()` so it can be handed `self` as the updater delegate.
    private var controller: SPUStandardUpdaterController!
    private var observation: NSKeyValueObservation?

    /// The version of a downloaded update that is waiting for the user's yes because this Mac
    /// is hosting. nil = nothing is being held.
    @Published private(set) var pendingUpdateVersion: String?
    /// Continues the held install (Sparkle's block). Calling it relaunches the app.
    private var pendingInstall: (() -> Void)?
    /// The user said yes to the held update: do not ask again on the way out.
    private var consented = false
    private var promptShown = false
    private var activeObserver: NSObjectProtocol?

    /// "Check for updates automatically" (Profile). Sparkle keeps the choice in the app's defaults;
    /// the default is on (`SUEnableAutomaticChecks` in Info.plist).
    @Published private(set) var automaticChecks = true

    /// Whether this build updates itself at all. A Debug build never does: it must not replace
    /// itself with the published release while it is being worked on, and it has no business
    /// calling GitHub. No feed or no public key in the build → no updates either (never an
    /// unverified one).
    static let enabled: Bool = {
        #if DEBUG
        return false
        #else
        let info = Bundle.main.infoDictionary ?? [:]
        guard let key = info["SUPublicEDKey"] as? String, !key.isEmpty,
              let feed = info["SUFeedURL"] as? String, isAcceptableFeed(feed) else { return false }
        return true
        #endif
    }()

    /// The feed must be a plain `https://` URL — never cleartext, loopback or with credentials.
    static func isAcceptableFeed(_ feed: String) -> Bool {
        guard let comps = URLComponents(string: feed), comps.scheme?.lowercased() == "https",
              let host = comps.host, !host.isEmpty, !InviteLink.isLoopback(host.lowercased()),
              comps.user == nil, comps.password == nil else { return false }
        return true
    }

    private override init() {
        // startingUpdater: true starts Sparkle's scheduled background checks right away.
        super.init()
        controller = SPUStandardUpdaterController(startingUpdater: Self.enabled, updaterDelegate: self, userDriverDelegate: nil)
        guard Self.enabled else { automaticChecks = false; return }
        // A feed URL left in user defaults (written by anything running as this user) is
        // removed; `feedURLString(for:)` below would override it anyway.
        controller.updater.clearFeedURLFromUserDefaults()
        automaticChecks = controller.updater.automaticallyChecksForUpdates
        observation = controller.updater.observe(\.automaticallyChecksForUpdates, options: [.new]) { [weak self] updater, _ in
            let on = updater.automaticallyChecksForUpdates
            DispatchQueue.main.async { self?.automaticChecks = on }
        }
    }

    var canCheckForUpdates: Bool { Self.enabled && controller.updater.canCheckForUpdates }

    /// User-initiated check — shows Sparkle's standard UI (progress, release notes, install prompt).
    func checkForUpdates() {
        guard Self.enabled else { return }
        controller.updater.checkForUpdates()
    }

    /// Turn the daily background check on or off. Off = nothing contacts GitHub until the user
    /// asks; on also re-enables download + install-on-quit.
    func setAutomaticChecks(_ on: Bool) {
        guard Self.enabled else { return }
        controller.updater.automaticallyChecksForUpdates = on
        if on { controller.updater.automaticallyDownloadsUpdates = true }
        automaticChecks = on
    }

    // MARK: not while hosting, unless the user says so

    /// "Install now": continue the held update. The app relaunches and the server with it.
    func installPendingUpdate() {
        guard let install = pendingInstall else { return }
        consented = true
        pendingInstall = nil
        pendingUpdateVersion = nil
        MainActor.assumeIsolated { HostManager.shared.quittingForUpdate = true }
        install()
    }

    private var hosting: Bool {
        MainActor.assumeIsolated { HostManager.shared.isHosting }
    }

    /// Keep Sparkle's "go on" block and ask — now if the app is in front, otherwise the next
    /// time it is (a dialog must not jump out of a menu-bar app the user is not looking at).
    private func hold(_ item: SUAppcastItem, install: @escaping () -> Void) {
        pendingInstall = install
        pendingUpdateVersion = item.displayVersionString
        promptShown = false
        DispatchQueue.main.async { [weak self] in self?.promptWhenActive() }
    }

    private func promptWhenActive() {
        guard pendingInstall != nil, !promptShown else { return }
        guard NSApp.isActive else {
            if activeObserver == nil {
                activeObserver = NotificationCenter.default.addObserver(
                    forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
                ) { [weak self] _ in self?.promptWhenActive() }
            }
            return
        }
        if let activeObserver { NotificationCenter.default.removeObserver(activeObserver) }
        activeObserver = nil
        promptShown = true
        // Hosting stopped in the meantime: nobody would go offline, so there is nothing to ask —
        // the update installs when Skwod quits, as it does on a Mac that is not hosting.
        guard hosting else { return }
        let alert = NSAlert()
        alert.messageText = HostReliability.updatePromptTitle
        alert.informativeText = HostReliability.updatePromptBody
        alert.addButton(withTitle: "Install now")
        alert.addButton(withTitle: "Later")
        if alert.runModal() == .alertFirstButtonReturn { installPendingUpdate() }
        // "Later": the update stays held; the server panel keeps an "Install now" row, and
        // quitting Skwod installs it.
    }

    // MARK: SPUUpdaterDelegate

    /// The one feed this build reads: the URL compiled into its Info.plist, read from the bundle
    /// itself — never from user defaults.
    static var bundledFeed: String? {
        guard let feed = Bundle.main.infoDictionary?["SUFeedURL"] as? String, isAcceptableFeed(feed) else { return nil }
        return feed
    }

    func feedURLString(for updater: SPUUpdater) -> String? { Self.bundledFeed }

    /// An automatically downloaded update is about to be scheduled for a silent install. While
    /// hosting, take charge of it (true): Sparkle then does not prompt or relaunch by itself, and
    /// the user is asked instead. It is still installed when the app quits.
    func updater(_ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem,
                 immediateInstallationBlock immediateInstallHandler: @escaping () -> Void) -> Bool {
        guard hosting else { return false }
        hold(item, install: immediateInstallHandler)
        return true
    }

    /// Sparkle is about to quit and relaunch the app to install. While hosting that needs a yes
    /// that knows about the members — Sparkle's own "Install and Relaunch" does not mention them.
    func updater(_ updater: SPUUpdater, shouldPostponeRelaunchForUpdate item: SUAppcastItem,
                 untilInvokingBlock installHandler: @escaping () -> Void) -> Bool {
        guard HostReliability.updateNeedsConsent(hosting: hosting, consented: consented) else { return false }
        hold(item, install: installHandler)
        return true
    }

    /// The relaunch is going ahead: the quit that follows is not the user's to confirm again.
    func updaterWillRelaunchApplication(_ updater: SPUUpdater) {
        MainActor.assumeIsolated { HostManager.shared.quittingForUpdate = true }
    }
}
#endif
