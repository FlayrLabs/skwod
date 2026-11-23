import SwiftUI
import Combine

/// App-wide state across one or more connected workspaces. skwod hosts nothing: each workspace is a
/// friend's self-hosted server, held as a fully isolated identity (own account/keys/cache). The user
/// can be in several at once and switch between them; the "active" workspace drives every chat view.
@MainActor
final class AppState: ObservableObject {
    /// All workspaces the user has joined (persisted, tokens in Keychain).
    @Published private(set) var workspaces: [Workspace] = []
    /// The workspace currently in view.
    @Published private(set) var current: Workspace?
    @Published var deviceId: String?
    @Published var restoring = true
    /// A security event the user must see: a contact's safety number changed, this device moved to
    /// the Signal protocol, or the app/server need updating. Shown as an alert at the root.
    @Published var securityNotice: SecurityAlert? {
        didSet { if securityNotice == nil, oldValue != nil { showNextNotice() } }
    }
    /// Notices waiting behind the one on screen. EVERY notice is shown, in order; a second one is
    /// never dropped because a first is up.
    private var noticeQueue: [SecurityAlert] = []

    /// Show `alert` now, or queue it behind the notice already on screen.
    func enqueueNotice(_ alert: SecurityAlert) {
        if securityNotice == alert || noticeQueue.contains(alert) { return }
        if securityNotice == nil { securityNotice = alert } else { noticeQueue.append(alert) }
    }

    private func showNextNotice() {
        guard !noticeQueue.isEmpty else { return }
        // Give SwiftUI a beat to take the dismissed alert down before presenting the next.
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(400))
            guard let self, self.securityNotice == nil, !self.noticeQueue.isEmpty else { return }
            self.securityNotice = self.noticeQueue.removeFirst()
        }
    }

    /// The user chose the action a notice offers ("Let in", "Accept", "Connect").
    func perform(_ action: SecurityAlert.Action) {
        Task { @MainActor [weak self] in
            guard let self else { return }
            switch action {
            case .acceptDevices(let userId, let workspaceId, let shown):
                // Only through the client of the skwod the notice was about — never whichever
                // is current when the user gets to the button. Only the set the notice was
                // raised for (audit L2): if more was listed since, nothing is accepted and the
                // conversation's banner shows the new set.
                guard let client = try? BoundClient.of(self.bound, for: workspaceId) else { return }
                try? await client.acceptIdentityChange(userId: userId, deviceId: "", shown: shown)
            case .useFallback(let workspaceId):
                self.fallbackApproved.insert(workspaceId)
                if let w = self.workspaces.first(where: { $0.id == workspaceId }), self.current?.id == workspaceId {
                    await self.activate(w)
                }
            case .saveRecoveryKey(let reason):
                self.recoveryKeyPrompt = reason
            }
        }
    }

    /// p2p workspaces the user has agreed (this launch) to reach through their https address
    /// when the host cannot be reached by key. Switching transports is never automatic.
    private var fallbackApproved: Set<String> = []
    private var fallbackAsked: Set<String> = []
    /// This account already has a device, so this one must be linked from it (or the account
    /// restored / reset) before it can do anything encrypted. Drives `DeviceLinkSheet`.
    @Published var needsDeviceLink = false
    /// The skwod (workspace id) whose host is newer than this app: it refuses what this build
    /// sends (426 / an unbindable session). Drives `HostNewerBanner` — never a sign-out.
    @Published var hostNewerWorkspaceId: String?
    /// nil = not yet checked; true/false = may use the app. Always true unless the build opts into
    /// the paywall (`SKWOD_PAYWALL`, off by default — see docs/APPLE.md).
    @Published var entitled: Bool?
    /// The base URL to use for the active workspace RIGHT NOW: the https address of a classic
    /// server, or this launch's loopback proxy for a p2p host. Empty while a p2p host is
    /// unreachable. Never persisted, never shown, never logged.
    ///
    /// DERIVED, never stored on its own: the URL is kept together with the workspace it was
    /// resolved for (`LiveBase`), and reads as "" for any other workspace. `session` comes from
    /// `current`, so a request built from `session` + `serverURL` can never pair one skwod's
    /// token with another skwod's server — not even while a switch is still dialing.
    var liveBase: String { LiveBase.url(liveBinding, for: current?.id) }
    @Published private var liveBinding: LiveBase?
    /// An invite that arrived from outside (tapped `skwod://` link, scanned QR) and is waiting for
    /// the connect form. Already validated; the user still has to confirm by signing up / logging in.
    @Published var incomingInvite: String?
    /// Keeps trying to reach a p2p host that was unreachable when its workspace was activated.
    private var reconnectTask: Task<Void, Never>?
    private var p2pCancellable: AnyCancellable?
    private var networkObserver: NSObjectProtocol?
    /// The live E2EE client for the active workspace.
    var client: SkwodClient? { binding.bound?.client }
    /// `client` together with the workspace whose cache it has open. Anything that belongs to
    /// ONE workspace (the conversation stores) takes its client from here — never from
    /// `client` + `current`, which change at different moments while switching workspaces.
    var bound: BoundClient<SkwodClient>? { binding.bound }
    /// Where the client is put up (`bind`, by turn) and taken down (`dropClient`). `client` and
    /// `bound` are both read from it, so they cannot disagree.
    private let binding = ClientBinding<SkwodClient>()
    /// Counts `activate` calls: one that suspended before switching gives way to a later one.
    private var activations = 0
    /// No client — and any `bind` still in flight is over: it will assign nothing.
    private func dropClient() { binding.begin() }

    /// What is bound right now, to hold on to across a server call (`BindTicket`).
    func bindTicket() -> BindTicket? { BindTicket(workspaceId: bound?.workspaceId, turn: bound?.turn) }
    /// Is what `ticket` captured still bound? If not, what the call brought back is dropped.
    func holds(_ ticket: BindTicket) -> Bool { ticket.isCurrent(workspaceId: bound?.workspaceId, turn: bound?.turn) }
    /// An invite code carried over from sign-up: signing up only gates account creation, so the
    /// shell runs the actual server join (membership + key provisioning + channel discovery) with
    /// this code right after the first load.
    var pendingJoinCode: String?
    /// Background inbox sync for the active workspace: fulfills members' provision requests (host)
    /// and installs any relayed keys. Cancelled/restarted when the active workspace changes.
    var inboxTask: Task<Void, Never>?
    /// Live WebSocket relay for the active workspace: instant presence + message notifications.
    let realtime = Realtime()
    /// Who is typing in the open conversation (build 46).
    let typing = TypingCenter()
    /// E2EE avatars (profile pics, server icons, skwod icons) for the active workspace.
    let avatars = AvatarStore()
    /// Who is waiting to be let into each server of the active workspace (join requests + members
    /// the core is holding) — the "Waiting to join" list and its badge.
    let waiting = WaitingRoom()
    /// The local contact book of the active workspace: whose NAME this device stands behind,
    /// and how far (unverified / known / verified).
    let contacts = ContactBook()
    private var contactsCancellable: AnyCancellable?
    // Live-sync bookkeeping (see LiveSync.swift).
    /// channel id → message ids announced by `message` events that still have to be fetched,
    /// decrypted and (if they turn out to be chat from someone else) notified about.
    var notifyQueue: [String: Set<String>] = [:]
    var notifyRunning: Set<String> = []
    /// Message ids already notified about, so a re-delivered event never notifies twice.
    var notified: Set<String> = []
    var mailboxBusy = false
    var mailboxAgain = false
    /// How many "link a device" requests arrived for this account while the app was running.
    @Published var linkRequests = 0
    /// The active ChatModel (set by ChatModel.bind) — lets the avatar store find my channels.
    weak var chatModel: ChatModel?
    /// Forwards nested store changes (avatars) up to `app.objectWillChange` so views observing only
    /// `@EnvironmentObject app` recompose when an avatar arrives/changes.
    private var nestedCancellable: AnyCancellable?
    private var waitingCancellable: AnyCancellable?

    init() {
        #if DEBUG
        E2E.atLaunch()
        E2E.startAccountDriver(self)
        #endif
        CallCoordinator.shared.app = self
        // Everything the live connection reports drives a refresh somewhere (LiveSync.swift).
        realtime.onEvent = { [weak self] topic, event, payload in self?.realtimeEvent(topic: topic, event: event, payload: payload) }
        realtime.onConnected = { [weak self] in self?.realtimeConnected() }
        typing.attach(self)
        nestedCancellable = avatars.objectWillChange
            .sink { [weak self] in self?.objectWillChange.send() }
        waiting.bind(self)
        contacts.bind(self)
        contactsCancellable = contacts.objectWillChange.sink { [weak self] in self?.objectWillChange.send() }
        waitingCancellable = waiting.objectWillChange
            .sink { [weak self] in self?.objectWillChange.send() }
        // The connection indicator reads P2PManager through `connection`.
        p2pCancellable = P2PManager.shared.objectWillChange
            .sink { [weak self] in self?.objectWillChange.send() }
        networkObserver = NotificationCenter.default.addObserver(
            forName: .skwodNetworkChanged, object: nil, queue: .main
        ) { [weak self] _ in Task { @MainActor in await self?.connectionMayHaveChanged() } }
    }

    /// How the active workspace is reached right now (drives `ConnectionPill`).
    var connection: ConnectionQuality {
        guard let w = current else { return .offline }
        guard let nodeId = w.nodeId else { return .server }
        // A p2p workspace currently served by its https fallback.
        if !liveBase.isEmpty, P2PManager.shared.liveBase(for: nodeId) != liveBase { return .server }
        return P2PManager.shared.quality[nodeId] ?? (liveBase.isEmpty ? .offline : .connecting)
    }

    /// Compatibility accessors so existing views keep working against the active workspace.
    var session: AuthSession? {
        // A workspace the server signed out has no session: the root shows the log-in screen.
        guard let w = current, !w.isSignedOut else { return nil }
        return AuthSession(userId: w.userId, token: w.token, expiresAt: w.expiresAt)
    }
    /// The live base URL for REST/WebSocket calls against the active workspace ("" = unreachable).
    var serverURL: String { liveBase }

    /// A base URL that fails fast: lets the encrypted cache attach (history stays readable) while
    /// a p2p host is unreachable. Port 9 is "discard"; nothing listens there.
    private static let offlineBase = "http://127.0.0.1:9"

    /// Per-workspace cache file (isolated on disk by the workspace slug). On iOS it lives in the
    /// container shared with the notification extension when the build has one.
    private func cachePath(for w: Workspace) -> String {
        SharedContainer.cachePath(forWorkspace: w.id)
    }

    /// The call sheet: the server whose voice room is open (set by the Voice row, by answering a
    /// ring, or by a call answered on the system call screen). nil = no call.
    #if os(iOS)
    private var pushDebounce: Task<Void, Never>?

    /// The scene changed (or the screen locked): tell the server whether to push
    /// (`PushPresence` — at once when really away, after a grace when merely inactive, never
    /// during a call).
    func pushPhase(_ phase: PushPresence.Phase) {
        pushDebounce?.cancel(); pushDebounce = nil
        switch PushPresence.onPhase(phase, inCall: activeCall != nil) {
        case .active: realtime.sendPushState(active: true)
        case .background: realtime.sendPushState(active: false)
        case .backgroundAfter(let seconds):
            pushDebounce = Task { [weak self] in
                try? await Task.sleep(for: .seconds(seconds))
                guard !Task.isCancelled, let self, self.activeCall == nil else { return }
                self.realtime.sendPushState(active: false)
            }
        case .keep: break
        }
    }
    #endif

    /// A notification was opened (`Realtime` delegate): switch to its skwod if it is another
    /// one, then open the conversation. The lists may still be loading after a switch, so it
    /// is tried for a few seconds. (With app lock on, the lock screen stays in front until
    /// the user unlocks; the conversation is there behind it.)
    func openFromNotification(workspaceId: String, tag: String, scope: String, token: String = "") async {
        var (workspaceId, scope) = (workspaceId, scope)
        // A redacted notification (app lock, previews off) carries only a token: resolved
        // once the app is unlocked, and an unknown one just leaves the app open.
        if !token.isEmpty {
            for _ in 0..<240 where AppLock.shared.isLocked { try? await Task.sleep(for: .milliseconds(250)) }
            guard !AppLock.shared.isLocked, let target = realtime.target(forToken: token) else { return }
            (workspaceId, scope) = (target.workspaceId, target.scope)
        }
        guard scope.hasPrefix("channel:") || scope.hasPrefix("dm:") else { return }
        let wanted = workspaces.first(where: { $0.id == workspaceId && !workspaceId.isEmpty })
            ?? workspaces.first(where: { !tag.isEmpty && $0.wakeTag == tag })
        if let wanted, wanted.id != current?.id, !wanted.isSignedOut { await activate(wanted) }
        if let wanted, wanted.id != current?.id { return }
        #if os(macOS)
        NSApp.activate(ignoringOtherApps: true)
        #endif
        for _ in 0..<24 {
            if chatModel?.open(scope: scope) == true { return }
            try? await Task.sleep(for: .milliseconds(250))
        }
    }

    /// Who is in each server's voice room (build 47; `VoiceRoster`, fed by `voice_state`).
    @Published var voiceRoster = VoiceRoster()
    @Published var activeCall: CallTarget? {
        didSet {
            if activeCall == nil, oldValue != nil {
                CallCoordinator.shared.callSheetClosed()
                #if os(iOS)
                // The call that kept this install in-band is over and the app is not in
                // front: from now on it is pushed.
                if !appActive { pushPhase(.background) }
                #endif
            }
        }
    }
    /// A call that is ringing right now (from a `ring` event). iOS shows it through CallKit only;
    /// macOS shows the in-app banner.
    @Published var incomingCall: IncomingCall?
    /// A call push woke the app and more than one skwod reports a ring, with nothing to say
    /// which of them sent it: the user picks ("Who's calling?"). Never chosen for them.
    struct RingChoice: Identifiable {
        let workspaceId: String
        let skwod: String
        let ring: RingInfo
        var id: String { workspaceId + ring.ringId }
    }
    @Published var ringChoices: [RingChoice] = []
    /// The cache generation we last saw (the notification extension bumps it when it writes).
    private var seenStoreGeneration = NotificationState.storeGeneration

    /// The app is leaving the foreground: stop syncing and let go of the encrypted cache so the
    /// notification extension may use it. Everything shown so far counts as seen.
    func enterBackground() {
        #if os(iOS)
        // Tell the server we are away, then close the live socket. A socket left open is killed
        // by the system some seconds later without a word, and until the server notices it keeps
        // delivering in-band to a process that is no longer listening — no push, no wake. An
        // explicit "offline" makes this install push-wakeable immediately. (A call keeps the
        // process running in the background, and with it the socket.)
        if activeCall == nil { realtime.suspend() }
        inboxTask?.cancel()
        if let w = current { NotificationState.setHighWater(Int64(Date().timeIntervalSince1970 * 1000), workspaceId: w.id) }
        NotificationState.publicFallback = P2PManager.publicFallback
        seenStoreGeneration = NotificationState.storeGeneration
        StoreLock.shared.release()
        #endif
    }

    /// Back in the foreground: take the cache back (waiting briefly for the extension to finish),
    /// and if the extension wrote to it meanwhile, re-open it so we never work from stale state.
    func enterForeground() async {
        #if os(iOS)
        if let w = current, !w.isSignedOut {
            // The extension may have used the cache while we were away — or may be using it
            // right now. Either way the client we kept is not touched again: `activate` drops
            // it, waits for the lock (asking the extension to yield) and opens the cache anew.
            if NotificationState.storeGeneration != seenStoreGeneration || !StoreLock.shared.acquire(timeout: 0) {
                seenStoreGeneration = NotificationState.storeGeneration
                await activate(w)
                return
            }
            if inboxTask == nil || inboxTask?.isCancelled == true { startInboxSync() }
        }
        #endif
        await connectionMayHaveChanged()
    }

    /// Attach the workspace's own encrypted cache to a client, restoring its engine or registering a
    /// fresh device. Each workspace has an independent cache key in the Keychain.
    private func bind(_ w: Workspace, base: String) async {
        // Drop the previous client first so two clients never hold the same cache at once.
        // This bind's turn. A later bind, or anything that takes the client down, ends it: after
        // every suspension below a superseded bind stops, discards `c` and assigns nothing —
        // and what it does assign is under `w.id`, the workspace THIS call was given.
        let turn = binding.begin()
        let c = SkwodClient(baseUrl: base, token: w.token)
        // A nil key means the Keychain read failed transiently (NOT "no key exists") — attaching
        // would register a fresh device and orphan the real cache. Retry briefly (launch-time
        // keychain hiccups clear fast), then come back cache-less; the next activate retries.
        var keyHex = Keychain.cacheKeyHex(for: w.id)
        for _ in 0..<3 where keyHex == nil {
            try? await Task.sleep(for: .milliseconds(300))
            keyHex = Keychain.cacheKeyHex(for: w.id)
        }
        guard binding.isCurrent(turn) else { return }
        guard let keyHex else {
            deviceId = nil
            _ = binding.commit(turn, workspaceId: w.id, client: c, cacheOpen: false)
            return
        }
        // The cache is opened ONLY while this process holds the cross-process lock. If the
        // notification extension has it (it was decrypting a push), it is asked to yield and
        // we wait for it; without the lock nothing is opened — two processes advancing the
        // same ratchets would corrupt the sessions.
        let locked = await StoreLock.shared.holdForApp()
        guard binding.isCurrent(turn) else { return }
        guard locked else {
            deviceId = nil
            _ = binding.commit(turn, workspaceId: w.id, client: c, cacheOpen: false)
            Log.app.error("cache lock not available; not opening the cache")
            enqueueNotice(SecurityAlert(
                title: "Still finishing a notification",
                message: "Skwod was decrypting a notification in the background and hasn't finished. Your messages will appear in a moment."))
            Task { [weak self] in
                try? await Task.sleep(for: .seconds(3))
                guard let self, self.current?.id == w.id, self.deviceId == nil else { return }
                await self.activate(w)
            }
            return
        }
        #if DEBUG
        StoreLockTrace.note("app_holds_lock")
        #endif
        // The cache file is device-only data: never in an iCloud / Finder backup (it holds the
        // identity key; a restored copy on another device would be a clone of this one).
        SharedContainer.excludeCacheFromBackup(forWorkspace: w.id)
        // A cache that will not open under its key is moved aside by the core (returns false).
        // A cache that could not be opened AT ALL (I/O, a lock) throws: then nothing may be
        // registered — a device made now would be forgotten at the next launch.
        do {
            _ = try await c.attachCache(path: cachePath(for: w), keyHex: keyHex)
        } catch {
            guard binding.isCurrent(turn) else { return }
            deviceId = nil
            _ = binding.commit(turn, workspaceId: w.id, client: c, cacheOpen: false)
            enqueueNotice(SecurityAlert(
                title: "Couldn't open this skwod's data",
                message: "Skwod could not open the encrypted data it keeps for \(w.displayName) on this device, so nothing was set up or changed. Quit and open Skwod again; if this keeps happening, restart the device."))
            return
        }
        guard binding.isCurrent(turn) else { return }
        // (Again now that the file certainly exists: the first open creates it.)
        SharedContainer.excludeCacheFromBackup(forWorkspace: w.id)
        #if DEBUG
        E2E.cacheOpened()
        #endif
        if let resetAt = await c.cacheWasReset(), await c.kvGet(key: "cache.resetTold") != String(resetAt) {
            await c.kvSet(key: "cache.resetTold", value: String(resetAt))
            if binding.isCurrent(turn) { enqueueNotice(SecurityAlert(
                title: "This device's data could not be read",
                message: "The encrypted data Skwod kept for \(w.displayName) on this device would not open, so it was set aside and this device starts again. Link it from another device or restore with your recovery key to get your messages back.")) }
        }
        guard binding.isCurrent(turn) else { return }
        // The invite pinned this server's identity key: the sealed-sender trust root is only
        // accepted if that key signed it (set before anything is sent or received).
        if let pinned = w.pinnedKey {
            do {
                try await c.setPinnedServerKey(serverPublicB64: pinned)
            } catch {
                // The pin could not be applied. Carrying on would mean accepting whatever key the
                // server presents (trust on first use) for a skwod we HAVE a pin for — so stop:
                // no device is registered and nothing encrypted happens until this is resolved.
                guard binding.isCurrent(turn) else { return }
                deviceId = nil
                _ = binding.commit(turn, workspaceId: w.id, client: c, cacheOpen: true)
                enqueueNotice(SecurityAlert(
                    title: "Couldn't verify this skwod",
                    message: "The server identity saved for this skwod could not be loaded, so Skwod can't check that it is talking to the right server. Nothing was sent. Try again; if this keeps happening, leave this skwod and join again with a fresh invite."))
                return
            }
        }
        // What this device calls itself (sealed to the account's own devices), before it registers.
        await c.setDeviceLabel(name: DeviceLabel.suggested)
        // A build-45 server refuses a session bound to no device everything but linking,
        // restoring and binding once the account has a device. Bind it to this install BEFORE
        // the client goes up and anything else asks the server for something (lists, the
        // socket, push). `false`: not a device yet — registering, completing a link and
        // restoring bind by themselves. Removed / superseded: `routeDeviceState` below shows
        // it. Unreachable: the inbox loop binds before its next sync (`bindSession` is cheap
        // once it succeeded).
        if binding.isCurrent(turn), !liveBase.isEmpty {
            do { _ = try await c.bindSession() } catch {
                Log.app.info("session not bound yet: \(String(describing: error), privacy: .public)")
            }
        }
        guard binding.isCurrent(turn) else { return }
        // Up, in one step, as `w.id`'s — or not at all.
        guard binding.commit(turn, workspaceId: w.id, client: c, cacheOpen: true) else { return }
        await routeDeviceState(registerIfNew: true)
        guard binding.isCurrent(turn) else { return }
        await confirmRemovalIfFlagged()
        guard binding.isCurrent(turn) else { return }
        await surfaceSecurityNotices()
        guard binding.isCurrent(turn) else { return }
        await loadSecurityActivity()
    }

    /// Read where this install stands with the account and show the matching screen. Called
    /// after binding and after any typed failure (`DeviceRemoved`, `DeviceSuperseded`,
    /// `RecoveryPending`). `registerIfNew`: an install with no device registers one (which is
    /// what tells us the account already has devices: `LinkRequired`).
    func routeDeviceState(registerIfNew: Bool = false) async {
        // What the client says is written only while it is still the bound one: a bind that
        // was superseded (a switch, a sign-out) must not set this workspace's device state.
        guard let c = client, let asked = bindTicket() else { return }
        let state = await c.deviceState()
        guard holds(asked) else { return }
        #if DEBUG
        E2E.sawDeviceState(state)
        #endif
        switch state {
        case .active:
            let id = await c.currentDeviceId()
            guard holds(asked) else { return }
            deviceId = id
            // (A removal the server announced stays on screen until the core has asked.)
            if !removalFlagged { stopped = nil }
            recoveryWaiting = false
            needsDeviceLink = false
        case .removed, .superseded:
            deviceId = nil
            stopped = state == .removed ? .removed : .superseded
            inboxTask?.cancel()
        case .recoveryPending:
            deviceId = nil
            stopped = nil
            recoveryWaiting = true
        case .unregistered:
            deviceId = nil
            stopped = nil
            guard registerIfNew else { return }
            // Fresh device — or a device upgrading from the pre-libsignal protocol (builds ≤ 40),
            // which keeps its history + space keys but registers a brand-new identity.
            do {
                let id = try await c.registerDevice()
                guard holds(asked) else { return }
                deviceId = id
            } catch _ where !holds(asked) {
                return
            } catch CoreError.UpdateRequired(let detail) {
                hostNewerWorkspaceId = current?.id
                Log.app.info("register refused, update required: \(detail, privacy: .public)")
            } catch CoreError.LinkRequired {
                // A session token alone can't add a device: link it, restore it, or reset.
                needsDeviceLink = true
            } catch CoreError.ResetPending(let detail) {
                resetPending = detail
            } catch CoreError.DeviceLimit(let detail) {
                enqueueNotice(SecurityAlert(title: "Too many devices", message: detail.isEmpty
                    ? "This account already has the most devices it can have. Remove one from another device (Profile → Encryption → Devices), then try again." : detail))
            } catch {
                // Offline, or the server is not answering: the next activate tries again.
            }
            if deviceId != nil { needsDeviceLink = false }
        }
    }

    /// A typed failure from the core that means "this install is not the device any more" (or
    /// not yet): re-read the state and show its screen. Returns true if `error` was one.
    @discardableResult
    func routeIfDeviceError(_ error: Error) async -> Bool {
        switch error {
        case CoreError.DeviceRemoved, CoreError.DeviceSuperseded, CoreError.RecoveryPending:
            await routeDeviceState()
            return true
        default:
            return false
        }
    }

    /// This install was removed from the account, or stopped because the account was restored
    /// elsewhere. Drives `DeviceStoppedView` in place of the app.
    enum StoppedState: Equatable { case removed, superseded }
    @Published var stopped: StoppedState?
    /// A restore onto this install is waiting (an approval, the PIN, or the hold). Drives
    /// `RecoveryWaitingSheet`.
    @Published var recoveryWaiting = false
    /// The account PIN is being asked for (a reset, or a waiting restore).
    @Published var pinPrompt: PinPrompt?
    /// Restores of this account waiting for THIS device to approve or block them, oldest
    /// first. One prompt at a time; never answered automatically.
    @Published var recoveryRequests: [RecoveryRequest] = []
    #if DEBUG
    /// A screen put up by the `show:<name>` hook (E2EAccountHooks).
    @Published var e2eSheet: String?
    #endif
    /// What happened to the restore request the user just answered.
    @Published var recoveryOutcome: RecoveryOutcome?
    /// Why the recovery-key flow is up (nil = not shown).
    @Published var recoveryKeyPrompt: RecoveryKeyReason?
    /// The persistent list behind Profile → Encryption → Security activity (newest first).
    @Published var securityActivity: [SecurityEvent] = []
    /// The workspace whose stored Security activity `securityActivity` was built on (nil: not
    /// read — nothing may be written over the stored log).
    var activityReadFor: String?
    /// The workspace whose events `securityActivity` is showing.
    var activityShownFor: String?
    /// Events logged while the stored log could not be read or written, per workspace.
    var activityWaiting: [(workspaceId: String, event: SecurityEvent)] = []
    /// Reports sealed to this account as the skwod's owner (`Reports`).
    @Published var reports: [AbuseReport] = []
    /// Device names for notices (device id → name), from the last `listDevices`.
    var deviceNames: [String: String] = [:]

    /// A device reset was requested for this account and is in its 7-day hold (the detail says
    /// until when). Drives `ResetPendingSheet`.
    @Published var resetPending: String?

    /// A person's name for a notice: what the contact book shows for them (the DM's name is
    /// the server's claim and is only handed to that rule) — never the raw server name.
    private func name(of userId: String) -> String {
        contacts.authorLabel(userId, claimedName: chatModel?.dms.first(where: { $0.peerUserId == userId })?.name)
    }

    /// Pull pending security notices out of the core and queue EVERY one of them (never just the
    /// first). Called after binding and on every inbox tick, so nothing is silent. Notices about
    /// a contact are also written by the core as a persistent row in that contact's conversation.
    func surfaceSecurityNotices() async {
        guard let client, let noticesOf = bound?.workspaceId else { return }
        for n in await client.takeSecurityNotices() {
            // Someone waiting to join is a list to work through, not an interruption: it shows
            // in the members view ("Waiting to join") with a badge on the members button.
            if n.kind == "join_request" {
                if let serverId = n.serverId { await waiting.refresh(serverId: serverId) }
                continue
            }
            // A restore of this account without the recovery key is waiting for one of its
            // devices: a prompt of its own, showing the request's code. Never auto-answered.
            if n.kind == "recovery_requested" {
                noteRecoveryRequest(n)
                continue
            }
            if var alert = SecurityAlert.from(kind: n.kind, userId: n.userId, deviceId: n.deviceId,
                                              wasVerified: n.wasVerified, serverId: n.serverId, name: name(of:),
                                              deviceName: deviceNames[n.deviceId], workspaceId: noticesOf) {
                // "Accept" on this notice accepts the device set as it is NOW, when the notice
                // is raised — not whatever is listed by the time the button is tapped (L2).
                if case .acceptDevices(let userId, let workspaceId, _)? = alert.action {
                    let shown = await client.contactStatus(userId: userId).acceptFingerprint
                    alert.action = .acceptDevices(userId: userId, workspaceId: workspaceId, shown: shown)
                }
                // Every notice is an alert AND a row in Security activity.
                await logSecurity(kind: n.kind, title: alert.title, message: alert.message, atMs: Int64(n.atMs))
                // "Save a new recovery key" opens the flow itself; the notice is not one more OK.
                if n.kind == "recovery_key_needed" {
                    if recoveryKeyPrompt == nil { recoveryKeyPrompt = .needed }
                    continue
                }
                enqueueNotice(alert)
            }
        }
        await maybePromptForRecoveryKey()
    }

    /// Restore persisted workspaces at launch and open the last-active one (no network sign-in).
    func restore() async {
        defer { restoring = false }
        #if os(macOS)
        // If this Mac has hosted before, bring its local server back up first so the host's own
        // account (which connects via stable localhost) works immediately — the tunnel is separate.
        await HostManager.shared.ensureLocalServerRunning()
        #endif
        // Nothing a skwod answers (member lists, limits, profiles) is written to the system's
        // on-disk URL cache, which is not encrypted with anything of ours: responses are kept
        // in memory only, and what an earlier build left on disk is removed.
        URLCache.shared.removeAllCachedResponses()
        URLCache.shared = URLCache(memoryCapacity: 4 * 1024 * 1024, diskCapacity: 0)
        Keychain.migrateLegacyItems()
        // Each cache key gets the class the settings call for right now (`KeyAccess`; in place):
        // readable after first unlock only where the notification extension may decrypt for a
        // banner — so a notification on a locked phone can say who and what.
        Keychain.reclassify()
        for w in WorkspaceStore.load() { _ = SharedContainer.cachePath(forWorkspace: w.id) }
        AttachmentCache.wipe()   // decrypted attachment copies never survive a relaunch
        StreamedUpload.sweepStaged()   // nor does plaintext staged for an upload
        workspaces = WorkspaceStore.load()
        // What must hold before the first unlock after a restart — "every skwod is muted until
        // then" — is kept where it can be read then (`MuteFlagStore`). And nothing about
        // conversations stays in the shared plist.
        MuteFlagStore.settle(signedInWorkspaceIds: workspaces.filter { !$0.isSignedOut }.map(\.id))
        NotificationState.dropConversationLabelsIfUnused()
        // Screen security is on for a new install; an existing one keeps what it had.
        PrivacySettings.settleDefaults(hasWorkspaces: !workspaces.isEmpty)
        #if os(macOS)
        await HostManager.shared.attach(self)   // the local server may have had to move to another port
        #endif
        dropDeadDuplicates()
        // …and on every load.
        let checked = Workspace.revalidatingNames(workspaces)
        if checked != workspaces { workspaces = checked; WorkspaceStore.save(workspaces) }
        guard !workspaces.isEmpty else { return }
        var target = workspaces.first(where: { $0.id == WorkspaceStore.currentId }) ?? workspaces[0]
        // A skwod whose session ended is not where the app opens when another one is signed in:
        // its tile says "Log in again" instead of the whole app becoming a log-in screen.
        if target.isSignedOut, let live = workspaces.first(where: { !$0.isSignedOut }) { target = live }
        await activate(target)
    }

    /// A signed-out copy of a skwod + account that also has a signed-in entry (made by an older
    /// build joining the same host twice) leaves the LIST. Its files stay on disk; the signed-in
    /// entry is untouched.
    private func dropDeadDuplicates() {
        let drop = WorkspaceDedupe.droppableAtLaunch(workspaces.map(\.dedupeEntry))
        guard !drop.isEmpty else { return }
        workspaces.removeAll { drop.contains($0.id) }
        WorkspaceStore.save(workspaces)
        Log.app.info("dropped \(drop.count, privacy: .public) signed-out duplicate skwod entr(y/ies)")
    }

    /// Remember what a skwod calls itself (its oldest server's name) as the entry's name, so the
    /// rail and headers stop showing the generic "My skwod". Never over a name the user set, and
    /// only a name that passes `SkwodNameRule` (cleaned, capped, not a look-alike of another
    /// entry's name or a reserved label). The host key is shown beside it regardless.
    func learnName(_ learned: String, for workspaceId: String) {
        guard let w = workspaces.first(where: { $0.id == workspaceId }), w.nameSetByUser != true, w.nameFromHost != true else { return }
        let others = workspaces.filter { $0.id != workspaceId }.map(\.displayName)
        guard let n = SkwodNameRule.acceptLearned(learned, otherNames: others), w.name != n else { return }
        var updated = w
        updated.name = n
        store(updated)
    }

    /// The skwod's name as its owner set it on the host (build 46; an older host answers 404 and
    /// nothing changes). Cleaned and checked like any learned name; a name the user set wins.
    func refreshInstanceName() async {
        guard let w = current, !w.isSignedOut, let token = session?.token,
              let base = URL(string: liveBase), !liveBase.isEmpty else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/instance/name"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              var fresh = workspaces.first(where: { $0.id == w.id }), fresh.nameSetByUser != true else { return }
        let others = workspaces.filter { $0.id != w.id }.map(\.displayName)
        if let raw = obj["name"] as? String, let accepted = SkwodNameRule.acceptLearned(raw, otherNames: others) {
            guard fresh.name != accepted || fresh.nameFromHost != true else { return }
            fresh.name = accepted
            fresh.nameFromHost = true
        } else if fresh.nameFromHost == true {
            // The owner cleared it (or it no longer passes): back to the address-derived name.
            fresh.name = Workspace.defaultName(for: fresh.server)
            fresh.nameFromHost = nil
        } else {
            return
        }
        store(fresh)
    }

    /// The owner sets the skwod's name on the host (signed by this device through the core).
    /// Returns a sentence when it failed.
    func setInstanceName(_ raw: String) async -> String? {
        guard client != nil else { return "Not connected — try again in a moment." }
        return await InstanceNameSetter.set(raw, app: self)
    }

    /// "Rename…" on this device: the user's own label for a skwod (the skwod itself has no name
    /// the server keeps — `/api/instance/identity` carries only its id and key).
    func renameLocally(_ workspaceId: String, to raw: String) {
        guard var w = workspaces.first(where: { $0.id == workspaceId }) else { return }
        let cleaned = String(String.UnicodeScalarView(raw.unicodeScalars.filter { !WaitingTrust.isInvisible($0) }))
            .split(whereSeparator: \.isWhitespace).joined(separator: " ").prefix(SkwodNameRule.maxLength)
        if cleaned.isEmpty {
            w.name = Workspace.defaultName(for: w.server); w.nameSetByUser = nil
        } else {
            w.name = String(cleaned); w.nameSetByUser = true
        }
        store(w)
    }

    /// Entries that are the same skwod and account as another entry (the rail offers to remove one).
    var duplicateWorkspaceIds: Set<String> { WorkspaceDedupe.duplicated(workspaces.map(\.dedupeEntry)) }

    /// "Remove this duplicate": the record leaves this device's list and its session is revoked.
    /// Keys, cache and messages on disk are not deleted. Only for an entry that HAS a duplicate.
    func removeDuplicate(_ w: Workspace) async {
        guard duplicateWorkspaceIds.contains(w.id) else { return }
        if !w.isSignedOut { revokeSession(w, base: w.id == current?.id ? liveBase : nil) }
        let wasCurrent = current?.id == w.id
        workspaces.removeAll { $0.id == w.id }
        WorkspaceStore.save(workspaces)
        if wasCurrent, let next = workspaces.first(where: { !$0.isSignedOut }) ?? workspaces.first {
            await activate(next)
        }
    }

    /// Make `w` the active workspace (binding its client + cache). For a p2p host this dials the
    /// host by key first; if it can't be reached the workspace still opens on its local cache and
    /// a background task keeps trying.
    func activate(_ w: Workspace) async {
        var w = w
        reconnectTask?.cancel()
        activations += 1
        let activation = activations
        if current?.id != w.id {
            // What the previous workspace's lists still have to write is written through ITS
            // client, while that client is still up — not dropped with it.
            await chatModel?.flushConversations()
            // A later activate started meanwhile: that one decides where the app goes.
            guard activation == activations else { return }
        }
        // The previous workspace's client goes BEFORE `current` changes: until `bind` there is
        // no client at all, rather than workspace A's client under workspace B's name.
        if current?.id != w.id {
            dropClient(); waiting.reset(); contacts.reset()
            // Nothing of the previous workspace stays reachable under the new one's name: not
            // its base URL (the new session token must never be sent there), and not its live
            // socket (its events must never be handled as the new workspace's).
            liveBinding = nil
            inboxTask?.cancel()
            realtime.disconnect()
        }
        current = w
        WorkspaceStore.currentId = w.id
        if w.isSignedOut {
            // The server ended this session earlier: nothing to bind. The root shows log-in.
            inboxTask?.cancel()
            realtime.disconnect()
            dropClient()
            deviceId = nil
            liveBinding = nil
            signedOut = SignedOutNotice(workspaceId: w.id, name: w.displayName, address: w.server)
            return
        }
        let base = await resolveBase(for: w)
        guard current?.id == w.id else { return }   // superseded while dialing
        // A token older than a week is swapped for a fresh one BEFORE the client is built with it.
        if let base, let fresh = await rotatedIfDue(w, base: base) {
            w = fresh
            current = w
        }
        liveBinding = base.map { LiveBase(workspaceId: w.id, url: $0) }
        await bind(w, base: base ?? Self.offlineBase)
        // Superseded while binding (another activate, a sign-out, leaving): that bind put nothing
        // up, and what follows must not run for `w` against no client or another workspace's.
        guard bound?.workspaceId == w.id else { return }
        // The sidebar waited for this workspace's own client (`ChatModel.loadIfNeeded`).
        await chatModel?.loadIfNeeded()
        // The server may have ended this session while the app was closed (expired, revoked from
        // another device, account removed). That is "signed out", not "unreachable".
        if base != nil, let client, await client.sessionState() == .signedOut {
            await handleSignedOut(w)
            return
        }
        signedOut = nil
        startInboxSync()
        if let base {
            // Live relay: instant presence flips + message notifications for this workspace.
            realtime.mentionWorkspaceId = w.id
            realtime.configure(baseUrl: base, token: w.token, userId: w.userId, status: effectiveStatus)
            await avatars.loadIfNeeded()
            await refreshServerCreatePermission()
            await refreshInstanceName()
        } else {
            realtime.disconnect()
            scheduleReconnect(w)
        }
        await refreshEntitlement()
    }

    /// The base URL to talk to `w` through right now, or nil if it can't be reached.
    private func resolveBase(for w: Workspace) async -> String? {
        #if os(macOS)
        // This Mac's own server gets the session only once it has proven it is the child this
        // app started — never whatever else may be listening on that loopback port.
        if w.nodeId == nil { return await HostManager.shared.gatedBase(w.server) }
        #endif
        guard let nodeId = w.nodeId else { return w.server }
        if let base = await connectWithPatience(nodeId: nodeId) { return base }
        // The host also has a domain (VPS). That address is only ever one the host itself signed
        // (`checkAddressRecord`, learned over the pinned p2p connection — never an invite's
        // `?u=`), it must prove the pinned key FOR THAT ADDRESS, and switching to it is the
        // user's call: https exposes this device's IP address to the server's network path in a
        // way the p2p transport does not, so it is never automatic.
        if let fallback = w.fallbackURL, (w.addressTs ?? 0) > 0, let pinned = w.pinnedKey, await proves(fallback, pinned) {
            if fallbackApproved.contains(w.id) { return fallback }
            // Asked once per launch per skwod; the reconnect loop must not nag.
            guard fallbackAsked.insert(w.id).inserted else { return nil }
            enqueueNotice(SecurityAlert(
                title: "Can't reach \(w.displayName) directly",
                message: "The host isn't answering on its direct (peer-to-peer) address. It also has a web address, \(fallback), which has proved it is the same skwod. Connect through that instead? Your messages stay end-to-end encrypted either way.",
                action: .useFallback(workspaceId: w.id)))
        }
        return nil
    }

    /// Dial a p2p host, but don't make the app wait on a host that isn't answering: after
    /// `patience` seconds the caller carries on offline (cached history, "Host is offline") while
    /// the same dial keeps going in the background and is picked up by the reconnect loop.
    private func connectWithPatience(nodeId: String, patience: Double = 8) async -> String? {
        if let live = P2PManager.shared.liveBase(for: nodeId) { return live }
        var finished = false
        Task { @MainActor in
            _ = try? await P2PManager.shared.connect(nodeId: nodeId)
            finished = true
        }
        let deadline = Date().addingTimeInterval(patience)
        while Date() < deadline, !finished {
            try? await Task.sleep(for: .milliseconds(150))
        }
        return P2PManager.shared.liveBase(for: nodeId)
    }

    /// Keep dialing an unreachable p2p host (5 s → 60 s backoff) until it answers or the user
    /// switches away; then re-activate so the client, realtime and push all bind to the live URL.
    private func scheduleReconnect(_ w: Workspace) {
        reconnectTask?.cancel()
        reconnectTask = Task { [weak self] in
            var delay = 5.0
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(delay))
                guard !Task.isCancelled, let self, self.current?.id == w.id, self.liveBase.isEmpty else { return }
                if await self.resolveBase(for: w) != nil {
                    await self.activate(w)
                    return
                }
                delay = min(delay * 2, 60)
            }
        }
    }

    /// The app came to the foreground or the network changed: nudge the transport, and if the
    /// active host was unreachable, try again now instead of waiting out the backoff.
    func connectionMayHaveChanged() async {
        await P2PManager.shared.networkChanged()
        guard let w = current else { return }
        if liveBase.isEmpty {
            await activate(w)
        } else {
            realtime.reconnectNow()
        }
    }

    /// The relay setting changed: existing sessions were dialed under the old rule, so drop them
    /// and dial again.
    func reconnectAfterTransportSettingChange() async {
        await P2PManager.shared.disconnectAll()
        if let w = current { await activate(w) }
    }

    /// Whether I may create servers in this skwod (host-only + grantable). Defaults open until
    /// checked so an un-bootstrapped/open instance behaves normally.
    @Published var canCreateServers = true
    /// Whether I am this skwod's instance owner (the host) — gates owner-only management UI.
    @Published var isInstanceOwner = false

    func refreshServerCreatePermission() async {
        guard let token = session?.token, let base = URL(string: serverURL), !serverURL.isEmpty else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/instance/can-create-servers"))
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        canCreateServers = obj["can_create"] as? Bool ?? true
        isInstanceOwner = obj["is_owner"] as? Bool ?? false
        #if os(macOS)
        // Ownership of THIS Mac's own server has now been claimed → the one-time owner setup code is
        // dead server-side, so drop the plaintext `.join-code` stash it was mirrored in.
        if isInstanceOwner, HostManager.shared.hasHostedBefore, current?.server == HostManager.localURL {
            HostManager.shared.clearSetupCode()
        }
        #endif
    }

    /// Run a periodic inbox sync while this workspace is active: as a host it fulfills members'
    /// provision requests (auto-join case); for anyone it installs relayed keys. Idempotent + cheap.
    /// Also heartbeats presence (~once a minute) so members lists can show who's online.
    private func startInboxSync() {
        inboxTask?.cancel()
        inboxTask = Task { [weak self] in
            var tick = 0
            var failures = 0
            while !Task.isCancelled {
                if let self, let client = self.client, let me = self.session?.userId {
                    // The mailbox (DMs, keys, provision requests) is synced when the server says
                    // something is in it (`sealed` → `syncMailbox`) and when the socket comes up;
                    // this is the slow safety net behind those: every 30 s, or right away while
                    // there is no live socket to tell us.
                    if tick % 6 == 0 || !self.realtime.isLive {
                        var bound = false
                        do {
                            // Bound before anything else (a bind that could not reach the
                            // server at launch is done here; a no-op once it has been).
                            bound = try await client.bindSession()
                            _ = try await client.processControlInbox(myUserId: me)
                            failures = 0
                            if self.hostNewerWorkspaceId == self.current?.id { self.hostNewerWorkspaceId = nil }
                            await self.drainDmEvents()
                            await self.surfaceSecurityNotices()
                        } catch {
                            // Removed, superseded, or a restore still waiting: its screen is up.
                            if await self.routeIfDeviceError(error) { return }
                            failures += 1
                            // What the refusal means (`SessionRefusal`): never a silent sign-out,
                            // never a wipe. Only a 401 on /api/auth/me ends the session, and then
                            // for this skwod only, with its log-in screen saying so.
                            var updateRequired = false
                            if case CoreError.UpdateRequired = error { updateRequired = true }
                            let signedOut = updateRequired ? false : await client.sessionState() == .signedOut
                            let decision = SessionRefusal.decide(.init(
                                errorText: String(describing: error), updateRequired: updateRequired,
                                sessionSignedOut: signedOut, isRegisteredDevice: self.deviceId != nil,
                                bindSucceeded: bound))
                            Log.app.info("sync refused: \(String(describing: decision), privacy: .public)")
                            switch decision {
                            case .signedOut:
                                if let w = self.current { await self.handleSignedOut(w); return }
                            case .updateApp:
                                failures = 0
                                self.hostNewerWorkspaceId = self.current?.id
                            case .linkDevice:
                                self.needsDeviceLink = true
                            case .deviceStopped:
                                await self.routeDeviceState()
                            case .bindThenRetry, .transient:
                                break
                            }
                        }
                    }
                    if let nodeId = self.current?.nodeId { await P2PManager.shared.refresh(nodeId: nodeId) }
                    if tick % 12 == 0 { await self.heartbeatPresence() }
                    if tick % 6 == 0 { await self.refreshPrimaryChannel() }
                    if tick % 12 == 6 { await self.checkAddressRecord() }
                    // Seed everyone's presence app-wide (~30s) so every surface — DM rows, people
                    // strip, member lists — has dots, not just views that poll for themselves.
                    if tick % 6 == 3 { await self.pollPresence() }
                    tick += 1
                }
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    /// The status I present to others (persisted; "offline" = invisible).
    var myStatus: String {
        get { UserDefaults.standard.string(forKey: "skwod.myStatus") ?? "online" }
        set {
            UserDefaults.standard.set(newValue, forKey: "skwod.myStatus")
            realtime.sendPresence(effectiveStatus)   // instant fan-out over the socket
            Task { await heartbeatPresence() }        // REST fallback keeps last_seen fresh
        }
    }

    /// Whether the app is in the foreground. When it isn't (backgrounded/closed), we present as
    /// offline immediately instead of waiting out the server's 3-minute stale window — so closing
    /// the app reads as offline to everyone right away (parity with Android).
    var appActive = true
    private var effectiveStatus: String { appActive ? myStatus : "offline" }

    /// Called from the scene-phase observer as the app enters foreground/background.
    func setActive(_ active: Bool) {
        appActive = active
        realtime.appActive = active
        realtime.sendPresence(effectiveStatus)   // flip on the socket immediately
        Task { await heartbeatPresence() }
    }

    /// Fetch every subscribed server's member statuses and seed the realtime store, so presence
    /// dots render on all surfaces even before (or without) a live socket event.
    func pollPresence() async {
        guard let token = session?.token, !serverURL.isEmpty, let base = URL(string: serverURL) else { return }
        var statuses: [String: String] = [:]
        for sid in realtime.subscribedServerIds where !sid.isEmpty && sid != "demo" {
            var req = URLRequest(url: base.appendingPathComponent("api/servers/\(sid)/members"))
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            guard let (data, resp) = try? await URLSession.shared.data(for: req),
                  (resp as? HTTPURLResponse)?.statusCode == 200,
                  let parsed = try? JSONDecoder().decode(PresenceMemberList.self, from: data) else { continue }
            for m in parsed.members { statuses[m.userId] = m.status }
        }
        if !statuses.isEmpty { realtime.seedPresence(statuses) }
    }

    /// Push my current status + liveness to the server (members lists stale silent users offline).
    func heartbeatPresence() async {
        guard let token = session?.token, !serverURL.isEmpty, let base = URL(string: serverURL) else { return }
        var req = URLRequest(url: base.appendingPathComponent("api/profiles/me/status"))
        req.httpMethod = "PUT"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: ["status": effectiveStatus])
        _ = try? await URLSession.shared.data(for: req)
    }

    /// Adopt a session just obtained from the skwod at `address`: create/replace its workspace,
    /// persist, activate. `liveBase` is the URL the session was obtained through (the https
    /// address itself, or this launch's loopback proxy for a p2p host) — used here only to read
    /// and pin the server's identity; it is never stored.
    func signIn(_ s: AuthSession, address: SkwodAddress, liveBase: String) async {
        // Pin the server's cryptographic identity (the E2EE trust root hangs off it).
        let identity = try? await fetchServerIdentity(baseUrl: liveBase)
        // The instance id is the SERVER's string, and for a new skwod it becomes the workspace
        // id — a cache FILE name. Only a plain id is kept or matched against; anything else
        // (`../`, a slash, something long) is as if the server had reported none. The core's
        // `safe_instance_id` is the one rule (Android and the core apply the same); the plain
        // check after it only keeps a value that is a plain id as given.
        let reportedInstanceId = WorkspaceIdRule.acceptedInstanceId(identity.map { safeInstanceId(raw: $0.instanceId) })
        let stored = address.stored
        // Reuse an existing workspace's stable localId when this is really the same skwod (matched by
        // host key, instance identity, or the old url-hash for pre-pinning installs) so its
        // cache/keys survive.
        //
        // A p2p node id is authenticated by the transport, so a node-id match is proof on its own.
        // Anything else (instanceId, url slug) is just a claim an impostor can echo, so it only
        // counts when this address proves possession of that workspace's pinned key. Otherwise a
        // malicious host claiming another skwod's instanceId would inherit that skwod's local
        // keys/cache and overwrite its pinned trust root.
        var existing: Workspace?
        if let nodeId = address.nodeId, let byNode = workspaces.first(where: { $0.nodeId == nodeId }) {
            existing = byNode
        } else if let claimed = workspaces.first(where: {
            (reportedInstanceId != nil && $0.instanceId == reportedInstanceId) || $0.id == Workspace.slug(for: stored)
        }) {
            // Never cross-match a p2p address onto a different p2p skwod. (A p2p skwod reached
            // through its https address IS the same skwod once its pinned key is proven: before
            // build 46 that made a second entry for it.)
            let crossesNode = claimed.nodeId != nil && address.nodeId != nil && claimed.nodeId != address.nodeId
            let proven: Bool
            if let pinned = claimed.pinnedKey {
                proven = await proves(liveBase, pinned)
            } else {
                proven = false
            }
            existing = (proven && !crossesNode) ? claimed : nil
        }
        // The same skwod, but a DIFFERENT account than the one whose keys and messages this
        // device keeps for it (it signed out — the data stays — and someone else logs in): that
        // account gets a store of its own. Its session must never open the other's cache.
        let sameSkwod = existing
        if let other = existing, other.userId != s.userId {
            existing = workspaces.first(where: { $0.userId == s.userId && $0.id != other.id
                && (($0.nodeId != nil && $0.nodeId == other.nodeId) || ($0.instanceId != nil && $0.instanceId == other.instanceId)) })
        }
        // An unproven newcomer must never take a localId an existing workspace already uses.
        let takenIds = Set(workspaces.filter { $0.id != existing?.id }.map { $0.id })
        var localId = existing?.localId ?? reportedInstanceId ?? Workspace.slug(for: stored)
        if existing == nil && (takenIds.contains(localId) || !WorkspaceIdRule.isSafe(localId)) { localId = UUID().uuidString.lowercased() }
        // A key that was pinned STAYS pinned. `existing` is only ever set on proof (the p2p
        // node id authenticated by the transport, or a pinned-key challenge above), so what this
        // login presents can never replace the pin of a workspace it did not prove.
        // A p2p skwod logged into through its https address keeps its p2p address (the key is
        // its identity); the https one is not stored from a login.
        let keepsP2P = address.nodeId == nil && existing?.nodeId != nil
        var w = Workspace(server: keepsP2P ? existing!.server : stored, userId: s.userId, token: s.token, expiresAt: s.expiresAt,
                          name: existing?.name ?? Workspace.defaultName(for: stored),
                          localId: localId, instanceId: existing?.instanceId ?? sameSkwod?.instanceId ?? reportedInstanceId,
                          pinnedKey: existing?.pinnedKey ?? sameSkwod?.pinnedKey ?? identity?.serverPublic)
        w.tokenIssuedAt = Int64(Date().timeIntervalSince1970 * 1000)
        signedOut = nil
        if case .p2p(let nodeId, _) = address {
            w.nodeId = nodeId
            // Never from the invite's `?u=` (anyone can write one into a link): only what the
            // host's signed address record told us earlier.
            w.fallbackURL = existing?.fallbackURL ?? sameSkwod?.fallbackURL
        } else if keepsP2P, let existing {
            w.nodeId = existing.nodeId
            w.fallbackURL = existing.fallbackURL
        }
        w.addressTs = existing?.addressTs ?? sameSkwod?.addressTs
        w.wakeTag = existing?.wakeTag
        w.nameSetByUser = existing?.nameSetByUser
        w.nameFromHost = existing?.nameFromHost
        // Replace any existing workspace for the same skwod (re-login / moved).
        workspaces.removeAll { $0.id == w.id }
        workspaces.append(w)
        workspaces = Workspace.revalidatingNames(workspaces)
        WorkspaceStore.save(workspaces)
        // Remember the address (no secrets, no join code) so it survives sign-out for a one-tap
        // log back in.
        KnownServerStore.remember(address: stored, name: w.displayName)
        w = workspaces.last!
        await activate(w)
    }

    // MARK: Sessions

    /// Set while the active workspace has no session because the server ended it. The log-in
    /// screen says so and is prefilled with the skwod's address.
    struct SignedOutNotice: Equatable {
        let workspaceId: String; let name: String; let address: String
        /// The user signed out (as opposed to the server ending the session).
        var byUser = false
    }
    @Published var signedOut: SignedOutNotice?

    /// Tokens are rotated about once a week.
    private static let tokenMaxAgeMs: Int64 = 7 * 24 * 60 * 60 * 1000

    /// Swap a token older than a week for a fresh one and persist it (with its issue date).
    /// Returns the updated workspace, or nil when no rotation happened — not due, or the server
    /// could not do it right now (the old token stays in use; a 401 is dealt with by the session
    /// check that follows binding).
    private func rotatedIfDue(_ w: Workspace, base: String) async -> Workspace? {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        var due = now - (w.tokenIssuedAt ?? 0) > Self.tokenMaxAgeMs
        #if DEBUG
        if E2E.env("SKWOD_E2E_ROTATE") == "1", !E2E.rotatedOnce { due = true }
        #endif
        guard due, !w.isSignedOut, let fresh = try? await rotateSession(baseUrl: base, token: w.token) else { return nil }
        #if DEBUG
        E2E.rotatedOnce = true
        #endif
        var updated = w
        updated.token = fresh.token
        updated.expiresAt = fresh.expiresAt
        updated.tokenIssuedAt = now
        store(updated)
        Log.app.info("session token rotated")
        return updated
    }

    /// Replace the stored copy of a workspace (same id) and persist.
    private func store(_ updated: Workspace) {
        // Names are re-checked on every save: one accepted earlier may now clash.
        workspaces = Workspace.revalidatingNames(workspaces.map { $0.id == updated.id ? updated : $0 })
        WorkspaceStore.save(workspaces)
        if let c = current, let fresh = workspaces.first(where: { $0.id == c.id }) { current = fresh }
    }

    #if os(macOS)
    /// This Mac's own server had to move to another loopback port (`HostManager`): keep the
    /// owner's workspace — same id, keys, cache and pinned identity — under the new address.
    func hostAddressMoved(from old: String, to new: String) async {
        guard let w = workspaces.first(where: { $0.nodeId == nil && $0.server == old }),
              !workspaces.contains(where: { $0.server == new }) else { return }
        var moved = w
        moved.localId = w.id   // the id of an older workspace was derived from its address
        moved.server = new
        store(moved)
        KnownServerStore.forget(address: old)
        if current?.id == moved.id { await activate(moved) }
    }
    #endif

    /// The server answered 401 for `w`: its session is over. Drop the token (and nothing else —
    /// keys, cache and the pinned server identity stay), stop syncing, and show log-in. A Mac
    /// that hosts this skwod signs its owner straight back in with the login in its Keychain.
    func handleSignedOut(_ w: Workspace) async {
        guard let stored = workspaces.first(where: { $0.id == w.id }), !stored.isSignedOut else { return }
        #if os(macOS)
        // The saved password goes only to the child this app started, freshly challenged.
        if stored.server == HostManager.localURL, let local = await HostManager.shared.verifiedLocalURL(),
           let saved = HostManager.shared.ownerLogin,
           let s = try? await login(baseUrl: local, username: saved.username, password: saved.password),
           s.userId == stored.userId {
            var updated = stored
            updated.token = s.token
            updated.expiresAt = s.expiresAt
            updated.tokenIssuedAt = Int64(Date().timeIntervalSince1970 * 1000)
            store(updated)
            Log.app.info("host owner signed back in")
            if current?.id == updated.id { await activate(updated) }
            return
        }
        #endif
        var updated = stored
        updated.token = ""
        updated.expiresAt = 0
        store(updated)
        Log.app.info("session ended by the server; showing log-in")
        // Found out while not in front (a push or a call woke the app), or about a skwod that
        // is not the one on screen: say so, since no log-in screen is there to say it.
        if !appActive || current?.id != updated.id {
            realtime.notify(title: "Signed out", body: "You've been signed out of \(updated.displayName) — open to sign in",
                            privacy: .personal, thread: "session", id: "signed-out-\(updated.id)")
        }
        guard current?.id == updated.id else { return }
        inboxTask?.cancel()
        reconnectTask?.cancel()
        realtime.disconnect()
        // The cache stays on this device: what its lists still have to write is written first.
        await chatModel?.flushConversations()
        guard current?.id == updated.id else { return }
        dropClient()
        deviceId = nil
        signedOut = SignedOutNotice(workspaceId: updated.id, name: updated.displayName, address: updated.server)
    }

    /// The active workspace's wake tag, made on first use (24 characters of `[A-Za-z0-9_-]`
    /// from the system RNG) and stored with the workspace.
    func ensureWakeTag() -> String? {
        guard let w = current else { return nil }
        if let tag = w.wakeTag, !tag.isEmpty { return tag }
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")   // 64: no bias
        var bytes = [UInt8](repeating: 0, count: 24)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        var updated = w
        updated.wakeTag = String(bytes.map { alphabet[Int($0) & 63] })
        store(updated)
        return updated.wakeTag
    }

    /// What is ringing for this device right now, on EVERY skwod it is signed in to — not just
    /// the one in view. A skwod that answers 401 is marked signed out (and says so).
    func pendingRingsEverywhere() async -> [(workspace: Workspace, ring: RingInfo)] {
        var out: [(workspace: Workspace, ring: RingInfo)] = []
        for w in workspaces where !w.isSignedOut {
            let asker: SkwodClient
            if w.id == current?.id, let client, !liveBase.isEmpty {
                asker = client
            } else {
                // Another skwod: a throwaway client holding only that session — no cache, no keys.
                var base: String? = w.nodeId == nil ? w.server : nil
                #if os(macOS)
                if let plain = base { base = await HostManager.shared.gatedBase(plain) }   // own server: proven first
                #endif
                if let nodeId = w.nodeId { base = try? await P2PManager.shared.connect(nodeId: nodeId) }
                guard let base, !base.isEmpty else { continue }
                asker = SkwodClient(baseUrl: base, token: w.token)
            }
            if let rings = try? await asker.pendingRings() {
                out += rings.map { (workspace: w, ring: $0) }
            } else if await asker.sessionState() == .signedOut {
                await handleSignedOut(w)
            }
        }
        return out
    }

    /// Ask the server whether the active workspace's session still stands — called wherever the
    /// app would otherwise conclude "unreachable".
    func checkSession() async {
        guard let client, let w = current, !liveBase.isEmpty else { return }
        if await client.sessionState() == .signedOut { await handleSignedOut(w) }
    }

    /// Resolve an address to a base URL usable right now (dialing a p2p host if needed).
    /// Throws when the host can't be reached.
    func liveBase(for address: SkwodAddress) async throws -> String {
        switch address {
        case .https(let url):
            #if os(macOS)
            // A typed password for "This Mac" goes only to this app's own, proven server.
            guard let base = await HostManager.shared.gatedBase(url) else { throw HostError(HostReliability.notOurServer) }
            return base
            #else
            return url
            #endif
        case .p2p(let nodeId, _): return try await P2PManager.shared.connect(nodeId: nodeId)
        }
    }

    /// The workspace already joined at `address`, if any (matched by host key or stored address).
    func workspace(at address: SkwodAddress) -> Workspace? {
        workspaces.first { w in
            if let nodeId = address.nodeId { return w.nodeId == nodeId }
            return w.server == address.stored
        }
    }

    /// An invite arrived from outside the app (a tapped `skwod://` link, a scanned QR code, a
    /// pasted link). It is untrusted input: validate it, and never act on it beyond opening the
    /// right screen — joining a new skwod always needs the user to type credentials and confirm.
    func handleIncomingLink(_ raw: String) {
        guard let invite = try? InviteLink.parse(raw) else {
            securityNotice = SecurityAlert(
                title: "Not a Skwod invite",
                message: "That link isn't a valid Skwod invite, so nothing was opened. Ask your host to send it again.")
            return
        }
        if let known = workspace(at: invite.address) {
            // Already a member of this skwod: switch to it; the code (if any) joins one more of
            // its servers with the account we already have there.
            // The code is NOT acted on by the tap: a link is untrusted, and joining a server
            // (membership, key requests) is something the user confirms first.
            Task {
                if current?.id != known.id { await activate(known) }
                if let code = invite.joinCode {
                    confirmJoin = PendingJoin(code: code, skwodName: known.displayName)
                }
            }
            return
        }
        incomingInvite = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Bumped whenever `pendingJoinCode` is set while the shell is already up, so it runs the join.
    @Published var pendingJoinTick = 0

    /// A join code that arrived in a tapped link for a skwod we are already in, waiting for the
    /// user to say yes. Nothing is joined until they do.
    struct PendingJoin: Equatable { let code: String; let skwodName: String }
    @Published var confirmJoin: PendingJoin?

    /// The user confirmed the join a link asked for.
    func acceptPendingJoin() {
        guard let join = confirmJoin else { return }
        confirmJoin = nil
        pendingJoinCode = join.code
        pendingJoinTick += 1
    }

    /// The channel the inbox loop watches for host address announcements (set by ChatModel to the
    /// first joined channel). Auto-follow needs a channel to read the announcement from.
    var primaryChannelId: String?

    /// Background refresh of avatars broadcast to the primary channel.
    private func refreshPrimaryChannel() async {
        guard let client, let asked = bindTicket(), let me = session?.userId, let cid = primaryChannelId,
              let rows = try? await client.fetchChannelMessages(channelId: cid, myUserId: me) else { return }
        // Fetched from the skwod that was bound when it was asked: never filed into another's
        // avatar store after a switch.
        guard holds(asked) else { return }
        let serverId = chatModel?.spaces.first(where: { $0.channelId == cid })?.serverId
        let authority = await avatars.authority(serverId: serverId)
        guard holds(asked) else { return }
        avatars.ingest(rows, authority: authority)
    }

    /// Address moves. A new address for a skwod we already belong to is accepted ONLY as a record
    /// signed by the instance key we pinned, with a timestamp newer than the last one we accepted
    /// (`fetchAddressRecord` checks both) — never from a channel message, whoever wrote it, and
    /// never from an invite. It is fetched from the server we are connected to right now.
    ///
    /// - Classic https skwod: follow it through `reconnectIfKnown`, which still makes the NEW
    ///   address prove the pinned key (bound to that address) before any token is sent there.
    /// - p2p skwod: the record names the host's https address. It is remembered as the fallback
    ///   only when it was fetched over the p2p connection itself (the pinned channel); using it
    ///   later still needs the proof and the user's consent (`resolveBase`).
    private func checkAddressRecord() async {
        let askedBase = liveBase
        guard let w = current, !askedBase.isEmpty, let pinned = w.pinnedKey,
              let rec = try? await fetchAddressRecord(baseUrl: askedBase, pinnedServerPublicB64: pinned, lastTs: w.addressTs ?? 0)
        else { return }
        // The record was fetched for `w` as it was BEFORE the await. Write into what is stored
        // for that workspace NOW (a token rotated or a sign-out meanwhile is not undone by a
        // stale copy), and only if it is still the one on screen.
        guard current?.id == w.id, liveBase == askedBase,
              var updated = workspaces.first(where: { $0.id == w.id }), !updated.isSignedOut else { return }
        updated.addressTs = rec.ts
        if let nodeId = w.nodeId {
            guard P2PManager.shared.liveBase(for: nodeId) == askedBase else { return }   // not over p2p: ignore
            updated.fallbackURL = rec.address
        }
        workspaces = workspaces.map { $0.id == w.id ? updated : $0 }
        WorkspaceStore.save(workspaces)
        if current?.id == w.id { current = updated }
        if !w.isP2P, rec.address != w.server {
            _ = await reconnectIfKnown(.https(rec.address), liveBase: rec.address)
        }
    }

    /// Does `base` hold the private half of `pinned` — for that very address? The host app's own
    /// local server (the loopback address this Mac started it on) is the one case where a plain
    /// loopback address is provable; every other loopback address is refused by the core.
    private func proves(_ base: String, _ pinned: String) async -> Bool {
        #if os(macOS)
        if base == HostManager.localURL {
            return (try? await verifyLocalServerIdentity(baseUrl: base, pinnedServerPublicB64: pinned)) == true
        }
        #endif
        #if DEBUG
        // End-to-end runs use a bare server on this machine's loopback. The proof itself is the
        // real one (the pinned key must sign for that address); only "a loopback address may be
        // proven at all" is what this switch allows. Never in Release.
        if E2E.env("SKWOD_E2E_LOOPBACK_PROOF") == "1", base.hasPrefix("http://127.0.0.1:") {
            return (try? await verifyLocalServerIdentity(baseUrl: base, pinnedServerPublicB64: pinned)) == true
        }
        #endif
        return (try? await verifyServerIdentity(baseUrl: base, pinnedServerPublicB64: pinned)) == true
    }

    /// The display name of a known skwod served at `base` — but ONLY after proving that address
    /// holds that skwod's pinned key. instanceId alone is public and an impostor can echo it, so
    /// matching on it would let an attacker address render a trusted "you're already in X — it
    /// just moved" cue and lure credentials. Gating on proof-of-possession makes the cue trustworthy.
    func knownSkwodName(_ base: String) async -> String? {
        guard let identity = try? await fetchServerIdentity(baseUrl: base),
              let known = workspaces.first(where: { $0.instanceId != nil && $0.instanceId == identity.instanceId && !$0.isSignedOut }),
              let pinned = known.pinnedKey, await proves(base, pinned)
        else { return nil }
        return known.displayName
    }

    /// True if `base` presents the instanceId of a skwod you're in but FAILS its pinned-key
    /// proof — i.e. an impostor. Used to refuse sending credentials to a spoofed address.
    func impersonatesKnownSkwod(_ base: String) async -> Bool {
        guard let identity = try? await fetchServerIdentity(baseUrl: base),
              let known = workspaces.first(where: { $0.instanceId != nil && $0.instanceId == identity.instanceId }),
              let pinned = known.pinnedKey else { return false }
        // Known instanceId but the proof does not hold → impersonation.
        return !(await proves(base, pinned))
    }

    /// Reconnect to a skwod you're ALREADY in that is now reachable at `address` — no re-login.
    /// Returns true only if the new address proves it holds the pinned key of a known skwod, so a
    /// fake "reconnect here" link pointing at an impostor is rejected. Keeps the same account,
    /// cache and keys. This is also how a member of a host that used to hand out tunnel addresses
    /// moves over to the host's `skwod://` address: one paste, no new account.
    func reconnectIfKnown(_ address: SkwodAddress, liveBase base: String) async -> Bool {
        // (A skwod this device is signed OUT of has no session to reconnect with: that one goes
        // through log-in, which then finds the same workspace — its keys and messages — again.)
        guard let identity = try? await fetchServerIdentity(baseUrl: base),
              let known = workspaces.first(where: { $0.instanceId != nil && $0.instanceId == identity.instanceId && !$0.isSignedOut }),
              let pinned = known.pinnedKey, await proves(base, pinned)
        else { return false }
        var moved = known
        moved.server = address.stored
        if case .p2p(let nodeId, _) = address {
            moved.nodeId = nodeId
            moved.fallbackURL = known.fallbackURL   // never from the link's `?u=`
        } else {
            moved.nodeId = nil
            moved.fallbackURL = nil
        }
        workspaces = workspaces.map { $0.id == known.id ? moved : $0 }
        WorkspaceStore.save(workspaces)
        KnownServerStore.remember(address: moved.server, name: moved.displayName)
        await activate(moved)
        return true
    }

    /// Whether this build may be used. There is **no paywall in this build**: self-hosted skwods
    /// never gate, and the iOS pricing model isn't settled. The StoreKit check only exists behind
    /// the `SKWOD_PAYWALL` compilation condition, which is off by default (docs/APPLE.md).
    func refreshEntitlement() async {
        #if SKWOD_PAYWALL && os(iOS)
        #if targetEnvironment(simulator) && DEBUG
        entitled = true
        #else
        entitled = await IAP.isSubscribed()
        #endif
        #else
        entitled = true
        #endif
    }

    /// Sign out of the active skwod — and nothing else. The session token is dropped (and
    /// revoked on the server); the encrypted cache, its key and the workspace record STAY, so
    /// signing back in on this device is the same device again: no link, no restore. Deleting
    /// what this device holds is "Erase this device", a separate and explicit act.
    func leaveCurrent() {
        guard let w = current else { return }
        signOut(of: [w])
    }

    /// Sign out of one skwod (its tile's menu) — the same as `leaveCurrent` for any entry.
    func signOut(_ w: Workspace) {
        if w.id == current?.id { leaveCurrent() } else { signOut(of: [w]) }
    }

    private func signOut(of targets: [Workspace]) {
        let liveId = current?.id
        for w in targets where !w.isSignedOut {
            #if os(iOS)
            // Before the session ends: this skwod can no longer wake this install (docs/PUSH.md).
            PushManager.shared.release(w, base: w.id == liveId ? liveBase : nil)
            #endif
            revokeSession(w, base: w.id == liveId ? liveBase : nil)
            if let nodeId = w.nodeId { Task { await P2PManager.shared.disconnect(nodeId: nodeId) } }
            var updated = w
            updated.token = ""
            updated.expiresAt = 0
            workspaces = workspaces.map { $0.id == updated.id ? updated : $0 }
        }
        WorkspaceStore.save(workspaces)
        AttachmentCache.wipe()   // decrypted copies never outlive the session that made them
        Log.app.info("signed out; this device's keys and messages stay")
        guard let liveId, targets.contains(where: { $0.id == liveId }) else { return }
        inboxTask?.cancel()
        reconnectTask?.cancel()
        realtime.disconnect()
        noticeQueue.removeAll()
        securityNotice = nil
        // Signing out keeps this device's messages and lists. What the lists still had to
        // write is written through the client that has the cache open, before it is let go
        // (this function cannot wait, so the writes are handed over).
        if let leaving = bound, leaving.cacheOpen {
            let unsaved = chatModel?.takeUnsavedConversations() ?? []
            if !unsaved.isEmpty {
                let client = leaving.client
                Task { for write in unsaved { try? await client.kvWrite(key: write.key, value: write.value) } }
            }
        }
        dropClient()
        deviceId = nil
        liveBinding = nil
        stopped = nil
        recoveryWaiting = false
        needsDeviceLink = false
        recoveryRequests = []
        recoveryKeyPrompt = nil
        // Another skwod that is still signed in takes over; else the log-in screen, which
        // says where the user just signed out of and has its address filled in.
        if let next = workspaces.first(where: { !$0.isSignedOut }) {
            Task { await activate(next) }
        } else if let w = workspaces.first(where: { $0.id == liveId }) {
            current = w
            signedOut = SignedOutNotice(workspaceId: w.id, name: w.displayName, address: w.server, byUser: true)
        }
    }

    /// Sign out of everything (all workspaces).
    /// Tell the server this session is over, so the token stops working THERE too. Dropping it
    /// locally leaves it valid until it expires (and any open socket alive). Best-effort and
    /// bounded — signing out must work offline. Only a server we can reach right now is told:
    /// the live workspace, or a classic https one.
    private func revokeSession(_ w: Workspace, base: String?) {
        let live = (base?.isEmpty == false) ? base : nil
        guard let root = live ?? ((!w.isP2P && w.server.hasPrefix("https://")) ? w.server : nil),
              let url = URL(string: root)?.appendingPathComponent("api/auth/logout") else { return }
        var req = URLRequest(url: url, timeoutInterval: 4)
        req.httpMethod = "POST"
        req.setValue("Bearer \(w.token)", forHTTPHeaderField: "Authorization")
        Task.detached { _ = try? await URLSession.shared.data(for: req) }
    }

    /// The encrypted cache AND its SQLite side files (`-wal`, `-shm`, `-journal`), which hold
    /// recent pages of the same data.
    private func removeCache(of w: Workspace) {
        let path = cachePath(for: w)
        for suffix in ["", "-wal", "-shm", "-journal"] {
            try? FileManager.default.removeItem(atPath: path + suffix)
        }
    }

    /// Sign out of every skwod. Like `leaveCurrent`: sessions end, this device's keys and
    /// messages stay (see there).
    func signOut() {
        signOut(of: workspaces)
        fallbackApproved.removeAll()
        entitled = nil
    }

    /// Delete everything this device holds for `w`: the encrypted cache (and its side files),
    /// the cache key, the workspace record and what the notification extension kept about it.
    /// Local only — whether the device is still on the account is decided by what was done
    /// before this (`eraseCurrentDevice`), or not at all (`forgetLocally`).
    private func deleteLocalData(of w: Workspace) {
        #if os(iOS)
        // Erase, forget, account deleted: the wake credential this skwod holds is revoked.
        PushManager.shared.release(w, base: w.id == current?.id ? liveBase : nil)
        #endif
        // (Nothing is flushed here: the cache it would be written to is what is being deleted.)
        chatModel?.forgetParked(workspaceId: w.id)
        removeCache(of: w)
        // The cache key, the mutes, and everything else kept under this skwod's id — one list
        // (`WorkspaceItems`), so nothing stored per skwod outlives it.
        WorkspaceItems.wipe(workspaceId: w.id, deleteSecret: Keychain.delete, defaults: .standard, shared: SharedContainer.defaults)
        MuteCenter.shared.forget(workspaceId: w.id)
        UploadLimit.forget(workspace: w.id)
        realtime.forgetNotificationTargets(workspaceId: w.id)
        AttachmentCache.wipe()
        // Ciphertext waiting to upload and anything staged for it.
        StreamedUpload.removeWork(forWorkspace: w.id)
        PendingJoinStore.clear(address: w.server)
        for key in SharedContainer.defaults.dictionaryRepresentation().keys where key.hasPrefix("notif.\(w.id).") {
            SharedContainer.defaults.removeObject(forKey: key)
        }
        NotificationState.forgetConversationLabels(workspaceId: w.id)
        // The one time that is readable before first unlock is settled over the skwods that
        // are left.
        MuteFlagStore.settle(signedInWorkspaceIds: workspaces.filter { !$0.isSignedOut && $0.id != w.id }.map(\.id))
        workspaces.removeAll { $0.id == w.id }
        WorkspaceStore.save(workspaces)
        guard current?.id == w.id else { return }
        inboxTask?.cancel()
        reconnectTask?.cancel()
        realtime.disconnect()
        if let nodeId = w.nodeId { Task { await P2PManager.shared.disconnect(nodeId: nodeId) } }
        noticeQueue.removeAll()
        securityNotice = nil
        dropClient()
        deviceId = nil
        liveBinding = nil
        current = nil
        signedOut = nil
        stopped = nil
        recoveryWaiting = false
        needsDeviceLink = false
        recoveryRequests = []
        recoveryKeyPrompt = nil
        if let next = workspaces.first(where: { !$0.isSignedOut }) ?? workspaces.first {
            Task { await activate(next) }
        } else {
            WorkspaceStore.currentId = nil
        }
    }

    /// "Erase this device": take this device off the account (signed by it), then delete its
    /// cache, key and record. `asLost` erases it as LOST — never restorable, and the recovery
    /// key is retired at once. Throws when the server could not be told and `evenIfOffline`
    /// is false (the caller offers "Erase anyway (offline)").
    func eraseCurrentDevice(asLost: Bool, evenIfOffline: Bool) async throws {
        guard let w = current else { return }
        if let client {
            // Also deletes the cache file; the client is unusable afterwards.
            if asLost {
                try await client.eraseDeviceAsLost(evenIfOffline: evenIfOffline)
            } else {
                try await client.eraseDevice(evenIfOffline: evenIfOffline)
            }
        }
        revokeSession(w, base: liveBase)
        Log.app.info("this device was erased")
        deleteLocalData(of: w)
    }

    /// Remove a skwod this device is signed OUT of from the device, without the server: there
    /// is no session to tell it with. The device row stays on the account until another device
    /// removes it.
    func forgetLocally(_ w: Workspace) {
        guard w.isSignedOut else { return }
        deleteLocalData(of: w)
    }

    /// Every skwod's local data, signed in or not (factory reset, account deletion).
    private func deleteAllLocalData() {
        let liveId = current?.id
        for w in workspaces { revokeSession(w, base: w.id == liveId ? liveBase : nil) }
        Task { await P2PManager.shared.disconnectAll() }
        for w in workspaces { deleteLocalData(of: w) }
        StreamedUpload.removeAllWork()
        SharedContainer.wipeSharedState()
        fallbackApproved.removeAll()
        Keychain.delete("workspaces")
        WorkspaceStore.currentId = nil
        PendingJoinStore.clearAll()
        entitled = nil
    }

    /// The account behind the active skwod was deleted on the server: nothing here can be
    /// used again, so its local data goes too.
    func accountDeleted() {
        guard let w = current else { return }
        deleteLocalData(of: w)
    }

    /// Factory reset: erase EVERY trace of skwod from this Mac — the encrypted message caches, the
    /// workspace logins + cache keys + host owner login in the Keychain, all preferences, and (if this
    /// Mac hosts) the hosted skwod's server database itself. Irreversible; drops the user back to
    /// sign-in. On the host, this destroys the server for all its members.
    func wipeAllLocalData() {
        #if os(iOS)
        // Every wake registration of this device the gateway knows, known to us or not. First:
        // what proves it is this device is among the data deleted next.
        PushManager.shared.revokeEverything()
        #endif
        deleteAllLocalData()   // caches + cache-keys + workspace logins
        #if os(macOS)
        HostManager.shared.wipeHostData()   // stop + delete the hosted server database
        Keychain.delete("tunnel-token")          // left behind by builds that used a Cloudflare tunnel
        Keychain.delete(HostManager.ownerCredentialsAccount)
        #endif
        AttachmentCache.wipe()
        // Sweep any orphaned client caches, then clear the whole preferences domain.
        let appSupport = SharedContainer.privateURL
        if let files = try? FileManager.default.contentsOfDirectory(at: appSupport, includingPropertiesForKeys: nil) {
            for f in files where f.lastPathComponent.hasPrefix("skwod-") { try? FileManager.default.removeItem(at: f) }
        }
        if let domain = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: domain)
        }
    }
}

@main
struct SkwodApp: App {
    @StateObject private var app = AppState()
    @StateObject private var updater = Updater()
    @ObservedObject private var appLock = AppLock.shared
    @Environment(\.scenePhase) private var scenePhase
    #if os(iOS)
    // Bridges APNs token + background wakeups into PushManager (SwiftUI has no hook for these).
    @UIApplicationDelegateAdaptor(PushAppDelegate.self) private var pushDelegate
    #endif
    #if os(macOS)
    // Asks before a quit takes a hosted skwod offline; starts the server at login without a window.
    @NSApplicationDelegateAdaptor(HostAppDelegate.self) private var hostDelegate
    #endif

    var body: some Scene {
        mainWindow
        #if os(macOS)
        // Menu-bar status: the icon itself reflects whether this Mac is hosting (filled = live), and
        // the menu shows the shareable address + join code.
        MenuBarExtra {
            HostStatusMenu()
        } label: {
            HostMenuBarLabel()
        }
        .menuBarExtraStyle(.menu)
        #endif
    }

    private var mainWindow: some Scene {
        let group = WindowGroup {
            root
                .environmentObject(app)
                .environmentObject(updater)
                .environment(\.typingCenter, app.typing)
                .preferredColorScheme(.dark)
                .tint(.skAccent)
                .windowGlass()   // translucent macOS window — desktop shows through the glass
                // iOS: check the connected server's JSON manifest and, if behind, banner a
                // TestFlight hand-off. macOS needs nothing here: Sparkle reads the public release
                // feed on its own daily schedule (SparkleUpdater), whatever skwod is connected.
                .task(id: app.serverURL) {
                    #if os(macOS)
                    _ = SparkleUpdater.shared   // start the scheduled updater with the first window
                    #else
                    if !app.serverURL.isEmpty {
                        await updater.check(serverURL: app.serverURL)
                        // Register for push against the newly-connected server (once authed).
                        PushManager.shared.start()
                        await PushManager.shared.registerIfNeeded()
                    }
                    #endif
                }
                // A tapped `skwod://join/…` invite, or (iOS, through the applinks:skwod.io
                // associated domain) a tapped `https://skwod.io/join#…` share link. Untrusted input: validated, then only ever used
                // to open/prefill the connect screen (see `AppState.handleIncomingLink`).
                .onOpenURL { url in app.handleIncomingLink(url.absoluteString) }
                .modifier(HostSetupPresenter(app: app))   // macOS: owner setup asked for from the menu bar
                .modifier(PrivacyShield())
                #if os(iOS)
                // The screen locked (with a passcode set): away, whatever the scene says.
                .onReceive(NotificationCenter.default.publisher(for: UIApplication.protectedDataWillBecomeUnavailableNotification)) { _ in
                    app.pushPhase(.locked)
                }
                #endif
                .onReceive(NotificationCenter.default.publisher(for: .skwodOpenChat)) { note in
                    let info = note.userInfo as? [String: String] ?? [:]
                    Task { await app.openFromNotification(workspaceId: info["workspace"] ?? "", tag: info["tag"] ?? "", scope: info["scope"] ?? "", token: info["token"] ?? "") }
                }
                .onChange(of: scenePhase) { _, phase in
                    // Back in front: the network may have changed while we were away and a p2p
                    // session may need to re-dial.
                    #if os(iOS)
                    // Away (background, or inactive for longer than a glance at Control
                    // Center): the server is told, so it pushes instead of trusting the socket.
                    app.pushPhase(phase == .active ? .active : phase == .background ? .background : .inactive)
                    #endif
                    if phase == .active { appLock.didBecomeActive(); MentionBadges.reload(); Task { await app.enterForeground() } }
                    // Looking at a chat again: what Notification Center holds about it is read.
                    if phase == .active, let topic = app.realtime.focusedTopic { app.realtime.clearDelivered(topic: topic) }
                    if phase == .background { appLock.didEnterBackground(); app.enterBackground() }
                    // Presence follows the CONNECTION, not window focus. On macOS, scenePhase goes
                    // .inactive whenever the window loses focus — that must never read as offline
                    // (it made everyone red the moment they looked at another app). On iOS, a real
                    // background suspends the process and the server flips us offline when the
                    // socket dies; going offline eagerly here just makes it instant.
                    #if os(iOS)
                    app.setActive(phase != .background)
                    #else
                    // macOS: focus DOES gate notifications (a message in the focused chat while
                    // you're in another app must still notify) — but never presence.
                    app.realtime.appActive = (phase == .active)
                    #endif
                }
        }
        #if os(macOS)
        // Compact titlebar: the toolbar (back/forward + centered workspace label)
        // shares the strip with the traffic lights, and no system title text competes with it.
        return group.windowResizability(.automatic).defaultSize(width: 1180, height: 820)
            .windowToolbarStyle(.unifiedCompact(showsTitle: false))
            // Standard "Check for Updates…" in the app menu, driven by Sparkle.
            .commands {
                CommandGroup(after: .appInfo) {
                    Button("Check for Updates…") { SparkleUpdater.shared.checkForUpdates() }
                }
            }
        #else
        return group
        #endif
    }

    /// The app lock replaces everything: while locked, none of the app is mounted (so no sheet
    /// or alert of it can be up either), only the lock screen.
    @ViewBuilder private var root: some View {
        if appLock.isLocked {
            AppLockScreen(onUnlock: {})
        } else {
            unlockedRoot
        }
    }

    @ViewBuilder private var unlockedRoot: some View {
        #if DEBUG
        // Debug screen selector (for screenshots): SIMCTL_CHILD_SKWOD_SCREEN=chess etc. DEBUG-only, so
        // the mock-session entry point is compiled out of release (App Store/TestFlight) builds.
        if let screen = ProcessInfo.processInfo.environment["SKWOD_SCREEN"] {
            DebugScreen(name: screen).task { app.mockSession() }
        } else {
            liveRoot
        }
        #else
        liveRoot
        #endif
    }

    private var liveRoot: some View {
        Group {
            if app.restoring {
                SplashView().task { await app.restore() }
            } else if let stopped = app.stopped {
                // Not a device of the account any more: say so, in place of the app — also
                // when the removal has already ended the session.
                DeviceStoppedView(state: stopped)
            } else if app.session == nil {
                AuthView()
            } else {
                gated
            }
        }
        // One account sheet at a time, most pressing first (SwiftUI presents one per view).
        .sheet(item: Binding(get: { app.session != nil && !app.restoring ? app.accountSheet : nil },
                             set: { if $0 == nil { app.dismissAccountSheet() } })) { sheet in
            Group {
                switch sheet {
                case .pin(let prompt): PinEntrySheet(prompt: prompt)
                case .waiting: RecoveryWaitingSheet()
                case .setup: DeviceSetupSheet()
                case .approve(let request): RecoveryApprovalSheet(request: request)
                case .recoveryKey(let reason): RecoveryKeySheet(reason: reason)
                }
            }
            .environmentObject(app)
        }
        #if DEBUG
        .sheet(isPresented: Binding(get: { app.e2eSheet != nil }, set: { if !$0 { app.e2eSheet = nil } })) {
            E2ESheet(name: app.e2eSheet ?? "").environmentObject(app).environmentObject(app.chatModel ?? ChatModel())
        }
        #endif
        .alert(app.recoveryOutcome?.title ?? "",
               isPresented: Binding(get: { app.recoveryOutcome != nil }, set: { if !$0 { app.recoveryOutcome = nil } })) {
            Button("OK", role: .cancel) { app.recoveryOutcome = nil }
        } message: {
            Text(app.recoveryOutcome?.message ?? "")
        }
        .sheet(isPresented: Binding(get: { app.resetPending != nil && app.session != nil },
                                    set: { if !$0 { app.resetPending = nil } })) {
            ResetPendingSheet().environmentObject(app)
        }
        // An invite to a skwod we're not in yet, while already signed in elsewhere: the connect
        // form opens prefilled. (Signed out, AuthView itself picks the invite up.)
        .sheet(isPresented: Binding(get: { app.incomingInvite != nil && app.session != nil && !app.restoring },
                                    set: { if !$0 { app.incomingInvite = nil } })) {
            DismissableSheet { AuthView(onConnected: { app.incomingInvite = nil }) }
                .environmentObject(app)
        }
        // One notice at a time; dismissing it brings up the next queued one (none is dropped).
        .alert(app.securityNotice?.title ?? "",
               isPresented: Binding(get: { app.securityNotice != nil }, set: { if !$0 { app.securityNotice = nil } })) {
            if let action = app.securityNotice?.action {
                Button(action.label) { app.securityNotice = nil; app.perform(action) }
                Button("Not now", role: .cancel) { app.securityNotice = nil }
            } else {
                Button("OK", role: .cancel) { app.securityNotice = nil }
            }
        } message: {
            Text(app.securityNotice?.message ?? "")
        }
        // A tapped link carried a join code for a skwod we are already in: ask first.
        .alert("Join a server in \(app.confirmJoin?.skwodName ?? "this skwod")?",
               isPresented: Binding(get: { app.confirmJoin != nil }, set: { if !$0 { app.confirmJoin = nil } })) {
            Button("Join") { app.acceptPendingJoin() }
            Button("Cancel", role: .cancel) { app.confirmJoin = nil }
        } message: {
            Text("The link you opened contains an invite code. Joining adds you to that server with your account here and asks its host for the server's keys. Only continue if you trust where the link came from.")
        }
    }

    /// No paywall in this build. The gate below only exists when the build opts in with the
    /// `SKWOD_PAYWALL` compilation condition (off by default — docs/APPLE.md).
    @ViewBuilder private var gated: some View {
        #if SKWOD_PAYWALL && os(iOS)
        switch app.entitled {
        case .none: SplashView()
        case .some(false): PaywallView()
        case .some(true): MainView()
        }
        #else
        MainView()
        #endif
    }
}

/// The account sheets the root can present — one at a time.
enum AccountSheetRoute: Identifiable, Equatable {
    case pin(PinPrompt)
    case waiting
    case setup
    case approve(RecoveryRequest)
    case recoveryKey(RecoveryKeyReason)

    var id: String {
        switch self {
        case .pin(let p): return "pin-\(p.id)"
        case .waiting: return "waiting"
        case .setup: return "setup"
        case .approve(let r): return "approve-\(r.requestId)"
        case .recoveryKey(let r): return "key-\(r.rawValue)"
        }
    }
}

extension AppState {
    /// Which account sheet is up: what blocks the device first (PIN, a waiting restore, set-up),
    /// then a restore someone is asking this device to approve, then the recovery-key flow.
    var accountSheet: AccountSheetRoute? {
        if let pinPrompt { return .pin(pinPrompt) }
        if recoveryWaiting { return .waiting }
        if needsDeviceLink { return .setup }
        if let request = recoveryRequests.first { return .approve(request) }
        if let recoveryKeyPrompt { return .recoveryKey(recoveryKeyPrompt) }
        return nil
    }

    /// The sheet on screen was dismissed by the system (swipe / Escape where allowed).
    func dismissAccountSheet() {
        switch accountSheet {
        case .pin: pinPrompt = nil
        case .waiting: recoveryWaiting = false
        case .setup: needsDeviceLink = false
        // A restore waiting for this device's answer leaves the queue only by an answer or
        // "Decide later" (the sheet cannot be swiped away). When the SYSTEM takes the sheet
        // down — a permission prompt or another alert came up over it — the request stays and
        // is shown again: the core announces each request once, so dropping it here left a
        // restore nobody on this device could approve until the app was restarted.
        case .approve: break
        case .recoveryKey(let reason):
            recoveryKeyPrompt = nil
            // Closing the first-run prompt without saving a key is "Not now": ask again in a
            // week, not at the next sync.
            if reason == .firstRun { Task { await snoozeRecoveryKeyPrompt() } }
        case nil: break
        }
    }
}

/// A security event to put in front of the user (see `AppState.securityNotice`).
struct SecurityAlert: Equatable {
    /// Something the user can do about the notice (nil = just acknowledge it).
    enum Action: Equatable {
        /// Accept the devices the directory lists for a contact as theirs (clears "verified").
        /// `shown`: the `acceptFingerprint` of the contact's status when the notice was raised.
        case acceptDevices(userId: String, workspaceId: String, shown: String = "")
        /// Reach a p2p skwod through its (proven) https address for this launch.
        case useFallback(workspaceId: String)
        /// Open the recovery-key flow.
        case saveRecoveryKey(RecoveryKeyReason)

        var label: String {
            switch self {
            case .acceptDevices: return "Accept"
            case .useFallback: return "Connect"
            case .saveRecoveryKey(let reason): return reason == .deviceRemoved ? "Make a new key" : "Save a recovery key"
            }
        }
    }

    let title: String
    let message: String
    var action: Action? = nil

    /// A device shown by a short, recognisable prefix of its id.
    static func device(_ id: String) -> String { id.isEmpty ? "a device" : "device \(id.prefix(8))…" }

    /// What the user reads for one core security notice. One alert per notice.
    static func from(kind: String, userId: String, deviceId: String, wasVerified: Bool, serverId: String?,
                     name: (String) -> String, deviceName: String? = nil, workspaceId: String = "") -> SecurityAlert? {
        let who = name(userId)
        // One of this account's own devices: by the name its owner gave it, when known.
        let own = deviceName.map { "“\($0)”" } ?? device(deviceId).prefix(1).uppercased() + device(deviceId).dropFirst()
        switch kind {
        case "account_restored":
            return SecurityAlert(title: "Your account was restored on a new device",
                message: "\(own) was restored from your recovery key, or came back after being erased. If that wasn't you, remove it in Devices and change your password.")
        case "device_removed":
            return SecurityAlert(title: "A device was removed",
                message: "\(own) was removed from your account and your recovery key was retired. Make a new recovery key.",
                action: .saveRecoveryKey(.deviceRemoved))
        case "recovery_key_changed":
            return SecurityAlert(title: "Your recovery key changed",
                message: "The recovery key for your account was changed, removed or retired. If that wasn't you: restore with your old key within 7 days, or report it compromised in Profile → Encryption.")
        case "recovery_key_needed":
            return SecurityAlert(title: "Save a new recovery key",
                message: "Your account has no recovery key now.", action: .saveRecoveryKey(.needed))
        case "owner_changed":
            return SecurityAlert(title: "A skwod's owner changed",
                message: "After your restore, a skwod reports a different owner than the one this account trusted. Its owner is unconfirmed until you check with them.")
        case "protocol_upgraded":
            return SecurityAlert(title: "Encryption upgraded",
                message: "Skwod now uses the Signal protocol. This device has new encryption keys, so your contacts will see that your safety number changed — and theirs changed for you. Your message history on this device is kept. If you verified anyone before, verify them again.")
        case "reset_blocked":
            return SecurityAlert(title: "Blocked an account reset",
                message: "Someone signed in to your account tried to reset its encryption and remove your devices. This device cancelled it. If that wasn't you, change your password now.")
        case "unverified_device":
            return SecurityAlert(title: "Unrecognised device on your account",
                message: "The server lists \(device(deviceId)) on your account that none of your devices approved. Skwod is ignoring it: nothing is sent to it and nothing from it is trusted. If you did not try to add a device, change your password.")
        case "device_linked":
            return SecurityAlert(title: "New device linked",
                message: "A device (\(device(deviceId))) was linked to your account and can now read your new messages. If that wasn't you, remove it and change your password.")
        case "new_device":
            return SecurityAlert(title: "\(who) added a device",
                message: "\(who) linked \(device(deviceId)), vouched for by a device of theirs you already trust. Their messages may now come from it, and yours reach it too.")
        case "unverified_contact_device":
            let verifiedNote = wasVerified ? " You had verified \(who): nothing at all is sent to them until you decide." : ""
            return SecurityAlert(title: "Unverified device for \(who)",
                message: "The server lists \(device(deviceId)) for \(who), but none of their devices vouched for it. Skwod sends it nothing and is holding anything it sends.\(verifiedNote) Only accept it if \(who) confirms — outside Skwod — that the device is theirs.",
                action: .acceptDevices(userId: userId, workspaceId: workspaceId))
        case "identity_changed":
            // Build 45: the same notice stands for a key that really changed and for one
            // somebody presented and the core refused (nothing held then, nothing to accept).
            // The wording fits both; the conversation's banner shows which (`IdentityHold`).
            let verifiedNote = wasVerified ? " You had verified \(who)." : ""
            return SecurityAlert(title: "\(who)'s security key changed",
                message: "Someone presented a different security key for \(who)'s device. Skwod has not trusted it: if messages to \(who) are on hold, your conversation lets you accept the new key or verify it — check with \(who) another way first. A new or reinstalled phone is the usual reason.\(verifiedNote)")
        case "channel_remap_refused":
            // `device_id` is the channel, `server_id` where this device has it confirmed.
            return SecurityAlert(title: "A channel was claimed by another skwod space",
                message: "The server listed a channel you already have under a different space. Skwod kept it where you first opened it, so a clear or deletion from the other space cannot touch it.")
        case "owner_change_refused":
            return SecurityAlert(title: "An invite claims a different owner",
                message: "An invite pointed to a space you are already in, but named a different host as its owner. Nothing was changed. If the space really has a new owner, leave it and join again with a fresh invite.")
        case "restored_devices_unconfirmed":
            return SecurityAlert(title: "Confirm your other devices",
                message: "This device was restored from a backup, which may be older than your account. Nothing is synced to the devices it lists until you confirm them: open Profile → Encryption → Devices and answer “Is this still your device?” for each one that is.")
        case "recovery_multiple":
            return SecurityAlert(title: "More than one install is trying to restore your account",
                message: "Several restore requests are waiting for the same device, each with its own code. Approve only the one whose code matches the screen in front of you and block the rest. If none of them is you, block them all and change your password.")
        case "backup_fetched":
            return SecurityAlert(title: "Your key backup was downloaded",
                message: "A sign-in that is not one of your devices downloaded your encrypted key backup. If this was not you, change your password and save a new recovery key.",
                action: .saveRecoveryKey(.manual))
        default:
            return nil
        }
    }

    /// A persistent system row (author "__system__") as the conversation shows it, or nil if
    /// `m` is not one this build knows. `name` turns a user id into what the reader calls them.
    ///
    /// Whether a row IS a system row is the core's word (`Message.isSystem`, recorded when the
    /// core wrote it) — never the text or the author: any member can send a message that
    /// merely starts like one, and that is shown as the plain message it is.
    static func systemMessage(_ m: Message, name: (String) -> String) -> ChatMessage? {
        let tag = "\u{2}skwod/sys|"
        guard m.isSystem, let content = m.content, content.hasPrefix(tag),
              let data = String(content.dropFirst(tag.count)).data(using: .utf8),
              let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let kind = o["kind"] as? String else { return nil }
        let userId = o["user_id"] as? String ?? ""
        let user = name(userId)
        let dev = device(o["device_id"] as? String ?? "")
        let by = (o["by_user_id"] as? String).flatMap { $0.isEmpty ? nil : name($0) }
        let wasVerified = (o["was_verified"] as? Bool) == true
        let text: String
        var row = SystemRow(kind: kind, userId: userId, icon: "lock.fill")
        switch kind {
        case "member_joined":
            // "Sam joined (let in by you)" — who approved them is the point of the row.
            text = by.map { "\(user) joined (let in by \($0 == "You" ? "you" : $0))." } ?? "\(user) joined."
            row.icon = "person.crop.circle.badge.checkmark"
        case "device_added", "new_device":
            text = "\(user) added a device (\(dev)). It was vouched for by a device of theirs you already trust."
            row.icon = "laptopcomputer.and.iphone"
        case "member_held":
            text = "\(user) is waiting to join. The server lists them as a member, but nobody you trust has let them in, so this device has not given them any keys."
            row.icon = "person.crop.circle.badge.questionmark"
            row.warning = true
            row.actionLabel = "Review"
        case "unverified_contact_device":
            text = "The server lists \(dev) for \(user), but none of their devices vouched for it. Nothing is sent to it and what it sends is held."
            row.icon = "exclamationmark.shield.fill"
            row.warning = true
            row.actionLabel = "View safety number"
        case "identity_changed":
            text = "\(user)'s safety number changed — their devices are different now."
                + (wasVerified ? " You had verified them, so sending is paused until you check." : "")
            row.icon = wasVerified ? "exclamationmark.shield.fill" : "shield.lefthalf.filled"
            row.warning = wasVerified
            row.actionLabel = "View safety number"
        default: return nil
        }
        return ChatMessage(id: m.messageId, author: "Skwod", authorId: nil, body: text, mine: false,
                           createdAt: m.createdAt, system: row)
    }

    /// The row shown in place of a message this device could not decrypt, or nil if `m` is not
    /// one (decided by the core's flag on the row, like a system row). It reads as a muted
    /// system line; the core replaces it when the author's device sends the message again.
    static func placeholderMessage(_ m: Message, name: (String) -> String) -> ChatMessage? {
        guard m.isUndecryptable, let info = undecryptablePlaceholder(message: m) else { return nil }
        let text = placeholderText(from: name(info.fromUserId), isFinal: info.isFinal)
        let row = SystemRow(kind: "undecryptable", userId: info.fromUserId, icon: "lock.slash")
        return ChatMessage(id: m.messageId, author: "Skwod", authorId: nil, body: text, mine: false,
                           createdAt: m.createdAt, system: row)
    }

    static func placeholderText(from who: String, isFinal: Bool) -> String {
        isFinal ? "Couldn't decrypt this message" : "Couldn't decrypt this message — asking \(who) to resend"
    }

    static let systemAuthor = "__system__"
}

/// Shown while we restore a persisted session + decrypt the local cache at launch.
private struct SplashView: View {
    var body: some View {
        ZStack {
            SkwodBackground()
            VStack(spacing: 18) {
                SkwodLogoTile(size: 96)
                ProgressView().tint(.skAccent)
            }
        }
    }
}

#if DEBUG
private struct DebugScreen: View {
    let name: String
    @EnvironmentObject private var app: AppState
    var body: some View {
        switch name {
        case "chess": NavigationStack { ChessView() }
        case "whiteboard": NavigationStack { WhiteboardView() }
        #if SKWOD_PAYWALL
        case "paywall": PaywallView()
        #endif
        #if os(macOS)
        case "host": HostWizardView()
        #endif
        case "auth": AuthView()
        case "pin": RegistrationPinSheet()
        case "resetpending": ResetPendingSheet().task { app.resetPending = "reset requested — it can complete in about 7 day(s), unless one of this account's devices cancels it" }
        case "devicelink": DeviceLinkSheet()
        case "devicesetup": DeviceSetupSheet()
        case "devices": DevicesView()
        case "erase": EraseDeviceSheet()
        case "recoverykey": RecoveryKeySheet(reason: .firstRun)
        case "recoverywaiting": RecoveryWaitingSheet()
        case "recoveryapprove": RecoveryApprovalSheet(request: RecoveryRequest(deviceId: "d", requestId: "r", fingerprint: "K7QF-29XM"))
        case "pinentry": PinEntrySheet(prompt: PinPrompt(purpose: .reset, attemptsLeft: 3))
        case "removed": DeviceStoppedView(state: .removed)
        case "superseded": DeviceStoppedView(state: .superseded)
        case "securityactivity": SecurityActivityView()
        case "reports": ReportsInboxView()
        case "applock": AppLockScreen(onUnlock: {})
        case "linkapprove": DeviceLinkApproveSheet()
        case "backup": KeyBackupSetupSheet {}
        case "chatpreview": ChatSurfacePreview()
        case "profile": ProfileView()
        case "feed": FeedView().environmentObject(ChatModel())
        case "music": MusicSearchSheet { _ in }
        case "story": StoryComposer { _, _ in }
        case "postcompose": PostComposer { _, _, _, _ in }
        default: MainView()
        }
    }
}

extension AppState {
    /// A mock workspace so authed screens render for screenshots (no network). DEBUG-only.
    func mockSession() {
        if current == nil {
            let w = Workspace(server: "https://demo.invalid", userId: "demo-user-01",
                              token: "demo", expiresAt: 0, name: "Demo")
            workspaces = [w]
            current = w
            deviceId = "demo-device-aa"
        }
    }
}
#endif
