import SwiftUI
#if os(macOS)
import AppKit
#endif

/// Which voice room the call sheet is open on.
struct CallTarget: Identifiable, Equatable {
    let serverId: String
    var id: String { serverId }
}

/// Who is speaking in the call THIS device is in (build 47): the green ring around a name in
/// the sidebar's voice list. Nobody else's call is known here — the server never sees speech.
@MainActor
final class VoiceSpeaking: ObservableObject {
    static let shared = VoiceSpeaking()
    /// The server whose call this is, and the user ids speaking in it.
    @Published private(set) var serverId = ""
    @Published private(set) var speaking: Set<String> = []

    func update(serverId: String, speaking: Set<String>) {
        if self.serverId != serverId { self.serverId = serverId }
        if self.speaking != speaking { self.speaking = speaking }
    }

    func isSpeaking(_ userId: String, in serverId: String) -> Bool { self.serverId == serverId && speaking.contains(userId) }
}

/// A call that is ringing: which server's voice room, and what to call it on screen.
struct IncomingCall: Equatable {
    let serverId: String
    let channelId: String
    /// "‹caller› · ‹server›" when both are known — built on this device from local names.
    let label: String
    /// The server's id for this ring; `ring_cancel` names it. "" from a server that has none.
    var ringId: String = ""
    /// Unix ms after which the ring is over (0 = the server did not say).
    var expiresAt: Int64 = 0
}

/// Ringing, on both platforms.
///
/// A ring reaches a running app as a `ring` event on its own user topic of the live connection
/// (`Realtime`), carrying the server and the voice channel. A sleeping iPhone gets an empty VoIP
/// push instead (`PushManager`), which says nothing about who or where.
///
/// - **iOS:** both are shown by CallKit (`CallManager`) and by nothing else — no notification, no
///   in-app banner — so the only thing that can appear over a locked screen is the system call UI.
/// - **macOS:** an in-app banner with a ring sound. Nothing is posted to Notification Center.
///
/// Answering opens the call sheet on the ring's server (`AppState.activeCall`).
@MainActor
final class CallCoordinator {
    static let shared = CallCoordinator()

    /// How long an unanswered call rings (same as Android).
    static let ringSeconds: TimeInterval = 45

    weak var app: AppState?
    /// The call that is up, if any. Ended here when the call sheet closes for any reason — the
    /// microphone must never outlive the call's UI, whatever SwiftUI does with the view.
    weak var session: CallSession?
    private var timeout: Task<Void, Never>?
    #if os(macOS)
    private var ringer: Task<Void, Never>?
    #endif

    private static var nowMs: Int64 { Int64(Date().timeIntervalSince1970 * 1000) }

    /// How much longer a ring that ends at `expiresAt` may ring: never past the server's
    /// deadline, never longer than `ringSeconds`. nil = it is already over.
    static func remaining(expiresAt: Int64) -> TimeInterval? {
        guard let deadline = clampedDeadline(expiresAt: expiresAt, now: nowMs) else { return nil }
        return Double(deadline - nowMs) / 1000
    }

    /// A ring's deadline as this app honours it. The server reports `expiresAt`, but a server
    /// can report anything: the deadline is clamped to now + the app's own `ringSeconds`, so no
    /// skwod can make its ring outlast — or outrank — another's by claiming a later one.
    /// nil = already over.
    static func clampedDeadline(expiresAt: Int64, now: Int64) -> Int64? {
        let cap = now + Int64(ringSeconds * 1000)
        guard expiresAt > 0 else { return cap }           // an older server that names no deadline
        guard expiresAt - now > 500 else { return nil }
        return min(expiresAt, cap)
    }

    /// What to do with the rings found after a call push.
    enum RingPick: Equatable {
        /// Nothing (credible) is ringing: take the call screen down.
        case none
        /// Exactly this workspace's ring: show / join it.
        case use(String)
        /// More than one skwod says it is ringing and nothing says which one sent the push —
        /// or picking would mean switching skwods under a user who has already answered: ask.
        case ask([String])
    }

    /// Choose among the workspaces that report a live ring.
    ///
    /// - `tagOwner`: the workspace that owns the push's `tag` (`.some(nil)` = the push carried
    ///   a tag no workspace of this device owns; `nil` = no tag at all: an older gateway).
    ///   With a tag, ONLY its owner may supply the ring — whatever any other skwod claims.
    /// - Without a tag: exactly one ring is used; several are never auto-joined (the old rule,
    ///   "the latest `expiresAt` wins", let one malicious skwod always win) — the user is asked.
    /// - After the user has answered, the app does not switch skwods on an untagged guess.
    static func pick(ringing: [String], tagOwner: String??, current: String?, answered: Bool) -> RingPick {
        if let tagOwner {
            guard let owner = tagOwner, ringing.contains(owner) else { return .none }
            return .use(owner)
        }
        let unique = Array(Set(ringing)).sorted()
        switch unique.count {
        case 0: return .none
        case 1: return (answered && unique[0] != current) ? .ask(unique) : .use(unique[0])
        default: return .ask(unique)
        }
    }

    /// A ring: a `ring` event on the live connection, or one `pendingRings` reported after a
    /// call push woke the app. A ring past its `expiresAt` is not shown at all.
    func ringReceived(serverId: String, channelId: String, from: String, ringId: String = "", expiresAt: Int64 = 0) {
        #if DEBUG
        CallDebug.lastRing = ["server_id": serverId, "channel_id": channelId, "from": from, "ring_id": ringId, "expires_at": expiresAt]
        #endif
        guard let app, !serverId.isEmpty, app.activeCall == nil else { return }   // already in a call
        guard app.incomingCall?.serverId != serverId else { return }               // already ringing
        guard Self.remaining(expiresAt: expiresAt) != nil else {
            #if DEBUG
            CallDebug.lastRing?["dropped"] = "expired"
            #endif
            return
        }
        Task {
            let label = await self.label(serverId: serverId, from: from)
            guard app.activeCall == nil, app.incomingCall?.serverId != serverId,
                  let seconds = Self.remaining(expiresAt: expiresAt) else { return }
            let call = IncomingCall(serverId: serverId, channelId: channelId, label: label, ringId: ringId, expiresAt: expiresAt)
            app.incomingCall = call
            #if os(iOS)
            // CallKit rings and keeps its own clock (to the ring's deadline); it reports back
            // through `ringEnded`.
            CallManager.shared.ringArrived(call, seconds: seconds)
            #else
            startRinger()
            timeout?.cancel()
            timeout = Task { [weak self] in
                try? await Task.sleep(for: .seconds(seconds))
                guard !Task.isCancelled, let self, self.app?.incomingCall == call else { return }
                self.ringEnded()
            }
            #endif
        }
    }

    /// `ring_cancel`: the caller hung up before anyone answered, or this account answered on
    /// another device. Stop ringing for that room — the banner on macOS, the CallKit call on iOS.
    /// A call this device has already answered is not touched.
    func ringCancelled(channelId: String, ringId: String?) {
        #if DEBUG
        CallDebug.lastRing = (CallDebug.lastRing ?? [:]).merging(["cancelled": ringId ?? channelId]) { _, new in new }
        #endif
        guard let app, let call = app.incomingCall else {
            #if os(iOS)
            // A push put "Skwod call" on screen and no `ring` has named it yet: it is over.
            CallManager.shared.ringCancelled()
            #endif
            return
        }
        if let ringId, !ringId.isEmpty, !call.ringId.isEmpty, ringId != call.ringId { return }
        if !channelId.isEmpty, !call.channelId.isEmpty, channelId != call.channelId { return }
        #if os(iOS)
        CallManager.shared.ringCancelled()
        #endif
        ringEnded()
    }

    /// A call push woke the app. The push says nothing (the gateway knows nothing), so ask —
    /// EVERY skwod this device is signed in to — what is ringing, and show that call: the right
    /// server, the right room, the caller's name. If nothing is ringing any more (cancelled or
    /// timed out before we woke), the call screen is taken down rather than guessed at.
    ///
    /// `tag` is the push's opaque wake tag, when the gateway passes one: it names the skwod that
    /// sent the wake, and then only that skwod's ring counts. Without one, a single ring is
    /// used and several are put to the user ("Who's calling?") — never auto-joined.
    func findRingAfterWake(tag: String? = nil, answered: Bool = false) async {
        // (Started by the push: the app's state may not be there yet.)
        for _ in 0..<40 where app == nil { try? await Task.sleep(for: .milliseconds(250)) }
        guard let app else { return }
        for _ in 0..<40 where app.restoring {
            try? await Task.sleep(for: .milliseconds(250))
        }
        if let tag { pushTag = tag }
        await app.connectionMayHaveChanged()
        // A muted skwod's ring is not one (the push could not say whose it was — no tag — and
        // rang; the in-band `ring` of a muted skwod is dropped the same way in `LiveSync`).
        let rings = await app.pendingRingsEverywhere().filter {
            Self.remaining(expiresAt: $0.ring.expiresAt) != nil && MuteCenter.shared.callsRing(workspaceId: $0.workspace.id)
        }
        var tagOwner: String?? = nil
        if let tag = pushTag, !tag.isEmpty { tagOwner = .some(app.workspaces.first(where: { $0.wakeTag == tag })?.id) }
        let choice = Self.pick(ringing: rings.map(\.workspace.id), tagOwner: tagOwner, current: app.current?.id, answered: answered)
        #if DEBUG
        CallDebug.lastRing = (CallDebug.lastRing ?? [:]).merging(["pick": "\(choice)", "candidates": rings.count]) { _, new in new }
        #endif
        switch choice {
        case .none:
            #if os(iOS)
            CallManager.shared.noRingFound()
            #endif
        case .use(let workspaceId):
            guard let found = rings.first(where: { $0.workspace.id == workspaceId }) else { return }
            await show(found)
        case .ask(let ids):
            // The generic call stays on the system call screen; the choice is made in the app.
            app.ringChoices = rings.filter { ids.contains($0.workspace.id) }.map {
                AppState.RingChoice(workspaceId: $0.workspace.id, skwod: $0.workspace.displayName, ring: $0.ring)
            }
        }
    }

    /// The tag of the call push being resolved (kept until the ring ends).
    private var pushTag: String?

    /// The user said which skwod is calling ("Who's calling?").
    func chose(_ choice: AppState.RingChoice) async {
        guard let app, let w = app.workspaces.first(where: { $0.id == choice.workspaceId }) else { return }
        app.ringChoices = []
        await show((workspace: w, ring: choice.ring))
    }

    private func show(_ found: (workspace: Workspace, ring: RingInfo)) async {
        guard let app else { return }
        if app.current?.id != found.workspace.id { await app.activate(found.workspace) }
        ringReceived(serverId: found.ring.serverId, channelId: found.ring.channelId, from: found.ring.fromUserId,
                     ringId: found.ring.ringId, expiresAt: found.ring.expiresAt)
    }

    /// "‹caller› · ‹server›", from what this device already knows. The caller's name is the
    /// contact book's (`ContactTrust.authorLabel`): the server's member list is only a claim,
    /// so a server cannot ring as "Mom" — and with app lock on or previews off the call screen
    /// (shown on the lock screen) names nobody (`CallLabel`).
    private func label(serverId: String, from: String) async -> String {
        // (With no client — behind the front, before the call is answered — by what is in memory.)
        guard let app, let workspaceId = app.current?.id else { return CallLabel.generic }
        let asked = app.bindTicket()
        let server = app.chatModel?.spaces.first(where: { $0.serverId == serverId })?.name
        var claimed: String?
        if let members = try? await app.client?.listMembers(serverId: serverId) {
            claimed = members.first(where: { $0.userId == from })?.username
        }
        // Asked of one skwod: never used to label a call after a switch to another.
        guard app.current?.id == workspaceId, asked.map(app.holds) ?? true else { return CallLabel.generic }
        let who = from.isEmpty ? nil : app.contacts.authorLabel(from, claimedName: claimed)
        #if os(iOS)
        // The system's call screen is outside the app's gate.
        return CallLabel.text(caller: who, server: server,
                              appLock: AppLock.shared.enabled || NotificationState.appLockEnabled,
                              previews: NotificationState.showPreviews)
        #else
        // The Mac's banner is drawn inside the app, behind its own lock.
        return CallLabel.text(caller: who, server: server, appLock: false, previews: true)
        #endif
    }

    /// The user picked up (macOS banner; on iOS the system call screen, via `CallManager`).
    func answer() {
        guard let app, let call = app.incomingCall else { return }
        open(serverId: call.serverId)
    }

    /// Open the call sheet on a server's voice room and stop anything that is ringing.
    func open(serverId: String) {
        stopRinging()
        app?.incomingCall = nil
        app?.activeCall = CallTarget(serverId: serverId)
    }

    /// The user declined, or the ring ran out.
    func ringEnded() {
        stopRinging()
        pushTag = nil
        app?.ringChoices = []
        app?.incomingCall = nil
        #if os(iOS)
        // The socket was brought back from behind for the ring alone (a `ring_cancel`).
        if let app, app.store.phase != .active, app.activeCall == nil, !CallManager.shared.isAnswered { app.realtime.suspend() }
        #endif
    }

    func decline() {
        #if os(iOS)
        CallManager.shared.declineRingingCall()
        #endif
        ringEnded()
    }

    /// The call view is up for this server: a ring for the same room is answered by being there.
    func joined(serverId: String) {
        guard app?.incomingCall?.serverId == serverId else { return }
        stopRinging()
        app?.incomingCall = nil
        #if os(iOS)
        CallManager.shared.joinedInApp()
        #endif
    }

    /// `AppState.activeCall` became nil: the call sheet is closing. Disconnect now rather than
    /// waiting for the view to be torn down.
    func callSheetClosed() {
        session?.end()
    }

    /// The call view went away (the user left, or the room ended).
    func callViewClosed() {
        #if os(iOS)
        CallManager.shared.endAnsweredCall()
        #endif
    }

    /// The system call UI ended the call: close the call sheet (which disconnects the room).
    func endedBySystem() {
        stopRinging()
        app?.incomingCall = nil
        app?.activeCall = nil
    }

    private func stopRinging() {
        timeout?.cancel()
        timeout = nil
        #if os(macOS)
        ringer?.cancel()
        ringer = nil
        #endif
    }

    #if os(macOS)
    /// The app's own ring (`skwod_ring.wav`, a little over two seconds), repeated while the banner is up. No notification is posted, so nothing
    /// about the call is shown anywhere but in the app's own window.
    private func startRinger() {
        ringer?.cancel()
        ringer = Task {
            while !Task.isCancelled {
                SoundPlayer.play(.ring)
                try? await Task.sleep(for: .seconds(2.6))
            }
        }
    }
    #endif
}

#if os(macOS)
/// macOS: the incoming-call banner at the top of the main window.
struct IncomingCallBanner: View {
    @EnvironmentObject private var app: AppState

    var body: some View {
        if let call = app.incomingCall {
            HStack(spacing: 12) {
                Image(systemName: "phone.arrow.down.left.fill").font(.title3).foregroundStyle(.green)
                VStack(alignment: .leading, spacing: 2) {
                    Text(call.label).font(.headline).foregroundStyle(.white).lineLimit(1)
                    Text("Incoming call · end-to-end encrypted").font(.caption).foregroundStyle(.white.opacity(0.65))
                }
                Spacer(minLength: 12)
                Button("Decline") { CallCoordinator.shared.decline() }
                    .buttonStyle(.glass).accessibilityIdentifier("call.decline")
                Button("Answer") { CallCoordinator.shared.answer() }
                    .buttonStyle(.glassProminent).tint(.green).accessibilityIdentifier("call.answer")
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            .glassEffect(.regular, in: .rect(cornerRadius: 18, style: .continuous))
            .frame(maxWidth: 520)
            .padding(.top, 10)
            .transition(.move(edge: .top).combined(with: .opacity))
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Incoming call from \(call.label)")
        }
    }
}
#endif
