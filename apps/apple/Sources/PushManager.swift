#if os(iOS)
import SwiftUI
import UIKit
import UserNotifications
import PushKit
import CallKit
import AVFoundation
import LiveKit

/// iOS push through the **blind push gateway** (docs/PUSH.md).
///
/// The publisher runs no chat infrastructure and a self-hosted skwod has no Apple push
/// credentials, so wake-ups go through a gateway that is told as little as possible:
///
/// 1. The app asks the gateway for a WAKE CREDENTIAL for this install (proving it holds the
///    APNs token by echoing a challenge the gateway pushes to it — or, renewing, with the
///    revoke token of a credential it holds), and registers with the skwod
///    it is connected to — `POST /api/push/register` with the gateway URL and that credential.
///    The skwod never gets the APNs or VoIP token, and the credential is revoked at the gateway
///    on sign-out and erase: a skwod that was left cannot keep waking this device.
///    (Build ≤ 45 skwods and gateways get the raw tokens, during the transition only —
///    `PushRegistration`.)
/// 2. When there is something for this device, the skwod calls `POST <gateway>/v1/wake` with only
///    `{ credential, kind }`. The gateway never learns which skwod, who sent what, or any content.
/// 3. `kind: "message"` → a generic "New message" alert with `mutable-content: 1`. The notification
///    service extension may rewrite it on-device (see `NotificationService.swift`); otherwise the
///    generic text stays. `kind: "call"` → a PushKit VoIP push, reported to CallKit immediately.
///
/// With no gateway configured in the build (`SKWOD_PUSH_GATEWAY` empty — the default), remote
/// push is off entirely: no permission prompt for remote notifications, no token registration.
/// Notifications then come from the live connection while the app is running.
@MainActor
final class PushManager: NSObject, ObservableObject {
    static let shared = PushManager()

    /// The gateway base URL baked into the build, if it is a usable https URL.
    static let gateway: String? = {
        guard var g = Bundle.main.object(forInfoDictionaryKey: "SkwodPushGateway") as? String else { return nil }
        g = g.trimmingCharacters(in: .whitespacesAndNewlines)
        while g.hasSuffix("/") { g.removeLast() }
        guard let comps = URLComponents(string: g), comps.scheme?.lowercased() == "https",
              let host = comps.host, !host.isEmpty, comps.user == nil, comps.password == nil else { return nil }
        return g
    }()

    static var enabled: Bool { gateway != nil }

    /// The APNs device token (hex), once the system hands it over.
    private var apnsToken: String?
    /// The PushKit VoIP token (hex).
    private var voipToken: String?
    /// workspace id → the registration last accepted by that skwod, to avoid duplicate uploads.
    private var registered: [String: String] = [:]
    private var voipRegistry: PKPushRegistry?
    /// The app state (which skwod is active, and its live base URL).
    private var app: AppState? { CallCoordinator.shared.app }

    /// Ask for notification permission and register for remote + VoIP push. Safe to call
    /// repeatedly. Does nothing when the build has no gateway.
    func start() {
        guard Self.enabled else { return }
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .notDetermined:
                center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
                    if granted { Task { @MainActor in UIApplication.shared.registerForRemoteNotifications() } }
                }
            case .denied:
                break
            default:
                Task { @MainActor in UIApplication.shared.registerForRemoteNotifications() }
            }
        }
        startVoIP()
    }

    /// Calls: at EVERY launch, and first of all (`didFinishLaunching`) — a VoIP push can be what
    /// started the process, with no skwod reached and no view up, and the system ends an app that
    /// has nobody to hand it to. Asks for nothing and sends nothing.
    func startVoIP() {
        guard Self.enabled else { return }
        if voipRegistry == nil {
            // Created on the main queue so the delegate callbacks arrive there.
            let registry = PKPushRegistry(queue: .main)
            registry.delegate = self
            registry.desiredPushTypes = [.voIP]
            voipRegistry = registry
            startedAt = Date()
        }
    }

    /// Called from the app delegate with the raw APNs token.
    func setToken(_ data: Data) {
        let token = Self.hex(data)
        // A challenge is bound to the token it was pushed to: one kept for another is useless.
        if let heldFor = challengeFor, heldFor != token {
            dropChallenge()
            challengeAskedAt = nil
        }
        apnsToken = token
        Task { await registerIfNeeded() }
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: registration (capability-bound wakes — the rules are `PushRegistration`)

    /// Wake credentials this install holds, by workspace id. A keychain item of this app's own.
    private static let credentialsAccount = "push-credentials"
    /// Revocations the gateway has not confirmed yet (sent again on the next occasion).
    private static let revocationsAccount = "push-revocations"

    private func loadCredentials() -> [String: PushRegistration.Stored] {
        guard let raw = Keychain.get(Self.credentialsAccount), let data = raw.data(using: .utf8) else { return [:] }
        return (try? JSONDecoder().decode([String: PushRegistration.Stored].self, from: data)) ?? [:]
    }

    private func saveCredentials(_ all: [String: PushRegistration.Stored]) {
        guard let data = try? JSONEncoder().encode(all), let raw = String(data: data, encoding: .utf8) else { return }
        Keychain.set(raw, for: Self.credentialsAccount)
    }

    private func pendingRevocations() -> [String] {
        guard let raw = Keychain.get(Self.revocationsAccount), let data = raw.data(using: .utf8) else { return [] }
        return (try? JSONDecoder().decode([String].self, from: data)) ?? []
    }

    private func setPendingRevocations(_ list: [String]) {
        guard let data = try? JSONEncoder().encode(Array(list.suffix(64))), let raw = String(data: data, encoding: .utf8) else { return }
        Keychain.set(raw, for: Self.revocationsAccount)
    }

    /// The latest registration challenge a silent push brought (single use, short-lived).
    private static let challengeAccount = "push-challenge"
    /// The registration ids (`skwod_cred`) this install made itself, in the shared defaults so
    /// the PushKit handler and the notification extension can read them synchronously. Not
    /// secret: every wake carries one.
    private nonisolated static let registrationIdsKey = WakeOrigin.registrationIdsKey

    private struct HeldChallenge: Codable {
        var value: String
        var at: Int64
        /// The APNs token it was pushed to, when that was known.
        var apns: String?
    }

    /// The ids this install registered itself and that have not run out. Callable from the
    /// PushKit callback (no actor, no await).
    nonisolated static func knownRegistrationIds() -> Set<String> {
        WakeOrigin.knownIds(SharedContainer.defaults.data(forKey: registrationIdsKey), now: Int64(Date().timeIntervalSince1970))
    }

    private nonisolated static func registrationIds() -> [String: PushRegistration.KnownId] {
        guard let data = SharedContainer.defaults.data(forKey: registrationIdsKey) else { return [:] }
        return (try? JSONDecoder().decode([String: PushRegistration.KnownId].self, from: data)) ?? [:]
    }

    private static func updateRegistrationIds(_ change: (inout [String: PushRegistration.KnownId]) -> Void) {
        var ids = PushRegistration.pruned(registrationIds(), now: nowS)
        change(&ids)
        if ids.isEmpty {
            SharedContainer.defaults.removeObject(forKey: registrationIdsKey)
        } else if let data = try? JSONEncoder().encode(ids) {
            SharedContainer.defaults.set(data, forKey: registrationIdsKey)
        }
    }

    /// Keep the challenge a silent push brought — in the keychain too: it usually arrives
    /// while the app is in the background and may be needed by the next launch.
    private func holdChallenge(_ value: String) {
        let held = HeldChallenge(value: value, at: Self.nowS, apns: apnsToken)
        challenge = .received(value, at: held.at)
        challengeFor = held.apns
        if let data = try? JSONEncoder().encode(held), let raw = String(data: data, encoding: .utf8) {
            // Readable while locked: it tends to arrive, and to be wanted, in the background.
            Keychain.set(raw, for: Self.challengeAccount, accessibility: .afterFirstUnlock)
        }
    }

    /// The kept challenge is spent, or no good any more.
    private func dropChallenge() {
        if case .received = challenge { Keychain.delete(Self.challengeAccount) }
        challenge = .none
        challengeFor = nil
    }

    /// Once per launch: a challenge kept by an earlier launch, if it is still good.
    private func restoreChallenge() {
        guard !challengeRestored else { return }
        challengeRestored = true
        guard case .none = challenge, let raw = Keychain.get(Self.challengeAccount), let data = raw.data(using: .utf8),
              let held = try? JSONDecoder().decode(HeldChallenge.self, from: data) else { return }
        guard PushRegistration.challengeUsable(receivedAt: held.at, now: Self.nowS),
              held.apns == nil || apnsToken == nil || held.apns == apnsToken else {
            Keychain.delete(Self.challengeAccount)
            return
        }
        challenge = .received(held.value, at: held.at)
        challengeFor = held.apns
    }

    private var gatewaySupport: PushRegistration.Support = .unknown
    /// workspace id → whether that skwod takes `wake_credential` (learned this launch).
    private var skwodSupport: [String: PushRegistration.Support] = [:]
    /// Skwods (workspace ids) that refused the wake-credential shape: a host older than build
    /// 45. They get no push registration at all (audit M1) — the user is told that host needs
    /// updating, and its notifications arrive only while Skwod is open.
    @Published private(set) var hostNeedsUpdate: Set<String> = []
    private var challenge: PushRegistration.Challenge = .none
    private var challengeFailures = 0
    private var lastChallengeFailure: Int64 = 0
    /// The APNs token the kept challenge was pushed to, when known.
    private var challengeFor: String?
    private var challengeRestored = false
    /// When the last challenge was asked for and has not arrived (the gateway sends no other
    /// while that one is alive).
    private var challengeAskedAt: Int64?
    /// The gateway refused a held revoke token as proof: a challenge instead.
    private var revokeProofRefused = false
    /// A "cut off every skwod" in flight: single revocations wait for it.
    private var revokeAllTask: Task<Void, Never>?
    /// workspace id → the revoke token of the credential a rotation is replacing.
    private var replaced: [String: String] = [:]
    private var registering = false
    private var startedAt: Date?
    /// A "cut off every skwod" is waiting for its challenge.
    private var revokeAllPending = false

    private static var nowS: Int64 { Int64(Date().timeIntervalSince1970) }

    /// POST a small JSON body; the status, and the decoded object when there is one.
    private static func post(_ url: URL, body: [String: Any], bearer: String? = nil) async -> (status: Int?, json: [String: Any]?) {
        var req = URLRequest(url: url, timeoutInterval: 15)
        req.httpMethod = "POST"
        if let bearer { req.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization") }
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        // (`RawSink`, checked as it is sent: never to a retired or suspect front.)
        guard let (data, resp) = try? await RawSink.data(for: req),
              let code = (resp as? HTTPURLResponse)?.statusCode else { return (nil, nil) }
        return (code, (try? JSONSerialization.jsonObject(with: data)) as? [String: Any])
    }

    private static func gatewayURL(_ path: String) -> URL? {
        guard let gateway else { return nil }
        return URL(string: gateway)?.appendingPathComponent(path)
    }

    /// Register this install with the ACTIVE skwod. Called after sign-in, when the active skwod
    /// changes, when a token arrives and when a challenge arrives. The skwod is given a wake
    /// credential minted by the gateway for this install — never the APNs or VoIP token — unless
    /// the transition fallback applies (`PushRegistration.allowLegacyRawPushRegistration`).
    func registerIfNeeded() async {
        guard Self.gateway != nil, let app, let apns = apnsToken,
              let w = app.current, let session = app.session,
              let base = URL(string: app.serverURL), !app.serverURL.isEmpty,
              let topic = Bundle.main.bundleIdentifier, !registering else { return }
        // The VoIP token usually follows the APNs token within moments, and a credential is
        // minted for both: give it a few seconds rather than spend a second challenge on it.
        if voipToken == nil, let startedAt, Date().timeIntervalSince(startedAt) < 5 {
            Task { try? await Task.sleep(nanoseconds: 5_000_000_000); await self.registerIfNeeded() }
            return
        }
        registering = true
        defer { registering = false }
        await flushRevocations()
        restoreChallenge()
        // A per-skwod random tag: sealed into the credential by the gateway and returned in the
        // wake, so the app knows which skwod a contentless push came from.
        let wakeTag = app.ensureWakeTag()
        let binding = PushRegistration.binding(apns: apns, voip: voipToken, tag: wakeTag)
        let account = "\(w.id)|\(session.userId)"
        for _ in 0..<8 {
            let stored = loadCredentials()[w.id]
            let input = PushRegistration.Input(
                now: Self.nowS, apns: apns, binding: binding, account: account, stored: stored, accepted: registered[w.id],
                gateway: gatewaySupport, skwod: skwodSupport[w.id] ?? .unknown, challenge: challenge,
                challengeFailures: challengeFailures, lastChallengeFailure: lastChallengeFailure,
                revokeProofRefused: revokeProofRefused)
            switch PushRegistration.next(input) {
            case .nothing, .wait, .unavailable:
                return
            case .requestChallenge:
                guard let url = Self.gatewayURL("v1/challenge") else { return }
                switch PushRegistration.gatewayAnswer(status: await Self.post(url, body: ["apns_token": apns, "topic": topic]).status) {
                case .ok:
                    gatewaySupport = .yes
                    challenge = .requested(at: Self.nowS)
                    challengeAskedAt = Self.nowS
                    // Look again when the wait is over (the push itself calls in earlier).
                    let wait = UInt64(PushRegistration.challengeTimeout + 1) * 1_000_000_000
                    Task { try? await Task.sleep(nanoseconds: wait); await self.registerIfNeeded() }
                    return
                case .unsupported:
                    gatewaySupport = .no
                case .challengeRejected, .forbidden, .later:
                    challengeFailures += 1
                    lastChallengeFailure = Self.nowS
                    return
                }
            case .challengeTimedOut:
                challenge = .none
                challengeFailures += 1
                lastChallengeFailure = Self.nowS
                Log.push.info("no registration challenge arrived")
            case .cutOffOldToken(let old, let token):
                // The APNs token changed. Everything minted for the old one is ended at the
                // gateway with a revoke token held for it — best effort: whatever the answer,
                // what was held for the old token is forgotten and the new pair is registered
                // with a challenge. The old revoke token is never offered for the new token.
                var cutOff = false
                if let url = Self.gatewayURL("v1/revoke-all") {
                    let body = PushRegistration.revokeAllBody(apns: old, topic: topic, proof: .revoke(token))
                    cutOff = PushRegistration.gatewayAnswer(status: await Self.post(url, body: body).status) == .ok
                }
                var all = loadCredentials()
                var dropped: [String: PushRegistration.Stored] = [:]
                for (id, held) in all where held.issuedFor == old { dropped[id] = held; all[id] = nil }
                saveCredentials(all)
                for id in dropped.keys { registered[id] = nil }
                let workspaces = Set(dropped.keys)
                Self.updateRegistrationIds { ids in ids = ids.filter { !workspaces.contains($0.value.workspace) } }
                if !cutOff {
                    // Not confirmed: end them one by one, retried until the gateway has it.
                    var pending = pendingRevocations()
                    for t in dropped.values.map(\.revoke) where !t.isEmpty && !pending.contains(t) { pending.append(t) }
                    setPendingRevocations(pending)
                }
                Log.push.info("the APNs token changed: old registrations cut off (\(cutOff ? "confirmed" : "queued", privacy: .public))")
            case .mint(let proof):
                guard let url = Self.gatewayURL("v1/register") else { return }
                // Exactly one proof: a pushed challenge (single use), or a held revoke token.
                let body = PushRegistration.registerBody(apns: apns, voip: voipToken, topic: topic, tag: wakeTag, proof: proof)
                let answer = await Self.post(url, body: body)
                let outcome = PushRegistration.gatewayAnswer(status: answer.status)
                // The challenge is spent once the gateway has answered about it (taken or
                // refused). With no answer, or "later", it is still the only one the gateway
                // will send for a while: kept. (Unless a newer one arrived meanwhile.)
                if case .challenge(let sent) = proof, outcome == .ok || outcome == .forbidden || outcome == .challengeRejected,
                   case .received(let kept, _) = challenge, kept == sent {
                    dropChallenge()
                }
                switch outcome {
                case .ok:
                    guard let credential = answer.json?["credential"] as? String, !credential.isEmpty,
                          let revoke = answer.json?["revoke"] as? String, !revoke.isEmpty,
                          let expires = (answer.json?["expires_at"] as? NSNumber)?.int64Value else { return }
                    gatewaySupport = .yes
                    let id = (answer.json?["id"] as? String).flatMap { $0.isEmpty ? nil : $0 }
                    let fresh = PushRegistration.Stored(credential: credential, revoke: revoke, expiresAt: expires, issuedAt: Self.nowS,
                                                        boundTo: binding, id: id, apns: apns)
                    if let old = PushRegistration.toRevokeAfterRotation(old: stored, new: fresh) { replaced[w.id] = old }
                    var all = loadCredentials()
                    all[w.id] = fresh
                    saveCredentials(all)
                    // Its wakes are ours. (The id of the credential it replaces stays known
                    // until this skwod has the new one: it still wakes with the old.)
                    if let id {
                        let known = PushRegistration.KnownId(workspace: w.id, expiresAt: expires)
                        Self.updateRegistrationIds { $0[id] = known }
                    }
                    challengeFailures = 0
                    if case .challenge = proof { revokeProofRefused = false }
                case .unsupported:
                    gatewaySupport = .no
                case .forbidden, .challengeRejected, .later:
                    if PushRegistration.fallsBackToChallenge(proof: proof, status: answer.status) {
                        // The held revoke token was not taken as proof: on to a challenge.
                        revokeProofRefused = true
                        continue
                    }
                    // A refused challenge counts against the silent-push path; a gateway
                    // that could not answer does not.
                    if case .challenge = proof, outcome != .later {
                        challengeFailures += 1
                        lastChallengeFailure = Self.nowS
                    }
                    return
                }
            case .registerCredential(let credential):
                var body: [String: Any] = ["provider": "gateway", "gateway": Self.gateway ?? "", "wake_credential": credential]
                if let deviceId = app.deviceId, !deviceId.isEmpty { body["device_id"] = deviceId }
                let status = await Self.post(base.appendingPathComponent("api/push/register"), body: body, bearer: session.token).status
                switch PushRegistration.skwodAnswer(status: status, credentialShape: true) {
                case .accepted:
                    registered[w.id] = PushRegistration.accepted(account: account, binding: binding, credential: credential)
                    Log.push.info("registered with the active skwod (wake credential)")
                    hostNeedsUpdate.remove(w.id)
                    // The credential this one replaced is ended only now, so there was no gap.
                    let keep = stored?.id
                    let workspace = w.id
                    Self.updateRegistrationIds { ids in ids = ids.filter { $0.value.workspace != workspace || $0.key == keep } }
                    if let old = replaced.removeValue(forKey: w.id) { await revoke([old]) }
                    return
                case .credentialUnknown:
                    skwodSupport[w.id] = .no
                    if !PushRegistration.allowLegacyRawPushRegistration {
                        // No raw tokens for it (audit M1). Ask it to drop any it holds from an
                        // earlier build — best effort: a host that will not is ignored anyway,
                        // its raw wakes are never rung or followed (`WakeOrigin`).
                        hostNeedsUpdate.insert(w.id)
                        Log.push.info("this skwod does not take wake credentials: no push for it until it is updated")
                        _ = await Self.post(base.appendingPathComponent("api/push/unregister"), body: [:], bearer: session.token)
                    }
                case .credentialGone:
                    var all = loadCredentials()
                    all[w.id] = nil
                    saveCredentials(all)
                    if let gone = stored?.id { Self.updateRegistrationIds { $0[gone] = nil } }
                case .later:
                    // Includes 403 for an account still in the waiting room: nothing is
                    // remembered, so the next call tries again.
                    Log.push.info("push registration not accepted yet (status \(status ?? 0, privacy: .public))")
                    return
                }
            case .registerRaw:
                // TRANSITION (build ≤ 45 skwod or gateway): the old contract, raw tokens.
                var body: [String: Any] = [
                    "provider": "gateway",
                    "gateway": Self.gateway ?? "",
                    "apns_token": apns,
                    "voip_token": voipToken.map { $0 as Any } ?? NSNull(),
                    "topic": topic,
                ]
                if let wakeTag { body["wake_tag"] = wakeTag }
                // Which device this registration is for: removing another device of the
                // account must not take this one's push with it (push C5).
                if let deviceId = app.deviceId, !deviceId.isEmpty { body["device_id"] = deviceId }
                let status = await Self.post(base.appendingPathComponent("api/push/register"), body: body, bearer: session.token).status
                if PushRegistration.skwodAnswer(status: status, credentialShape: false) == .accepted {
                    registered[w.id] = PushRegistration.accepted(account: account, binding: binding, credential: nil)
                    Log.push.info("registered with the active skwod (legacy raw tokens)")
                } else {
                    Log.push.info("push registration not accepted (status \(status ?? 0, privacy: .public))")
                }
                return
            }
        }
    }

    /// The gateway's silent push with a registration challenge (app delegate). Nothing is shown.
    /// The latest one is KEPT whether or not this install asked for it: while one is unused the
    /// gateway pushes no other, so a challenge someone else caused is the only one there is.
    func challengeArrived(_ value: String) {
        guard !value.isEmpty, value.count <= 512 else { return }
        challengeAskedAt = nil
        if revokeAllPending {
            revokeAllPending = false
            Task { await self.sendRevokeAll(challenge: value) }
            return
        }
        holdChallenge(value)
        Task { await registerIfNeeded() }
    }

    // MARK: revocation

    /// End these credentials at the gateway. What could not be confirmed is kept and sent again.
    private func revoke(_ tokens: [String]) async {
        // A revoke-all that is using one of these tokens as its proof goes first.
        await revokeAllTask?.value
        var pending = pendingRevocations()
        for t in tokens where !t.isEmpty && !pending.contains(t) { pending.append(t) }
        setPendingRevocations(pending)
        await flushRevocations()
    }

    private func flushRevocations() async {
        let pending = pendingRevocations()
        guard !pending.isEmpty, let url = Self.gatewayURL("v1/revoke") else { return }
        var left: [String] = []
        for token in pending {
            let status = await Self.post(url, body: ["revoke": token]).status
            // Done, or nothing the gateway will ever accept (malformed, expired): drop it.
            // Unreachable, rationed or a gateway without the route yet: keep it for later.
            if let status, (200...299).contains(status) || status == 400 || status == 410 { continue }
            left.append(token)
        }
        // Whatever was queued meanwhile stays queued.
        setPendingRevocations(left + pendingRevocations().filter { !pending.contains($0) })
    }

    /// This install stops being wakeable by `w` — sign-out, erase, forgetting the skwod. The
    /// credential is revoked at the gateway (so a skwod that keeps it gains nothing) and the
    /// skwod is asked to drop its registration while the session still works. Best effort and
    /// never waited for; a revocation that did not get through is retried later.
    func release(_ w: Workspace, base: String?) {
        registered[w.id] = nil
        skwodSupport[w.id] = nil
        hostNeedsUpdate.remove(w.id)
        var all = loadCredentials()
        let stored = all.removeValue(forKey: w.id)
        if stored != nil { saveCredentials(all) }
        // Its wakes are no longer ours, from this moment: a ring through it is ended unseen.
        let workspace = w.id
        Self.updateRegistrationIds { ids in ids = ids.filter { $0.value.workspace != workspace } }
        var tokens = [stored?.revoke ?? ""]
        if let old = replaced.removeValue(forKey: w.id) { tokens.append(old) }
        let live = (base?.isEmpty == false) ? base : nil
        let root = live ?? ((!w.isP2P && w.server.hasPrefix("https://")) ? w.server : nil)
        // A p2p skwod is told over its member connection, before the session ends
        // (`AppState.endSession`): nothing with the session goes through the loopback port.
        let token = (root.map { isFrontBase(baseUrl: $0) || isFrontSuspect(baseUrl: $0) } ?? false) ? "" : w.token
        Task {
            if !token.isEmpty, let root, let url = URL(string: root)?.appendingPathComponent("api/push/unregister") {
                _ = await Self.post(url, body: [:], bearer: token)
            }
            await self.revoke(tokens)
        }
    }

    /// Cut off EVERY registration of this device at the gateway — the ones this install knows
    /// and any it does not (a skwod that minted its own from a token it was once given). Used
    /// by the factory reset, BEFORE the per-skwod data goes: a revoke token this install holds
    /// for the current APNs token is the proof, so nothing has to be waited for while erasing.
    /// With none held, or if the gateway refuses it (403, 400), a challenge is used instead —
    /// one already kept, else one asked for, and the call completes when the silent push
    /// arrives. Every skwod still signed in has to register again after.
    func revokeEverything() {
        // Nothing is ours any more, whether or not the gateway can be told.
        registered = [:]
        Self.updateRegistrationIds { $0 = [:] }
        guard let apns = apnsToken, let topic = Bundle.main.bundleIdentifier, let url = Self.gatewayURL("v1/revoke-all") else { return }
        restoreChallenge()
        let proof = PushRegistration.revokeAllProof(held: Array(loadCredentials().values), apns: apns, now: Self.nowS)
        revokeAllTask = Task {
            if let proof {
                let status = await Self.post(url, body: PushRegistration.revokeAllBody(apns: apns, topic: topic, proof: proof)).status
                Log.push.info("revoke-all answered \(status ?? 0, privacy: .public)")
                guard PushRegistration.fallsBackToChallenge(proof: proof, status: status) else { return }
            }
            // Nothing held, or it was not taken: prove possession with a pushed challenge —
            // the one already kept, if it is still good.
            if case .received(let value, let at) = self.challenge, PushRegistration.challengeUsable(receivedAt: at, now: Self.nowS) {
                self.dropChallenge()
                await self.sendRevokeAll(challenge: value)
                return
            }
            self.revokeAllPending = true
            // Not asked for again while one is already on its way.
            if PushRegistration.challengeStillComing(askedAt: self.challengeAskedAt, now: Self.nowS) { return }
            guard let ask = Self.gatewayURL("v1/challenge") else { return }
            if PushRegistration.gatewayAnswer(status: await Self.post(ask, body: ["apns_token": apns, "topic": topic]).status) == .ok {
                self.challenge = .none
                self.challengeAskedAt = Self.nowS
            } else {
                self.revokeAllPending = false
            }
        }
    }

    private func sendRevokeAll(challenge value: String) async {
        guard let apns = apnsToken, let topic = Bundle.main.bundleIdentifier, let url = Self.gatewayURL("v1/revoke-all") else { return }
        let status = await Self.post(url, body: PushRegistration.revokeAllBody(apns: apns, topic: topic, proof: .challenge(value))).status
        Log.push.info("revoke-all answered \(status ?? 0, privacy: .public)")
    }

    /// Forget what the skwods accepted this launch (sign-out of everything).
    func reset() { registered = [:]; skwodSupport = [:]; hostNeedsUpdate = [] }
}

extension PushManager: PKPushRegistryDelegate {
    nonisolated func pushRegistry(_ registry: PKPushRegistry, didUpdate pushCredentials: PKPushCredentials, for type: PKPushType) {
        guard type == .voIP else { return }
        let token = pushCredentials.token.map { String(format: "%02x", $0) }.joined()
        Task { @MainActor in
            self.voipToken = token
            await self.registerIfNeeded()
        }
    }

    nonisolated func pushRegistry(_ registry: PKPushRegistry, didInvalidatePushTokenFor type: PKPushType) {
        Task { @MainActor in self.voipToken = nil }
    }

    /// A VoIP push. Apple requires that EVERY one is reported to CallKit before this method
    /// returns control (an app that doesn't is killed and eventually stops receiving them), so the
    /// report happens first and synchronously; connecting comes after.
    nonisolated func pushRegistry(_ registry: PKPushRegistry, didReceiveIncomingPushWith payload: PKPushPayload,
                                  for type: PKPushType, completion: @escaping () -> Void) {
        guard type == .voIP else { completion(); return }
        // What a wake carries: the id of the registration it was sent for (`skwod_cred`; a raw
        // wake — a host holding an earlier build's tokens — has none) and the opaque tag of the
        // skwod that asked. Only a registration of this install rings (audit M1).
        let wake = payload.dictionaryPayload
        let signedInTags = WorkspaceStore.load().filter { !$0.isSignedOut }.map(\.wakeTag)
        switch PushRegistration.callWake(credentialId: wake["skwod_cred"], known: PushManager.knownRegistrationIds(),
                                         tag: wake["tag"] as? String, signedInTags: signedInTags) {
        case .ring:
            CallManager.shared.reportIncomingCall(tag: wake["tag"] as? String, completion: completion)
        case .endImmediately:
            // Not a registration of this install — a skwod that was left, a credential someone
            // else minted for this device's VoIP token, or a raw token kept from an earlier
            // build. Reported, as it must be, and over.
            CallManager.shared.reportRefusedCall(completion: completion)
        }
    }
}

/// CallKit front for every incoming call on iOS.
///
/// A call can be announced two ways, and both end up on the system call screen:
///
/// - **VoIP push** (the app was asleep). The push carries nothing — the gateway knows nothing — so
///   the call is reported at once as "skwod call" and the app reconnects while the phone rings.
/// - **`ring` event** on the live connection (the app is running). It names the server and the
///   voice channel, so the call screen shows who is calling, and answering joins that room.
///
/// A push names no room (the wake contract has none), so after one the app asks every skwod it
/// is signed in to what is ringing (`pendingRings`) and shows — or, if the user has answered
/// already, joins — exactly that call. If nothing is ringing any more the call is ended; the
/// app never guesses a room. A `ring_cancel` event ends the ringing call.
///
/// Calls are kept out of the system Recents list — that list syncs to iCloud. Nothing else about
/// a call is ever posted (no notification), so the lock screen shows only what CallKit shows.
final class CallManager: NSObject, CXProviderDelegate {
    static let shared = CallManager()

    private let provider: CXProvider
    private let controller = CXCallController()
    /// The call CallKit currently knows about (ringing or answered).
    private var current: UUID?
    /// Which room `current` is for, once a `ring` event has said so.
    private var ring: IncomingCall?
    private var answered = false
    /// A call this app answered is up.
    var isAnswered: Bool { current != nil && answered }
    private var timeout: DispatchWorkItem?
    private var roomWait: Task<Void, Never>?

    private override init() {
        let config = CXProviderConfiguration()
        config.supportsVideo = true
        config.maximumCallGroups = 1
        config.maximumCallsPerCallGroup = 1
        config.supportedHandleTypes = [.generic]
        config.includesCallsInRecents = false
        provider = CXProvider(configuration: config)
        super.init()
        provider.setDelegate(self, queue: .main)
    }

    private func update(label: String?) -> CXCallUpdate {
        let update = CXCallUpdate()
        update.remoteHandle = CXHandle(type: .generic, value: "Skwod")
        update.localizedCallerName = label ?? "Skwod call"
        update.hasVideo = false
        update.supportsHolding = false
        update.supportsGrouping = false
        update.supportsUngrouping = false
        update.supportsDTMF = false
        return update
    }

    /// A VoIP push: report the call NOW (it must happen in the PushKit callback), then wake the
    /// connection. If a `ring` event already put this call on screen, the same call is reported
    /// again — CallKit refuses the duplicate, and the push still counts as reported.
    ///
    /// A push for a MUTED skwod (`pushIsMuted`) is still reported — PushKit demands it of every
    /// VoIP push, whatever the app thinks of the call — and the call is ended in the same
    /// breath, as unanswered: it is never armed, never looked up, never joins anything, and
    /// leaves nothing in Recents. LIMITATION: iOS gives an app no way to take a VoIP push
    /// without presenting a call, so between the report and the end the system call screen
    /// (a banner on an unlocked phone) can flash, and the first instant of the ringtone or a
    /// vibration can be felt; how visible that is is the system's doing and differs between
    /// iOS versions. A skwod's server never learns of a mute (it stays on this device), so
    /// it cannot hold the push back either. Not sending the VoIP token to a muted skwod would
    /// avoid the flash but tell that skwod about the mute, and lose calls for the minutes it
    /// takes to register again — not done.
    func reportIncomingCall(tag: String? = nil, completion: @escaping () -> Void) {
        // Only a push that would START a call screen: one that is ringing or answered already
        // is somebody the user is hearing from, and is never ended by a muted skwod's push.
        if current == nil, Self.pushIsMuted(tag: tag) {
            let uuid = UUID()
            provider.reportNewIncomingCall(with: uuid, update: update(label: nil)) { [weak self] error in
                defer { completion() }
                self?.note("pushMuted", error == nil)
                guard error == nil else { return }
                self?.provider.reportCall(with: uuid, endedAt: nil, reason: .unanswered)
            }
            return
        }
        let isNew = current == nil
        let uuid = current ?? UUID()
        current = uuid
        provider.reportNewIncomingCall(with: uuid, update: update(label: ring?.label)) { [weak self] error in
            defer { completion() }
            guard let self, isNew else { return }
            self.note("pushReported", error == nil)
            guard error == nil else { self.clear(); return }
            self.armTimeout(uuid)
            // Bring the transport back while the phone rings, and find out WHICH call this is:
            // ask every signed-in skwod what is ringing.
            Task { @MainActor in await CallCoordinator.shared.findRingAfterWake(tag: tag) }
        }
    }

    /// Is a call push with this wake tag for muted skwods only (`MuteList.wakeIsMuted`)? Read
    /// straight from the Keychain, as the notification extension does — this runs inside the
    /// PushKit callback, possibly in a process the push just launched, on a locked phone: the
    /// workspace list and a skwod's own mute are the items readable there (`KeyAccess`).
    static func pushIsMuted(tag: String?, now: TimeInterval = Date().timeIntervalSince1970) -> Bool {
        let signedIn = WorkspaceStore.load().filter { !$0.isSignedOut }
        return MuteList.wakeIsMuted(tag: tag, signedIn: signedIn.map { ($0.id, $0.wakeTag) },
                                    skwodIsMuted: { !MuteStore.load(workspaceId: $0).callsRing(now: now) })
    }

    /// A VoIP push that is not for a registration of this install. PushKit still requires a
    /// CallKit report, so a call of its own is reported and ended (`.failed`) the moment CallKit
    /// has it: no timeout, no connecting, nothing of ours on screen. It never becomes `current`,
    /// so a real call that is ringing or answered is untouched — and an answer tapped in the
    /// instant it is visible is refused (see the delegate).
    func reportRefusedCall(completion: @escaping () -> Void) {
        let uuid = UUID()
        provider.reportNewIncomingCall(with: uuid, update: update(label: nil)) { [weak self] error in
            if error == nil { self?.provider.reportCall(with: uuid, endedAt: nil, reason: .failed) }
            self?.note("pushRefused", error == nil)
            completion()
        }
    }

    /// `ring_cancel`: the caller gave up (or this account answered elsewhere). End the ringing
    /// call on the system call screen. An answered call is left alone.
    func ringCancelled() {
        guard let uuid = current, !answered else { return }
        provider.reportCall(with: uuid, endedAt: nil, reason: .remoteEnded)
        note("ringCancelled", true)
        clear()
    }

    /// A push announced a call, but no skwod reports a ring any more: it was cancelled or ran
    /// out before this device woke. Take the call screen down (or fail the answer) — no guessing.
    func noRingFound() {
        // An in-band `ring` already named this call: that one stands.
        guard let uuid = current, ring == nil else { return }
        provider.reportCall(with: uuid, endedAt: nil, reason: answered ? .failed : .remoteEnded)
        note("noRingFound", true)
        clear()
        Task { @MainActor in CallCoordinator.shared.ringEnded() }
    }

    /// A `ring` event named the room. Either this is the first we hear of the call (show it), or
    /// a push already put "skwod call" on screen (fill in who is calling — and if the user has
    /// answered meanwhile, join now).
    @MainActor
    func ringArrived(_ call: IncomingCall, seconds: TimeInterval = CallCoordinator.ringSeconds) {
        ring = call
        if let uuid = current {
            provider.reportCall(with: uuid, updated: update(label: call.label))
            if answered { openAnsweredCall() } else { armTimeout(uuid, seconds: seconds) }
            return
        }
        let uuid = UUID()
        current = uuid
        provider.reportNewIncomingCall(with: uuid, update: update(label: call.label)) { [weak self] error in
            guard let self else { return }
            self.note("ringReported", error == nil)
            if let error {
                // Focus / Do Not Disturb, or the system refused: nothing rings.
                self.note("ringError", (error as NSError).code)
                self.clear()
                Task { @MainActor in CallCoordinator.shared.ringEnded() }
                return
            }
            self.armTimeout(uuid, seconds: seconds)
            #if DEBUG
            // The Simulator has no system call screen and ends an incoming call about a second
            // after accepting it; an end-to-end run can ask for the answer right away instead.
            if E2E.env("SKWOD_E2E_AUTOANSWER") == "1" { self.debugAnswer() }
            #endif
        }
    }

    private func armTimeout(_ uuid: UUID, seconds: TimeInterval = CallCoordinator.ringSeconds) {
        timeout?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.current == uuid, !self.answered else { return }
            self.provider.reportCall(with: uuid, endedAt: nil, reason: .unanswered)
            self.clear()
            Task { @MainActor in CallCoordinator.shared.ringEnded() }
        }
        timeout = work
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds, execute: work)
    }

    private func clear() {
        timeout?.cancel()
        timeout = nil
        roomWait?.cancel()
        roomWait = nil
        current = nil
        ring = nil
        answered = false
        DispatchQueue.main.async { MainActor.assumeIsolated { CallCoordinator.shared.app?.store.callMayHaveEnded() } }
        // Whatever happened, calls started from inside the app must be able to use audio.
        try? AudioManager.shared.setEngineAvailability(.default)
    }

    /// Open the call sheet for the answered call: on the ring's server when a ring named it,
    /// else (push only) once connected, ask every skwod what is ringing and join that — and if
    /// nothing is, fail the call rather than open some room.
    private func openAnsweredCall() {
        roomWait?.cancel()
        // The client (the app may have been launched by the push; and behind the front it is put up
        // only now that the call was answered).
        let connected: @MainActor () async -> Void = {
            for _ in 0..<80 {
                if Task.isCancelled { return }
                if let app = CallCoordinator.shared.app, !app.serverURL.isEmpty, app.clientIsOnline { return }
                try? await Task.sleep(for: .milliseconds(250))
            }
        }
        if let ring {
            note("openedServer", ring.serverId)
            roomWait = Task { @MainActor in
                await connected()
                if !Task.isCancelled { CallCoordinator.shared.open(serverId: ring.serverId) }
            }
            return
        }
        roomWait = Task { @MainActor [weak self] in
            // 1. the connection
            await connected()
            // 2. a `ring` event that names the room (`ringArrived` then opens it and cancels us)
            for _ in 0..<16 {
                if Task.isCancelled { return }
                try? await Task.sleep(for: .milliseconds(250))
            }
            guard !Task.isCancelled, let self, self.answered, self.ring == nil else { return }
            // 3. still no room named: ask every signed-in skwod what is ringing. That either
            //    names the room (`ringArrived` → this call is opened there) or ends the call.
            await CallCoordinator.shared.findRingAfterWake(answered: true)
        }
    }

    /// The in-app call view went away (the user left the room): end the call it belongs to — the
    /// ANSWERED one. A call that is still ringing is someone else calling and is left alone.
    func endAnsweredCall() {
        guard let uuid = current, answered else { return }
        controller.request(CXTransaction(action: CXEndCallAction(call: uuid))) { _ in }
    }

    /// The user declined the ringing call from inside the app.
    func declineRingingCall() {
        guard let uuid = current, !answered else { return }
        controller.request(CXTransaction(action: CXEndCallAction(call: uuid))) { _ in }
    }

    /// The user opened the ringing room from inside the app instead of the call screen.
    func joinedInApp() {
        guard let uuid = current, !answered else { return }
        provider.reportCall(with: uuid, endedAt: nil, reason: .answeredElsewhere)
        clear()
    }

    private func note(_ key: String, _ value: Any) {
        #if DEBUG
        Task { @MainActor in CallDebug.callKit[key] = value }
        #endif
    }

    #if DEBUG
    /// DEBUG end-to-end hook: answer the ringing call the way the system call screen does — a
    /// `CXAnswerCallAction` transaction through CallKit, which then calls the delegate below.
    func debugAnswer() {
        guard let uuid = current else { note("answerRequested", "no call"); return }
        controller.request(CXTransaction(action: CXAnswerCallAction(call: uuid))) { [weak self] error in
            self?.note("answerRequested", error.map { "error \(($0 as NSError).code)" } ?? "ok")
        }
    }
    #endif

    // MARK: CXProviderDelegate

    func providerDidReset(_ provider: CXProvider) {
        clear()
        Task { @MainActor in CallCoordinator.shared.endedBySystem() }
    }

    func provider(_ provider: CXProvider, perform action: CXAnswerCallAction) {
        // Only the call this app is tracking can be answered — never a refused wake's.
        guard action.callUUID == current else { action.fail(); return }
        timeout?.cancel()
        answered = true
        // (CallKit's delegate queue is the main one.)
        MainActor.assumeIsolated { CallCoordinator.shared.app?.callAnswered() }
        note("answered", true)
        // CallKit owns the audio session for this call: hold the audio engine until the system
        // has activated the session (`didActivate`), with a short safety net in case it never says.
        try? AudioManager.shared.setEngineAvailability(.none)
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
            try? AudioManager.shared.setEngineAvailability(.default)
        }
        openAnsweredCall()
        action.fulfill()
    }

    func provider(_ provider: CXProvider, perform action: CXEndCallAction) {
        // The end of a call that is not the tracked one (a refused wake) changes nothing here.
        guard action.callUUID == current else { action.fulfill(); return }
        let wasAnswered = answered
        clear()
        note("ended", true)
        Task { @MainActor in
            if wasAnswered { CallCoordinator.shared.endedBySystem() } else { CallCoordinator.shared.ringEnded() }
        }
        action.fulfill()
    }

    func provider(_ provider: CXProvider, didActivate audioSession: AVAudioSession) {
        note("audioActivated", true)
        audioLive = true
        try? AudioManager.shared.setEngineAvailability(.default)
    }

    /// The system has the call's audio session active right now.
    private(set) var audioLive = false

    func provider(_ provider: CXProvider, didDeactivate audioSession: AVAudioSession) {
        audioLive = false
        try? AudioManager.shared.setEngineAvailability(.default)
    }
}

/// UIKit app delegate bridged into SwiftUI, purely to receive the APNs token (SwiftUI has no
/// first-class hook for it).
final class PushAppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        PushManager.shared.startVoIP()
        return true
    }

    func application(_ application: UIApplication,
                     didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        Task { @MainActor in PushManager.shared.setToken(deviceToken) }
    }

    /// A silent push. The only one this app is sent is the gateway's registration challenge
    /// (docs/PUSH.md): proof, to the gateway, that whoever asks for a wake credential for this
    /// token really is the device the token belongs to. Nothing is shown for it.
    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any],
                     fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        // Kept before the system is told this push is dealt with (it may suspend the app then).
        if let value = userInfo["skwod_challenge"] as? String {
            PushManager.shared.challengeArrived(value)
        }
        completionHandler(.noData)
    }

    func application(_ application: UIApplication,
                     didFailToRegisterForRemoteNotificationsWithError error: Error) {
        // No-op: without a token, push simply stays off (in-app notifications still work).
    }
}
#endif
