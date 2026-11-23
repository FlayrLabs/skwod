import Foundation

/// How this install gets a skwod to wake it — the rules, without any I/O (docs/PUSH.md).
///
/// **Capability-bound wakes.** The skwod is never given the APNs or VoIP token. The device asks
/// the gateway for a *wake credential* — an opaque string good for waking this install, for one
/// skwod, until it is revoked or expires — and hands the skwod only that:
///
/// 1. `POST <gateway>/v1/challenge { apns_token, topic }` → the gateway sends a silent push to
///    that token carrying `skwod_challenge`. Only the device the token belongs to receives it,
///    so someone who merely copied the token out of a skwod's database cannot register.
/// 2. `POST <gateway>/v1/register { apns_token, voip_token, topic, tag, <proof> }` →
///    `{ credential, revoke, id, expires_at }`. The proof is EXACTLY ONE of `challenge` (step 1)
///    or `revoke` — the revoke token of a credential this install still holds for the same APNs
///    token, which is how a registration is renewed silently, with no push round trip. The wake
///    credential itself is never proof: the skwod has it.
/// 3. `POST <skwod>/api/push/register { provider: "gateway", gateway, wake_credential }`.
///
/// `POST <gateway>/v1/revoke { revoke }` ends one credential (sign-out, erase, rotation): the
/// skwod that still holds it can no longer wake this device. `revoke` never leaves the device.
/// `POST <gateway>/v1/revoke-all { apns_token, topic, <proof> }` ends every one for a token.
///
/// **Whose wake is it.** Every push for a credential wake carries the registration `id` under
/// `skwod_cred`. A VoIP push naming an id this install did not register is reported to CallKit
/// (it must be) and ended at once (`callWake`).
///
/// **No raw tokens (build 45, audit M1).** Build ≤ 44 skwods and gateways know only raw tokens,
/// and a raw token cannot be revoked: a host that refused the credential shape to get it could
/// ring the phone after it was left. So [`allowLegacyRawPushRegistration`] is false: a skwod
/// that refuses credentials gets NO push registration (the user is told that host needs
/// updating, `hostNeedsUpdate`), and a wake without a `skwod_cred` this install registered is
/// never rung (`WakeOrigin`).
///
/// Foundation only; tested as shipped (`PushRegistrationTests`).
enum PushRegistration {
    /// THE transition switch, OFF from build 45 (audit M1). `true` handed the skwod the raw
    /// APNs/VoIP tokens when the gateway or the skwod did not speak wake credentials — and a
    /// skwod could force that by refusing the credential shape, then keep the tokens and ring
    /// after the user left. Kept as a switch (not deleted) only so the old path stays tested.
    static let allowLegacyRawPushRegistration = false

    /// Re-mint once less than this fraction (1/n) of a credential's lifetime is left. The
    /// lifetime is whatever the gateway granted (`expires_at` − when it was minted).
    static let renewWhenLeftIsUnderOneIn: Int64 = 3
    /// How long a requested challenge is waited for before the attempt is given up.
    static let challengeTimeout: Int64 = 45
    /// How long the gateway keeps one challenge alive. While it does, asking again sends no
    /// second push (the gateway just answers 202) — so the app does not ask again, and keeps
    /// the latest challenge it receives — asked for or not, late or not — for this long.
    static let challengeLifetime: Int64 = 10 * 60
    /// After a challenge that never arrived, wait this long times 2^(failures-1), capped at
    /// `maxBackoff`. Never shorter than `challengeLifetime`.
    static let baseBackoff: Int64 = challengeLifetime
    static let maxBackoff: Int64 = 6 * 3600
    /// Silent pushes that never arrive this many times in a row: use the raw path while allowed.
    static let challengeFailuresBeforeFallback = 2

    /// What is stored (by this device, for one skwod) about its wake credential.
    struct Stored: Codable, Equatable {
        var credential: String
        var revoke: String
        /// Unix seconds.
        var expiresAt: Int64
        /// When it was minted (unix seconds, this device's clock).
        var issuedAt: Int64
        /// `binding(...)` of the tokens and tag the credential was minted for.
        var boundTo: String
        /// The registration id the gateway gave it: what its wakes carry as `skwod_cred`.
        /// (Optional, like `apns`: an entry stored before these existed must still decode.)
        var id: String? = nil
        /// The APNs token it — and so its revoke token — was issued for.
        var apns: String? = nil

        /// The APNs token the revoke token is good for (`apns`, else the head of `boundTo`).
        var issuedFor: String { apns ?? String(boundTo.prefix(while: { $0 != "|" })) }
    }

    /// What a credential is good for: change any of these and it has to be minted again.
    static func binding(apns: String, voip: String?, tag: String?) -> String {
        "\(apns)|\(voip ?? "")|\(tag ?? "")"
    }

    enum Support: Equatable { case unknown, yes, no }

    enum Challenge: Equatable {
        case none
        /// Asked for at this time (unix seconds); the silent push has not arrived.
        case requested(at: Int64)
        /// The latest `skwod_challenge` a silent push brought, and when (unix seconds) —
        /// whether or not it was asked for. Good for `challengeLifetime`, once.
        case received(String, at: Int64)
    }

    struct Input: Equatable {
        var now: Int64
        /// The APNs token as it is now.
        var apns: String
        /// `binding` of the tokens and tag as they are now.
        var binding: String
        /// Which account on which skwod (changing it means registering again).
        var account: String
        var stored: Stored?
        /// What this skwod last accepted from this launch: `accepted(...)`, or nil.
        var accepted: String?
        /// Does the gateway speak `/v1/challenge` (learned this launch)?
        var gateway: Support = .unknown
        /// Does this skwod take `wake_credential` (learned this launch)?
        var skwod: Support = .unknown
        var challenge: Challenge = .none
        /// Challenges in a row that never arrived, and when the last one was given up.
        var challengeFailures = 0
        var lastChallengeFailure: Int64 = 0
        /// The gateway refused a held revoke token as proof (403 or 400): use a challenge.
        var revokeProofRefused = false
        var allowLegacy = PushRegistration.allowLegacyRawPushRegistration
    }

    enum Step: Equatable {
        /// Registered as things stand; nothing to send.
        case nothing
        /// Ask the gateway to send a challenge to this device.
        case requestChallenge
        /// A challenge is on its way (or rationed): do nothing now, look again later.
        case wait
        /// The challenge that was waited for did not come: record the failure, then look again.
        case challengeTimedOut
        /// The APNs token changed and a revoke token for the old one is held: cut off every
        /// registration of the OLD token (`/v1/revoke-all`, best effort), forget what was held
        /// for it, then look again — the new pair is registered with a challenge.
        case cutOffOldToken(apns: String, revoke: String)
        /// Mint a credential, proving to the gateway that this is the device.
        case mint(proof: Proof)
        /// Hand this skwod the stored credential.
        case registerCredential(String)
        /// Transition only: hand this skwod the raw tokens.
        case registerRaw
        /// Push stays off for this skwod for now (no usable path); look again later.
        case unavailable
    }

    /// What tells the gateway that a registration request comes from the device itself.
    enum Proof: Equatable {
        /// The value of a silent push the gateway sent to this device (single use).
        case challenge(String)
        /// The revoke token of a credential this install holds, still outstanding at the
        /// gateway for the SAME APNs token. Using it as proof does not spend it.
        case revoke(String)
    }

    /// The body of `/v1/register`: the tokens (`voip_token` always there, null without one),
    /// the topic, the tag if any — and exactly one proof.
    static func registerBody(apns: String, voip: String?, topic: String, tag: String?, proof: Proof) -> [String: Any] {
        var body = revokeAllBody(apns: apns, topic: topic, proof: proof)
        body["voip_token"] = voip.map { $0 as Any } ?? NSNull()
        if let tag { body["tag"] = tag }
        return body
    }

    /// The body of `/v1/revoke-all`: the token, the topic and exactly one proof.
    static func revokeAllBody(apns: String, topic: String, proof: Proof) -> [String: Any] {
        var body: [String: Any] = ["apns_token": apns, "topic": topic]
        switch proof {
        case .challenge(let value): body["challenge"] = value
        case .revoke(let token): body["revoke"] = token
        }
        return body
    }

    /// The marker for "this skwod accepted this registration".
    static func accepted(account: String, binding: String, credential: String?) -> String {
        "\(account)|\(binding)|\(credential ?? "raw")"
    }

    /// Is the stored credential usable as things stand? One without a registration id is not:
    /// its wakes could not be told from a stranger's (`WakeOrigin`), so it is minted again.
    static func usable(_ stored: Stored?, binding: String, now: Int64) -> Bool {
        guard let stored, stored.id?.isEmpty == false else { return false }
        let lifetime = max(stored.expiresAt - stored.issuedAt, 0)
        return stored.boundTo == binding && (stored.expiresAt - now) * renewWhenLeftIsUnderOneIn > lifetime
    }

    /// When the next challenge may be asked for after `failures` in a row.
    static func backoff(failures: Int) -> Int64 {
        guard failures > 0 else { return 0 }
        return min(maxBackoff, baseBackoff << Int64(min(failures - 1, 20)))
    }

    /// The one decision: what to do next for the active skwod.
    static func next(_ i: Input) -> Step {
        let raw = accepted(account: i.account, binding: i.binding, credential: nil)
        func legacy() -> Step {
            guard i.allowLegacy else { return .unavailable }
            return i.accepted == raw ? .nothing : .registerRaw
        }
        // A skwod that refused the credential shape (build ≤ 45): raw tokens, or nothing.
        if i.skwod == .no { return legacy() }
        // A usable credential: make sure this skwod has it.
        if usable(i.stored, binding: i.binding, now: i.now), let stored = i.stored {
            return i.accepted == accepted(account: i.account, binding: i.binding, credential: stored.credential)
                ? .nothing : .registerCredential(stored.credential)
        }
        // A credential has to be minted. A gateway that cannot (build ≤ 45): raw, or nothing.
        if i.gateway == .no { return legacy() }
        if let held = i.stored, held.issuedFor != i.apns {
            // The APNs token changed. The old revoke token is never proof for the new token:
            // it cuts the old one off, and the new pair needs a challenge.
            if !held.revoke.isEmpty, !held.issuedFor.isEmpty {
                return .cutOffOldToken(apns: held.issuedFor, revoke: held.revoke)
            }
        } else if !i.revokeProofRefused, let held = i.stored, !held.revoke.isEmpty, held.expiresAt > i.now {
            // Renewal: the revoke token of a credential still held proves it is the device.
            return .mint(proof: .revoke(held.revoke))
        }
        switch i.challenge {
        case .received(let value, let at) where challengeUsable(receivedAt: at, now: i.now):
            return .mint(proof: .challenge(value))
        case .requested(let at):
            return i.now - at >= challengeTimeout ? .challengeTimedOut : .wait
        case .none, .received:
            // Silent pushes are not reaching this device: do not leave it without wakes.
            if i.challengeFailures >= challengeFailuresBeforeFallback, i.allowLegacy { return legacy() }
            if i.challengeFailures > 0, i.now - i.lastChallengeFailure < backoff(failures: i.challengeFailures) { return .wait }
            return .requestChallenge
        }
    }

    /// Is a challenge that arrived at `receivedAt` still one the gateway honours?
    static func challengeUsable(receivedAt: Int64, now: Int64) -> Bool {
        now >= receivedAt && now - receivedAt < challengeLifetime
    }

    /// Would asking for a challenge now send no push, because the one asked for at `askedAt`
    /// (nil = none) is still alive at the gateway?
    static func challengeStillComing(askedAt: Int64?, now: Int64) -> Bool {
        guard let askedAt else { return false }
        return now >= askedAt && now - askedAt <= challengeLifetime
    }

    /// The gateway did not take a held revoke token as proof (403: not outstanding for this
    /// token; 400: not a shape it accepts): go on, once, with a challenge. Anything else —
    /// and any refusal of a challenge — is just a failed attempt.
    static func fallsBackToChallenge(proof: Proof, status: Int?) -> Bool {
        guard case .revoke = proof else { return false }
        return status == 403 || status == 400
    }

    /// What proves "this is the device" for cutting off EVERY registration of `apns`
    /// (`/v1/revoke-all`): a held revoke token of a credential issued for that same token and
    /// not expired. nil: nothing held — a challenge is needed.
    static func revokeAllProof(held: [Stored], apns: String, now: Int64) -> Proof? {
        held.first(where: { !$0.revoke.isEmpty && $0.issuedFor == apns && $0.expiresAt > now }).map { .revoke($0.revoke) }
    }

    // MARK: whose wake is it

    /// A registration this install made itself, as remembered for the PushKit handler and the
    /// notification extension (defined beside the rules that read it, `WakeOrigin`).
    typealias KnownId = WakeOrigin.KnownId

    /// The remembered registrations without those that ran out more than a day ago.
    static func pruned(_ ids: [String: KnownId], now: Int64) -> [String: KnownId] {
        ids.filter { $0.value.expiresAt + 86400 > now }
    }

    enum CallWake: Equatable {
        /// One of ours: ring.
        case ring
        /// Not ours. PushKit still demands a CallKit report, so: report, then end at once —
        /// no connecting, no UI of ours.
        case endImmediately
    }

    /// What to do with a VoIP push (audit M1). `credentialId`: the payload's `skwod_cred`, as it
    /// came (nil = the key is absent). `known`: the ids this install registered itself. `tag`:
    /// the payload's tag; `signedInTags`: the wake tags of the skwods signed in here.
    ///
    /// Rung only for a registration of this install. No id at all is a raw-token wake — a host
    /// that kept an earlier build's raw tokens, perhaps one the user has left: ended, like a
    /// stranger's. (Were raw wakes followed again, `allowLegacy`, only one whose tag a signed-in
    /// skwod owns would ring.) An id that is there but is not a string, or is empty, is nobody's.
    static func callWake(credentialId: Any?, known: Set<String>, tag: String? = nil, signedInTags: [String?] = [],
                         allowLegacy: Bool = WakeOrigin.followsRawWakes) -> CallWake {
        let origin = WakeOrigin.of(credentialId: credentialId, known: known)
        return WakeOrigin.isOurs(origin, tag: tag, signedInTags: signedInTags, followRaw: allowLegacy) ? .ring : .endImmediately
    }

    // MARK: what an answer means

    enum GatewayAnswer: Equatable {
        /// 2xx.
        case ok
        /// The gateway has no such route / is not set up for credentials (404, 501, 503).
        case unsupported
        /// The request was malformed or its proof is spent or expired (400, 401, 410). A 400
        /// to a revoke-token proof also means "use a challenge" (`fallsBackToChallenge`).
        case challengeRejected
        /// 403: the proof was refused (`fallsBackToChallenge`).
        case forbidden
        /// Rationed or unreachable (429, other 5xx, no answer): later.
        case later
    }

    static func gatewayAnswer(status: Int?) -> GatewayAnswer {
        guard let status else { return .later }
        switch status {
        case 200...299: return .ok
        case 404, 405, 501, 503: return .unsupported
        case 403: return .forbidden
        case 400, 401, 410: return .challengeRejected
        default: return .later
        }
    }

    enum SkwodAnswer: Equatable {
        case accepted
        /// The skwod does not know `wake_credential` (a build ≤ 45 answers 400 or 422 to it).
        case credentialUnknown
        /// The skwod says this credential is dead (410: the gateway called it gone — revoked,
        /// expired, or pushed out by newer registrations): forget it and mint another.
        case credentialGone
        /// Not now — and NOT remembered as done: 403 is an account still in the waiting room,
        /// 401 an ended session, 429/5xx/no answer a skwod that is busy or away.
        case later
    }

    /// `credentialShape`: the request carried `wake_credential` (not raw tokens).
    static func skwodAnswer(status: Int?, credentialShape: Bool) -> SkwodAnswer {
        guard let status else { return .later }
        if status == 200 { return .accepted }
        if credentialShape, status == 400 || status == 422 { return .credentialUnknown }
        if credentialShape, status == 410 { return .credentialGone }
        return .later
    }

    /// The credential a newly accepted one replaces, to be revoked at the gateway — only once
    /// the skwod has the new one, so there is no gap without wakes.
    static func toRevokeAfterRotation(old: Stored?, new: Stored) -> String? {
        guard let old, old.credential != new.credential, !old.revoke.isEmpty else { return nil }
        return old.revoke
    }
}
