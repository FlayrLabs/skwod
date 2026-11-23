import XCTest

/// Capability-bound wakes on the client (`PushRegistration`, audit H2): the skwod gets a
/// revocable credential, never the raw token; raw tokens only behind the transition switch.
final class PushRegistrationTests: XCTestCase {
    private typealias R = PushRegistration
    private let now: Int64 = 1_800_000_000
    private let binding = R.binding(apns: "aa", voip: "bb", tag: "tag")

    private func input(_ change: (inout R.Input) -> Void = { _ in }) -> R.Input {
        var i = R.Input(now: now, apns: "aa", binding: binding, account: "ws|alice", stored: nil, accepted: nil)
        change(&i)
        return i
    }
    /// A 30-day credential with `expiresIn` seconds left.
    private func stored(expiresIn: Int64 = 30 * 86400, boundTo: String? = nil) -> R.Stored {
        R.Stored(credential: "w1.cred", revoke: "r1.rev", expiresAt: now + expiresIn, issuedAt: now + expiresIn - 30 * 86400,
                 boundTo: boundTo ?? binding, id: "id-1", apns: "aa")
    }

    func testAFreshInstallAsksForAChallengeThenMintsThenRegistersTheCredentialOnly() {
        XCTAssertEqual(R.next(input()), .requestChallenge)
        XCTAssertEqual(R.next(input { $0.challenge = .requested(at: self.now - 5) }), .wait)
        XCTAssertEqual(R.next(input { $0.challenge = .received("c1", at: self.now) }), .mint(proof: .challenge("c1")))
        let have = input { $0.stored = self.stored() }
        XCTAssertEqual(R.next(have), .registerCredential("w1.cred"))
        let done = input { $0.stored = self.stored(); $0.accepted = R.accepted(account: "ws|alice", binding: self.binding, credential: "w1.cred") }
        XCTAssertEqual(R.next(done), .nothing)
        // Never the raw tokens while the credential path works.
        for step in [R.next(input()), R.next(have), R.next(done)] { XCTAssertNotEqual(step, .registerRaw) }
    }

    func testAnotherAccountANearExpiryOrAChangedVoipTokenMeansRegisteringAgain() {
        let accepted = R.accepted(account: "ws|alice", binding: binding, credential: "w1.cred")
        // The held REVOKE token is the proof for a renewal — never the wake credential, which
        // the skwod has too. The gateway decides (403/400 → a challenge).
        let held = R.Step.mint(proof: .revoke("r1.rev"))
        // Less than a third of its lifetime left (whatever lifetime the gateway gave): renew
        // silently — no push round trip.
        XCTAssertEqual(R.next(input { $0.stored = self.stored(expiresIn: 9 * 86400); $0.accepted = accepted }), held)
        XCTAssertEqual(R.next(input { $0.stored = self.stored(expiresIn: 11 * 86400); $0.accepted = accepted }), .nothing)
        // The VoIP token arrived or changed, the APNs token did not: same proof.
        let voip = R.binding(apns: "aa", voip: "dd", tag: "tag")
        XCTAssertEqual(R.next(input { $0.binding = voip; $0.stored = self.stored(); $0.accepted = accepted }), held)
        // Expired: its revoke token proves nothing any more.
        XCTAssertEqual(R.next(input { $0.stored = self.stored(expiresIn: -5); $0.accepted = accepted }), .requestChallenge)
        let week = R.Stored(credential: "w1.cred", revoke: "r", expiresAt: now + 3 * 86400, issuedAt: now - 4 * 86400, boundTo: binding, id: "id-1")
        XCTAssertEqual(R.next(input { $0.stored = week; $0.accepted = accepted }), .nothing)
        // One without a registration id: its wakes could not be told from a stranger's, so it
        // is minted again (renewed with its revoke token).
        var noId = week; noId.id = nil
        XCTAssertEqual(R.next(input { $0.stored = noId; $0.accepted = accepted }), .mint(proof: .revoke("r")))
        // Another account signed in on this skwod: the skwod has to be told again.
        XCTAssertEqual(R.next(input { $0.account = "ws|bob"; $0.stored = self.stored(); $0.accepted = accepted }), .registerCredential("w1.cred"))
        // After a rotation the old credential is revoked — and only a different one.
        let new = R.Stored(credential: "w1.new", revoke: "r1.new", expiresAt: now, issuedAt: now, boundTo: binding)
        XCTAssertEqual(R.toRevokeAfterRotation(old: stored(), new: new), "r1.rev")
        XCTAssertNil(R.toRevokeAfterRotation(old: new, new: new))
        XCTAssertNil(R.toRevokeAfterRotation(old: nil, new: new))
    }

    func testAChangedApnsTokenCutsTheOldOneOffThenRegistersWithAChallenge() {
        let accepted = R.accepted(account: "ws|alice", binding: binding, credential: "w1.cred")
        let moved = R.binding(apns: "cc", voip: "bb", tag: "tag")
        func after(_ change: @escaping (inout R.Input) -> Void = { _ in }) -> R.Input {
            input { $0.apns = "cc"; $0.binding = moved; $0.stored = self.stored(); $0.accepted = accepted; change(&$0) }
        }
        // First: revoke-all for the OLD token, with the revoke token that was issued for it.
        XCTAssertEqual(R.next(after()), .cutOffOldToken(apns: "aa", revoke: "r1.rev"))
        let body = R.revokeAllBody(apns: "aa", topic: "com.skwod.app", proof: .revoke("r1.rev"))
        XCTAssertEqual(Set(body.keys), ["apns_token", "topic", "revoke"])
        XCTAssertEqual(body["apns_token"] as? String, "aa")
        // Then (what was held for the old token is forgotten, whatever the gateway answered):
        // a challenge for the new pair.
        XCTAssertEqual(R.next(after { $0.stored = nil }), .requestChallenge)
        XCTAssertEqual(R.next(after { $0.stored = nil; $0.challenge = .received("c", at: self.now) }), .mint(proof: .challenge("c")))
        // The old revoke token is never the proof for the new token — not even with a
        // challenge in hand, a refused proof, or no revoke token to cut the old one off with.
        for step in [R.next(after()), R.next(after { $0.challenge = .received("c", at: self.now) }), R.next(after { $0.revokeProofRefused = true })] {
            XCTAssertEqual(step, .cutOffOldToken(apns: "aa", revoke: "r1.rev"))
        }
        var bare = stored()
        bare.revoke = ""
        XCTAssertEqual(R.next(after { $0.stored = bare }), .requestChallenge)
        // An entry stored before the token was recorded: it is read off the binding.
        var early = stored()
        early.apns = nil
        early.id = nil
        XCTAssertEqual(early.issuedFor, "aa")
        XCTAssertEqual(R.next(after { $0.stored = early }), .cutOffOldToken(apns: "aa", revoke: "r1.rev"))
        let decoded = try? JSONDecoder().decode(R.Stored.self, from: Data(#"{"credential":"w","revoke":"r","expiresAt":2,"issuedAt":1,"boundTo":"aa|bb|t"}"#.utf8))
        XCTAssertEqual(decoded?.issuedFor, "aa")
        XCTAssertNil(decoded?.id)
    }

    func testOnlyOneProofIsEverEncodedAndNeverTheCredential() {
        for proof in [R.Proof.challenge("c1.x"), R.Proof.revoke("r1.x")] {
            let register = R.registerBody(apns: "aa", voip: nil, topic: "com.skwod.app", tag: nil, proof: proof)
            let all = R.revokeAllBody(apns: "aa", topic: "com.skwod.app", proof: proof)
            for body in [register, all] {
                XCTAssertEqual(["challenge", "revoke"].filter { body[$0] != nil }.count, 1)
                XCTAssertNil(body["credential"])
                XCTAssertNil(body["wake_credential"])
            }
            // The key set is strict at the gateway: `voip_token` is always there (null without
            // a token), `tag` only when there is one, and revoke-all has neither.
            XCTAssertTrue(register["voip_token"] is NSNull)
            XCTAssertEqual(Set(register.keys).subtracting(["challenge", "revoke"]), ["apns_token", "voip_token", "topic"])
            XCTAssertEqual(Set(all.keys).subtracting(["challenge", "revoke"]), ["apns_token", "topic"])
            XCTAssertTrue(JSONSerialization.isValidJSONObject(register))
        }
        let full = R.registerBody(apns: "aa", voip: "bb", topic: "t", tag: "tag-tag-tag-tag-", proof: .challenge("c1.x"))
        XCTAssertEqual(Set(full.keys), ["apns_token", "voip_token", "topic", "tag", "challenge"])
        XCTAssertEqual(full["voip_token"] as? String, "bb")
        XCTAssertEqual(full["challenge"] as? String, "c1.x")
        XCTAssertEqual(R.registerBody(apns: "aa", voip: "bb", topic: "t", tag: nil, proof: .revoke("r1.x"))["revoke"] as? String, "r1.x")
        // Whatever the state, a mint step carries a challenge or a revoke token.
        let steps = [
            R.next(input { $0.challenge = .received("c", at: self.now) }),
            R.next(input { $0.stored = self.stored(expiresIn: 86400) }),
            R.next(input { $0.stored = self.stored(expiresIn: 86400); $0.revokeProofRefused = true; $0.challenge = .received("c", at: self.now) }),
        ]
        XCTAssertEqual(steps, [.mint(proof: .challenge("c")), .mint(proof: .revoke("r1.rev")), .mint(proof: .challenge("c"))])
    }

    func testAnOldGatewayOrAnOldSkwodGetsRawTokensOnlyWhileTheSwitchAllowsIt() {
        // A gateway without /v1/challenge. (`allowLegacy` set explicitly: build 45 ships with it off.)
        XCTAssertEqual(R.next(input { $0.gateway = .no; $0.allowLegacy = true }), .registerRaw)
        XCTAssertEqual(R.next(input { $0.gateway = .no; $0.allowLegacy = false }), .unavailable)
        // A skwod that refused the credential shape — even with a perfectly good credential.
        XCTAssertEqual(R.next(input { $0.skwod = .no; $0.stored = self.stored(); $0.allowLegacy = true }), .registerRaw)
        XCTAssertEqual(R.next(input { $0.skwod = .no; $0.stored = self.stored(); $0.allowLegacy = false }), .unavailable)
        // Registered raw once: not again.
        let raw = R.accepted(account: "ws|alice", binding: binding, credential: nil)
        XCTAssertEqual(R.next(input { $0.skwod = .no; $0.accepted = raw; $0.allowLegacy = true }), .nothing)
        // An old gateway does not stop a credential that already exists from being used.
        XCTAssertEqual(R.next(input { $0.gateway = .no; $0.stored = self.stored() }), .registerCredential("w1.cred"))
        // Build 45 (audit M1): OFF. A skwod that refuses credentials gets no registration at all
        // — a malicious host refusing them on purpose gets nothing to ring with.
        XCTAssertFalse(R.allowLegacyRawPushRegistration, "raw tokens cannot be revoked: never handed to a skwod again")
        XCTAssertFalse(WakeOrigin.followsRawWakes)
        XCTAssertEqual(R.next(input { $0.skwod = .no; $0.stored = self.stored() }), .unavailable)
        XCTAssertEqual(R.next(input { $0.gateway = .no }), .unavailable)
        XCTAssertEqual(R.next(input { $0.challengeFailures = 5; $0.lastChallengeFailure = self.now }), .wait)
    }

    func testAChallengeThatNeverArrivesIsNotAskedForInALoop() {
        XCTAssertEqual(R.next(input { $0.challenge = .requested(at: self.now - R.challengeTimeout) }), .challengeTimedOut)
        XCTAssertEqual(R.next(input { $0.challengeFailures = 1; $0.lastChallengeFailure = self.now - 60 }), .wait)
        // Not asked again while the gateway would still be holding the first one (it sends no
        // second push for a live challenge) — and that one is still used if it turns up late.
        XCTAssertGreaterThanOrEqual(R.backoff(failures: 1), R.challengeLifetime)
        XCTAssertEqual(R.next(input { $0.challengeFailures = 1; $0.lastChallengeFailure = self.now - 599 }), .wait)
        XCTAssertEqual(R.next(input { $0.challengeFailures = 1; $0.lastChallengeFailure = self.now - 601 }), .requestChallenge)
        XCTAssertTrue(R.challengeStillComing(askedAt: now - 300, now: now))
        XCTAssertFalse(R.challengeStillComing(askedAt: now - 601, now: now))
        XCTAssertFalse(R.challengeStillComing(askedAt: nil, now: now))
        XCTAssertEqual(R.next(input { $0.challengeFailures = 1; $0.lastChallengeFailure = self.now - 60; $0.challenge = .received("late", at: self.now) }),
                       .mint(proof: .challenge("late")))
        // Two in a row: silent pushes are not getting through; raw while allowed, else keep trying slowly.
        XCTAssertEqual(R.next(input { $0.challengeFailures = 2; $0.lastChallengeFailure = self.now; $0.allowLegacy = true }), .registerRaw)
        XCTAssertEqual(R.next(input { $0.challengeFailures = 2; $0.lastChallengeFailure = self.now; $0.allowLegacy = false }), .wait)
        XCTAssertEqual(R.next(input { $0.challengeFailures = 2; $0.lastChallengeFailure = self.now - 1201; $0.allowLegacy = false }), .requestChallenge)
        XCTAssertEqual(R.backoff(failures: 0), 0)
        XCTAssertEqual(R.backoff(failures: 3), 40 * 60)
        XCTAssertEqual(R.backoff(failures: 50), R.maxBackoff)
    }

    func testAChallengeNobodyAskedForIsKeptAndUsedForTenMinutes() {
        // Never asked (anyone who knows the token can make the gateway push one, and it pushes
        // no other while that one is unused): it is what gets this install registered.
        XCTAssertEqual(R.next(input { $0.challenge = .received("unasked", at: self.now - 30) }), .mint(proof: .challenge("unasked")))
        // Also in the middle of a back-off, and after the raw fallback would have applied.
        XCTAssertEqual(R.next(input { $0.challengeFailures = 2; $0.lastChallengeFailure = self.now; $0.challenge = .received("unasked", at: self.now - 30) }),
                       .mint(proof: .challenge("unasked")))
        // Good for the gateway's ten minutes; after that it is as if there were none.
        XCTAssertEqual(R.next(input { $0.challenge = .received("c", at: self.now - 599) }), .mint(proof: .challenge("c")))
        XCTAssertEqual(R.next(input { $0.challenge = .received("c", at: self.now - 600) }), .requestChallenge)
        XCTAssertEqual(R.next(input { $0.challenge = .received("c", at: self.now + 5) }), .requestChallenge)
        XCTAssertTrue(R.challengeUsable(receivedAt: now, now: now))
        XCTAssertFalse(R.challengeUsable(receivedAt: now - R.challengeLifetime, now: now))
        // With a usable one in hand, or a request outstanding, no other is asked for.
        for i in [input { $0.challenge = .received("c", at: self.now - 100) }, input { $0.challenge = .requested(at: self.now - 10) }] {
            XCTAssertNotEqual(R.next(i), .requestChallenge)
        }
        // A held revoke token still comes first: the kept challenge is not spent on a renewal.
        XCTAssertEqual(R.next(input { $0.stored = self.stored(expiresIn: 86400); $0.challenge = .received("c", at: self.now) }), .mint(proof: .revoke("r1.rev")))
    }

    func testARefusedRevokeProofFallsBackToAChallengeOnce() {
        // 403 (not outstanding for this token) and 400 (not a proof this gateway takes).
        XCTAssertTrue(R.fallsBackToChallenge(proof: .revoke("r1.rev"), status: 403))
        XCTAssertTrue(R.fallsBackToChallenge(proof: .revoke("r1.rev"), status: 400))
        // Unreachable, rationed, no such route: not a refusal of the proof.
        for status in [nil, 429, 500, 404, 410, 200] as [Int?] { XCTAssertFalse(R.fallsBackToChallenge(proof: .revoke("r1.rev"), status: status)) }
        // A refused challenge is a failed attempt; there is nothing to fall back to.
        XCTAssertFalse(R.fallsBackToChallenge(proof: .challenge("c"), status: 403))
        XCTAssertFalse(R.fallsBackToChallenge(proof: .challenge("c"), status: 400))
        // After the refusal: ask for a challenge, then mint with it — the revoke token is not
        // offered again.
        let refused = input { $0.stored = self.stored(expiresIn: 86400); $0.revokeProofRefused = true }
        XCTAssertEqual(R.next(refused), .requestChallenge)
        XCTAssertEqual(R.next(input { $0.stored = self.stored(expiresIn: 86400); $0.revokeProofRefused = true; $0.challenge = .received("c", at: self.now) }),
                       .mint(proof: .challenge("c")))
    }

    func testCuttingOffEveryRegistrationUsesAHeldRevokeTokenForThisTokenElseAChallenge() {
        let dead = R.Stored(credential: "w1.old", revoke: "r1.dead", expiresAt: now - 1, issuedAt: now - 100, boundTo: binding)
        let noRevoke = R.Stored(credential: "w1.live", revoke: "", expiresAt: now + 100, issuedAt: now - 100, boundTo: binding)
        let other = R.Stored(credential: "w1.other", revoke: "r1.other", expiresAt: now + 100, issuedAt: now - 100, boundTo: "zz|bb|tag", apns: "zz")
        XCTAssertEqual(R.revokeAllProof(held: [dead, noRevoke, other, stored()], apns: "aa", now: now), .revoke("r1.rev"))
        // A live credential is not a proof; nor is an expired one's revoke token, nor one
        // issued for another APNs token.
        XCTAssertNil(R.revokeAllProof(held: [dead, noRevoke, other], apns: "aa", now: now))
        XCTAssertNil(R.revokeAllProof(held: [], apns: "aa", now: now))
    }

    func testAVoipPushIsRungOnlyForARegistrationOfThisInstall() {
        let known: Set<String> = ["id-1", "id-2"]
        XCTAssertEqual(R.callWake(credentialId: "id-1", known: known), .ring)
        XCTAssertEqual(R.callWake(credentialId: "id-1", known: known, allowLegacy: false), .ring)
        // Someone else's registration (a skwod that was left, a credential minted by another
        // device for this VoIP token): reported and ended, with the legacy switch on or off.
        for legacy in [true, false] {
            XCTAssertEqual(R.callWake(credentialId: "id-9", known: known, allowLegacy: legacy), .endImmediately)
            XCTAssertEqual(R.callWake(credentialId: "id-1", known: [], allowLegacy: legacy), .endImmediately)
            // There, but not an id: nobody's — not a legacy wake.
            XCTAssertEqual(R.callWake(credentialId: "", known: known, allowLegacy: legacy), .endImmediately)
            XCTAssertEqual(R.callWake(credentialId: 7, known: known, allowLegacy: legacy), .endImmediately)
            XCTAssertEqual(R.callWake(credentialId: NSNull(), known: known, allowLegacy: legacy), .endImmediately)
        }
        // No id at all — a raw-token wake (a host holding an earlier build's tokens, perhaps one
        // the user left): never rung by build 45, whatever its tag (audit M1).
        XCTAssertEqual(R.callWake(credentialId: nil, known: known), .endImmediately)
        XCTAssertEqual(R.callWake(credentialId: nil, known: known, tag: "tag-a", signedInTags: ["tag-a"]), .endImmediately)
        // Were raw wakes followed again, only one whose tag a SIGNED-IN skwod owns would ring:
        // never an untagged one, never a tag nobody here has.
        XCTAssertEqual(R.callWake(credentialId: nil, known: known, tag: "tag-a", signedInTags: ["tag-a", nil], allowLegacy: true), .ring)
        XCTAssertEqual(R.callWake(credentialId: nil, known: known, tag: "tag-z", signedInTags: ["tag-a"], allowLegacy: true), .endImmediately)
        XCTAssertEqual(R.callWake(credentialId: nil, known: known, tag: nil, signedInTags: ["tag-a", nil], allowLegacy: true), .endImmediately)
        XCTAssertEqual(R.callWake(credentialId: nil, known: known, tag: "", signedInTags: ["", nil], allowLegacy: true), .endImmediately)
        // As it comes out of a PushKit payload.
        let payload: [AnyHashable: Any] = ["aps": [String: Any](), "tag": "t", "skwod_cred": "id-2"]
        XCTAssertEqual(R.callWake(credentialId: payload["skwod_cred"], known: known), .ring)
        XCTAssertEqual(R.callWake(credentialId: (["aps": 1, "tag": "t"] as [AnyHashable: Any])["skwod_cred"], known: known, tag: "t", signedInTags: ["t"]), .endImmediately)
        // The remembered ids: one that ran out more than a day ago is no longer ours.
        let ids = ["live": R.KnownId(workspace: "ws", expiresAt: now + 5), "recent": R.KnownId(workspace: "ws", expiresAt: now - 3600),
                   "old": R.KnownId(workspace: "ws", expiresAt: now - 2 * 86400)]
        XCTAssertEqual(Set(R.pruned(ids, now: now).keys), ["live", "recent"])
        // The extension reads the same list from the shared defaults, by the same rule.
        XCTAssertEqual(WakeOrigin.knownIds(try? JSONEncoder().encode(ids), now: now), ["live", "recent"])
        XCTAssertEqual(WakeOrigin.knownIds(nil, now: now), [])
        XCTAssertEqual(WakeOrigin.knownIds(Data("junk".utf8), now: now), [])
    }

    func testWhatTheAnswersMean() {
        XCTAssertEqual(R.gatewayAnswer(status: 202), .ok)
        XCTAssertEqual(R.gatewayAnswer(status: 404), .unsupported)
        XCTAssertEqual(R.gatewayAnswer(status: 503), .unsupported)
        XCTAssertEqual(R.gatewayAnswer(status: 403), .forbidden)
        XCTAssertEqual(R.gatewayAnswer(status: 400), .challengeRejected)
        XCTAssertEqual(R.gatewayAnswer(status: 429), .later)
        XCTAssertEqual(R.gatewayAnswer(status: nil), .later)

        XCTAssertEqual(R.skwodAnswer(status: 200, credentialShape: true), .accepted)
        // A build-45 skwod: "apns_token must be hex" (400), or 422 for the unknown body.
        XCTAssertEqual(R.skwodAnswer(status: 400, credentialShape: true), .credentialUnknown)
        XCTAssertEqual(R.skwodAnswer(status: 422, credentialShape: true), .credentialUnknown)
        XCTAssertEqual(R.skwodAnswer(status: 410, credentialShape: true), .credentialGone)
        // The raw shape refused is not a reason to do anything else.
        XCTAssertEqual(R.skwodAnswer(status: 400, credentialShape: false), .later)
        // An account still in the waiting room gets 403: NOT done, and not "use raw tokens".
        XCTAssertEqual(R.skwodAnswer(status: 403, credentialShape: true), .later)
        XCTAssertEqual(R.skwodAnswer(status: 401, credentialShape: true), .later)
        XCTAssertEqual(R.skwodAnswer(status: nil, credentialShape: true), .later)
    }
}
