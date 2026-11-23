import XCTest

/// Build 45 audit (push A2, B4, B5, C1, C2, C3): what a contentless wake may make the device
/// do. Compiled from the source files the app and the notification extension use.
final class WakeRulesTests: XCTestCase {
    private let now: TimeInterval = 1_800_000_000
    private let a = WakeRule.Skwod(id: "a", wakeTag: "tag-a")
    private let b = WakeRule.Skwod(id: "b", wakeTag: "tag-b")
    private let legacy = WakeRule.Skwod(id: "old", wakeTag: nil)

    private func plan(tag: String?, signedIn: [WakeRule.Skwod]?, everyMutedUntil: TimeInterval? = nil,
                      muted: [String: Bool] = [:], unreadable: Set<String> = [], mayDecrypt: Bool = true) -> WakeRule.Plan {
        WakeRule.plan(tag: tag, signedIn: signedIn, everySkwodMutedUntil: everyMutedUntil,
                      skwodMuted: { unreadable.contains($0) ? nil : (muted[$0] ?? false) },
                      mayDecrypt: mayDecrypt, now: now)
    }

    // MARK: whose push (audit M1: skwod_cred before the tag)

    func testAnAlertWithoutARegistrationOfThisInstallIsGenericAndDialsNobody() {
        let known: Set<String> = ["id-1"]
        func planned(_ cred: Any?, tag: String?, followRaw: Bool = WakeOrigin.followsRawWakes) -> WakeRule.Plan {
            WakeRule.plan(tag: tag, origin: WakeOrigin.of(credentialId: cred, known: known), signedIn: [a, b],
                          everySkwodMutedUntil: nil, skwodMuted: { _ in false }, mayDecrypt: true, now: now, followRaw: followRaw)
        }
        XCTAssertEqual(WakeOrigin.of(credentialId: "id-1", known: known), .registered)
        XCTAssertEqual(WakeOrigin.of(credentialId: nil, known: known), .raw)
        for odd: Any in ["id-9", "", 7, NSNull()] { XCTAssertEqual(WakeOrigin.of(credentialId: odd, known: known), .stranger) }
        // Ours: decrypted for the skwod whose tag it carries.
        XCTAssertEqual(planned("id-1", tag: "tag-b"), .decrypt(["b"]))
        // A raw-token wake (no id) — even with a signed-in skwod's tag, which a host the user
        // left still knows: generic, nothing dialed.
        XCTAssertEqual(planned(nil, tag: "tag-a"), .generic)
        // Someone else's registration, or a revoked one: the same.
        XCTAssertEqual(planned("id-9", tag: "tag-a"), .generic)
        XCTAssertEqual(planned("", tag: "tag-a"), .generic)
        // Were raw wakes followed, only with a signed-in skwod's tag — never untagged.
        XCTAssertEqual(planned(nil, tag: "tag-a", followRaw: true), .decrypt(["a"]))
        XCTAssertEqual(planned(nil, tag: nil, followRaw: true), .generic)
        XCTAssertEqual(planned(nil, tag: "forged", followRaw: true), .generic)
        // Not even "every skwod muted" makes a stranger's wake a reason to dial.
        let muted = WakeRule.plan(tag: "tag-a", origin: .stranger, signedIn: [a], everySkwodMutedUntil: nil,
                                  skwodMuted: { _ in true }, mayDecrypt: true, now: now)
        XCTAssertEqual(muted, .generic)
    }

    // MARK: whose wake (push A2: fan-out on the device)

    func testATaggedWakeIsAboutExactlyTheSkwodThatChoseTheTag() {
        XCTAssertEqual(WakeRule.candidates(tag: "tag-b", signedIn: [a, b, legacy]), ["b"])
        XCTAssertEqual(plan(tag: "tag-b", signedIn: [a, b]), .decrypt(["b"]))
    }

    func testAWakeThatIsNobodysDialsNobodyButIsNotHidden() {
        // A tag no skwod here chose.
        XCTAssertEqual(WakeRule.candidates(tag: "forged", signedIn: [a, b, legacy]), [])
        XCTAssertEqual(plan(tag: "forged", signedIn: [a, b]), .generic)
        // No tag, and every skwod has one: whoever sent it merely holds the push token.
        XCTAssertEqual(WakeRule.candidates(tag: nil, signedIn: [a, b]), [])
        XCTAssertEqual(plan(tag: nil, signedIn: [a, b]), .generic)
        XCTAssertEqual(plan(tag: "", signedIn: [a, b]), .generic)
        // Not even with every skwod muted is it a reason to dial; and no skwods at all: generic.
        XCTAssertEqual(plan(tag: "forged", signedIn: [a, b], muted: ["a": true, "b": true]), .generic)
        XCTAssertEqual(plan(tag: nil, signedIn: []), .generic)
        XCTAssertEqual(plan(tag: "tag-a", signedIn: []), .generic)
    }

    func testAnUntaggedWakeIsOnlyForSkwodsThatNeverRegisteredATag() {
        XCTAssertEqual(WakeRule.candidates(tag: nil, signedIn: [a, legacy, b]), ["old"])
        XCTAssertEqual(plan(tag: nil, signedIn: [a, legacy]), .decrypt(["old"]))
    }

    // MARK: a missed notification is worse than an extra one (push C1)

    func testAMutedSkwodsOwnWakeIsQuietAlsoWithPreviewsOffOrAppLockOn() {
        for mayDecrypt in [true, false] {
            XCTAssertEqual(plan(tag: "tag-a", signedIn: [a, b], muted: ["a": true], mayDecrypt: mayDecrypt), .quiet)
            // Another skwod's mute does not silence this one.
            XCTAssertNotEqual(plan(tag: "tag-b", signedIn: [a, b], muted: ["a": true], mayDecrypt: mayDecrypt), .quiet)
        }
    }

    func testAnUntaggedWakeIsQuietOnlyWhenEverySkwodItCouldBeFromIsMuted() {
        let other = WakeRule.Skwod(id: "old2", wakeTag: "")
        // One of two muted: not quiet — and only the one that is not muted is looked at.
        XCTAssertEqual(plan(tag: nil, signedIn: [legacy, other], muted: ["old2": true]), .decrypt(["old"]))
        XCTAssertEqual(plan(tag: nil, signedIn: [legacy, other], muted: ["old2": true], mayDecrypt: false), .generic)
        XCTAssertEqual(plan(tag: nil, signedIn: [legacy, other], muted: ["old": true, "old2": true]), .quiet)
        XCTAssertEqual(plan(tag: nil, signedIn: [legacy, other]), .decrypt(["old", "old2"]))
    }

    func testAMuteThatCannotBeReadIsNotAMute() {
        XCTAssertEqual(plan(tag: "tag-a", signedIn: [a], unreadable: ["a"]), .decrypt(["a"]))
        XCTAssertEqual(plan(tag: "tag-a", signedIn: [a], unreadable: ["a"], mayDecrypt: false), .generic)
    }

    func testWhereNothingMayBeDecryptedAnUnmutedSkwodsBannerStaysAudible() {
        // Previews off or app lock on: only the skwod's own mute silences; a muted
        // conversation in it is not even an input to the plan.
        XCTAssertEqual(plan(tag: "tag-a", signedIn: [a, b], mayDecrypt: false), .generic)
        XCTAssertEqual(plan(tag: "tag-a", signedIn: [a, b], muted: ["a": true], mayDecrypt: false), .quiet)
    }

    func testBeforeTheFirstUnlockOnlyEverySkwodBeingMutedMakesAWakeQuiet() {
        // Nothing in the Keychain is readable: not even which skwods there are.
        XCTAssertEqual(plan(tag: "tag-a", signedIn: nil), .generic)
        XCTAssertEqual(plan(tag: "tag-a", signedIn: nil, everyMutedUntil: MuteList.forever), .quiet)
        XCTAssertEqual(plan(tag: nil, signedIn: nil, everyMutedUntil: now + 5), .quiet)
        XCTAssertEqual(plan(tag: nil, signedIn: nil, everyMutedUntil: now - 5), .generic)
        // The one time that is kept: only when ALL skwods are muted, and then the earliest end.
        XCTAssertNil(WakeRule.everySkwodMutedUntil([], now: now))
        XCTAssertNil(WakeRule.everySkwodMutedUntil([now + 60, nil], now: now), "one skwod is not muted")
        XCTAssertNil(WakeRule.everySkwodMutedUntil([now + 60, now - 1], now: now), "one mute ran out")
        XCTAssertEqual(WakeRule.everySkwodMutedUntil([now + 60, MuteList.forever, now + 30], now: now), now + 30)
        XCTAssertEqual(WakeRule.everySkwodMutedUntil([MuteList.forever, MuteList.forever], now: now), MuteList.forever)
        // A muted conversation is not a skwod's mute: it never reaches this.
        var list = MuteList()
        list.mute("dm:c1", for: .forever, now: now)
        XCTAssertNil(WakeRule.everySkwodMutedUntil([list.skwodUntil], now: now))
    }

    func testAWakeEndsQuietOnlyWhenEverySkwodAskedSaidNothingNeedsYou() {
        XCTAssertEqual(WakeRule.withoutAMessage(unknown: false, onlyBackgroundTraffic: true), .quiet)
        // Unreachable, out of time, or the dial budget spent: the banner stays, and sounds.
        XCTAssertEqual(WakeRule.withoutAMessage(unknown: true, onlyBackgroundTraffic: true), .generic)
        XCTAssertEqual(WakeRule.withoutAMessage(unknown: true, onlyBackgroundTraffic: false), .generic)
        XCTAssertEqual(WakeRule.withoutAMessage(unknown: false, onlyBackgroundTraffic: false), .generic)
    }

    // MARK: a stalling host does not use the whole wake (push C6)

    func testACallThatDoesNotEndIsLeftWhenItsTimeIsUp() async {
        final class Flag: @unchecked Sendable { private let l = NSLock(); private var v = false
            var isSet: Bool { l.lock(); defer { l.unlock() }; return v }
            func set() { l.lock(); v = true; l.unlock() } }
        let abandoned = Flag()
        let started = Date()
        // A call that cannot be interrupted (as a call into the core cannot): 1.5 s.
        let outcome: (value: Int?, lingering: BoundedCall.Lingering?) = await BoundedCall.run(seconds: 0.2, onAbandon: { abandoned.set() }) {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) { c.resume() }
            }
            return 7
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 1.0, "it waited for the stalled call")
        XCTAssertNil(outcome.value)
        XCTAssertTrue(abandoned.isSet)
        guard let lingering = outcome.lingering else { return XCTFail("the call left behind was not handed back") }
        XCTAssertFalse(lingering.isDone())
        // Not ended within what is left: still handed back, so what it holds is kept.
        let still = await BoundedCall.wait(for: [lingering], until: Date().addingTimeInterval(0.1))
        XCTAssertEqual(still.count, 1)
        // Given the time, it ends and nothing is left.
        let none = await BoundedCall.wait(for: [lingering], until: Date().addingTimeInterval(5))
        XCTAssertTrue(none.isEmpty)
    }

    func testACallThatEndsInTimeGivesItsResultAndLeavesNothingBehind() async {
        let outcome: (value: Int?, lingering: BoundedCall.Lingering?) = await BoundedCall.run(seconds: 5, onAbandon: { XCTFail("not abandoned") }) { 7 }
        XCTAssertEqual(outcome.value, 7)
        XCTAssertNil(outcome.lingering)
        // The app asked for the cache: out at once, the call handed back.
        let stopped: (value: Int?, lingering: BoundedCall.Lingering?) = await BoundedCall.run(seconds: 5, shouldStop: { true }, onAbandon: {}) {
            try? await Task.sleep(nanoseconds: 300_000_000)
            return 1
        }
        XCTAssertNil(stopped.value)
        XCTAssertNotNil(stopped.lingering)
    }

    // MARK: how often a host may make the device connect (push B5)

    func testAHostCannotMakeThePhoneDialItMoreThanTheBudgetAllows() {
        var history: [TimeInterval] = []
        var allowed = 0
        // A wake every 20 s for an hour.
        for i in 0..<180 {
            let spent = WakeBudget.spend(history: history, now: now + Double(i) * 20)
            history = spent.history
            if spent.allowed { allowed += 1 }
        }
        XCTAssertEqual(allowed, WakeBudget.limit)
        XCTAssertLessThanOrEqual(history.count, WakeBudget.limit * 2)
        // Once the window has passed, it may again.
        XCTAssertTrue(WakeBudget.spend(history: history, now: now + 2 * 3600 + 1).allowed)
        // A clock set back does not hand out more.
        XCTAssertFalse(WakeBudget.spend(history: history, now: now - 10).allowed)
    }

    // MARK: every claimed message is shown (push C2)

    func testOneWakeShowsTheNewestAndTheOthersBesideIt() {
        XCTAssertNil(WakePick.pick(ranks: []))
        let pick = WakePick.pick(ranks: [10, 30, 20])!
        XCTAssertEqual(pick.primary, 1)
        XCTAssertEqual(pick.extras, [2, 0])
        // Beyond what one wake shows, nothing is picked (and so nothing is claimed).
        let many = WakePick.pick(ranks: (0..<20).map(Int64.init))!
        XCTAssertEqual(many.primary, 19)
        XCTAssertEqual(many.extras.count, WakePick.maxExtras)
        XCTAssertFalse(many.extras.contains(0))
    }

    // MARK: the ledger cannot be flushed (push C3)

    func testUndecryptableRowsDoNotPushRealIdsOutOfTheAnnouncedLedger() {
        var announced: [String] = []
        var unsure: [String] = []
        announced = AnnouncedLedger.claim(["real-1"], in: announced).ledger
        // A member posts 1000 rows that do not decrypt; each wake records them as unsure.
        for i in 0..<1000 {
            unsure = AnnouncedLedger.adding(["junk-\(i)"], to: unsure, limit: AnnouncedLedger.unsureLimit)
        }
        XCTAssertEqual(unsure.count, AnnouncedLedger.unsureLimit)
        XCTAssertEqual(announced, ["real-1"])
        // The server serves the old message again: it is still known, so it is not announced.
        let again = NotificationDecision.scan(scope: "channel:c", rows: [.init(messageId: "real-1", authorId: "u", unreadable: false, notifies: true)],
                                              senders: [:], announced: Set(announced).union(unsure))
        XCTAssertNil(again.announce)
    }

    // MARK: who the user talks to is not kept in a plist (push B4)

    func testConversationLabelsAreKeptOnlyWhereTheExtensionMayUseThem() {
        XCTAssertTrue(NotificationKeep.keepsConversationLabels(appLock: false, previews: true))
        XCTAssertFalse(NotificationKeep.keepsConversationLabels(appLock: true, previews: true))
        XCTAssertFalse(NotificationKeep.keepsConversationLabels(appLock: false, previews: false))
        // In the Keychain they follow the cache key: readable on a locked phone only on iOS
        // with app lock off and previews on, and never more than `whenUnlocked` otherwise.
        for account in [KeyAccess.notifNamesPrefix + "w", KeyAccess.notifSendersPrefix + "w"] {
            XCTAssertTrue(KeyAccess.moves(account))
            XCTAssertEqual(KeyAccess.accessibility(for: account, settings: .init(appLock: false, previews: true), platform: .iOS), .afterFirstUnlock)
            XCTAssertEqual(KeyAccess.accessibility(for: account, settings: .init(appLock: true, previews: true), platform: .iOS), .whenUnlocked)
            XCTAssertEqual(KeyAccess.accessibility(for: account, settings: .init(appLock: false, previews: false), platform: .iOS), .whenUnlocked)
            XCTAssertEqual(KeyAccess.accessibility(for: account, settings: .init(appLock: false, previews: true), platform: .macOS), .whenUnlocked)
        }
    }
}
