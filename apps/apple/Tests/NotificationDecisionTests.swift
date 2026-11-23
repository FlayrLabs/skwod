import XCTest

/// What the notification extension does with a wake (`NotificationDecision`), and how the app
/// and the extension keep from announcing one message twice (`AnnouncedLedger`).
///
/// The rule under test: the passive "New activity" line is only for a wake that was positively
/// about nothing the user needs to see. Build 44 used it whenever nothing was announceable.
final class NotificationDecisionTests: XCTestCase {
    private typealias Row = NotificationDecision.Row
    private let senders: [String: [String]] = ["dm:dm1": ["bob"], "dm:g1": ["carol", "dave"], "dm:ignored": []]

    private func verdict(_ scans: [NotificationDecision.Scan], complete: Bool = true) -> NotificationDecision.Verdict {
        NotificationDecision.verdict(announces: scans.contains { $0.announce != nil }, unsure: scans.contains { $0.unsure },
                                     lookedAtAny: !scans.isEmpty, complete: complete)
    }

    func testARealMessageIsAnnouncedInADirectAGroupAndAChannelConversation() {
        let dm = NotificationDecision.scan(scope: "dm:dm1", rows: [Row(messageId: "m1", authorId: "bob")], senders: senders)
        XCTAssertEqual(dm, .init(announce: 0))
        // The newest row by a member wins; a like after it does not hide it.
        let group = NotificationDecision.scan(scope: "dm:g1", rows: [
            Row(messageId: "m1", authorId: "carol"), Row(messageId: "m2", authorId: "dave"), Row(messageId: "m3", authorId: "carol", notifies: false),
        ], senders: senders)
        XCTAssertEqual(group, .init(announce: 1))
        // Channels are not sender-checked — also for build-43 data that has no sender sets.
        let channel = NotificationDecision.scan(scope: "channel:c1", rows: [Row(messageId: "m1", authorId: "anyone")], senders: nil)
        XCTAssertEqual(channel, .init(announce: 0))
        XCTAssertEqual(verdict([dm, group, channel]), .announce)
    }

    func testOnlyLikesAndTheLikeAreTheQuietLine() {
        let scans = [
            NotificationDecision.scan(scope: "channel:c1", rows: [Row(messageId: "l1", authorId: "bob", notifies: false)], senders: senders),
            NotificationDecision.scan(scope: "dm:dm1", rows: [], senders: senders),
        ]
        XCTAssertEqual(verdict(scans), .quiet)
        // A second (trailing) wake after everything was announced: read it all, nothing new.
        XCTAssertEqual(verdict([NotificationDecision.scan(scope: "dm:dm1", rows: [], senders: senders)]), .quiet)
    }

    func testAConversationThatCouldNotBeReadKeepsTheVisibleBanner() {
        // Build 44: one channel fetch failed, the others had nothing → "New activity", passive.
        let scans = [
            NotificationDecision.scan(scope: "channel:c1", rows: nil, senders: senders),
            NotificationDecision.scan(scope: "dm:dm1", rows: [], senders: senders),
        ]
        XCTAssertTrue(scans[0].unsure)
        XCTAssertEqual(verdict(scans), .generic)
    }

    func testAMessageThisDeviceCouldNotDecryptKeepsTheVisibleBanner() {
        let scan = NotificationDecision.scan(scope: "dm:dm1", rows: [Row(messageId: "m1", authorId: "bob", unreadable: true, notifies: false)], senders: senders)
        XCTAssertEqual(scan, .init(announce: nil, unsure: true, unsureIds: ["m1"]))
        XCTAssertEqual(verdict([scan]), .generic)
    }

    func testASenderTheAppHasNotVouchedForIsNeverShownAndNeverWavedThroughAsNothing() {
        // Build-43 data / updated and not opened since: no sender sets at all.
        var scan = NotificationDecision.scan(scope: "dm:g1", rows: [Row(messageId: "m1", authorId: "carol")], senders: nil)
        XCTAssertEqual(scan, .init(announce: nil, unsure: true, unsureIds: ["m1"]))
        // A conversation the app has no set for (it started after the app last ran).
        scan = NotificationDecision.scan(scope: "dm:new", rows: [Row(messageId: "m1", authorId: "bob")], senders: senders)
        XCTAssertEqual(scan, .init(announce: nil, unsure: true, unsureIds: ["m1"]))
        // Someone who joined the group since, or a ghost the server put there: their text is
        // never shown under the group's title — and the wake stays a visible "New message".
        scan = NotificationDecision.scan(scope: "dm:g1", rows: [Row(messageId: "m1", authorId: "erin")], senders: senders)
        XCTAssertEqual(scan, .init(announce: nil, unsure: true, unsureIds: ["m1"]))
        XCTAssertEqual(verdict([scan]), .generic)
        scan = NotificationDecision.scan(scope: "dm:g1", rows: [Row(messageId: "m1", authorId: nil)], senders: senders)
        XCTAssertTrue(scan.unsure)
        // A member's row is still announced when a ghost wrote after it.
        scan = NotificationDecision.scan(scope: "dm:g1", rows: [Row(messageId: "m1", authorId: "carol"), Row(messageId: "m2", authorId: "ghost")], senders: senders)
        XCTAssertEqual(scan.announce, 0)
        // Their likes are background traffic like anyone's.
        scan = NotificationDecision.scan(scope: "dm:g1", rows: [Row(messageId: "m1", authorId: "erin", notifies: false)], senders: senders)
        XCTAssertEqual(scan, .init())
    }

    func testARowThatCouldNotBeShownIsOneBannerNotOnePerLaterWake() {
        // Wake 1: a row this device could not decrypt, and one by someone not in the group.
        let rows = [Row(messageId: "u1", authorId: "bob", unreadable: true, notifies: false), Row(messageId: "g1", authorId: "erin")]
        var scan = NotificationDecision.scan(scope: "dm:g1", rows: rows, senders: senders)
        XCTAssertEqual(scan.unsureIds, ["u1", "g1"])
        XCTAssertEqual(verdict([scan]), .generic)
        // The extension records them with the banner it shows…
        let ledger = Set(AnnouncedLedger.adding(scan.unsureIds, to: []))
        // …so wake 2 (only a like arrived; or the trailing wake of the burst) is quiet again.
        scan = NotificationDecision.scan(scope: "dm:g1", rows: rows + [Row(messageId: "l1", authorId: "carol", notifies: false)], senders: senders, announced: ledger)
        XCTAssertEqual(scan, .init())
        XCTAssertEqual(verdict([scan]), .quiet)
    }

    func testAConversationTheAppShowsNothingOfStaysQuiet() {
        // An invitation or an ignored group: its (empty) sender set says "announce nothing".
        let scan = NotificationDecision.scan(scope: "dm:ignored", rows: [Row(messageId: "m1", authorId: "mallory")], senders: senders)
        XCTAssertEqual(scan, .init())
        XCTAssertEqual(verdict([scan]), .quiet)
    }

    func testARunThatWasCutShortOrReadNothingKeepsTheVisibleBanner() {
        let nothingNew = NotificationDecision.scan(scope: "dm:dm1", rows: [], senders: senders)
        XCTAssertEqual(verdict([nothingNew], complete: false), .generic, "the app asked for the cache / time ran out")
        XCTAssertEqual(verdict([]), .generic, "no conversation is known to the extension")
    }

    func testAMessageAlreadyAnnouncedByEitherProcessIsNotAnnouncedAgain() {
        // Delivered in-band and announced by the app; the push wake for it arrives after.
        let ledger = Set(AnnouncedLedger.adding(["m1"], to: []))
        var scan = NotificationDecision.scan(scope: "dm:dm1", rows: [Row(messageId: "m1", authorId: "bob")], senders: senders, announced: ledger)
        XCTAssertEqual(scan, .init())
        XCTAssertEqual(verdict([scan]), .quiet, "at most one visible notification per message")
        // A later message in the same conversation is.
        scan = NotificationDecision.scan(scope: "dm:dm1", rows: [Row(messageId: "m1", authorId: "bob"), Row(messageId: "m2", authorId: "bob")], senders: senders, announced: ledger)
        XCTAssertEqual(scan.announce, 1)
    }

    func testTheLedgerKeepsTheNewestIdsOnceEach() {
        var ids = AnnouncedLedger.adding(["a", "b", "a", ""], to: ["a"])
        XCTAssertEqual(ids, ["a", "b"])
        ids = AnnouncedLedger.adding((0..<10).map { "m\($0)" }, to: ids, limit: 4)
        XCTAssertEqual(ids, ["m6", "m7", "m8", "m9"])
    }

    func testGarbageInAnIgnoredConversationIsNeverABanner() {
        // Ciphertext nobody can read, in a group the user ignored or declined: checked FIRST.
        let scan = NotificationDecision.scan(scope: "dm:ignored", rows: [Row(messageId: "x1", authorId: "mallory", unreadable: true, notifies: false)], senders: senders)
        XCTAssertEqual(scan, .init())
        XCTAssertEqual(verdict([scan]), .quiet)
    }

    func testTwoProcessesClaimingOneMessageGetItOnce() {
        // The app and the extension both read the message; each claims under the lock.
        let first = AnnouncedLedger.claim(["m1", "m2"], in: [])
        XCTAssertEqual(first.claimed, ["m1", "m2"])
        let second = AnnouncedLedger.claim(["m2", "m3", "m3", ""], in: first.ledger)
        XCTAssertEqual(second.claimed, ["m3"], "m2 was taken; nothing is claimed twice")
        XCTAssertEqual(second.ledger, ["m1", "m2", "m3"])
        XCTAssertTrue(AnnouncedLedger.claim(["m1"], in: second.ledger).claimed.isEmpty)
    }

    func testBannerSoundsAreCoalescedOnlyWithinAShortBurst() {
        XCTAssertTrue(SoundBurst.sounds(lastSoundAt: 0, now: 1000), "the first one is heard")
        XCTAssertFalse(SoundBurst.sounds(lastSoundAt: 1000, now: 1002), "the same conversation, two seconds on: shown, not sounded again")
        XCTAssertTrue(SoundBurst.sounds(lastSoundAt: 1000, now: 1005), "five seconds on it sounds again — not once a minute")
        XCTAssertTrue(SoundBurst.sounds(lastSoundAt: 1000, now: 1021), "the next message twenty seconds later is heard")
        // Another conversation has its own key, so its `lastSoundAt` is 0: always heard.
        XCTAssertTrue(SoundBurst.sounds(lastSoundAt: 0, now: 1001))
        XCTAssertTrue(SoundBurst.sounds(lastSoundAt: 2000, now: 1000), "a clock that went backwards never mutes for good")
    }

    func testTheServerIsToldAwayOnlyWhenTheAppReallyIs() {
        XCTAssertEqual(PushPresence.onPhase(.active, inCall: false), .active)
        XCTAssertEqual(PushPresence.onPhase(.inactive, inCall: false), .backgroundAfter(1.5), "Control Center, the switcher, Face ID: not yet")
        XCTAssertEqual(PushPresence.onPhase(.background, inCall: false), .background)
        XCTAssertEqual(PushPresence.onPhase(.locked, inCall: false), .background)
        // A call keeps the process and its socket: it stays in-band.
        for phase in [PushPresence.Phase.inactive, .background, .locked] {
            XCTAssertEqual(PushPresence.onPhase(phase, inCall: true), .keep)
        }
        XCTAssertEqual(PushPresence.onPhase(.active, inCall: true), .active)
    }

    // MARK: which keychain class each secret gets (`KeyAccess`)

    func testTheCacheKeyIsReadableWhileLockedOnlyWhereTheExtensionMayDecrypt() {
        typealias S = KeyAccess.Settings
        let key = "cache-key-0123abcd"
        // The whole matrix: platform × app lock × previews.
        let expected: [(KeyAccess.Platform, Bool, Bool, KeyAccess.Class)] = [
            (.iOS, false, true, .afterFirstUnlock),    // the one case: a banner may show text
            (.iOS, true, true, .whenUnlocked),         // app lock: the extension never opens the cache
            (.iOS, false, false, .whenUnlocked),       // previews off: nothing decrypted is shown
            (.iOS, true, false, .whenUnlocked),
            (.macOS, false, true, .whenUnlocked),      // no extension on the Mac
            (.macOS, true, true, .whenUnlocked),
            (.macOS, false, false, .whenUnlocked),
            (.macOS, true, false, .whenUnlocked),
        ]
        for (platform, appLock, previews, cls) in expected {
            XCTAssertEqual(KeyAccess.accessibility(for: key, settings: S(appLock: appLock, previews: previews), platform: platform), cls,
                           "\(platform) appLock \(appLock) previews \(previews)")
        }
    }

    func testTheWorkspaceListStaysAsItWasAndEverythingElseIsWhenUnlocked() {
        typealias S = KeyAccess.Settings
        for platform in [KeyAccess.Platform.iOS, .macOS] {
            for settings in [S(appLock: false, previews: true), S(appLock: true, previews: false)] {
                // A call push on a locked phone needs the session to ask who is ringing.
                XCTAssertEqual(KeyAccess.accessibility(for: "workspaces", settings: settings, platform: platform), .afterFirstUnlock)
                for other in ["owner-credentials", "contacts-w1", "probe", "", "cache-keyX", "workspaces2"] {
                    XCTAssertEqual(KeyAccess.accessibility(for: other, settings: settings, platform: platform), .whenUnlocked, other)
                }
            }
        }
    }

    func testChangingAppLockOrPreviewsMovesTheCacheKeysBothWays() {
        typealias S = KeyAccess.Settings
        let open = S(appLock: false, previews: true)
        XCTAssertTrue(KeyAccess.cacheKeysMove(from: open, to: S(appLock: true, previews: true), platform: .iOS), "app lock turned on")
        XCTAssertTrue(KeyAccess.cacheKeysMove(from: S(appLock: true, previews: true), to: open, platform: .iOS), "…and off again")
        XCTAssertTrue(KeyAccess.cacheKeysMove(from: open, to: S(appLock: false, previews: false), platform: .iOS), "previews turned off")
        XCTAssertTrue(KeyAccess.cacheKeysMove(from: S(appLock: false, previews: false), to: open, platform: .iOS))
        XCTAssertFalse(KeyAccess.cacheKeysMove(from: S(appLock: true, previews: true), to: S(appLock: true, previews: false), platform: .iOS))
        XCTAssertFalse(KeyAccess.cacheKeysMove(from: open, to: S(appLock: true, previews: false), platform: .macOS), "nothing ever moves on the Mac")
    }

    // MARK: mutes (`MuteList`)

    func testAMutedConversationIsMutedUntilItsTimeRunsOut() {
        var mutes = MuteList()
        mutes.mute("dm:c1", for: .hour, now: 1000)
        XCTAssertTrue(mutes.isMuted(scope: "dm:c1", now: 1000))
        XCTAssertTrue(mutes.isMuted(scope: "dm:c1", now: 1000 + 3599))
        XCTAssertFalse(mutes.isMuted(scope: "dm:c1", now: 1000 + 3600), "expiry is automatic")
        XCTAssertFalse(mutes.isMuted(scope: "dm:c2", now: 1000), "another conversation is not")
        mutes.mute("channel:x", for: .eightHours, now: 1000)
        XCTAssertTrue(mutes.isMuted(scope: "channel:x", now: 1000 + 8 * 3600 - 1))
        XCTAssertFalse(mutes.isMuted(scope: "channel:x", now: 1000 + 8 * 3600))
        mutes.mute("channel:y", for: .day, now: 1000)
        XCTAssertTrue(mutes.isMuted(scope: "channel:y", now: 1000 + 24 * 3600 - 1))
        XCTAssertFalse(mutes.isMuted(scope: "channel:y", now: 1000 + 24 * 3600))
    }

    func testUntilIUnmuteLastsAndUnmuteEndsIt() {
        var mutes = MuteList()
        mutes.mute("dm:c1", for: .forever, now: 1000)
        XCTAssertTrue(mutes.isMuted(scope: "dm:c1", now: 1000 + 10 * 365 * 24 * 3600))
        mutes.unmute("dm:c1")
        XCTAssertFalse(mutes.isMuted(scope: "dm:c1", now: 1001))
        // Muting again replaces what was there; expired entries are dropped on a change.
        mutes.mute("dm:old", for: .hour, now: 1000)
        mutes.mute("dm:c1", for: .hour, now: 9000)
        XCTAssertEqual(Set(mutes.conversations.keys), ["dm:c1"])
    }

    func testAMutedSkwodMutesEveryConversationAndItsCallsAMutedConversationDoesNot() {
        var mutes = MuteList()
        mutes.mute("dm:c1", for: .hour, now: 1000)
        XCTAssertTrue(mutes.callsRing(now: 1000), "a call still rings when only a conversation is muted")
        mutes.mute(MuteList.skwod, for: .hour, now: 1000)
        XCTAssertTrue(mutes.isMuted(scope: "channel:anything", now: 1000))
        XCTAssertFalse(mutes.callsRing(now: 1000))
        XCTAssertTrue(mutes.callsRing(now: 1000 + 3600), "…and again once the skwod's mute has run out")
        XCTAssertFalse(mutes.isMuted(scope: "channel:anything", now: 1000 + 3600))
        // Stored apart: the conversation list, and the skwod's time.
        XCTAssertEqual(Set(mutes.conversations.keys), ["dm:c1"])
        XCTAssertEqual(mutes.skwodUntil, 1000 + 3600)
    }

    func testAMutedConversationMakesNoSoundAndNoBanner() {
        var mutes = MuteList()
        mutes.mute("dm:c1", for: .hour, now: 1000)
        for active in [true, false] {
            let muted = MessageAlert.received(.init(muted: mutes.isMuted(scope: "dm:c1", now: 1500), appActive: active, now: 1500))
            XCTAssertEqual(muted, .nothing)
            let other = MessageAlert.received(.init(muted: mutes.isMuted(scope: "dm:c2", now: 1500), appActive: active, now: 1500))
            XCTAssertTrue(other.banner)
        }
    }

    func testTheMuteItemsFollowTheKeyRules() {
        typealias S = KeyAccess.Settings
        let open = S(appLock: false, previews: true), locked = S(appLock: true, previews: true)
        // The conversation mutes: readable on a locked phone only where the extension decrypts.
        XCTAssertEqual(KeyAccess.accessibility(for: "mutes-w1", settings: open, platform: .iOS), .afterFirstUnlock)
        XCTAssertEqual(KeyAccess.accessibility(for: "mutes-w1", settings: locked, platform: .iOS), .whenUnlocked)
        XCTAssertEqual(KeyAccess.accessibility(for: "mutes-w1", settings: open, platform: .macOS), .whenUnlocked)
        XCTAssertTrue(KeyAccess.moves("mutes-w1"))
        // The skwod's own mute (a time): wherever the extension runs.
        XCTAssertEqual(KeyAccess.accessibility(for: "mute-skwod-w1", settings: locked, platform: .iOS), .afterFirstUnlock)
        XCTAssertEqual(KeyAccess.accessibility(for: "mute-skwod-w1", settings: open, platform: .macOS), .whenUnlocked)
        XCTAssertFalse(KeyAccess.moves("mute-skwod-w1"))
    }
}
