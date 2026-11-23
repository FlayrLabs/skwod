import XCTest

/// When the app sounds and notifies for a message (`MessageAlert`), and where a clicked
/// notification leads (`NotificationTarget`).
final class MessageAlertTests: XCTestCase {
    private typealias In = MessageAlert.Incoming
    private typealias Out = MessageAlert.Outcome

    func testTheChatOnScreenIsSilent() {
        XCTAssertEqual(MessageAlert.received(In(appActive: true, onScreen: true, now: 100)), .nothing)
    }

    func testInFrontAnotherChatIsTheAppsSoundAndASilentBanner() {
        let out = MessageAlert.received(In(appActive: true, onScreen: false, now: 100))
        XCTAssertEqual(out, Out(banner: true, bannerSound: false, inAppSound: true), "one sound, never two")
    }

    func testNotInFrontIsABannerWithSoundAndNoInAppSound() {
        // macOS: another app is focused (even if this chat is the one open in the window).
        let out = MessageAlert.received(In(appActive: false, onScreen: false, now: 100))
        XCTAssertEqual(out, Out(banner: true, bannerSound: true, inAppSound: false))
    }

    func testNeverForOwnBlockedMutedOrAlreadyAnnouncedMessages() {
        for silent in [In(fromSelf: true), In(blocked: true), In(muted: true), In(claimed: false)] {
            var m = silent
            XCTAssertEqual(MessageAlert.received(m), .nothing)
            m.appActive = true
            XCTAssertEqual(MessageAlert.received(m), .nothing)
        }
    }

    func testDoNotDisturbInterruptsWithNothing() {
        XCTAssertEqual(MessageAlert.received(In(doNotDisturb: true, appActive: true, now: 100)), .nothing)
        XCTAssertEqual(MessageAlert.received(In(doNotDisturb: true, appActive: false, now: 100)), .nothing)
    }

    func testTheSoundSwitchSilencesBothSoundsAndKeepsTheBanner() {
        XCTAssertEqual(MessageAlert.received(In(appActive: true, soundOn: false, now: 100)), Out(banner: true))
        XCTAssertEqual(MessageAlert.received(In(appActive: false, soundOn: false, now: 100)), Out(banner: true))
    }

    func testABurstIsOneSound() {
        var m = In(appActive: true, lastSoundAt: 100, now: 100.4)
        XCTAssertEqual(MessageAlert.received(m), Out(banner: true), "0.4 s after the last one: shown, not sounded")
        m.now = 101
        XCTAssertTrue(MessageAlert.received(m).inAppSound)
        m.now = 50
        XCTAssertTrue(MessageAlert.received(m).inAppSound, "a clock that went backwards never mutes for good")
    }

    func testTheSentSoundIsForAcceptedComposedMessagesOnly() {
        XCTAssertTrue(MessageAlert.sentSound(composedWaiting: 1, accepted: 1, soundOn: true))
        XCTAssertFalse(MessageAlert.sentSound(composedWaiting: 1, accepted: 0, soundOn: true), "queued, not accepted yet: not on tap")
        XCTAssertFalse(MessageAlert.sentSound(composedWaiting: 0, accepted: 3, soundOn: true), "likes and game moves the app sent by itself")
        XCTAssertFalse(MessageAlert.sentSound(composedWaiting: 2, accepted: 2, soundOn: false))
    }

    func testAClickedNotificationLeadsOnlyToAWellFormedConversation() {
        let target = NotificationTarget(workspaceId: "w1", scope: "dm:0123456789")
        XCTAssertEqual(NotificationTarget(userInfo: target.userInfo), target)
        XCTAssertNil(NotificationTarget(userInfo: [:]))
        XCTAssertNil(NotificationTarget(userInfo: [NotificationTarget.workspaceKey: "w1", NotificationTarget.scopeKey: "skwod.locked"]))
        XCTAssertNil(NotificationTarget(userInfo: [NotificationTarget.workspaceKey: "", NotificationTarget.scopeKey: "channel:0123456789"]))
        XCTAssertNil(NotificationTarget(userInfo: [NotificationTarget.workspaceKey: "w1", NotificationTarget.scopeKey: 7]))
    }

    func testARedactedNotificationCarriesOnlyAnOpaqueTokenThatThisRunCanResolve() {
        var tokens = NotificationTokens()
        let target = NotificationTarget(workspaceId: "workspace-1", scope: "dm:conversation-1")
        // Previews on, no app lock: the target itself.
        XCTAssertEqual(tokens.userInfo(for: target, redacted: false, now: 1000), target.userInfo)
        // App lock on / previews off: nothing of the skwod or the conversation is written.
        let info = tokens.userInfo(for: target, redacted: true, now: 1000, random: { "tok-A" })
        XCTAssertEqual(info, [NotificationTokens.key: "tok-A"])
        XCTAssertNil(NotificationTarget(userInfo: info))
        XCTAssertFalse(info.values.contains { $0.contains("workspace-1") || $0.contains("conversation-1") })
        // On tap: this run knows it; another run (or a made-up token) does not; it expires.
        XCTAssertEqual(tokens.resolve("tok-A", now: 2000), target)
        XCTAssertNil(tokens.resolve("tok-B", now: 2000))
        XCTAssertNil(tokens.resolve("", now: 2000))
        XCTAssertNil(NotificationTokens().resolve("tok-A", now: 2000))
        XCTAssertNil(tokens.resolve("tok-A", now: 1000 + NotificationTokens.lifetime + 1))
        // Bounded: old ones fall out.
        for i in 0..<(NotificationTokens.limit + 5) { _ = tokens.userInfo(for: target, redacted: true, now: 3000, random: { "t\(i)" }) }
        XCTAssertNil(tokens.resolve("tok-A", now: 3000))
        XCTAssertEqual(tokens.resolve("t\(NotificationTokens.limit + 4)", now: 3000), target)
    }

    /// Every notification the apps post goes through `NotificationShaper`. Redacted (app lock
    /// on, or previews off), NOTHING in it — text, thread, request identifier, userInfo —
    /// holds a workspace, server, channel or conversation id.
    func testARedactedNotificationHoldsNoIdAnywhere() {
        let ids = ["ws-1111", "srv-2222", "chan-3333", "conv-4444"]
        let posts: [(thread: String, id: String, target: NotificationTarget?)] = [
            ("channel:chan-3333", "msg-chan-3333", NotificationTarget(workspaceId: "ws-1111", scope: "channel:chan-3333")),
            ("dm:conv-4444", "plain-uuid", NotificationTarget(workspaceId: "ws-1111", scope: "dm:conv-4444")),
            ("dm:conv-4444", "invite-conv-4444", nil),
            ("join:srv-2222", "joined-srv-2222", nil),
            ("session", "signed-out-ws-1111", nil),
        ]
        for (appLock, previews) in [(true, true), (false, false), (true, false)] {
            var shaper = NotificationShaper()
            var n = 0
            for p in posts {
                let s = shaper.shape(title: "#general", body: "New message", text: .personal, thread: p.thread, identifier: p.id, target: p.target,
                                     appLock: appLock, previews: previews, now: 1000, random: { n += 1; return "r\(n)" })
                let everything = [s.title, s.body, s.thread, s.identifier] + s.userInfo.keys + s.userInfo.values
                for id in ids {
                    XCTAssertFalse(everything.contains { $0.contains(id) }, "\(id) in \(everything) (appLock \(appLock), previews \(previews))")
                }
                if appLock { XCTAssertEqual([s.title, s.body, s.thread], ["Skwod", "New message", "skwod.locked"]) }
            }
        }
    }

    func testRedactedNotificationsAboutTheSameThingStillReplaceAndGroup() {
        var shaper = NotificationShaper()
        var n = 0
        let next = { () -> String in n += 1; return "r\(n)" }
        let target = NotificationTarget(workspaceId: "ws-1111", scope: "channel:chan-3333")
        let a = shaper.shape(title: "t", body: "b", text: .personal, thread: "channel:chan-3333", identifier: "msg-chan-3333", target: target, appLock: false, previews: false, now: 1, random: next)
        let b = shaper.shape(title: "t", body: "b", text: .personal, thread: "channel:chan-3333", identifier: "msg-chan-3333", target: target, appLock: false, previews: false, now: 2, random: next)
        let other = shaper.shape(title: "t", body: "b", text: .personal, thread: "channel:chan-9999", identifier: "msg-chan-9999", target: nil, appLock: false, previews: false, now: 3, random: next)
        XCTAssertEqual(a.identifier, b.identifier, "the later one replaces the earlier")
        XCTAssertEqual(a.thread, b.thread, "grouped by conversation")
        XCTAssertNotEqual(a.identifier, other.identifier)
        XCTAssertNotEqual(a.thread, other.thread)
        XCTAssertEqual(shaper.knownStandIn(for: "thread|channel:chan-3333"), a.thread, "found again to clear on read")
        // The click still leads there — through the token, in this run.
        XCTAssertEqual(shaper.target(forToken: b.userInfo[NotificationTokens.key] ?? "", now: 5), target)
    }

    func testWithPreviewsOnAndNoLockNothingIsRedacted() {
        var shaper = NotificationShaper()
        let target = NotificationTarget(workspaceId: "ws-1111", scope: "dm:conv-4444")
        let s = shaper.shape(title: "bob", body: "hi", text: .personal, thread: "dm:conv-4444", identifier: "x", target: target, appLock: false, previews: true, now: 1)
        XCTAssertEqual(s, .init(title: "bob", body: "hi", thread: "dm:conv-4444", identifier: "x", userInfo: target.userInfo))
    }

    /// A caller that passes a name and the message text gets neither into the notification
    /// with previews off, or with app lock on — the shaper decides, not the caller.
    func testANamedTitleAndBodyAreGenericWithPreviewsOffAndWithAppLockOn() {
        for (appLock, previews) in [(false, false), (true, true), (true, false)] {
            var shaper = NotificationShaper()
            let s = shaper.shape(title: "Dana Whitfield", body: "meet me at 8 by the fountain", text: .personal, thread: "dm:conv-4444",
                                 identifier: "x", target: nil, appLock: appLock, previews: previews, now: 1)
            XCTAssertEqual(s.title, "Skwod", "appLock \(appLock), previews \(previews)")
            XCTAssertEqual(s.body, "New message")
        }
        // Previews on, no lock: as written.
        var shaper = NotificationShaper()
        var s = shaper.shape(title: "Dana Whitfield", body: "meet me at 8", text: .personal, thread: "dm:c", identifier: "x", target: nil, appLock: false, previews: true, now: 1)
        XCTAssertEqual([s.title, s.body], ["Dana Whitfield", "meet me at 8"])
        // A sentence of the app's own that names nobody survives previews-off, not app lock.
        s = shaper.shape(title: "Link a device?", body: "A new device is asking to join your account.", text: .fixed, thread: "account", identifier: "link-request", target: nil, appLock: false, previews: false, now: 1)
        XCTAssertEqual(s.title, "Link a device?")
        s = shaper.shape(title: "Link a device?", body: "A new device is asking to join your account.", text: .fixed, thread: "account", identifier: "link-request", target: nil, appLock: true, previews: true, now: 1)
        XCTAssertEqual([s.title, s.body], ["Skwod", "New message"])
    }
}
