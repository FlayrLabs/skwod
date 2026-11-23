import XCTest

/// Build 46: logging in without a code, the code field, what a refused session means, and one
/// entry per skwod and account.
final class Build46Tests: XCTestCase {
    private let key = "ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1u"   // 52 chars of z-base-32

    // MARK: log-in entry

    func testBareHostKeyBecomesAppLink() {
        XCTAssertEqual(key.count, 52)
        XCTAssertTrue(LoginEntry.isBareNodeId(key))
        XCTAssertEqual(LoginEntry.canonical("  \(key)\n"), "skwod://join/\(key)")
        XCTAssertEqual(LoginEntry.canonical(key.uppercased()), "skwod://join/\(key)")
        XCTAssertEqual(LoginEntry.canonical("\(key)#SKWD-AB12-CD34"), "skwod://join/\(key)#SKWD-AB12-CD34")
        XCTAssertEqual(LoginEntry.canonical("\(key).AB12CD34"), "skwod://join/\(key)#AB12CD34")
    }

    func testOtherEntriesPassThroughUntouched() {
        // The share link keeps its fragment: the host key itself is after the "#".
        let share = "https://skwod.io/join#\(key).SKWD-AB12-CD34"
        XCTAssertEqual(LoginEntry.canonical(share), share)
        XCTAssertEqual(LoginEntry.canonical("skwod://join/\(key)"), "skwod://join/\(key)")
        XCTAssertEqual(LoginEntry.canonical("chat.example.com"), "chat.example.com")
        XCTAssertFalse(LoginEntry.isBareNodeId(String(key.dropLast())))
        XCTAssertFalse(LoginEntry.isBareNodeId(String(key.dropLast()) + "0"))   // 0 is not z-base-32
        XCTAssertTrue(LoginEntry.isBareNodeId(String(repeating: "ab", count: 32)))   // hex form
    }

    func testLogInNeverSendsACode() {
        XCTAssertNil(LoginEntry.codeToSend("SKWD-AB12-CD34", mode: .logIn))
        XCTAssertNil(LoginEntry.codeToSend(nil, mode: .logIn))
        XCTAssertEqual(LoginEntry.codeToSend("skwd ab12 cd34", mode: .createAccount), "SKWD-AB12-CD34")
        XCTAssertNil(LoginEntry.codeToSend(nil, mode: .createAccount))
        XCTAssertNil(LoginEntry.codeToSend("  - ", mode: .createAccount))
    }

    func testPastingALinkNeverUndoesLogIn() {
        XCTAssertEqual(LoginEntry.modeAfterAdopting(hasCode: true, userChoseLogIn: true), .logIn)
        XCTAssertEqual(LoginEntry.modeAfterAdopting(hasCode: true, userChoseLogIn: false), .createAccount)
        XCTAssertEqual(LoginEntry.modeAfterAdopting(hasCode: false, userChoseLogIn: false), .logIn)
    }

    // MARK: code field

    func testJoinCodeNormaliser() {
        XCTAssertEqual(JoinCode.normalize("skwd-ab12-cd34"), "SKWD-AB12-CD34")
        XCTAssertEqual(JoinCode.normalize("SKWDAB12CD34"), "SKWD-AB12-CD34")
        XCTAssertEqual(JoinCode.normalize(" skwd ab12 - cd34\n"), "SKWD-AB12-CD34")
        XCTAssertEqual(JoinCode.normalize("ab12-cd34"), "AB12CD34")
        XCTAssertEqual(JoinCode.normalize("ab12 cd34"), "AB12CD34")
        XCTAssertEqual(JoinCode.normalize(""), "")
        // Something else is left as typed (upper-cased), never truncated.
        XCTAssertEqual(JoinCode.normalize("abc_defghijk"), "ABC_DEFGHIJK")
    }

    // MARK: refused sessions

    private func decide(_ text: String, update: Bool = false, signedOut: Bool = false,
                        registered: Bool = true, bound: Bool = false) -> SessionRefusal {
        SessionRefusal.decide(.init(errorText: text, updateRequired: update, sessionSignedOut: signedOut,
                                    isRegisteredDevice: registered, bindSucceeded: bound))
    }

    func testOnlyARealSignOutSignsOut() {
        XCTAssertEqual(decide("Engine(detail: \"api: status 401\")", signedOut: true), .signedOut)
        // A 401 on one request with /auth/me still fine: keep the session.
        XCTAssertEqual(decide("Engine(detail: \"api: status 401\")"), .transient)
        XCTAssertEqual(decide("Engine(detail: \"timed out\")"), .transient)
        XCTAssertEqual(decide("Engine(detail: \"status 403: forbidden\")"), .transient)
    }

    func testBindRequired() {
        let refused = "Engine(detail: \"api status 403: {\\\"error\\\":\\\"device bind required\\\"}\")"
        // A second device straight after log-in is not a device yet: link it — never "update".
        XCTAssertEqual(decide(refused, registered: false), .linkDevice)
        XCTAssertEqual(decide(refused, registered: false, bound: true), .linkDevice)
        XCTAssertEqual(decide(refused), .bindThenRetry)
        // Still refused right after a successful bind: the host wants what this build can't give.
        XCTAssertEqual(decide(refused, bound: true), .updateApp)
        // Even when /auth/me said 401 too, the bind answer is what decides.
        XCTAssertEqual(decide(refused, signedOut: true), .bindThenRetry)
    }

    func testUpdateAndDeviceStates() {
        XCTAssertEqual(decide("UpdateRequired(detail: \"x\")", update: true), .updateApp)
        XCTAssertEqual(decide("Engine(detail: \"http status 426: {\\\"error\\\":\\\"update required\\\"}\")"), .updateApp)
        XCTAssertEqual(decide("status 403 device removed"), .deviceStopped)
        XCTAssertEqual(decide("status 409 device superseded"), .deviceStopped)
        XCTAssertEqual(decide("status 403 device link required"), .linkDevice)
    }

    func testOnlyTheTypedErrorOrA426StatusMeansUpdate() {
        // The status the core writes, read where it writes it.
        XCTAssertEqual(SessionRefusal.httpStatus("Engine(detail: \"http status 426: x\")"), 426)
        XCTAssertEqual(SessionRefusal.httpStatus("http status 426"), 426)
        XCTAssertEqual(SessionRefusal.httpStatus("http status 403: {\"error\":\"http status 426\"}"), 403)
        XCTAssertNil(SessionRefusal.httpStatus("http status 4260: x"))
        XCTAssertNil(SessionRefusal.httpStatus("timed out after 426 ms"))
        // A "426" or "upgrade required" in the server's words is not one.
        XCTAssertEqual(decide("Engine(detail: \"http status 403: {\\\"error\\\":\\\"message 426 not found\\\"}\")"), .transient)
        XCTAssertEqual(decide("Engine(detail: \"http status 404: upgrade required\")"), .transient)
        XCTAssertEqual(decide("Engine(detail: \"http status 500: update required 426\")"), .transient)
        XCTAssertEqual(decide("Engine(detail: \"message 14260 not found\")"), .transient)
        XCTAssertEqual(decide("426"), .transient)
        // The typed error alone is enough, whatever its words.
        XCTAssertEqual(decide("UpdateRequired(detail: \"protocol 3 required\")", update: true), .updateApp)
    }

    // MARK: one entry per skwod and account

    private func entry(_ id: String, user: String = "u1", server: String = "skwod://join/a", node: String? = "a",
                       instance: String? = "inst", pinned: String? = "K", out: Bool = false) -> WorkspaceDedupe.Entry {
        .init(id: id, userId: user, server: server, nodeId: node, instanceId: instance, pinnedKey: pinned,
              signedOut: out, tokenIssuedAt: nil)
    }

    func testSameSkwodRules() {
        XCTAssertTrue(WorkspaceDedupe.sameSkwod(entry("1"), entry("2")))
        // Different host keys are different skwods, whatever they claim.
        XCTAssertFalse(WorkspaceDedupe.sameSkwod(entry("1"), entry("2", server: "skwod://join/b", node: "b")))
        // A server claiming another skwod's instance id AND pinned key is still not that skwod:
        // both are what the server said, never proof.
        let spoof = entry("2", server: "https://evil.example", node: nil)
        XCTAssertFalse(WorkspaceDedupe.sameSkwod(entry("1"), spoof))
        XCTAssertFalse(WorkspaceDedupe.sameSkwod(entry("1", server: "https://a", node: nil), spoof))
        XCTAssertTrue(WorkspaceDedupe.duplicated([entry("1"), spoof]).isEmpty)
        XCTAssertTrue(WorkspaceDedupe.droppableAtLaunch([entry("1"), entry("2", server: "https://evil.example", node: nil, out: true)]).isEmpty)
        // Same address, nothing else known.
        XCTAssertTrue(WorkspaceDedupe.sameSkwod(entry("1", server: "https://a", node: nil, instance: nil, pinned: nil),
                                                entry("2", server: "https://a", node: nil, instance: nil, pinned: nil)))
    }

    func testDeadDuplicateIsDroppedAtLaunchAndTheLiveOneKept() {
        let live = entry("live")
        let dead = entry("dead", out: true)
        XCTAssertEqual(WorkspaceDedupe.droppableAtLaunch([dead, live]), ["dead"])
        XCTAssertEqual(WorkspaceDedupe.duplicated([dead, live]), ["dead", "live"])
    }

    func testSameHttpsAddressIsOnlyMarkedNeverDropped() {
        let a = entry("1", server: "https://a", node: nil)
        let b = entry("2", server: "https://a", node: nil, out: true)
        XCTAssertEqual(WorkspaceDedupe.duplicated([a, b]), ["1", "2"])
        XCTAssertTrue(WorkspaceDedupe.droppableAtLaunch([a, b]).isEmpty)
    }

    // MARK: learned skwod names

    func testLearnedNamesAreCleanedAndCannotImpersonate() {
        XCTAssertNil(SkwodNameRule.acceptLearned("Weekend\nCrew", otherNames: []), "a newline is not allowed")
        XCTAssertEqual(SkwodNameRule.acceptLearned("  Weekend   Crew ", otherNames: []), "Weekend Crew")
        // Bidi overrides and zero-width characters are refused outright (host names).
        XCTAssertNil(SkwodNameRule.acceptLearned("Crew\u{202E}lab\u{200B}", otherNames: []))
        XCTAssertEqual(SkwodNameRule.acceptLearned(String(repeating: "x", count: 100), otherNames: [])?.count, SkwodNameRule.maxLength)
        XCTAssertNil(SkwodNameRule.acceptLearned("\u{200B}\u{202E}", otherNames: []))
        // Another entry's name, or a look-alike of it (digit 0), is refused.
        XCTAssertNil(SkwodNameRule.acceptLearned("Family", otherNames: ["family"]))
        XCTAssertNil(SkwodNameRule.acceptLearned("W0rk", otherNames: ["Work"]))
        // Reserved labels.
        XCTAssertNil(SkwodNameRule.acceptLearned("This Mac", otherNames: []))
        XCTAssertNil(SkwodNameRule.acceptLearned("My Skwod", otherNames: []))
        XCTAssertEqual(SkwodNameRule.acceptLearned("Book club", otherNames: ["Family"]), "Book club")
    }

    func testNothingDroppedWithoutALiveCopyOrForAnotherAccount() {
        // Both signed out, or both signed in: kept (the rail offers "Remove this duplicate").
        XCTAssertTrue(WorkspaceDedupe.droppableAtLaunch([entry("1", out: true), entry("2", out: true)]).isEmpty)
        XCTAssertTrue(WorkspaceDedupe.droppableAtLaunch([entry("1"), entry("2")]).isEmpty)
        // Another account on the same skwod has its own keys and cache: never a duplicate.
        let other = entry("2", user: "u2", out: true)
        XCTAssertTrue(WorkspaceDedupe.droppableAtLaunch([entry("1"), other]).isEmpty)
        XCTAssertTrue(WorkspaceDedupe.duplicated([entry("1"), other]).isEmpty)
        // A signed-out entry of a DIFFERENT skwod stays.
        XCTAssertTrue(WorkspaceDedupe.droppableAtLaunch([entry("1"), entry("2", server: "skwod://join/b", node: "b", out: true)]).isEmpty)
    }

    // MARK: server and skwod menus

    func testServerMenuByRole() {
        XCTAssertEqual(ServerMenuRule.items(role: .owner, channelsKnown: true), [.mute, .invite, .settings, .copyLink, .delete])
        XCTAssertEqual(ServerMenuRule.items(role: .admin, channelsKnown: true), [.mute, .invite, .settings, .copyLink, .leave])
        XCTAssertEqual(ServerMenuRule.items(role: .member, channelsKnown: true), [.mute, .invite, .copyLink, .leave])
        // Only the owner may delete; the owner can never "leave" (the server refuses it).
        XCTAssertFalse(ServerMenuRule.items(role: .admin, channelsKnown: true).contains(.delete))
        XCTAssertFalse(ServerMenuRule.items(role: .owner, channelsKnown: true).contains(.leave))
        XCTAssertEqual(ServerMenuRule.items(role: .member, channelsKnown: false), [.copyLink, .leave])
    }

    func testSkwodMenu() {
        // The instance owner, on screen.
        XCTAssertEqual(SkwodMenuRule.items(signedOut: false, isCurrent: true, isInstanceOwner: true, isDuplicate: false),
                       [.rename, .renameOnHost, .invite, .mute, .settings, .devices, .signOut])
        // A member, on screen: no skwod settings.
        XCTAssertEqual(SkwodMenuRule.items(signedOut: false, isCurrent: true, isInstanceOwner: false, isDuplicate: false),
                       [.rename, .invite, .mute, .devices, .signOut])
        // Another signed-in skwod: nothing that needs its client.
        XCTAssertEqual(SkwodMenuRule.items(signedOut: false, isCurrent: false, isInstanceOwner: false, isDuplicate: false),
                       [.rename, .mute, .signOut])
        // Signed out (and a duplicate): log in again, remove.
        XCTAssertEqual(SkwodMenuRule.items(signedOut: true, isCurrent: false, isInstanceOwner: false, isDuplicate: true),
                       [.logInAgain, .rename, .removeDuplicate, .removeFromDevice])
    }

    // MARK: staged attachments belong to one conversation

    func testStagedAttachmentsStayInTheirConversation() {
        XCTAssertTrue(StagingRule.belongs(startedFor: "chan-1", current: "chan-1"))
        // A drop that finishes after switching to another conversation — even one with the
        // same display name — is discarded.
        XCTAssertFalse(StagingRule.belongs(startedFor: "chan-1", current: "chan-2"))
        XCTAssertFalse(StagingRule.belongs(startedFor: "", current: ""))
        XCTAssertFalse(StagingRule.belongs(startedFor: "chan-1", current: ""))
    }

    // MARK: typing indicators

    func testTypingExpiresDedupesAndStaysInItsConversation() {
        var t = TypingState()
        let now = Date(timeIntervalSince1970: 1000)
        t.focus("channel:a")
        t.received(userId: "sam", topic: "channel:a", me: "me", blocked: [], audience: Self.channelA, enabled: true, now: now)
        t.received(userId: "sam", topic: "channel:a", me: "me", blocked: [], audience: Self.channelA, enabled: true, now: now.addingTimeInterval(1))
        XCTAssertEqual(t.active(now: now.addingTimeInterval(2)), ["sam"], "one entry per person")
        XCTAssertEqual(t.active(now: now.addingTimeInterval(5.9)), ["sam"], "refreshed at +1 s")
        XCTAssertEqual(t.active(now: now.addingTimeInterval(6.1)), [], "gone 5 s after the last event")
        // Their message ends it at once.
        t = TypingState(); t.focus("channel:a")
        t.received(userId: "robin", topic: "channel:a", me: "me", blocked: [], audience: Self.channelA, enabled: true, now: now)
        t.messageArrived(from: "robin")
        XCTAssertEqual(t.active(now: now), [])
        // Not mine, not a blocked user's, not another conversation's, not with the setting off.
        t.received(userId: "me", topic: "channel:a", me: "me", blocked: [], audience: Self.channelA, enabled: true, now: now)
        t.received(userId: "eve", topic: "channel:a", me: "me", blocked: ["eve"], audience: Self.channelA, enabled: true, now: now)
        t.received(userId: "kim", topic: "channel:b", me: "me", blocked: [], audience: Self.channelA, enabled: true, now: now)
        t.received(userId: "lee", topic: "channel:a", me: "me", blocked: [], audience: Self.channelA, enabled: false, now: now)
        XCTAssertEqual(t.active(now: now), [])
        // Switching conversation clears what was shown.
        t.received(userId: "sam", topic: "channel:a", me: "me", blocked: [], audience: Self.channelA, enabled: true, now: now)
        t.focus("dm:x")
        XCTAssertEqual(t.active(now: now), [])
    }

    private static let channelA = TypingAudience(conversationId: "a", members: ["sam", "robin", "me", "eve", "kim", "lee"])

    func testTypingShowsOnlyThisConversationsPeople() {
        let now = Date(timeIntervalSince1970: 1000)
        // A DM: only its peer.
        let dm = TypingAudience(conversationId: "d1", members: ["peer"])
        XCTAssertTrue(TypingAudience.accepts(userId: "peer", topic: "dm:d1", audience: dm))
        XCTAssertFalse(TypingAudience.accepts(userId: "stranger", topic: "dm:d1", audience: dm))
        // The audience of another conversation never lets anyone in here.
        XCTAssertFalse(TypingAudience.accepts(userId: "peer", topic: "dm:d2", audience: dm))
        XCTAssertFalse(TypingAudience.accepts(userId: "peer", topic: "d1", audience: dm))
        // Nothing known yet: nobody (fail closed).
        XCTAssertFalse(TypingAudience.accepts(userId: "peer", topic: "dm:d1", audience: nil))
        XCTAssertFalse(TypingAudience.accepts(userId: "peer", topic: "dm:", audience: .init(conversationId: "", members: ["peer"])))
        var t = TypingState()
        t.focus("dm:d1")
        t.received(userId: "stranger", topic: "dm:d1", me: "me", blocked: [], audience: dm, enabled: true, now: now)
        t.received(userId: "peer", topic: "dm:d1", me: "me", blocked: [], audience: nil, enabled: true, now: now)
        XCTAssertEqual(t.active(now: now), [])
        t.received(userId: "peer", topic: "dm:d1", me: "me", blocked: [], audience: dm, enabled: true, now: now)
        XCTAssertEqual(t.active(now: now), ["peer"])
        // A group: its held members; a channel: its server's members.
        let group = TypingAudience(conversationId: "g1", members: ["a", "b"])
        XCTAssertTrue(TypingAudience.accepts(userId: "b", topic: "dm:g1", audience: group))
        XCTAssertFalse(TypingAudience.accepts(userId: "c", topic: "dm:g1", audience: group))
        let channel = TypingAudience(conversationId: "c1", members: ["m1"])
        XCTAssertTrue(TypingAudience.accepts(userId: "m1", topic: "channel:c1", audience: channel))
        XCTAssertFalse(TypingAudience.accepts(userId: "outsider", topic: "channel:c1", audience: channel))
    }

    func testTypingText() {
        XCTAssertNil(TypingState.text([]))
        XCTAssertEqual(TypingState.text(["Sam"]), "Sam is typing…")
        XCTAssertEqual(TypingState.text(["Sam", "Robin"]), "Sam and Robin are typing…")
        XCTAssertEqual(TypingState.text(["A", "B", "C"]), "A, B and C are typing…")
        XCTAssertEqual(TypingState.text(["A", "B", "C", "D"]), "Several people are typing…")
    }

    func testTypingSendThrottleAndSetting() {
        var th = TypingSendThrottle()
        let now = Date(timeIntervalSince1970: 1000)
        XCTAssertFalse(th.shouldSend(draft: "  ", enabled: true, now: now), "nothing for an empty composer")
        XCTAssertFalse(th.shouldSend(draft: "hi", enabled: false, now: now), "setting off: never sent")
        XCTAssertTrue(th.shouldSend(draft: "hi", enabled: true, now: now))
        XCTAssertFalse(th.shouldSend(draft: "hi!", enabled: true, now: now.addingTimeInterval(2.9)))
        XCTAssertTrue(th.shouldSend(draft: "hi!!", enabled: true, now: now.addingTimeInterval(3)))
        th.reset()
        XCTAssertTrue(th.shouldSend(draft: "again", enabled: true, now: now.addingTimeInterval(3.1)))
        let defaults = UserDefaults(suiteName: "typing-test-\(UUID().uuidString)")!
        XCTAssertTrue(TypingSetting.isOn(defaults), "on by default")
        defaults.set(false, forKey: TypingSetting.key)
        XCTAssertFalse(TypingSetting.isOn(defaults))
    }

    func testServerRoleFromServerLists() {
        let roles: [ServerRoleRule.Role] = [.init(id: "everyone", permissions: 64, isDefault: true),
                                            .init(id: "mod", permissions: 8, isDefault: false),
                                            .init(id: "admin", permissions: 8192, isDefault: false)]
        XCTAssertEqual(ServerRoleRule.role(me: "u", ownerId: "u", myRoleIds: [], roles: roles), .owner)
        XCTAssertEqual(ServerRoleRule.role(me: "u", ownerId: "o", myRoleIds: ["admin"], roles: roles), .admin)
        XCTAssertEqual(ServerRoleRule.role(me: "u", ownerId: "o", myRoleIds: ["mod"], roles: roles), .member)
        XCTAssertEqual(ServerRoleRule.role(me: "u", ownerId: nil, myRoleIds: [], roles: roles), .member)
    }

    // MARK: security review (names, owners)

    func testHostNamesAreRecheckedAndAddressesWin() {
        XCTAssertNil(SkwodNameRule.acceptLearned("chat.example.com", otherNames: []), "looks like an address")
        XCTAssertNil(SkwodNameRule.acceptLearned("host:8443", otherNames: []))
        XCTAssertNil(SkwodNameRule.acceptLearned("a/b", otherNames: []))
        typealias N = SkwodNameRule.Named
        // A host name accepted earlier now clashes with a name the user set: the host one goes.
        XCTAssertEqual(SkwodNameRule.revalidate([N(id: "1", name: "Family", source: .host),
                                                 N(id: "2", name: "family", source: .user)]), ["1"])
        // …and with an address-based name.
        XCTAssertEqual(SkwodNameRule.revalidate([N(id: "1", name: "example.org", source: .address),
                                                 N(id: "2", name: "Example.org", source: .host)]), ["2"])
        // Two host names that look alike: the earlier entry keeps its name.
        XCTAssertEqual(SkwodNameRule.revalidate([N(id: "1", name: "Crew", source: .host),
                                                 N(id: "2", name: "Cr\u{0435}w", source: .host)]), ["2"])
        XCTAssertTrue(SkwodNameRule.revalidate([N(id: "1", name: "Crew", source: .host),
                                                N(id: "2", name: "Book club", source: .learned)]).isEmpty)
    }

    func testOwnershipComesFromThePinnedOwner() {
        XCTAssertEqual(ServerOwnership.decide(me: "u", pinned: "u", hostSays: "u"), .me)
        // The host claiming I own it changes nothing; nor does it claiming I don't.
        XCTAssertEqual(ServerOwnership.decide(me: "u", pinned: "o", hostSays: "u"), .someoneElse)
        XCTAssertEqual(ServerOwnership.decide(me: "u", pinned: "u", hostSays: "o"), .me)
        XCTAssertEqual(ServerOwnership.decide(me: "u", pinned: nil, hostSays: "u"), .unknown)
        // No pinned owner: no Delete, and Leave only behind a warning; a pinned owner never leaves.
        XCTAssertEqual(ServerMenuRule.items(role: .member, channelsKnown: false, ownerPinned: false), [.copyLink, .leaveUnverified])
        XCTAssertFalse(ServerMenuRule.items(role: .owner, channelsKnown: true).contains(.leave))
    }

    func testHostNamesRefuseAddressLookalikes() {
        for bad in ["chat\u{3002}example", "a\u{2024}b", "x\u{FF0E}y", "host\u{A789}443", "a\u{2215}b", "me\u{FF20}there",
                    "a\\b", "50%", "a+b", "crew!"] {
            XCTAssertNil(SkwodNameRule.acceptLearned(bad, otherNames: []), bad)
        }
        for good in ["Weekend Crew", "Rock & Roll", "D'Artagnan", "crew_2-b", "Party 🎉", "👨\u{200D}👩\u{200D}👧", "❤\u{FE0F} crew"] {
            XCTAssertEqual(SkwodNameRule.acceptLearned(good, otherNames: []), good, good)
        }
        // Other scripts, combining marks, stray joiners: refused for a HOST-supplied name.
        for bad in ["Ποδόσφαιρο", "東京", "cafe\u{0301}", "café", "F\u{0430}mily", "a\u{200D}b", "\u{FE0F}x", "\u{00A9} crew"] {
            XCTAssertNil(SkwodNameRule.acceptLearned(bad, otherNames: []), bad)
        }
    }

    // MARK: mentions

    func testMentionWireFormatRoundTripsAndOldClientsSeePlainText() {
        let visible = "hi @Sam and @Robin"
        var p = MentionPayload()
        p.mentions = [.init(userId: "u-sam", start: 3, length: 4), .init(userId: "u-robin", start: 12, length: 6)]
        let sent = MentionCodec.encode(visible, p)
        // What an older app shows: the same characters it renders (tag characters are invisible).
        let rendered = String(String.UnicodeScalarView(sent.unicodeScalars.filter { !WaitingTrust.isInvisible($0) }))
        XCTAssertEqual(rendered, visible)
        let back = MentionCodec.decode(sent)
        XCTAssertEqual(back.visible, visible)
        XCTAssertEqual(back.payload, p)
        // Nothing to say: nothing added.
        XCTAssertEqual(MentionCodec.encode("plain", MentionPayload()), "plain")
        XCTAssertEqual(MentionCodec.decode("plain").visible, "plain")
        // The exact format (shared with Android): U+2063, then TAG("M1" + sorted-key JSON).
        var e = MentionPayload(); e.everyone = true
        let tagged = MentionCodec.encode("@everyone", e)
        let ascii = String(tagged.unicodeScalars.dropFirst(10).map { Character(Unicode.Scalar($0.value - 0xE0000)!) })
        XCTAssertEqual(ascii, "M1{\"e\":true}")
    }

    func testAMentionRangeNeverHidesText() {
        let body = "@Sam please read this carefully"
        var p = MentionPayload()
        // A range over the whole message (or any words after the name) is not a mention.
        p.mentions = [.init(userId: "u", start: 0, length: (body as NSString).length)]
        XCTAssertTrue(MentionCodec.decode(MentionCodec.encode(body, p)).payload.mentions.isEmpty)
        p.mentions = [.init(userId: "u", start: 0, length: 11)]
        XCTAssertTrue(MentionCodec.decode(MentionCodec.encode(body, p)).payload.mentions.isEmpty)
        p.mentions = [.init(userId: "u", start: 0, length: 4)]
        XCTAssertEqual(MentionCodec.decode(MentionCodec.encode(body, p)).payload.mentions.count, 1)
        XCTAssertFalse(MentionCodec.isMentionRange("@" + String(repeating: "a", count: 64) as NSString, start: 0, length: 65))
        XCTAssertTrue(MentionCodec.isMentionRange("@" + String(repeating: "a", count: 63) as NSString, start: 0, length: 64))
    }

    func testTheComposerInsertsATokenEveryAppAccepts() {
        XCTAssertEqual(MentionCodec.token("Sam"), "@Sam")
        XCTAssertEqual(MentionCodec.token("Sam Smith (unverified)"), "@Sam_Smith_unverified")
        XCTAssertEqual(MentionCodec.token("Hangul\u{3164}filler"), "@Hangul_filler")
        XCTAssertEqual(MentionCodec.token("😀"), "@member")
        XCTAssertEqual(MentionCodec.token("  Zoë\n"), "@Zoë")
        XCTAssertEqual(MentionCodec.token("a@b"), "@a_b")
        XCTAssertEqual(MentionCodec.token(" \u{200B} "), "@member")
        let long = MentionCodec.token(String(repeating: "山", count: 80))
        XCTAssertLessThanOrEqual((long as NSString).length, MentionCodec.maxRange)
        XCTAssertTrue(MentionCodec.isMentionRange(long as NSString, start: 0, length: (long as NSString).length))
        // Compose → send → receive: a spaced label still arrives as a mention.
        var p = MentionPayload()
        let draft = MentionAutocomplete.insert(name: "Sam Smith (unverified)", userId: "u-sam", into: "hi @sa", at: 3, payload: &p)
        XCTAssertEqual(draft, "hi @Sam_Smith_unverified ")
        let kept = MentionAutocomplete.reconcile(p, draft: draft, names: ["u-sam": "Sam Smith (unverified)"])
        XCTAssertEqual(kept.mentions.count, 1)
        let back = MentionCodec.decode(MentionCodec.encode(draft, kept))
        XCTAssertEqual(back.payload.mentions, [.init(userId: "u-sam", start: 3, length: 21)])
    }

    func testMalformedTrailersAreIgnored() {
        // A range that does not start with "@", or runs past the text, is dropped.
        var p = MentionPayload(); p.mentions = [.init(userId: "u", start: 0, length: 2)]
        XCTAssertTrue(MentionCodec.decode(MentionCodec.encode("xy", p)).payload.isEmpty)
        p.mentions = [.init(userId: "u", start: 0, length: 50)]
        XCTAssertTrue(MentionCodec.decode(MentionCodec.encode("@x", p)).payload.isEmpty)
        // A separator followed by ordinary text is just text.
        XCTAssertEqual(MentionCodec.decode("a\u{2063}b").visible, "a\u{2063}b")
        // A trailer that is not ours is stripped and ignored.
        let junk = "hi\u{2063}" + String(String.UnicodeScalarView("XX{}".unicodeScalars.map { Unicode.Scalar(0xE0000 + $0.value)! }))
        XCTAssertEqual(MentionCodec.decode(junk).visible, "hi")
        XCTAssertTrue(MentionCodec.decode(junk).payload.isEmpty)
    }

    func testMentionsMeAndTheEveryoneGate() {
        var p = MentionPayload(); p.mentions = [.init(userId: "me", start: 0, length: 3)]
        XCTAssertTrue(MentionRule.mentionsMe(p, me: "me", senderMayMentionEveryone: false, replyToMine: false))
        XCTAssertFalse(MentionRule.mentionsMe(p, me: "other", senderMayMentionEveryone: false, replyToMine: false))
        var e = MentionPayload(); e.everyone = true
        XCTAssertFalse(MentionRule.mentionsMe(e, me: "me", senderMayMentionEveryone: false, replyToMine: false), "a member's @everyone notifies nobody")
        XCTAssertTrue(MentionRule.mentionsMe(e, me: "me", senderMayMentionEveryone: true, replyToMine: false))
        XCTAssertTrue(MentionRule.mentionsMe(MentionPayload(), me: "me", senderMayMentionEveryone: false, replyToMine: true), "a reply to me counts")
        XCTAssertFalse(MentionRule.mentionsMe(MentionPayload(), me: "me", senderMayMentionEveryone: false, replyToMine: true, repliesCount: false))
        XCTAssertTrue(MentionRule.mayMentionEveryone(senderIsPinnedOwner: true, senderPermissions: 0))
        XCTAssertTrue(MentionRule.mayMentionEveryone(senderIsPinnedOwner: false, senderPermissions: 8192))
        XCTAssertTrue(MentionRule.mayMentionEveryone(senderIsPinnedOwner: false, senderPermissions: 4), "Manage Server is an admin")
        XCTAssertFalse(MentionRule.mayMentionEveryone(senderIsPinnedOwner: false, senderPermissions: 16384), "admins only (build 46)")
        XCTAssertFalse(MentionRule.mayMentionEveryone(senderIsPinnedOwner: false, senderPermissions: 64))
    }

    func testAMentionAlwaysAlertsExceptSkwodMuteOrBlockedSender() {
        for conv in [false, true] { for server in [false, true] { for skwod in [false, true] { for blocked in [false, true] {
            let mention = MentionAlertRule.alerts(mentionsMe: true, conversationMuted: conv, serverMuted: server, skwodMuted: skwod, senderBlocked: blocked)
            XCTAssertEqual(mention, !skwod && !blocked, "mention conv=\(conv) server=\(server) skwod=\(skwod) blocked=\(blocked)")
            let plain = MentionAlertRule.alerts(mentionsMe: false, conversationMuted: conv, serverMuted: server, skwodMuted: skwod, senderBlocked: blocked)
            XCTAssertEqual(plain, !conv && !server && !skwod && !blocked)
        }}}}
        XCTAssertEqual(MentionAlertRule.title(sender: "Sam", place: "#general", previews: true), "Sam mentioned you in #general")
        XCTAssertEqual(MentionAlertRule.title(sender: "Sam", place: "#general", previews: false), "You were mentioned")
    }

    func testAutocomplete() {
        XCTAssertEqual(MentionAutocomplete.activeQuery(in: "hey @sa")?.query, "sa")
        XCTAssertEqual(MentionAutocomplete.activeQuery(in: "@")?.query, "")
        XCTAssertNil(MentionAutocomplete.activeQuery(in: "mail@host"), "not inside a word")
        XCTAssertNil(MentionAutocomplete.activeQuery(in: "hey @sam done"))
        let members = [(userId: "1", name: "Sam"), (userId: "2", name: "Robin"), (userId: "3", name: "Isam")]
        XCTAssertEqual(MentionAutocomplete.matches("sa", in: members).map(\.userId), ["1", "3"])
        var p = MentionPayload()
        let text = MentionAutocomplete.insert(name: "Sam", userId: "1", into: "hey @sa", at: 4, payload: &p)
        XCTAssertEqual(text, "hey @Sam ")
        XCTAssertEqual(p.mentions, [.init(userId: "1", start: 4, length: 4)])
        // Editing the token away drops the mention.
        XCTAssertTrue(MentionAutocomplete.reconcile(p, draft: "hey @Sa ", names: ["1": "Sam"]).mentions.isEmpty)
        XCTAssertEqual(MentionAutocomplete.reconcile(p, draft: "hey @Sam !", names: ["1": "Sam"]).mentions.count, 1)
    }

    // MARK: sender-controlled trailers (shared vectors with Android)

    static func sharedVectors(_ name: String) throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../shared-test-vectors/\(name)").standardizedFileURL
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    static func tagged(_ ascii: String) -> String {
        String(String.UnicodeScalarView(ascii.unicodeScalars.map { Unicode.Scalar(0xE0000 + $0.value)! }))
    }

    func testHostileMentionTrailersNeverCrashAndReadNothingBad() throws {
        let cases = try XCTUnwrap(Self.sharedVectors("mention-trailers.json")["cases"] as? [[String: Any]])
        XCTAssertGreaterThan(cases.count, 20)
        for c in cases {
            let name = c["name"] as? String ?? "?"
            let visible = try XCTUnwrap(c["visible"] as? String)
            let decoded = MentionCodec.decode(visible + "\u{2063}" + Self.tagged(try XCTUnwrap(c["payload"] as? String)))
            XCTAssertEqual(decoded.visible, visible, name)
            let want = (c["mentions"] as? [[Any]] ?? []).map {
                MentionPayload.Mention(userId: $0[0] as! String, start: ($0[1] as! NSNumber).intValue, length: ($0[2] as! NSNumber).intValue)
            }
            XCTAssertEqual(decoded.payload.mentions, want, name)
            XCTAssertEqual(decoded.payload.everyone, c["everyone"] as? Bool ?? false, name)
        }
    }

    func testBoundsNeverAdd() {
        XCTAssertFalse(MentionCodec.inBounds(start: Int.max, length: Int.max, count: 3))
        XCTAssertFalse(MentionCodec.inBounds(start: 1, length: Int.max, count: 3))
        XCTAssertFalse(MentionCodec.inBounds(start: Int.min, length: 2, count: 3))
        XCTAssertTrue(MentionCodec.inBounds(start: 1, length: 2, count: 3))
        XCTAssertNil(MentionCodec.exactInt(NSNumber(value: Double.nan)))
        XCTAssertNil(MentionCodec.exactInt(NSNumber(value: Double.infinity)))
        XCTAssertNil(MentionCodec.exactInt(NSNumber(value: 1.5)))
        XCTAssertNil(MentionCodec.exactInt(NSNumber(value: true)))
        XCTAssertNil(MentionCodec.exactInt("2"))
        XCTAssertEqual(MentionCodec.exactInt(NSNumber(value: 7)), 7)
        // A huge random-ish sweep: nothing traps.
        var rng = SystemRandomNumberGenerator()
        for _ in 0..<2000 {
            let s = [Int.max, Int.min, -1, 0, 1, 2, Int(Int32.max), Int.random(in: Int.min...Int.max, using: &rng)]
            let payload = "M1{\"m\":[[\"u\",\(s.randomElement()!),\(s.randomElement()!)]]}"
            _ = MentionCodec.decode("@ab\u{2063}" + Self.tagged(payload))
        }
    }

    func testHostSkwodNamesFollowTheSharedRule() throws {
        let v = try Self.sharedVectors("skwod-names.json")
        let cases = try XCTUnwrap(v["cases"] as? [[String: Any]])
        XCTAssertGreaterThan(cases.count, 50)
        for c in cases {
            let name = try XCTUnwrap(c["name"] as? String)
            let want = c["expect"] as? String
            XCTAssertEqual(SkwodNameRule.acceptLearned(name, otherNames: []), want,
                           name.unicodeScalars.map { String($0.value, radix: 16) }.joined(separator: " "))
        }
        for c in try XCTUnwrap(v["clash"] as? [[String: Any]]) {
            XCTAssertEqual(SkwodNameRule.acceptLearned(c["name"] as! String, otherNames: c["others"] as! [String]), c["expect"] as? String)
        }
    }

    func testTheDefaultRoleNeverOpensTheEveryoneGate() {
        let roles: [ServerRoleRule.Role] = [.init(id: "everyone", permissions: 8192 | 4, isDefault: true),
                                            .init(id: "admin", permissions: 8192, isDefault: false),
                                            .init(id: "mod", permissions: 64, isDefault: false)]
        XCTAssertEqual(ServerRoleRule.everyonePermissions(memberRoleIds: [], roles: roles), 0)
        XCTAssertEqual(ServerRoleRule.everyonePermissions(memberRoleIds: ["mod"], roles: roles), 64)
        // Listing the default role's id among one's roles changes nothing either.
        XCTAssertEqual(ServerRoleRule.everyonePermissions(memberRoleIds: ["everyone", "mod"], roles: roles), 64)
        XCTAssertEqual(ServerRoleRule.everyonePermissions(memberRoleIds: ["admin"], roles: roles), 8192)
        let perms = ["plain": ServerRoleRule.everyonePermissions(memberRoleIds: [], roles: roles),
                     "modded": ServerRoleRule.everyonePermissions(memberRoleIds: ["mod"], roles: roles),
                     "admin": ServerRoleRule.everyonePermissions(memberRoleIds: ["admin"], roles: roles)]
        XCTAssertEqual(EveryoneRule.allowed(pinnedOwner: "owner", memberPermissions: perms, held: [], blocked: []), ["owner", "admin"])
    }

    func testEveryoneIsHonouredFromThePinnedOwnerAndVerifiedAdmins() {
        let perms: [String: Int64] = ["admin": 8192, "manager": 4 | 64, "member": 64 | 128, "heldAdmin": 8192, "blockedAdmin": 4, "mentioner": 16384]
        let allowed = EveryoneRule.allowed(pinnedOwner: "owner", memberPermissions: perms, held: ["heldAdmin"], blocked: ["blockedAdmin"])
        XCTAssertEqual(allowed, ["owner", "admin", "manager"])
        // The pinned owner counts even when the server leaves them out of the member list; never when blocked.
        XCTAssertEqual(EveryoneRule.allowed(pinnedOwner: "owner", memberPermissions: [:], held: [], blocked: ["owner"]), [])
        XCTAssertEqual(EveryoneRule.allowed(pinnedOwner: nil, memberPermissions: ["": 8192], held: [], blocked: []), [])
        XCTAssertEqual(EveryoneRule.sendersKey(channelId: "c1"), "everyone:channel:c1")
    }

    func testTheExtensionNamesOnlyTrustedPeopleInMentionBanners() {
        let names = ["channel:c": "general", "dm:g": "Mom", "dm:d": "Sam", "person:u-sam": "Sam", "person:u-x": "New message"]
        XCTAssertEqual(MentionNotice.senderName(authorId: "u-sam", names: names), "Sam")
        XCTAssertNil(MentionNotice.senderName(authorId: "u-x", names: names), "the generic title is no name")
        XCTAssertNil(MentionNotice.senderName(authorId: "u-mom", names: names), "a group's title is never a person's name")
        XCTAssertNil(MentionNotice.senderName(authorId: nil, names: names))
        XCTAssertEqual(MentionNotice.title(sender: "Sam", place: "#general"), "Sam mentioned you in #general")
        XCTAssertEqual(MentionNotice.title(sender: nil, place: "#general"), "You were mentioned in #general")
        XCTAssertEqual(MentionNotice.title(sender: "Sam", place: "Sam"), "Sam mentioned you")
        XCTAssertEqual(MentionNotice.title(sender: nil, place: nil), "You were mentioned")
        XCTAssertTrue(MentionNotice.isConversation("channel:c"))
        XCTAssertTrue(MentionNotice.isConversation("dm:d"))
        XCTAssertFalse(MentionNotice.isConversation("person:u-sam"))
        XCTAssertTrue(MentionNotice.replyToMine("m1", mine: ["m1"]))
        XCTAssertFalse(MentionNotice.replyToMine(nil, mine: ["m1"]))
    }

    func testMentionBadgesCountEachMessageOnceAcrossTheAppAndTheExtension() throws {
        let suite = "skwod.tests.badges.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        // The extension saw two; the app later sees one of them again and a new one.
        MentionBadgeLedger.update(defaults) { $0.add(ids: ["a", "b"], topic: "channel:c", workspaceId: "w") }
        let (l, fresh) = MentionBadgeLedger.update(defaults) { $0.add(ids: ["b", "c", "c"], topic: "channel:c", workspaceId: "w") }
        XCTAssertEqual(fresh, 1)
        XCTAssertEqual(l.count("channel:c", workspaceId: "w"), 3)
        XCTAssertEqual(MentionBadgeLedger.load(defaults).count("channel:c", workspaceId: "w"), 3)
        MentionBadgeLedger.update(defaults) { $0.clear(topic: "channel:c", workspaceId: "w") }
        XCTAssertEqual(MentionBadgeLedger.load(defaults).count("channel:c", workspaceId: "w"), 0)
        // Cleared ids stay counted: an old mention found again is not a new badge.
        XCTAssertEqual(MentionBadgeLedger.update(defaults) { $0.add(ids: ["a"], topic: "channel:c", workspaceId: "w") }.1, 0)
        var big = MentionBadgeLedger()
        big.add(ids: (0..<(MentionBadgeLedger.maxCounted + 10)).map(String.init), topic: "t", workspaceId: "w")
        XCTAssertEqual(big.counted.count, MentionBadgeLedger.maxCounted)
    }

    func testTheServerListIsReadByServerIdAndAMalformedAnswerPrunesNothing() {
        let ok = Data(#"{"servers":[{"server_id":"s1","owner_id":"me"},{"server_id":"s2","owner_id":"them"}]}"#.utf8)
        XCTAssertEqual(ServerListRule.owners(ok), ["s1": "me", "s2": "them"])
        XCTAssertEqual(ServerListRule.owners(Data(#"{"servers":[]}"#.utf8)), [:])
        XCTAssertNil(ServerListRule.owners(Data(#"{"servers":[{"id":"s1","owner_id":"me"}]}"#.utf8)), "no server_id: not a complete answer")
        XCTAssertNil(ServerListRule.owners(Data("not json".utf8)))
    }
}
