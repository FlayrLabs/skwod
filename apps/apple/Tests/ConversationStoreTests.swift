import XCTest

/// Drives the real `ConversationStore` — the code the apps run for every change to the 1:1 and
/// group stores — against a server that lies and answers at the worst moments.
@MainActor
final class ConversationStoreTests: XCTestCase {
    // MARK: A fake core: an in-memory cache and a scripted, untrusted server

    @MainActor
    final class FakeBackend: ConversationBackend {
        var kv: [String: String] = [:]
        var writes: [(key: String, value: String)] = []
        var dmRows: [ListedDM] = []
        var groupRows: [(conversationId: String, memberUserIds: [String])] = []
        var directory: [String: String] = [:]
        var openGroupAnswer = "new-group"
        var failListings = false
        var groupListings = 0
        /// Called (once) in the middle of the named call, after the server has "answered" and
        /// before the answer is returned — where the app would be suspended.
        var during: [String: () async -> Void] = [:]
        /// Calls to hold open until `release(_:)`.
        var held: Set<String> = []
        private var waiters: [String: [CheckedContinuation<Void, Never>]] = [:]
        private(set) var waiting: [String: Int] = [:]

        private func pause(_ name: String) async {
            if let hook = during.removeValue(forKey: name) { await hook() }
            guard held.contains(name) else { return }
            waiting[name, default: 0] += 1
            await withCheckedContinuation { waiters[name, default: []].append($0) }
        }

        func release(_ name: String) {
            held.remove(name)
            for w in waiters.removeValue(forKey: name) ?? [] { w.resume() }
        }

        /// This workspace's cache is not open — no client is bound to it, or the client that
        /// is came up WITHOUT its cache. Exactly what the app's backend does then
        /// (`BoundClient.withCache`): every read and write of the cache throws, while the
        /// server still answers (listings, lookups, "open").
        var cacheClosed = false

        func kvGet(key: String) async throws -> String? {
            await pause("kvGet")
            if cacheClosed { throw ConversationError.notReady }
            return kv[key]
        }
        /// The cache is open but a write does not go through.
        var failWrites = false

        func kvSet(key: String, value: String) async throws {
            await pause("kvSet")
            if cacheClosed || failWrites { throw ConversationError.notReady }
            kv[key] = value
            writes.append((key, value))
        }
        func listDms() async throws -> [ListedDM] {
            let rows = dmRows
            await pause("listDms")
            if failListings { throw ConversationError.notReady }
            return rows
        }
        func listGroupDms() async throws -> [(conversationId: String, memberUserIds: [String])] {
            groupListings += 1
            // What the server answers is decided when it is ASKED, not when the answer lands.
            let rows = groupRows, fail = failListings
            await pause("listGroupDms")
            if fail { throw ConversationError.notReady }
            return rows
        }
        func findUserId(username: String) async throws -> String {
            await pause("findUser")
            guard let id = directory[username] else { throw ConversationError.notReady }
            return id
        }
        func openGroupDm(memberUserIds: [String]) async throws -> String {
            await pause("openGroupDm")
            return openGroupAnswer
        }
    }

    private var backend: FakeBackend!
    private var store: ConversationStore!
    private var notices: [ConversationStore.Notice] = []
    /// Does Security activity manage to store a notice's row?
    private var activityWrites = true

    override func setUp() async throws {
        backend = FakeBackend()
        notices = []
        store = makeStore()
    }

    private func makeStore() -> ConversationStore {
        let s = ConversationStore(backend: backend, workspaceId: "w1")
        // Like the app: Security activity stores the row, then reports it stored.
        s.onNotice = { [weak self, weak s] in self?.notices.append($0); if self?.activityWrites ?? true { s?.stored($0) } }
        return s
    }

    private func settle(_ times: Int = 50) async { for _ in 0..<times { await Task.yield() } }

    private func dm(_ id: String, _ peer: String, name: String = "") -> DMConversation {
        DMConversation(name: name, peerUserId: peer, peerDeviceId: "d", conversationId: id)
    }

    /// A store with one user-started DM (`dm1` with bob) and one accepted group (`g1`: carol, dave).
    private func loadedWithOneOfEach() async {
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertEqual(store.addDM(dm("dm1", "bob", name: "bob")), .added(store.dms[0]))
        backend.groupRows = [("g1", ["carol", "dave"])]
        let asked = await store.refreshGroups()
        XCTAssertTrue(asked)
        XCTAssertNotNil(store.accept(store.invitations[0]))
        backend.groupRows = []
        await store.flush()
        XCTAssertEqual(store.groups.map(\.conversationId), ["g1"])
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm1"])
    }

    private func assertUntouched(file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm1"], file: file, line: line)
        XCTAssertEqual(store.dms.first?.peerUserId, "bob", file: file, line: line)
        XCTAssertEqual(store.groups.map(\.conversationId), ["g1"], file: file, line: line)
        XCTAssertEqual(store.groups.first?.memberUserIds, ["carol", "dave"], file: file, line: line)
    }

    // MARK: A group passed off as a direct conversation

    func testDeliveryNeverMakesADirectEntryForAGroupsId() async {
        await loadedWithOneOfEach()
        let delivered = await store.deliverDM(conversationId: "g1", peerUserId: "mallory")
        XCTAssertNil(delivered)
        assertUntouched()
        XCTAssertEqual(store.route("g1"), .group)
        XCTAssertEqual(notices, [.conflict(conversationId: "g1")])
    }

    func testListingNeverMakesADirectEntryForAGroupsId() async {
        await loadedWithOneOfEach()
        backend.dmRows = [ListedDM(conversationId: "g1", peerUserId: "mallory", peerUsername: "mallory"),
                          ListedDM(conversationId: "dm2", peerUserId: "erin", peerUsername: "erin")]
        backend.directory = ["erin": "erin", "mallory": "mallory"]
        let added = await store.refreshDMList()
        XCTAssertEqual(added.map(\.conversationId), ["dm2"])
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm2", "dm1"])
        XCTAssertEqual(store.groups.first?.memberUserIds, ["carol", "dave"])
        XCTAssertEqual(store.route("g1"), .group)
        XCTAssertEqual(notices, [.conflict(conversationId: "g1")])
    }

    func testOpeningADirectConversationUnderAGroupsIdIsRefused() async {
        await loadedWithOneOfEach()
        XCTAssertEqual(store.addDM(dm("g1", "mallory")), .refused)
        assertUntouched()
        XCTAssertEqual(notices, [.conflict(conversationId: "g1")])
    }

    func testAGroupAcceptedWhileADeliveryWasBeingLookedUpWins() async {
        // upsertDM's window: the checks pass, the name lookup is awaited, and meanwhile the id
        // becomes a group. The entry must not be written from the stale check.
        _ = await store.load()
        backend.groupRows = [("x1", ["carol", "dave"])]
        backend.during["listDms"] = { [store, backend] in
            // The invitation is not there when the delivery starts; it appears, and the user
            // accepts it, while the delivery is suspended.
            _ = await store!.refreshGroups()
            XCTAssertNotNil(store!.accept(store!.invitations[0]))
            _ = backend
        }
        let delivered = await store.deliverDM(conversationId: "x1", peerUserId: "carol")
        XCTAssertNil(delivered)
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.groups.map(\.conversationId), ["x1"])
        XCTAssertEqual(notices, [.conflict(conversationId: "x1")])
    }

    func testAGroupAcceptedWhileAListedRowsNameWasBeingCheckedWins() async {
        // refreshDMList's window: the same, across `findUser`.
        _ = await store.load()
        backend.groupRows = [("x1", ["carol", "dave"])]
        _ = await store.refreshGroups()
        let invitation = store.invitations[0]
        // Listed as a DM first (so it is not an invitation's id when the row is looked at).
        store.decline(invitation)
        backend.dmRows = [ListedDM(conversationId: "x2", peerUserId: "erin", peerUsername: "erin")]
        backend.groupRows = [("x2", ["carol", "dave"])]
        backend.directory = ["erin": "erin"]
        backend.during["findUser"] = { [store] in
            _ = await store!.refreshGroups()
            XCTAssertNotNil(store!.accept(store!.invitations[0]))
        }
        let added = await store.refreshDMList()
        XCTAssertTrue(added.isEmpty)
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.groups.map(\.conversationId), ["x2"])
    }

    func testNothingOfAnInvitationOrAnIgnoredGroupIsListedAsDirect() async {
        _ = await store.load()
        backend.groupRows = [("inv", ["carol", "dave"]), ("ign", ["erin", "frank"])]
        _ = await store.refreshGroups()
        store.decline(store.invitations.first { $0.conversationId == "ign" }!)
        XCTAssertEqual(store.route("ign"), .declined)
        XCTAssertEqual(store.route("inv"), .invitation)
        backend.dmRows = [ListedDM(conversationId: "inv", peerUserId: "carol", peerUsername: ""),
                          ListedDM(conversationId: "ign", peerUserId: "erin", peerUsername: "")]
        let added = await store.refreshDMList()
        let a = await store.deliverDM(conversationId: "inv", peerUserId: "carol")
        let b = await store.deliverDM(conversationId: "ign", peerUserId: "erin")
        XCTAssertTrue(added.isEmpty)
        XCTAssertNil(a)
        XCTAssertNil(b)
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.route("ign"), .declined)
        // Ignored for good: a later listing does not bring it back either.
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.map(\.conversationId), ["inv"])
    }

    // MARK: A direct conversation passed off as a group

    func testAClaimedDirectIdListedAsAGroupMakesNoInvitation() async {
        await loadedWithOneOfEach()
        backend.groupRows = [("dm1", ["carol", "mallory"]), ("dm1", ["carol", "mallory"])]
        let asked = await store.refreshGroups()
        XCTAssertTrue(asked)
        XCTAssertTrue(store.invitations.isEmpty)
        assertUntouched()
        XCTAssertEqual(store.route("dm1"), .direct)
        XCTAssertEqual(notices, [.conflict(conversationId: "dm1")])
    }

    func testStartingAGroupTheServerAnswersWithADirectIdIsRefused() async {
        await loadedWithOneOfEach()
        backend.openGroupAnswer = "dm1"
        do {
            _ = try await store.startGroup(memberUserIds: ["carol", "mallory"], names: [:])
            XCTFail("started")
        } catch { XCTAssertEqual(error as? ConversationError, .conflict) }
        assertUntouched()
        XCTAssertEqual(notices, [.conflict(conversationId: "dm1")])
    }

    func testStartingAGroupTheServerAnswersWithAnotherGroupsIdIsRefused() async {
        await loadedWithOneOfEach()
        backend.openGroupAnswer = "g1"
        do {
            _ = try await store.startGroup(memberUserIds: ["erin", "frank"], names: [:])
            XCTFail("started")
        } catch { XCTAssertEqual(error as? ConversationError, .conflict) }
        assertUntouched()
    }

    func testADirectConversationOpenedWhileAGroupWasBeingStartedWins() async {
        _ = await store.load()
        backend.openGroupAnswer = "x1"
        backend.during["openGroupDm"] = { [store] in _ = store!.addDM(DMConversation(name: "bob", peerUserId: "bob", peerDeviceId: "d", conversationId: "x1")) }
        do {
            _ = try await store.startGroup(memberUserIds: ["carol", "dave"], names: [:])
            XCTFail("started")
        } catch { XCTAssertEqual(error as? ConversationError, .conflict) }
        XCTAssertTrue(store.groups.isEmpty)
        XCTAssertEqual(store.dms.map(\.conversationId), ["x1"])
    }

    func testAcceptingAnInvitationUnderAClaimedDirectIdKeepsBoth() async {
        // A listed (unclaimed) direct entry, then an invitation under the same id, then the
        // user WRITES in the direct conversation: it is theirs. Accepting is refused, and the
        // invitation is NOT removed by the clash.
        _ = await store.load()
        _ = await store.deliverDM(conversationId: "x1", peerUserId: "bob")
        backend.groupRows = [("x1", ["carol", "dave"])]
        _ = await store.refreshGroups()
        let invitation = store.invitations[0]
        store.claimDM(conversationId: "x1", peerUserId: "bob")
        XCTAssertNil(store.accept(invitation))
        XCTAssertEqual(store.invitations.map(\.conversationId), ["x1"])
        XCTAssertTrue(store.groups.isEmpty)
        XCTAssertEqual(store.dms.map(\.conversationId), ["x1"])
        XCTAssertEqual(store.route("x1"), .direct)
        XCTAssertEqual(notices, [.conflict(conversationId: "x1")])
    }

    func testOpeningADirectConversationUnderAnInvitationOrAnIgnoredGroupIsRefusedUpFront() async {
        // "Open a chat" answered with the id of a group this device was invited to, or one the
        // user ignored: a direct entry there would never receive anything — so none is made.
        _ = await store.load()
        backend.groupRows = [("inv", ["carol", "dave"]), ("ign", ["erin", "frank"])]
        _ = await store.refreshGroups()
        store.decline(store.invitations.first { $0.conversationId == "ign" }!)
        XCTAssertEqual(store.addDM(dm("inv", "bob")), .refused)
        XCTAssertEqual(store.addDM(dm("ign", "bob")), .refusedIgnored, "refused, and the caller can say why")
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.invitations.map(\.conversationId), ["inv"])
        XCTAssertEqual(notices, [.conflict(conversationId: "inv"), .conflict(conversationId: "ign")])
    }

    func testAnIgnoredGroupCanBeUnignoredAndThenComesBackAsAnInvitation() async {
        _ = await store.load()
        backend.groupRows = [("ign", ["erin", "frank"])]
        _ = await store.refreshGroups()
        var silentWhenTold: Set<String> = []
        store.didChange = { [unowned self] in silentWhenTold = self.store.silentIds }
        store.decline(store.invitations[0])
        XCTAssertEqual(silentWhenTold, ["ign"], "whoever hears of the change sees the id as ignored already")
        _ = await store.refreshGroups()
        XCTAssertTrue(store.invitations.isEmpty)
        await store.flush()
        // The user stops ignoring it: the id is free again, and the listing shows the group.
        XCTAssertTrue(store.unignore("ign"))
        XCTAssertFalse(store.unignore("ign"))
        XCTAssertTrue(store.declined.isEmpty)
        XCTAssertEqual(silentWhenTold, [])
        await store.flush()
        XCTAssertEqual(backend.kv["groups.declined"], "[]")
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.map(\.conversationId), ["ign"])
        // …or, if the server no longer lists a group there, the id can be a direct conversation.
        store.decline(store.invitations[0])
        XCTAssertEqual(store.addDM(dm("ign", "bob")), .refusedIgnored)
        store.unignore("ign")
        guard case .added = store.addDM(dm("ign", "bob")) else { return XCTFail("not added") }
    }

    // MARK: A direct list that is lost as a whole

    func testAWhollyUnreadableDirectListBlocksServerDrivenEntriesUntilTheUserActs() async {
        backend.kv["w1|sidebar.dms"] = "{ not the list"
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertTrue(store.review.allDirect)
        XCTAssertTrue(store.reviewPending)
        // The server lists a direct conversation, delivers into one, and lists a group — under
        // ids this device may have held as something else.
        backend.dmRows = [ListedDM(conversationId: "c1", peerUserId: "mallory", peerUsername: "mom")]
        backend.groupRows = [("c2", ["gil", "hana"])]
        let added = await store.refreshDMList()
        let delivered = await store.deliverDM(conversationId: "c1", peerUserId: "mallory")
        _ = await store.refreshGroups()
        XCTAssertTrue(added.isEmpty)
        XCTAssertNil(delivered)
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.invitations.map { $0.needsReview == true }, [true], "a group may sit under the id of a lost direct conversation")
        // What the USER opens is theirs, and goes on receiving.
        guard case .added = store.addDM(dm("c3", "bob")) else { return XCTFail("not added") }
        let own = await store.deliverDM(conversationId: "c3", peerUserId: "bob")
        XCTAssertEqual(own?.isNew, false)
        await store.flush()
        // It survives a relaunch…
        let relaunched = makeStore()
        _ = await relaunched.load()
        XCTAssertTrue(relaunched.review.allDirect)
        let still = await relaunched.refreshDMList()
        XCTAssertTrue(still.isEmpty)
        // …until the user says they have seen it: both flags go, and stay gone.
        _ = await relaunched.refreshGroups()
        var changes = 0
        relaunched.didChange = { changes += 1 }
        relaunched.clearReview()
        XCTAssertEqual(changes, 1)
        XCTAssertFalse(relaunched.reviewPending)
        XCTAssertEqual(relaunched.invitations.map { $0.needsReview == true }, [false])
        let now = await relaunched.refreshDMList()
        XCTAssertEqual(now.map(\.conversationId), ["c1"])
        XCTAssertEqual(now.first?.isClaimed, false)
        await relaunched.flush()
        let third = makeStore()
        _ = await third.load()
        XCTAssertEqual(third.review, ConversationStore.Review())
    }

    func testClearingTheReviewKeepsTheGroupsKnownByIdToHaveBeenHeld() async {
        backend.kv["sidebar.groups"] = #"[{"conversationId":"g2","memberUserIds":"oops"}]"#
        backend.kv["groups.declined"] = "{ nope"
        _ = await store.load()
        XCTAssertTrue(store.review.allGroups)
        XCTAssertFalse(store.review.allDirect)
        backend.groupRows = [("g2", ["gil", "hana"]), ("g4", ["ivy", "jon"])]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.map { $0.needsReview == true }, [true, true])
        store.clearReview()
        XCTAssertFalse(store.review.allGroups)
        XCTAssertEqual(store.invitations.map { $0.needsReview == true }, [true, false])
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.map { $0.needsReview == true }, [true, false])
    }

    func testAnUnreadableReviewRecordAlsoBlocksDirectEntries() async {
        backend.kv["w1|conversations.review"] = "nope"
        _ = await store.load()
        XCTAssertTrue(store.review.allGroups)
        XCTAssertTrue(store.review.allDirect)
    }

    // MARK: Small things

    func testASlotThatIsBeingWrittenIsStillHandedOverAtSignOut() async {
        _ = await store.load()
        backend.held = ["kvSet"]
        guard case .added = store.addDM(dm("dm1", "bob")) else { return XCTFail("not added") }
        await settle()
        XCTAssertEqual(backend.waiting["kvSet"], 1, "the write is under way and has not landed")
        guard case .added = store.addDM(dm("dm2", "carol")) else { return XCTFail("not added") }
        let unsaved = store.takeUnsaved()
        XCTAssertEqual(unsaved.map(\.key), ["w1|sidebar.dms"])
        XCTAssertTrue(unsaved[0].value.contains("dm2") && unsaved[0].value.contains("dm1"))
        backend.release("kvSet")
        await store.flush()
    }

    func testThisAccountIsNeverOneOfAGroupsOtherMembers() async {
        let mine = ConversationStore(backend: backend, workspaceId: "w1", me: "me")
        _ = await mine.load()
        backend.groupRows = [("g1", ["carol", "me", "dave", "carol"])]
        _ = await mine.refreshGroups()
        XCTAssertEqual(mine.invitations.first?.memberUserIds, ["carol", "dave"])
        backend.openGroupAnswer = "g9"
        let started = try? await mine.startGroup(memberUserIds: ["me", "erin", "frank"], names: [:])
        XCTAssertEqual(started?.memberUserIds, ["erin", "frank"])
    }

    func testALoadThatKeepsFailingIsCountedAndKeepsOneCopyPerContent() async {
        backend.kv["sidebar.groups"] = "{ not the groups"
        store.clock = { 1000 }
        _ = await store.load()
        XCTAssertEqual(store.loadFailures, 0)
        // Another store (the next bind) finds the same bytes back in place — the salvaged list
        // could not be written — again and again.
        for ms in [2000, 3000] as [Int64] {
            backend.kv["sidebar.groups"] = "{ not the groups"
            let next = makeStore()
            next.clock = { ms }
            let ok = await next.load()
            XCTAssertTrue(ok)
        }
        XCTAssertEqual(backend.kv.keys.filter { $0.hasPrefix("sidebar.groups.unreadable.") }, ["sidebar.groups.unreadable.1000"], "one copy per distinct content")
        // A cache that cannot be read: counted, so it can be said; back to 0 once it reads.
        backend.kv = [:]
        let shut = makeStore()
        backend.cacheClosed = true
        _ = await shut.load()
        _ = await shut.load()
        XCTAssertEqual(shut.loadFailures, 2)
        backend.cacheClosed = false
        _ = await shut.load()
        XCTAssertEqual(shut.loadFailures, 0)
    }

    func testTheExtensionsTitleIsNeverAServerSuppliedName() {
        XCTAssertEqual(NotificationTitles.direct(isClaimed: true, trustedName: "mom"), "mom")
        XCTAssertEqual(NotificationTitles.direct(isClaimed: false, trustedName: "mom"), NotificationTitles.generic, "listed or delivered, never opened by the user")
        XCTAssertEqual(NotificationTitles.direct(isClaimed: true, trustedName: nil), NotificationTitles.generic, "unverified, flagged, or the book is not read")
        XCTAssertEqual(NotificationTitles.direct(isClaimed: true, trustedName: ""), NotificationTitles.generic)
    }

    // MARK: One direct conversation, one peer

    func testASecondAccountNeverGetsAnEntryUnderAHeldDirectId() async {
        await loadedWithOneOfEach()
        backend.dmRows = [ListedDM(conversationId: "dm1", peerUserId: "mallory", peerUsername: "bob")]
        backend.directory = ["bob": "mallory"]
        // Delivered into it, listed under it, and answered to "open a DM with mallory".
        let delivered = await store.deliverDM(conversationId: "dm1", peerUserId: "mallory")
        let added = await store.refreshDMList()
        XCTAssertNil(delivered)
        XCTAssertTrue(added.isEmpty)
        XCTAssertEqual(store.addDM(dm("dm1", "mallory", name: "bob")), .refused)
        assertUntouched()
        XCTAssertEqual(store.dms[0].name, "bob")
        XCTAssertEqual(notices, [.otherPeer(conversationId: "dm1")])
        // The real peer is still delivered, and still the only one announced under the title.
        let real = await store.deliverDM(conversationId: "dm1", peerUserId: "bob")
        XCTAssertEqual(real?.isNew, false)
        let senders = NotificationSenders.allowed(dms: store.dms, groups: store.groups)
        XCTAssertEqual(senders["dm:dm1"], ["bob"])
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:dm1", authorId: "mallory", senders: senders))
    }

    func testASecondAccountAppearingWhileADeliveryWasBeingLookedUpGetsNoEntry() async {
        _ = await store.load()
        backend.during["listDms"] = { [store] in _ = store!.addDM(DMConversation(name: "bob", peerUserId: "bob", peerDeviceId: "d", conversationId: "x1")) }
        let delivered = await store.deliverDM(conversationId: "x1", peerUserId: "mallory")
        XCTAssertNil(delivered)
        XCTAssertEqual(store.dms.map(\.peerUserId), ["bob"])
        XCTAssertEqual(notices, [.otherPeer(conversationId: "x1")])
    }

    func testDuplicateEntriesStoredByAnEarlierBuildAreReducedToTheHolder() async {
        // Newest first, as stored: mallory's entry was added (by a delivery) after bob's.
        backend.kv["w1|sidebar.dms"] = #"""
        [{"id":"7E6C3E0B-58C5-4B4E-9C0A-0E3B0C0A7A13","name":"bob","peerUserId":"mallory","peerDeviceId":"","conversationId":"old1"},
         {"id":"7E6C3E0B-58C5-4B4E-9C0A-0E3B0C0A7A12","name":"erin","peerUserId":"erin","peerDeviceId":"","conversationId":"old2"},
         {"id":"7E6C3E0B-58C5-4B4E-9C0A-0E3B0C0A7A11","name":"bob","peerUserId":"bob","peerDeviceId":"dev","conversationId":"old1","startedHere":true}]
        """#
        let asStored = backend.kv["w1|sidebar.dms"]
        store.clock = { 500 }
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertEqual(store.dms.map(\.peerUserId), ["erin", "bob"])
        // Nothing is deleted without a copy: the list as it was is kept, and it is said.
        XCTAssertEqual(backend.kv["w1|sidebar.dms.duplicates.500"], asStored)
        XCTAssertEqual(notices, [.duplicates(keptAs: "w1|sidebar.dms.duplicates.500")])
        XCTAssertEqual(NotificationSenders.allowed(dms: store.dms, groups: [])["dm:old1"], ["bob"])
        await store.flush()
        let saved = try? JSONDecoder().decode([DMConversation].self, from: Data((backend.kv["w1|sidebar.dms"] ?? "").utf8))
        XCTAssertEqual(saved?.map(\.peerUserId), ["erin", "bob"])
        // The OLDEST entry is not the holder when it is only what the server listed and a
        // newer one is the conversation the user started.
        let listedFirst = [DMConversation(name: "bob", peerUserId: "bob", peerDeviceId: "dev", conversationId: "c", startedHere: true),
                           DMConversation(name: "", peerUserId: "mallory", peerDeviceId: "", conversationId: "c")]
        XCTAssertEqual(ConversationStore.holders(listedFirst).map(\.peerUserId), ["bob"])
        // …nor when it does not claim the id and a newer one does.
        let unclaimedFirst = [DMConversation(name: "bob", peerUserId: "bob", peerDeviceId: "", conversationId: "c", claimed: true),
                              DMConversation(name: "", peerUserId: "mallory", peerDeviceId: "", conversationId: "c", claimed: false)]
        XCTAssertEqual(ConversationStore.holders(unclaimedFirst).map(\.peerUserId), ["bob"])
        // Even handed an unreduced list, the map names one account per conversation.
        let both = [dm("c", "mallory"), dm("c", "bob")]
        XCTAssertEqual(NotificationSenders.allowed(dms: both, groups: []), ["dm:c": ["bob"]])
    }

    // MARK: Only the user's own action claims an id

    func testAServerListedDirectEntryDoesNotBlockAcceptingAGroup() async {
        _ = await store.load()
        backend.dmRows = [ListedDM(conversationId: "x1", peerUserId: "carol", peerUsername: "")]
        let added = await store.refreshDMList()
        XCTAssertEqual(added.first?.claimed, false)
        XCTAssertEqual(store.route("x1"), .direct)
        backend.groupRows = [("x1", ["carol", "dave"])]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.map(\.conversationId), ["x1"])
        XCTAssertTrue(notices.isEmpty)
        // Until the user decides, the entry that exists keeps routing.
        XCTAssertEqual(store.route("x1"), .direct)
        XCTAssertNotNil(store.accept(store.invitations[0]))
        // The user's action took the id: it is in one store only.
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.route("x1"), .group)
    }

    func testWritingInAListedConversationClaimsIt() async {
        _ = await store.load()
        backend.dmRows = [ListedDM(conversationId: "x1", peerUserId: "carol", peerUsername: "")]
        _ = await store.refreshDMList()
        store.claimDM(conversationId: "x1", peerUserId: "carol")
        XCTAssertEqual(store.dms.first?.claimed, true)
        backend.groupRows = [("x1", ["carol", "dave"])]
        _ = await store.refreshGroups()
        XCTAssertTrue(store.invitations.isEmpty)
        XCTAssertEqual(notices, [.conflict(conversationId: "x1")])
    }

    func testEntriesStoredBeforeTheClaimFieldExistedAreClaimed() async {
        // Exactly what an earlier build wrote: no `claimed` key at all.
        backend.kv["w1|sidebar.dms"] = #"[{"id":"7E6C3E0B-58C5-4B4E-9C0A-0E3B0C0A7A11","name":"bob","peerUserId":"bob","peerDeviceId":"","conversationId":"old1"}]"#
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertEqual(store.claimedDirectIds, ["old1"])
        backend.groupRows = [("old1", ["carol", "dave"])]
        _ = await store.refreshGroups()
        XCTAssertTrue(store.invitations.isEmpty)
        XCTAssertEqual(store.route("old1"), .direct)
    }

    // MARK: The load-order window

    func testNothingServerDrivenHappensBeforeBothStoresAreRead() async {
        // The cache holds a group. The server lists (and delivers into) its id as a DM while
        // the stores are still being read.
        backend.kv["sidebar.groups"] = #"[{"conversationId":"g1","memberUserIds":["carol","dave"],"claimedNames":{}}]"#
        backend.dmRows = [ListedDM(conversationId: "g1", peerUserId: "mallory", peerUsername: "")]
        backend.groupRows = [("g9", ["x", "y"])]
        backend.held.insert("kvGet")
        let loading = Task { await store.load() }
        await settle()
        XCTAssertFalse(store.ready)

        // Everything server-driven that starts in the window waits for the stores…
        let listing = Task { await store.refreshDMList() }
        let delivery = Task { await store.deliverDM(conversationId: "g1", peerUserId: "mallory") }
        let grouping = Task { await store.refreshGroups() }
        await settle()
        // …and nothing has been asked of the server, or decided, meanwhile.
        XCTAssertEqual(backend.groupListings, 0)
        XCTAssertEqual(store.route("g1"), .unknown)
        XCTAssertEqual(store.addDM(dm("g1", "mallory")), .refused)
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertTrue(store.invitations.isEmpty)

        backend.release("kvGet")
        let loaded = await loading.value
        XCTAssertTrue(loaded)
        // Decided only now, against the group that was in the cache all along.
        let added = await listing.value
        let delivered = await delivery.value
        _ = await grouping.value
        XCTAssertTrue(added.isEmpty)
        XCTAssertNil(delivered)
        // Now the same listing is checked against the group that was there all along.
        _ = await store.refreshDMList()
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.route("g1"), .group)
        XCTAssertEqual(notices, [.conflict(conversationId: "g1")])
    }

    func testAStoreThatCannotBeReadIsNotAnEmptyStore() async {
        // The client is up WITHOUT this workspace's cache (no key yet, the notification
        // extension holds the lock, the file would not open) — and the server lists things.
        let stored = #"[{"conversationId":"g1","memberUserIds":["carol","dave"]}]"#   // as stored without names: still a group
        backend.kv["sidebar.groups"] = stored
        backend.kv["w1|sidebar.dms"] = #"[{"id":"7E6C3E0B-58C5-4B4E-9C0A-0E3B0C0A7A11","name":"bob","peerUserId":"bob","peerDeviceId":"dev","conversationId":"dm1","startedHere":true}]"#
        let before = backend.kv
        backend.cacheClosed = true
        backend.groupRows = [("g1", ["carol", "dave", "mallory"]), ("g2", ["erin", "frank"])]
        backend.dmRows = [ListedDM(conversationId: "g1", peerUserId: "mallory", peerUsername: ""),
                          ListedDM(conversationId: "dm2", peerUserId: "zed", peerUsername: "zed")]
        let loaded = await store.load()
        XCTAssertFalse(loaded)
        XCTAssertFalse(store.ready)
        let added = await store.refreshDMList()
        let delivered = await store.deliverDM(conversationId: "g1", peerUserId: "mallory")
        let asked = await store.refreshGroups()
        let place = await store.place(ofEventIn: "g1", since: store.listingMark())
        XCTAssertTrue(added.isEmpty)
        XCTAssertNil(delivered)
        XCTAssertFalse(asked)
        XCTAssertEqual(place, .nothing)
        XCTAssertEqual(store.addDM(dm("dm3", "erin")), .refused)
        XCTAssertNil(store.accept(GroupDM(conversationId: "g1", memberUserIds: ["carol", "dave", "mallory"])))
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertTrue(store.groups.isEmpty)
        XCTAssertTrue(store.invitations.isEmpty, "an accepted group is never offered again as an invitation")
        await store.flush()
        XCTAssertTrue(backend.writes.isEmpty, "nothing is written over a store that could not be read")
        XCTAssertEqual(backend.kv, before)

        // The next bind has the cache: the SAME calls now read what was stored all along.
        backend.cacheClosed = false
        let again = await store.refreshGroups()
        XCTAssertTrue(again)
        XCTAssertEqual(store.groups.map(\.conversationId), ["g1"])
        XCTAssertEqual(store.groups[0].memberUserIds, ["carol", "dave"], "the members this device fixed, not the server's")
        XCTAssertEqual(store.groups[0].serverDisagrees, true)
        XCTAssertEqual(store.invitations.map(\.conversationId), ["g2"])
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm1"])
        _ = await store.refreshDMList()
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm2", "dm1"])
        XCTAssertEqual(notices, [.conflict(conversationId: "g1")])
    }

    func testTheBackendOnlyReachesTheCacheThroughAClientThatHasItOpen() {
        let binding = ClientBinding<Int>()
        let first = binding.begin()
        XCTAssertTrue(binding.commit(first, workspaceId: "w1", client: 1, cacheOpen: false))
        XCTAssertEqual(binding.bound?.turn, first)
        // Up, and usable for asking the server — but not for reading or writing the stores.
        XCTAssertEqual(try BoundClient.of(binding.bound, for: "w1"), 1)
        XCTAssertThrowsError(try BoundClient.withCache(binding.bound, for: "w1"))
        // The retry binds again, this time with the cache: a new turn, so it is read again.
        let second = binding.begin()
        XCTAssertTrue(binding.commit(second, workspaceId: "w1", client: 2, cacheOpen: true))
        XCTAssertNotEqual(binding.bound?.turn, first)
        XCTAssertEqual(try BoundClient.withCache(binding.bound, for: "w1"), 2)
        XCTAssertThrowsError(try BoundClient.withCache(binding.bound, for: "w2"))
        XCTAssertThrowsError(try BoundClient<Int>.withCache(nil, for: "w1"))
    }

    // MARK: A stored list that cannot be decoded is kept, said, and started again

    func testAnUndecodableListIsKeptAsideSaidAndStartedAgain() async {
        let bad = "{ not the groups"
        backend.kv["sidebar.groups"] = bad
        backend.kv["w1|sidebar.dms"] = #"[{"id":"7E6C3E0B-58C5-4B4E-9C0A-0E3B0C0A7A11","name":"bob","peerUserId":"bob","peerDeviceId":"dev","conversationId":"dm1","startedHere":true}]"#
        store.clock = { 1000 }
        let loaded = await store.load()
        XCTAssertTrue(loaded, "not shut for good")
        XCTAssertEqual(backend.kv["sidebar.groups.unreadable.1000"], bad, "the bytes are kept exactly")
        XCTAssertEqual(notices, [.unreadable(list: "groups", keptAs: "sidebar.groups.unreadable.1000")])
        XCTAssertTrue(store.groups.isEmpty)
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm1"], "the list that could be read is untouched")
        await store.flush()
        XCTAssertEqual(backend.kv["sidebar.groups"], "[]")
        XCTAssertEqual(backend.kv["sidebar.groups.unreadable.1000"], bad)

        // It happens again later: a second copy, the first is not written over.
        backend.kv["sidebar.groups"] = "[[["
        let relaunched = makeStore()
        relaunched.clock = { 2000 }
        let reloaded = await relaunched.load()
        XCTAssertTrue(reloaded)
        XCTAssertEqual(backend.kv["sidebar.groups.unreadable.1000"], bad)
        XCTAssertEqual(backend.kv["sidebar.groups.unreadable.2000"], "[[[")
        XCTAssertEqual(notices.count, 2)
    }

    func testWhatCanStillBeReadIsSalvagedAndALostGroupNeverComesBackAsAPlainInvitation() async {
        // One element of the groups list is damaged; its id can still be read.
        let bad = #"[{"conversationId":"g1","memberUserIds":["carol","dave"],"claimedNames":{}},{"conversationId":"g2","memberUserIds":"oops"},{"conversationId":"g3","memberUserIds":["erin","frank"]},17]"#
        backend.kv["sidebar.groups"] = bad
        store.clock = { 1000 }
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertEqual(store.groups.map(\.conversationId), ["g1", "g3"], "the readable groups are still joined, with their members")
        XCTAssertEqual(store.groups[0].memberUserIds, ["carol", "dave"])
        XCTAssertEqual(store.review.group, ["g2"])
        XCTAssertEqual(backend.kv["sidebar.groups.unreadable.1000"], bad)
        XCTAssertNotNil(backend.kv["w1|conversations.review"], "the record is written before the salvaged list replaces the original")
        XCTAssertEqual(backend.writes.map(\.key).prefix(3), ["sidebar.groups.unreadable.1000", "sidebar.groups.latest.unreadable", "w1|conversations.review"])
        await store.flush()
        // The server lists the lost group with a ghost in it, and a group that really is new.
        backend.groupRows = [("g2", ["gil", "hana", "mallory"]), ("g4", ["ivy", "jon"])]
        backend.dmRows = [ListedDM(conversationId: "g2", peerUserId: "mallory", peerUsername: "")]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.map(\.conversationId), ["g2", "g4"])
        XCTAssertEqual(store.invitations.map { $0.needsReview == true }, [true, false], "shown as needing review, not as a new invitation")
        XCTAssertNil(store.group(for: "g2"), "never silently re-joined with the server's members")
        // Nothing server-driven makes it a direct conversation either; nor does "open a chat".
        let added = await store.refreshDMList()
        let delivered = await store.deliverDM(conversationId: "g2", peerUserId: "mallory")
        XCTAssertTrue(added.isEmpty)
        XCTAssertNil(delivered)
        XCTAssertEqual(store.addDM(dm("g2", "mallory")), .refused)
        XCTAssertTrue(store.dms.isEmpty)
        // The user reviews it and joins: those members, and nothing left to review.
        guard case .joined(let rejoined) = store.join(store.invitations[0]) else { return XCTFail("not joined") }
        XCTAssertEqual(rejoined.memberUserIds, ["gil", "hana", "mallory"])
        XCTAssertTrue(store.review.group.isEmpty)
        await store.flush()
        // Next launch: everything reads; nothing is kept aside again.
        let relaunched = makeStore()
        let again = await relaunched.load()
        XCTAssertTrue(again)
        XCTAssertEqual(Set(relaunched.groups.map(\.conversationId)), ["g1", "g2", "g3"])
        XCTAssertEqual(relaunched.review, ConversationStore.Review())
        XCTAssertEqual(backend.kv.keys.filter { $0.contains(".unreadable.") }.count, 1)
    }

    func testALostDirectEntryIsNotRecreatedByTheServerOnlyByTheUser() async {
        backend.kv["w1|sidebar.dms"] = #"[{"id":"7E6C3E0B-58C5-4B4E-9C0A-0E3B0C0A7A11","name":"bob","peerUserId":"bob","peerDeviceId":"dev","conversationId":"dm1","startedHere":true},{"conversationId":"dmX","peerUserId":42}]"#
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm1"])
        XCTAssertEqual(store.review.direct, ["dmX"])
        // The server offers the lost id back — as a DM with someone, and as a group.
        backend.dmRows = [ListedDM(conversationId: "dmX", peerUserId: "mallory", peerUsername: "bob")]
        backend.groupRows = [("dmX", ["mallory", "zed"])]
        let added = await store.refreshDMList()
        _ = await store.refreshGroups()
        let delivered = await store.deliverDM(conversationId: "dmX", peerUserId: "mallory")
        XCTAssertTrue(added.isEmpty)
        XCTAssertNil(delivered)
        XCTAssertTrue(store.invitations.isEmpty)
        backend.openGroupAnswer = "dmX"
        do { _ = try await store.startGroup(memberUserIds: ["carol", "dave"], names: [:]); XCTFail("started") } catch { XCTAssertEqual(error as? ConversationError, .conflict) }
        // The user opens the chat again: theirs, and no longer lost.
        guard case .added = store.addDM(dm("dmX", "bob")) else { return XCTFail("not added") }
        XCTAssertTrue(store.review.direct.isEmpty)
    }

    func testAGroupsListThatCannotBeReadAtAllMakesEveryListedGroupOneToReview() async {
        backend.kv["sidebar.groups"] = "{ not the groups"
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertTrue(store.review.allGroups)
        backend.groupRows = [("g1", ["carol", "dave", "mallory"]), ("g2", ["erin", "frank"])]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.map { $0.needsReview == true }, [true, true])
        XCTAssertTrue(store.groups.isEmpty)
        // …also when it is the review record itself that cannot be read.
        backend.kv = ["w1|conversations.review": "nope"]
        let other = makeStore()
        let reloaded = await other.load()
        XCTAssertTrue(reloaded)
        XCTAssertTrue(other.review.allGroups)
        XCTAssertEqual(backend.kv.first { $0.key.hasPrefix("w1|conversations.review.unreadable.") }?.value, "nope")
    }

    func testAnUndecodableListThatCannotBeKeptLeavesTheStoreShut() async {
        backend.kv["w1|sidebar.dms"] = "not json"
        backend.failWrites = true
        let loaded = await store.load()
        XCTAssertFalse(loaded)
        XCTAssertFalse(store.ready)
        XCTAssertEqual(backend.kv["w1|sidebar.dms"], "not json")
        XCTAssertTrue(notices.isEmpty)
        // Once it can be kept, the store opens.
        backend.failWrites = false
        let again = await store.load()
        XCTAssertTrue(again)
        XCTAssertEqual(backend.kv.keys.filter { $0.hasPrefix("w1|sidebar.dms.unreadable.") }.count, 1)
        XCTAssertEqual(backend.kv.first { $0.key.hasPrefix("w1|sidebar.dms.unreadable.") }?.value, "not json")
    }

    func testAReadThatFailsIsNeverKeptAsideAsUndecodable() async {
        backend.kv["sidebar.groups"] = #"[{"conversationId":"g1","memberUserIds":["carol","dave"],"claimedNames":{}}]"#
        backend.cacheClosed = true
        let loaded = await store.load()
        XCTAssertFalse(loaded)
        backend.cacheClosed = false
        XCTAssertEqual(backend.kv.count, 1)
        XCTAssertTrue(backend.writes.isEmpty)
        XCTAssertTrue(notices.isEmpty)
    }

    // MARK: A store only ever uses its own workspace's client

    func testAStoreNeverReadsOrWritesThroughAnotherWorkspacesClient() async {
        // What the app does: the backend of w1's store takes its client from the
        // (workspace, client) pair that is bound right now.
        @MainActor final class Routed: ConversationBackend {
            var bound: BoundClient<FakeBackend>?
            private func c() throws -> FakeBackend { try BoundClient.of(bound, for: "w1") }
            func kvGet(key: String) async throws -> String? { try await c().kvGet(key: key) }
            func kvSet(key: String, value: String) async throws { try await c().kvSet(key: key, value: value) }
            func listDms() async throws -> [ListedDM] { try await c().listDms() }
            func listGroupDms() async throws -> [(conversationId: String, memberUserIds: [String])] { try await c().listGroupDms() }
            func findUserId(username: String) async throws -> String { try await c().findUserId(username: username) }
            func openGroupDm(memberUserIds: [String]) async throws -> String { try await c().openGroupDm(memberUserIds: memberUserIds) }
        }
        let other = FakeBackend()   // workspace w2's cache and server
        other.kv["sidebar.groups"] = #"[{"conversationId":"theirs","memberUserIds":["x","y"],"claimedNames":{}}]"#
        other.dmRows = [ListedDM(conversationId: "theirs-2", peerUserId: "zed", peerUsername: "")]
        let routed = Routed()
        routed.bound = BoundClient(workspaceId: "w2", client: other)   // mid-switch: w2's client is up
        let w1 = ConversationStore(backend: routed, workspaceId: "w1")
        // Nothing of w2 is read as w1's, and w1's gate stays shut (not "empty").
        let early = await w1.load()
        let added = await w1.refreshDMList()
        let asked = await w1.refreshGroups()
        XCTAssertFalse(early); XCTAssertFalse(w1.ready)
        XCTAssertTrue(added.isEmpty); XCTAssertFalse(asked)
        XCTAssertTrue(w1.groups.isEmpty); XCTAssertTrue(w1.dms.isEmpty)
        routed.bound = nil
        let none = await w1.load()
        XCTAssertFalse(none)
        // w1's own client is bound: the next thing that needs the stores reads them — w1's.
        routed.bound = BoundClient(workspaceId: "w1", client: backend)
        _ = await w1.refreshDMList()
        XCTAssertTrue(w1.ready); XCTAssertTrue(w1.groups.isEmpty)
        XCTAssertNotEqual(w1.addDM(dm("mine", "bob")), .refused)
        await w1.flush()
        // A switch away before a save: not written into w2's cache, and not lost.
        routed.bound = BoundClient(workspaceId: "w2", client: other)
        w1.claimDM(conversationId: "mine", peerUserId: "bob")
        XCTAssertNotEqual(w1.addDM(dm("mine2", "erin")), .refused)
        await w1.flush()
        XCTAssertTrue(other.writes.isEmpty)
        routed.bound = BoundClient(workspaceId: "w1", client: backend)
        await w1.flush()
        let saved = try? JSONDecoder().decode([DMConversation].self, from: Data((backend.kv["w1|sidebar.dms"] ?? "").utf8))
        XCTAssertEqual(saved?.map(\.conversationId), ["mine2", "mine"])
        XCTAssertTrue(other.writes.isEmpty)
        XCTAssertThrowsError(try BoundClient.of(BoundClient(workspaceId: "w2", client: 1), for: "w1"))
        XCTAssertThrowsError(try BoundClient<Int>.of(nil, for: "w1"))
        XCTAssertEqual(try BoundClient.of(BoundClient(workspaceId: "w1", client: 1), for: "w1"), 1)
    }

    // MARK: Accept / start racing a refresh

    func testAnAcceptDuringARefreshIsNotReverted() async {
        await loadedWithOneOfEach()
        backend.groupRows = [("g1", ["carol", "dave"]), ("g2", ["erin", "frank"])]
        _ = await store.refreshGroups()
        let invitation = store.invitations[0]
        // A refresh is in flight (the listing has been "sent"); the user accepts g2 and starts
        // g3 before it comes back. The old code wrote its pre-request copy back over both.
        backend.held.insert("listGroupDms")
        let refresh = Task { await store.refreshGroups() }
        await settle()
        XCTAssertEqual(backend.waiting["listGroupDms"], 1)
        XCTAssertNotNil(store.accept(invitation))
        backend.openGroupAnswer = "g3"
        let started = try? await store.startGroup(memberUserIds: ["gina", "hal"], names: [:])
        XCTAssertNotNil(started)
        backend.release("listGroupDms")
        let asked = await refresh.value
        XCTAssertTrue(asked)
        XCTAssertEqual(Set(store.groups.map(\.conversationId)), ["g1", "g2", "g3"])
        XCTAssertTrue(store.invitations.isEmpty)
        await store.flush()
        let saved = try? JSONDecoder().decode([GroupDM].self, from: Data((backend.kv["sidebar.groups"] ?? "").utf8))
        XCTAssertEqual(Set((saved ?? []).map(\.conversationId)), ["g1", "g2", "g3"])
    }

    func testAListingNeverRemovesOrReMembersAnAcceptedGroup() async {
        await loadedWithOneOfEach()
        backend.groupRows = []
        _ = await store.refreshGroups()
        assertUntouched()
        backend.groupRows = [("g1", ["carol", "dave", "ghost"])]
        _ = await store.refreshGroups()
        assertUntouched()
        XCTAssertEqual(store.groups[0].serverDisagrees, true)
        // Listed twice, once truthfully: still flagged.
        backend.groupRows = [("g1", ["carol", "dave", "ghost"]), ("g1", ["dave", "carol"])]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.groups[0].serverDisagrees, true)
        backend.groupRows = [("g1", ["dave", "carol"])]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.groups[0].serverDisagrees, false)
    }

    func testARepeatedListingMakesOneInvitation() async {
        _ = await store.load()
        backend.groupRows = [("g2", ["erin", "frank"]), ("g2", ["erin", "mallory"]), ("g2", ["erin", "frank"])]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.invitations.count, 1)
        XCTAssertEqual(store.invitations[0].memberUserIds, ["erin", "frank"])
    }

    func testABurstOfUnknownConversationsIsOneListing() async {
        await loadedWithOneOfEach()
        let before = backend.groupListings
        let mark = store.listingMark()
        backend.held.insert("listGroupDms")
        let waiters = (0..<20).map { _ in Task { await store.groupsListed(since: mark) } }
        await settle()
        backend.release("listGroupDms")
        for w in waiters { let ok = await w.value; XCTAssertTrue(ok) }
        // …and the rest of the same batch, looked at afterwards, asks nothing more.
        let again = await store.groupsListed(since: mark)
        XCTAssertTrue(again)
        XCTAssertEqual(backend.groupListings, before + 1)
    }

    func testAMarkTakenDuringAListingWaitsForANewerOneAndEnds() async {
        await loadedWithOneOfEach()
        let before = backend.groupListings
        backend.held.insert("listGroupDms")
        let early = store.listingMark()
        let first = Task { await store.groupsListed(since: early) }
        while backend.waiting["listGroupDms", default: 0] < 1 { await Task.yield() }
        // A second batch arrives while that listing is with the server: its mark is the
        // listing's own number, so that listing started too early to count for it.
        let during = store.listingMark()
        XCTAssertEqual(during, early + 1)
        let second = (0..<5).map { _ in Task { await store.groupsListed(since: during) } }
        await settle()
        // What the server answers the SECOND time is what the second batch must see.
        backend.groupRows = [("late", ["erin", "frank"])]
        backend.release("listGroupDms")
        let ok = await first.value
        XCTAssertTrue(ok)
        for w in second { let ok = await w.value; XCTAssertTrue(ok) }
        XCTAssertEqual(backend.groupListings, before + 2, "one newer listing for the whole second batch")
        XCTAssertEqual(store.invitations.map(\.conversationId), ["late"])
        // …also when the first listing FAILS: the second batch still gets its own.
        backend.failListings = true
        backend.held.insert("listGroupDms")
        let mark = store.listingMark()
        let failing = Task { await store.groupsListed(since: mark) }
        while backend.waiting["listGroupDms", default: 0] < 2 { await Task.yield() }
        backend.failListings = false
        let later = Task { await store.groupsListed(since: store.listingMark()) }
        await settle()
        backend.release("listGroupDms")
        let failed = await failing.value, succeeded = await later.value
        XCTAssertFalse(failed)
        XCTAssertTrue(succeeded)
    }

    func testAnEventIsPlacedByWhatThisDeviceHolds() async {
        await loadedWithOneOfEach()
        // Held: decided without asking anyone.
        let asked = backend.groupListings
        var place = await store.place(ofEventIn: "g1", since: store.listingMark())
        XCTAssertEqual(place, .group(store.groups[0]))
        place = await store.place(ofEventIn: "dm1", since: store.listingMark())
        XCTAssertEqual(place, .direct)
        XCTAssertEqual(backend.groupListings, asked)
        // Unknown: the groups are asked first. A listed group is an invitation — never direct.
        backend.groupRows = [("g2", ["erin", "frank"]), ("g3", ["gil", "hana"])]
        let mark = store.listingMark()
        place = await store.place(ofEventIn: "g2", since: mark)
        XCTAssertEqual(place, .invitation)
        // An ignored group: nothing, and nothing of it becomes a direct conversation.
        store.decline(store.invitations.first { $0.conversationId == "g3" }!)
        place = await store.place(ofEventIn: "g3", since: mark)
        XCTAssertEqual(place, .nothing)
        let delivered = await store.deliverDM(conversationId: "g3", peerUserId: "gil")
        XCTAssertNil(delivered)
        // Unknown and not a listed group: direct. One listing served the whole batch.
        place = await store.place(ofEventIn: "dm9", since: mark)
        XCTAssertEqual(place, .direct)
        XCTAssertEqual(backend.groupListings, asked + 1)
        // Unknown, and the groups cannot be asked: held back.
        backend.failListings = true
        place = await store.place(ofEventIn: "dm10", since: store.listingMark())
        XCTAssertEqual(place, .nothing)
    }

    func testOnlyWhatTheStoresAcceptIsShownOrAnnounced() async {
        await loadedWithOneOfEach()
        func decide(_ id: String, _ sender: String, fromSelf: Bool = false) async -> ConversationStore.Verdict {
            await store.decide(conversationId: id, senderId: sender, fromSelf: fromSelf, since: store.listingMark())
        }
        // A group: its stored members and this account's own copies; a ghost is dropped, said once.
        var verdict = await decide("g1", "carol")
        XCTAssertEqual(verdict, .group(store.groups[0]))
        verdict = await decide("g1", "me", fromSelf: true)
        XCTAssertEqual(verdict, .group(store.groups[0]))
        verdict = await decide("g1", "mallory")
        XCTAssertEqual(verdict, .drop)
        verdict = await decide("g1", "mallory")
        XCTAssertEqual(verdict, .drop)
        XCTAssertEqual(notices, [.outsider(conversationId: "g1")])
        // A direct conversation: its peer; a second account under the id is dropped, said once.
        verdict = await decide("dm1", "bob")
        XCTAssertEqual(verdict, .direct(name: "bob", isNew: false))
        verdict = await decide("dm1", "mallory")
        XCTAssertEqual(verdict, .drop)
        XCTAssertEqual(notices, [.outsider(conversationId: "g1"), .otherPeer(conversationId: "dm1")])
        // New and direct: listed (unclaimed), with the name the server row claims for that account.
        backend.dmRows = [ListedDM(conversationId: "dm2", peerUserId: "zed", peerUsername: "zed")]
        backend.directory = ["zed": "zed"]
        verdict = await decide("dm2", "zed")
        XCTAssertEqual(verdict, .direct(name: "zed", isNew: true))
        // An unclaimed direct entry under an id the server then lists as a group: the
        // invitation, or the user's "ignore", decides — nothing of it is direct any more.
        backend.groupRows = [("dm2", ["zed", "yan"]), ("g3", ["gil", "hana"])]
        let listed = await store.refreshGroups()
        XCTAssertTrue(listed)
        XCTAssertEqual(store.route("dm2"), .direct, "the existing entry still routes its id…")
        verdict = await decide("dm2", "zed")
        XCTAssertEqual(verdict, .drop, "…but nothing of an unaccepted group is shown as direct")
        store.decline(store.invitations.first { $0.conversationId == "g3" }!)
        verdict = await decide("g3", "gil")
        XCTAssertEqual(verdict, .drop)
        verdict = await decide("gX", "erin")   // unknown, not a group: direct
        XCTAssertEqual(verdict, .direct(name: "", isNew: true))
        // Not read: nothing at all.
        backend.cacheClosed = true
        let unread = makeStore()
        let nothing = await unread.decide(conversationId: "dm1", senderId: "bob", fromSelf: false, since: 0)
        XCTAssertEqual(nothing, .drop)
    }

    /// Build 45: the core's sealed group marker (`DmEvent.is_group`) decides group or 1:1 —
    /// and with it, when an unclaimed direct entry gives way to a group (audit A16).
    func testTheCoresGroupMarkerDecidesGroupOrDirect() async {
        await loadedWithOneOfEach()
        func decide(_ id: String, _ sender: String, isGroup: Bool) async -> ConversationStore.Verdict {
            await store.decide(conversationId: id, senderId: sender, fromSelf: false, since: store.listingMark(), isGroup: isGroup)
        }
        // A bare (1:1) payload is never shown in a group, a group-marked one never as direct.
        var verdict = await decide("g1", "carol", isGroup: false)
        XCTAssertEqual(verdict, .drop)
        verdict = await decide("g1", "carol", isGroup: true)
        XCTAssertEqual(verdict, .group(store.groups[0]))
        verdict = await decide("dm1", "bob", isGroup: false)
        XCTAssertEqual(verdict, .direct(name: "bob", isNew: false))
        // Group-marked, unknown, and no listing names a group under it: not filed as direct,
        // and no direct entry is made for it.
        verdict = await decide("gNew", "erin", isGroup: true)
        XCTAssertEqual(verdict, .drop)
        XCTAssertFalse(store.dms.contains { $0.conversationId == "gNew" })
        // Group-marked under the id of a CLAIMED direct conversation: the conversation keeps its
        // id, the event is dropped and said once.
        verdict = await decide("dm1", "bob", isGroup: true)
        XCTAssertEqual(verdict, .drop)
        XCTAssertEqual(store.dms.map(\.conversationId), ["dm1"])
        XCTAssertTrue(notices.contains(.conflict(conversationId: "dm1")))
        // An UNCLAIMED direct entry (listed / delivered, nothing of the user's) gives way to a
        // group-marked event: the id becomes the group the server lists — an invitation.
        backend.dmRows = [ListedDM(conversationId: "dm2", peerUserId: "zed", peerUsername: "zed")]
        backend.directory = ["zed": "zed"]
        verdict = await decide("dm2", "zed", isGroup: false)
        XCTAssertEqual(verdict, .direct(name: "zed", isNew: true))
        XCTAssertEqual(store.dms.first { $0.conversationId == "dm2" }?.isClaimed, false)
        backend.groupRows = [("dm2", ["zed", "yan"])]
        verdict = await decide("dm2", "zed", isGroup: true)
        XCTAssertEqual(verdict, .invitation)
        XCTAssertFalse(store.dms.contains { $0.conversationId == "dm2" }, "the unclaimed direct entry gave way")
        XCTAssertEqual(store.route("dm2"), .invitation)
        // No marker (a build-44 event): decided by the stores alone, as before.
        verdict = await store.decide(conversationId: "dm1", senderId: "bob", fromSelf: false, since: store.listingMark())
        XCTAssertEqual(verdict, .direct(name: "bob", isNew: false))
    }

    func testAnUnknownConversationIsNotDecidedWhenTheGroupsCannotBeAsked() async {
        await loadedWithOneOfEach()
        backend.failListings = true
        let asked = await store.groupsListed(since: store.listingMark())
        XCTAssertFalse(asked)
    }

    // MARK: Saving, notices

    func testSavesLandInOrder() async {
        _ = await store.load()
        backend.held.insert("kvSet")
        for i in 0..<5 { _ = store.addDM(dm("c\(i)", "p\(i)")) }
        await settle()
        backend.release("kvSet")
        await store.flush()
        let last = backend.writes.last { $0.key == "w1|sidebar.dms" }
        let saved = try? JSONDecoder().decode([DMConversation].self, from: Data((last?.value ?? "").utf8))
        XCTAssertEqual(saved?.map(\.conversationId), ["c4", "c3", "c2", "c1", "c0"])
        XCTAssertEqual(saved, store.dms)
    }

    func testANoticeIsSaidOnceAcrossLaunches() async {
        await loadedWithOneOfEach()
        for _ in 0..<3 { _ = await store.deliverDM(conversationId: "g1", peerUserId: "mallory") }
        store.notice(.outsider(conversationId: "g1"))
        store.notice(.outsider(conversationId: "g1"))
        XCTAssertEqual(notices, [.conflict(conversationId: "g1"), .outsider(conversationId: "g1")])
        await store.flush()
        // Next launch: a new store over the same cache.
        notices = []
        store = makeStore()
        _ = await store.load()
        _ = await store.deliverDM(conversationId: "g1", peerUserId: "mallory")
        store.notice(.outsider(conversationId: "g1"))
        XCTAssertTrue(notices.isEmpty)
        XCTAssertEqual(store.groups.map(\.conversationId), ["g1"])
    }

    // MARK: Who the notification extension may announce

    func testWhatCouldNotBeWrittenIsNotLostWhenTheClientGoes() async {
        await loadedWithOneOfEach()
        // The cache closes (the client is going); the user's last change cannot be written.
        backend.cacheClosed = true
        XCTAssertEqual(store.addDM(dm("dm2", "erin")), .added(store.dms[0]))
        await store.flush()
        XCTAssertTrue(store.hasUnsaved, "kept, not dropped")
        XCTAssertNil(backend.writes.last { $0.key == "w1|sidebar.dms" && $0.value.contains("dm2") })
        // The SAME store is taken up again on the workspace's next bind (the app parks it): it
        // still holds the change, and writes it.
        backend.cacheClosed = false
        await store.flush()
        XCTAssertFalse(store.hasUnsaved)
        XCTAssertTrue(backend.kv["w1|sidebar.dms"]?.contains("dm2") == true)
        // Sign-out cannot wait: the pending writes are handed over, once, as they are now.
        backend.cacheClosed = true
        store.claimDM(conversationId: "dm2", peerUserId: "erin")
        _ = store.addDM(dm("dm3", "zed"))
        await store.flush()
        let handed = store.takeUnsaved()
        XCTAssertEqual(handed.map(\.key), ["w1|sidebar.dms"])
        XCTAssertTrue(handed[0].value.contains("dm3"))
        XCTAssertFalse(store.hasUnsaved)
        XCTAssertTrue(store.takeUnsaved().isEmpty)
    }

    func testNothingIsAnnouncedUnderAnIdOfWhichNothingIsShown() async {
        await loadedWithOneOfEach()
        _ = await store.deliverDM(conversationId: "x1", peerUserId: "erin")
        _ = await store.deliverDM(conversationId: "x2", peerUserId: "gil")
        backend.groupRows = [("x1", ["erin", "frank"]), ("x2", ["gil", "hana"])]
        _ = await store.refreshGroups()
        store.decline(store.invitations.first { $0.conversationId == "x2" }!)
        XCTAssertEqual(store.silentIds, ["x1", "x2"])
        let senders = NotificationSenders.allowed(dms: store.dms, groups: store.groups, silent: store.silentIds)
        // The unclaimed direct entries exist, but the app shows nothing under an invitation or
        // an ignored group — and neither does the extension.
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:x1", authorId: "erin", senders: senders))
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:x2", authorId: "gil", senders: senders))
        XCTAssertTrue(NotificationSenders.mayAnnounce(scope: "dm:dm1", authorId: "bob", senders: senders))
        XCTAssertTrue(NotificationSenders.mayAnnounce(scope: "dm:g1", authorId: "carol", senders: senders))
    }

    func testANoticeWhoseRowCouldNotBeStoredIsSaidAgainNextLaunch() async {
        await loadedWithOneOfEach()
        // Security activity cannot write right now.
        activityWrites = false
        for _ in 0..<3 { _ = await store.deliverDM(conversationId: "g1", peerUserId: "mallory") }
        XCTAssertEqual(notices, [.conflict(conversationId: "g1")], "not twice in one launch")
        await store.flush()
        // Next launch: it was never stored, so it is said — and this time it is stored.
        notices = []
        activityWrites = true
        store = makeStore()
        _ = await store.load()
        _ = await store.deliverDM(conversationId: "g1", peerUserId: "mallory")
        XCTAssertEqual(notices, [.conflict(conversationId: "g1")])
        await store.flush()
        notices = []
        store = makeStore()
        _ = await store.load()
        _ = await store.deliverDM(conversationId: "g1", peerUserId: "mallory")
        XCTAssertTrue(notices.isEmpty, "stored: never again")
    }

    func testOnlyAGroupsStoredMembersAreAnnouncedUnderItsTitle() async {
        await loadedWithOneOfEach()
        let senders = NotificationSenders.allowed(dms: store.dms, groups: store.groups)
        XCTAssertTrue(NotificationSenders.mayAnnounce(scope: "dm:g1", authorId: "carol", senders: senders))
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:g1", authorId: "ghost", senders: senders))
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:g1", authorId: nil, senders: senders))
        XCTAssertTrue(NotificationSenders.mayAnnounce(scope: "dm:dm1", authorId: "bob", senders: senders))
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:dm1", authorId: "mallory", senders: senders))
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:unknown", authorId: "bob", senders: senders))
        // Never written (updated, not opened since): no DM content at all; channels as before.
        XCTAssertFalse(NotificationSenders.mayAnnounce(scope: "dm:g1", authorId: "carol", senders: nil))
        XCTAssertTrue(NotificationSenders.mayAnnounce(scope: "channel:c1", authorId: "anyone", senders: nil))
    }

    // ---- two binds that overlap: only the latest puts a client up, under its own workspace ----

    func testOverlappingBindsNeverLabelOneWorkspacesClientAsAnothers() async {
        // What the app's bind does: take a turn, open the cache (a suspension), then commit
        // under the workspace id IT was given — or discard its client if superseded.
        @MainActor final class Binder {
            let binding = ClientBinding<String>()
            var discarded: [String] = []
            func bind(_ workspaceId: String, opened: AsyncStream<Void>) async {
                let turn = binding.begin()
                let client = "client-of-" + workspaceId
                for await _ in opened { break }
                guard binding.isCurrent(turn) else { discarded.append(client); return }
                if !binding.commit(turn, workspaceId: workspaceId, client: client, cacheOpen: true) { discarded.append(client) }
            }
        }
        let binder = Binder(), binding = binder.binding
        var openA: AsyncStream<Void>.Continuation!, openB: AsyncStream<Void>.Continuation!
        let a = AsyncStream<Void> { openA = $0 }, b = AsyncStream<Void> { openB = $0 }
        // bind(w1) starts and is suspended opening its cache; bind(w2) starts during that.
        async let first: Void = binder.bind("w1", opened: a)
        while !binding.isCurrent(1) { await Task.yield() }
        async let second: Void = binder.bind("w2", opened: b)
        while !binding.isCurrent(2) { await Task.yield() }
        XCTAssertNil(binding.bound)
        // w1's cache opens first, while w2's bind is the current one: w1's client is NOT put up
        // — not as w2's (the bug), and not as w1's either.
        openA.yield(); await first
        XCTAssertNil(binding.bound)
        XCTAssertEqual(binder.discarded, ["client-of-w1"])
        XCTAssertThrowsError(try BoundClient.of(binding.bound, for: "w2"))
        openB.yield(); await second
        XCTAssertEqual(binding.bound?.workspaceId, "w2"); XCTAssertEqual(binding.bound?.client, "client-of-w2")
        XCTAssertThrowsError(try BoundClient.of(binding.bound, for: "w1"))

        // The other order: the later bind finishes first; the earlier one then changes nothing.
        let (c, openC) = AsyncStream<Void>.makeStream(), (d, openD) = AsyncStream<Void>.makeStream()
        let base = 2
        async let third: Void = binder.bind("w1", opened: c)
        while !binding.isCurrent(base + 1) { await Task.yield() }
        async let fourth: Void = binder.bind("w2", opened: d)
        while !binding.isCurrent(base + 2) { await Task.yield() }
        openD.yield(); await fourth
        openC.yield(); await third
        XCTAssertEqual(binding.bound?.workspaceId, "w2"); XCTAssertEqual(binding.bound?.client, "client-of-w2")

        // Taking the client down (sign-out, leaving) also ends a bind in flight.
        let (e, openE) = AsyncStream<Void>.makeStream()
        async let fifth: Void = binder.bind("w1", opened: e)
        while !binding.isCurrent(base + 3) { await Task.yield() }
        binding.begin()
        openE.yield(); await fifth
        XCTAssertNil(binding.bound)
        XCTAssertFalse(binding.commit(1, workspaceId: "w1", client: "stale", cacheOpen: true))
        XCTAssertNil(binding.bound)
    }

    // MARK: A server answer belongs to the workspace whose client was asked

    func testAnAnswerHeldAcrossAWorkspaceSwitchIsDecidedNowhere() async {
        await loadedWithOneOfEach()
        let otherBackend = FakeBackend()
        let w2 = ConversationStore(backend: otherBackend, workspaceId: "w2")
        let loaded = await w2.load()
        XCTAssertTrue(loaded)
        let binding = ClientBinding<Int>()
        var current: ConversationStore = store
        XCTAssertTrue(binding.commit(binding.begin(), workspaceId: "w1", client: 1, cacheOpen: true))
        // What the app's handlers do: take the ticket, ask the server, then check it.
        guard let ticket = StoreTicket(boundWorkspaceId: binding.bound?.workspaceId, turn: binding.bound?.turn, store: current) else { return XCTFail("no ticket") }
        backend.held.insert("listGroupDms")
        backend.groupRows = [("gX", ["erin", "frank"])]
        let deciding = Task { await ticket.store.decide(conversationId: "gX", senderId: "erin", fromSelf: false, since: ticket.store.listingMark()) }
        while backend.waiting["listGroupDms", default: 0] < 1 { await Task.yield() }
        // The server holds its answer; the user switches to w2 meanwhile.
        XCTAssertTrue(binding.commit(binding.begin(), workspaceId: "w2", client: 2, cacheOpen: true))
        current = w2
        backend.release("listGroupDms")
        _ = await deciding.value
        XCTAssertFalse(ticket.isCurrent(boundWorkspaceId: binding.bound?.workspaceId, turn: binding.bound?.turn, store: current), "the batch is dropped")
        XCTAssertTrue(w2.dms.isEmpty)
        XCTAssertTrue(w2.invitations.isEmpty, "nothing of w1's answer is in w2's stores")
        XCTAssertEqual(otherBackend.groupListings, 0)
        // Mid-switch (one of the two has changed, the other not yet): no ticket at all.
        XCTAssertNil(StoreTicket(boundWorkspaceId: "w1", turn: 1, store: w2))
        XCTAssertNil(StoreTicket(boundWorkspaceId: nil, turn: nil, store: w2))
        // Back on w1 through a NEW bind: an answer asked of the old client is still not used.
        XCTAssertTrue(binding.commit(binding.begin(), workspaceId: "w1", client: 3, cacheOpen: true))
        current = store
        XCTAssertFalse(ticket.isCurrent(boundWorkspaceId: binding.bound?.workspaceId, turn: binding.bound?.turn, store: current))
    }

    // MARK: Only the members the user was shown can be accepted

    func testAcceptingFixesOnlyTheMembersThatWereOnScreen() async {
        await loadedWithOneOfEach()
        backend.groupRows = [("g2", ["erin", "frank"])]
        _ = await store.refreshGroups()
        let onScreen = store.invitations[0]
        // While the sheet is open, the server lists the conversation with someone else in it.
        backend.groupRows = [("g2", ["erin", "frank", "mallory"])]
        _ = await store.refreshGroups()
        XCTAssertEqual(store.join(onScreen), .changed(store.invitations[0]))
        XCTAssertNil(store.accept(onScreen))
        XCTAssertNil(store.group(for: "g2"), "a member set the user never saw is not fixed")
        XCTAssertEqual(store.invitations.map(\.conversationId), ["g2"])
        // Shown again and accepted as shown: those members, exactly.
        let reviewed = store.invitations[0]
        XCTAssertEqual(store.join(reviewed), .joined(store.groups[0]))
        XCTAssertEqual(Set(store.groups[0].memberUserIds), ["erin", "frank", "mallory"])
        // A second tap on the same sheet: the group as accepted; a stale sheet: nothing.
        XCTAssertEqual(store.join(reviewed), .joined(store.groups[0]))
        XCTAssertEqual(store.join(onScreen), .refused)
        // Names heard meanwhile are not a change of members.
        backend.groupRows = [("g3", ["gil", "hana"])]
        _ = await store.refreshGroups()
        var named = store.invitations[0]
        named.claimedNames = ["gil": "gil"]
        XCTAssertEqual(store.join(named), .joined(store.groups[0]))
    }
}
