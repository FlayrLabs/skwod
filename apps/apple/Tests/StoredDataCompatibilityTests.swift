import XCTest

/// What build 43 (commit 54ba47181) left in a workspace's encrypted cache, read by this build's
/// strict loaders. Build 43 stored three JSON values, each under `<workspace id>|<name>`:
///
/// - `sidebar.dms`    — `[DMConversation]` as `JSONEncoder` wrote it: `id`, `name`, `peerUserId`,
///                      `peerDeviceId`, `conversationId`, and `startedHere` only when set
///                      (no `claimed`);
/// - `sidebar.spaces` — `[RealSpace]`: `id`, `name`, `channelName`, `serverId`, `channelId`,
///                      `inviteCode`, `spaceKeyHex`;
/// - `contacts.v1`    — `[user id: Contact]`: `name`, `level` (`unverified` / `known` / `verified`).
///
/// It stored NO group list, NO ignored-groups list, NO review record and NO Security activity
/// log (those keys do not exist in build 43): the first launch of this build finds them absent.
///
/// An update must read all of it as it is: nothing kept aside as unreadable, nothing to
/// review, no notice, nothing dropped, and every stored conversation still the user's own.
@MainActor
final class StoredDataCompatibilityTests: XCTestCase {
    private var backend: ConversationStoreTests.FakeBackend!
    private var notices: [ConversationStore.Notice] = []

    override func setUp() async throws {
        backend = ConversationStoreTests.FakeBackend()
        notices = []
    }

    private func makeStore() -> ConversationStore {
        let s = ConversationStore(backend: backend, workspaceId: "w43", me: Self.me)
        s.onNotice = { [weak self, weak s] in self?.notices.append($0); s?.stored($0) }
        return s
    }

    private static let me = "5a0d1c5e-7c0b-4c53-9f0e-0f8f6f1f43aa"
    private static let bob = "9c1b7a52-2e0d-4b61-8a3c-51c1e2d0b0b1"
    private static let carol = "0b9f4f1e-63a7-4d0a-b1f4-7e2a0c9d4c02"
    private static let dave = "c3a1e8d4-0f5b-4e7a-9a6d-2b7f8e1d5d03"
    private static let erin = "e4b2f9c5-1a6c-4f8b-8b7e-3c8a9f2e6e04"

    /// `<workspace>|sidebar.dms` as build 43 wrote it, newest first: a chat started here (with
    /// the peer's device id and `startedHere`), one started here before `startedHere` existed,
    /// one a delivery made (no device id, the sender's claimed name) and one the server's
    /// listing made (no name at all).
    private static let dms43 = """
    [{"id":"1D0C6E55-7A0B-4F3B-9E57-3C1C6F1B0A01","name":"dave","peerUserId":"\(dave)","peerDeviceId":"","conversationId":"6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8004"},\
    {"id":"1D0C6E55-7A0B-4F3B-9E57-3C1C6F1B0A02","name":"","peerUserId":"\(erin)","peerDeviceId":"","conversationId":"6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8005"},\
    {"id":"1D0C6E55-7A0B-4F3B-9E57-3C1C6F1B0A03","name":"bobby43","peerUserId":"\(bob)","peerDeviceId":"3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e01","conversationId":"6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8001","startedHere":true},\
    {"id":"1D0C6E55-7A0B-4F3B-9E57-3C1C6F1B0A04","name":"carol","peerUserId":"\(carol)","peerDeviceId":"3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e02","conversationId":"6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8002"}]
    """

    /// `<workspace>|sidebar.spaces`: two channels of one server and one of another, the first
    /// joined with an invite, the others listed later (empty invite, the server's space key).
    private static let spaces43 = """
    [{"id":"2E1D7F66-8B1C-4A4C-8F68-4D2D7A2C1B01","name":"The Crew","channelName":"general","serverId":"a1b2c3d4-0001-4000-8000-000000000001","channelId":"a1b2c3d4-0001-4000-8000-0000000000c1","inviteCode":"Q7KD-2MXP-9RTA","spaceKeyHex":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},\
    {"id":"2E1D7F66-8B1C-4A4C-8F68-4D2D7A2C1B02","name":"The Crew","channelName":"photos","serverId":"a1b2c3d4-0001-4000-8000-000000000001","channelId":"a1b2c3d4-0001-4000-8000-0000000000c2","inviteCode":"","spaceKeyHex":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},\
    {"id":"2E1D7F66-8B1C-4A4C-8F68-4D2D7A2C1B03","name":"Work","channelName":"general","serverId":"a1b2c3d4-0002-4000-8000-000000000002","channelId":"a1b2c3d4-0002-4000-8000-0000000000c3","inviteCode":"","spaceKeyHex":""}]
    """

    /// `<workspace>|contacts.v1`: every level build 43 could store.
    private static let contacts43 = """
    {"\(bob)":{"name":"bobby43","level":"verified"},"\(carol)":{"name":"carol","level":"known"},\
    "\(dave)":{"name":"dave","level":"unverified"},"\(erin)":{"name":"","level":"unverified"}}
    """

    // MARK: The conversation lists, through the real loader

    func testBuild43DirectListLoadsWholeWithNothingKeptAsideOrToReview() async {
        backend.kv["w43|sidebar.dms"] = Self.dms43
        let store = makeStore()
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertTrue(store.ready)
        XCTAssertEqual(store.loadFailures, 0)
        // Every stored entry, in the stored order, with what it held.
        XCTAssertEqual(store.dms.map(\.peerUserId), [Self.dave, Self.erin, Self.bob, Self.carol])
        XCTAssertEqual(store.dms.map(\.name), ["dave", "", "bobby43", "carol"])
        XCTAssertEqual(store.dms.map(\.peerDeviceId), ["", "", "3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e01", "3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e02"])
        XCTAssertEqual(store.dms.map(\.startedHere), [nil, nil, true, nil])
        XCTAssertEqual(store.dms.map(\.id.uuidString).first, "1D0C6E55-7A0B-4F3B-9E57-3C1C6F1B0A01")
        // Stored before entries said whether they claim their id: they all do.
        XCTAssertTrue(store.dms.allSatisfy(\.isClaimed))
        XCTAssertEqual(store.claimedDirectIds.count, 4)
        // Build 43 had no groups: none, none ignored, none invited.
        XCTAssertTrue(store.groups.isEmpty)
        XCTAssertTrue(store.invitations.isEmpty)
        XCTAssertTrue(store.declined.isEmpty)
        // Nothing to review, nothing said, nothing kept aside, nothing rewritten.
        XCTAssertEqual(store.review, ConversationStore.Review())
        XCTAssertFalse(store.review.all)
        XCTAssertTrue(store.silentIds.isEmpty)
        XCTAssertTrue(notices.isEmpty)
        await store.flush()
        XCTAssertTrue(backend.writes.isEmpty, "loading build-43 data wrote \(backend.writes.map(\.key))")
        XCTAssertEqual(Set(backend.kv.keys), ["w43|sidebar.dms"])
        XCTAssertEqual(backend.kv["w43|sidebar.dms"], Self.dms43)
    }

    func testBuild43DirectEntriesKeepTheirIdsAgainstTheServer() async {
        backend.kv["w43|sidebar.dms"] = Self.dms43
        let store = makeStore()
        _ = await store.load()
        let ids = store.dms.map(\.conversationId)
        // The server lists every one of them as a group, and lists the same conversations
        // again as direct: no invitation, no second entry, every one still routed as direct.
        backend.groupRows = ids.map { ($0, [Self.bob, Self.carol]) }
        backend.dmRows = [ListedDM(conversationId: ids[2], peerUserId: Self.bob, peerUsername: "bobby43"),
                          ListedDM(conversationId: ids[3], peerUserId: Self.carol, peerUsername: "carol")]
        _ = await store.refreshGroups()
        let added = await store.refreshDMList()
        XCTAssertTrue(added.isEmpty)
        XCTAssertTrue(store.invitations.isEmpty)
        XCTAssertTrue(store.groups.isEmpty)
        XCTAssertEqual(store.dms.map(\.conversationId), ids)
        for id in ids { XCTAssertEqual(store.route(id), .direct) }
        // A message from the stored peer is shown in the stored conversation, not as a new one.
        let verdict = await store.decide(conversationId: ids[2], senderId: Self.bob, fromSelf: false, since: store.listingMark())
        XCTAssertEqual(verdict, .direct(name: "bobby43", isNew: false))
        // The notification extension may announce exactly the stored peer under each id.
        let allowed = NotificationSenders.allowed(dms: store.dms, groups: store.groups, silent: store.silentIds)
        XCTAssertEqual(allowed["dm:\(ids[2])"], [Self.bob])
        XCTAssertEqual(allowed.count, 4)
    }

    func testAFirstLaunchAfterBuild43WithNoDirectListIsAnEmptyReadyStore() async {
        // A build-43 user who never opened a DM: the key was never written.
        let store = makeStore()
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertTrue(store.dms.isEmpty)
        XCTAssertEqual(store.review, ConversationStore.Review())
        XCTAssertTrue(notices.isEmpty)
        XCTAssertTrue(backend.writes.isEmpty)
        // …and build 43 could store an empty list after the last entry went.
        backend.kv["w43|sidebar.dms"] = "[]"
        let again = makeStore()
        let reloaded = await again.load()
        XCTAssertTrue(reloaded)
        XCTAssertTrue(again.dms.isEmpty)
        XCTAssertTrue(notices.isEmpty)
        XCTAssertTrue(backend.writes.isEmpty)
    }

    /// The ONE build-43 shape that is not read back as it is, by design: two entries under one
    /// conversation id (build 43 could add an entry for another account under an id it held).
    /// This build keeps one entry per id — the user's own — after copying the list as it was,
    /// and says so once. Named here so the behaviour on update is on record, not a surprise.
    func testABuild43ListWithTwoEntriesUnderOneIdIsReducedWithACopyAndANotice() async {
        backend.kv["w43|sidebar.dms"] = """
        [{"id":"1D0C6E55-7A0B-4F3B-9E57-3C1C6F1B0A09","name":"bobby43","peerUserId":"\(Self.erin)","peerDeviceId":"","conversationId":"6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8001"},\
        {"id":"1D0C6E55-7A0B-4F3B-9E57-3C1C6F1B0A03","name":"bobby43","peerUserId":"\(Self.bob)","peerDeviceId":"3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e01","conversationId":"6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8001","startedHere":true}]
        """
        let asStored = backend.kv["w43|sidebar.dms"]
        let store = makeStore()
        store.clock = { 44 }
        let loaded = await store.load()
        XCTAssertTrue(loaded)
        XCTAssertEqual(store.dms.map(\.peerUserId), [Self.bob])
        XCTAssertEqual(backend.kv["w43|sidebar.dms.duplicates.44"], asStored)
        XCTAssertEqual(notices, [.duplicates(keptAs: "w43|sidebar.dms.duplicates.44")])
        // Not "unreadable", and nothing to review.
        XCTAssertEqual(store.review, ConversationStore.Review())
    }

    // MARK: Spaces, contacts, Security activity — the decode the loaders decide on
    //
    // `ChatModel.readSpaces`, `ContactBook.loadIfNeeded` and `AppState.loadSecurityActivity`
    // each try exactly this strict decode of the stored value and keep it aside as unreadable
    // only when it fails. (Those loaders need the app and the core, so what is tested here is
    // the decision they make, with the types they use.)

    func testBuild43SpacesDecodeWholeWithTheStrictDecoder() throws {
        let spaces = try JSONDecoder().decode([RealSpace].self, from: Data(Self.spaces43.utf8))
        XCTAssertEqual(spaces.count, 3)
        XCTAssertEqual(spaces.map(\.name), ["The Crew", "The Crew", "Work"])
        XCTAssertEqual(spaces.map(\.channelName), ["general", "photos", "general"])
        XCTAssertEqual(spaces.map(\.channelId), ["a1b2c3d4-0001-4000-8000-0000000000c1", "a1b2c3d4-0001-4000-8000-0000000000c2", "a1b2c3d4-0002-4000-8000-0000000000c3"])
        XCTAssertEqual(Set(spaces.map(\.serverId)).count, 2)
        // The invite the space was joined with and its key are what a re-read must not lose.
        XCTAssertEqual(spaces[0].inviteCode, "Q7KD-2MXP-9RTA")
        XCTAssertEqual(spaces[0].spaceKeyHex.count, 64)
        XCTAssertEqual(spaces[0].id.uuidString, "2E1D7F66-8B1C-4A4C-8F68-4D2D7A2C1B01")
        // Written back and read again, it is the same list.
        let again = try JSONDecoder().decode([RealSpace].self, from: JSONEncoder().encode(spaces))
        XCTAssertEqual(again, spaces)
        XCTAssertEqual(try JSONDecoder().decode([RealSpace].self, from: Data("[]".utf8)), [])
    }

    func testBuild43ContactBookDecodesWholeAndKeepsEveryLevel() throws {
        let book = try JSONDecoder().decode([String: Contact].self, from: Data(Self.contacts43.utf8))
        XCTAssertEqual(book.count, 4)
        XCTAssertEqual(book[Self.bob], Contact(name: "bobby43", level: .verified))
        XCTAssertEqual(book[Self.carol], Contact(name: "carol", level: .known))
        XCTAssertEqual(book[Self.dave], Contact(name: "dave", level: .unverified))
        XCTAssertEqual(book[Self.erin], Contact(name: "", level: .unverified))
        let again = try JSONDecoder().decode([String: Contact].self, from: JSONEncoder().encode(book))
        XCTAssertEqual(again, book)
        XCTAssertEqual(try JSONDecoder().decode([String: Contact].self, from: Data("{}".utf8)), [:])
    }

    func testSecurityActivityThisBuildWritesReadsBackAndBuild43StoredNone() throws {
        // Build 43 had no Security activity log: the key is absent and the loader starts an
        // empty one (it decodes nothing). What this build then writes must read back whole.
        let events = [SecurityEvent(kind: "device_added", title: "A new device was added", message: "Pixel 9", atMs: 1_763_700_000_000),
                      SecurityEvent(kind: "recovery_key_set", title: "Recovery key turned on", message: "", atMs: 1_763_600_000_000)]
        let stored = try JSONEncoder().encode(events)
        XCTAssertEqual(try JSONDecoder().decode([SecurityEvent].self, from: stored), events)
        XCTAssertEqual(SecurityEvent.merged([], adding: events), events)
        XCTAssertEqual(try JSONDecoder().decode([SecurityEvent].self, from: Data("[]".utf8)), [])
    }
}
