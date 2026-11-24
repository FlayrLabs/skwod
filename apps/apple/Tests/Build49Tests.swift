import XCTest

/// Build 49: what is new in a conversation since this device last read it.
final class Build49Tests: XCTestCase {
    private func item(_ id: String, _ t: Int64, mine: Bool = false, system: Bool = false) -> UnreadItem {
        UnreadItem(id: id, createdAt: t, mine: mine, system: system)
    }
    private lazy var convo: [UnreadItem] = [
        item("a", 1), item("b", 2), item("c", 3, mine: true), item("d", 4), item("e", 5, system: true), item("f", 6),
    ]

    func testNeverOpenedMeansNothingUnread() {
        XCTAssertNil(UnreadRule.firstUnreadIndex(convo, marker: nil))
        XCTAssertEqual(UnreadRule.unreadCount(convo, marker: nil), 0)
    }

    func testFirstUnreadIsAfterTheMarker() {
        let m = ReadMarker(messageId: "d", createdAt: 4)
        XCTAssertEqual(UnreadRule.firstUnreadIndex(convo, marker: m), 5)   // e is a system line
        XCTAssertEqual(UnreadRule.unreadCount(convo, marker: m), 1)
    }

    func testMyOwnMessageMeansIWasHere() {
        let m = ReadMarker(messageId: "a", createdAt: 1)
        // b came before my c: only d and f are new.
        XCTAssertEqual(UnreadRule.firstUnreadIndex(convo, marker: m), 3)
        XCTAssertEqual(UnreadRule.unreadCount(convo, marker: m), 2)
    }

    func testReadToTheEndIsNothingUnread() {
        XCTAssertNil(UnreadRule.firstUnreadIndex(convo, marker: ReadMarker(messageId: "f", createdAt: 6)))
    }

    func testAMarkerOutsideThePageFallsBackToTime() {
        // The marker's message was deleted, or is older than the loaded page.
        let gone = ReadMarker(messageId: "zz", createdAt: 3)
        XCTAssertEqual(UnreadRule.firstUnreadIndex(convo, marker: gone), 3)
        let older = ReadMarker(messageId: "old", createdAt: 0)
        XCTAssertEqual(UnreadRule.firstUnreadIndex(convo, marker: older), 3)   // after my c
        let onlyTheirs = [item("x", 10), item("y", 11)]
        XCTAssertEqual(UnreadRule.unreadCount(onlyTheirs, marker: older), 2)
    }

    func testMarkerNeverMovesBackwards() {
        let m = ReadMarker(messageId: "f", createdAt: 6)
        XCTAssertEqual(UnreadRule.advanced(m, to: item("b", 2)), m)
        XCTAssertEqual(UnreadRule.advanced(m, to: item("g", 7)), ReadMarker(messageId: "g", createdAt: 7))
        XCTAssertEqual(UnreadRule.advanced(nil, to: item("b", 2)), ReadMarker(messageId: "b", createdAt: 2))
        XCTAssertEqual(UnreadRule.readAll(convo, marker: nil), ReadMarker(messageId: "f", createdAt: 6))
        XCTAssertNil(UnreadRule.readAll([], marker: nil))
    }

    func testNewBelowCountsOnlyOthersAfterWhatWasSeen() {
        XCTAssertEqual(UnreadRule.newBelow(convo, lastSeenId: "b"), 2)   // d, f (not my c, not the system e)
        XCTAssertEqual(UnreadRule.newBelow(convo, lastSeenId: "f"), 0)
        XCTAssertEqual(UnreadRule.newBelow(convo, lastSeenId: nil), 0)
        XCTAssertEqual(UnreadRule.newBelow(convo, lastSeenId: "missing"), 0)
    }

    func testKeysArePerSkwodAndConversation() {
        XCTAssertEqual(UnreadRule.storageKey(workspaceId: "w1", conversationId: "c1"), "w1|read.c1")
        XCTAssertNotEqual(UnreadRule.storageKey(workspaceId: "w1", conversationId: "c1"),
                          UnreadRule.storageKey(workspaceId: "w2", conversationId: "c1"))
    }

    func testBarText() {
        let now = Date()
        XCTAssertTrue(UnreadRule.barText(count: 1, since: now, now: now).hasPrefix("1 new message since "))
        XCTAssertTrue(UnreadRule.barText(count: 3, since: now, now: now).hasPrefix("3 new messages since "))
    }

    func testMarkerRoundTripsThroughJSON() throws {
        let m = ReadMarker(messageId: "abc", createdAt: 42)
        let back = try JSONDecoder().decode(ReadMarker.self, from: JSONEncoder().encode(m))
        XCTAssertEqual(back, m)
    }

    // MARK: renaming a server

    func testOnlyOwnersAndAdminsAreOfferedRename() {
        XCTAssertTrue(ServerMenuRule.items(role: .owner, channelsKnown: true).contains(.rename))
        XCTAssertTrue(ServerMenuRule.items(role: .admin, channelsKnown: false).contains(.rename))
        XCTAssertFalse(ServerMenuRule.items(role: .member, channelsKnown: true).contains(.rename))
        XCTAssertFalse(ServerMenuRule.items(role: .member, channelsKnown: false, ownerPinned: false).contains(.rename))
    }

    func testServerNameRule() {
        XCTAssertEqual(ServerNameRule.checked("  Weekend Crew "), .success("Weekend Crew"))
        XCTAssertNotNil(ServerNameRule.problem(""))
        XCTAssertNotNil(ServerNameRule.problem("   "))
        XCTAssertNil(ServerNameRule.problem(String(repeating: "x", count: 100)))
        XCTAssertNotNil(ServerNameRule.problem(String(repeating: "x", count: 101)))
        XCTAssertNil(ServerNameRule.problem(String(repeating: "é", count: 100)))
        XCTAssertNotNil(ServerNameRule.problem("two\nlines"))
        XCTAssertNotNil(ServerNameRule.problem("evil\u{202E}txt"))
    }

    func testServerNameRuleCountsScalarsAndBytesLikeTheCore() {
        // A flag is one Character but two scalars: 50 flags = 100 scalars (OK), 51 = 102 (not).
        XCTAssertNil(ServerNameRule.problem(String(repeating: "🇫🇷", count: 50)))
        XCTAssertNotNil(ServerNameRule.problem(String(repeating: "🇫🇷", count: 51)))
        // 100 scalars of 4 bytes = 400 bytes (OK); the byte cap binds before the scalar cap.
        XCTAssertNil(ServerNameRule.problem(String(repeating: "😀", count: 100)))
    }

    // MARK: build 49 — state from our own other devices

    private func merged(_ synced: Contact, local: Contact? = nil, vouched: Bool = true, mismatched: Bool = false,
                        book: [String: Contact] = [:], userId: String = "u-robin") -> Contact? {
        SiblingRules.mergedContact(userId: userId, local: local, synced: synced, vouched: vouched, mismatched: mismatched, book: book)
    }

    func testASyncedContactNeverBeatsWhatTheUserSetHere() {
        let synced = Contact(name: "Robin", level: .verified)
        // Nothing here: taken, but never above KNOWN (VERIFIED is the core's word, per device set).
        XCTAssertEqual(merged(synced), Contact(name: "Robin", level: .known, known: true))
        // Known or verified here: ours stands.
        XCTAssertNil(merged(synced, local: Contact(name: "Rob", level: .known)))
        XCTAssertNil(merged(Contact(name: "X", level: .known), local: Contact(name: "Rob", level: .verified)))
        // Only server-claimed here: the sibling's name wins.
        XCTAssertEqual(merged(synced, local: Contact(name: "srv", level: .unverified)), Contact(name: "Robin", level: .known, known: true))
        // Not vouched by the sender's snapshot, or held under other keys here: skipped (fail closed).
        XCTAssertNil(merged(synced, vouched: false))
        XCTAssertNil(merged(synced, mismatched: true))
        // An unverified entry stays unverified.
        XCTAssertEqual(merged(Contact(name: "Sam", level: .unverified, known: false)), Contact(name: "Sam", level: .unverified, known: false))
    }

    func testASyncedNameCannotPassItselfOffAsSomeoneTheUserKnows() {
        let book = ["u-alice": Contact(name: "alice", level: .known)]
        // Another account named like a known contact: kept at UNVERIFIED (the look-alike flag shows).
        XCTAssertEqual(merged(Contact(name: "alice", level: .known), book: book, userId: "u-mallory"), Contact(name: "alice", level: .unverified, known: false))
        XCTAssertEqual(merged(Contact(name: "ａｌｉｃｅ", level: .known), book: book, userId: "u-mallory")?.level, .unverified)
        // Characters no Skwod name has: UNVERIFIED.
        XCTAssertEqual(merged(Contact(name: "bob\u{202E}", level: .known))?.level, .unverified)
        // The whole book: the local pin wins, and the second synced "carol" collides with the first.
        let result = SiblingRules.mergedBook(local: book,
                                             synced: ["u-alice": Contact(name: "Alicia", level: .known),
                                                      "u-c1": Contact(name: "carol", level: .known),
                                                      "u-c2": Contact(name: "carol", level: .known),
                                                      "u-x": Contact(name: "alice", level: .known)],
                                             vouched: ["u-alice", "u-c1", "u-c2", "u-x"], mismatched: [])
        XCTAssertEqual(result["u-alice"], Contact(name: "alice", level: .known))
        XCTAssertEqual(result["u-c1"]?.level, .known)
        XCTAssertEqual(result["u-c2"]?.level, .unverified)
        XCTAssertEqual(result["u-x"]?.level, .unverified)
    }

    func testSyncedAvatarsAreValidatedBoundedAndClearsWin() {
        let now: Int64 = 1_000_000
        let small = Data(repeating: 1, count: 1000).base64EncodedString()
        let huge = Data(repeating: 1, count: SiblingRules.maxAvatarBytes + 1).base64EncodedString()
        let ok: (Data) -> Bool = { $0.first == 1 }
        let entries: [SiblingRules.AvatarEntry] = [
            .init(key: "user:a", img: small, ts: 10),
            .init(key: "user:b", img: huge, ts: 10),                       // oversized
            .init(key: "user:c", img: Data([2, 2]).base64EncodedString(), ts: 10), // not an image
            .init(key: "user:mallory", img: small, ts: 10),                // pinned to other keys here
            .init(key: "user:stranger", img: small, ts: 10),               // not in the sender's snapshot
            .init(key: "user:d", img: small, ts: now + 10 * 60 * 1000),    // from the future
            .init(key: "user:e", img: small, ts: 5),                       // older than held
            .init(key: "other:x", img: small, ts: 10),                     // not an avatar key
            .init(key: "user:f", img: "!!", ts: 10),                       // not base64
            .init(key: "user:g", img: nil, ts: 20),                        // cleared after what is held
            .init(key: "user:h", img: nil, ts: 3),                         // a clear older than held
            .init(key: "server:s", img: small, ts: 10),                    // not user-bound
        ]
        let vouched: Set<String> = ["a", "b", "c", "mallory", "d", "e", "f", "g", "h"]
        let got = SiblingRules.acceptedAvatars(entries, vouched: vouched, mismatched: ["mallory"],
                                               heldTs: ["user:e": 9, "user:g": 15, "user:h": 4], now: now, acceptable: ok)
        XCTAssertEqual(Set(got.keys), ["user:a", "user:g", "server:s"])
        XCTAssertNil(got["user:g"]?.data, "a newer clear must win over the picture held here")
        // The batch cap: many pictures stop at the total.
        let many = (0..<40).map { SiblingRules.AvatarEntry(key: "user:\($0)", img: Data(repeating: 1, count: 20_000).base64EncodedString(), ts: 10) }
        let capped = SiblingRules.acceptedAvatars(many, vouched: Set((0..<40).map(String.init)), mismatched: [], heldTs: [:], now: now, acceptable: ok)
        XCTAssertLessThanOrEqual(capped.values.reduce(0) { $0 + ($1.data?.count ?? 0) }, SiblingRules.maxBatchBytes)
        XCTAssertFalse(capped.isEmpty)
    }

    func testAvatarBatchesFitAPayloadAndPutMineFirst() {
        let pic = Data(repeating: 1, count: 30_000).base64EncodedString()
        let entries = (0..<10).map { SiblingRules.AvatarEntry(key: "user:\($0)", img: pic, ts: Int64($0)) }
        let batches = SiblingRules.batches(entries, first: "user:3")
        XCTAssertEqual(batches.first?.first?.key, "user:3")
        for b in batches {
            let size = b.reduce(0) { $0 + ($1.img?.utf8.count ?? 0) + $1.key.utf8.count + 32 }
            XCTAssertLessThanOrEqual(size, SiblingRules.sendBudget)
        }
        XCTAssertEqual(batches.flatMap { $0 }.count, 10)
    }

    // MARK: build 49 — the emoji picker

    func testEmojiSearchByNameAndRecents() {
        XCTAssertTrue(EmojiCatalog.search("thumbs up").contains("👍"))
        XCTAssertTrue(EmojiCatalog.search("SQUID").contains("🦑"))
        XCTAssertTrue(EmojiCatalog.search("").isEmpty)
        XCTAssertTrue(EmojiCatalog.search("zzzz-not-an-emoji").isEmpty)
        var r: [String] = []
        for e in ["😀", "👍", "😀"] { r = EmojiCatalog.used(e, recents: r) }
        XCTAssertEqual(r, ["😀", "👍"])
        for i in 0..<40 { r = EmojiCatalog.used(EmojiCatalog.all[i], recents: r) }
        XCTAssertEqual(r.count, EmojiCatalog.maxRecents)
        // Every catalog entry is one emoji (no stray text).
        XCTAssertTrue(EmojiCatalog.all.allSatisfy { $0.count == 1 })
    }

    // MARK: build 49 — mentions in attachment captions (the notification extension)

    func testAMentionInAnAttachmentCaptionIsFound() {
        let caption = "look @me"
        var payload = MentionPayload()
        payload.mentions = [.init(userId: "u-me", start: 5, length: 3)]
        let encodedCaption = MentionCodec.encode(caption, payload)
        let json = try! JSONSerialization.data(withJSONObject: ["blobId": "b", "caption": encodedCaption])
        let body = MessageMentions.attachTag + String(data: json, encoding: .utf8)!
        XCTAssertTrue(MessageMentions.payload(body).mentions.contains { $0.userId == "u-me" })
        XCTAssertTrue(MessageMentions.payload(MessageMentions.musicTag + "{}").isEmpty)
        let plain = MentionCodec.encode(caption, payload)
        XCTAssertTrue(MessageMentions.payload(plain).mentions.contains { $0.userId == "u-me" })
    }

    func testServerNameRuleRefusesInvisibleAndBlankLooking() {
        for bad in ["a\u{200B}b", "\u{2060}x", "x\u{FEFF}", "\u{00AD}soft", "tag\u{E0041}", "\u{3164}", "\u{2800}", "Crew \u{3164}name"] {
            XCTAssertNotNil(ServerNameRule.problem(bad), "\(bad.unicodeScalars.map { String($0.value, radix: 16) })")
        }
        XCTAssertNil(ServerNameRule.problem("Café 🎉"))
    }

    /// The contacts.v1 format is shared with Android: this fixture is what Android's
    /// `SiblingBook.encode` writes (Build49Test.siblingBookFormatMatchesApple decodes it too).
    func testSiblingBookFormatMatchesAndroid() throws {
        let fixture = #"{"u-a":{"name":"alice","level":"known","known":true},"u-b":{"name":"bob","level":"verified"}}"#
        let book = try JSONDecoder().decode([String: Contact].self, from: Data(fixture.utf8))
        XCTAssertEqual(book["u-a"], Contact(name: "alice", level: .known, known: true))
        XCTAssertEqual(book["u-b"], Contact(name: "bob", level: .verified))
        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(book)) as? [String: [String: Any]]
        XCTAssertEqual(encoded?["u-a"]?["level"] as? String, "known")
        XCTAssertEqual(encoded?["u-b"]?["level"] as? String, "verified")
    }

    func testServerNameRuleRefusesSeparatorsAndIgnorables() {
        for bad in ["\u{FE0F}", "a\u{FE0F}b", "\u{E0100}", "crew\u{2028}name", "x\u{2029}y", "\u{180B}x", "x\u{FE00}", "\u{FFF0}x"] {
            XCTAssertNotNil(ServerNameRule.problem(bad), "\(bad.unicodeScalars.map { String($0.value, radix: 16) })")
        }
        XCTAssertNil(ServerNameRule.problem("❤️ crew"))
        XCTAssertNil(ServerNameRule.problem("Weekend ✌️"))
    }

    func testAVerifiedOnlySyncedContactStaysUnverifiedAndUnverifyReturnsThere() {
        let synced = Contact(name: "vera", level: .verified, known: false)
        let merged = SiblingRules.mergedContact(userId: "u-v", local: nil, synced: synced, vouched: true, mismatched: false, book: [:])
        XCTAssertEqual(merged?.level, .unverified)
        XCTAssertEqual(merged?.known, false)
        let verified = ContactTrust.withVerification(merged, name: "vera", verified: true)
        XCTAssertEqual(ContactTrust.withVerification(verified, name: "vera", verified: false)?.level, .unverified)
        // Explicitly known on the sibling: KNOWN here.
        XCTAssertEqual(SiblingRules.mergedContact(userId: "u-k", local: nil, synced: Contact(name: "kim", level: .verified, known: true),
                                                  vouched: true, mismatched: false, book: [:])?.level, .known)
    }
}
