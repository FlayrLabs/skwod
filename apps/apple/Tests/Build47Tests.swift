import XCTest

/// Build 47: who is in a voice room (`VoiceRoster`), mention tokens from the username, and a
/// left server that stays gone (`LeaveTombstones`).
final class Build47Tests: XCTestCase {

    // MARK: voice rosters

    private func event(_ server: String, _ channel: String, _ people: [[String: Any]]) -> [String: Any] {
        ["server_id": server, "channel_id": channel, "participants": people]
    }

    func testAVoiceStateReplacesTheRoomsRoster() {
        var r = VoiceRoster()
        XCTAssertTrue(r.apply(topic: "server:s1", payload: event("s1", "v1", [
            ["user_id": "bob", "muted": true, "video": false, "screen": false, "joined_at": 20],
            ["user_id": "amy", "muted": false, "video": true, "screen": true, "joined_at": 10],
        ])))
        XCTAssertEqual(r.participants(serverId: "s1").map(\.userId), ["amy", "bob"], "join order")
        XCTAssertEqual(r.participants(serverId: "s1").first?.video, true)
        XCTAssertEqual(r.participants(serverId: "s1").last?.muted, true)
        XCTAssertEqual(r.count(serverId: "s1"), 2)
        // The same roster again is no change; a leave is.
        XCTAssertFalse(r.apply(topic: "server:s1", payload: event("s1", "v1", [
            ["user_id": "bob", "muted": true, "video": false, "screen": false, "joined_at": 20],
            ["user_id": "amy", "muted": false, "video": true, "screen": true, "joined_at": 10],
        ])))
        XCTAssertTrue(r.apply(topic: "server:s1", payload: event("s1", "v1", [["user_id": "amy", "joined_at": 10]])))
        XCTAssertEqual(r.participants(serverId: "s1").map(\.userId), ["amy"])
        // Everyone left: the room goes.
        XCTAssertTrue(r.apply(topic: "server:s1", payload: event("s1", "v1", [])))
        XCTAssertEqual(r.count(serverId: "s1"), 0)
        XCTAssertTrue(r.rooms.isEmpty)
    }

    func testAnEventIsTakenOnlyOnTheTopicOfTheServerItNames() {
        var r = VoiceRoster()
        XCTAssertFalse(r.apply(topic: "server:other", payload: event("s1", "v1", [["user_id": "amy"]])))
        XCTAssertFalse(r.apply(topic: "user:me", payload: event("s1", "v1", [["user_id": "amy"]])))
        XCTAssertFalse(r.apply(topic: "server:s1", payload: ["server_id": "s1", "participants": []]), "no channel")
        XCTAssertEqual(r.count(serverId: "s1"), 0)
    }

    func testBlockedPeopleDuplicatesAndJunkAreNotListed() {
        var r = VoiceRoster()
        r.apply(topic: "server:s1", payload: event("s1", "v1", [["user_id": "amy"], ["user_id": "amy"], ["user_id": ""], ["nope": 1], ["user_id": "eve"]]))
        XCTAssertEqual(r.participants(serverId: "s1").map(\.userId), ["amy", "eve"])
        XCTAssertEqual(r.participants(serverId: "s1", hidden: ["eve"]).map(\.userId), ["amy"])
        XCTAssertEqual(r.count(serverId: "s1", hidden: ["eve"]), 1)
        let many = (0..<200).map { ["user_id": "u\($0)"] as [String: Any] }
        r.apply(topic: "server:s1", payload: event("s1", "v2", many))
        XCTAssertLessThanOrEqual(r.rooms["s1"]?["v2"]?.count ?? 0, VoiceRoster.maxListed)
    }

    func testAHostCannotGrowTheRosterWithoutBound() {
        var r = VoiceRoster()
        XCTAssertFalse(r.apply(topic: "server:s1", payload: event("s1", String(repeating: "c", count: 129), [["user_id": "amy"]])))
        for i in 0..<(VoiceRoster.maxRooms + 10) {
            r.apply(topic: "server:s1", payload: event("s1", "v\(i)", [["user_id": "u\(i)"]]))
        }
        XCTAssertEqual(r.rooms["s1"]?.count, VoiceRoster.maxRooms)
        // A room already listed still updates, and one that empties makes space.
        XCTAssertTrue(r.apply(topic: "server:s1", payload: event("s1", "v0", [["user_id": "amy"]])))
        XCTAssertTrue(r.apply(topic: "server:s1", payload: event("s1", "v1", [])))
        XCTAssertTrue(r.apply(topic: "server:s1", payload: event("s1", "new", [["user_id": "bob"]])))
    }

    func testRoomsOfOneServerShowTogetherAndAReconnectStartsClean() {
        var r = VoiceRoster()
        r.apply(topic: "server:s1", payload: event("s1", "v1", [["user_id": "amy", "joined_at": 3]]))
        r.apply(topic: "server:s1", payload: event("s1", "v2", [["user_id": "bob", "joined_at": 1]]))
        r.apply(topic: "server:s2", payload: event("s2", "v3", [["user_id": "cat"]]))
        XCTAssertEqual(r.participants(serverId: "s1").map(\.userId), ["bob", "amy"])
        XCTAssertEqual(r.count(serverId: "s2"), 1)
        r.reset()
        XCTAssertEqual(r.count(serverId: "s1"), 0)
        XCTAssertEqual(VoiceRoster.countLabel(3), "3 in voice")
        XCTAssertNil(VoiceRoster.countLabel(0))
    }

    // MARK: mention tokens

    func testTheTokenIsTheUsernameAndTheLabelStillMatches() {
        let members: [MentionCandidate] = [
            (userId: "u-sam", name: "Sam Smith (unverified)", username: "sam_smith"),
            (userId: "u-rob", name: "Robin", username: "rob"),
        ]
        // Typing either the label or the username finds them.
        XCTAssertEqual(MentionAutocomplete.matches("sam", in: members).map(\.userId), ["u-sam"])
        XCTAssertEqual(MentionAutocomplete.matches("smith", in: members).map(\.userId), ["u-sam"])
        XCTAssertEqual(MentionAutocomplete.matches("rob", in: members).map(\.userId), ["u-rob"])
        var p = MentionPayload()
        let draft = MentionAutocomplete.insert(name: members[0].name, username: members[0].username, userId: members[0].userId, into: "hi @sa", at: 3, payload: &p)
        XCTAssertEqual(draft, "hi @sam_smith ", "the username, not the trust label")
        XCTAssertEqual(p.mentions, [.init(userId: "u-sam", start: 3, length: 10)])
        // Kept while it is still there (reconcile builds the same token), and sent as a mention.
        let names = Dictionary(uniqueKeysWithValues: members.map { ($0.userId, MentionAutocomplete.tokenSource(name: $0.name, username: $0.username)) })
        let kept = MentionAutocomplete.reconcile(p, draft: draft, names: names)
        XCTAssertEqual(kept.mentions.count, 1)
        let back = MentionCodec.decode(MentionCodec.encode(draft, kept))
        XCTAssertEqual(back.visible, "hi @sam_smith ")
        XCTAssertEqual(back.payload.mentions, [.init(userId: "u-sam", start: 3, length: 10)])
        // Without a username (an older listing) the label's token is used, as before.
        var q = MentionPayload()
        XCTAssertEqual(MentionAutocomplete.insert(name: "Sam Smith (unverified)", username: " ", userId: "u", into: "@s", at: 0, payload: &q),
                       "@Sam_Smith_unverified ")
    }

    // MARK: leaving a server

    private struct Row: Equatable { let server: String; let channel: String }

    func testLeaveHidesAtOnceAndNothingInFlightBringsItBack() {
        var t = LeaveTombstones()
        XCTAssertTrue(t.begin("s1"))
        XCTAssertFalse(t.begin("s1"), "a second tap does nothing")
        XCTAssertTrue(t.hides("s1"), "hidden while the host has not answered")
        XCTAssertFalse(t.hides("s2"))
        t.confirm("s1")
        XCTAssertTrue(t.hides("s1"), "and after it confirmed")
        XCTAssertFalse(t.failed("s1"), "a confirmed leave is not rolled back")
        XCTAssertTrue(t.hides("s1"))
        t.rejoined("s1")
        XCTAssertFalse(t.hides("s1"), "only joining again on purpose lifts it")
    }

    func testARefusedLeaveBringsTheChannelsBackWhereTheyWere() {
        var t = LeaveTombstones()
        let before = [Row(server: "a", channel: "a1"), Row(server: "s1", channel: "x1"), Row(server: "s1", channel: "x2"), Row(server: "b", channel: "b1")]
        t.begin("s1")
        var now = before.filter { $0.server != "s1" } + [Row(server: "c", channel: "c1")]   // c joined meanwhile
        XCTAssertTrue(t.failed("s1"))
        XCTAssertFalse(t.hides("s1"))
        now = LeaveTombstones.restore(before: before, now: now, serverId: "s1", server: \.server, key: \.channel)
        XCTAssertEqual(now.map(\.channel), ["a1", "x1", "x2", "b1", "c1"])
        // A server dropped for another reason while the leave was out stays out.
        var u = LeaveTombstones()
        u.begin("s2")
        u.dropped(["s2"])
        XCTAssertFalse(u.failed("s2"))
        XCTAssertTrue(u.hides("s2"))
    }
}
