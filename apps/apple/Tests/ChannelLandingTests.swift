import XCTest

/// Build 51 (`Landing`). The Kotlin twin runs the same cases (`ChannelLandingTest.kt`).
final class ChannelLandingTests: XCTestCase {
    private let list = [LandingChannel(id: "a", serverId: "s1"), LandingChannel(id: "b", serverId: "s1"),
                        LandingChannel(id: "x", serverId: "s2"), LandingChannel(id: "y", serverId: "s2")]
    private func place(_ l: Landing, open: Bool = false, ready: Bool = true, settingUp: Bool = false,
                       _ memory: ChannelMemory = ChannelMemory(), _ channels: [LandingChannel]? = nil) -> Landing.Place {
        l.place(open: open, ready: ready, settingUp: settingUp, memory: memory, channels: channels ?? list)
    }
    private func asked(_ server: String?) -> Landing { var l = Landing(); l.asked(.init(server: server)); return l }

    func testATapLandsOnTheLastOrTheFirst() {
        XCTAssertEqual(place(asked("s2")), .channel("x"))
        XCTAssertEqual(place(asked("s1"), ChannelMemory(server: "s2", channels: ["s1": "b"])), .channel("b"))
        XCTAssertEqual(place(asked("s1"), ChannelMemory(channels: ["s1": "gone"])), .channel("a"))
        XCTAssertEqual(place(asked("s1"), ChannelMemory(channels: ["s1": "y"])), .channel("a"), "another server's id")
        var some = list
        some[1].readable = false
        XCTAssertEqual(place(asked("s1"), ChannelMemory(channels: ["s1": "b"]), some), .channel("a"))
        some[0].readable = false
        XCTAssertEqual(place(asked("s1"), ChannelMemory(), some), .empty(server: "s1"), "never another server's")
    }

    func testAFastSecondTapWins() {
        var l = asked("s1")
        XCTAssertEqual(place(l, ready: false), .loading, "lists not read, or another skwod's")
        l.asked(.init(server: "s2"))
        XCTAssertEqual(place(l), .channel("x"))
        l.opened()   // a channel tapped while it was loading
        XCTAssertEqual(l.want, nil)
        XCTAssertTrue(l.byUser)
        XCTAssertEqual(place(l, open: true), .open)
    }

    func testLaunch() {
        XCTAssertEqual(place(asked(nil), ChannelMemory(server: "s2", channels: ["s2": "y"])), .channel("y"))
        XCTAssertEqual(place(asked(nil), ChannelMemory(server: "s9")), .channel("a"))
        XCTAssertEqual(place(asked(nil), ready: false), .loading)
        XCTAssertEqual(place(asked(nil), ChannelMemory(), []), .noServers)
        XCTAssertEqual(place(asked(nil), settingUp: true, ChannelMemory(), []), .loading)
        var l = asked(nil)
        l.landed()
        XCTAssertFalse(l.byUser)
    }

    func testNothingTheHostSendsOpensOrReplacesAnything() {
        let lists = [[], Array(list.dropFirst()), list + [LandingChannel(id: "z", serverId: "s3")],
                     list.map { LandingChannel(id: $0.id, serverId: $0.serverId, readable: false) }]
        for user in [true, false] {
            var l = asked("s1")
            if user { l.opened() } else { l.landed() }
            let before = l
            l.joined("s3", startedHere: false, open: true)   // decided later, resumed, member added
            l.joined("s3", startedHere: true, open: true)    // started here, but something is open
            XCTAssertEqual(l, before)
            for channels in lists {   // hidden, deleted, added, refused
                XCTAssertEqual(place(l, open: true, ChannelMemory(), channels), .open)
                XCTAssertEqual(place(l, open: false, ChannelMemory(server: "s1"), channels), .closed, "gone: nothing in its place")
            }
        }
        var waiting = asked(nil)
        waiting.joined("s1", startedHere: false, open: false)
        XCTAssertEqual(place(waiting), .closed, "only listed")
    }

    func testAJoinStartedHereWithNothingOpen() {
        var l = Landing()
        l.joined("s2", startedHere: true, open: false)
        XCTAssertEqual(place(l), .channel("x"))
    }

    func testADraftGoesWhereItWasWrittenOrNowhere() {
        let here = Landing.conversationKey(workspaceId: "w1", serverId: "s1", channelId: "a")
        XCTAssertTrue(Landing.maySend(composedIn: here, now: here))
        for (w, s, c) in [("w1", "s1", "b"), ("w1", "s2", "a"), ("w2", "s1", "a")] {
            XCTAssertFalse(Landing.maySend(composedIn: here, now: Landing.conversationKey(workspaceId: w, serverId: s, channelId: c)))
        }
        XCTAssertFalse(Landing.maySend(composedIn: nil, now: here))
    }

    func testMemoryRefusalsAndWhoMayCreate() throws {
        var m = ChannelMemory()
        m.opened("a", in: "s1"); m.opened("x", in: "s2")
        XCTAssertEqual(try JSONDecoder().decode(ChannelMemory.self, from: JSONEncoder().encode(m)), m)
        m.forget("s2")
        XCTAssertEqual(m, ChannelMemory(channels: ["s1": "a"]))
        XCTAssertTrue(Landing.isReadRefusal("http status 403: {\"error\":\"forbidden\"}"))
        XCTAssertFalse(Landing.isReadRefusal("http status 403: {\"error\":\"device removed\"}"))
        XCTAssertTrue(Landing.mayCreateChannels(isOwner: false, permissions: 1))
        XCTAssertFalse(Landing.mayCreateChannels(isOwner: false, permissions: 2 | 4 | 64))
    }
}
