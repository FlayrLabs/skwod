import XCTest

/// Build 51: who shows as online. The same table runs on Android (PresenceRulesTest.kt).
final class PresenceRulesTests: XCTestCase {
    private enum Step { case event(String, TimeInterval), poll(String, asked: TimeInterval), pollWithout(asked: TimeInterval) }

    private func dot(_ steps: [Step], now: TimeInterval) -> String {
        var b = PresenceBook()
        for s in steps {
            switch s {
            case .event(let status, let at): b.event("kim", status, at: at)
            case .poll(let status, let asked): b.polled(["kim": status, "other": "online"], askedAt: asked)
            case .pollWithout(let asked): b.polled(["other": "online"], askedAt: asked)
            }
        }
        return b.view("kim", now: now).dot
    }

    func testTheTable() {
        let table: [(String, [Step], TimeInterval, String)] = [
            ("before the first answer nobody is called offline", [], 100, "unknown"),
            ("a list", [.poll("online", asked: 100)], 110, "online"),
            ("do not disturb is not offline", [.poll("dnd", asked: 100)], 110, "dnd"),
            ("a newer list beats an older event", [.event("offline", 100), .poll("online", asked: 103)], 110, "online"),
            ("a late list does not beat a newer event", [.event("online", 105), .poll("offline", asked: 100)], 110, "online"),
            ("…however long it took", [.event("online", 100.1), .poll("offline", asked: 100)], 140, "online"),
            ("two lists out of order", [.poll("online", asked: 120), .poll("offline", asked: 100)], 130, "online"),
            ("two devices: one goes away, the other says so again", [.event("online", 100), .event("offline", 130), .event("online", 131)], 132, "online"),
            ("a lost connection here is unknown, not offline", [.poll("online", asked: 100)], 195, "unknown"),
            ("…and stays unknown", [.poll("online", asked: 100)], 5000, "unknown"),
            ("an event for someone else after a long gap says nothing of them", [.poll("online", asked: 100), .event("idle", 101)], 5000, "unknown"),
            ("reconnected and listed", [.poll("online", asked: 100), .poll("offline", asked: 5000)], 5001, "offline"),
            ("no longer listed for 3 minutes", [.poll("online", asked: 100), .pollWithout(asked: 300)], 301, "offline"),
            ("a status nobody has is ignored", [.poll("online", asked: 100), .event("gone", 105)], 110, "online"),
        ]
        for (what, steps, now, want) in table { XCTAssertEqual(dot(steps, now: now), want, what) }
    }

    func testAfterComingBackAnEventAboutOneDoesNotMakeTheRestOffline() {
        var b = PresenceBook()
        b.polled(["kim": "online", "lee": "online"], askedAt: 100)
        b.event("lee", "online", at: 5000)
        XCTAssertEqual(b.view("lee", now: 5001).dot, "online")
        XCTAssertEqual(b.view("kim", now: 5001), .init(status: "online", current: false), "listed where last seen, dot unknown")
    }

    func testOnlyADeviceInUseSpeaksForTheAccount() {
        XCTAssertEqual(PresenceAnnounce.status(active: true, chosen: "dnd"), "dnd")
        XCTAssertNil(PresenceAnnounce.status(active: false, chosen: "online"), "in the background it says nothing")
        XCTAssertEqual(PresenceAnnounce.status(active: true, chosen: "offline"), "offline", "invisible is said once")
        XCTAssertNil(PresenceAnnounce.periodic(active: true, chosen: "offline"))
        XCTAssertNil(PresenceAnnounce.periodic(active: false, chosen: "online"))
    }

    func testAnActiveDeviceCorrectsAnOlderOneThatTookTheAccountOffline() {
        func corrects(_ user: String = "me", _ status: String = "offline", announced: String? = "online", last: TimeInterval? = nil, now: TimeInterval = 100) -> Bool {
            PresenceAnnounce.corrects(eventUser: user, status: status, me: "me", announced: announced, lastSentAt: last, now: now)
        }
        XCTAssertTrue(corrects())
        XCTAssertTrue(corrects(announced: "dnd", last: 85))
        XCTAssertFalse(corrects(last: 86), "at most every 15 s")
        XCTAssertFalse(corrects("kim"), "someone else")
        XCTAssertFalse(corrects(announced: nil), "this device is away too")
        XCTAssertFalse(corrects(announced: "offline"), "invisible here")
        XCTAssertFalse(corrects("me", "idle"), "another device's choice stands")
    }

    /// Red is Do Not Disturb, and nothing else.
    func testRedIsOnlyDoNotDisturb() throws {
        let file = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources/MainView.swift")
        let source = try String(contentsOf: file, encoding: .utf8)
        let start = source.range(of: "enum PresenceStyle {")!.lowerBound
        let body = source[start...].prefix(700).components(separatedBy: "\n").filter { $0.contains("return .red") }
        XCTAssertEqual(body.count, 1)
        XCTAssertTrue(body.first?.contains("case \"dnd\"") == true)
    }

    /// The owner's report: with this device's own connection down, "1 online" stayed. Not connected,
    /// nobody is presented as online — no count, no online group, no green dot.
    func testNothingIsPresentedAsOnlineWhileThisDeviceIsNotConnected() {
        let status = ["me": "online", "a": "online", "b": "offline", "c": "dnd"]
        let ids = ["me", "a", "b", "c"]
        XCTAssertEqual(PresenceRoster.onlineCount(ids, me: "me", live: true) { status[$0]! }, 3)
        XCTAssertNil(PresenceRoster.onlineCount(ids, me: "me", live: false) { status[$0]! })
        let live = PresenceRoster.groups(ids, live: true) { status[$0]! }
        XCTAssertEqual(live.online, ["me", "a", "c"]); XCTAssertEqual(live.offline, ["b"]); XCTAssertTrue(live.unknown.isEmpty)
        let down = PresenceRoster.groups(ids, live: false) { status[$0]! }
        XCTAssertTrue(down.online.isEmpty); XCTAssertTrue(down.offline.isEmpty); XCTAssertEqual(down.unknown, ids)
        XCTAssertEqual(PresenceRoster.dot("online", live: true), "online")
        for dot in ["online", "idle", "dnd", "offline"] { XCTAssertEqual(PresenceRoster.dot(dot, live: false), "unknown") }
        XCTAssertFalse(PresenceRoster.unknownTitle(4).lowercased().contains("online"))
    }
}
