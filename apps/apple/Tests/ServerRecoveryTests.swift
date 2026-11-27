import XCTest

/// Build 51: a newly linked device's servers appear by themselves, and an empty list says why.
/// The same table runs on Android (ServerRecoveryTest.kt).
final class ServerRecoveryTests: XCTestCase {
    private func after(_ steps: (inout ServerRecovery) -> Void) -> ServerRecovery {
        var r = ServerRecovery()
        steps(&r)
        return r
    }
    private func state(_ r: ServerRecovery, setUp: Bool = true, shown: Set<String> = [], hidden: Set<String> = []) -> ServerRecovery.State {
        r.state(setUp: setUp, shown: shown, hidden: hidden)
    }

    func testWhatAnEmptyListSays() {
        XCTAssertEqual(state(ServerRecovery()), .loading)
        XCTAssertEqual(state(ServerRecovery(), setUp: false), .notSetUp)
        // Refused or unreachable once (a session not bound yet): still loading. Again: say so.
        XCTAssertEqual(state(after { $0.answered(nil) }), .loading)
        XCTAssertEqual(state(after { $0.answered(nil); $0.answered(nil) }), .failed)
        // Only a successful, complete, empty answer says "none" — and not once a later one failed.
        XCTAssertEqual(state(after { $0.answered([]) }), .none)
        XCTAssertEqual(state(after { $0.answered([]); $0.answered(nil) }), .loading)
        XCTAssertEqual(state(after { $0.answered([]); $0.answered(nil); $0.answered(nil) }), .failed)
        XCTAssertEqual(state(after { $0.answered(nil); $0.answered(nil); $0.answered([]) }), .none)
        // A member without keys waits for them, however the next request ends.
        XCTAssertEqual(state(after { $0.answered(["s"]) }), .waitingForKeys)
        XCTAssertEqual(state(after { $0.answered(["s"]); $0.answered(nil); $0.answered(nil) }), .waitingForKeys)
        XCTAssertEqual(state(after { $0.answered(["s"]); $0.found("s", keyed: true) }), .noChannels)
        XCTAssertEqual(state(after { $0.answered(["s", "t"]); $0.found("s", keyed: true) }), .waitingForKeys)
        // Left here: not waited for.
        XCTAssertEqual(state(after { $0.answered(["s"]) }, hidden: ["s"]), .none)
    }

    func testItNeverGivesUpWhileSomethingIsMissing() {
        var r = after { $0.answered(["s"]) }
        var waited: TimeInterval = 0
        // The base looked 40 times, 3 s apart, and never again: here the keys come after an hour.
        for _ in 0..<200 {
            XCTAssertFalse(r.settled(shown: [], hidden: []))
            r.passed()
            let d = r.delay(active: true)
            XCTAssertTrue(d >= ServerRecovery.spacing && d <= 60, "bounded: \(d)")
            waited += d
        }
        XCTAssertTrue(waited > 3600)
        XCTAssertTrue(r.settled(shown: ["s"], hidden: []), "and it ends when they are shown")
    }

    func testItBacksOffAndComesBackAtOnce() {
        var r = after { $0.answered(["s"]) }
        var delays: [TimeInterval] = []
        for _ in 0..<7 { r.passed(); delays.append(r.delay(active: true)) }
        XCTAssertEqual(delays, [2, 4, 8, 15, 30, 60, 60])
        XCTAssertEqual(after { $0.passed() }.delay(active: false), 60, "not in front: slowly")
        r.nudged()
        XCTAssertEqual(r.delay(active: true), ServerRecovery.spacing)
    }

    func testARefusedRequestIsNotTheEnd() {
        // The first request went out before this device's session was bound: 403. The base
        // returned there, and nothing asked again until the next launch.
        var r = after { $0.answered(nil) }
        XCTAssertFalse(r.settled(shown: [], hidden: []))
        r.answered(["s"])
        XCTAssertEqual(r.missing(shown: [], hidden: []), ["s"])
        XCTAssertFalse(r.settled(shown: [], hidden: []))
        XCTAssertTrue(r.settled(shown: ["s"], hidden: []))
        // A server joined on another device while this one already shows some.
        r.answered(["s", "t"])
        XCTAssertEqual(r.missing(shown: ["s"], hidden: []), ["t"])
    }

    func testMembersAreAskedForKeysLessAndLessOften() {
        var r = ServerRecovery()
        XCTAssertTrue(r.mayAsk("s", now: 0))
        r.didAsk("s", now: 0)
        XCTAssertFalse(r.mayAsk("s", now: 9))
        XCTAssertTrue(r.mayAsk("s", now: 10))
        XCTAssertTrue(r.mayAsk("t", now: 1), "each server on its own")
        for i in 0..<20 { r.didAsk("s", now: Double(i)) }
        XCTAssertFalse(r.mayAsk("s", now: 19 + 299))
        XCTAssertTrue(r.mayAsk("s", now: 19 + 300))
        r.nudged()
        XCTAssertFalse(r.mayAsk("s", now: 20), "looking again is not asking again")
    }

    /// The link sheet closes itself when the link completes, which cancels the task it ran in.
    /// The base did the rest of the link in that very task: its request was cancelled.
    @MainActor
    func testWorkOutlivesTheSheetThatStartedIt() async {
        var inTheSheet: Bool?, outliving: Bool?
        let sheet = Task { @MainActor in
            while !Task.isCancelled { await Task.yield() }
            inTheSheet = Task.isCancelled
            await OutlivingWork.run { outliving = Task.isCancelled }
        }
        sheet.cancel()
        await sheet.value
        XCTAssertEqual(inTheSheet, true)
        XCTAssertEqual(outliving, false)
    }
}
