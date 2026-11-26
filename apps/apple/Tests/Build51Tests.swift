import XCTest

/// Build 51: messages that are always current.
final class Build51Tests: XCTestCase {
    // MARK: A dead p2p session is replaced (SessionHealthRule)

    func testAnAnsweringSessionIsHealthyAndForgetsEarlierFailures() {
        let step = SessionHealthRule.next(failures: 1, proxyOK: true, upstreamOK: true, urgent: false)
        XCTAssertEqual(step.failures, 0)
        XCTAssertEqual(step.outcome, .healthy)
    }

    func testOneSlowAnswerOnTheTimerIsNotADeadSession() {
        let first = SessionHealthRule.next(failures: 0, proxyOK: true, upstreamOK: false, urgent: false)
        XCTAssertEqual(first.outcome, .degraded, "shown as Reconnecting…, not torn down")
        XCTAssertEqual(first.failures, 1)
        let second = SessionHealthRule.next(failures: first.failures, proxyOK: true, upstreamOK: false, urgent: false)
        XCTAssertEqual(second.outcome, .replace, "two in a row: dial a fresh session")
        XCTAssertEqual(second.failures, 0, "the fresh session starts with a clean slate")
    }

    func testComingBackToTheAppReplacesASilentSessionAtOnce() {
        // Foreground, wake, network change, Retry: the moments the OS may have taken the
        // session's sockets, and the user is looking.
        XCTAssertEqual(SessionHealthRule.next(failures: 0, proxyOK: true, upstreamOK: false, urgent: true).outcome, .replace)
    }

    func testADeadOrForeignProxyIsReplacedAtOnceWhateverElse() {
        for failures in [0, 1] {
            for urgent in [false, true] {
                let step = SessionHealthRule.next(failures: failures, proxyOK: false, upstreamOK: true, urgent: urgent)
                XCTAssertEqual(step.outcome, .replace, "no second strike for a proxy that is not ours or not alive")
            }
        }
    }

    func testAFreshAnswerIsNotAskedAgainOnEveryWindowFocus() {
        let now = Date()
        XCTAssertFalse(SessionHealthRule.shouldProbe(lastOK: now.addingTimeInterval(-1), now: now, userAsked: false))
        XCTAssertTrue(SessionHealthRule.shouldProbe(lastOK: now.addingTimeInterval(-10), now: now, userAsked: false))
        XCTAssertTrue(SessionHealthRule.shouldProbe(lastOK: nil, now: now, userAsked: false))
        XCTAssertTrue(SessionHealthRule.shouldProbe(lastOK: now, now: now, userAsked: true), "Retry always asks")
    }

    func testTheProbeIsBoundedAndTheTimerIsCheap() {
        XCTAssertLessThanOrEqual(SessionHealthRule.probeTimeout, 10)
        XCTAssertGreaterThanOrEqual(SessionHealthRule.foregroundInterval, 15, "no hammering the host")
        XCTAssertLessThanOrEqual(SessionHealthRule.foregroundInterval, 30, "the pill can't stay stale for long")
    }
}


/// Build 51: catch-up, retries, and where the list scrolls.
final class Build51SyncTests: XCTestCase {
    func testCatchUpRequestsThatArriveTogetherMakeOneRunAndOneMore() {
        var gate = CatchUpGate()
        let t0 = Date()
        XCTAssertEqual(gate.request(now: t0), .start)
        gate.started(now: t0)
        // Foreground, network re-probe and socket-up all ask while it runs: one more run, not three.
        XCTAssertEqual(gate.request(now: t0), .queued)
        XCTAssertEqual(gate.request(now: t0), .queued)
        XCTAssertTrue(gate.finished(), "runs once more")
        gate.started(now: t0.addingTimeInterval(1))
        XCTAssertFalse(gate.finished(), "and then stops")
    }

    func testEveryChannelIsSweptAfterAGapNotOnEveryWindowFocus() {
        let t0 = Date()
        XCTAssertTrue(CatchUpGate.sweepDue(lastSweep: nil, now: t0, socketCameUpSince: false), "first time")
        XCTAssertTrue(CatchUpGate.sweepDue(lastSweep: t0, now: t0.addingTimeInterval(1), socketCameUpSince: true),
                      "the socket was down: events may have been missed")
        XCTAssertFalse(CatchUpGate.sweepDue(lastSweep: t0, now: t0.addingTimeInterval(5), socketCameUpSince: false),
                       "a window focus with the socket live all along")
        XCTAssertTrue(CatchUpGate.sweepDue(lastSweep: t0, now: t0.addingTimeInterval(CatchUpGate.sweepFloor), socketCameUpSince: false))
    }

    func testCatchUpRunsAreSpacedOut() {
        var gate = CatchUpGate()
        let t0 = Date()
        _ = gate.request(now: t0); gate.started(now: t0); _ = gate.finished()
        XCTAssertEqual(gate.request(now: t0.addingTimeInterval(0.5)), .startAfter(CatchUpGate.minGap - 0.5))
        gate.started(now: t0.addingTimeInterval(CatchUpGate.minGap)); _ = gate.finished()
        XCTAssertEqual(gate.request(now: t0.addingTimeInterval(10)), .start)
    }

    func testAFailedFetchIsRetriedWithBoundedBackoffThenOffersRetry() {
        XCTAssertEqual(FetchRetryRule.delay(afterFailure: 1), 2)
        XCTAssertEqual(FetchRetryRule.delay(afterFailure: 2), 4)
        XCTAssertEqual(FetchRetryRule.delay(afterFailure: 4), 16)
        XCTAssertEqual(FetchRetryRule.delay(afterFailure: 5), 30, "capped")
        XCTAssertNil(FetchRetryRule.delay(afterFailure: FetchRetryRule.maxAttempts + 1), "no hammering: it stops")
        XCTAssertEqual(FetchRetryRule.status(failures: 0), .ok)
        XCTAssertEqual(FetchRetryRule.status(failures: 1), .retrying, "never a silent empty list")
        XCTAssertEqual(FetchRetryRule.status(failures: FetchRetryRule.maxAttempts + 1), .failed)
        XCTAssertEqual(FetchRetryRule.status(failures: 1, stripShowing: true), .ok, "the strip already says it")
        XCTAssertEqual(FetchRetryRule.status(failures: 1, stripShowing: false), .retrying, "back once the strip is gone")
    }

    func testANewMessageFollowsOnlyAReaderAtTheBottom() {
        XCTAssertEqual(ChatScrollRule.onArrival(atBottom: true, newestIsMine: false, justSent: false, newFromOthers: 1), .follow)
        XCTAssertEqual(ChatScrollRule.onArrival(atBottom: false, newestIsMine: false, justSent: false, newFromOthers: 2), .pill,
                       "reading history: not yanked down, the pill says what came in")
        XCTAssertEqual(ChatScrollRule.onArrival(atBottom: false, newestIsMine: true, justSent: false, newFromOthers: 0), .follow)
        XCTAssertEqual(ChatScrollRule.onArrival(atBottom: false, newestIsMine: false, justSent: true, newFromOthers: 0), .follow,
                       "sending always goes to the bottom")
        XCTAssertEqual(ChatScrollRule.onArrival(atBottom: false, newestIsMine: false, justSent: false, newFromOthers: 0), .nothing)
        XCTAssertTrue(ChatScrollRule.opensAtNewest)
    }

    func testAConversationReloadsForEveryNewClient() {
        XCTAssertNotEqual(ConversationLoadKey(id: "c", clientTurn: nil), ConversationLoadKey(id: "c", clientTurn: 3),
                          "opened before the client was up: loads once it is")
        XCTAssertNotEqual(ConversationLoadKey(id: "c", clientTurn: 3), ConversationLoadKey(id: "c", clientTurn: 4),
                          "re-bound (extension wrote the cache, session replaced): loads again")
        XCTAssertEqual(ConversationLoadKey(id: "c", clientTurn: 4), ConversationLoadKey(id: "c", clientTurn: 4))
    }
}

final class Build51ScrollTests: XCTestCase {
    func testOnlyTheReaderLeavesTheBottom() {
        XCTAssertTrue(ChatScrollRule.stillAtBottom(was: true, offsetMoved: false, nowAtEnd: false),
                      "rows arrived / the window changed: still at the bottom, so the arrival follows")
        XCTAssertFalse(ChatScrollRule.stillAtBottom(was: true, offsetMoved: true, nowAtEnd: false), "scrolled up")
        XCTAssertTrue(ChatScrollRule.stillAtBottom(was: false, offsetMoved: true, nowAtEnd: true), "scrolled back down")
        XCTAssertFalse(ChatScrollRule.stillAtBottom(was: false, offsetMoved: false, nowAtEnd: false), "reading history stays put")
    }
}

/// Build 51: stale dials and urgency.
final class Build51FrontTests: XCTestCase {
    func testAStaleDialIsDiscarded() {
        XCTAssertTrue(DialRule.usable(dialGeneration: 3, currentGeneration: 3, dialFallback: true, currentFallback: true))
        XCTAssertFalse(DialRule.usable(dialGeneration: 3, currentGeneration: 4, dialFallback: true, currentFallback: true), "relay setting changed meanwhile")
        XCTAssertFalse(DialRule.usable(dialGeneration: 3, currentGeneration: 3, dialFallback: true, currentFallback: false), "relays now off")
    }

    func testAWindowFocusIsNotUrgentARealEventIs() {
        XCTAssertFalse(UrgencyRule.isUrgent(.windowFocus), "macOS focus must not replace connections")
        XCTAssertFalse(UrgencyRule.isUrgent(.timer))
        for t in [UrgencyRule.Trigger.foreground, .wake, .networkChange, .userRetry] { XCTAssertTrue(UrgencyRule.isUrgent(t)) }
    }

    func testASessionIsEndedByWhatItIsBoundThrough() {
        XCTAssertEqual(SignOutRoute.of(boundBase: "https://chat.example.org", boundIsFront: false, isP2P: true), .server,
                       "a p2p skwod on its https fallback: told there")
        XCTAssertEqual(SignOutRoute.of(boundBase: "http://127.0.0.1:5001/aa", boundIsFront: true, isP2P: true), .front)
        XCTAssertEqual(SignOutRoute.of(boundBase: nil, boundIsFront: false, isP2P: true), .front, "not bound now: its front, if any")
        XCTAssertEqual(SignOutRoute.of(boundBase: "", boundIsFront: false, isP2P: false), .none)
    }

    func testOnlyRequestsToThatFrontAreCancelledWhenItMoves() {
        let base = "http://127.0.0.1:5001/aaaa"
        XCTAssertTrue(URLScope.isUnder("http://127.0.0.1:5001/aaaa/api/blobs/x", base: base))
        XCTAssertFalse(URLScope.isUnder("http://127.0.0.1:5001/aaaab/api", base: base), "another secret")
        XCTAssertFalse(URLScope.isUnder("http://127.0.0.1:5002/aaaa/api", base: base), "the new front")
        XCTAssertFalse(URLScope.isUnder(nil, base: base))
    }

    func testTheTokenNeverGoesToAFrontAndAFrontWithoutACredentialGetsNothing() {
        XCTAssertEqual(WireRule.of(baseIsFront: true, credential: "front-abc", token: "real"), "front-abc")
        XCTAssertNil(WireRule.of(baseIsFront: true, credential: nil, token: "real"))
        XCTAssertNil(WireRule.of(baseIsFront: true, credential: "", token: "real"))
        XCTAssertEqual(WireRule.of(baseIsFront: false, credential: "front-abc", token: "real"), "real")
        XCTAssertNil(WireRule.of(baseIsFront: false, credential: nil, token: ""))
    }

    func testASignOutDuringAnAwaitStopsTheBind() {
        XCTAssertTrue(LiveRecordRule.stillValid(liveId: "w", liveSignedOut: false, liveToken: "t", startId: "w", startToken: "t"))
        XCTAssertFalse(LiveRecordRule.stillValid(liveId: "w", liveSignedOut: true, liveToken: "t", startId: "w", startToken: "t"), "signed out meanwhile")
        XCTAssertFalse(LiveRecordRule.stillValid(liveId: "w", liveSignedOut: false, liveToken: "t2", startId: "w", startToken: "t"), "a new token meanwhile")
        XCTAssertFalse(LiveRecordRule.stillValid(liveId: nil, liveSignedOut: false, liveToken: nil, startId: "w", startToken: "t"), "removed")
    }

    /// Cold launch: the list opens on the cache (all read), THEN the catch-up brings three rows
    /// written while the app was closed. They are what was unread at open — not read on arrival.
    func testACatchUpAfterOpeningFillsTheNewSinceBar() {
        let m = ReadMarker(messageId: "r", createdAt: 100)
        var items = [UnreadItem(id: "r", createdAt: 100, mine: false)]
        XCTAssertNil(UnreadRule.atOpen(items, markerAtOpen: m, openedAt: 1_000), "the cache alone: nothing new")
        items += [UnreadItem(id: "c1", createdAt: 200, mine: false), UnreadItem(id: "c2", createdAt: 300, mine: false),
                  UnreadItem(id: "c3", createdAt: 400, mine: false)]
        let open = UnreadRule.atOpen(items, markerAtOpen: m, openedAt: 1_000)
        XCTAssertEqual(open?.first, 1); XCTAssertEqual(open?.count, 3)
        // A live message written after the open is not "since you last looked" (the pill's).
        items.append(UnreadItem(id: "live", createdAt: 2_000, mine: false))
        XCTAssertEqual(UnreadRule.atOpen(items, markerAtOpen: m, openedAt: 1_000)?.count, 3)
        // Never opened here (no marker): nothing is unread.
        XCTAssertNil(UnreadRule.atOpen(items, markerAtOpen: nil, openedAt: 1_000))
    }

    func testAProofThatFailedIsNeverAHealthyFront() {
        XCTAssertEqual(FrontProof.of(relistened: false, failed: false, stillSuspect: false), .proved)
        XCTAssertEqual(FrontProof.of(relistened: true, failed: false, stillSuspect: false), .moved)
        XCTAssertEqual(FrontProof.of(relistened: false, failed: true, stillSuspect: true), .unproved, "a re-key delayed by a call")
        XCTAssertEqual(FrontProof.of(relistened: false, failed: false, stillSuspect: true), .unproved, "suspected meanwhile")
        XCTAssertEqual(FrontProof.of(relistened: true, failed: true, stillSuspect: true), .unproved)
        for maySend in [true, false] {
            XCTAssertFalse(FrontProof.isHealthy(.unproved, maySend: maySend))
            XCTAssertFalse(FrontProof.isHealthy(.moved, maySend: maySend))
        }
        XCTAssertTrue(FrontProof.isHealthy(.proved, maySend: true))
        XCTAssertFalse(FrontProof.isHealthy(.proved, maySend: false))
    }

    func testOnlyTheFrontOfAConnectedCallWithLiveAudioIsExemptOnForeground() {
        XCTAssertEqual(ForegroundRule.exempt(callWorkspace: "w", connected: true, audioLive: true), "w")
        XCTAssertNil(ForegroundRule.exempt(callWorkspace: "w", connected: false, audioLive: true), "ringing or connecting")
        XCTAssertNil(ForegroundRule.exempt(callWorkspace: "w", connected: true, audioLive: false), "suspended with its call")
        XCTAssertNil(ForegroundRule.exempt(callWorkspace: nil, connected: true, audioLive: true))
    }

    @MainActor
    func testARelayChangeThatWasSupersededLeavesTheRestToTheLaterOne() async {
        var log: [String] = []
        var newest = true
        let ok = await RelayOptOut.apply(relaysOn: false, current: { newest }, turnOn: { log.append("on") },
                                         turnOff: { log.append("off"); newest = false },
                                         redial: { log.append("dial") }, disconnectAll: { log.append("disconnect") })
        XCTAssertTrue(ok); XCTAssertEqual(log, ["off"], "changed while it ran: nothing dialed under it")
        log = []
        _ = await RelayOptOut.apply(relaysOn: true, current: { false }, turnOn: { log.append("on") }, turnOff: {},
                                    redial: { log.append("dial") }, disconnectAll: {})
        XCTAssertEqual(log, [], "superseded before its turn: never turned on")
    }

    @MainActor
    func testARelayOptOutThatFailsDisconnectsEverythingAndDialsNothing() async {
        struct Failed: Error {}
        var log: [String] = []
        var ok = await RelayOptOut.apply(relaysOn: false, turnOn: { log.append("on") }, turnOff: { log.append("off"); throw Failed() },
                                         redial: { log.append("dial") }, disconnectAll: { log.append("disconnect") })
        XCTAssertFalse(ok); XCTAssertEqual(log, ["off", "disconnect"])
        log = []
        ok = await RelayOptOut.apply(relaysOn: false, turnOn: { log.append("on") }, turnOff: { log.append("off") },
                                     redial: { log.append("dial") }, disconnectAll: { log.append("disconnect") })
        XCTAssertTrue(ok); XCTAssertEqual(log, ["off", "dial"], "closed before anything is dialed")
        log = []
        ok = await RelayOptOut.apply(relaysOn: true, turnOn: { log.append("on") }, turnOff: { log.append("off") },
                                     redial: { log.append("dial") }, disconnectAll: { log.append("disconnect") })
        XCTAssertTrue(ok); XCTAssertEqual(log, ["on", "dial"], "allowed before anything is dialed")
    }

    func testARequestIsCheckedAgainstTheFrontItGoesTo() {
        XCTAssertEqual(FrontURL.base(of: "http://127.0.0.1:5001/abcd/api/push/register"), "http://127.0.0.1:5001/abcd")
        XCTAssertEqual(FrontURL.base(of: "http://127.0.0.1:5001/abcd?x=1"), "http://127.0.0.1:5001/abcd")
        XCTAssertNil(FrontURL.base(of: "https://chat.example.org/api/x"))
        XCTAssertNil(FrontURL.base(of: "http://127.0.0.1:notaport/abcd"))
    }

    func testOnlyAConfirmedAnswerAboutTheBoundSessionEndsIt() {
        XCTAssertTrue(SignOutRule.mayEnd(confirmed: true, sameBind: true, sameRecord: true))
        XCTAssertFalse(SignOutRule.mayEnd(confirmed: false, sameBind: true, sameRecord: true), "a local error, no answer")
        XCTAssertFalse(SignOutRule.mayEnd(confirmed: true, sameBind: false, sameRecord: true), "another bind meanwhile")
        XCTAssertFalse(SignOutRule.mayEnd(confirmed: true, sameBind: true, sameRecord: false), "a rotated token stored meanwhile")
    }

    /// Overlapping activates, a rotation and a ring check of ONE workspace: each sees what the one
    /// before it stored (an install whose token has no issue date rotates once, not twice), and
    /// none presents a credential the other replaced. Another workspace does not wait.
    @MainActor
    func testArmingIsOneAtATimePerWorkspace() async {
        let serial = SerialByKey()
        var token = "old", issued: Int64? = nil, rotations = 0, inside = 0, most = 0
        var armed: [String] = []
        func arm() async -> String {
            await serial.run("w") {
                inside += 1; most = max(most, inside)
                let mine = token
                try? await Task.sleep(for: .milliseconds(5))       // sign-in
                if issued == nil {
                    rotations += 1
                    try? await Task.sleep(for: .milliseconds(5))   // rotate on the host
                    XCTAssertEqual(mine, token, "nobody else rotated it meanwhile")
                    token = "fresh\(rotations)"; issued = 1
                }
                inside -= 1
                return token
            }
        }
        async let a = arm(); async let b = arm(); async let c = arm()
        let other = await serial.run("x") { "x" }
        XCTAssertEqual(other, "x")
        armed = await [a, b, c]
        XCTAssertEqual(armed, ["fresh1", "fresh1", "fresh1"])
        XCTAssertEqual(rotations, 1); XCTAssertEqual(most, 1)
    }

    @MainActor
    func testRelaysOffRevokesAtOnceWhateverTheEarlierChangeIsDoing() async {
        let runs = RelayRuns()
        var setting = true, log: [String] = []
        var release: CheckedContinuation<Void, Never>?
        let on = Task { @MainActor in
            await runs.changed(setting: { setting }, revoke: { log.append("revoke") }, turnOn: { log.append("on") }, turnOff: { log.append("off") },
                               redial: { _ in log.append("dialing"); await withCheckedContinuation { release = $0 }; log.append("dialed") },
                               disconnectAll: { log.append("disconnect") })
        }
        while release == nil { await Task.yield() }       // its redial hangs: the host is unreachable
        setting = false
        let off = Task { @MainActor in
            await runs.changed(setting: { setting }, revoke: { log.append("revoke") }, turnOn: { log.append("on") }, turnOff: { log.append("off") },
                               redial: { _ in log.append("redial") }, disconnectAll: {})
        }
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(log, ["on", "dialing", "revoke"], "revoked at once; only the confirmation waits")
        release?.resume()
        _ = await (on.value, off.value)
        XCTAssertEqual(log, ["on", "dialing", "revoke", "dialed", "off", "redial"])
    }

    func testTheEndOfASessionComesBeforeARebind() {
        XCTAssertEqual(SyncFailureRule.step(signedOut: true, deviceStopped: true, signInReplaced: true), .signedOut)
        XCTAssertEqual(SyncFailureRule.step(signedOut: false, deviceStopped: true, signInReplaced: true), .deviceStopped)
        XCTAssertEqual(SyncFailureRule.step(signedOut: false, deviceStopped: false, signInReplaced: true), .rebind)
        XCTAssertEqual(SyncFailureRule.step(signedOut: false, deviceStopped: false, signInReplaced: false), .other)
    }

    func testRebindingBacksOffAndIsCapped() {
        var p = RebindPacer()
        let t = Date()
        XCTAssertEqual((0..<6).map { _ in p.next("a", now: t) }, [0, 2, 8, 30, nil, nil])
        XCTAssertEqual(p.next("b", now: t), 0, "each workspace has its own")
        XCTAssertNil(p.next("a", now: t.addingTimeInterval(59)))
        XCTAssertEqual(p.next("a", now: t.addingTimeInterval(60)), 0, "armed again every minute")
        XCTAssertNil(p.next("a", now: t.addingTimeInterval(61)))
        XCTAssertEqual(p.next("a", now: t.addingTimeInterval(120)), 0)
        p.succeeded("a")
        XCTAssertEqual((0..<2).map { _ in p.next("a", now: t) }, [0, 2])
    }

    /// The front says the credential is not the one signed in any more (a re-key while the host
    /// rotated): signed in again with the fresh token — no dead credential is handed on; not at all
    /// when it cannot be. And what a sign-out meanwhile made unwanted is taken back.
    @MainActor
    func testArmingNeverHandsOnADeadCredential() async {
        var credentials = ["c1", "c2"], cleared: [String] = [], stored = "t1"
        func flow(_ signIn: @escaping @MainActor (String) -> String?, stillStored: @escaping @MainActor (String) -> Bool = { _ in true }) -> ArmFlow<String> {
            ArmFlow(stored: { stored }, isStored: stillStored, signIn: { signIn($0) }, rotate: { _, _ in stored = "t2"; return "t2" },
                    rotateToken: { _, _ in false }, clear: { cleared.append($0) })
        }
        var asked: [String] = []
        let ok = await flow({ asked.append($0); return credentials.removeFirst() }).run(throughFront: true, rotating: true)
        XCTAssertEqual(ok?.record, "t2"); XCTAssertEqual(ok?.credential, "c2"); XCTAssertEqual(asked, ["t1", "t2"])
        stored = "t1"; credentials = ["c1"]
        let none = await flow({ _ in credentials.isEmpty ? nil : credentials.removeFirst() }).run(throughFront: true, rotating: true)
        XCTAssertNil(none?.credential); XCTAssertNil(none)
        stored = "t1"
        let out = await flow({ _ in "c9" }, stillStored: { _ in false }).run(throughFront: true, rotating: false)
        XCTAssertNil(out); XCTAssertEqual(cleared, ["c9"])
    }

    @MainActor
    func testAMoveKeepsTheSessionAndWhatChangedMeanwhile() async {
        struct R: Equatable { var server = "old", token = "t1", name = "n", out = false }
        var stored = R(), log: [String] = []
        func flow(_ proves: @escaping @MainActor () async -> Bool, close: @escaping @MainActor () async -> Void = {}) -> MoveFlow<R> {
            MoveFlow(proves: proves, latest: { stored.out ? nil : stored }, closeFront: { log.append("close"); await close() },
                     write: { stored.server = "new"; return stored })
        }
        // A token rotated while the new address proved itself, a name while the front closed.
        let r = await flow({ stored.token = "t2"; return true }, close: { stored.name = "m" }).run()
        XCTAssertEqual(r, R(server: "new", token: "t2", name: "m")); XCTAssertEqual(log, ["close"])
        // Signed out meanwhile: not undone, nothing written.
        stored = R()
        let none = await flow({ stored.out = true; return true }).run()
        XCTAssertNil(none); XCTAssertEqual(stored.server, "old")
        stored = R(); log = []
        let unproved = await flow({ false }).run()
        XCTAssertNil(unproved); XCTAssertEqual(log, [])
    }

    func testOnlyTheEndOfASessionTellsTheHost() {
        for why in [SessionEnd.signOut, .removed, .accountEnded] { XCTAssertTrue(SessionEnd.tellsHost(why)) }
        for why in [SessionEnd.moved, .hostChanged, .relaysOff, .superseded] { XCTAssertFalse(SessionEnd.tellsHost(why)) }
        XCTAssertTrue(SessionEnd.tellsHost(.removed, token: "t", others: ["u", ""]))
        XCTAssertFalse(SessionEnd.tellsHost(.removed, token: "t", others: ["t"]), "another entry uses the same session")
        XCTAssertFalse(SessionEnd.tellsHost(.signOut, token: "", others: []))
    }

    @MainActor
    func testARotationThatCannotBeStoredIsNotUsedAndIsAskedAgainWithItsKey() async {
        var key: String?, asked: [String] = [], writable = false, token = "t1"
        func run(answer: String?) async -> RotationFlow<String>.Outcome {
            await RotationFlow<String>(storeKey: { key = key ?? "k"; return key }, ask: { asked.append($0); return answer.map { ("u", $0, 0) } },
                                       stillStored: { true }, persist: { guard writable else { return nil }; token = $0.token; key = nil; return token }).run()
        }
        for answer in [nil, "t2"] { if case .again = await run(answer: answer) {} else { XCTFail("\(answer ?? "lost")") } }
        XCTAssertEqual(token, "t1"); XCTAssertEqual(key, "k")
        writable = true
        if case .rotated(let r) = await run(answer: "t3") { XCTAssertEqual(r, "t3") } else { XCTFail() }
        XCTAssertEqual(asked, ["k", "k", "k"], "the same key each time"); XCTAssertNil(key)
        // No key on disk, no request.
        let none = await RotationFlow<String>(storeKey: { nil }, ask: { _ in XCTFail("asked"); return nil }, stillStored: { true }, persist: { _ in nil }).run()
        if case .notDue = none {} else { XCTFail() }
    }

    @MainActor
    func testTheCallerStopsWaitingAtTheDeadlineAndNothingOvertakes() async {
        let serial = SerialByKey()
        var log: [String] = [], release: CheckedContinuation<Void, Never>?
        let late: String? = await serial.run("w", deadline: .milliseconds(30)) { log.append("first"); await withCheckedContinuation { release = $0 }; log.append("first done"); return "x" }
        XCTAssertNil(late)
        let second = Task { @MainActor in await serial.run("w") { log.append("second"); return 1 } }
        try? await Task.sleep(for: .milliseconds(30))
        XCTAssertEqual(log, ["first"], "still running: the next one waits for it")
        release?.resume()
        _ = await second.value
        XCTAssertEqual(log, ["first", "first done", "second"])
    }

    /// A background task is given back exactly once, in time, whatever happens to its owner.
    @MainActor
    func testABackgroundTaskIsAlwaysGivenBackOnceAndInTime() {
        final class Fake {
            var now: TimeInterval = 0
            var granted: Int? = 7
            var expired: (@MainActor () -> Void)?
            var expireWhileAsking = false
            var ended: [(Int, TimeInterval)] = []
            var timers: [(TimeInterval, @MainActor () -> Void)] = []
            @MainActor func advance(to t: TimeInterval) {
                now = t
                let due = timers.filter { $0.0 <= t }
                timers.removeAll { $0.0 <= t }
                for d in due { d.1() }
            }
            @MainActor var system: BackgroundHold.System {
                .init(begin: { _, expired in
                    self.expired = expired
                    if self.expireWhileAsking { expired() }
                    return self.granted
                }, end: { self.ended.append(($0, self.now)) },
                   after: { s, f in self.timers.append((self.now + s, f)) })
            }
        }
        // Ended by its owner: the warning and the limit that come later change nothing.
        var f = Fake()
        var hold: BackgroundHold? = BackgroundHold("x", system: f.system)
        f.now = 2; hold?.end(); hold?.end()
        f.expired?(); f.advance(to: 60)
        XCTAssertEqual(f.ended.map(\.0), [7]); XCTAssertEqual(f.ended.first?.1, 2)

        // The warning: ended before the handler returns — the owner is gone by then.
        f = Fake()
        hold = BackgroundHold("x", system: f.system); hold = nil
        f.now = 5; f.expired?()
        XCTAssertEqual(f.ended.map(\.1), [5], "synchronously, without its owner")
        f.advance(to: 60)
        XCTAssertEqual(f.ended.count, 1)

        // Nobody ends it and no warning comes: the limit, well inside what the system allows.
        f = Fake()
        hold = BackgroundHold("x", system: f.system); hold = nil
        f.advance(to: 19.9); XCTAssertTrue(f.ended.isEmpty)
        f.advance(to: 20); XCTAssertEqual(f.ended.map(\.1), [20])
        f.expired?(); XCTAssertEqual(f.ended.count, 1)
        XCTAssertLessThanOrEqual(BackgroundHold.limit, 20)

        // Out of time while it is being asked for: given back, once, and no timer is left.
        f = Fake(); f.expireWhileAsking = true
        hold = BackgroundHold("x", system: f.system)
        XCTAssertEqual(f.ended.map(\.0), [7]); XCTAssertTrue(f.timers.isEmpty)
        hold?.end(); XCTAssertEqual(f.ended.count, 1)

        // Not granted: nothing to give back.
        f = Fake(); f.granted = nil
        hold = BackgroundHold("x", system: f.system); hold?.end(); f.advance(to: 60)
        XCTAssertTrue(f.ended.isEmpty); XCTAssertTrue(f.timers.isEmpty)
    }

    func testNoDirectRouteIsSaidAfterAWhileAndOnlyWithRelaysOff() {
        let t0 = Date(timeIntervalSince1970: 0)
        func at(_ s: Double) -> Date { t0.addingTimeInterval(s) }
        var r = DirectOnlyRule()
        XCTAssertFalse(r.note(workspace: "a", usable: false, relaysOff: true, now: at(0)))
        XCTAssertFalse(r.note(workspace: "a", usable: false, relaysOff: true, now: at(24)))
        XCTAssertTrue(r.note(workspace: "a", usable: false, relaysOff: true, now: at(25)))
        XCTAssertFalse(r.note(workspace: "b", usable: false, relaysOff: true, now: at(26)), "another skwod starts anew")
        XCTAssertFalse(r.note(workspace: "b", usable: false, relaysOff: false, now: at(90)), "with relays it says what it always did")
        XCTAssertFalse(r.note(workspace: "b", usable: false, relaysOff: true, now: at(91)))
        XCTAssertFalse(r.note(workspace: "b", usable: true, relaysOff: true, now: at(120)))
        XCTAssertFalse(r.note(workspace: nil, usable: false, relaysOff: true, now: at(200)))
        XCTAssertTrue(DirectOnlyRule.text("Crew").contains("Can't reach Crew directly"))
    }

    func testTheConnectionIsNotLookedAtFromTheBackground() {
        XCTAssertTrue(ConnectionWatch.looks(appActive: true, inBackground: false, callActive: false))
        XCTAssertFalse(ConnectionWatch.looks(appActive: false, inBackground: true, callActive: false))
        XCTAssertFalse(ConnectionWatch.looks(appActive: true, inBackground: true, callActive: false), "launched in the background by a push")
        XCTAssertFalse(ConnectionWatch.looks(appActive: false, inBackground: false, callActive: false))
        XCTAssertTrue(ConnectionWatch.looks(appActive: false, inBackground: true, callActive: true), "a call goes on")
    }

    @MainActor
    func testTheConnectionIsLookedAtWhileASyncPassWaits() async {
        let watch = ConnectionWatch()
        var looks = 0
        watch.start(every: .milliseconds(10)) { _ in looks += 1; try? await Task.sleep(for: .seconds(30)) }   // each look hangs
        try? await Task.sleep(for: .milliseconds(200))
        XCTAssertGreaterThan(looks, 3)
        watch.stop()
        try? await Task.sleep(for: .milliseconds(30))
        let n = looks
        try? await Task.sleep(for: .milliseconds(60))
        XCTAssertEqual(looks, n)
    }

    /// The false sign-out and the lost session, forced: two binds of one workspace — in every order
    /// their steps can interleave — with one thing happening anywhere between (a rotation's answer
    /// lost, the old token's grace over, a re-key, a sign-out by the user, the host ending the
    /// session), and a third actor (a ring check); through a front and over
    /// https; rotation due or not. The host can refuse here: its tokens are superseded, expire and
    /// are deleted as the server does it.
    @MainActor
    func testNoInterleavingLosesTheSessionOrSignsOutFalsely() async {
        let all = Self.interleavings([("A", 4), ("B", 4), ("E", 1)])
        XCTAssertEqual(all.count, 630)
        var rnd = SystemRandom(seed: 51)
        // (A bind, a ring check and the event: in every order; all four: a sample.)
        let third = Self.interleavings([("A", 4), ("C", 2), ("E", 1)]) + (0..<160).map { _ in rnd.shuffled("AAAABBBBCCE") }
        for front in [true, false] {
            for event in BindWorld.Event.allCases {
                for due in [true, false] {
                    for order in (due ? all : Array(all.prefix(90))) + third {
                        let w = BindWorld(due: due, front: front, event: event)
                        await w.play(order)
                        if let wrong = w.wrong() { XCTFail("\(wrong) — \(event) front=\(front) due=\(due) \(order)"); return }
                    }
                }
            }
        }
    }

    /// …and the logic of 070b2f383 in the same world: this test does force the race.
    @MainActor
    func testTheOldLogicFailsInTheSameWorld() async {
        var wrong = 0
        for order in Self.interleavings([("A", 4), ("B", 4)]) {
            let w = BindWorld(due: true, front: true, event: .none, old: true)
            await w.play(order)
            if w.wrong() != nil { wrong += 1 }
        }
        XCTAssertGreaterThan(wrong, 0)
        print("old logic: \(wrong) of 70 orders go wrong")
    }

    private static func interleavings(_ who: [(String, Int)]) -> [String] {
        if who.allSatisfy({ $0.1 == 0 }) { return [""] }
        return who.indices.filter { who[$0].1 > 0 }.flatMap { i -> [String] in
            var rest = who
            rest[i].1 -= 1
            return interleavings(rest).map { who[i].0 + $0 }
        }
    }
}

private struct SystemRandom: RandomNumberGenerator {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 { state ^= state << 13; state ^= state >> 7; state ^= state << 17; return state &* 2685821657736338717 }
    mutating func shuffled(_ s: String) -> String { var a = Array(s); a.shuffle(using: &self); return String(a) }
}

/// One workspace, its front and its host; every step of every actor waits for its turn.
@MainActor
private final class BindWorld {
    enum Event: CaseIterable { case none, loseReply, graceOver, rekey, userSignOut, hostEnds }
    let due: Bool, throughFront: Bool, event: Event, old: Bool
    // What is stored.
    var token = "t1", key: String?, issued: Bool, signedOut = false, userOut = false
    // The host.
    private struct Tok { var superseded = false, expired = false, used = false; var key: String?, successor: String? }
    private var tokens: [String: Tok] = ["t1": Tok(used: true)], minted = 1, rotations = 0, ended = false, loseNext: Bool
    // The front.
    private var front: (credential: String, token: String)?, credentials = 0
    // The app.
    private var bound = "", turn = 0
    private let serial = SerialByKey()
    private var allowed: [String: Int] = [:], waiting: [String: CheckedContinuation<Void, Never>] = [:], running = 0

    init(due: Bool, front: Bool, event: Event, old: Bool = false) {
        self.due = due; throughFront = front; self.event = event; self.old = old
        issued = !due; loseNext = event == .loseReply
    }

    private func host(_ t: String) -> Bool {
        guard !ended, var tok = tokens[t], !tok.expired else { return false }
        tok.used = true
        tokens[t] = tok
        return true
    }
    private func hostRotate(_ t: String, _ k: String) -> String? {
        guard !ended, var tok = tokens[t], !tok.expired else { return nil }
        if tok.superseded {
            guard tok.key == k, let s = tok.successor, let unheld = tokens[s], !unheld.used, !unheld.superseded else { return nil }
            tokens[s] = nil
        }
        minted += 1; rotations += 1
        let fresh = "t\(minted)"
        tok.superseded = true; tok.key = tok.key ?? k; tok.successor = fresh; tok.used = true
        tokens[t] = tok
        tokens[fresh] = Tok()
        if loseNext { loseNext = false; return nil }
        return fresh
    }
    private func signIn(_ t: String) -> String {
        if !old, let f = front, f.token == t { return f.credential }
        credentials += 1
        front = ("c\(credentials)", t)
        return "c\(credentials)"
    }
    /// What a client presenting `wire` is told; nil: refused here, not sent.
    private func ask(_ wire: String) -> Bool? {
        guard throughFront else { return host(wire) }
        guard let f = front, f.credential == wire else { return old ? false : nil }
        return host(f.token)
    }
    /// The token `wire` stands for now (the core's `real_token`).
    private func real(_ wire: String) -> String? { throughFront ? (front?.credential == wire ? front?.token : nil) : wire }
    /// The core's `session_check`: ended?
    private func confirmedEnd(_ wire: String) -> Bool {
        if old { return ask(wire) == false }
        guard let t = real(wire) else { return false }
        for _ in 0..<2 where ask(wire) != false || real(wire) != t { return false }
        return true
    }

    private func step(_ who: String) async {
        if let n = allowed[who], n > 0 { allowed[who] = n - 1; return }
        await withCheckedContinuation { waiting[who] = $0 }
    }
    private func go(_ who: String) {
        if let c = waiting.removeValue(forKey: who) { c.resume() } else { allowed[who, default: 0] += 1 }
    }
    private func start(_ who: String, _ body: @escaping @MainActor () async -> Void) {
        running += 1
        Task { @MainActor in await body(); running -= 1 }
    }

    func play(_ order: String) async {
        start("A") { await self.bind("A") }
        start("B") { await self.bind("B") }
        if order.contains("C") { start("C") { await self.ring("C") } }
        start("E") { await self.step("E"); self.happen() }
        for who in order { go(String(who)); for _ in 0..<8 { await Task.yield() } }
        while running > 0 { for w in ["A", "B", "C", "D", "E"] where waiting[w] != nil { go(w) }; await Task.yield() }
        // What the app does next on its own: bind again after a rotation that did not come to its
        // end (while the old token's grace still runs).
        guard !old else { return }
        if !signedOut, !userOut, due && !issued {
            start("F") { await self.bind("F") }
            while running > 0 { if waiting["F"] != nil { go("F") }; await Task.yield() }
        }
        if event == .hostEnds, !signedOut, !userOut { end(bound, token) }
        graceOver()
    }
    private func happen() {
        switch event {
        case .none, .loseReply: break
        case .graceOver: graceOver()
        case .rekey: 
            // The app binds again whenever its front moved (`.moved` → activate).
            if let f = front { credentials += 1; front = ("c\(credentials)", f.token); start("D") { await self.bind("D") } }
        case .userSignOut: userOut = true; token = ""; key = nil; front = nil
        case .hostEnds: ended = true
        }
    }
    /// (Minutes later: never before the fresh token is stored.)
    private func graceOver() { for (t, tok) in tokens where tok.superseded && t != token { tokens[t]?.expired = true } }

    private func stored(_ t: String) -> Bool { !signedOut && !userOut && token == t }
    private func end(_ wire: String, _ record: String, sameBind: Bool = true) {
        if SignOutRule.mayEnd(confirmed: confirmedEnd(wire), sameBind: sameBind, sameRecord: stored(record)) { signedOut = true; token = ""; front = nil }
    }
    private func rotation(_ who: String, _ t: String, _ wire: String) -> RotationFlow<String> {
        RotationFlow<String>(
            storeKey: {
                guard self.stored(t) else { return nil }
                self.key = self.key ?? "k-\(who)"
                return self.key
            },
            ask: { k in
                await self.step(who)
                guard let now = self.real(wire), let fresh = self.hostRotate(now, k) else { return nil }
                return ("u", fresh, 0)
            },
            stillStored: { self.stored(t) },
            persist: { fresh in self.token = fresh.token; self.issued = true; self.key = nil; return fresh.token })
    }
    private func arm(_ who: String, rotating: Bool) async -> [String]? {
        await serial.run("w") {
            let flow = ArmFlow<String>(
                stored: { self.signedOut || self.userOut ? nil : self.token }, isStored: { self.stored($0) },
                signIn: { let t = $0; await self.step(who); return self.signIn(t) },
                rotate: { t, c in
                    guard !self.issued else { return nil }
                    if case .rotated(let fresh) = await self.rotation(who, t, c ?? t).run() { return fresh }
                    return nil
                },
                rotateToken: { c, t in
                    guard self.front?.credential == c else { return false }
                    self.front = (c, t)
                    return true
                },
                clear: { if self.front?.credential == $0 { self.front = nil } })
            return await flow.run(throughFront: self.throughFront, rotating: rotating).map { [$0.record, $0.credential ?? $0.record] }
        }
    }
    private func bind(_ who: String) async {
        await step(who)
        turn += 1
        let mine = turn
        if old {
            let t = token, c = signIn(t)
            await step(who)
            if !issued, let f = front, f.credential == c, let fresh = hostRotate(f.token, "k"), token == t {
                token = fresh; issued = true
                if front?.credential == c { front = (c, fresh) }
            }
            await step(who)
            bound = c
            await step(who)
            if confirmedEnd(c) { signedOut = true }
            return
        }
        guard let armed = await arm(who, rotating: true), mine == turn else { return }   // a later bind decides
        await step(who)
        guard mine == turn, stored(armed[0]) else { return }
        bound = armed[1]
        end(armed[1], armed[0], sameBind: mine == turn)
    }
    private func ring(_ who: String) async {
        await step(who)
        guard let armed = await arm(who, rotating: false) else { return }
        await step(who)
        if ask(armed[1]) != true { end(armed[1], armed[0]) }
    }

    /// What went wrong, if anything.
    func wrong() -> String? {
        if event == .userSignOut && userOut {
            if !token.isEmpty { return "a record that was signed out got a token again" }
            return front == nil ? nil : "the front is armed after a sign-out"
        }
        if event == .hostEnds && ended { return signedOut ? nil : "the host ended the session and the app did not notice" }
        if signedOut { return "signed out of a session the host holds" }
        if !host(token) { return "the stored token is dead: the session is lost" }
        if ask(bound) != true { return "what is bound does not work" }
        let live = tokens.values.filter { !$0.superseded && !$0.expired }.count
        if live != 1 { return "\(live) live tokens on the host" }
        let expected = due ? (event == .loseReply ? 2 : 1) : 0
        if rotations != expected { return "rotated \(rotations) times, not \(expected)" }
        return nil
    }
}
