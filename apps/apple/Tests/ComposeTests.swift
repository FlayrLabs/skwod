import XCTest

// Build 51: what a person sends goes where they sent it, and a client goes online only with its pin.

private final class FakeSkwod {
    let id: String
    var queued: [SendOrder] = []
    var detached = false
    init(_ id: String) { self.id = id }
    struct Detached: Error {}
    func queue(_ order: SendOrder) throws { if detached { throw Detached() }; queued.append(order) }
}

final class ComposeTests: XCTestCase {
    /// A composer on screen, as the views use the rules: one step takes everything, then it is queued.
    @MainActor
    private final class Composer {
        let home: String
        let place: SendOrder.Place
        var draft = ""
        var editing: String?
        var replyTo: String?
        var said: String?
        var kept: [String: String] = [:]
        var key = "k"
        init(home: String, place: SendOrder.Place) { self.home = home; self.place = place }

        func tap(_ bound: BoundClient<FakeSkwod>?) -> Task<Void, Never>? {
            let taken = Compose.take(text: draft, home: home, bound: bound.flatMap { $0.cacheOpen ? $0.workspaceId : nil },
                                     place: place, replyTo: replyTo, editing: editing)
            guard case .send(let order) = taken, let client = try? BoundClient.withCache(bound, for: home) else {
                if taken != .nothing { said = Compose.opening }
                return nil
            }
            draft = ""; replyTo = nil; editing = nil; said = nil
            return Task { @MainActor in
                do { try client.queue(order) } catch { self.draft = Compose.givenBack(order.text, to: self.draft) }
            }
        }
    }
    private func up(_ s: FakeSkwod, cacheOpen: Bool = true, turn: Int = 1) -> BoundClient<FakeSkwod> {
        BoundClient(workspaceId: s.id, client: s, cacheOpen: cacheOpen, turn: turn)
    }

    @MainActor
    func testASendIsSettledAtTheTapWhateverIsOpenedNext() async {
        let a = FakeSkwod("a"), b = FakeSkwod("b")
        let alice = Composer(home: "a", place: .direct(conversationId: "alice", peers: ["alice"]))
        let bob = Composer(home: "a", place: .direct(conversationId: "bob", peers: ["bob"]))
        alice.draft = "  for alice "
        alice.replyTo = "m1"
        let sending = alice.tap(up(a))
        // The user is already somewhere else, writing something else, in another skwod.
        bob.draft = "for bob"; alice.draft = "not yet"; alice.replyTo = "m2"
        await sending?.value
        XCTAssertEqual(a.queued, [SendOrder(workspaceId: "a", place: .direct(conversationId: "alice", peers: ["alice"]), text: "for alice", replyTo: "m1")])
        XCTAssertEqual(alice.draft, "not yet", "what was typed since stays"); XCTAssertEqual(bob.draft, "for bob")
        await bob.tap(up(a))?.value
        XCTAssertEqual(a.queued.last?.place, .direct(conversationId: "bob", peers: ["bob"])); XCTAssertEqual(a.queued.count, 2)
        XCTAssertTrue(b.queued.isEmpty)
    }

    @MainActor
    func testNothingOfOneSkwodGoesThroughAnothersCache() async {
        let a = FakeSkwod("a"), b = FakeSkwod("b")
        let composer = Composer(home: "a", place: .channel("c"))
        composer.draft = "hello"
        // Still on screen, and the other skwod's client is already up — or none, or one without its cache.
        for bound in [up(b), nil, up(a, cacheOpen: false)] {
            XCTAssertNil(composer.tap(bound))
            XCTAssertEqual(composer.draft, "hello", "kept"); XCTAssertEqual(composer.said, Compose.opening)
        }
        XCTAssertTrue(b.queued.isEmpty)
        await composer.tap(up(a))?.value
        XCTAssertEqual(a.queued.map(\.text), ["hello"]); XCTAssertEqual(composer.draft, ""); XCTAssertNil(composer.said)
        // An empty one says nothing; a conversation that belongs to no skwod sends nothing.
        XCTAssertEqual(Compose.take(text: "  ", home: "a", bound: nil, place: .channel("c")), .nothing)
        XCTAssertEqual(Compose.take(text: "x", home: nil, bound: nil, place: .channel("c")), .opening)
        XCTAssertEqual(Compose.take(text: "x", home: "", bound: "", place: .channel("c")), .opening)
    }

    /// Cut off in the middle (the app was sent away): nothing was queued, nothing is sent twice, and
    /// the text is back in its own composer.
    @MainActor
    func testACacheTakenInTheMiddleGivesTheTextBackOnce() async {
        let a = FakeSkwod("a")
        let composer = Composer(home: "a", place: .channel("c"))
        composer.draft = "hello"
        a.detached = true
        await composer.tap(up(a))?.value
        XCTAssertTrue(a.queued.isEmpty); XCTAssertEqual(composer.draft, "hello")
        let again = FakeSkwod("a")
        await composer.tap(up(again, turn: 2))?.value
        XCTAssertEqual(again.queued.count, 1); XCTAssertTrue(a.queued.isEmpty)
        XCTAssertEqual(Compose.givenBack("one", to: "two"), "one\ntwo")
        XCTAssertNotEqual(Compose.directKey(workspaceId: "a", conversationId: "x"), Compose.directKey(workspaceId: "b", conversationId: "x"))
    }

    // MARK: Going online

    private struct PinRefused: Error {}
    private struct Unreachable: Error {}

    @MainActor
    func testAClientGoesOnlineOnlyWithThePinThatWasAppliedToIt() async {
        func run(_ pin: PinState, pinnedNow: String?, cacheOpen: Bool = true, current: Bool = true, error: Error? = nil)
            async -> (GoOnline<FakeSkwod>.Outcome, asked: [String?], renewed: Int, failed: Int) {
            let a = FakeSkwod("a")
            var asked: [String?] = [], renewed = 0, failed = 0
            let outcome = await GoOnline(
                up: BoundClient(workspaceId: "a", client: a, cacheOpen: cacheOpen, turn: 3, pin: pin), pinned: pinnedNow,
                isCurrent: { current },
                goOnline: { _, pinned in asked.append(pinned); if let error { throw error } },
                isPinError: { $0 is PinRefused }, renew: { renewed += 1; return 4 }, failPin: { failed += 1 }).run()
            return (outcome, asked, renewed, failed)
        }
        // The pin is handed to the core with the way to the host: it applies it first.
        var r = await run(.applied(key: "K"), pinnedNow: "K")
        XCTAssertEqual(r.0, .online(turn: 4)); XCTAssertEqual(r.asked, ["K"]); XCTAssertEqual(r.renewed, 1)
        r = await run(.applied(key: nil), pinnedNow: nil)
        XCTAssertEqual(r.0, .online(turn: 4))
        // Failed, or never made for this client, or for another key: nothing is asked of anyone.
        r = await run(.failed, pinnedNow: "K")
        XCTAssertEqual(r.0, .pinFailed); XCTAssertTrue(r.asked.isEmpty); XCTAssertEqual(r.renewed, 0)
        for (pin, now) in [(PinState.unchecked, Optional("K")), (.unchecked, nil), (.applied(key: nil), "K"), (.applied(key: "K"), nil), (.applied(key: "K"), "L")] {
            r = await run(pin, pinnedNow: now)
            XCTAssertEqual(r.0, .notThisOne); XCTAssertTrue(r.asked.isEmpty); XCTAssertEqual(r.renewed, 0)
        }
        r = await run(.applied(key: "K"), pinnedNow: "K", cacheOpen: false)
        XCTAssertEqual(r.0, .notThisOne); XCTAssertTrue(r.asked.isEmpty)
        // It cannot be applied again: marked, and no turn, so no sync, no socket.
        r = await run(.applied(key: "K"), pinnedNow: "K", error: PinRefused())
        XCTAssertEqual(r.0, .pinFailed); XCTAssertEqual(r.renewed, 0); XCTAssertEqual(r.failed, 1)
        // The host did not answer: the core kept the offline way, so it is bound anew on the host.
        r = await run(.applied(key: "K"), pinnedNow: "K", error: Unreachable())
        XCTAssertEqual(r.0, .notThisOne); XCTAssertEqual(r.renewed, 0); XCTAssertEqual(r.failed, 0)
        // Superseded meanwhile: nothing is renewed or marked.
        for error in [nil, Unreachable(), PinRefused()] as [Error?] {
            r = await run(.applied(key: "K"), pinnedNow: "K", current: false, error: error)
            XCTAssertEqual(r.0, .superseded); XCTAssertEqual(r.renewed, 0); XCTAssertEqual(r.failed, 0)
        }
    }

    func testAPinIsTheClientsOwnAndANewBindStartsWithout() {
        let binding = ClientBinding<FakeSkwod>()
        XCTAssertTrue(binding.commit(binding.begin(), workspaceId: "a", client: FakeSkwod("a"), cacheOpen: true, pin: .applied(key: "K")))
        XCTAssertEqual(binding.renew(), 2); XCTAssertEqual(binding.bound?.pin, .applied(key: "K")); XCTAssertEqual(binding.bound?.turn, 2)
        binding.failPin()
        XCTAssertEqual(binding.bound?.pin, .failed)
        XCTAssertTrue(binding.commit(binding.begin(), workspaceId: "a", client: FakeSkwod("a"), cacheOpen: true))
        XCTAssertEqual(binding.bound?.pin, .unchecked)
        binding.begin()
        XCTAssertNil(binding.renew())
    }
}
