import XCTest

/// Build 45 audit (Apple A4, A9, A10; push B3): names the SERVER supplies — channel authors,
/// feed posts and comments, callers — go through the same rule as direct messages.
final class NameTrustTests: XCTestCase {
    private let book: [String: Contact] = [
        "u-alice": Contact(name: "alice", level: .verified),
        "u-bob": Contact(name: "bob", level: .known),
    ]

    func testAServerThatSwapsTwoKnownMembersNamesChangesNothing() {
        // The member list now says Bob's account is "alice" and Alice's is "bob".
        XCTAssertEqual(ContactTrust.authorLabel(userId: "u-bob", claimedName: "alice", book: book), "bob")
        XCTAssertEqual(ContactTrust.authorLabel(userId: "u-alice", claimedName: "bob", book: book), "alice")
    }

    func testAnotherAccountCannotWearAKnownName() {
        for claimed in ["alice", "Alice", "a1ice", "al\u{0456}ce", "alice\u{200B}"] {
            let label = ContactTrust.authorLabel(userId: "u-ghost", claimedName: claimed, book: book, lookup: true)
            XCTAssertTrue(label.hasPrefix("Unknown contact"), "\(claimed) was shown as \(label)")
        }
        // Nor the name of an accepted member of a shared server.
        let label = ContactTrust.authorLabel(userId: "u-ghost", claimedName: "carol", book: book, roster: ["u-carol": "carol"], lookup: true)
        XCTAssertTrue(label.hasPrefix("Unknown contact"))
    }

    func testANameOnlyTheServerVouchesForCarriesItsMarker() {
        XCTAssertEqual(ContactTrust.authorLabel(userId: "u-carol", claimedName: "carol", book: book, roster: ["u-carol": "carol"], lookup: true),
                       "carol (unverified)")
        XCTAssertEqual(ContactTrust.authorLabel(userId: "u-carol", claimedName: "carol", book: book, lookup: nil), "carol (unconfirmed)")
        // The directory says the name is someone else's (or nobody's): not shown as a name.
        XCTAssertTrue(ContactTrust.authorLabel(userId: "u-carol", claimedName: "carol", book: book, lookup: false).hasPrefix("Unknown contact"))
    }

    func testNoNameAndNoAuthorAreNeverBlankOrAGuess() {
        XCTAssertEqual(ContactTrust.authorLabel(userId: "u-123456789", claimedName: nil, book: [:]), "Unknown contact u-1234")
        XCTAssertEqual(ContactTrust.authorLabel(userId: nil, claimedName: "mom", book: [:]), "Unknown member")
        XCTAssertEqual(ContactTrust.authorLabel(userId: "", claimedName: "mom", book: [:]), "Unknown member")
    }

    // MARK: the call screen (push B3)

    func testTheCallScreenNamesNobodyWithAppLockOnOrPreviewsOff() {
        XCTAssertEqual(CallLabel.text(caller: "alice", server: "Family", appLock: false, previews: true), "alice · Family")
        XCTAssertEqual(CallLabel.text(caller: "alice", server: "Family", appLock: true, previews: true), "Skwod call")
        XCTAssertEqual(CallLabel.text(caller: "alice", server: "Family", appLock: false, previews: false), "Skwod call")
        XCTAssertEqual(CallLabel.text(caller: nil, server: "Family", appLock: false, previews: true), "Family")
        XCTAssertEqual(CallLabel.text(caller: "", server: nil, appLock: false, previews: true), "Skwod call")
    }

    func testACallerIsLabelledByTheContactBookNotTheServer() {
        // The server lists the ringing account as "Mom"; the user knows Mom under another id.
        let book = ["u-mom": Contact(name: "Mom", level: .known)]
        let who = ContactTrust.authorLabel(userId: "u-ghost", claimedName: "Mom", book: book, lookup: true)
        let label = CallLabel.text(caller: who, server: "Family", appLock: false, previews: true)
        XCTAssertFalse(label.contains("Mom"), label)
    }

    // MARK: A9 — accept only pins a name that is on screen

    func testAcceptIsRefusedForANameThatIsNotShown() {
        // The server lists an accomplice as "dad"; the directory lookup leads elsewhere, so the
        // screen says "Unknown contact …". Accepting would pin the hidden "dad".
        let hidden = ContactTrust.display(userId: "u-ghost1", claimedName: "dad", book: [:], lookup: false)
        XCTAssertTrue(hidden.text.hasPrefix("Unknown contact"))
        XCTAssertFalse(ContactTrust.mayAccept(shown: hidden, name: "dad"))
        // A look-alike: refused as before.
        let lookalike = ContactTrust.display(userId: "u-ghost1", claimedName: "alice", book: book, lookup: true)
        XCTAssertFalse(ContactTrust.mayAccept(shown: lookalike, name: "alice"))
        // A name that IS on screen (unverified or unconfirmed) can be accepted; an empty one cannot.
        let visible = ContactTrust.display(userId: "u-carol", claimedName: "carol", book: [:], lookup: true)
        XCTAssertTrue(ContactTrust.mayAccept(shown: visible, name: "carol"))
        XCTAssertTrue(ContactTrust.mayAccept(shown: ContactTrust.display(userId: "u-carol", claimedName: "carol", book: [:], lookup: nil), name: "carol"))
        XCTAssertFalse(ContactTrust.mayAccept(shown: ContactTrust.display(userId: "u-carol", claimedName: "", book: [:]), name: ""))
    }

    // MARK: A8 — reactions count only from the conversation's people

    func testAThirdAccountsReactionDoesNotCountInADirectChat() {
        XCTAssertTrue(ContactTrust.reactionCounts(from: "u-peer", me: "u-me", participants: ["u-peer"]))
        XCTAssertTrue(ContactTrust.reactionCounts(from: "u-me", me: "u-me", participants: ["u-peer"]))
        XCTAssertFalse(ContactTrust.reactionCounts(from: "u-outsider", me: "u-me", participants: ["u-peer"]))
        XCTAssertFalse(ContactTrust.reactionCounts(from: "", me: "u-me", participants: ["u-peer"]))
    }

    // MARK: A11 — every screen that can let someone in checks the name

    func testLetInIsOnlyForANameThatCheckedOut() {
        let known = [(userId: "u-alice", name: "alice")]
        let ok = WaitingTrust.assess(userId: "u-new", username: "newbie", lookup: .some("u-new"), known: known)
        XCTAssertTrue(WaitingTrust.mayLetIn(ok))
        // A look-alike of someone the user knows, under another account.
        XCTAssertFalse(WaitingTrust.mayLetIn(WaitingTrust.assess(userId: "u-ghost", username: "a1ice", lookup: .some("u-ghost"), known: known)))
        // The directory says the name is someone else's, or nobody's; or it was never asked.
        XCTAssertFalse(WaitingTrust.mayLetIn(WaitingTrust.assess(userId: "u-new", username: "newbie", lookup: .some("u-other"), known: known)))
        XCTAssertFalse(WaitingTrust.mayLetIn(WaitingTrust.assess(userId: "u-new", username: "newbie", lookup: .some(nil), known: known)))
        XCTAssertFalse(WaitingTrust.mayLetIn(WaitingTrust.assess(userId: "u-new", username: "newbie", lookup: nil, known: known)))
        XCTAssertFalse(WaitingTrust.mayLetIn(WaitingTrust.assess(userId: "u-new", username: "n\u{0435}wbie", lookup: .some("u-new"), known: known)))
    }
}
