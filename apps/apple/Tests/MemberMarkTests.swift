import XCTest

/// Build 51: an ordinary member's mark is quiet and explains itself; a warning stays a warning.
final class MemberMarkTests: XCTestCase {
    private let book = ["u-alice": Contact(name: "alice", level: .known), "u-vera": Contact(name: "vera", level: .verified)]
    private func badge(_ id: String, _ name: String, _ lookup: Bool?) -> ContactTrust.Badge {
        ContactTrust.display(userId: id, claimedName: name, book: book, lookup: lookup).badge
    }

    func testTheTable() {
        let table: [(String, ContactTrust.Badge, ContactTrust.Mark, ContactTrust.Mark)] = [
            ("known", badge("u-alice", "alice", nil), .none, .none),
            ("verified", badge("u-vera", "vera", nil), .shield, .shield),
            ("the directory agrees", badge("u-carol", "carol", true), .symbol("questionmark.circle"), .words),
            ("not answered yet (every member of a newly linked device)", badge("u-carol", "carol", nil), .symbol("questionmark.circle.dashed"), .loud),
            ("the directory says another account", badge("u-carol", "carol", false), .loud, .loud),
            ("a look-alike", badge("u-ghost", "a1ice", true), .loud, .loud),
            ("odd characters", badge("u-odd", "car\u{043E}l", true), .loud, .loud),
            ("odd characters, not looked up", badge("u-odd", "car\u{043E}l", nil), .loud, .loud),
            ("a look-alike, not looked up", badge("u-ghost", "alice", nil), .loud, .loud),
        ]
        for (what, badge, row, screen) in table {
            XCTAssertEqual(ContactTrust.mark(badge, compact: true), row, what)
            XCTAssertEqual(ContactTrust.mark(badge, compact: false), screen, what)
            XCTAssertEqual(ContactTrust.explanation(badge) == nil, badge == .none, what)
        }
    }

    func testNothingGotWeaker() {
        let hidden = ContactTrust.display(userId: "u-x", claimedName: "carol", book: book, lookup: false)
        XCTAssertEqual(hidden, .init(text: "Unknown contact u-x", badge: .mismatch))
        XCTAssertTrue(ContactTrust.isFlagged(.mismatch) && ContactTrust.isFlagged(.unconfirmed) && ContactTrust.isFlagged(.impersonation))
        XCTAssertFalse(ContactTrust.mayPinOnVerify(.mismatch) || ContactTrust.mayPinOnVerify(.unconfirmed) || ContactTrust.mayPinOnVerify(.impersonation))
        XCTAssertEqual(ContactTrust.afterOpening(existing: nil, isNewConversation: true, name: "carol", badge: .mismatch)?.level, .unverified)
        XCTAssertEqual(hidden.chipWords, "unconfirmed")
        // Text-only places keep the words for a name not confirmed yet.
        let pending = ContactTrust.display(userId: "u-carol", claimedName: "carol", book: book, lookup: nil)
        for surface in ContactTrust.Surface.allCases where ContactTrust.form(surface) == .text {
            XCTAssertEqual(pending.label(for: surface), "carol (unconfirmed)")
        }
    }

    /// The base marked the request done when it was SENT: a sibling that was away, or whose book
    /// came before its snapshot, was never asked again — nor was a device that was linked again.
    func testANewDeviceAsksUntilASiblingHasAnswered() {
        XCTAssertTrue(SiblingRules.mayRequest(answered: false, asks: 0, lastAsk: nil, now: 100))
        XCTAssertFalse(SiblingRules.mayRequest(answered: false, asks: 1, lastAsk: 100, now: 100 + 600))
        XCTAssertTrue(SiblingRules.mayRequest(answered: false, asks: 1, lastAsk: 100, now: 100 + 660))
        XCTAssertFalse(SiblingRules.mayRequest(answered: false, asks: SiblingRules.maxRequests, lastAsk: 100, now: 99_999))
        XCTAssertFalse(SiblingRules.mayRequest(answered: true, asks: 0, lastAsk: nil, now: 100))
        let book = ["u-alice": Contact(name: "alice", level: .known)]
        XCTAssertFalse(SiblingRules.answers(book: book, vouched: []), "nobody could be taken: not an answer")
        XCTAssertTrue(SiblingRules.answers(book: book, vouched: ["u-alice"]))
        XCTAssertTrue(SiblingRules.answers(book: [:], vouched: []), "nothing to hand over is an answer")
        // What it then brings: someone the other device's user made known is known here.
        XCTAssertEqual(SiblingRules.mergedBook(local: [:], synced: book, vouched: ["u-alice"], mismatched: [])["u-alice"]?.level, .known)
    }
}
