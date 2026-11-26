import XCTest

/// "‹name› is typing…" says what the message header says, under the same trust rules.
final class TypingNameTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1000)
    private func typing(_ ids: [String], in audience: TypingAudience) -> TypingState {
        var t = TypingState()
        t.focus("channel:c")
        for (i, id) in ids.enumerated() {
            t.received(userId: id, topic: "channel:c", me: "me", blocked: [], audience: audience, enabled: true, now: now.addingTimeInterval(Double(i) / 10))
        }
        return t
    }

    func testEachRowOfTheTableNamesThePersonAsTheHeaderDoes() {
        let book = ["u-kim": Contact(name: "kim", level: .known), "u-ver": Contact(name: "vera", level: .verified)]
        let names = ["u-carol": "carol", "u-kim": "hostsays", "u-ver": "other", "u-ghost": "kim", "u-odd": "car\u{043E}l", "u-none": ""]
        let audience = TypingAudience(conversationId: "c", names: names)
        let lookups = ["u-carol": true, "u-ghost": true, "u-odd": true]
        let display: (String, String?) -> ContactTrust.Display = { ContactTrust.display(userId: $0, claimedName: $1, book: book, lookup: lookups[$0]) }
        let expected = ["u-carol": "carol (unverified)", "u-kim": "kim", "u-ver": "vera",
                        "u-ghost": "Unknown contact u-ghos", "u-odd": "Unknown contact u-odd", "u-none": "Unknown contact u-none"]
        for (id, want) in expected {
            let got = typing([id], in: audience).names(now: now, audience: audience) { display($0, $1).label(for: .typing) }
            XCTAssertEqual(got, [want])
            // The same name as the header; the trust in words here, as a badge there.
            XCTAssertTrue(got[0].hasPrefix(display(id, names[id]).label(for: .messageHeader)), id)
        }
    }

    /// What 0.50 did: nobody's claimed name was handed over, so an ordinary member had none.
    func testAMemberNobodyMessagedIsNamed() {
        let audience = TypingAudience(conversationId: "c", names: ["u-carol": "carol"])
        let got = typing(["u-carol"], in: audience).names(now: now, audience: audience) {
            ContactTrust.display(userId: $0, claimedName: $1, book: [:], lookup: true).label(for: .typing)
        }
        XCTAssertEqual(TypingState.text(got), "carol (unverified) is typing…")
    }

    func testTheNameFollowsARosterThatArrivesWhileTheyType() {
        let before = TypingAudience(conversationId: "c", names: ["u-carol": ""])
        let t = typing(["u-carol"], in: before)
        let label: (String, String?) -> String = { ContactTrust.display(userId: $0, claimedName: $1, book: [:], lookup: true).label(for: .typing) }
        XCTAssertEqual(t.names(now: now, audience: before, label: label), ["Unknown contact u-caro"], "a placeholder, never blank")
        XCTAssertEqual(t.names(now: now, audience: TypingAudience(conversationId: "c", names: ["u-carol": "carol"]), label: label), ["carol (unverified)"])
    }
}
