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

    /// Build 49: every surface a name appears on, and its form — table-driven. Styled rows show
    /// the plain name with a badge; everything without a badge keeps the words.
    func testEverySurfaceHasItsForm() {
        let table: [(ContactTrust.Surface, ContactTrust.Form)] = [
            (.messageHeader, .badge), (.memberRow, .badge), (.dmRow, .badge), (.mentionChip, .badge), (.profileCard, .badge),
            (.mentionPicker, .text), (.replyPreview, .text), (.notification, .text), (.incomingCall, .text),
            (.dialogTitle, .text), (.kickBanDialog, .text), (.actionSheet, .text), (.approvalRow, .text),
            (.joinConfirmation, .text), (.groupConfirmation, .text), (.securityNotice, .text), (.typing, .text),
            (.blockReportTarget, .text),
        ]
        XCTAssertEqual(Set(table.map(\.0)), Set(ContactTrust.Surface.allCases), "a new surface needs its form decided here")
        let shown = ContactTrust.display(userId: "u-carol", claimedName: "carol", book: [:], lookup: true)
        for (surface, form) in table {
            XCTAssertEqual(ContactTrust.form(surface), form, "\(surface)")
            XCTAssertEqual(shown.label(for: surface), form == .badge ? "carol" : "carol (unverified)", "\(surface)")
        }
        XCTAssertTrue(shown.needsBadge, "a row that drops the words must draw the badge")
        let known = ContactTrust.display(userId: "u-k", claimedName: "x", book: ["u-k": Contact(name: "kim", level: .known)])
        XCTAssertEqual(known.label(for: .notification), "kim")
        XCTAssertFalse(known.needsBadge)
        // A chip keeps words only for flagged names.
        XCTAssertNil(shown.chipWords)
        XCTAssertEqual(ContactTrust.display(userId: "u-c", claimedName: "carol", book: [:], lookup: nil).chipWords, "unconfirmed")
    }

    /// A read of the core's state never creates or raises a pinned name; un-verifying falls back
    /// to KNOWN only for someone the user made known themself.
    func testAStatusReadNeverRaisesTrust() {
        XCTAssertNil(ContactTrust.afterStatusRead(nil, verified: true))
        XCTAssertNil(ContactTrust.afterStatusRead(Contact(name: "a", level: .unverified), verified: true))
        XCTAssertNil(ContactTrust.afterStatusRead(Contact(name: "a", level: .known), verified: true))
        XCTAssertEqual(ContactTrust.afterStatusRead(Contact(name: "a", level: .verified, known: true), verified: false)?.level, .known)
        XCTAssertEqual(ContactTrust.afterStatusRead(Contact(name: "a", level: .verified, known: false), verified: false)?.level, .unverified)
        // Verified straight from unverified (never made known): un-verify returns to UNVERIFIED.
        let v = ContactTrust.withVerification(Contact(name: "a", level: .unverified), name: "a", verified: true)!
        XCTAssertEqual(ContactTrust.withVerification(v, name: "a", verified: false)?.level, .unverified)
        let k = ContactTrust.withVerification(ContactTrust.merged(existing: nil, name: "b", level: .known), name: "b", verified: true)!
        XCTAssertEqual(ContactTrust.withVerification(k, name: "b", verified: false)?.level, .known)
        XCTAssertFalse(ContactTrust.mayPinOnVerify(.impersonation))
        XCTAssertFalse(ContactTrust.mayPinOnVerify(.unconfirmed))
        XCTAssertTrue(ContactTrust.mayPinOnVerify(.unverified))
    }

    /// The raise path has a registry: every call of `noteVerification` that can raise trust
    /// (anything but a literal `verified: false`) is in one of the listed places — the explicit
    /// verify in the safety-number screen, and the sibling merge (both gated in the store).
    func testOnlyTheListedCallersCanRaiseTrust() throws {
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Sources")
        let files = try FileManager.default.contentsOfDirectory(at: sources, includingPropertiesForKeys: nil).filter { $0.pathExtension == "swift" }
        var raisers: [String] = []
        for f in files {
            let lines = try String(contentsOf: f, encoding: .utf8).components(separatedBy: "\n")
            for line in lines where line.contains("noteVerification(") && !line.contains("func noteVerification") && !line.trimmingCharacters(in: .whitespaces).hasPrefix("//") && !line.trimmingCharacters(in: .whitespaces).hasPrefix("///") {
                if !line.contains("verified: false") { raisers.append(f.lastPathComponent) }
            }
        }
        XCTAssertEqual(Set(raisers), ["SafetyNumberView.swift", "SiblingSync.swift"], "a new caller can raise trust: route it through the explicit verify")
        XCTAssertEqual(raisers.filter { $0 == "SafetyNumberView.swift" }.count, 1, "only reconcile(after: .verified) raises")
    }

    func testAMentionOfMeShowsMyOwnNameWithNoMarker() {
        let other: (String) -> ContactTrust.Display = { ContactTrust.display(userId: $0, claimedName: nil, book: [:]) }
        let me = ContactTrust.mentionDisplay(userId: "u-me", me: "u-me", myName: "owner49", other: other)
        XCTAssertEqual(me.label(for: .mentionChip), "owner49")
        XCTAssertEqual(me.badge, .none)
        XCTAssertNil(me.chipWords)
        XCTAssertEqual(ContactTrust.mentionDisplay(userId: "u-me", me: "u-me", myName: nil, other: other).text, "you")
        XCTAssertEqual(ContactTrust.mentionDisplay(userId: "u-x", me: "u-me", myName: "owner49", other: other).badge, .unconfirmed)
        // The server renames me to a contact the user knows: shown as "you", never as them.
        let book = ["u-alice": Contact(name: "alice", level: .known)]
        XCTAssertEqual(ContactTrust.mentionDisplay(userId: "u-me", me: "u-me", myName: "alice", book: book, other: other).text, "you")
        XCTAssertEqual(ContactTrust.mentionDisplay(userId: "u-me", me: "u-me", myName: "ali\u{200B}ce", other: other).text, "you")
    }
}
