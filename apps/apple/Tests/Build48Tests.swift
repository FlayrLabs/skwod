import XCTest

/// Build 48: a new device must never sit on "Finding your host…" forever, and a share link can
/// carry the host's home relay so the first dial needs no lookup.
final class Build48Tests: XCTestCase {
    // The relay-hint grammar (allow-list, canonical form, round trip in both link forms) is
    // tested in Rust (`skwod-net` invite.rs, `skwod-core` p2p.rs) — this target has no core.

    // MARK: never hang

    func testTheBackstopSitsJustAfterTheCoreBudget() {
        XCTAssertEqual(ConnectDeadline.backstop(coreSeconds: 20), .seconds(25))
    }

    func testDeadlineThrowsInsteadOfWaitingForever() async {
        let started = ContinuousClock.now
        do {
            _ = try await ConnectDeadline.run(.milliseconds(200)) {
                try await Task.sleep(for: .seconds(60))
                return 1
            }
            XCTFail("a stalled connect must time out")
        } catch {
            XCTAssertTrue(error is P2PConnectTimeout)
        }
        XCTAssertLessThan(ContinuousClock.now - started, .seconds(5))
    }

    /// The stalled-core case: a body that ignores cancellation must not hold the caller.
    func testDeadlineReturnsEvenIfTheBodyIgnoresCancellation() async {
        let started = ContinuousClock.now
        do {
            _ = try await ConnectDeadline.run(.milliseconds(200)) { () async throws -> Int in
                // Blocks a thread for 3 s and never checks for cancellation.
                Thread.sleep(forTimeInterval: 3)
                return 1
            }
            XCTFail("expected a timeout")
        } catch {
            XCTAssertTrue(error is P2PConnectTimeout)
        }
        XCTAssertLessThan(ContinuousClock.now - started, .seconds(1))
    }

    func testDeadlinePassesAFastResultThrough() async throws {
        let v = try await ConnectDeadline.run(.seconds(5)) { 42 }
        XCTAssertEqual(v, 42)
    }

    func testTheUnreachableHintNamesWhatToTry() {
        XCTAssertTrue(HostUnreachableHint.tips.contains("Wi-Fi"))
        XCTAssertTrue(HostUnreachableHint.tips.contains("Local Network"))
        XCTAssertTrue(HostUnreachableHint.relaysOff.contains("Relays are off"))
    }

    // MARK: QR pairing must not phish

    /// Anyone can print a QR. What a device pairing by QR says names the host by its key and the
    /// account, never asks for a password, and never claims the code came from "your other device".
    func testPairingCopyNeverAsksForAPasswordAndNamesTheHost() {
        for known in [true, false] {
            let text = PairingCopy.header(shortKey: "moesz7…xbmo", username: "alice", known: known)
            XCTAssertTrue(text.contains("moesz7…xbmo") && text.contains("@alice"), text)
            XCTAssertTrue(text.hasPrefix(known ? "A Skwod you use" : "A new Skwod"), text)
            for line in [text, PairingCopy.confirmInstruction(), PairingCopy.joinDetail, PairingCopy.pickHint, PairingCopy.waitingForOther] {
                XCTAssertFalse(line.lowercased().contains("password"), line)
                XCTAssertFalse(line.lowercased().contains("from your other device"), line)
            }
        }
        let now = Date(timeIntervalSince1970: 1_000)
        XCTAssertEqual(PairingCopy.secondsLeft(expiresAt: 1_300, now: now), 300)
        XCTAssertEqual(PairingCopy.secondsLeft(expiresAt: 900, now: now), 0)
    }

    /// A denied or expired pairing says so in plain words, never as a raw protocol error.
    func testPairingFailureReadsAsDeniedOrExpired() {
        let raw = "protocol error: this pairing was not approved, or it expired; make a new code on your other device"
        XCTAssertEqual(PairingCopy.failure(detail: raw), PairingCopy.notApproved)
        XCTAssertFalse(PairingCopy.failure(detail: raw).contains("protocol"))
        let offline = "Couldn't reach that Skwod. Check your connection and try again."
        XCTAssertEqual(PairingCopy.failure(detail: offline), offline)
    }

    /// M2: before dialling, the new device asks which skwod and account — naming the skwod only
    /// by a workspace it already has, else by the host's key, never by anything in the QR.
    func testTheJoinQuestionNamesTheSkwodOnlyByWhatThisDeviceKnows() {
        XCTAssertEqual(PairingCopy.joinPrompt(knownName: nil, shortKey: "moesz7…xbmo", username: "alice"), "Join moesz7…xbmo as @alice?")
        XCTAssertEqual(PairingCopy.joinPrompt(knownName: "Book club", shortKey: "moesz7…xbmo", username: "alice"), "Join Book club as @alice?")
        XCTAssertEqual(PairingCopy.joinPrompt(knownName: "  ", shortKey: "moesz7…xbmo", username: "alice"), "Join moesz7…xbmo as @alice?")
        XCTAssertTrue(PairingCopy.joinDetail.contains("their account"), "says what a QR from someone else would do")
        // After approval, before entering: whose host this is, by key.
        XCTAssertEqual(PairingCopy.approved(shortKey: "moesz7…xbmo"), "Approved on your other device · moesz7…xbmo")
    }

    /// M1: the device that shows the QR asks the person to pick, among sets, the one on the new
    /// device, and offers a way out that is not a pick.
    func testTheExistingDeviceAsksForAPickNotATap() {
        XCTAssertTrue(PairingCopy.pickTitle.contains("Which set"))
        XCTAssertTrue(PairingCopy.pickHint.contains("refuses"))
        XCTAssertEqual(PairingCopy.noneOfThese, "None of these")
        XCTAssertTrue(PairingCopy.confirmInstruction().contains("five"))
        XCTAssertTrue(PairingCopy.confirmInstruction().contains(PairingCopy.noneOfThese))
    }

    /// A failed check, a refusal and a host setting each read as what they are.
    func testPairingFailuresKeepTheirMeaning() {
        let mismatch = "protocol error: the other device's check did not match this code, so nothing was added; make a new code on your other device"
        XCTAssertEqual(PairingCopy.failure(detail: mismatch), PairingCopy.mismatch)
        let off = "protocol error: this Skwod's host hasn't turned on adding devices by QR"
        XCTAssertEqual(PairingCopy.failure(detail: off), "This Skwod's host hasn't turned on adding devices by QR")
        let denied = "protocol error: this pairing was not approved, or it expired; make a new code on your other device"
        XCTAssertEqual(PairingCopy.failure(detail: denied), PairingCopy.notApproved)
    }
}
