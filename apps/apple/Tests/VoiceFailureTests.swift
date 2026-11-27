import XCTest

/// Build 51: what joining a call says when it fails — one table for both apps.
final class VoiceFailureTests: XCTestCase {
    private func table() throws -> [String: Any] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../shared-test-vectors/voice-failures.json").standardizedFileURL
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    func testEveryFailureHasItsOneSentenceAndNoneBlamesAVPN() throws {
        let messages = try XCTUnwrap(try table()["messages"] as? [String: String])
        XCTAssertEqual(Set(messages.keys), Set(VoiceFailure.allCases.map(\.rawValue)))
        for failure in VoiceFailure.allCases {
            XCTAssertEqual(failure.message, messages[failure.rawValue])
            XCTAssertFalse(failure.message.contains("VPN"))
        }
        XCTAssertEqual(Set(try XCTUnwrap(try table()["retry_once"] as? [String])),
                       Set(VoiceFailure.allCases.filter(\.retriesOnce).map(\.rawValue)))
    }

    /// The server's 503 (`voice_off` / `voice_starting`) reaches here as the core's code.
    func testTheCoresCodes() throws {
        for c in try XCTUnwrap(try table()["codes"] as? [[String: String]]) {
            XCTAssertEqual(VoiceFailure(code: c["code"]!).rawValue, c["expect"], c["code"]!)
        }
    }

    func testAMediaFailureIsPlacedByTheTunnelsCounters() throws {
        func counters(_ v: Any?) -> VoiceFailure.Counters? {
            (v as? [Int]).map { .init(accepted: UInt64($0[0]), up: UInt64($0[1]), down: UInt64($0[2]), undelivered: UInt64($0[3])) }
        }
        for c in try XCTUnwrap(try table()["media"] as? [[String: Any]]) {
            XCTAssertEqual(VoiceFailure.media(before: counters(c["before"]), after: counters(c["after"])).rawValue,
                           c["expect"] as? String, c["why"] as? String ?? "")
        }
    }

    func testTheVoiceRowNeverOffersTheSetupPanelOnASkwodWithItsOwnCallServer() throws {
        let cases = try XCTUnwrap(try table()["gate"] as? [[String: Any]])
        for c in cases {
            let gate = VoiceGate.decide(configured: c["configured"] as! Bool, status: c["status"] as! String,
                                        bundled: c["bundled"] as! Bool, owner: c["owner"] as! Bool)
            switch c["expect"] as! String {
            case "join": XCTAssertEqual(gate, .join)
            case "set_up": XCTAssertEqual(gate, .setUp)
            case "not_set_up": XCTAssertEqual(gate, .say(VoiceGate.notSetUp))
            case let code: XCTAssertEqual(gate, .say(VoiceFailure(code: code).message))
            }
            if c["bundled"] as! Bool { XCTAssertNotEqual(gate, .setUp) }
        }
    }
}
