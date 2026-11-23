import CryptoKit
import XCTest

/// Audit (release M1/M2): the iOS "update" banner — build number, text and above all the
/// TestFlight link — comes only from a statement the publisher signed.
final class UpdateManifestTests: XCTestCase {
    private let key = Curve25519.Signing.PrivateKey()
    private var pub: String { key.publicKey.rawRepresentation.base64EncodedString() }
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let link = "https://testflight.apple.com/join/AbCd1234"

    private func statement(build: Int = 46, link: String? = nil, issued: Int = 1_800_000_000, expires: Int = 1_810_368_000, v: Int = 1) -> Data {
        let s: [String: Any] = ["v": v, "issued": issued, "expires": expires,
                                "ios": ["build": build, "version": "0.1.0", "notes": "hi", "testflight": link ?? self.link]]
        return try! JSONSerialization.data(withJSONObject: s, options: [.sortedKeys])
    }

    private func manifest(_ statement: Data, signer: Curve25519.Signing.PrivateKey? = nil, labelled: Bool = true, legacyLink: String? = nil) -> Data {
        let message = (labelled ? Data(UpdateManifest.label.utf8) : Data()) + statement
        let sig = try! (signer ?? key).signature(for: message)
        let m: [String: Any] = ["ios": ["build": 9999, "version": "9", "testflight": legacyLink ?? "https://testflight.apple.com/join/EVIL"],
                                "signed": statement.base64EncodedString(), "signed_sig": sig.base64EncodedString()]
        return try! JSONSerialization.data(withJSONObject: m)
    }

    func testASignedStatementIsRead() {
        guard case .valid(let ios?, let expired) = UpdateManifest.read(manifest(statement()), publisherKeyB64: pub, now: now) else { return XCTFail() }
        XCTAssertFalse(expired)
        XCTAssertEqual(ios.build, 46)                       // not the unsigned 9999
        XCTAssertEqual(ios.link?.absoluteString, link)      // not the unsigned …/EVIL
        XCTAssertEqual(ios.notes, "hi")
    }

    func testUnsignedOrForgedManifestsOfferNothing() {
        let unsigned = Data(#"{"ios":{"build":9999,"version":"9","testflight":"https://testflight.apple.com/join/EVIL"}}"#.utf8)
        XCTAssertEqual(UpdateManifest.read(unsigned, publisherKeyB64: pub, now: now), .invalid)
        let other = Curve25519.Signing.PrivateKey()
        XCTAssertEqual(UpdateManifest.read(manifest(statement(), signer: other), publisherKeyB64: pub, now: now), .invalid)
        // A throwaway key is not the pinned production key.
        XCTAssertEqual(UpdateManifest.read(manifest(statement()), now: now), .invalid)
        // Signed without the label: some other signature by the same key, not a manifest.
        XCTAssertEqual(UpdateManifest.read(manifest(statement(), labelled: false), publisherKeyB64: pub, now: now), .invalid)
        // The statement swapped after signing.
        var m = try! JSONSerialization.jsonObject(with: manifest(statement())) as! [String: Any]
        m["signed"] = statement(link: "https://testflight.apple.com/join/EVIL").base64EncodedString()
        XCTAssertEqual(UpdateManifest.read(try! JSONSerialization.data(withJSONObject: m), publisherKeyB64: pub, now: now), .invalid)
        XCTAssertEqual(UpdateManifest.read(Data("not json".utf8), publisherKeyB64: pub, now: now), .invalid)
    }

    func testOnlyApplesHostsAreEverALink() {
        for bad in ["http://testflight.apple.com/join/x", "https://testflight.apple.com.evil.example/join/x",
                    "https://evil.example/testflight.apple.com", "https://user@testflight.apple.com/join/x",
                    "https://testflight.apple.com:8443/join/x", "skwod://join", ""] {
            XCTAssertNil(UpdateManifest.appleLink(bad), bad)
            // Even when the publisher signed it.
            guard case .valid(let ios?, _) = UpdateManifest.read(manifest(statement(link: bad)), publisherKeyB64: pub, now: now) else { return XCTFail(bad) }
            XCTAssertNil(ios.link, bad)
        }
        XCTAssertNotNil(UpdateManifest.appleLink("https://apps.apple.com/app/id123"))
        XCTAssertNotNil(UpdateManifest.appleLink("https://TestFlight.apple.com/join/x"))
    }

    func testExpiryAndPostDating() {
        let later = Date(timeIntervalSince1970: 1_810_368_000)
        guard case .valid(let ios?, let expired) = UpdateManifest.read(manifest(statement()), publisherKeyB64: pub, now: later) else { return XCTFail() }
        XCTAssertTrue(expired); XCTAssertTrue(ios.expired)
        XCTAssertEqual(UpdateManifest.read(manifest(statement(issued: 1_800_000_000 + 2 * 86400)), publisherKeyB64: pub, now: now), .invalid)
        XCTAssertNotEqual(UpdateManifest.read(manifest(statement(issued: 1_800_000_000 + 3600)), publisherKeyB64: pub, now: now), .invalid)
        XCTAssertEqual(UpdateManifest.read(manifest(statement(expires: 1_800_000_000)), publisherKeyB64: pub, now: now), .invalid)
        XCTAssertEqual(UpdateManifest.read(manifest(statement(v: 2)), publisherKeyB64: pub, now: now), .invalid)
    }

    /// The fixture `tools/release/sign-manifest.sh` wrote with a throwaway key: the script, the
    /// Android updater and this code agree on the bytes.
    func testTheScriptsFixtureVerifies() throws {
        var dir = URL(fileURLWithPath: #filePath)
        var fixtures: URL?
        for _ in 0..<8 {
            dir.deleteLastPathComponent()
            let candidate = dir.appendingPathComponent("tools/release/fixtures")
            if FileManager.default.fileExists(atPath: candidate.path) { fixtures = candidate; break }
        }
        let found = try XCTUnwrap(fixtures, "tools/release/fixtures not found")
        let body = try Data(contentsOf: found.appendingPathComponent("manifest-v1.json"))
        let fixturePub = try String(contentsOf: found.appendingPathComponent("manifest-v1.pub"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        guard case .valid(let ios?, false) = UpdateManifest.read(body, publisherKeyB64: fixturePub, now: Date(timeIntervalSince1970: 1_800_000_060)) else { return XCTFail() }
        XCTAssertEqual(ios.build, 46)
        XCTAssertEqual(ios.link?.absoluteString, link)
        XCTAssertEqual(ios.notes, "Fixes \"things\" & more.")
    }
}
