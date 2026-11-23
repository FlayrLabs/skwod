import XCTest

/// The notification extension's "is this row new?" rule (`AnnounceWindow`): by message id and
/// this device's clock — never by a date the server chose (audit L3).
final class AnnounceWindowTests: XCTestCase {
    private let floor: Int64 = 1_000_000
    private let now: Int64 = 2_000_000

    /// One wake, as the extension runs it: which of `rows` are new, and what is remembered.
    private func wake(_ rows: [(id: String, at: Int64)], seen: [String]) -> (fresh: [String], seen: [String]) {
        let known = Set(seen)
        let fresh = rows.filter { AnnounceWindow.isNew(messageId: $0.id, createdAt: $0.at, floor: floor, seen: known) }.map(\.id)
        return (fresh, AnnounceWindow.remembering(page: rows.map(\.id), fresh: fresh, in: seen))
    }

    func testAFarFutureDateDoesNotSuppressLaterBanners() {
        // The host dates one row a century ahead. Build 45 raised its mark to that date.
        let first = wake([("m1", floor + 10), ("evil", 9_999_999_999_999)], seen: [])
        XCTAssertEqual(first.fresh, ["m1", "evil"])
        // A real message afterwards, dated normally, is still new.
        let second = wake([("m1", floor + 10), ("evil", 9_999_999_999_999), ("m2", floor + 20)], seen: first.seen)
        XCTAssertEqual(second.fresh, ["m2"])
        // And the future date wins nothing when one banner is chosen among new rows.
        XCTAssertEqual(AnnounceWindow.rank(createdAt: 9_999_999_999_999, now: now), now)
        XCTAssertEqual(AnnounceWindow.rank(createdAt: floor + 20, now: now), floor + 20)
    }

    func testARowServedAgainUnderANewDateIsNotNewAgain() {
        // An old row (from before the app was closed) and a new one.
        let first = wake([("old", floor - 500), ("m1", floor + 10)], seen: [])
        XCTAssertEqual(first.fresh, ["m1"])
        // The host re-dates both to "just now": neither is announced again — the old one was
        // in the page the first wake fetched, the new one was scanned.
        let second = wake([("old", now - 1), ("m1", now - 1)], seen: first.seen)
        XCTAssertTrue(second.fresh.isEmpty)
    }

    func testRowsAtOrBeforeTheDeviceFloorAreNeverNew() {
        XCTAssertFalse(AnnounceWindow.isNew(messageId: "a", createdAt: floor, floor: floor, seen: []))
        XCTAssertFalse(AnnounceWindow.isNew(messageId: "", createdAt: floor + 1, floor: floor, seen: []))
        XCTAssertTrue(AnnounceWindow.isNew(messageId: "a", createdAt: floor + 1, floor: floor, seen: []))
    }

    func testWhatIsRememberedIsBoundedKeepsTheNewestAndNeverRepeats() {
        var seen = AnnounceWindow.remembering(page: ["a", "b", "a", ""], fresh: ["b"], in: ["a"])
        XCTAssertEqual(seen, ["a", "b"])
        // Only the tail of a long page is kept, plus every new row wherever it sits.
        seen = AnnounceWindow.remembering(page: (0..<10).map { "p\($0)" }, fresh: ["p0"], in: [], limit: 100, tail: 3)
        XCTAssertEqual(seen, ["p0", "p7", "p8", "p9"])
        seen = AnnounceWindow.remembering(page: (0..<10).map { "q\($0)" }, fresh: [], in: seen, limit: 5, tail: 10)
        XCTAssertEqual(seen, ["q5", "q6", "q7", "q8", "q9"])
    }
}
