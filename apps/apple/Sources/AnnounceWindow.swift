import Foundation

/// Which rows a push wake treats as NEW — decided by message id, not by the server's clock.
///
/// Build 44/45 kept a "high-water mark": the `created_at` of the newest row a wake announced,
/// and nothing at or below it was looked at again. `created_at` of a channel row is whatever
/// the SERVER says, so a host could announce one row dated far in the future and silence every
/// later banner, or serve an old row under a new date and have it announced again.
///
/// Now:
/// - the floor is only ever this DEVICE's clock, taken when the app went to the background
///   (`NotificationState.setHighWater`, called by the app alone). The extension never moves it,
///   so nothing a server sends can raise it;
/// - what a wake has looked at is remembered by ID (`seen`): every row a wake scanned, and the
///   tail of each conversation it fetched, is never "new" again — whatever date it is served
///   under next time;
/// - a row's date is used for one thing only, choosing which of several new rows is shown, and
///   there it is capped at the device's own "now" so a future date wins nothing.
///
/// What is left: a row older than anything a wake ever fetched AND older than the ledger, that
/// a host serves again under a fresh date, is shown once more (it is authentic — the id is
/// sealed inside the ciphertext — and then it is remembered too). Foundation only; tested as
/// shipped (`AnnounceWindowTests`).
enum AnnounceWindow {
    /// Ids kept per skwod. A wake adds at most `tail` per conversation plus its new rows.
    static let limit = 2000
    /// How much of the end of each fetched conversation is remembered besides its new rows.
    static let tail = 60

    /// May this row be announced by this wake (before the per-conversation rules)?
    /// `floor`: the device-clock mark the app left (0 = never). `seen`: ids earlier wakes scanned.
    static func isNew(messageId: String, createdAt: Int64, floor: Int64, seen: Set<String>) -> Bool {
        !messageId.isEmpty && createdAt > floor && !seen.contains(messageId)
    }

    /// The order new rows compete in for the one banner: their date, but never later than now.
    static func rank(createdAt: Int64, now: Int64) -> Int64 { min(createdAt, now) }

    /// `seen` after a wake looked at one conversation: `page` is everything fetched (oldest
    /// first), `fresh` the ids it treated as new. Newest last, no repeats, cut to `limit`.
    static func remembering(page: [String], fresh: [String], in seen: [String], limit: Int = AnnounceWindow.limit, tail: Int = AnnounceWindow.tail) -> [String] {
        var known = Set(seen)
        var out = seen
        for id in fresh + page.suffix(tail) where !id.isEmpty && known.insert(id).inserted { out.append(id) }
        return out.count > limit ? Array(out.suffix(limit)) : out
    }
}
