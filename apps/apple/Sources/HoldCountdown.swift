import Foundation

// What a waiting hold says (Foundation only: the logic tests compile this file too).

/// "in 6 days 23 hours" — how long until a hold ends.
enum HoldCountdown {
    static func text(until atMs: Int64, now: Date = Date()) -> String {
        let seconds = Int(Double(atMs) / 1000 - now.timeIntervalSince1970)
        if seconds <= 60 { return "any moment now" }
        let minutes = seconds / 60, hours = minutes / 60, days = hours / 24
        func unit(_ n: Int, _ word: String) -> String { "\(n) \(word)\(n == 1 ? "" : "s")" }
        if days >= 1 {
            let restHours = hours - days * 24
            return "in " + unit(days, "day") + (restHours > 0 ? " " + unit(restHours, "hour") : "")
        }
        if hours >= 1 { return "in " + unit(hours, "hour") }
        return "in " + unit(minutes, "minute")
    }
}

/// The line under the code on "Waiting to restore". A contested request (another install asked
/// to restore the same device) never completes by the hold, so it promises no countdown.
/// `nil`: nothing to add yet (the server has not said when the hold ends).
enum RestoreWaitLine {
    static let contested = "Waiting for approval on one of your devices."

    static func text(completesAt: Int64?, contested: Bool, now: Date = Date()) -> String? {
        if contested { return Self.contested }
        guard let completesAt else { return nil }
        return "Or wait: it completes by itself \(HoldCountdown.text(until: completesAt, now: now))."
    }
}
