import Foundation

/// What both devices say while one pairs by QR (build 48). Foundation only (logic-tested).
///
/// Anyone can print a QR. So a scanned one is never a reason to type a password (pairing needs
/// none), and nothing claims the code came from "your other device" — the new device names the
/// host by its key (or by a name this device already knows it by) and asks before it dials, and
/// the person picks the matching emoji on the device they already use.
enum PairingCopy {
    /// "A new Skwod · moesz7…xbmo · @alice" — what the QR names, nothing more.
    static func header(shortKey: String, username: String, known: Bool) -> String {
        "\(known ? "A Skwod you use" : "A new Skwod") · \(shortKey) · @\(username)"
    }

    /// Asked before the new device dials anything. `knownName` comes only from a workspace this
    /// device already has for that host — never from the QR or the host itself.
    static func joinPrompt(knownName: String?, shortKey: String, username: String) -> String {
        let name = knownName.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.flatMap { $0.isEmpty ? nil : $0 }
        return "Join \(name ?? shortKey) as @\(username)?"
    }

    static let joinDetail = "Continue only if you just scanned this on a device of yours. Anyone can print a QR code, and one from someone else would add this device to their account instead."

    static let waitingForOther = "Waiting for your other device to see this one…"

    static func confirmInstruction() -> String {
        "On the device you already use, pick the set that matches these five. If none of them match, choose “None of these” there."
    }

    /// Shown once approved, before this device enters the account.
    static func approved(shortKey: String) -> String {
        "Approved on your other device · \(shortKey)"
    }

    static let notApproved = "This device wasn't added: it was denied on your other device, or the code expired. Make a new code there to try again."

    /// The app was sent away while pairing.
    static let left = "Pairing stopped because you left Skwod. Make a new code on your other device and keep Skwod open until it says you're approved."

    static let mismatch = "This device wasn't added: the code didn't check out, so someone may have tampered with it. Make a new code on your other device."

    /// What to show when pairing stops with `detail` (the core's error text): a refusal, an expiry
    /// or a failed check reads as such, and nothing reads as a raw protocol message.
    static func failure(detail: String) -> String {
        let d = detail.lowercased()
        if d.contains("did not match") { return mismatch }
        if d.contains("not approved") || d.contains("expired") { return notApproved }
        if d.hasPrefix("protocol error:") {
            let rest = detail.dropFirst("protocol error:".count).trimmingCharacters(in: .whitespaces)
            return rest.prefix(1).uppercased() + rest.dropFirst()
        }
        return detail
    }

    // MARK: the device that shows the QR

    static let pickTitle = "Which set does the new device show?"
    static let pickHint = "Pick the five emoji on the device in your hand. Picking a set it doesn't show refuses it. It will be able to read your new messages."
    static let noneOfThese = "None of these"

    /// Seconds left before an offer made at `expiresAt` (unix seconds) is void.
    static func secondsLeft(expiresAt: UInt64, now: Date = Date()) -> Int {
        max(0, Int(expiresAt) - Int(now.timeIntervalSince1970))
    }
}
