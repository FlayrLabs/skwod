import Foundation

/// What the log-in / create-account form accepts, before anything goes near the network
/// (Foundation only, so the logic tests compile it as is).
///
/// - **Log in** (an existing account, e.g. on a second device) needs only WHERE the skwod is:
///   an invite link with or without its code, a `skwod://join/` link, the bare 52-character host
///   key, an `https://` address, or a skwod this device already knows. A code in the link is
///   simply not used.
/// - **Create account** is the only mode that needs the invite's code.
enum LoginEntry {
    enum Mode: Equatable { case logIn, createAccount }

    /// The host key alphabet: z-base-32 (`core/skwod-net/src/invite.rs`, iroh `to_z32`).
    static let z32Alphabet = Set("ybndrfg8ejkmcpqxot1uwisza345h769")

    /// True for a bare host key: 52 characters of z-base-32, or the 64-character hex form iroh
    /// prints in logs.
    static func isBareNodeId(_ text: String) -> Bool {
        let t = text.lowercased()
        if t.count == 52 { return t.allSatisfy { z32Alphabet.contains($0) } }
        if t.count == 64 { return t.allSatisfy { $0.isHexDigit } }
        return false
    }

    /// The entry in a shape `InviteLink.parse` takes: a bare host key (optionally followed by
    /// `#code` or `.code`) becomes `skwod://join/<key>[#code]`; anything else is returned trimmed
    /// and otherwise unchanged (the parser decides whether it is valid).
    static func canonical(_ raw: String) -> String {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let head: Substring
        let code: Substring?
        if let i = text.firstIndex(where: { $0 == "#" || $0 == "." }) {
            head = text[..<i]; code = text[text.index(after: i)...]
        } else {
            head = Substring(text); code = nil
        }
        guard isBareNodeId(String(head)) else { return text }
        var out = "skwod://join/" + head.lowercased()
        if let code, !code.isEmpty { out += "#" + code }
        return out
    }

    /// The join code the form will SEND for `mode`, given the code the entry carried: none when
    /// logging in (an existing account never needs one), the normalised code when creating an
    /// account. nil for create-account means "ask for a code".
    static func codeToSend(_ carried: String?, mode: Mode) -> String? {
        guard mode == .createAccount, let carried else { return nil }
        let code = JoinCode.normalize(carried)
        return code.isEmpty ? nil : code
    }

    /// Which mode a link that ARRIVED (paste, scan, tap) should put the form in. A link with a
    /// code suggests a new member — unless the user had already chosen "Log in", which a paste
    /// must never undo (that is how a second device ended up on "Create account").
    static func modeAfterAdopting(hasCode: Bool, userChoseLogIn: Bool) -> Mode {
        if userChoseLogIn { return .logIn }
        return hasCode ? .createAccount : .logIn
    }
}

/// Join codes as people type them: `SKWD-AB12-CD34` (a host's setup / friend code) or eight
/// characters (`AB12CD34`, an invite made in the app). Typed in lower case, with spaces, with or
/// without dashes, pasted with a trailing newline — all the same code.
enum JoinCode {
    static func normalize(_ raw: String) -> String {
        // Keep what a code can contain; spaces, newlines, dots and the rest are dropped.
        let kept = raw.uppercased().unicodeScalars.filter {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_")
        }
        let s = String(String.UnicodeScalarView(kept))
        let bare = s.replacingOccurrences(of: "-", with: "")
        // Nothing but dashes / separators: no code at all.
        if bare.replacingOccurrences(of: "_", with: "").isEmpty { return "" }
        // The setup-code shape: SKWD + 8 → SKWD-XXXX-XXXX whatever dashes were typed.
        if bare.hasPrefix("SKWD"), bare.count == 12, !bare.contains("_") {
            let body = Array(bare.dropFirst(4))
            return "SKWD-" + String(body[0..<4]) + "-" + String(body[4..<8])
        }
        // An eight-character app invite: dashes typed for readability go.
        if bare.count == 8, !bare.contains("_") { return bare }
        return s
    }
}
