import Foundation

/// One skwod must appear ONCE per account. Foundation only (the logic tests compile it); it works
/// on plain facts about stored workspaces, not on `Workspace` itself.
///
/// Two stored entries are the same skwod only on PROVEN identity: the same p2p host key (the
/// transport authenticates it), or — for classic servers — the same stored https address (the
/// one TLS name the user gave). An instance id or a pinned key is what the server SAID when it was
/// first pinned, which a hostile server can copy from another skwod: it never merges or removes
/// anything. Different accounts on one skwod are kept apart on purpose (own keys and cache).
///
/// Nothing is ever deleted automatically: at launch only a signed-out record whose HOST KEY
/// equals a signed-in one's leaves the list (its files stay). Everything else that looks
/// duplicated is only marked, and the rail offers "Remove this duplicate".
enum WorkspaceDedupe {
    struct Entry: Equatable {
        var id: String
        var userId: String
        var server: String
        var nodeId: String?
        var instanceId: String?
        var pinnedKey: String?
        var signedOut: Bool
        var tokenIssuedAt: Int64?
    }

    static func sameSkwod(_ a: Entry, _ b: Entry) -> Bool {
        if let n = a.nodeId, let m = b.nodeId { return n == m }
        // One p2p, one not: not provably the same (the https copy would have to prove the key).
        if a.nodeId != nil || b.nodeId != nil { return false }
        return a.server == b.server
    }

    /// Same skwod AND same account: one of them is a duplicate.
    static func duplicates(_ a: Entry, _ b: Entry) -> Bool {
        a.id != b.id && a.userId == b.userId && sameSkwod(a, b)
    }

    /// The ids of entries that may be dropped at launch: a signed-out copy of a skwod+account
    /// that ALSO has a signed-in entry. The signed-in one (and every file of both) stays; only the
    /// dead record leaves the list. When every copy is signed in, or every copy is signed out,
    /// nothing is dropped automatically (the rail offers "Remove this duplicate" instead).
    static func droppableAtLaunch(_ entries: [Entry]) -> Set<String> {
        var drop: Set<String> = []
        for e in entries where e.signedOut && e.nodeId != nil {
            if entries.contains(where: { !$0.signedOut && $0.nodeId == e.nodeId && duplicates($0, e) }) { drop.insert(e.id) }
        }
        return drop
    }

    /// The ids of every entry that has a duplicate in `entries` (for the rail's menu).
    static func duplicated(_ entries: [Entry]) -> Set<String> {
        var out: Set<String> = []
        for (i, a) in entries.enumerated() {
            for b in entries[(i + 1)...] where duplicates(a, b) { out.insert(a.id); out.insert(b.id) }
        }
        return out
    }
}

/// The name a skwod entry shows. A name LEARNED from the skwod (its first server's name, which
/// any member who can rename that server controls) is only a label: it is cleaned, capped,
/// refused when it looks like another entry's name or a reserved label, and never replaces a
/// name the user set. The host key's short form is always shown beside it (`identityCue`).
enum SkwodNameRule {
    static let maxLength = 32
    static let reserved = ["skwod", "my skwod", "this mac", "home", "direct messages", "feed"]

    /// The cleaned name, or nil when it must not be used.
    ///
    /// THE rule for a name a HOST supplies — identical to Android's `SkwodName.hostName` /
    /// `accepted`, with the vectors in `apps/shared-test-vectors/skwod-names.json`: runs of
    /// spaces become one space and the ends are trimmed (tabs and newlines are refused); every character must be allowed
    /// (`HostNameChars.units`); at most `maxLength` units (an ASCII character or one whole emoji
    /// sequence); never address-like, reserved or a look-alike of another entry's name. Anything
    /// else is refused and the entry keeps its default name beside its host key.
    static func acceptLearned(_ raw: String, otherNames: [String]) -> String? {
        let spaced = collapseSpaces(raw)
        guard !spaced.isEmpty, spaced.unicodeScalars.count <= HostNameChars.maxScalars,
              let units = HostNameChars.units(spaced) else { return nil }
        let cleaned = trimSpaces(units.prefix(maxLength).joined())
        guard !cleaned.isEmpty else { return nil }
        // Nothing that looks like an address, folded or as a skeleton.
        if WaitingTrust.normalize(cleaned).contains(where: { ".:/\\@".contains($0) })
            || WaitingTrust.skeleton(cleaned).contains(where: { ".:/\\@".contains($0) }) { return nil }
        let shape = WaitingTrust.skeleton(cleaned)
        if reserved.contains(where: { WaitingTrust.skeleton($0) == shape }) { return nil }
        if otherNames.contains(where: { WaitingTrust.skeleton($0) == shape }) { return nil }
        return cleaned
    }

    /// Runs of spaces become one space; the ends are trimmed. Nothing else is treated as space
    /// (a tab, newline or no-break space is then refused by the rule).
    static func collapseSpaces(_ raw: String) -> String {
        var out = String.UnicodeScalarView()
        var pendingSpace = false
        for u in raw.unicodeScalars {
            if u == " " { pendingSpace = true; continue }
            if pendingSpace, !out.isEmpty { out.append(" ") }
            pendingSpace = false
            out.append(u)
        }
        return String(out)
    }

    private static func trimSpaces(_ s: String) -> String {
        var scalars = Array(s.unicodeScalars)
        while scalars.first == " " { scalars.removeFirst() }
        while scalars.last == " " { scalars.removeLast() }
        return String(String.UnicodeScalarView(scalars))
    }
}

/// The characters a host-supplied skwod name may use — one explicit table, the same as Android's
/// `HostNameChars` (never the OS's Unicode properties, which differ by OS version).
enum HostNameChars {
    private static let zwj: UInt32 = 0x200D
    private static let vs16: UInt32 = 0xFE0F
    /// Most pictographs one ZWJ sequence may join (a family of four).
    static let maxJoined = 4
    /// Most Unicode scalars a host-supplied name may have before it is capped (a sequence is one
    /// unit of the 32, so this bounds its real size).
    static let maxScalars = 128

    /// Unicode Extended_Pictographic (emoji-data 15.1), without skin tones or regional indicators.
    private static let pictographic: [ClosedRange<UInt32>] = [
        0x00A9...0x00A9, 0x00AE...0x00AE, 0x203C...0x203C, 0x2049...0x2049, 0x2122...0x2122, 0x2139...0x2139,
        0x2194...0x2199, 0x21A9...0x21AA, 0x231A...0x231B, 0x2328...0x2328, 0x2388...0x2388, 0x23CF...0x23CF,
        0x23E9...0x23F3, 0x23F8...0x23FA, 0x24C2...0x24C2, 0x25AA...0x25AB, 0x25B6...0x25B6, 0x25C0...0x25C0,
        0x25FB...0x25FE, 0x2600...0x2605, 0x2607...0x2612, 0x2614...0x2685, 0x2690...0x2705, 0x2708...0x2712,
        0x2714...0x2714, 0x2716...0x2716, 0x271D...0x271D, 0x2721...0x2721, 0x2728...0x2728, 0x2733...0x2734,
        0x2744...0x2744, 0x2747...0x2747, 0x274C...0x274C, 0x274E...0x274E, 0x2753...0x2755, 0x2757...0x2757,
        0x2763...0x2767, 0x2795...0x2797, 0x27A1...0x27A1, 0x27B0...0x27B0, 0x27BF...0x27BF, 0x2934...0x2935,
        0x2B05...0x2B07, 0x2B1B...0x2B1C, 0x2B50...0x2B50, 0x2B55...0x2B55, 0x3030...0x3030, 0x303D...0x303D,
        0x3297...0x3297, 0x3299...0x3299,
        0x1F000...0x1F0FF, 0x1F10D...0x1F10F, 0x1F12F...0x1F12F, 0x1F16C...0x1F171, 0x1F17E...0x1F17F,
        0x1F18E...0x1F18E, 0x1F191...0x1F19A, 0x1F1AD...0x1F1E5, 0x1F201...0x1F20F, 0x1F21A...0x1F21A,
        0x1F22F...0x1F22F, 0x1F232...0x1F23A, 0x1F23C...0x1F23F, 0x1F249...0x1F3FA, 0x1F400...0x1F53D,
        0x1F546...0x1F64F, 0x1F680...0x1F6FF, 0x1F774...0x1F77F, 0x1F7D5...0x1F7FF, 0x1F80C...0x1F80F,
        0x1F848...0x1F84F, 0x1F85A...0x1F85F, 0x1F888...0x1F88F, 0x1F8AE...0x1F8FF, 0x1F90C...0x1F93A,
        0x1F93C...0x1F945, 0x1F947...0x1FAFF, 0x1FC00...0x1FFFD,
    ]

    /// Extended_Pictographic code points that read as letters, punctuation, arrows or plain
    /// shapes rather than pictures: (c) (R) TM !! !? (i), arrows, the circled M, small squares and
    /// triangles, the wavy dash, part-alternation mark and the circled ideographs. Refused.
    private static let symbolLike: [ClosedRange<UInt32>] = [
        0x00A9...0x00A9, 0x00AE...0x00AE, 0x203C...0x203C, 0x2049...0x2049, 0x2122...0x2122, 0x2139...0x2139,
        0x2194...0x2199, 0x21A9...0x21AA, 0x24C2...0x24C2, 0x25AA...0x25AB, 0x25B6...0x25B6, 0x25C0...0x25C0,
        0x25FB...0x25FE, 0x27A1...0x27A1, 0x2934...0x2935, 0x2B05...0x2B07, 0x3030...0x3030, 0x303D...0x303D,
        0x3297...0x3297, 0x3299...0x3299,
    ]

    static func isPictograph(_ v: UInt32) -> Bool {
        pictographic.contains { $0.contains(v) } && !symbolLike.contains { $0.contains(v) }
    }
    static func isSkinTone(_ v: UInt32) -> Bool { (0x1F3FB...0x1F3FF).contains(v) }
    static func isRegionalIndicator(_ v: UInt32) -> Bool { (0x1F1E6...0x1F1FF).contains(v) }
    private static func isAsciiAllowed(_ v: UInt32) -> Bool {
        (0x61...0x7A).contains(v) || (0x41...0x5A).contains(v) || (0x30...0x39).contains(v)
            || [0x20, 0x2D, 0x5F, 0x27, 0x26].contains(v)   // space - _ ' &
    }

    /// `s` split into units — one ASCII character, one flag (a regional-indicator PAIR) or one
    /// emoji sequence: a pictograph with an optional skin tone or VS16, joined by ZWJ only to
    /// another such pictograph — or nil when anything else appears (a lone skin tone, VS16 or
    /// ZWJ, an odd regional indicator, a keycap, tag characters, another script, a mark, ...).
    static func units(_ s: String) -> [String]? {
        let u = Array(s.unicodeScalars)
        var out: [String] = []
        var i = 0
        func piece(_ a: Int, _ b: Int) -> String { String(String.UnicodeScalarView(u[a..<b])) }
        func modifier(_ j: Int) -> Bool { j < u.count && (isSkinTone(u[j].value) || u[j].value == vs16) }
        while i < u.count {
            let c = u[i].value
            if isAsciiAllowed(c) {
                out.append(piece(i, i + 1)); i += 1
            } else if isRegionalIndicator(c) {
                guard i + 1 < u.count, isRegionalIndicator(u[i + 1].value) else { return nil }
                out.append(piece(i, i + 2)); i += 2
            } else if isPictograph(c) {
                var j = i + 1
                var pictographs = 1
                if modifier(j) { j += 1 }
                while j + 1 < u.count, u[j].value == zwj, isPictograph(u[j + 1].value) {
                    // At most `maxJoined` pictographs in one sequence: a longer chain is refused.
                    pictographs += 1
                    guard pictographs <= maxJoined else { return nil }
                    j += 2
                    if modifier(j) { j += 1 }
                }
                out.append(piece(i, j)); i = j
            } else {
                return nil
            }
        }
        return out
    }
}

extension SkwodNameRule {
    /// One entry's name and where it came from.
    struct Named: Equatable {
        enum Source: Equatable { case address, user, host, learned }
        var id: String
        var name: String
        var source: Source
    }

    /// Re-checked on every load, save and add (a name accepted earlier may clash with an entry
    /// added since): the ids whose host-supplied / learned name must go back to the address
    /// name. Address-based and user-set names always win a clash; between two host names the
    /// earlier entry keeps its name.
    static func revalidate(_ entries: [Named]) -> Set<String> {
        var reset: Set<String> = []
        var kept: [Named] = entries.filter { $0.source == .address || $0.source == .user }
        for e in entries where e.source == .host || e.source == .learned {
            let others = kept.filter { $0.id != e.id }.map(\.name)
            if acceptLearned(e.name, otherNames: others) == e.name { kept.append(e) } else { reset.insert(e.id) }
        }
        return reset
    }
}
