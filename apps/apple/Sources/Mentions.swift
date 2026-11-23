import Foundation

/// @mentions (build 46), Foundation only so the logic tests (and the notification extension)
/// compile it.
///
/// **Wire format, end to end.** Who is mentioned travels INSIDE the encrypted message text, so the
/// server never learns it: the visible text, then a trailer — U+2063 (invisible separator)
/// followed by the payload with every ASCII character c written as the Unicode TAG character
/// U+E0000 + c. Tag characters render as nothing everywhere, so an older app shows just the
/// visible text with its plain "@name". Payload: `M1` + compact JSON
/// `{"m":[["<user id>",<start>,<length>],…],"e":true}` (`e` only for @everyone); offsets are
/// UTF-16 code units into the visible text, and each range is a mention token
/// (`MentionCodec.isMentionRange`: "@" and a name of letters, digits, marks and `_ . -`, at most
/// 64 units, after whitespace or punctuation; ranges never overlap or touch).
/// Anything malformed is ignored (the text shows without the trailer). Android writes and reads
/// the same format.
struct MentionPayload: Hashable {
    struct Mention: Hashable {
        var userId: String
        /// UTF-16 range in the visible text.
        var start: Int
        var length: Int
    }
    var mentions: [Mention] = []
    var everyone = false

    var isEmpty: Bool { mentions.isEmpty && !everyone }
}

enum MentionCodec {
    static let separator: Character = "\u{2063}"
    static let maxTrailer = 4096
    static let maxMentions = 50
    private static let tagBase: UInt32 = 0xE0000

    /// The text to send: `visible` plus the trailer (nothing added when there is nothing to say).
    static func encode(_ visible: String, _ payload: MentionPayload) -> String {
        guard !payload.isEmpty else { return visible }
        var obj: [String: Any] = [:]
        if !payload.mentions.isEmpty {
            obj["m"] = payload.mentions.prefix(maxMentions).map { [$0.userId, $0.start, $0.length] as [Any] }
        }
        if payload.everyone { obj["e"] = true }
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
              let json = String(data: data, encoding: .utf8) else { return visible }
        let ascii = "M1" + json
        var trailer = String(separator)
        for scalar in ascii.unicodeScalars where (0x20...0x7E).contains(scalar.value) {
            trailer.unicodeScalars.append(Unicode.Scalar(tagBase + scalar.value)!)
        }
        guard trailer.unicodeScalars.count <= maxTrailer else { return visible }
        return visible + trailer
    }

    /// Split a received text into what to show and who it mentions. Never throws: anything that
    /// is not a valid trailer leaves the text as it came (minus a malformed trailer).
    static func decode(_ text: String) -> (visible: String, payload: MentionPayload) {
        let scalars = Array(text.unicodeScalars)
        guard let sep = scalars.lastIndex(of: "\u{2063}") else { return (text, MentionPayload()) }
        let tail = scalars[(sep + 1)...]
        let visible = String(String.UnicodeScalarView(scalars[..<sep]))
        guard !tail.isEmpty, tail.allSatisfy({ (tagBase + 0x20...tagBase + 0x7E).contains($0.value) }) else {
            return (text, MentionPayload())
        }
        // Ours but oversized: stripped, and nothing in it is read.
        guard tail.count <= maxTrailer else { return (visible, MentionPayload()) }
        let ascii = String(String.UnicodeScalarView(tail.map { Unicode.Scalar($0.value - tagBase)! }))
        guard ascii.hasPrefix("M1"), let data = ascii.dropFirst(2).data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return (visible, MentionPayload())
        }
        let ns = visible as NSString
        var out = MentionPayload()
        if let e = obj["e"] as? NSNumber, isBool(e) { out.everyone = e.boolValue }
        // Every value below is the SENDER's: never added, multiplied or trusted before it is
        // checked (an Int.max start would overflow `start + length` and trap — a remote crash).
        // A list longer than the cap is refused whole, like Android.
        guard let list = obj["m"] as? [Any] ?? (obj["m"] == nil ? [] : nil), list.count <= maxMentions else {
            return (visible, out)
        }
        for case let item as [Any] in list {
            guard item.count == 3, let uid = item[0] as? String, !uid.isEmpty, uid.utf8.count <= 128,
                  let start = exactInt(item[1]), let length = exactInt(item[2]) else { continue }
            out.mentions.append(.init(userId: uid, start: start, length: length))
        }
        // Only what may replace text on screen (`valid`): the shared rule, checked before use.
        out.mentions = valid(out.mentions, in: ns)
        return (visible, out)
    }

    /// The longest mention token, in UTF-16 units ("@" included).
    static let maxRange = 64
    /// The most text all of a message's mentions may cover together.
    static let maxCovered = maxMentions * maxRange

    /// The mentions that may replace text on screen, in order: each one `isMentionRange`, none
    /// overlapping or touching the one before, at most `maxMentions` covering at most
    /// `maxCovered` units. Ties keep the sender's order. Android's `Mentions.valid` is the same.
    static func valid(_ mentions: [MentionPayload.Mention], in ns: NSString) -> [MentionPayload.Mention] {
        var out: [MentionPayload.Mention] = []
        var end = -1
        var covered = 0
        let ordered = mentions.enumerated().sorted { ($0.element.start, $0.offset) < ($1.element.start, $1.offset) }.map(\.element)
        for m in ordered {
            guard !m.userId.isEmpty, isMentionRange(ns, start: m.start, length: m.length),
                  m.start > end, covered + m.length <= maxCovered else { continue }
            out.append(m)
            end = m.start + m.length   // in bounds: cannot overflow
            covered += m.length
            if out.count == maxMentions { break }
        }
        return out
    }

    /// A range a mention may replace on screen: inside the text, 2…`maxRange` units, an "@" at
    /// the start of the text or after whitespace or punctuation, then only letters, digits,
    /// combining marks attached to a letter, and `_ . -` (an ALLOW-list: blanks, fillers,
    /// invisible, bidi, variation and tag characters are all refused). Anything else would let a
    /// mention hide what the sender wrote; it then shows as plain text. Android's
    /// `Mentions.isMentionRange` is the same rule, code point for code point.
    static func isMentionRange(_ ns: NSString, start: Int, length: Int) -> Bool {
        guard length >= 2, length <= maxRange, inBounds(start: start, length: length, count: ns.length),
              ns.character(at: start) == 0x40 /* "@" */ else { return false }
        if start > 0 {
            var before = UInt32(ns.character(at: start - 1))
            if UTF16.isTrailSurrogate(UInt16(before)), start >= 2, UTF16.isLeadSurrogate(ns.character(at: start - 2)) {
                before = 0x10000 + ((UInt32(ns.character(at: start - 2)) - 0xD800) << 10) + (before - 0xDC00)
            }
            guard mayPrecede(before) else { return false }
        }
        var i = start + 1
        let end = start + length
        var afterLetter = false
        while i < end {
            let u = ns.character(at: i)
            var cp = UInt32(u)
            if UTF16.isLeadSurrogate(u) {
                guard i + 1 < end, UTF16.isTrailSurrogate(ns.character(at: i + 1)) else { return false }
                cp = 0x10000 + ((UInt32(u) - 0xD800) << 10) + (UInt32(ns.character(at: i + 1)) - 0xDC00)
                i += 2
            } else {
                guard !UTF16.isTrailSurrogate(u) else { return false }
                i += 1
            }
            switch tokenClass(cp) {
            case .letter: afterLetter = true
            case .other: afterLetter = false
            case .mark: guard afterLetter else { return false }
            case .refused: return false
            }
        }
        return true
    }

    enum TokenClass { case letter, mark, other, refused }

    /// Blank-looking letters and marks the general categories would let through.
    private static func isBlankLike(_ cp: UInt32) -> Bool {
        cp == 0x115F || cp == 0x1160 || cp == 0x3164 || cp == 0xFFA0 || cp == 0x034F || cp == 0x17B4 || cp == 0x17B5
            || (0x180B...0x180F).contains(cp) || (0xFE00...0xFE0F).contains(cp) || (0xE0000...0xE01EF).contains(cp)
    }

    /// What a code point is inside a mention token: a letter (L*), a combining mark (Mn, Mc —
    /// only after a letter), another allowed character (a digit, Nd, or `_ . -`), or refused.
    static func tokenClass(_ cp: UInt32) -> TokenClass {
        if cp == 0x5F || cp == 0x2E || cp == 0x2D { return .other }
        guard !isBlankLike(cp), let scalar = Unicode.Scalar(cp) else { return .refused }
        switch scalar.properties.generalCategory {
        case .uppercaseLetter, .lowercaseLetter, .titlecaseLetter, .modifierLetter, .otherLetter: return .letter
        case .nonspacingMark, .spacingMark: return .mark
        case .decimalNumber: return .other
        default: return .refused
        }
    }

    /// What may stand right before a mention's "@": whitespace (tab to carriage return, Zs, Zl,
    /// Zp) or punctuation (P*).
    static func mayPrecede(_ cp: UInt32) -> Bool {
        if (0x09...0x0D).contains(cp) { return true }
        guard let scalar = Unicode.Scalar(cp) else { return false }
        switch scalar.properties.generalCategory {
        case .spaceSeparator, .lineSeparator, .paragraphSeparator,
             .connectorPunctuation, .dashPunctuation, .openPunctuation, .closePunctuation,
             .initialPunctuation, .finalPunctuation, .otherPunctuation: return true
        default: return false
        }
    }

    /// The token the composer inserts for `name`: "@" and the name's allowed characters
    /// (`isMentionRange`), each run of anything else written as "_", cut to `maxRange` units.
    /// A name that leaves nothing becomes "@member".
    static func token(_ name: String) -> String {
        var out = "@"
        var units = 1
        var gap = false
        var afterLetter = false
        for scalar in name.unicodeScalars {
            let cls = tokenClass(scalar.value)
            let ok = cls == .letter || cls == .other || (cls == .mark && afterLetter)
            guard ok else { gap = units > 1; afterLetter = false; continue }
            let n = scalar.value > 0xFFFF ? 2 : 1
            let add = (gap ? 1 : 0) + n
            guard units + add <= maxRange else { break }
            if gap { out += "_" }
            out.unicodeScalars.append(scalar)
            units += add
            gap = false
            if cls == .letter { afterLetter = true } else if cls == .other { afterLetter = false }
        }
        return units > 1 ? out : "@member"
    }

    /// `start..<start+length` lies inside `count` UTF-16 units — checked without any addition.
    static func inBounds(start: Int, length: Int, count: Int) -> Bool {
        start >= 0 && length >= 1 && count >= 0 && start <= count && length <= count - start
    }

    /// A JSON number that is exactly a (non-boolean) integer no larger than a UTF-16 length can
    /// be; anything else (fractions, NaN, infinities, huge values, strings, arrays) is nil.
    static func exactInt(_ value: Any) -> Int? {
        guard let n = value as? NSNumber, !isBool(n) else { return nil }
        let d = n.doubleValue
        guard d.isFinite, d == d.rounded(), d >= 0, d <= Double(Int32.max) else { return nil }
        let i = n.int64Value
        guard Double(i) == d else { return nil }
        return Int(i)
    }

    private static func isBool(_ n: NSNumber) -> Bool { CFGetTypeID(n) == CFBooleanGetTypeID() }

    /// The visible text only (for display, copy, previews, editing).
    static func visible(_ text: String) -> String { decode(text).visible }
}

/// Who a message is about, for highlighting and notifying.
enum MentionRule {
    /// Does this message mention me? A direct mention; @everyone only from someone allowed to
    /// use it (the pinned server owner, or a role with Administrator / Mention Everyone); a reply
    /// to one of my messages counts too (unless the user turned that off).
    static func mentionsMe(_ payload: MentionPayload, me: String, senderMayMentionEveryone: Bool,
                           replyToMine: Bool, repliesCount: Bool = true) -> Bool {
        if payload.mentions.contains(where: { $0.userId == me }) { return true }
        if payload.everyone && senderMayMentionEveryone { return true }
        return replyToMine && repliesCount
    }

    /// May this sender's @everyone count? (Pinned owner, or Administrator / Manage Server from
    /// the roles the server lists for them — see `EveryoneRule` for what is trusted.)
    static func mayMentionEveryone(senderIsPinnedOwner: Bool, senderPermissions: Int64) -> Bool {
        senderIsPinnedOwner || senderPermissions & EveryoneRule.adminBits != 0
    }
}

/// Whose @everyone counts in a server — ONE rule for the composer's offer, the in-app alert and
/// highlight, and the notification extension (which gets the resulting id set from the app,
/// per channel, next to the sender sets). Android's `Mentions.everyoneSenders` is the same rule.
///
/// What is trusted:
/// - the PINNED owner (`spaceOwner`: from this device's own create/join flow, a key backup or a
///   verified sibling) — cryptographically, never what the server lists;
/// - admins — members whose roles grant Administrator or Manage Server. Roles and role
///   assignments are the SERVER's word (nothing signs them), so they are checked against what
///   this device knows: the account must be in the server's member list, must not be one this
///   device is holding (no trusted approval — `heldMembers`) and must not be blocked. A hostile
///   host could still name an approved member an admin; the most that buys is that member's
///   @everyone alerting through mutes (never a skwod mute, never a blocked sender).
enum EveryoneRule {
    static let administrator: Int64 = 8192
    static let manageServer: Int64 = 4
    static let adminBits: Int64 = administrator | manageServer

    static func allowed(pinnedOwner: String?, memberPermissions: [String: Int64],
                        held: Set<String>, blocked: Set<String>) -> Set<String> {
        var out = Set(memberPermissions.filter { id, perms in
            !id.isEmpty && perms & adminBits != 0 && !held.contains(id) && !blocked.contains(id)
        }.keys)
        if let pinnedOwner, !pinnedOwner.isEmpty, !blocked.contains(pinnedOwner) { out.insert(pinnedOwner) }
        return out
    }

    /// The key under which the app leaves a channel's id set for the notification extension
    /// (in the sender sets, beside the `dm:` entries).
    static func sendersKey(channelId: String) -> String { "everyone:channel:\(channelId)" }
}

/// What the notification extension says for a mention, from what it already holds: the
/// conversation titles and sender sets the app leaves it (`NotificationState`). A sender is named
/// only when this device trusts a name for them — the `person:` entry the app writes into the
/// titles for each peer of a claimed direct conversation whose name carries no marker (the same
/// name that titles that conversation, `NotificationTitles.direct`). A group's or a channel's
/// title is never taken for a person, and nothing the server lists names anyone. Otherwise:
/// "You were mentioned in #channel".
enum MentionNotice {
    static let personPrefix = "person:"

    static func senderName(authorId: String?, names: [String: String]) -> String? {
        guard let authorId, !authorId.isEmpty, let n = names[personPrefix + authorId],
              !n.isEmpty, n != NotificationTitles.generic else { return nil }
        return n
    }

    /// The banner title. `place`: "#general", a group's or DM's title, or nil when unknown.
    static func title(sender: String?, place: String?) -> String {
        switch (sender, place) {
        case let (s?, p?) where s == p: return "\(s) mentioned you"   // their own direct conversation
        case let (s?, p?): return MentionAlertRule.title(sender: s, place: p, previews: true)
        case let (s?, nil): return "\(s) mentioned you"
        case let (nil, p?): return "You were mentioned in \(p)"
        default: return "You were mentioned"
        }
    }

    /// Scopes the extension fetches (the `person:` entries are names, not conversations).
    static func isConversation(_ scope: String) -> Bool { scope.hasPrefix("channel:") || scope.hasPrefix("dm:") }

    /// Is `replyToId` one of mine, among the rows fetched with it?
    static func replyToMine(_ replyToId: String?, mine: Set<String>) -> Bool { replyToId.map(mine.contains) ?? false }
}

/// Unseen mentions of me, per workspace and conversation — kept in the APP GROUP's defaults, so
/// the notification extension adds to the same counts. Each message counts once, whichever
/// process saw it first (`counted`, bounded).
struct MentionBadgeLedger: Codable, Equatable {
    static let maxCounted = 2000
    var counts: [String: [String: Int]] = [:]
    var counted: [String] = []

    /// Adds the ids not counted before; returns how many were new.
    @discardableResult
    mutating func add(ids: [String], topic: String, workspaceId: String) -> Int {
        let seen = Set(counted)
        var fresh: [String] = []
        for id in ids where !id.isEmpty && !seen.contains(id) && !fresh.contains(id) { fresh.append(id) }
        guard !fresh.isEmpty, !topic.isEmpty, !workspaceId.isEmpty else { return 0 }
        counts[workspaceId, default: [:]][topic, default: 0] += fresh.count
        counted.append(contentsOf: fresh)
        if counted.count > Self.maxCounted { counted.removeFirst(counted.count - Self.maxCounted) }
        return fresh.count
    }

    mutating func clear(topic: String, workspaceId: String) {
        counts[workspaceId]?[topic] = nil
        if counts[workspaceId]?.isEmpty == true { counts[workspaceId] = nil }
    }

    func count(_ topic: String, workspaceId: String) -> Int { counts[workspaceId]?[topic] ?? 0 }

    static let key = "mention-badges.v2"

    static func load(_ defaults: UserDefaults) -> MentionBadgeLedger {
        guard let data = defaults.data(forKey: key), let l = try? JSONDecoder().decode(MentionBadgeLedger.self, from: data) else { return .init() }
        return l
    }

    func save(_ defaults: UserDefaults) {
        if let data = try? JSONEncoder().encode(self) { defaults.set(data, forKey: Self.key) }
    }

    /// Read, change and write back at once (the app and the extension both write it).
    @discardableResult
    static func update<T>(_ defaults: UserDefaults, _ change: (inout MentionBadgeLedger) -> T) -> (MentionBadgeLedger, T) {
        var l = load(defaults)
        let r = change(&l)
        l.save(defaults)
        return (l, r)
    }
}

/// Whether a message alerts (banner + sound). A mention of me ALWAYS alerts — through a muted
/// conversation or a muted server — except when the whole skwod is muted or the sender is
/// blocked. Everything else alerts unless its conversation (or the skwod) is muted.
enum MentionAlertRule {
    static func alerts(mentionsMe: Bool, conversationMuted: Bool, serverMuted: Bool,
                       skwodMuted: Bool, senderBlocked: Bool) -> Bool {
        if senderBlocked || skwodMuted { return false }
        // A server mute is always "mute, but still notify me for @mentions".
        if mentionsMe { return true }
        return !conversationMuted && !serverMuted
    }

    /// The notification's title for a mention ("You were mentioned" when previews are off or the
    /// app is locked).
    static func title(sender: String, place: String, previews: Bool) -> String {
        previews ? "\(sender) mentioned you in \(place)" : "You were mentioned"
    }
}

/// While typing "@…": which members match, best first.
enum MentionAutocomplete {
    /// The "@query" the caret is in, if any: the text after the last "@" that starts a word and
    /// has no space after it. Returns the query and the UTF-16 location of the "@".
    static func activeQuery(in text: String) -> (query: String, at: Int)? {
        let ns = text as NSString
        let at = ns.range(of: "@", options: .backwards)
        guard at.location != NSNotFound else { return nil }
        if at.location > 0 {
            let before = ns.substring(with: NSRange(location: at.location - 1, length: 1))
            guard before.rangeOfCharacter(from: .whitespacesAndNewlines) != nil else { return nil }
        }
        let query = ns.substring(from: at.location + 1)
        guard query.count <= 32, query.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else { return nil }
        return (query, at.location)
    }

    /// Members whose shown name starts with (then contains) the query, case-insensitively.
    static func matches(_ query: String, in members: [(userId: String, name: String)], limit: Int = 8) -> [(userId: String, name: String)] {
        let q = query.lowercased()
        guard !q.isEmpty else { return Array(members.prefix(limit)) }
        let starts = members.filter { $0.name.lowercased().hasPrefix(q) }
        let contains = members.filter { !$0.name.lowercased().hasPrefix(q) && $0.name.lowercased().contains(q) }
        return Array((starts + contains).prefix(limit))
    }

    /// Replace the "@query" at `at` with "@name " and record its mention range.
    static func insert(name: String, userId: String, into text: String, at: Int, payload: inout MentionPayload) -> String {
        let ns = text as NSString
        // A token every app accepts (`MentionCodec.token`): a name with spaces is still one.
        let token = MentionCodec.token(name)
        let replaced = ns.replacingCharacters(in: NSRange(location: at, length: ns.length - at), with: token + " ")
        payload.mentions.append(.init(userId: userId, start: at, length: (token as NSString).length))
        return replaced
    }

    /// After the user edited the draft: keep only mentions whose token is still exactly there.
    static func reconcile(_ payload: MentionPayload, draft: String, names: [String: String]) -> MentionPayload {
        let ns = draft as NSString
        var out = payload
        out.mentions = payload.mentions.filter { m in
            guard let name = names[m.userId], MentionCodec.inBounds(start: m.start, length: m.length, count: ns.length) else { return false }
            return ns.substring(with: NSRange(location: m.start, length: m.length)) == MentionCodec.token(name)
        }
        out.everyone = payload.everyone && draft.contains("@everyone")
        return out
    }
}
