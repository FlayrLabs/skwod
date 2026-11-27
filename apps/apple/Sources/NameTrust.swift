import Foundation

// Whose name is shown, and how far it is trusted. Pure (Foundation only): the logic tests
// compile this file. The contact book that feeds it is `Contacts.swift`; the waiting-room
// screens are `WaitingRoom.swift`.

/// The ONE rule set for showing a person's name, wherever it appears: the DM list, a chat's
/// header, "Waiting to join", the member list, notifications. Pure, so the self-check covers it.
enum ContactTrust {
    enum Badge: Equatable {
        case none          // known: shown normally
        case verified      // safety number compared
        case unverified    // server-claimed only; the directory agrees the name is this account's
        case unconfirmed   // server-claimed, and the directory has not answered (yet)
        case mismatch      // server-claimed, and the directory said it is another account's, or nobody's
        case impersonation // looks like someone the user knows but is another account — or
                           // holds characters no Skwod name has
    }

    struct Display: Equatable {
        var text: String
        var badge: Badge
        /// The name for `surface`: the plain name where a badge is drawn beside it, the words
        /// everywhere else.
        func label(for surface: Surface) -> String { ContactTrust.form(surface) == .badge ? text : spoken }
        /// A badge must be drawn beside the plain name (`label(for:)` on a badge surface).
        var needsBadge: Bool { badge != .none }
        /// The words a mention chip keeps for a flagged name (its mark otherwise: a dotted
        /// underline for UNVERIFIED, nothing for a known or verified name).
        var chipWords: String? {
            switch badge {
            case .unconfirmed, .mismatch: return "unconfirmed"
            case .impersonation: return "look-alike"
            case .none, .verified, .unverified: return nil
            }
        }
        /// A name to put in a banner / notification / sentence.
        var spoken: String {
            switch badge {
            case .none, .verified: return text
            case .unverified: return text.hasPrefix("Unknown contact") ? text : "\(text) (unverified)"
            case .unconfirmed, .mismatch: return text.hasPrefix("Unknown contact") ? text : "\(text) (unconfirmed)"
            case .impersonation: return text
            }
        }
    }

    /// Build 49: where a name appears decides its form. Styled rows (message headers, member
    /// and DM rows, mention chips) show the plain name WITH a small badge (`TrustBadge`, or a
    /// dotted underline in a mention chip); text-only and security-relevant places keep the
    /// words ("(unverified)"). The trust signal never disappears — it changes shape.
    enum Surface: CaseIterable {
        case notification, incomingCall, dialogTitle, joinConfirmation, groupConfirmation, kickBanDialog, securityNotice, typing
        case mentionPicker, replyPreview, actionSheet, approvalRow, blockReportTarget
        case messageHeader, memberRow, dmRow, mentionChip, profileCard
    }
    enum Form: Equatable { case text, badge }

    static func form(_ surface: Surface) -> Form {
        switch surface {
        case .messageHeader, .memberRow, .dmRow, .mentionChip, .profileCard: return .badge
        case .notification, .incomingCall, .dialogTitle, .joinConfirmation, .groupConfirmation, .kickBanDialog, .securityNotice, .typing,
             .mentionPicker, .replyPreview, .actionSheet, .approvalRow, .blockReportTarget: return .text
        }
    }

    /// How a badge is drawn. In rows (`compact`) an ordinary member — nobody's name is confirmed
    /// until the user does it — carries a quiet symbol that explains itself; whatever says this may
    /// NOT be who the name says stays loud everywhere; screens where one decides about people
    /// (joining a group, a person's card) keep the words.
    enum Mark: Equatable { case none, shield, symbol(String), words, loud }

    static func mark(_ badge: Badge, compact: Bool) -> Mark {
        switch badge {
        case .none: return .none
        case .verified: return .shield
        case .unverified: return compact ? .symbol("questionmark.circle") : .words
        case .unconfirmed: return compact ? .symbol("questionmark.circle.dashed") : .loud
        case .mismatch, .impersonation: return .loud
        }
    }

    /// What a mark means, in a sentence or two (nil: nothing to explain).
    static func explanation(_ badge: Badge) -> String? {
        switch badge {
        case .none: return nil
        case .verified: return "You compared safety numbers with this person."
        case .unverified: return "This name comes from the host of this Skwod. To be sure who it is, compare safety numbers."
        case .unconfirmed: return "This name comes from the host of this Skwod, which has not answered yet whose it is. To be sure who it is, compare safety numbers."
        case .mismatch: return "Looking this person's name up leads to another account, or to nobody. Don't rely on it."
        case .impersonation: return "This account's name looks like someone's you know, or has characters no Skwod name has. Don't rely on it."
        }
    }

    static func unknownName(_ userId: String) -> String { "Unknown contact \(userId.prefix(6))" }

    /// How a mention of `userId` is shown: the signed-in user is themself — their own name, no
    /// marker (they have no contact entry for themself); anyone else through `other`.
    /// `myName` should be a name this device holds for itself (never the server's list); as a
    /// second line, one that looks like someone the user knows, or has unusual characters, is
    /// shown as "you".
    static func mentionDisplay(userId: String, me: String?, myName: String?, book: [String: Contact] = [:],
                               roster: [String: String] = [:], other: (String) -> Display) -> Display {
        if let me, !me.isEmpty, userId == me {
            guard let myName, !myName.isEmpty, !collides(userId: me, name: myName, book: book, roster: roster),
                  !WaitingTrust.hasUnusualCharacters(myName) else { return Display(text: "you", badge: .none) }
            return Display(text: myName, badge: .none)
        }
        return other(userId)
    }

    /// Does `name` look like the name of someone ELSE the user has grounds to recognise: a
    /// KNOWN or VERIFIED contact, or an accepted member (`roster`: user id → name) of a server
    /// they share? Being in the roster does not raise a member's own level — it only means
    /// nobody else may wear their name unflagged.
    static func collides(userId: String, name: String, book: [String: Contact], roster: [String: String] = [:]) -> Bool {
        let shape = WaitingTrust.skeleton(name)
        guard !shape.isEmpty else { return false }
        if book.contains(where: { id, c in id != userId && c.level >= .known && WaitingTrust.skeleton(c.name) == shape }) { return true }
        return roster.contains { id, other in id != userId && WaitingTrust.skeleton(other) == shape }
    }

    /// What to show for `userId`, given the name the server (or a stored conversation) offers.
    ///
    /// - `roster`: accepted members of the servers the user shares (user id → name).
    /// - `lookup`: what the directory said when this name was looked up (`findUser`): `true` =
    ///   it leads to exactly this account, `false` = to another account or nobody, `nil` = the
    ///   lookup failed or has not been made. Only `true` gets the quiet "unverified" marker;
    ///   anything else is flagged. A lookup never raises a name above UNVERIFIED.
    static func display(userId: String, claimedName: String?, book: [String: Contact],
                        roster: [String: String] = [:], lookup: Bool? = nil) -> Display {
        if let mine = book[userId], mine.level >= .known, !mine.name.isEmpty {
            return Display(text: mine.name, badge: mine.level == .verified ? .verified : .none)
        }
        let name = (claimedName?.isEmpty == false ? claimedName : book[userId]?.name) ?? ""
        guard !WaitingTrust.normalize(name).isEmpty else { return Display(text: unknownName(userId), badge: .unconfirmed) }
        // A look-alike of someone the user would recognise gets the strong warning — and is
        // never shown under that name.
        if collides(userId: userId, name: name, book: book, roster: roster) { return Display(text: unknownName(userId), badge: .impersonation) }
        // So does a name no Skwod server issues (other scripts, invisible characters): on its own.
        if WaitingTrust.hasUnusualCharacters(name) { return Display(text: unknownName(userId), badge: .impersonation) }
        if lookup == false { return Display(text: unknownName(userId), badge: .mismatch) }
        return Display(text: name, badge: lookup == true ? .unverified : .unconfirmed)
    }

    /// The name to put beside something a member wrote or did where the only name on offer is
    /// the SERVER's member list: a channel message, a feed post or comment, a reply preview,
    /// "X joined", an incoming call. The same rule as everywhere else (`display`): a known or
    /// verified contact is shown under the name THIS DEVICE keeps for them, whatever the
    /// server says today; a name only the server vouches for carries its marker; a look-alike
    /// of someone the user knows, or a name with characters no Skwod name has, is not shown as
    /// a name at all. So a server that swaps two members' names in its list changes nothing
    /// for people the user knows, and cannot pass anyone off as them.
    static func authorLabel(userId: String?, claimedName: String?, book: [String: Contact],
                            roster: [String: String] = [:], lookup: Bool? = nil) -> String {
        guard let userId, !userId.isEmpty else { return "Unknown member" }
        return display(userId: userId, claimedName: claimedName, book: book, roster: roster, lookup: lookup).spoken
    }

    /// Record a name at a level. Server-claimed data (`.unverified`) never renames, re-levels or
    /// otherwise touches a contact the user pinned; a user action sets the name it was taken
    /// under and raises the level (it never lowers it).
    static func merged(existing: Contact?, name: String, level: TrustLevel) -> Contact {
        guard let existing else { return Contact(name: name, level: level, known: level >= .known ? true : nil) }
        if level == .unverified {
            return existing.level >= .known ? existing : Contact(name: name.isEmpty ? existing.name : name, level: .unverified, known: existing.known)
        }
        return Contact(name: name.isEmpty ? existing.name : name, level: max(existing.level, level),
                       known: level >= .known ? true : existing.known)
    }

    /// The core says whether the safety number is (still) verified: verifying promotes to
    /// VERIFIED; a verification that no longer holds falls back to KNOWN (the user did act).
    static func withVerification(_ existing: Contact?, name: String, verified: Bool) -> Contact? {
        if verified {
            return Contact(name: (existing?.level ?? .unverified) >= .known ? existing!.name : name, level: .verified,
                           known: existing?.explicitlyKnown ?? false)
        }
        guard let existing else { return nil }
        // Un-verified: back to KNOWN only if the user had made them known themself.
        guard existing.level == .verified else { return existing }
        return Contact(name: existing.name, level: existing.explicitlyKnown ? .known : .unverified, known: existing.known)
    }

    /// Build 49: a READ of the core's state (opening the safety-number screen, refreshing it)
    /// may only demote or leave alone — it never creates or raises a pinned name. Raising
    /// happens only after an explicit, successful verification (`withVerification(verified: true)`).
    static func afterStatusRead(_ existing: Contact?, verified: Bool) -> Contact? {
        guard let existing, !verified, existing.level == .verified else { return nil }
        return withVerification(existing, name: existing.name, verified: false)
    }

    /// May an explicit verification pin this name? Not a flagged one (unconfirmed, look-alike).
    static func mayPinOnVerify(_ badge: Badge) -> Bool { !isFlagged(badge) }

    /// A flag that stands in the way of trusting a name: a look-alike / unusual characters, a
    /// directory lookup that led elsewhere, or one that could not be made.
    static func isFlagged(_ badge: Badge) -> Bool { badge == .impersonation || badge == .mismatch || badge == .unconfirmed }

    /// What OPENING a conversation does to the contact book.
    ///
    /// - Selecting a conversation that already exists changes nothing: looking is not vouching.
    /// - Starting a NEW one is the user picking that person — which makes them KNOWN only when
    ///   nothing about the name is flagged. A flagged person's conversation starts UNVERIFIED,
    ///   and only the explicit "I know them — accept" raises it.
    /// `badge` is how the name is shown right now (`display`).
    static func afterOpening(existing: Contact?, isNewConversation: Bool, name: String, badge: Badge) -> Contact? {
        guard isNewConversation else { return existing }
        return merged(existing: existing, name: name, level: isFlagged(badge) ? .unverified : .known)
    }

    /// "I know them — accept": refused while the strong warning stands (a look-alike of
    /// someone the user knows, or characters no Skwod name has).
    static func mayAccept(_ badge: Badge) -> Bool { badge != .impersonation }

    /// "I know them — accept" pins `name` as this person's. It is offered — and honoured —
    /// only for the name that is ON SCREEN: when the rule shows something else in its place
    /// ("Unknown contact 1a2b3c", because the directory led elsewhere, or the name looks like
    /// someone's), the user would be vouching for a name they never saw.
    static func mayAccept(shown: Display, name: String) -> Bool {
        mayAccept(shown.badge) && !name.isEmpty && shown.text == name
    }

    /// Whose reactions count in a conversation: this account's and its participants'. The
    /// core stores a sealed reaction from any authenticated sender; one from an account that
    /// is not in the conversation must not show as a pill that reads as the peer's.
    static func reactionCounts(from userId: String, me: String, participants: Set<String>) -> Bool {
        userId == me || userId == "__me__" || participants.contains(userId)
    }

    /// Which stored conversation a decrypted DM belongs to. A conversation is bound to its peer
    /// account for good: the index of the entry with this conversation id AND this sender, or
    /// nil — the sender gets an entry of its own, and no existing entry is re-keyed.
    static func conversationIndex(for senderUserId: String, conversationId: String,
                                  in entries: [(conversationId: String, peerUserId: String)]) -> Int? {
        entries.firstIndex { $0.conversationId == conversationId && $0.peerUserId == senderUserId }
    }

    /// The level a conversation stored without any trust information starts at: one this device
    /// started itself is KNOWN (the user picked that person); anything else is UNVERIFIED.
    static func migratedLevel(startedHere: Bool) -> TrustLevel { startedHere ? .known : .unverified }
}

/// Is the name on a "Waiting to join" entry trustworthy enough to act on?
///
/// "Let in" signs a member approval that every other member's device will honour, and the user
/// decides by reading a NAME. But the name comes from the server: a hostile host can list a
/// ghost account under a friend's name. So before the name is shown as a name:
///
/// - the directory lookup for that username (`findUser`) must return this very account. If it
///   returns another account, or nobody, the label is not this account's name;
/// - the name must not be the name of someone ELSE the user already has here — an accepted
///   member of the server, or a DM contact — under a different account id. That is what an
///   impersonation looks like, and it gets the strongest warning.
///
/// Anything but `.ok` disables "Let in". Pure, so it is covered by the self-check / unit tests.
enum WaitingTrust {
    enum Verdict: Hashable {
        /// The name resolves to this account and collides with nobody the user knows.
        case ok
        /// Not checked yet, or the directory could not be reached. No decision is offered.
        case unchecked
        /// The directory says this username belongs to a different account (or to nobody).
        case nameMismatch
        /// The name contains characters a Skwod username cannot have: non-ASCII letters
        /// (look-alikes from other scripts, full-width forms) or invisible characters. Never
        /// let in on the strength of such a name.
        case unusualCharacters
        /// Someone the user already knows by this name — or by a name that LOOKS the same —
        /// has a DIFFERENT account id.
        case impersonation
    }

    /// Characters that take no space on screen: Unicode's default-ignorable set plus every
    /// format (Cf) and control (Cc) character. The explicit ranges are the ones that matter
    /// for names (soft hyphen, combining grapheme joiner, Hangul fillers, Khmer inherent
    /// vowels, Mongolian selectors, zero-width and bidi controls, variation selectors, BOM,
    /// tags); the property checks cover the rest and whatever Unicode adds later.
    static func isInvisible(_ u: Unicode.Scalar) -> Bool {
        switch u.value {
        case 0x00AD, 0x034F, 0x061C, 0x115F...0x1160, 0x17B4...0x17B5, 0x180B...0x180F,
             0x200B...0x200F, 0x202A...0x202E, 0x2060...0x206F, 0x3164, 0xFE00...0xFE0F,
             0xFEFF, 0xFFA0, 0xFFF0...0xFFF8, 0x1BCA0...0x1BCA3, 0x1D173...0x1D17A,
             0xE0000...0xE0FFF:
            return true
        default:
            break
        }
        if u.properties.isDefaultIgnorableCodePoint { return true }
        switch u.properties.generalCategory {
        case .format, .control: return true
        default: return false
        }
    }

    /// A name as it is compared for equality: compatibility-composed (NFKC — full-width and
    /// other compatibility forms become their plain letters), invisible characters and white
    /// space removed, case-folded.
    static func normalize(_ name: String) -> String {
        let composed = name.precomposedStringWithCompatibilityMapping
        var out = String.UnicodeScalarView()
        for u in composed.unicodeScalars where !isInvisible(u) && !u.properties.isWhitespace {
            out.append(u)
        }
        // Case folding can itself produce compatibility forms; compose once more.
        return String(out).lowercased().precomposedStringWithCompatibilityMapping
    }

    /// Does the RAW name hold anything a Skwod username cannot (`[a-z0-9_]`, case aside)?
    /// Any non-ASCII scalar, any invisible or control character.
    static func hasUnusualCharacters(_ name: String) -> Bool {
        name.trimmingCharacters(in: CharacterSet(charactersIn: " ")).unicodeScalars.contains {
            !$0.isASCII || isInvisible($0) || $0.value < 0x20 || $0.value == 0x7F
        }
    }

    /// Look-alikes of Latin letters in Cyrillic, Greek and a few stray blocks (after NFKC and
    /// case folding) — the UTS #39 "confusables" that matter for a username.
    private static let confusables: [Unicode.Scalar: String] = [
        // Cyrillic
        "\u{0430}": "a", "\u{0432}": "b", "\u{0435}": "e", "\u{0451}": "e", "\u{0454}": "e",
        "\u{043A}": "k", "\u{043C}": "m", "\u{043D}": "h", "\u{043E}": "o", "\u{0440}": "p",
        "\u{0441}": "c", "\u{0442}": "t", "\u{0443}": "y", "\u{0445}": "x", "\u{0455}": "s",
        "\u{0456}": "i", "\u{0457}": "i", "\u{0458}": "j", "\u{04BB}": "h", "\u{0501}": "d",
        "\u{051B}": "q", "\u{051D}": "w", "\u{044C}": "b", "\u{0433}": "r", "\u{0491}": "r",
        "\u{043F}": "n", "\u{0438}": "u", "\u{04CF}": "l", "\u{04C0}": "l", "\u{0437}": "3",
        "\u{0431}": "6", "\u{0448}": "w", "\u{0461}": "w", "\u{0475}": "v", "\u{04AF}": "y",
        "\u{04D9}": "e", "\u{0493}": "f", "\u{0497}": "x",
        // Greek
        "\u{03B1}": "a", "\u{03B2}": "b", "\u{03B5}": "e", "\u{03B7}": "n", "\u{03B9}": "i",
        "\u{03BA}": "k", "\u{03BD}": "v", "\u{03BF}": "o", "\u{03C1}": "p", "\u{03C4}": "t",
        "\u{03C5}": "u", "\u{03C7}": "x", "\u{03C9}": "w", "\u{03B3}": "y", "\u{03BC}": "u",
        "\u{03F2}": "c", "\u{03F3}": "j", "\u{03C3}": "o", "\u{03C2}": "c", "\u{03B6}": "z",
        "\u{03B4}": "d", "\u{03C0}": "n",
        // Latin extensions, IPA, Armenian and symbols that pass for plain letters
        "\u{0131}": "i", "\u{0251}": "a", "\u{0261}": "g", "\u{0269}": "i", "\u{026A}": "i",
        "\u{01C0}": "l", "\u{0237}": "j", "\u{00F8}": "o", "\u{0111}": "d", "\u{0142}": "l",
        "\u{00DF}": "b", "\u{0585}": "o", "\u{0570}": "h", "\u{0578}": "n", "\u{057D}": "u",
        "\u{0581}": "g", "\u{0566}": "q", "\u{0575}": "j",
        "|": "l", "!": "l", "$": "s", "@": "a",
    ]

    /// The UTS #39-style skeleton of a name: what it LOOKS like. Two names with the same
    /// skeleton can be mistaken for one another on screen. Built from the normalized name by
    /// dropping accents, mapping look-alike letters to Latin, folding the classic digit/letter
    /// pairs (0/o, 1/l/i) and the two-letter shapes (rn/m, vv/w).
    static func skeleton(_ name: String) -> String {
        var out = ""
        for u in normalize(name).decomposedStringWithCanonicalMapping.unicodeScalars {
            switch u.properties.generalCategory {
            case .nonspacingMark, .spacingMark, .enclosingMark: continue   // accents
            default: break
            }
            if let mapped = confusables[u] { out += mapped } else { out.unicodeScalars.append(u) }
        }
        out = out.lowercased()
        out = out.replacingOccurrences(of: "0", with: "o")
        out = out.replacingOccurrences(of: "1", with: "l").replacingOccurrences(of: "i", with: "l")
        out = out.replacingOccurrences(of: "rn", with: "m").replacingOccurrences(of: "vv", with: "w")
        return out
    }

    /// "Let in" — on ANY screen that offers it — only for a name that checked out. Everything
    /// else (not checked yet, the directory led elsewhere, unusual characters, a look-alike of
    /// someone the user knows) is not approved on the strength of the name.
    static func mayLetIn(_ verdict: Verdict) -> Bool { verdict == .ok }

    /// - `lookup`: what `findUser(username)` returned — `.some(id)`, `.some(nil)` when the
    ///   directory has no such user, or `nil` when the lookup itself failed.
    /// - `known`: accounts the user already knows under a name (accepted members of this server,
    ///   DM contacts), as (user id, name).
    static func assess(userId: String, username: String, lookup: String??, known: [(userId: String, name: String)]) -> Verdict {
        let name = normalize(username)
        if name.isEmpty { return .nameMismatch }
        // Looks like someone the user knows, but is another account: the strongest warning.
        let shape = skeleton(username)
        if known.contains(where: { $0.userId != userId && skeleton($0.name) == shape }) { return .impersonation }
        // A name no Skwod server would issue is never shown as trustworthy, collision or not.
        if hasUnusualCharacters(username) { return .unusualCharacters }
        guard let lookup else { return .unchecked }
        return lookup == userId ? .ok : .nameMismatch
    }
}

/// What an incoming call's screen says. It is shown by the SYSTEM — on the lock screen, over
/// other apps — so it follows the notification rule: with app lock on or previews off it names
/// nobody and no skwod. Otherwise "‹caller› · ‹server›", the caller already passed through
/// `ContactTrust.authorLabel`.
enum CallLabel {
    static let generic = "Skwod call"

    static func text(caller: String?, server: String?, appLock: Bool, previews: Bool) -> String {
        guard !appLock, previews else { return generic }
        switch (caller.flatMap { $0.isEmpty ? nil : $0 }, server.flatMap { $0.isEmpty ? nil : $0 }) {
        case let (who?, server?): return "\(who) · \(server)"
        case let (who?, nil): return who
        case let (nil, server?): return server
        default: return generic
        }
    }
}

/// Where a direct conversation stands with the contact's KEYS, as the banner above the composer
/// shows it (build 45: the core never accepts a changed key by itself). Decided from the core's
/// `contact_status` and from sends that failed because of it — never from an `identity_changed`
/// notice alone: that notice is also raised for a refused impersonation, after which nothing is
/// held and there is nothing to accept.
enum IdentityHold: Equatable {
    /// Nothing waits on a decision.
    case none
    /// Sends to them are on hold: their devices changed since they were verified, the only
    /// devices left are ones nobody of theirs vouched for (a replaced phone), or a send just
    /// failed because of that.
    case onHold
    /// They have a device nobody of theirs vouched for, next to ones that still get messages:
    /// nothing goes to the new one, and what it sends is held, until the user decides.
    case unacceptedDevice

    /// - `sendsHeld`, `devices`, `unvouchedDevices`: `ContactStatus`.
    /// - `failedOnIdentity`: a queued send of this conversation failed on the contact's keys.
    static func decide(sendsHeld: Bool, devices: UInt32, unvouchedDevices: UInt32, failedOnIdentity: Bool) -> IdentityHold {
        if sendsHeld || failedOnIdentity || (unvouchedDevices > 0 && devices == 0) { return .onHold }
        if unvouchedDevices > 0 { return .unacceptedDevice }
        return .none
    }

    /// The outbox's reason for a send the core refused because of the contact's keys
    /// (`skwod-core` outbox: `IdentityChanged`). The only part of the sentence relied on.
    static func isIdentityFailure(_ reason: String) -> Bool {
        reason.localizedCaseInsensitiveContains("safety number")
    }

    /// The banner's headline.
    func headline(name: String) -> String? {
        switch self {
        case .none: return nil
        case .onHold: return "\(name)'s security key changed. Messages to them are on hold until you accept or verify."
        case .unacceptedDevice: return "\(name) has a new device you haven't accepted. Nothing is sent to it until you accept or verify."
        }
    }
}
