import Foundation

/// Where a skwod lives. Two kinds, and only two:
///
/// - **p2p** — the host's key is the address (`skwod://join/<node id>`). Nothing about the network
///   location is stored; the app dials the key and gets a loopback URL that is only valid for this
///   launch (see `P2PManager`). This is what a Mac host hands out.
/// - **https** — a classic server on a domain (a VPS behind a reverse proxy). Plain `http://` is
///   accepted for loopback only, which is how a Mac host's own app reaches its own server.
enum SkwodAddress: Equatable, Hashable {
    case p2p(nodeId: String, fallbackURL: String?)
    case https(String)

    /// The stable string persisted for this address (never a loopback proxy URL).
    var stored: String {
        switch self {
        case .p2p(let nodeId, _): return InviteLink.p2pPrefix + nodeId
        case .https(let url): return url
        }
    }

    var nodeId: String? {
        if case .p2p(let id, _) = self { return id }
        return nil
    }
}

/// An invite (or a bare address) after validation.
struct ParsedInvite: Equatable {
    let address: SkwodAddress
    /// The join code, if the link carried one.
    let joinCode: String?
}

enum InviteError: LocalizedError, Equatable {
    case empty, tooLong, notAnInvite, insecureAddress, badCode

    var errorDescription: String? {
        switch self {
        case .empty: return "Paste the invite link your host sent you."
        case .tooLong: return "That link is too long to be a Skwod invite."
        case .notAnInvite: return "That doesn't look like a Skwod invite. It should start with https://skwod.io/join# or skwod://join/ (or be an https:// address)."
        case .insecureAddress: return "Skwod only connects to https:// addresses or skwod:// invites."
        case .badCode: return "The code in that link isn't valid. Ask your host for a fresh invite."
        }
    }
}

/// Parsing + validation for everything that can name a skwod: a tapped `skwod://` deep link, a
/// tapped or pasted `https://skwod.io/join#…` share link, a scanned QR code, pasted text. All of these are **untrusted input** — a link can come from
/// anyone — so nothing here touches the network, and anything that is not exactly one of the two
/// accepted shapes is refused rather than "fixed up".
enum InviteLink {
    static let p2pPrefix = "skwod://join/"
    /// The share form, `https://skwod.io/join#<node id>.<join code>`: what Share / Copy / the QR
    /// code hand out (build 42 on). It names the same thing as `skwod://join/<node id>#<code>`;
    /// the whole invite is in the URL fragment, which is never sent to skwod.io. See
    /// `core/skwod-net/src/invite.rs` for the grammar.
    static let shareOrigin = "https://skwod.io"
    /// Longest input we will even look at. A real invite is ~80 characters (~300 with a fallback).
    static let maxLength = 1024

    static func parse(_ raw: String) throws -> ParsedInvite {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { throw InviteError.empty }
        guard text.utf8.count <= maxLength else { throw InviteError.tooLong }
        // No control characters or interior whitespace: those only show up in crafted input.
        guard !text.unicodeScalars.contains(where: {
            CharacterSet.controlCharacters.contains($0) || CharacterSet.whitespacesAndNewlines.contains($0)
        }) else { throw InviteError.notAnInvite }

        // skwod.io is the invite page, never a server: a link to it is a share link or nothing.
        // Routing on the origin (not on "looks like a share link") means a mangled share link is
        // refused instead of being treated as the address of a server called skwod.io.
        if text.lowercased().hasPrefix("skwod:") || isOnShareOrigin(text) {
            // The Rust core owns the link grammar for both spellings (node id encoding, code
            // charset, fallback), so a share link goes through exactly the same validation.
            guard let inv = try? p2pParseInvite(link: text) else { throw InviteError.notAnInvite }
            if let code = inv.joinCode, !isValidCode(code) { throw InviteError.badCode }
            // The core already drops non-https fallbacks; re-check here so the rule is visible.
            let fallback = inv.fallbackUrl.flatMap { try? normalizedServer($0, allowLoopbackHTTP: false) }
            return ParsedInvite(address: .p2p(nodeId: inv.nodeId, fallbackURL: fallback), joinCode: inv.joinCode)
        }

        // Classic `<address>#<code>` (VPS hosts), or a bare address for log-in.
        let parts = text.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        let server = try normalizedServer(String(parts[0]), allowLoopbackHTTP: true)
        var code: String?
        if parts.count == 2 {
            // Older links may carry a trailing `~b.<pubkey>.<key>` beacon suffix; it is ignored now.
            let c = InviteBeacon.strip(String(parts[1]))
            guard isValidCode(c) else { throw InviteError.badCode }
            code = c
        }
        return ParsedInvite(address: .https(server), joinCode: code)
    }

    /// True for `https://skwod.io`, alone or followed by a path, query, fragment or port. A
    /// look-alike host (`skwod.io.example`, `chat.skwod.io`) is not on the share origin.
    static func isOnShareOrigin(_ text: String) -> Bool {
        let lower = text.lowercased()
        guard lower.hasPrefix(shareOrigin) else { return false }
        guard let next = lower.dropFirst(shareOrigin.count).first else { return true }
        return next == "/" || next == "#" || next == "?" || next == ":"
    }

    /// Join codes are server-minted: `SKWD-XXXX-XXXX`, or a URL-safe token.
    static func isValidCode(_ code: String) -> Bool {
        (1...128).contains(code.count) && code.unicodeScalars.allSatisfy {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_")
        }
    }

    /// Normalize a typed server address to a base URL, or refuse it. `https://` only — except
    /// loopback `http://`, which never leaves this machine.
    static func normalizedServer(_ raw: String, allowLoopbackHTTP: Bool) throws -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { throw InviteError.empty }
        if !s.contains("://") { s = "https://" + s }
        while s.hasSuffix("/") { s.removeLast() }
        guard let comps = URLComponents(string: s), let scheme = comps.scheme?.lowercased(),
              let host = comps.host?.lowercased(), !host.isEmpty,
              comps.user == nil, comps.password == nil, comps.query == nil, comps.fragment == nil
        else { throw InviteError.notAnInvite }
        switch scheme {
        case "https": break
        case "http":
            guard allowLoopbackHTTP, isLoopback(host) else { throw InviteError.insecureAddress }
        default: throw InviteError.notAnInvite
        }
        return s
    }

    static func isLoopback(_ host: String) -> Bool {
        host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]"
    }

    /// Build the link people share: `https://skwod.io/join#<node>[.<code>][&u=https://…]`.
    /// Use this for Copy, Share and QR codes. Builds ≤ 41 cannot parse it when pasted, but the
    /// page it opens forwards to the `skwod://` form, which they handle.
    static func shareLink(nodeId: String, joinCode: String?, fallbackURL: String? = nil) -> String? {
        guard let link = try? p2pFormatShareLink(nodeId: nodeId, joinCode: joinCode, fallbackUrl: fallbackURL)
        else { return nil }
        // Round-trip through the parser so we never hand out a link we would refuse ourselves.
        return (try? parse(link)) != nil ? link : nil
    }

    /// Build the app-scheme form: `skwod://join/<node>[?u=https://…]#<code>`. This is what the
    /// app registers and stores; hand out `shareLink` instead.
    static func format(nodeId: String, joinCode: String?, fallbackURL: String? = nil) -> String? {
        guard var link = try? p2pFormatInvite(nodeId: nodeId, joinCode: nil) else { return nil }
        if let fallbackURL, fallbackURL.hasPrefix("https://") { link += "?u=" + fallbackURL }
        if let joinCode, !joinCode.isEmpty { link += "#" + joinCode }
        // Round-trip through the parser so we never hand out a link we would refuse ourselves.
        return (try? parse(link)) != nil ? link : nil
    }

    /// A short, human-comparable form of a host key, for "is this the right host?" displays.
    static func shortKey(_ nodeId: String) -> String {
        nodeId.count > 12 ? "\(nodeId.prefix(6))…\(nodeId.suffix(6))" : nodeId
    }
}

/// Older invite links carried `~b.<pubkey>.<contentKey>` after the code (a Nostr "beacon" used to
/// find a host whose tunnel address had moved). A p2p address never moves, so the beacon is gone;
/// this only strips the suffix so an old link still yields its code.
enum InviteBeacon {
    static let marker = "~b."

    static func strip(_ codePortion: String) -> String {
        guard let r = codePortion.range(of: marker) else { return codePortion }
        return String(codePortion[..<r.lowerBound])
    }
}
