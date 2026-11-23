package io.skwod.app

import java.net.URI

/**
 * Where a skwod lives. Two kinds, and only two (mirror of the Apple app's `SkwodAddress`):
 *
 * - **P2p** — the host's key is the address (`skwod://join/<node id>`). Nothing about the network
 *   location is stored; the app dials the key and gets a loopback URL that is only valid for this
 *   process (see [P2PManager]).
 * - **Https** — a classic server on a domain (a VPS behind a reverse proxy). Plain `http://` is
 *   accepted for `127.0.0.1` only, which never leaves this device.
 */
sealed class SkwodAddress {
    data class P2p(val nodeId: String, val fallbackUrl: String? = null) : SkwodAddress()
    data class Https(val url: String) : SkwodAddress()

    /** The stable string persisted for this address (never a loopback proxy URL). */
    val stored: String
        get() = when (this) {
            is P2p -> InviteLink.P2P_PREFIX + nodeId
            is Https -> url
        }
}

/** An invite (or a bare address) after validation. */
data class ParsedInvite(val address: SkwodAddress, val joinCode: String?, val relayHint: String? = null)

/**
 * The last known home relay of each p2p host (`&r=` in a link, or `relay_url` from
 * `GET /api/instance/p2p`). Used to dial a host at once without a lookup, and put into the links
 * this device shares. Only allow-listed relays ([InviteLink.allowedRelay]) are ever stored; a relay
 * URL names one of n0's public relays, never the host's IP. In memory: a hint is an optimisation,
 * and the DHT / n0 lookup still finds the host without it.
 */
object RelayHints {
    private val hints = java.util.concurrent.ConcurrentHashMap<String, String>()
    fun get(nodeId: String): String? = hints[nodeId]
    fun set(nodeId: String, relay: String?) {
        InviteLink.allowedRelay(relay ?: return)?.let { hints[nodeId] = it }
    }
}

class InviteException(val reason: Reason) : Exception(reason.message) {
    enum class Reason(val message: String) {
        Empty("Paste the invite link your host sent you."),
        TooLong("That link is too long to be a Skwod invite."),
        NotAnInvite("That doesn't look like a Skwod invite. It should start with https://skwod.io/join# or skwod://join/ (or be an https:// address)."),
        InsecureAddress("Skwod only connects to https:// addresses or skwod:// invites."),
        BadCode("The code in that link isn't valid. Ask your host for a fresh invite."),
    }
}

/**
 * Parsing + validation for everything that can name a skwod: a tapped `skwod://` deep link, a
 * tapped or pasted `https://skwod.io/join#…` share link, a scanned QR code, pasted text. All of these are **untrusted input** — a link can come from
 * anyone — so nothing here touches the network, and anything that is not exactly one of the two
 * accepted shapes is refused rather than "fixed up". Pure Kotlin so it is unit-tested on the JVM;
 * the Rust core re-checks the node id when it is dialed.
 */
object InviteLink {
    const val P2P_PREFIX = "skwod://join/"
    /**
     * The share form, `https://skwod.io/join#<node id>[.<join code>][&u=https://…]`: what Share /
     * Copy / the QR code hand out (build 42 on). It names the same thing as
     * `skwod://join/<node id>#<code>`; the whole invite is in the URL fragment, which is never
     * sent to skwod.io. Grammar: `core/skwod-net/src/invite.rs`.
     */
    const val SHARE_ORIGIN = "https://skwod.io"
    private const val SHARE_PATH = "/join"
    /** Longest input we will even look at. A real invite is ~80 characters (~300 with a fallback). */
    const val MAX_LENGTH = 1024
    /** z-base-32 alphabet: an iroh node id is 32 bytes = 52 of these characters. */
    private const val ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"
    private const val NODE_ID_LENGTH = 52

    fun parse(raw: String): ParsedInvite {
        val text = raw.trim()
        if (text.isEmpty()) throw InviteException(InviteException.Reason.Empty)
        if (text.toByteArray().size > MAX_LENGTH) throw InviteException(InviteException.Reason.TooLong)
        // No control characters or interior whitespace: those only show up in crafted input.
        if (text.any { it.isISOControl() || it.isWhitespace() }) throw InviteException(InviteException.Reason.NotAnInvite)

        if (text.startsWith("skwod:", ignoreCase = true)) return parseP2p(text)
        // skwod.io is the invite page, never a server: a link to it is a share link or nothing.
        // Routing on the origin (not on "looks like a share link") means a mangled share link is
        // refused instead of being treated as the address of a server called skwod.io.
        if (isOnShareOrigin(text)) return parseShare(text)

        // Classic `<address>#<code>` (VPS hosts), or a bare address for log-in.
        val hash = text.indexOf('#')
        val server = normalizedServer(if (hash >= 0) text.substring(0, hash) else text, allowLoopbackHttp = true)
        var code: String? = null
        if (hash >= 0) {
            // Older links may carry a trailing `~b.<pubkey>.<key>` beacon suffix; it is ignored now.
            val c = InviteBeacon.strip(text.substring(hash + 1))
            if (!isValidCode(c)) throw InviteException(InviteException.Reason.BadCode)
            code = c
        }
        return ParsedInvite(SkwodAddress.Https(server), code)
    }

    /**
     * True for `https://skwod.io`, alone or followed by a path, query, fragment or port. A
     * look-alike host (`skwod.io.example`, `chat.skwod.io`) is not on the share origin.
     */
    fun isOnShareOrigin(text: String): Boolean {
        if (!text.startsWith(SHARE_ORIGIN, ignoreCase = true)) return false
        val next = text.getOrNull(SHARE_ORIGIN.length) ?: return true
        return next == '/' || next == '#' || next == '?' || next == ':'
    }

    /** `skwod://join/<52-char node id>[?u=https://…&l=…][#<join code>]` — nothing else. */
    private fun parseP2p(text: String): ParsedInvite {
        if (!text.startsWith(P2P_PREFIX, ignoreCase = true)) throw InviteException(InviteException.Reason.NotAnInvite)
        var rest = text.substring(P2P_PREFIX.length)
        var code: String? = null
        val hash = rest.indexOf('#')
        if (hash >= 0) {
            val c = InviteBeacon.strip(rest.substring(hash + 1))
            rest = rest.substring(0, hash)
            if (c.isNotEmpty()) {
                if (!isValidCode(c)) throw InviteException(InviteException.Reason.BadCode)
                code = c
            }
        }
        var query = ""
        val q = rest.indexOf('?')
        if (q >= 0) { query = rest.substring(q + 1); rest = rest.substring(0, q) }
        return p2pInvite(rest.trimEnd('/'), query, code)
    }

    /**
     * `https://skwod.io/join#<52-char node id>[.<join code>][&u=https://…&l=…]` — nothing else.
     * Exactly that origin and path, and nothing before the `#`: a query string would be sent to
     * the web server, so a link carrying one is refused rather than parsed around.
     */
    private fun parseShare(text: String): ParsedInvite {
        val prefix = SHARE_ORIGIN + SHARE_PATH
        if (!text.startsWith(prefix, ignoreCase = true)) throw InviteException(InviteException.Reason.NotAnInvite)
        var rest = text.substring(prefix.length)
        rest = when {
            rest.startsWith("#") -> rest.substring(1)
            rest.startsWith("/#") -> rest.substring(2)
            else -> throw InviteException(InviteException.Reason.NotAnInvite)
        }
        var params = ""
        val amp = rest.indexOf('&')
        if (amp >= 0) { params = rest.substring(amp + 1); rest = rest.substring(0, amp) }
        var code: String? = null
        val dot = rest.indexOf('.')
        if (dot >= 0) {
            val c = rest.substring(dot + 1)
            rest = rest.substring(0, dot)
            if (c.isNotEmpty()) {
                if (!isValidCode(c)) throw InviteException(InviteException.Reason.BadCode)
                code = c
            }
        }
        return p2pInvite(rest, params, code)
    }

    /** The part both spellings share: the node id, and the `u=` / `l=` parameters. */
    private fun p2pInvite(rawNodeId: String, query: String, code: String?): ParsedInvite {
        val nodeId = rawNodeId.lowercase()
        if (nodeId.length != NODE_ID_LENGTH || nodeId.any { it !in ZBASE32 }) {
            throw InviteException(InviteException.Reason.NotAnInvite)
        }
        // `?u=` is an https address of the same skwod (a host that also has a domain). Anything
        // that is not a clean https URL is dropped, never "repaired". Other params are ignored.
        var fallback: String? = null
        for (pair in query.split('&')) {
            if (!pair.startsWith("u=")) continue
            val value = pair.substring(2)
            fallback = if (!value.startsWith("https://")) null
                else try { normalizedServer(value, allowLoopbackHttp = false) } catch (_: InviteException) { null }
            break
        }
        // `r=`: the host's home relay (build 48). Allow-listed n0 relays only; anything else is
        // dropped. Remembered so the dial goes straight through it.
        val relay = query.split('&').firstOrNull { it.startsWith("r=") }?.substring(2)?.let { allowedRelay(it) }
        if (relay != null) RelayHints.set(nodeId, relay)
        return ParsedInvite(SkwodAddress.P2p(nodeId, fallback), code, relay)
    }

    /**
     * `https://<host>/` (lowercase, no trailing dot) if [url] names an allow-listed relay
     * (`*.relay.n0.iroh.link`) with no port, path, query or credentials; else null. Same rule as
     * `is_allowed_relay` in core/skwod-net/src/invite.rs and RELAY in the website's invite.js.
     */
    fun allowedRelay(url: String): String? {
        if (!url.startsWith("https://", ignoreCase = true)) return null
        val host = url.substring(8).removeSuffix("/").removeSuffix(".").lowercase()
        if (host.isEmpty() || host.length > 253) return null
        if (!host.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' }) return null
        if (host.split('.').any { it.isEmpty() || it.length > 63 || it.startsWith('-') || it.endsWith('-') }) return null
        val suffix = ".relay.n0.iroh.link"
        if (host.length <= suffix.length || !host.endsWith(suffix)) return null
        return "https://$host/"
    }

    /** Join codes are server-minted: `SKWD-XXXX-XXXX`, or a URL-safe token. */
    fun isValidCode(code: String): Boolean =
        code.length in 1..128 && code.all { (it in 'a'..'z') || (it in 'A'..'Z') || (it in '0'..'9') || it == '-' || it == '_' }

    /**
     * Normalize a typed server address to a base URL, or refuse it. `https://` only — except
     * `http://127.0.0.1`, which never leaves this device (and is the only cleartext destination
     * the network security config allows).
     */
    fun normalizedServer(raw: String, allowLoopbackHttp: Boolean): String {
        var s = raw.trim()
        if (s.isEmpty()) throw InviteException(InviteException.Reason.Empty)
        if (!s.contains("://")) s = "https://$s"
        while (s.endsWith("/")) s = s.dropLast(1)
        val uri = try { URI(s) } catch (_: Exception) { throw InviteException(InviteException.Reason.NotAnInvite) }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()
        if (scheme == null || host.isNullOrEmpty() || uri.userInfo != null || uri.query != null || uri.fragment != null) {
            throw InviteException(InviteException.Reason.NotAnInvite)
        }
        when (scheme) {
            "https" -> {}
            "http" -> if (!allowLoopbackHttp || host != "127.0.0.1") throw InviteException(InviteException.Reason.InsecureAddress)
            else -> throw InviteException(InviteException.Reason.NotAnInvite)
        }
        return s
    }

    /**
     * Build the link people share: `https://skwod.io/join#<node>[.<code>][&u=https://…]`.
     * Use this for Copy, Share and QR codes. Builds ≤ 41 cannot parse it when pasted, but the
     * page it opens forwards to the `skwod://` form, which they handle.
     */
    fun shareLink(nodeId: String, joinCode: String?, fallbackUrl: String? = null, relayUrl: String? = RelayHints.get(nodeId)): String? {
        var link = "$SHARE_ORIGIN$SHARE_PATH#$nodeId"
        if (!joinCode.isNullOrEmpty()) link += ".$joinCode"
        if (fallbackUrl != null && fallbackUrl.startsWith("https://")) link += "&u=$fallbackUrl"
        relayUrl?.let { allowedRelay(it) }?.let { link += "&r=$it" }
        // Round-trip through the parser so we never hand out a link we would refuse ourselves.
        return try { parse(link); link } catch (_: InviteException) { null }
    }

    /**
     * Build the app-scheme form: `skwod://join/<node>[?u=https://…]#<code>`. This is what the app
     * registers and stores; hand out [shareLink] instead.
     */
    fun format(nodeId: String, joinCode: String?, fallbackUrl: String? = null): String? {
        var link = P2P_PREFIX + nodeId
        if (fallbackUrl != null && fallbackUrl.startsWith("https://")) link += "?u=$fallbackUrl"
        if (!joinCode.isNullOrEmpty()) link += "#$joinCode"
        // Round-trip through the parser so we never hand out a link we would refuse ourselves.
        return try { parse(link); link } catch (_: InviteException) { null }
    }

    /** A short, human-comparable form of a host key, for "is this the right host?" displays. */
    fun shortKey(nodeId: String): String =
        if (nodeId.length > 12) "${nodeId.take(6)}…${nodeId.takeLast(6)}" else nodeId
}

/**
 * Older invite links carried `~b.<pubkey>.<contentKey>` after the code (a Nostr "beacon" used to
 * find a host whose tunnel address had moved). A p2p address is a key and never moves, so new
 * invites have no beacon; classic https workspaces that joined with one keep using it.
 */
object InviteBeacon {
    const val MARKER = "~b."

    fun appended(link: String, pubkey: String?, contentKey: String?): String =
        if (!pubkey.isNullOrEmpty() && !contentKey.isNullOrEmpty()) "$link$MARKER$pubkey.$contentKey" else link

    /** Split a post-`#` code portion into (code, beaconPubkey?, contentKey?). */
    fun parse(codePortion: String): Triple<String, String?, String?> {
        val i = codePortion.indexOf(MARKER)
        if (i < 0) return Triple(codePortion, null, null)
        val code = codePortion.substring(0, i)
        val rest = codePortion.substring(i + MARKER.length)
        val dot = rest.indexOf('.')
        if (dot < 0) return Triple(code, null, null)
        return Triple(code, rest.substring(0, dot), rest.substring(dot + 1))
    }

    /** Just the code, with any beacon suffix stripped — for sites that only consume the code. */
    fun strip(codePortion: String): String = parse(codePortion).first
}
