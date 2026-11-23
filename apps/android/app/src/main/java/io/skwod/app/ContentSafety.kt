package io.skwod.app

import java.net.URI

/*
 * Rules for content that arrives inside a message. Everything here is chosen by someone else
 * (the sender), so each rule is a pure function with a unit test — no android.* in this file.
 */

/**
 * Links inside messages. Markdown lets a sender put any label on any address
 * (`[skwod.io/reset](https://evil.example/x)`), so:
 *  1. a link whose label is not its own address is shown WITH its real address beside it;
 *  2. only web and mail links are links at all (`file:`, `intent:`, `content:`, `tel:`, custom
 *     schemes render as plain text);
 *  3. nothing opens on a tap — the full address is shown first and the user confirms.
 * The Android peer of Apple's `LinkSafety`.
 */
object LinkPolicy {
    /** The address to open for `raw`, normalised, or null if a message may not link to it. */
    fun openable(raw: String): String? {
        val t = raw.trim()
        if (t.isEmpty() || t.length > 2048 || t.any { it.isWhitespace() || it.isISOControl() }) return null
        val uri = try { URI(t) } catch (_: Exception) { return null }
        return when (uri.scheme?.lowercase()) {
            "https", "http" -> if (uri.host.isNullOrEmpty()) null else t
            "mailto" -> if (uri.schemeSpecificPart.isNullOrEmpty()) null else t
            else -> null
        }
    }

    /** Does the visible label already say where the link goes? */
    fun labelMatches(label: String, url: String): Boolean {
        fun norm(s: String): String {
            var t = s.trim().lowercase()
            for (p in listOf("https://", "http://", "mailto:")) if (t.startsWith(p)) { t = t.removePrefix(p); break }
            return t.trimEnd('/')
        }
        return norm(label) == norm(url)
    }

    /** The `)` that ends a link target starting at `from` (balanced parentheses inside the
     *  target belong to it, as in markdown), or -1. A target never spans a line. */
    private fun closingParen(s: String, from: Int): Int {
        var depth = 0
        var i = from
        while (i < s.length) {
            when (s[i]) {
                '\n' -> return -1
                '(' -> depth++
                ')' -> if (depth == 0) return i else depth--
            }
            i++
        }
        return -1
    }

    /** One piece of a message body: plain/styled text, or a link with its real target. */
    sealed class Piece {
        data class Text(val text: String) : Piece()
        /** `shownTarget` is non-null when the label does not say where the link goes. */
        data class Link(val label: String, val url: String, val shownTarget: String?) : Piece()
    }

    /**
     * Split `s` into text and `[label](target)` links. A target that is not [openable] leaves
     * the label as plain text (the brackets are dropped, nothing is clickable).
     */
    fun pieces(s: String): List<Piece> {
        val out = ArrayList<Piece>()
        val text = StringBuilder()
        fun flush() { if (text.isNotEmpty()) { out.add(Piece.Text(text.toString())); text.setLength(0) } }
        var i = 0
        while (i < s.length) {
            if (s[i] == '[') {
                val close = s.indexOf(']', i + 1)
                if (close > i + 1 && close + 1 < s.length && s[close + 1] == '(') {
                    val end = closingParen(s, close + 2)
                    val label = s.substring(i + 1, close)
                    if (end > close + 1 && !label.contains('\n')) {
                        val url = openable(s.substring(close + 2, end))
                        if (url != null) {
                            flush()
                            out.add(Piece.Link(label, url, if (labelMatches(label, url)) null else url))
                        } else {
                            text.append(label)
                        }
                        i = end + 1
                        continue
                    }
                }
            }
            text.append(s[i]); i++
        }
        flush()
        return out
    }
}

/**
 * Music cards carry URLs chosen by the sender (artwork, preview audio, "open in Apple Music").
 * They are only ever fetched from / opened on Apple's own hosts — identical to Apple's
 * `MusicTrack.isAppleHost`: https only, no credentials in the URL, default port, and a host that
 * is, or is a subdomain of, `mzstatic.com`, `apple.com` or `itunes.apple.com`.
 */
object MusicHosts {
    private val HOSTS = listOf("mzstatic.com", "apple.com", "itunes.apple.com")

    fun isAppleHost(url: String?): Boolean {
        if (url.isNullOrEmpty() || url.any { it.isWhitespace() || it.isISOControl() }) return false
        val uri = try { URI(url) } catch (_: Exception) { return false }
        if (uri.scheme?.lowercase() != "https") return false
        if (uri.userInfo != null) return false
        // `URI.host` is null for an authority it cannot parse as host[:port] (e.g. `a@b@c`).
        val host = uri.host?.lowercase() ?: return false
        if (host.isEmpty()) return false
        if (uri.port != -1 && uri.port != 443) return false
        return HOSTS.any { host == it || host.endsWith(".$it") }
    }

    /** `url` if it is on an Apple host, else null. */
    fun safe(url: String?): String? = if (isAppleHost(url)) url else null
}

/**
 * What may happen to a decrypted attachment once it is on disk.
 *
 * An attachment's name and type are the sender's claim. This app holds
 * `REQUEST_INSTALL_PACKAGES` (for its own verified self-update), so handing an `.apk` a member
 * sent to `ACTION_VIEW` would put the system installer one tap away, with this app as the
 * trusted source. Packages — and anything else the system would install or execute — are never
 * opened; they can only be shared out as an opaque file.
 */
object AttachmentOpenPolicy {
    /** Extensions the platform installs or runs. */
    private val PACKAGE_EXT = setOf("apk", "apks", "apkm", "xapk", "aab", "apex")
    private val INSTALLABLE_EXT = PACKAGE_EXT + setOf("dex", "jar", "so")
    private val INSTALLABLE_MIME = setOf(
        "application/vnd.android.package-archive",
        "application/vnd.apkm",
        "application/xapk-package-archive",
        "application/java-archive",
        "application/x-dex",
    )

    /** `PK\x03\x04` zip + an `AndroidManifest.xml` / `classes.dex` entry name in the first bytes. */
    fun looksLikeApk(head: ByteArray): Boolean {
        if (head.size < 4 || head[0] != 'P'.code.toByte() || head[1] != 'K'.code.toByte()) return false
        val s = String(head, Charsets.ISO_8859_1)
        return s.contains("AndroidManifest.xml") || s.contains("classes.dex") || s.contains("META-INF/MANIFEST.MF")
    }

    fun isInstallable(fileName: String, claimedMime: String?, head: ByteArray? = null): Boolean {
        // A package extension anywhere in the name counts ("photo.apk.jpg" is odd enough), and
        // "x.APK " or "x.apk." must not slip past either.
        val parts = fileName.lowercase().trim().trimEnd('.', ' ').split('.').drop(1).map { it.trim() }
        if (parts.lastOrNull() in INSTALLABLE_EXT || parts.any { it in PACKAGE_EXT }) return true
        val mime = claimedMime?.lowercase()?.substringBefore(';')?.trim()
        if (mime != null && mime in INSTALLABLE_MIME) return true
        return head != null && looksLikeApk(head)
    }

    /**
     * The MIME type to open a decrypted file with, or null when it must not be opened at all
     * (only shared as a file). Derived from the file's own extension — never the sender's claim.
     */
    fun viewMime(fileName: String, claimedMime: String?, head: ByteArray?, extensionMime: (String) -> String?): String? {
        if (isInstallable(fileName, claimedMime, head)) return null
        val ext = fileName.substringAfterLast('.', "").lowercase()
        val mime = extensionMime(ext)?.lowercase() ?: return "application/octet-stream"
        return if (mime in INSTALLABLE_MIME) null else mime
    }
}

/**
 * How the safety number is written out. (The QR payload and its comparison live in the core —
 * `safetyQr` / `checkSafetyQr` — because the code is directional and both platforms must agree.)
 */
object SafetyNumberFormat {
    /** 12 blocks of 5 digits, four to a line. */
    fun grouped(s: String): String = s.chunked(5).chunked(4).joinToString("\n") { it.joinToString(" ") }
}
