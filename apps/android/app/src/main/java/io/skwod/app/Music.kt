package io.skwod.app

import org.json.JSONObject
import java.net.URLEncoder

/**
 * Song search for Android, the way the Apple app falls back when MusicKit is not authorized:
 * Apple's public iTunes Search API. Pure (no android.*, no FFI) — unit-tested.
 *
 * The same allowlist rules as everywhere a music card is handled ([MusicHosts]): the request
 * goes to one fixed https host, and a result's URLs (artwork, preview, "open in Apple Music")
 * are kept only when they are on Apple's own hosts. A result is the catalogue's word, but a
 * card built from it travels to other people and is shown under the same rules there, so
 * nothing that would not be shown is ever put in one.
 */
object MusicSearch {
    const val HOST = "itunes.apple.com"
    const val LIMIT = 25
    /** Largest response read (25 results are ~40 KB). */
    const val MAX_BYTES = 512 * 1024
    const val MAX_TERM = 120

    /** The search URL for `term`, or null when there is nothing to search for. */
    fun url(term: String): String? {
        val t = term.trim().take(MAX_TERM)
        if (t.isEmpty()) return null
        return "https://$HOST/search?term=${URLEncoder.encode(t, "UTF-8")}&media=music&entity=song&limit=$LIMIT"
    }

    /** Larger artwork: the API hands back 100×100; the same path serves 200×200. */
    fun artwork(url: String?): String? = url?.replace("100x100bb", "200x200bb")

    /** The songs in an iTunes Search response. Anything malformed, or with no safe link, is skipped. */
    fun parse(json: String): List<MusicTrack> {
        val results = try { JSONObject(json).optJSONArray("results") } catch (_: Exception) { null } ?: return emptyList()
        val out = ArrayList<MusicTrack>()
        for (i in 0 until minOf(results.length(), LIMIT)) {
            val r = results.optJSONObject(i) ?: continue
            if (r.optString("kind") != "song") continue
            val title = r.optString("trackName").trim().take(200)
            if (title.isEmpty()) continue
            fun str(key: String): String? = if (r.has(key) && !r.isNull(key)) r.optString(key) else null
            val track = MusicTrack(
                title = title,
                artist = r.optString("artistName").trim().take(200),
                url = MusicHosts.safe(str("trackViewUrl")),
                artworkUrl = MusicHosts.safe(artwork(str("artworkUrl100"))),
                previewUrl = MusicHosts.safe(str("previewUrl")),
                id = r.optLong("trackId", 0).takeIf { it > 0 }?.toString() ?: "",
            )
            // A card nobody could open is not offered.
            if (track.url == null) continue
            out += track
        }
        return out
    }
}
