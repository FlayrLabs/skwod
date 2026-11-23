package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Rules for content chosen by the sender of a message: links, music-card URLs, attachments. */
class ContentSafetyTest {

    // ---- links ----

    @Test fun onlyWebAndMailAddressesAreLinks() {
        assertNotNull(LinkPolicy.openable("https://example.com/a?b=c#d"))
        assertNotNull(LinkPolicy.openable("http://example.com"))
        assertNotNull(LinkPolicy.openable("HTTPS://EXAMPLE.COM"))
        assertNotNull(LinkPolicy.openable("mailto:sam@example.com"))
        for (bad in listOf(
            "file:///data/data/com.skwod.app/files/skwod.sqlite3", "content://com.skwod.app.fileprovider/attachments/x",
            "intent://scan/#Intent;scheme=zxing;end", "javascript:alert(1)", "tel:+15551234", "sms:+15551234",
            "skwod://join/abc", "market://details?id=x", "data:text/html,hi", "ftp://example.com/x",
            "https://", "https:///nohost", "example.com", "", "   ", "https://exa mple.com", "https://example.com/\u0000",
            "mailto:", "x".repeat(3000),
        )) assertNull("must not be a link: $bad", LinkPolicy.openable(bad))
    }

    @Test fun aLabelThatHidesItsAddressGetsTheRealAddressBesideIt() {
        val pieces = LinkPolicy.pieces("Reset here: [skwod.io/reset](https://evil.example/x) now")
        assertEquals(3, pieces.size)
        val link = pieces[1] as LinkPolicy.Piece.Link
        assertEquals("skwod.io/reset", link.label)
        assertEquals("https://evil.example/x", link.url)
        assertEquals("https://evil.example/x", link.shownTarget)
        assertEquals(LinkPolicy.Piece.Text("Reset here: "), pieces[0])
        assertEquals(LinkPolicy.Piece.Text(" now"), pieces[2])
    }

    @Test fun aLabelThatIsItsOwnAddressIsNotRepeated() {
        for (s in listOf("[https://example.com/a](https://example.com/a)", "[example.com/a](https://example.com/a/)", "[Example.com](http://example.com)")) {
            val link = LinkPolicy.pieces(s).single() as LinkPolicy.Piece.Link
            assertNull(s, link.shownTarget)
        }
        assertTrue(LinkPolicy.labelMatches("sam@example.com", "mailto:sam@example.com"))
        assertFalse(LinkPolicy.labelMatches("example.com", "https://example.com.evil.test"))
        assertFalse(LinkPolicy.labelMatches("https://example.com", "https://examp1e.com"))
    }

    @Test fun aLinkToAnythingElseIsPlainText() {
        for (target in listOf("file:///sdcard/x", "intent://x#Intent;end", "javascript:alert(1)", "skwod://join/abc", "content://x/y")) {
            val pieces = LinkPolicy.pieces("see [this]($target) ok")
            assertEquals("no link for $target", listOf(LinkPolicy.Piece.Text("see this ok")), pieces)
        }
    }

    @Test fun parenthesesInsideATargetBelongToIt() {
        val link = LinkPolicy.pieces("[wiki](https://en.wikipedia.org/wiki/Rust_(language)) rest")[0] as LinkPolicy.Piece.Link
        assertEquals("https://en.wikipedia.org/wiki/Rust_(language)", link.url)
        assertEquals(listOf(LinkPolicy.Piece.Text("[a](https://example.com\nx)")), LinkPolicy.pieces("[a](https://example.com\nx)"))
    }

    @Test fun textWithoutLinksIsLeftAlone() {
        assertEquals(listOf(LinkPolicy.Piece.Text("a [b] (c) [d]( e")), LinkPolicy.pieces("a [b] (c) [d]( e"))
        assertEquals(listOf(LinkPolicy.Piece.Text("**bold** and `code`")), LinkPolicy.pieces("**bold** and `code`"))
        assertEquals(emptyList<LinkPolicy.Piece>(), LinkPolicy.pieces(""))
        // A bare address is never auto-linked (same as the Apple app's inline-only markdown).
        assertEquals(listOf(LinkPolicy.Piece.Text("go to https://example.com")), LinkPolicy.pieces("go to https://example.com"))
    }

    // ---- music-card hosts (must match Apple's MusicTrack.isAppleHost) ----

    @Test fun musicUrlsAreOnlyEverOnApplesHosts() {
        for (ok in listOf(
            "https://music.apple.com/us/album/x/1?i=2", "https://apple.com/x", "https://itunes.apple.com/x",
            "https://is1-ssl.mzstatic.com/image/thumb/a.jpg", "https://mzstatic.com/a", "https://audio-ssl.itunes.apple.com/p.m4a",
            "https://MUSIC.APPLE.COM/x", "https://music.apple.com:443/x",
        )) assertTrue("should be allowed: $ok", MusicHosts.isAppleHost(ok))
        for (bad in listOf(
            "http://music.apple.com/x",                       // not https
            "https://music.apple.com.evil.test/x",            // suffix trick
            "https://evilapple.com/x", "https://notmzstatic.com/a", "https://apple.com.evil/x",
            "https://user:pw@music.apple.com/x", "https://user@music.apple.com/x",   // credentials
            "https://music.apple.com@evil.test/x",            // the host is evil.test
            "https://music.apple.com:8443/x",                 // non-default port
            "https://evil.test/music.apple.com", "https://evil.test/?u=https://music.apple.com",
            "file:///music.apple.com", "intent://music.apple.com#Intent;end", "content://music.apple.com/x",
            "https://", "music.apple.com", "", "https://music.apple.com /x",
        )) assertFalse("should be refused: $bad", MusicHosts.isAppleHost(bad))
        assertFalse(MusicHosts.isAppleHost(null))
        assertNull(MusicHosts.safe("https://evil.test/a.jpg"))
        assertEquals("https://music.apple.com/x", MusicHosts.safe("https://music.apple.com/x"))
    }

    @Test fun aMusicCardOffersOnlyAppleUrls() {
        val t = MusicTrack.fromJson("""{"title":"T","artist":"A","url":"https://evil.test/x","artworkUrl":"https://is1-ssl.mzstatic.com/a.jpg","previewUrl":"http://audio-ssl.itunes.apple.com/p.m4a"}""")!!
        assertNull(t.safeUrl)
        assertEquals("https://is1-ssl.mzstatic.com/a.jpg", t.safeArtworkUrl)
        assertNull(t.safePreviewUrl)
        // The Apple app's field spellings.
        val apple = MusicTrack.fromJson("""{"title":"T","artist":"A","appleMusicURL":"https://music.apple.com/x","artworkURL":"https://evil.test/a.jpg"}""")!!
        assertEquals("https://music.apple.com/x", apple.safeUrl)
        assertNull(apple.safeArtworkUrl)
    }

    // ---- attachments that would install or run ----

    private val mimeOf: (String) -> String? = { ext ->
        mapOf("pdf" to "application/pdf", "jpg" to "image/jpeg", "txt" to "text/plain", "apk" to "application/vnd.android.package-archive")[ext]
    }
    private val zipHead = byteArrayOf('P'.code.toByte(), 'K'.code.toByte(), 3, 4)
    private fun apkHead() = zipHead + ByteArray(26) + "AndroidManifest.xml".toByteArray()

    @Test fun anApkIsRecognisedByNameMimeOrContent() {
        for (name in listOf("app.apk", "APP.APK", "app.apk ", "app.apk.", "update.apks", "x.xapk", "x.apkm", "bundle.aab", "photo.apk.jpg", "lib.so", "classes.dex", "tool.jar"))
            assertTrue("by name: $name", AttachmentOpenPolicy.isInstallable(name, "application/octet-stream"))
        assertTrue(AttachmentOpenPolicy.isInstallable("holiday.jpg", "application/vnd.android.package-archive"))
        assertTrue(AttachmentOpenPolicy.isInstallable("holiday.jpg", "Application/VND.android.package-archive; charset=x"))
        assertTrue(AttachmentOpenPolicy.isInstallable("holiday.jpg", "image/jpeg", apkHead()))
        assertTrue(AttachmentOpenPolicy.isInstallable("file", null, apkHead()))
        for (name in listOf("holiday.jpg", "notes.txt", "report.pdf", "apk", "my apk notes.txt", "file"))
            assertFalse("not a package: $name", AttachmentOpenPolicy.isInstallable(name, "application/octet-stream"))
        // An ordinary zip (or docx) is not an apk.
        assertFalse(AttachmentOpenPolicy.isInstallable("docs.zip", "application/zip", zipHead + "word/document.xml".toByteArray()))
        assertFalse(AttachmentOpenPolicy.looksLikeApk("AndroidManifest.xml".toByteArray()))
    }

    @Test fun anApkIsNeverGivenATypeToOpenWith() {
        assertNull(AttachmentOpenPolicy.viewMime("app.apk", "image/jpeg", null, mimeOf))
        assertNull(AttachmentOpenPolicy.viewMime("holiday.jpg", "application/vnd.android.package-archive", null, mimeOf))
        assertNull(AttachmentOpenPolicy.viewMime("holiday.jpg", "image/jpeg", apkHead(), mimeOf))
        // Everything else opens by ITS OWN extension, never the sender's claimed type.
        assertEquals("application/pdf", AttachmentOpenPolicy.viewMime("report.pdf", "text/html", null, mimeOf))
        assertEquals("image/jpeg", AttachmentOpenPolicy.viewMime("holiday.jpg", "application/pdf", zipHead, mimeOf))
        assertEquals("application/octet-stream", AttachmentOpenPolicy.viewMime("data.unknownext", "image/png", null, mimeOf))
        assertEquals("application/octet-stream", AttachmentOpenPolicy.viewMime("noext", "image/png", null, mimeOf))
    }

    // ---- safety number ----

    // The QR payload and its (directional) comparison are the core's: see skwod-crypto
    // `safety_qr_matches_only_across_the_two_parties` and the live verification test.
    @Test fun theSafetyNumberIsGroupedForReading() {
        val digits = "123456789012345678901234567890123456789012345678901234567890"
        assertEquals("12345 67890 12345 67890\n12345 67890 12345 67890\n12345 67890 12345 67890", SafetyNumberFormat.grouped(digits))
    }

    // ---- image bounds (the pure parts of SafeImage) ----

    @Test fun implausibleImageSizesAreRefusedFromTheHeader() {
        assertTrue(SafeImage.plausible(4032, 3024))
        assertTrue(SafeImage.plausible(8000, 8000))
        assertFalse(SafeImage.plausible(60_000, 60_000))
        assertFalse(SafeImage.plausible(65_536, 1))
        assertFalse(SafeImage.plausible(0, 100))
        assertFalse(SafeImage.plausible(-1, -1))            // what inJustDecodeBounds reports for a non-image
        assertFalse(SafeImage.plausible(Int.MAX_VALUE, Int.MAX_VALUE))
        assertEquals(1, SafeImage.sampleSize(1000, 800, 2048))
        assertEquals(2, SafeImage.sampleSize(4032, 3024, 2048))
        assertEquals(4, SafeImage.sampleSize(8000, 100, 2048))
        assertEquals(16, SafeImage.sampleSize(100, 8000, 512))
    }

    @Test fun imageFormatsAreTakenFromTheBytesNotTheName() {
        fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
        assertEquals(SafeImage.Format.JPEG, SafeImage.sniff(b(0xFF, 0xD8, 0xFF, 0xE1)))
        assertEquals(SafeImage.Format.PNG, SafeImage.sniff(b(0x89, 'P'.code, 'N'.code, 'G'.code, 0x0D, 0x0A, 0x1A, 0x0A)))
        assertEquals(SafeImage.Format.GIF, SafeImage.sniff("GIF89a....".toByteArray()))
        assertEquals(SafeImage.Format.WEBP, SafeImage.sniff("RIFF\u0000\u0000\u0000\u0000WEBPVP8 ....".toByteArray(Charsets.ISO_8859_1)))
        val animated = "RIFF\u0000\u0000\u0000\u0000WEBPVP8X\u0000\u0000\u0000\u0000\u0002".toByteArray(Charsets.ISO_8859_1)
        assertEquals(SafeImage.Format.ANIMATED_WEBP, SafeImage.sniff(animated))
        assertEquals(SafeImage.Format.HEIF, SafeImage.sniff("\u0000\u0000\u0000\u0018ftypheic".toByteArray(Charsets.ISO_8859_1)))
        assertEquals(SafeImage.Format.OTHER, SafeImage.sniff("not an image".toByteArray()))
        assertEquals(SafeImage.Format.OTHER, SafeImage.sniff(ByteArray(0)))
        // Animated images are sent as they are; a still one is always re-encoded.
        assertTrue(SafeImage.sendAsIs("GIF89a".toByteArray()))
        assertTrue(SafeImage.sendAsIs(animated))
        assertFalse(SafeImage.sendAsIs(b(0xFF, 0xD8, 0xFF, 0xE1)))
    }
}
