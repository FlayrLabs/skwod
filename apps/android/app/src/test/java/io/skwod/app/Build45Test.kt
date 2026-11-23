package io.skwod.app

import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Build 45: a story's song clip (the model, its place in the encrypted payload, and the JSON the
 * Apple app writes), the host's upload limit as the app applies it, and the feed's send progress.
 */
class Build45Test {
    // The same literals are in the Apple test (`Build45Tests.swift`): each platform must read
    // what the other writes.
    /** A story as the ANDROID app writes it. */
    private val androidStory = """{"photoB64":"AAEC","music":{"id":"1440833098","title":"Song","artist":"Artist","appleMusicURL":"https://music.apple.com/us/album/x/1?i=2","artworkURL":"https://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg","previewURL":"https://audio-ssl.itunes.apple.com/itunes-assets/p.m4a"},"clip":{"startMs":7000,"durationMs":10000},"ts":1763700000000}"""
    /** A story as the APPLE app writes it (JSONEncoder). */
    private val appleStory = """{"music":{"id":"1440833098","title":"Song","artist":"Artist","artworkURL":"https:\/\/is1-ssl.mzstatic.com\/image\/thumb\/a\/200x200bb.jpg","previewURL":"https:\/\/audio-ssl.itunes.apple.com\/itunes-assets\/p.m4a","appleMusicURL":"https:\/\/music.apple.com\/us\/album\/x\/1?i=2"},"clip":{"startMs":12500,"durationMs":15000},"ts":1763700000000}"""

    private val song = MusicTrack("Song", "Artist", "https://music.apple.com/us/album/x/1?i=2",
        "https://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg", "https://audio-ssl.itunes.apple.com/itunes-assets/p.m4a", "1440833098")

    @After fun forget() = UploadLimit.reset()

    // ---- the clip model ----

    @Test fun theComposerOnlyMakesClipsOfTheOfferedLengthsInsideThePreview() {
        assertEquals(listOf(5, 10, 15), MusicClip.DURATION_CHOICES)
        assertEquals(MusicClip.of(7000, 10_000), MusicClip.chosen(7000, 10))
        // A start past the end is pulled back so the whole clip fits the 30 s preview.
        assertEquals(MusicClip.of(15_000, 15_000), MusicClip.chosen(29_000, 15))
        assertEquals(MusicClip.of(0, 5000), MusicClip.chosen(-400, 5))
        // A length that is not offered becomes the default.
        assertEquals(15_000, MusicClip.chosen(0, 12).durationMs)
        assertEquals(15_000, MusicClip.chosen(0, 0).durationMs)
        // A preview shorter than the length: the clip is the whole preview.
        assertEquals(MusicClip.of(0, 9000), MusicClip.chosen(3000, 15, previewMs = 9000))
    }

    @Test fun aClipFromSomeoneElseIsBroughtInsideTheBounds() {
        assertEquals(MusicClip.of(0, 1000), MusicClip.of(-5, 0))
        assertEquals(600_000 to 30_000, MusicClip.of(Int.MAX_VALUE, Int.MAX_VALUE).let { it.startMs to it.durationMs })
        assertEquals(0 to 1000, MusicClip.of(Int.MIN_VALUE, Int.MIN_VALUE).let { it.startMs to it.durationMs })
    }

    @Test fun playbackNeverRunsPastTheRealAudio() {
        val clip = MusicClip.of(20_000, 15_000)
        assertEquals(20_000 to 35_000, clip.window(null))
        assertEquals(15_000 to 30_000, clip.window(30_000))
        assertEquals(0 to 8000, clip.window(8000))
        assertEquals(24_500 to 29_500, MusicClip.of(599_000, 5000).window(29_500))
        assertEquals(0 to 15_000, MusicClip.FALLBACK.window(30_000))
    }

    // ---- in the encrypted payload ----

    @Test fun theClipIsWrittenBesideTheSongAsTheAppleAppReadsIt() {
        // Built the way `FeedModel.send` builds a story's payload.
        val payload = JSONObject().put("photoB64", "AAEC").put("music", JSONObject(song.toJson()))
            .put("clip", MusicClip.chosen(7000, 10).toJson()).put("ts", 1763700000000L)
        // The same object as the fixture the Apple test reads (key order is not part of JSON).
        assertTrue(payload.toString(), JSONObject(androidStory).similar(JSONObject(payload.toString())))
        val clip = payload.getJSONObject("clip")
        assertEquals(2, clip.length())
        assertEquals(7000, clip.getInt("startMs")); assertEquals(10_000, clip.getInt("durationMs"))
        assertFalse(payload.getJSONObject("music").has("clip"))
        assertEquals(MusicClip.of(7000, 10_000), MusicClip.inPayload(JSONObject(payload.toString())))
    }

    @Test fun aStoryWrittenByTheAppleAppPlaysTheSameClip() {
        val o = JSONObject(appleStory)
        assertEquals(MusicClip.of(12_500, 15_000), MusicClip.inPayload(o))
        val track = MusicTrack.fromJson(o.getJSONObject("music").toString())
        assertNotNull(track)
        assertEquals("https://audio-ssl.itunes.apple.com/itunes-assets/p.m4a", track!!.safePreviewUrl)
        assertEquals("Song", track.title); assertEquals("1440833098", track.id)
    }

    @Test fun aStoryFromBuild44HasNoClipAndStillReads() {
        val o = JSONObject("""{"music":{"id":"1","title":"Song","artist":"Artist"},"ts":5}""")
        assertNull(MusicClip.inPayload(o))
        assertEquals("Song", MusicTrack.fromJson(o.getJSONObject("music").toString())?.title)
    }

    @Test fun aClipThisBuildCannotReadIsNoClipNotALostStory() {
        for (bad in listOf("\"soon\"", "7", "null", "[1,2]", """{"startMs":"7000","durationMs":10000}""", """{"startMs":7000}""", "{}", """{"startMs":true,"durationMs":false}""")) {
            val o = JSONObject("""{"music":{"id":"1","title":"Song","artist":"Artist"},"clip":$bad,"ts":5}""")
            assertNull(bad, MusicClip.inPayload(o))
            assertEquals(bad, "Song", MusicTrack.fromJson(o.getJSONObject("music").toString())?.title)
        }
        // Numbers out of range are clamped rather than refused; decimals are read — as on Apple.
        assertEquals(MusicClip.of(0, 30_000), MusicClip.inPayload(JSONObject("""{"clip":{"startMs":-3,"durationMs":99999999999}}""")))
        assertEquals(MusicClip.of(7000, 10_000), MusicClip.inPayload(JSONObject("""{"clip":{"startMs":7000.9,"durationMs":1.0e4}}""")))
        assertEquals(MusicClip.of(600_000, 5000), MusicClip.inPayload(JSONObject("""{"clip":{"startMs":1e300,"durationMs":5000}}""")))
    }

    @Test fun onlyApplesHostsAreEverPlayed() {
        fun preview(url: String) = MusicTrack("t", "a", null, null, url).safePreviewUrl
        assertNull(preview("https://evil.example/p.m4a"))
        assertNull(preview("http://audio-ssl.itunes.apple.com/p.m4a"))
        assertNull(preview("https://audio-ssl.itunes.apple.com.evil.example/p.m4a"))
        assertNotNull(preview("https://audio-ssl.itunes.apple.com/p.m4a"))
    }

    // ---- story music goes through the host ----

    @Test fun onlyAPreviewTheHostWillFetchIsEverAskedFor() {
        fun ok(u: String) = StoryMusicPolicy.hostFetchable(u) != null
        assertTrue(ok("https://audio-ssl.itunes.apple.com/itunes-assets/AudioPreview211/v4/cd/x/mzaf_1.plus.aac.p.m4a"))
        assertEquals(song.previewUrl, StoryMusicPolicy.hostFetchable(song.previewUrl))
        for (bad in listOf("http://audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "https://evil.example/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com.evil.example/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com@evil.example/itunes-assets/a.m4a",
            "https://user:pw@audio-ssl.itunes.apple.com/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com:8443/itunes-assets/a.m4a",
            // On Apple's hosts (so the card shows it), but not the preview host: not fetched.
            "https://is1-ssl.mzstatic.com/itunes-assets/a.m4a",
            "https://music.apple.com/itunes-assets/a.m4a",
            "https://audio-ssl.itunes.apple.com/other/a.m4a",
            "https://audio-ssl.itunes.apple.com/itunes-assets/a.html",
            "https://audio-ssl.itunes.apple.com/itunes-assets/a.m4a#x",
            "https://127.0.0.1/itunes-assets/a.m4a", "")) assertFalse(bad, ok(bad))
        assertNull(StoryMusicPolicy.hostFetchable(null))
    }

    @Test fun storyMusicStartsByItselfUnlessTheViewerChoseTapToPlay() {
        val p = StoryMusicPolicy
        // Default (the setting off): fetched — through the host — as the story opens.
        assertEquals(StoryMusicPolicy.OnOpen.FETCH, p.onOpen(tapToPlay = false, tapped = false, inCall = false, hasPreview = true))
        // Tap-to-play: nothing is fetched until the tap; then it is.
        assertEquals(StoryMusicPolicy.OnOpen.WAIT_FOR_TAP, p.onOpen(tapToPlay = true, tapped = false, inCall = false, hasPreview = true))
        assertEquals(StoryMusicPolicy.OnOpen.FETCH, p.onOpen(tapToPlay = true, tapped = true, inCall = false, hasPreview = true))
        // Never during a call, tapped or not; never for a song the host will not fetch.
        for (tapToPlay in listOf(true, false)) for (tapped in listOf(true, false)) {
            assertEquals(StoryMusicPolicy.OnOpen.SILENT, p.onOpen(tapToPlay, tapped, inCall = true, hasPreview = true))
            assertEquals(StoryMusicPolicy.OnOpen.SILENT, p.onOpen(tapToPlay, tapped, inCall = false, hasPreview = false))
        }
    }

    // ---- the host's upload limit ----

    private val mib = UploadLimit.MIB

    @Test fun theServersAnswerIsReadAndBounded() {
        assertEquals(250 * mib, UploadLimit.parse("""{"max_upload_bytes":262144000,"max_upload_mb":250,"host_set":true}"""))
        assertEquals(2 * mib, UploadLimit.parse("""{"error":"that file is too large","max_upload_bytes":2097152}"""))
        assertEquals(UploadLimit.MIN_BYTES, UploadLimit.parse("""{"max_upload_bytes":1}"""))
        assertEquals(UploadLimit.MAX_BYTES, UploadLimit.parse("""{"max_upload_bytes":99999999999999999999}"""))
        assertEquals(UploadLimit.MAX_BYTES, UploadLimit.parse("""{"max_upload_bytes":9223372036854775807}"""))
        for (bad in listOf("""{"max_upload_bytes":"lots"}""", """{"max_upload_bytes":true}""", """{"max_upload_bytes":-5}""",
            """{"max_upload_bytes":0}""", """{"error":"not found"}""", "not json", "", null)) assertNull(bad, UploadLimit.parse(bad))
    }

    @Test fun aFileIsCheckedAgainstTheHostsLimitBeforeItIsSent() {
        assertTrue(UploadLimit.allowsUpload(100 * mib, UploadLimit.DEFAULT_BYTES))
        assertFalse(UploadLimit.allowsUpload(100 * mib + 1, UploadLimit.DEFAULT_BYTES))
        assertTrue(UploadLimit.allowsUpload(400 * mib, 500 * mib))
        assertFalse(UploadLimit.allowsUpload(30 * mib, 25 * mib))
        assertFalse(UploadLimit.allowsUpload(-1, 25 * mib))
        assertFalse(UploadLimit.allowsUpload(400 * mib, 500 * mib, inMemory = true))
        assertTrue(UploadLimit.allowsUpload(100 * mib, 500 * mib, inMemory = true))
        assertFalse(UploadLimit.allowsUpload(30 * mib, 25 * mib, inMemory = true))
    }

    @Test fun loweringTheLimitNeverLocksOutFilesThatAreAlreadyThere() {
        assertEquals(100 * mib, UploadLimit.downloadCap(25 * mib))
        assertEquals(500 * mib, UploadLimit.downloadCap(500 * mib))
        assertEquals(UploadLimit.MAX_BYTES, UploadLimit.downloadCap(Long.MAX_VALUE))
    }

    @Test fun aHugeServerLimitNeverRaisesWhatIsHeldInMemory() {
        for (limit in listOf(100 * mib, 500 * mib, 1900 * mib, 1L shl 40, Long.MAX_VALUE)) {
            assertEquals(100 * mib, UploadLimit.inMemoryDownloadCap(limit))
            assertTrue(UploadLimit.downloadCap(limit) <= UploadLimit.MAX_BYTES)
        }
        assertEquals(100 * mib, UploadLimit.inMemoryDownloadCap(25 * mib))
        // With the largest limit a server can make the app believe in force:
        UploadLimit.learned(Long.MAX_VALUE, "ws")
        assertEquals(UploadLimit.MAX_BYTES, UploadLimit.current)
        assertEquals(100 * mib, UploadLimit.inMemoryDownloadCap())
        // …the streamed path follows it, a feed picture (decoded in memory) does not.
        assertTrue(AttachmentLimits.acceptable(1500 * mib))
        assertFalse(AttachmentLimits.acceptable(1500 * mib, AttachmentLimits.MAX_BYTES))
        assertTrue(AttachmentLimits.maxCiphertext(1500 * mib) >= 1500 * mib)
        // …and nothing over the fixed bound is ever fetched without being asked, on any network.
        assertTrue(AttachmentLimits.mayAutoDownload("image", 50 * mib, inFeed = false, metered = false))
        assertFalse(AttachmentLimits.mayAutoDownload("image", 101 * mib, inFeed = false, metered = false))
        assertFalse(AttachmentLimits.mayAutoDownload("image", 1500 * mib, inFeed = false, metered = false))
    }

    @Test fun theRealNumberIsWhatTheUserReads() {
        assertEquals("100 MB", UploadLimit.label(100 * mib))
        assertEquals("1 GB", UploadLimit.label(1024 * mib))
        assertEquals("1.5 GB", UploadLimit.label(1536 * mib))
        assertEquals("1.9 GB", UploadLimit.label(1900 * mib))
        assertEquals("That file is too large — this Skwod's host allows up to 250 MB per file.", UploadLimit.tooLargeSentence(250 * mib))
    }

    @Test fun eachSkwodKeepsItsOwnLimitAndAnOldServerMeansTheOldCap() {
        UploadLimit.activate("a")
        assertEquals(100 * mib, UploadLimit.current)
        UploadLimit.learned(500 * mib, "a")
        assertEquals(500 * mib, UploadLimit.current)
        UploadLimit.learned(25 * mib, "b")
        assertEquals(500 * mib, UploadLimit.current)
        UploadLimit.activate("b"); assertEquals(25 * mib, UploadLimit.current)
        UploadLimit.activate("a"); assertEquals(500 * mib, UploadLimit.current)
        UploadLimit.learned(null, "a")
        assertEquals(100 * mib, UploadLimit.current)
    }

    // ---- the feed's send progress ----

    @Test fun uploadProgressOnlyMovesForwardAndReadsAsAPercentage() {
        var s = FeedSend(FeedSend.Stage.ENCRYPTING, story = true)
        assertEquals("Encrypting your story…", s.label)
        s = s.advancedTo(0.25f)
        assertEquals(FeedSend.Stage.UPLOADING, s.stage)
        assertEquals("Uploading your story… 25%", s.label)
        // A late report from an earlier chunk does not move it back.
        assertEquals(25, s.advancedTo(0.1f).percent)
        assertEquals(100, s.advancedTo(7f).percent)
        assertTrue(s.advancedTo(1f).fraction < 1f)
        assertTrue(s.fraction > FeedSend(FeedSend.Stage.ENCRYPTING).fraction)
        assertEquals("Posting your post…", FeedSend(FeedSend.Stage.SENDING).label)
        // Sent but not yet confirmed by the host: it does not claim to be done.
        assertEquals("Finishing the upload of your story…", s.advancedTo(FeedSend.IN_FLIGHT_CEILING).label)
    }

    // ---- deleting a skwod's local data takes everything kept under its id ----

    @Test fun erasingASkwodDeletesItsMutesWithItsCacheKey() {
        val secrets = HashMap<String, String>()
        val notify = HashMap<String, Long>()
        for (id in listOf("ws-a", "ws-b")) {
            secrets[LocalData.cacheKeyName(id)] = "ab".repeat(32)
            secrets[LocalData.mutesName(id)] = """{"dm:someone":-1,"skwod":-1}"""
            notify[LocalData.seenAtName(id)] = 5L
        }
        secrets["workspaces"] = "[]"
        LocalData.forgetItems("ws-a", removeSecret = { secrets.remove(it) }, removeNotify = { notify.remove(it) })
        // Who was muted in an erased skwod is not left behind (build 45 kept it).
        org.junit.Assert.assertNull(secrets["mutes-ws-a"])
        org.junit.Assert.assertNull(secrets["cache-key-ws-a"])
        org.junit.Assert.assertFalse(secrets.keys.any { it.endsWith("ws-a") })
        org.junit.Assert.assertFalse(notify.keys.any { it.endsWith("ws-a") })
        // The other skwod and the workspace list are untouched.
        org.junit.Assert.assertEquals(setOf("cache-key-ws-b", "mutes-ws-b", "workspaces"), secrets.keys)
        org.junit.Assert.assertEquals(setOf("seenAt-ws-b"), notify.keys)
        // No id, nothing deleted.
        LocalData.forgetItems("", removeSecret = { secrets.remove(it) }, removeNotify = { notify.remove(it) })
        org.junit.Assert.assertEquals(3, secrets.size)
        // The names are the ones the stores have always used (an upgrade must find its items).
        org.junit.Assert.assertEquals(listOf("cache-key-w", "mutes-w", "announced-w", "contacts-w", "roster-w"), LocalData.secretNames("w"))
        org.junit.Assert.assertEquals(listOf("seenAt-w"), LocalData.notifyNames("w"))
    }

    @Test fun aForgottenSkwodsUploadLimitIsForgottenToo() {
        UploadLimit.learned(25 * UploadLimit.MIB, "ws-forget")
        UploadLimit.activate("ws-forget")
        org.junit.Assert.assertEquals(25 * UploadLimit.MIB, UploadLimit.current)
        UploadLimit.forget("ws-forget")
        org.junit.Assert.assertEquals(UploadLimit.DEFAULT_BYTES, UploadLimit.current)
        UploadLimit.activate("ws-forget")
        org.junit.Assert.assertEquals(UploadLimit.DEFAULT_BYTES, UploadLimit.current)
    }

    /** A contested restore request never completes by the hold: no countdown, an approval. */
    @Test
    fun aContestedRestoreWaitsForAnApprovalAndPromisesNoCountdown() {
        val now = 1_000_000_000L
        val inSevenDays = now + 7 * 86_400_000L
        assertEquals("Or wait: it completes by itself in 7 days.", RestoreWaitLine.text(inSevenDays, contested = false, nowMs = now))
        assertEquals("Waiting for approval on one of your devices.", RestoreWaitLine.text(inSevenDays, contested = true, nowMs = now))
        assertEquals("Waiting for approval on one of your devices.", RestoreWaitLine.text(null, contested = true, nowMs = now))
        assertNull("nothing until the server has said", RestoreWaitLine.text(null, contested = false, nowMs = now))
        assertFalse(RestoreWaitLine.text(inSevenDays, contested = true, nowMs = now)!!.contains("day"))
    }
}
