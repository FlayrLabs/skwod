package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Build 44 "content": the pure rules behind the outbox overlay, story expiry and music search. */
class ContentBatchTest {
    // ---- outbox ----

    @Test fun queuedSendsGetAStateAndFailedChangesAreReportedOnce() {
        val view = OutboxPolicy.view(listOf(
            OutboxPolicy.Row("l1", "m1", "send", "sending", null),
            OutboxPolicy.Row("l2", "m2", "send", "failed", "That is too big to send."),
            OutboxPolicy.Row("l3", "m3", "send", "failed", "  "),
            OutboxPolicy.Row("l4", "m1", "edit", "sending", null),
            OutboxPolicy.Row("l5", "m9", "delete", "failed", "You are not allowed to do that here."),
            OutboxPolicy.Row("l6", "m9", "reaction", "failed", null),
        ))
        assertEquals(SendState.Sending, view.byMessage["m1"])
        assertEquals(SendState.Failed("l2", "That is too big to send."), view.byMessage["m2"])
        assertEquals(SendState.Failed("l3", "This message wasn't sent."), view.byMessage["m3"])
        // An edit / delete / reaction has no row of its own: no state…
        assertNull(view.byMessage["m9"])
        assertEquals(3, view.byMessage.size)
        // …its sentence is shown (the first one) and the dead entries are dropped.
        assertEquals("You are not allowed to do that here.", view.problem)
        assertEquals(listOf("l5", "l6"), view.toDiscard)
        // A pending edit is neither a problem nor discarded.
        assertFalse("l4" in view.toDiscard)
    }

    @Test fun nothingQueuedIsNothingShown() {
        val view = OutboxPolicy.view(emptyList())
        assertTrue(view.byMessage.isEmpty()); assertNull(view.problem); assertTrue(view.toDiscard.isEmpty())
        assertEquals("That message is too big to send.", OutboxPolicy.queueError("that message is too big to send."))
        assertEquals("Couldn't send — try again.", OutboxPolicy.queueError(null))
        assertEquals("Couldn't forward.", OutboxPolicy.queueError(" ", "Couldn't forward."))
    }

    // ---- DM replies ----

    @Test fun aReplyPreviewQuotesOnlyTheTwoParticipants() {
        val (me, peer) = "me-id" to "peer"
        assertTrue(DmReplyPolicy.quotable("__me__", false, me, peer))
        assertTrue(DmReplyPolicy.quotable("me-id", false, me, peer))          // my other device
        assertTrue(DmReplyPolicy.quotable("peer", false, me, peer))
        // A third account filed under this conversation id, a system notice, an authorless row:
        assertFalse(DmReplyPolicy.quotable("ghost", false, me, peer))
        assertFalse(DmReplyPolicy.quotable("__system__", false, me, peer))
        assertFalse(DmReplyPolicy.quotable(null, false, me, peer))
        assertFalse(DmReplyPolicy.quotable("peer", true, me, peer))           // deleted
        // Attribution: "you" only for my own rows.
        assertTrue(DmReplyPolicy.mine("__me__", me)); assertTrue(DmReplyPolicy.mine("me-id", me))
        assertFalse(DmReplyPolicy.mine("peer", me)); assertFalse(DmReplyPolicy.mine("me-id", null))
    }

    // ---- stories ----

    @Test fun aStoryLivesTwentyFourHoursOfServerTime() {
        val posted = 1_763_510_400_000L
        assertTrue(StoryClock.live(posted, posted))
        assertTrue(StoryClock.live(posted, posted + StoryClock.TTL_MS - 1))
        assertFalse(StoryClock.live(posted, posted + StoryClock.TTL_MS))
        // A sender cannot make a story immortal by claiming a time: only createdAt (the
        // server's) is ever passed here, and a server time in the "future" is simply live.
        assertTrue(StoryClock.live(posted + 5_000, posted))
        assertFalse(StoryClock.live(posted, posted + 1_000, ttl = 1_000))
    }

    // ---- music ----

    private val itunes = """
        {"resultCount":4,"results":[
          {"wrapperType":"track","kind":"song","trackId":123,"artistName":"Nina Simone","trackName":"Feeling Good",
           "trackViewUrl":"https://music.apple.com/us/album/feeling-good/1?i=123","previewUrl":"https://audio-ssl.itunes.apple.com/p.m4a",
           "artworkUrl100":"https://is1-ssl.mzstatic.com/image/thumb/a/100x100bb.jpg"},
          {"wrapperType":"track","kind":"song","trackId":124,"artistName":"Evil","trackName":"Phish",
           "trackViewUrl":"https://music.apple.com.evil.example/x","previewUrl":"http://audio.itunes.apple.com/p.m4a",
           "artworkUrl100":"https://mzstatic.com@evil.example/100x100bb.jpg"},
          {"wrapperType":"track","kind":"song","trackId":125,"artistName":"Half","trackName":"Good Link Bad Art",
           "trackViewUrl":"https://music.apple.com/us/album/x/2?i=125","artworkUrl100":"https://evil.example/100x100bb.jpg"},
          {"wrapperType":"track","kind":"music-video","trackName":"A video"},
          {"wrapperType":"track","kind":"song","trackName":"   ","trackViewUrl":"https://music.apple.com/x"}
        ]}
    """.trimIndent()

    @Test fun searchResultsKeepOnlyAppleLinks() {
        val found = MusicSearch.parse(itunes)
        assertEquals(listOf("Feeling Good", "Good Link Bad Art"), found.map { it.title })
        val song = found[0]
        assertEquals("Nina Simone", song.artist)
        assertEquals("123", song.id)
        assertEquals("https://music.apple.com/us/album/feeling-good/1?i=123", song.url)
        assertEquals("https://is1-ssl.mzstatic.com/image/thumb/a/200x200bb.jpg", song.artworkUrl)
        assertEquals("https://audio-ssl.itunes.apple.com/p.m4a", song.previewUrl)
        // A result whose only link is off Apple's hosts is not offered at all; one with a good
        // link and bad artwork keeps the link and loses the artwork.
        assertNull(found[1].artworkUrl); assertNull(found[1].previewUrl)
        assertTrue(MusicSearch.parse("not json").isEmpty())
        assertTrue(MusicSearch.parse("{}").isEmpty())
    }

    @Test fun theSearchGoesToOneAppleHostAndNowhereElse() {
        val url = MusicSearch.url("  feeling good & more/../x?y=1  ")!!
        assertTrue(url.startsWith("https://itunes.apple.com/search?term=feeling+good+%26+more%2F..%2Fx%3Fy%3D1&"))
        assertTrue(MusicHosts.isAppleHost(url))
        assertTrue(url.endsWith("&media=music&entity=song&limit=25"))
        assertNull(MusicSearch.url("   "))
        assertEquals(MusicSearch.MAX_TERM, java.net.URLDecoder.decode(MusicSearch.url("a".repeat(500))!!.substringAfter("term=").substringBefore("&"), "UTF-8").length)
    }

    @Test fun aCardWrittenHereReadsTheSameOnApple() {
        val song = MusicSearch.parse(itunes)[0]
        val json = org.json.JSONObject(song.toJson())
        // The Apple app's Codable keys (`id` is required there).
        assertEquals("123", json.getString("id"))
        assertEquals("Feeling Good", json.getString("title"))
        assertEquals(song.url, json.getString("appleMusicURL"))
        assertEquals(song.artworkUrl, json.getString("artworkURL"))
        assertEquals(song.previewUrl, json.getString("previewURL"))
        // And back: what Android reads from either spelling.
        val back = MusicTrack.fromJson(song.toJson())!!
        assertEquals(song, back)
        // A card from someone else with an off-allowlist link renders, but offers nothing to open.
        val hostile = MusicTrack.fromJson("""{"id":"1","title":"t","artist":"a","appleMusicURL":"https://evil.example/","artworkURL":"javascript:alert(1)"}""")!!
        assertNull(hostile.safeUrl); assertNull(hostile.safeArtworkUrl)
        // A track with no id still gets one (Apple's decoder requires the key).
        assertTrue(org.json.JSONObject(MusicTrack("t", "a", null, null).toJson()).getString("id").isNotEmpty())
    }
}
