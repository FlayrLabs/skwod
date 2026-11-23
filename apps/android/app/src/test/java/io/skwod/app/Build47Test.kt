package io.skwod.app

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Build 47: who is in a voice room ([VoiceRoster]), mention tokens from the username, and a
 * left server that stays gone ([LeaveTombstones]).
 */
class Build47Test {

    private fun event(server: String, channel: String, vararg people: JSONObject) = JSONObject()
        .put("server_id", server).put("channel_id", channel).put("participants", JSONArray(people.toList()))

    private fun person(id: String, joinedAt: Long = 0, muted: Boolean = false, video: Boolean = false, screen: Boolean = false) =
        JSONObject().put("user_id", id).put("joined_at", joinedAt).put("muted", muted).put("video", video).put("screen", screen)

    // ---- voice rosters ----

    @Test fun aVoiceStateReplacesTheRoomsRoster() {
        var r = VoiceRoster()
        r = r.apply("server:s1", event("s1", "v1", person("bob", 20, muted = true), person("amy", 10, video = true, screen = true)))!!
        assertEquals(listOf("amy", "bob"), r.participants("s1").map { it.userId })
        assertTrue(r.participants("s1")[0].video && r.participants("s1")[0].screen)
        assertTrue(r.participants("s1")[1].muted)
        // The same roster again is no change; a leave is.
        assertNull(r.apply("server:s1", event("s1", "v1", person("bob", 20, muted = true), person("amy", 10, video = true, screen = true))))
        r = r.apply("server:s1", event("s1", "v1", person("amy", 10)))!!
        assertEquals(listOf("amy"), r.participants("s1").map { it.userId })
        r = r.apply("server:s1", event("s1", "v1"))!!
        assertEquals(0, r.count("s1"))
        assertTrue(r.rooms.isEmpty())
    }

    @Test fun anEventIsTakenOnlyOnTheTopicOfTheServerItNames() {
        val r = VoiceRoster()
        assertNull(r.apply("server:other", event("s1", "v1", person("amy"))))
        assertNull(r.apply("user:me", event("s1", "v1", person("amy"))))
        assertNull(r.apply("server:s1", JSONObject().put("server_id", "s1").put("participants", JSONArray())))
    }

    @Test fun blockedDuplicatesAndJunkAreNotListedAndRoomsShowTogether() {
        var r = VoiceRoster().apply("server:s1",
            event("s1", "v1", person("amy", 3), person("amy", 3), person(""), JSONObject().put("x", 1), person("eve", 4)))!!
        assertEquals(listOf("amy", "eve"), r.participants("s1").map { it.userId })
        assertEquals(listOf("amy"), r.participants("s1", setOf("eve")).map { it.userId })
        r = r.apply("server:s1", event("s1", "v2", person("bob", 1)))!!
        assertEquals(listOf("bob", "amy", "eve"), r.participants("s1").map { it.userId })
        val many = (0 until 200).map { person("u$it") }.toTypedArray()
        r = r.apply("server:s1", event("s1", "v3", *many))!!
        assertTrue(r.rooms["s1"]!!["v3"]!!.size <= VoiceRoster.MAX_LISTED)
        assertEquals("3 in voice", VoiceRoster.countLabel(3))
        assertNull(VoiceRoster.countLabel(0))
    }

    @Test fun aHostCannotGrowTheRosterWithoutBound() {
        var r = VoiceRoster()
        assertNull(r.apply("server:s1", event("s1", "c".repeat(129), person("amy"))))
        for (i in 0 until VoiceRoster.MAX_ROOMS + 10) r = r.apply("server:s1", event("s1", "v$i", person("u$i"))) ?: r
        assertEquals(VoiceRoster.MAX_ROOMS, r.rooms["s1"]!!.size)
        // A room already listed still updates, and one that empties makes space.
        r = r.apply("server:s1", event("s1", "v0", person("amy")))!!
        r = r.apply("server:s1", event("s1", "v1"))!!
        assertNotNull(r.apply("server:s1", event("s1", "new", person("bob"))))
    }

    // ---- mention tokens ----

    @Test fun theTokenIsTheUsernameAndTheLabelStillMatches() {
        val sam = Mentions.Candidate("u-sam", "Sam Smith (unverified)", "sam_smith")
        val rob = Mentions.Candidate("u-rob", "Robin", "rob")
        assertEquals(listOf("u-sam"), Mentions.matches("smith", listOf(sam, rob)).map { it.userId })
        assertEquals(listOf("u-sam"), Mentions.matches("sam_", listOf(sam, rob)).map { it.userId })
        assertEquals(listOf("u-rob"), Mentions.matches("rob", listOf(sam, rob)).map { it.userId })
        val token = Mentions.tokenFor(sam)
        assertEquals("@sam_smith", token)
        val draft = Mentions.complete("hi @sa", token)
        assertEquals("hi @sam_smith ", draft)
        val d = Mentions.decode(Mentions.encode(draft, Mentions.locate(draft, listOf("u-sam" to token))))
        assertEquals("hi @sam_smith ", d.text)
        assertEquals(listOf(Mentions.Mention("u-sam", 3, 10)), d.mentions)
        // Without a username the label's token is used, as before.
        assertEquals("@Sam_Smith_unverified", Mentions.tokenFor(sam.copy(username = " ")))
    }

    // ---- leaving a server ----

    @Test fun leaveHidesAtOnceAndNothingInFlightBringsItBack() {
        val t = LeaveTombstones()
        assertTrue(t.begin("s1"))
        assertFalse("a second tap does nothing", t.begin("s1"))
        assertTrue(t.hides("s1"))
        assertFalse(t.hides("s2"))
        t.confirm("s1")
        assertFalse("a confirmed leave is not rolled back", t.failed("s1"))
        assertTrue(t.hides("s1"))
        t.rejoined("s1")
        assertFalse(t.hides("s1"))
        assertNull(t.mark("s1"))
    }

    @Test fun aRefusedLeaveBringsTheChannelsBackWhereTheyWere() {
        data class Row(val server: String, val channel: String)
        val t = LeaveTombstones()
        val before = listOf(Row("a", "a1"), Row("s1", "x1"), Row("s1", "x2"), Row("b", "b1"))
        t.begin("s1")
        val now = before.filter { it.server != "s1" } + Row("c", "c1")
        assertTrue(t.failed("s1"))
        assertFalse(t.hides("s1"))
        assertEquals(listOf("a1", "x1", "x2", "b1", "c1"),
            LeaveTombstones.restore(before, now, "s1", { it.server }, { it.channel }).map { it.channel })
        // Dropped for another reason while the leave was out: it stays out.
        val u = LeaveTombstones()
        u.begin("s2"); u.dropped(listOf("s2"))
        assertFalse(u.failed("s2"))
        assertNotNull(u.mark("s2"))
    }
}
