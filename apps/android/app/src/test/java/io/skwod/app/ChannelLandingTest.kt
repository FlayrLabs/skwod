package io.skwod.app

import io.skwod.app.Landing.Place
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Build 51 ([Landing]). The Swift twin runs the same cases. */
class ChannelLandingTest {
    private val list = listOf(LandingChannel("a", "s1"), LandingChannel("b", "s1"), LandingChannel("x", "s2"), LandingChannel("y", "s2"))
    private fun place(l: Landing, memory: ChannelMemory = ChannelMemory(), channels: List<LandingChannel> = list,
                      open: Boolean = false, ready: Boolean = true, settingUp: Boolean = false) = l.place(open, ready, settingUp, memory, channels)
    private fun asked(server: String?) = Landing().asked(Landing.Want(server))

    @Test fun aTapLandsOnTheLastOrTheFirst() {
        assertEquals(Place.Channel("x"), place(asked("s2")))
        assertEquals(Place.Channel("b"), place(asked("s1"), ChannelMemory("s2", mapOf("s1" to "b"))))
        assertEquals(Place.Channel("a"), place(asked("s1"), ChannelMemory(null, mapOf("s1" to "gone"))))
        assertEquals("another server's id", Place.Channel("a"), place(asked("s1"), ChannelMemory(null, mapOf("s1" to "y"))))
        val some = listOf(list[0], list[1].copy(readable = false)) + list.drop(2)
        assertEquals(Place.Channel("a"), place(asked("s1"), ChannelMemory(null, mapOf("s1" to "b")), some))
        assertEquals("never another server's", Place.Empty("s1"), place(asked("s1"), channels = some.map { it.copy(readable = it.serverId != "s1") }))
    }

    @Test fun aFastSecondTapWins() {
        var l = asked("s1")
        assertEquals("lists not read, or another skwod's", Place.Loading, place(l, ready = false))
        l = l.asked(Landing.Want("s2"))
        assertEquals(Place.Channel("x"), place(l))
        l = l.opened()   // a channel tapped while it was loading
        assertEquals(null, l.want)
        assertTrue(l.byUser)
        assertEquals(Place.Open, place(l, open = true))
    }

    @Test fun launch() {
        assertEquals(Place.Channel("y"), place(asked(null), ChannelMemory("s2", mapOf("s2" to "y"))))
        assertEquals(Place.Channel("a"), place(asked(null), ChannelMemory("s9")))
        assertEquals(Place.Loading, place(asked(null), ready = false))
        assertEquals(Place.NoServers, place(asked(null), channels = emptyList()))
        assertEquals(Place.Loading, place(asked(null), channels = emptyList(), settingUp = true))
        assertFalse(asked(null).landed().byUser)
    }

    @Test fun nothingTheHostSendsOpensOrReplacesAnything() {
        val lists = listOf(emptyList(), list.drop(1), list + LandingChannel("z", "s3"), list.map { it.copy(readable = false) })
        for (l in listOf(asked("s1").opened(), asked("s1").landed())) {
            assertEquals("decided later, resumed, member added", l, l.joined("s3", startedHere = false, open = true))
            assertEquals("started here, but something is open", l, l.joined("s3", startedHere = true, open = true))
            for (channels in lists) {   // hidden, deleted, added, refused
                assertEquals(Place.Open, place(l, channels = channels, open = true))
                assertEquals("gone: nothing in its place", Place.Closed, place(l, ChannelMemory("s1"), channels))
            }
        }
        assertEquals("only listed", Place.Closed, place(asked(null).joined("s1", startedHere = false, open = false)))
    }

    @Test fun aJoinStartedHereWithNothingOpen() =
        assertEquals(Place.Channel("x"), place(Landing().joined("s2", startedHere = true, open = false)))

    @Test fun aDraftGoesWhereItWasWrittenOrNowhere() {
        val here = Landing.conversationKey("w1", "s1", "a")
        assertTrue(Landing.maySend(here, Landing.conversationKey("w1", "s1", "a")))
        for ((w, s, c) in listOf(Triple("w1", "s1", "b"), Triple("w1", "s2", "a"), Triple("w2", "s1", "a")))
            assertFalse(Landing.maySend(here, Landing.conversationKey(w, s, c)))
        assertFalse(Landing.maySend(null, here))
    }

    @Test fun memoryAndRefusals() {
        val m = ChannelMemory().opened("a", "s1").opened("x", "s2")
        assertEquals(m, ChannelMemory.decode(m.encode()))
        assertEquals(ChannelMemory(null, mapOf("s1" to "a")), m.forget("s2"))
        for (bad in listOf(null, "", "not json", "{}")) assertEquals(null, ChannelMemory.decode(bad))
        assertTrue(Landing.isReadRefusal("http status 403: {\"error\":\"forbidden\"}"))
        assertFalse(Landing.isReadRefusal("http status 403: {\"error\":\"device removed\"}"))
    }
}
