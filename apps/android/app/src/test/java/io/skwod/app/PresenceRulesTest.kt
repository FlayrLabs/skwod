package io.skwod.app

import org.junit.Assert.*
import org.junit.Test

/** The same table as the Apple apps' PresenceRulesTests. */
class PresenceRulesTest {
    private fun at(s: Double) = (s * 1000).toLong()
    private fun dot(now: Int, build: (PresenceBook) -> PresenceBook) = build(PresenceBook()).view("kim", at(now.toDouble())).dot
    private fun PresenceBook.ev(status: String, t: Double, who: String = "kim") = event(who, status, at(t))
    private fun PresenceBook.poll(status: String, asked: Double) = polled(mapOf("kim" to status, "other" to "online"), at(asked))

    @Test fun theTable() {
        assertEquals("unknown", dot(100) { it })
        assertEquals("online", dot(110) { it.poll("online", 100.0) })
        assertEquals("dnd", dot(110) { it.poll("dnd", 100.0) })
        assertEquals("online", dot(110) { it.ev("offline", 100.0).poll("online", 103.0) })
        assertEquals("online", dot(110) { it.ev("online", 105.0).poll("offline", 100.0) })
        assertEquals("online", dot(140) { it.ev("online", 100.1).poll("offline", 100.0) })
        assertEquals("online", dot(130) { it.poll("online", 120.0).poll("offline", 100.0) })
        assertEquals("online", dot(132) { it.ev("online", 100.0).ev("offline", 130.0).ev("online", 131.0) })
        assertEquals("unknown", dot(195) { it.poll("online", 100.0) })
        assertEquals("unknown", dot(5000) { it.poll("online", 100.0) })
        assertEquals("unknown", dot(5000) { it.poll("online", 100.0).ev("idle", 101.0) })
        assertEquals("offline", dot(5001) { it.poll("online", 100.0).poll("offline", 5000.0) })
        assertEquals("offline", dot(301) { it.poll("online", 100.0).polled(mapOf("other" to "online"), at(300.0)) })
        assertEquals("online", dot(110) { it.poll("online", 100.0).ev("gone", 105.0) })
    }

    @Test fun anEventAboutOneDoesNotMakeTheRestOffline() {
        val b = PresenceBook().polled(mapOf("kim" to "online", "lee" to "online"), at(100.0)).ev("online", 5000.0, "lee")
        assertEquals("online", b.view("lee", at(5001.0)).dot)
        assertEquals(PresenceBook.View("online", false), b.view("kim", at(5001.0)))
    }

    @Test fun onlyADeviceInUseSpeaksForTheAccount() {
        assertEquals("dnd", PresenceAnnounce.status(true, "dnd"))
        assertNull(PresenceAnnounce.status(false, "online"))
        assertEquals("offline", PresenceAnnounce.status(true, "offline"))
        assertNull(PresenceAnnounce.periodic(true, "offline"))
        assertNull(PresenceAnnounce.periodic(false, "online"))
    }

    @Test fun anActiveDeviceCorrectsAnOlderOne() {
        fun c(user: String = "me", status: String = "offline", announced: String? = "online", last: Long? = null, now: Long = 100_000) =
            PresenceAnnounce.corrects(user, status, "me", announced, last, now)
        assertTrue(c()); assertTrue(c(announced = "dnd", last = 85_000)); assertFalse(c(last = 86_000))
        assertFalse(c(user = "kim")); assertFalse(c(announced = null)); assertFalse(c(announced = "offline")); assertFalse(c(status = "idle"))
    }

    /** The owner's report: with this device's own connection down, "1 online" stayed. */
    @Test fun nothingIsPresentedAsOnlineWhileThisDeviceIsNotConnected() {
        val status = mapOf("me" to "online", "a" to "online", "b" to "offline", "c" to "dnd")
        val ids = listOf("me", "a", "b", "c")
        assertEquals(3, PresenceRoster.onlineCount(ids, "me", true) { status.getValue(it) })
        assertNull(PresenceRoster.onlineCount(ids, "me", false) { status.getValue(it) })
        assertEquals(PresenceRoster.Groups(listOf("me", "a", "c"), listOf("b")), PresenceRoster.groups(ids, true) { status.getValue(it) })
        assertEquals(PresenceRoster.Groups(unknown = ids), PresenceRoster.groups(ids, false) { status.getValue(it) })
        assertEquals("online", PresenceRoster.dot("online", true))
        listOf("online", "idle", "dnd", "offline").forEach { assertEquals("unknown", PresenceRoster.dot(it, false)) }
        assertFalse(PresenceRoster.unknownTitle(4).lowercase().contains("online"))
    }
}
