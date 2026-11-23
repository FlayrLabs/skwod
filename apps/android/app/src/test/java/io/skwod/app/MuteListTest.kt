package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mutes: per conversation and per skwod, with automatic expiry ([MuteList]) — and what they do to alerts. */
class MuteListTest {
    private val hour = 3_600_000L

    @Test fun aMutedConversationIsMutedUntilItsTimeRunsOut() {
        var m = MuteList().mute("dm:c1", MuteList.Duration.HOUR, now = 1000)
        assertTrue(m.isMuted("dm:c1", 1000))
        assertTrue(m.isMuted("dm:c1", 1000 + hour - 1))
        assertFalse("expiry is automatic", m.isMuted("dm:c1", 1000 + hour))
        assertFalse(m.isMuted("dm:c2", 1000))
        m = m.mute("channel:x", MuteList.Duration.EIGHT_HOURS, 1000).mute("channel:y", MuteList.Duration.DAY, 1000)
        assertTrue(m.isMuted("channel:x", 1000 + 8 * hour - 1)); assertFalse(m.isMuted("channel:x", 1000 + 8 * hour))
        assertTrue(m.isMuted("channel:y", 1000 + 24 * hour - 1)); assertFalse(m.isMuted("channel:y", 1000 + 24 * hour))
    }

    @Test fun untilIUnmuteLastsAndUnmuteEndsIt() {
        var m = MuteList().mute("dm:c1", MuteList.Duration.FOREVER, 1000)
        assertTrue(m.isMuted("dm:c1", 1000 + 10L * 365 * 24 * hour))
        m = m.unmute("dm:c1")
        assertFalse(m.isMuted("dm:c1", 1001))
        // Expired entries are dropped on a change.
        m = m.mute("dm:old", MuteList.Duration.HOUR, 1000).mute("dm:c1", MuteList.Duration.HOUR, 1000 + 2 * hour)
        assertEquals(setOf("dm:c1"), m.until.keys)
    }

    @Test fun aMutedSkwodMutesEverythingAndItsCallsAMutedConversationDoesNot() {
        var m = MuteList().mute("dm:c1", MuteList.Duration.HOUR, 1000)
        assertTrue("a call still rings when only a conversation is muted", m.callsRing(1000))
        m = m.mute(MuteList.SKWOD, MuteList.Duration.HOUR, 1000)
        assertTrue(m.isMuted("channel:anything", 1000))
        assertFalse(m.callsRing(1000))
        assertTrue(m.callsRing(1000 + hour))
        assertFalse(m.isMuted("channel:anything", 1000 + hour))
    }

    @Test fun aMutedConversationMakesNoSoundAndNoNotification() {
        val m = MuteList().mute("dm:c1", MuteList.Duration.HOUR, 1000)
        for (active in listOf(true, false)) {
            assertEquals(AlertPolicy.NOTHING, AlertPolicy.received(AlertPolicy.Incoming(muted = m.isMuted("dm:c1", 1500), appActive = active, now = 1500)))
            assertTrue(AlertPolicy.received(AlertPolicy.Incoming(muted = m.isMuted("dm:c2", 1500), appActive = active, now = 1500)).banner)
        }
    }

    @Test fun theStoredFormRoundTripsAndGarbageIsNothingMuted() {
        val m = MuteList().mute("dm:c1", MuteList.Duration.FOREVER, 1000).mute(MuteList.SKWOD, MuteList.Duration.HOUR, 1000)
        assertEquals(m, MuteList.parse(m.toJson()))
        assertEquals(MuteList(), MuteList.parse("not json"))
        assertEquals(MuteList(), MuteList.parse(null))
    }
}
