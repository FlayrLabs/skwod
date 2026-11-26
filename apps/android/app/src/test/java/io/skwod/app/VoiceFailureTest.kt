package io.skwod.app

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/** Build 51: what joining a call says when it fails — one table for both apps. */
class VoiceFailureTest {
    private val table = SharedVectors.load("voice-failures.json")

    private fun objects(name: String) = table.getJSONArray(name).let { a -> (0 until a.length()).map { a.getJSONObject(it) } }

    @Test fun everyFailureHasItsOneSentenceAndNoneBlamesAVpn() {
        val messages = table.getJSONObject("messages")
        assertEquals(messages.keys().asSequence().toSet(), VoiceFailure.entries.map { it.code }.toSet())
        for (f in VoiceFailure.entries) {
            assertEquals(messages.getString(f.code), f.message)
            assertEquals(false, f.message.contains("VPN"))
        }
        val once = table.getJSONArray("retry_once").let { a -> (0 until a.length()).map { a.getString(it) } }
        assertEquals(once.toSet(), VoiceFailure.entries.filter { it.retriesOnce }.map { it.code }.toSet())
    }

    /** The server's 503 (`voice_off` / `voice_starting`) reaches here as the core's code. */
    @Test fun theCoresCodes() {
        for (c in objects("codes")) assertEquals(c.getString("code"), c.getString("expect"), VoiceFailure.of(c.getString("code")).code)
    }

    @Test fun aMediaFailureIsPlacedByTheTunnelsCounters() {
        fun counters(a: JSONArray?) = a?.let { VoiceFailure.Counters(it.getLong(0), it.getLong(1), it.getLong(2), it.getLong(3)) }
        for (c in objects("media")) {
            assertEquals(c.getString("why"), c.getString("expect"), VoiceFailure.media(counters(c.optJSONArray("before")), counters(c.optJSONArray("after"))).code)
        }
    }

    @Test fun theVoiceRowNeverOffersTheSetupPanelOnASkwodWithItsOwnCallServer() {
        for (c in objects("gate")) {
            val gate = VoiceGate.decide(c.getBoolean("configured"), c.getString("status"), c.getBoolean("bundled"), c.getBoolean("owner"))
            when (val expect = c.getString("expect")) {
                "join" -> assertEquals(VoiceGate.Join, gate)
                "set_up" -> assertEquals(VoiceGate.SetUp, gate)
                "not_set_up" -> assertEquals(VoiceGate.Say(VoiceGate.NOT_SET_UP), gate)
                else -> assertEquals(VoiceGate.Say(VoiceFailure.of(expect).message), gate)
            }
            if (c.getBoolean("bundled")) assertNotEquals(VoiceGate.SetUp, gate)
        }
    }
}
