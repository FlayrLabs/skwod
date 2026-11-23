package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Build 48: a device pairing by QR never asks for a password and names the host by its key. */
class PairingCopyTest {
    @Test fun pairingCopyNeverAsksForAPasswordAndNamesTheHost() {
        for (known in listOf(true, false)) {
            val header = PairingCopy.header("moesz7…xbmo", "alice", known)
            assertTrue(header, header.contains("moesz7…xbmo") && header.contains("@alice"))
            assertTrue(header, header.startsWith(if (known) "A Skwod you use" else "A new Skwod"))
            for (line in listOf(header, PairingCopy.CONFIRM, PairingCopy.JOIN_DETAIL, PairingCopy.PICK_HINT, PairingCopy.WAITING_FOR_OTHER)) {
                assertFalse(line, line.lowercase().contains("password"))
                assertFalse(line, line.lowercase().contains("from your other device"))
            }
        }
    }

    @Test fun aDeniedOrExpiredPairingSaysSoInPlainWords() {
        val raw = "protocol error: this pairing was not approved, or it expired; make a new code on your other device"
        assertEquals(PairingCopy.NOT_APPROVED, PairingCopy.failure(raw))
        val offline = "Couldn't reach that Skwod. Check your connection and try again."
        assertEquals(offline, PairingCopy.failure(offline))
    }

    /** M2: the skwod is named only by a workspace this device has, else by the host's key. */
    @Test fun theJoinQuestionNamesTheSkwodOnlyByWhatThisDeviceKnows() {
        assertEquals("Join moesz7…xbmo as @alice?", PairingCopy.joinPrompt(null, "moesz7…xbmo", "alice"))
        assertEquals("Join Book club as @alice?", PairingCopy.joinPrompt("Book club", "moesz7…xbmo", "alice"))
        assertEquals("Join moesz7…xbmo as @alice?", PairingCopy.joinPrompt("  ", "moesz7…xbmo", "alice"))
        assertTrue(PairingCopy.JOIN_DETAIL.contains("their account"))
        assertEquals("Approved on your other device · moesz7…xbmo", PairingCopy.approved("moesz7…xbmo"))
    }

    /** M1: a pick among sets, with a way out that is not a pick. */
    @Test fun theExistingDeviceAsksForAPickNotATap() {
        assertTrue(PairingCopy.PICK_TITLE.contains("Which set"))
        assertTrue(PairingCopy.PICK_HINT.contains("refuses"))
        assertTrue(PairingCopy.CONFIRM.contains("five") && PairingCopy.CONFIRM.contains(PairingCopy.NONE_OF_THESE))
    }

    @Test fun pairingFailuresKeepTheirMeaning() {
        val mismatch = "protocol error: the other device's check did not match this code, so nothing was added; make a new code on your other device"
        assertEquals(PairingCopy.MISMATCH, PairingCopy.failure(mismatch))
        val off = "protocol error: this Skwod's host hasn't turned on adding devices by QR"
        assertEquals("This Skwod's host hasn't turned on adding devices by QR", PairingCopy.failure(off))
    }
}
