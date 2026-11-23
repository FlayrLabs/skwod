package io.skwod.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A host must not be able to talk its way into another skwod's workspace (cache + keys). */
class WorkspaceMatchTest {
    private val nodeA = "ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1u"
    private val nodeB = "y".repeat(52)

    private fun p2p(node: String, user: String = "u1", instance: String? = "inst-1", local: String = "local-" + node.take(4)) =
        Workspace("skwod://join/$node", user, "tok-$node", 0, "My skwod", localId = local,
            instanceId = instance, pinnedKey = "key-$node", nodeId = node)

    private fun https(url: String, user: String = "u1", instance: String? = "inst-1", pinned: String? = "key-real", local: String = "local-https") =
        Workspace(url, user, "tok-https", 0, "x", localId = local, instanceId = instance, pinnedKey = pinned)

    private val never: suspend (String) -> Boolean = { false }
    private val always: suspend (String) -> Boolean = { true }

    @Test fun twoP2pHostsClaimingTheSameInstanceIdStaySeparate() = runBlocking {
        val real = p2p(nodeA)
        // A malicious host with a DIFFERENT key claims the real skwod's instance id (and even the
        // same account id). It must not be handed the real workspace.
        val found = WorkspaceMatch.find(listOf(real), SkwodAddress.P2p(nodeB), "u1", "inst-1", always)
        assertNull(found)
        val id = WorkspaceMatch.newLocalId(listOf(real), SkwodAddress.P2p(nodeB), "u1")
        assertNotEquals(real.localId, id)
    }

    @Test fun p2pMatchesOnlyTheSameNodeIdAndAccount() = runBlocking {
        val real = p2p(nodeA)
        assertEquals(real, WorkspaceMatch.find(listOf(real), SkwodAddress.P2p(nodeA), "u1", "anything-else", never))
        assertNull(WorkspaceMatch.find(listOf(real), SkwodAddress.P2p(nodeA), "u2", "inst-1", always))
    }

    @Test fun p2pAndClassicNeverCrossMatch() = runBlocking {
        val classic = https("https://chat.example.org")
        assertNull(WorkspaceMatch.find(listOf(classic), SkwodAddress.P2p(nodeA), "u1", "inst-1", always))
        val p = p2p(nodeA)
        assertNull(WorkspaceMatch.find(listOf(p), SkwodAddress.Https("https://evil.example"), "u1", "inst-1", always))
    }

    @Test fun classicHostClaimingAnInstanceIdMustProveThePinnedKey() = runBlocking {
        val real = https("https://chat.example.org")
        val impostor = SkwodAddress.Https("https://evil.example")
        assertNull(WorkspaceMatch.find(listOf(real), impostor, "u1", "inst-1", never))
        // Same URL but the pinned-key proof fails (key swapped): still not reused.
        assertNull(WorkspaceMatch.find(listOf(real), SkwodAddress.Https("https://chat.example.org"), "u1", "inst-1", never))
        // The real server at a new address proves the key: reused.
        var asked: String? = null
        val moved = WorkspaceMatch.find(listOf(real), SkwodAddress.Https("https://new.example.org"), "u1", "inst-1") { asked = it; true }
        assertEquals(real, moved)
        assertEquals("key-real", asked)
    }

    @Test fun aThrowingProofIsAFailedProof() = runBlocking {
        val real = https("https://chat.example.org")
        assertNull(WorkspaceMatch.find(listOf(real), SkwodAddress.Https("https://evil.example"), "u1", "inst-1") { error("offline") })
    }

    @Test fun prePinningWorkspaceOnlyForTheExactSameUrl() = runBlocking {
        val legacy = https("https://chat.example.org", pinned = null)
        assertEquals(legacy, WorkspaceMatch.find(listOf(legacy), SkwodAddress.Https("https://chat.example.org"), "u1", null, never))
        assertNull(WorkspaceMatch.find(listOf(legacy), SkwodAddress.Https("https://evil.example"), "u1", "inst-1", always))
    }

    @Test fun newLocalIdNeverCollidesWithAnExistingWorkspace() {
        val addr = SkwodAddress.P2p(nodeB)
        val first = WorkspaceMatch.newLocalId(emptyList(), addr, "u1")
        assertEquals(Workspace.slug(addr.stored), first)
        val other = p2p(nodeB, user = "u1", local = first)
        val second = WorkspaceMatch.newLocalId(listOf(other), addr, "u2")
        assertNotEquals(first, second)
        val third = WorkspaceMatch.newLocalId(listOf(other, p2p(nodeB, user = "u2", local = second)), addr, "u2")
        assertTrue(third != first && third != second)
    }

    @Test fun notificationIntentsNeedOurNonceAndTheRingingCall() {
        val nonce = "0123456789abcdef0123456789abcdef"
        assertTrue(IntentGuard.isOurs(nonce, nonce))
        assertFalse(IntentGuard.isOurs(null, nonce))
        assertFalse(IntentGuard.isOurs("", nonce))
        assertFalse(IntentGuard.isOurs("0123456789abcdef0123456789abcdee", nonce))
        assertTrue(IntentGuard.isForRingingCall(nonce, "srv", "srv", nonce))
        assertFalse(IntentGuard.isForRingingCall(nonce, "srv", null, nonce))           // nothing is ringing
        assertFalse(IntentGuard.isForRingingCall(nonce, "other", "srv", nonce))        // not the ringing call
        assertFalse(IntentGuard.isForRingingCall(null, "srv", "srv", nonce))           // not our intent
        assertFalse(IntentGuard.isForRingingCall(nonce, "", "", nonce))
        assertEquals(32, IntentGuard.nonce.length)
    }
}
