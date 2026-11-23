package io.skwod.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList

/**
 * What build 43 (commit 54ba47181) left on a phone, read by this build's strict loaders.
 * Build 43 stored:
 *
 * - kv `<workspace>|sidebar.dms`    — a list of `name`, `peerUserId`, `peerDeviceId`,
 *                                     `conversationId`, `bound`, `origin` (`local` / `inbound` /
 *                                     `listed` / `split`) — no `claimed`;
 * - kv `<workspace>|sidebar.spaces` — a list of `name`, `channelName`, `serverId`, `channelId`,
 *                                     `inviteCode`, `spaceKeyHex`;
 * - secret store `contacts-<workspace>` (and `roster-<workspace>`) — a list of `userId`,
 *                                     `name`, `level` (`UNVERIFIED` / `KNOWN` / `VERIFIED`).
 *
 * It stored NO group list, NO ignored-groups list, NO review record and NO Security activity
 * log: the first launch of this build finds those absent.
 *
 * An update must read all of it as it is: nothing kept aside as unreadable, nothing to review,
 * no notice, nothing dropped, and every stored conversation still the user's own.
 */
class StoredDataCompatibilityTest {
    private class Cache : ConversationBackend {
        val kv = ConcurrentHashMap<String, String>()
        val writes = CopyOnWriteArrayList<Pair<String, String>>()
        @Volatile var dmRows: List<ListedDm> = emptyList()
        @Volatile var groupRows: List<Pair<String, List<String>>> = emptyList()
        override suspend fun kvGet(key: String): String? = kv[key]
        override suspend fun kvSet(key: String, value: String) { kv[key] = value; writes += key to value }
        override suspend fun listDms(): List<ListedDm> = dmRows
        override suspend fun dmHistory(conversationId: String): List<HistoryAuthor> = emptyList()
        override suspend fun listGroupDms(): List<Pair<String, List<String>>> = groupRows
        override suspend fun openGroupDm(members: List<String>): String = "g-new"
    }

    private val backend = Cache()
    private val notices = CopyOnWriteArrayList<ConversationStore.Notice>()
    private val states = CopyOnWriteArrayList<Triple<Boolean, Set<String>, Int>>()
    private val pendingSaves = ConcurrentLinkedQueue<suspend () -> Unit>()

    private fun newStore(): ConversationStore {
        lateinit var made: ConversationStore
        made = ConversationStore(backend, "w43", ME, { pendingSaves += it }, object : ConversationStore.Listener {
            override fun changed(dms: List<DMConversation>, groups: List<GroupConversation>, invitations: List<GroupConversation>) {}
            override fun notice(notice: ConversationStore.Notice) { notices += notice; made.stored(notice) }
            override fun state(reviewPending: Boolean, ignored: Set<String>, loadFailures: Int) { states += Triple(reviewPending, ignored, loadFailures) }
        })
        return made
    }

    private suspend fun drain(store: ConversationStore) { while (true) { (pendingSaves.poll() ?: break)() }; store.flush() }

    companion object {
        const val ME = "5a0d1c5e-7c0b-4c53-9f0e-0f8f6f1f43aa"
        const val BOB = "9c1b7a52-2e0d-4b61-8a3c-51c1e2d0b0b1"
        const val CAROL = "0b9f4f1e-63a7-4d0a-b1f4-7e2a0c9d4c02"
        const val DAVE = "c3a1e8d4-0f5b-4e7a-9a6d-2b7f8e1d5d03"
        const val ERIN = "e4b2f9c5-1a6c-4f8b-8b7e-3c8a9f2e6e04"
        const val C_BOB = "6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8001"
        const val C_CAROL = "6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8002"
        const val C_DAVE = "6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8004"
        const val C_ERIN = "6f0e8b1a-0c1d-4e2f-8a3b-4c5d6e7f8005"

        /**
         * `sidebar.dms` exactly as build 43's `persistDms` wrote it, newest first: one a
         * delivery made, one only the server's list made (unbound, no name), and two the user
         * started with "New chat" (the peer's device id).
         */
        val DMS_43 = """[{"name":"dave","peerUserId":"$DAVE","peerDeviceId":"","conversationId":"$C_DAVE","bound":true,"origin":"inbound"},""" +
            """{"name":"","peerUserId":"$ERIN","peerDeviceId":"","conversationId":"$C_ERIN","bound":false,"origin":"listed"},""" +
            """{"name":"bobby43","peerUserId":"$BOB","peerDeviceId":"3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e01","conversationId":"$C_BOB","bound":true,"origin":"local"},""" +
            """{"name":"carol","peerUserId":"$CAROL","peerDeviceId":"3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e02","conversationId":"$C_CAROL","bound":true,"origin":"local"}]"""

        /** `sidebar.spaces` exactly as build 43's `persistSpaces` wrote it. */
        val SPACES_43 = """[{"name":"The Crew","channelName":"general","serverId":"a1b2c3d4-0001-4000-8000-000000000001","channelId":"a1b2c3d4-0001-4000-8000-0000000000c1","inviteCode":"Q7KD-2MXP-9RTA","spaceKeyHex":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},""" +
            """{"name":"The Crew","channelName":"photos","serverId":"a1b2c3d4-0001-4000-8000-000000000001","channelId":"a1b2c3d4-0001-4000-8000-0000000000c2","inviteCode":"","spaceKeyHex":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"},""" +
            """{"name":"Work","channelName":"general","serverId":"a1b2c3d4-0002-4000-8000-000000000002","channelId":"a1b2c3d4-0002-4000-8000-0000000000c3","inviteCode":"","spaceKeyHex":""}]"""

        /** `contacts-<workspace>` exactly as build 43's `ContactTrust.encode` wrote it. */
        val CONTACTS_43 = """[{"userId":"$BOB","name":"bobby43","level":"VERIFIED"},{"userId":"$CAROL","name":"carol","level":"KNOWN"},""" +
            """{"userId":"$DAVE","name":"dave","level":"UNVERIFIED"},{"userId":"$ERIN","name":"","level":"UNVERIFIED"}]"""

        /** `roster-<workspace>`: accepted members, stored with the same encoder at UNVERIFIED. */
        val ROSTER_43 = """[{"userId":"$BOB","name":"bobby43","level":"UNVERIFIED"},{"userId":"$CAROL","name":"carol","level":"UNVERIFIED"}]"""
    }

    // ---- the conversation lists, through the real loader ----

    @Test fun build43DirectListLoadsWholeWithNothingKeptAsideOrToReview() = runBlocking {
        backend.kv["w43|sidebar.dms"] = DMS_43
        val store = newStore()
        assertTrue(store.load())
        assertEquals(0, store.loadFailures)
        // Every stored entry, in the stored order, with what it held.
        assertEquals(listOf(C_DAVE to DAVE, C_ERIN to ERIN, C_BOB to BOB, C_CAROL to CAROL), store.dms.map { it.conversationId to it.peerUserId })
        assertEquals(listOf("dave", "", "bobby43", "carol"), store.dms.map { it.name })
        assertEquals(listOf("", "", "3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e01", "3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e02"), store.dms.map { it.peerDeviceId })
        assertEquals(listOf(true, false, true, true), store.dms.map { it.bound })
        assertEquals(listOf("inbound", "listed", "local", "local"), store.dms.map { it.origin })
        // Stored before entries said whether they claim their id: they all do.
        assertTrue(store.dms.all { it.claimed })
        // Build 43 had no groups: none, none ignored, none invited.
        assertTrue(store.groups.isEmpty()); assertTrue(store.invitations.isEmpty()); assertTrue(store.declined.isEmpty())
        // Nothing to review, nothing said, nothing kept aside, nothing rewritten.
        assertEquals(ConversationStore.Review(), store.review)
        assertFalse(store.review.all)
        assertTrue(notices.isEmpty())
        assertTrue(states.none { it.first || it.third != 0 })
        drain(store)
        assertTrue("loading build-43 data wrote ${backend.writes.map { it.first }}", backend.writes.isEmpty())
        assertEquals(setOf("w43|sidebar.dms"), backend.kv.keys.toSet())
        assertEquals(DMS_43, backend.kv["w43|sidebar.dms"])
    }

    @Test fun build43DirectEntriesKeepTheirIdsAgainstTheServer() = runBlocking {
        backend.kv["w43|sidebar.dms"] = DMS_43
        val store = newStore()
        assertTrue(store.load())
        val ids = store.dms.map { it.conversationId }
        // The server lists every one of them as a group: no invitation, every one still direct.
        backend.groupRows = ids.map { it to listOf(ME, BOB, CAROL) }
        assertTrue(store.refreshGroups())
        assertTrue(store.invitations.isEmpty()); assertTrue(store.groups.isEmpty())
        assertEquals(ids, store.dms.map { it.conversationId })
        for (id in ids) assertEquals(GroupRules.Route.DIRECT, store.route(id))
        // A message from the stored peer lands in the stored conversation: no new entry.
        assertEquals(ConversationStore.Delivery.None, store.deliverDM(C_BOB, BOB, "bobby43"))
        assertEquals(4, store.dms.size)
        // Written back in this build's form, every entry is still there and still claimed.
        store.claimDM(C_DAVE, DAVE); drain(store)
        val written = DmCodec.decode(backend.kv["w43|sidebar.dms"])
        assertNotNull(written)
        assertEquals(listOf(C_DAVE to DAVE, C_ERIN to ERIN, C_BOB to BOB, C_CAROL to CAROL), written!!.map { it.conversationId to it.peerUserId })
        assertTrue(written.all { it.claimed })
        assertEquals(listOf("inbound", "listed", "local", "local"), written.map { it.origin })
    }

    @Test fun aFirstLaunchAfterBuild43WithNoDirectListIsAnEmptyReadyStore() = runBlocking {
        // A build-43 user who never had a DM: the key was never written…
        val store = newStore()
        assertTrue(store.load())
        assertTrue(store.dms.isEmpty())
        assertEquals(ConversationStore.Review(), store.review)
        // …or it holds the empty list build 43 wrote after the last entry went.
        backend.kv["w43|sidebar.dms"] = "[]"
        val again = newStore()
        assertTrue(again.load())
        assertTrue(again.dms.isEmpty())
        assertTrue(notices.isEmpty()); assertTrue(backend.writes.isEmpty())
    }

    /**
     * The ONE build-43 shape that is not read back as it is, by design: build 43 kept a message
     * that arrived inside a conversation bound to someone else as a "split" entry under the
     * same id. This build keeps one entry per id — the user's own — after copying the list as
     * it was, and says so once. Named here so the behaviour on update is on record.
     */
    @Test fun aBuild43SplitEntryIsReducedWithACopyAndANotice() = runBlocking {
        val stored = """[{"name":"","peerUserId":"$ERIN","peerDeviceId":"","conversationId":"$C_BOB","bound":true,"origin":"split"},""" +
            """{"name":"bobby43","peerUserId":"$BOB","peerDeviceId":"3b9a1f0e-5d6c-4b7a-8e9f-0a1b2c3d4e01","conversationId":"$C_BOB","bound":true,"origin":"local"}]"""
        backend.kv["w43|sidebar.dms"] = stored
        val store = newStore()
        store.clock = { 44L }
        assertTrue(store.load())
        assertEquals(listOf(BOB), store.dms.map { it.peerUserId })
        assertEquals(stored, backend.kv["w43|sidebar.dms.duplicates.44"])
        assertEquals(listOf<ConversationStore.Notice>(ConversationStore.Notice.Duplicates("w43|sidebar.dms.duplicates.44")), notices.toList())
        // Not "unreadable", and nothing to review.
        assertEquals(ConversationStore.Review(), store.review)
    }

    // ---- spaces, contacts, Security activity: the strict decoders the loaders decide on ----

    @Test fun build43SpacesDecodeWholeWithTheStrictDecoder() {
        val spaces = SpaceCodec.decode(SPACES_43)
        assertNotNull("build-43 spaces would be kept aside as unreadable", spaces)
        assertEquals(listOf(
            RealSpace("The Crew", "general", "a1b2c3d4-0001-4000-8000-000000000001", "a1b2c3d4-0001-4000-8000-0000000000c1", "Q7KD-2MXP-9RTA", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            RealSpace("The Crew", "photos", "a1b2c3d4-0001-4000-8000-000000000001", "a1b2c3d4-0001-4000-8000-0000000000c2", "", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            RealSpace("Work", "general", "a1b2c3d4-0002-4000-8000-000000000002", "a1b2c3d4-0002-4000-8000-0000000000c3", "", "")), spaces)
        assertEquals(spaces, SpaceCodec.salvage(SPACES_43))
        assertEquals(emptyList<RealSpace>(), SpaceCodec.decode(null))
        assertEquals(emptyList<RealSpace>(), SpaceCodec.decode("[]"))
    }

    @Test fun build43ContactBookDecodesWholeAndKeepsEveryLevel() {
        val book = ContactTrust.decodeStrict(CONTACTS_43)
        assertNotNull("the build-43 contact book would be kept aside as unreadable", book)
        assertEquals(mapOf(
            BOB to Contact(BOB, "bobby43", TrustLevel.VERIFIED), CAROL to Contact(CAROL, "carol", TrustLevel.KNOWN),
            DAVE to Contact(DAVE, "dave", TrustLevel.UNVERIFIED), ERIN to Contact(ERIN, "", TrustLevel.UNVERIFIED)), book)
        // Written back by this build and read again, it is the same book.
        assertEquals(book, ContactTrust.decodeStrict(ContactTrust.encode(book!!)))
        assertEquals(mapOf(BOB to "bobby43", CAROL to "carol"), ContactTrust.decode(ROSTER_43).mapValues { it.value.name })
        // No book stored yet (a build-43 user with no contacts): an empty one, not unreadable.
        assertEquals(emptyMap<String, Contact>(), ContactTrust.decodeStrict(null))
        assertEquals(emptyMap<String, Contact>(), ContactTrust.decodeStrict("[]"))
    }

    @Test fun build43StoredNoSecurityActivityAndWhatThisBuildWritesReadsBack() {
        // Build 43 had no Security activity log: the key is absent — an empty log, not an unreadable one.
        assertEquals(emptyList<SecurityEvent>(), SecurityActivity.decodeStrict(null))
        val events = listOf(SecurityEvent("device_added", "A new device was added", "Pixel 9", 1_763_700_000_000L),
            SecurityEvent("recovery_key_set", "Recovery key turned on", "", 1_763_600_000_000L))
        assertEquals(events, SecurityActivity.decodeStrict(SecurityActivity.encode(events)))
    }
}
