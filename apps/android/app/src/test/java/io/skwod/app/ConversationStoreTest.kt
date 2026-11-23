package io.skwod.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Drives the real [ConversationStore] — the code the app runs for every change to the 1:1 and
 * group lists — against a server that lies and answers at the worst moments.
 */
class ConversationStoreTest {
    /** An in-memory cache and a scripted, untrusted server. */
    private class FakeBackend : ConversationBackend {
        val kv = ConcurrentHashMap<String, String>()
        val writes = CopyOnWriteArrayList<Pair<String, String>>()
        @Volatile var dmRows: List<ListedDm> = emptyList()
        @Volatile var groupRows: List<Pair<String, List<String>>> = emptyList()
        val histories = ConcurrentHashMap<String, List<HistoryAuthor>>()
        @Volatile var openAnswer = "g-new"
        /** No read or write of the cache goes through (the client is down, or the read fails). */
        @Volatile var cacheBroken = false
        /** The cache reads, but a write does not go through. */
        @Volatile var failWrites = false
        @Volatile var serverDown = false
        /** Run (once) in the middle of the named call: after the server "answered", before the app sees it. */
        val during = ConcurrentHashMap<String, suspend () -> Unit>()
        /** Calls held open until completed. */
        val gates = ConcurrentHashMap<String, CompletableDeferred<Unit>>()
        val entered = ConcurrentHashMap<String, CompletableDeferred<Unit>>()

        private suspend fun pause(name: String) {
            during.remove(name)?.invoke()
            entered[name]?.complete(Unit)
            gates[name]?.await()
        }

        override suspend fun kvGet(key: String): String? { pause("kvGet"); if (cacheBroken) throw IllegalStateException("cache"); return kv[key] }
        override suspend fun kvSet(key: String, value: String) { pause("kvSet"); if (cacheBroken || failWrites) throw IllegalStateException("cache"); kv[key] = value; writes += key to value }
        override suspend fun listDms(): List<ListedDm> { val r = dmRows; pause("listDms"); if (serverDown) throw IllegalStateException("net"); return r }
        override suspend fun dmHistory(conversationId: String): List<HistoryAuthor> { pause("dmHistory"); return histories[conversationId] ?: emptyList() }
        override suspend fun listGroupDms(): List<Pair<String, List<String>>> { val r = groupRows; pause("listGroupDms"); if (serverDown) throw IllegalStateException("net"); return r }
        override suspend fun openGroupDm(members: List<String>): String { pause("openGroupDm"); return openAnswer }
        /** What the core fixed each conversation as (`dm_is_group`); absent = never used here. */
        val fixed = ConcurrentHashMap<String, Boolean>()
        override suspend fun dmIsGroup(conversationId: String): Boolean? = fixed[conversationId]
    }

    private val backend = FakeBackend()
    private val notices = CopyOnWriteArrayList<ConversationStore.Notice>()
    private val pendingSaves = ConcurrentLinkedQueue<suspend () -> Unit>()
    /** Does Security activity manage to store a notice's row? */
    @Volatile private var activityWrites = true
    private var store = newStore()

    private fun newStore(): ConversationStore {
        lateinit var made: ConversationStore
        made = ConversationStore(backend, "w1", "u-me", { pendingSaves += it }, object : ConversationStore.Listener {
            override fun changed(dms: List<DMConversation>, groups: List<GroupConversation>, invitations: List<GroupConversation>) {}
            // Like the app: Security activity stores the row, then reports it stored.
            override fun notice(notice: ConversationStore.Notice) { notices += notice; if (activityWrites) made.stored(notice) }
        })
        return made
    }

    private fun from(vararg authors: String) = authors.map { HistoryAuthor(it, false) }
    private fun dm(id: String, peer: String) = DMConversation(peer, peer, "dev", id)
    private fun conflict(id: String) = ConversationStore.Notice.Conflict(id)

    /** One user-started DM (`d-1` with bob) and one accepted group (`g-1`: carol, dave). */
    private suspend fun loadedWithOneOfEach() {
        assertTrue(store.load())
        assertTrue(store.addDM(dm("d-1", "u-bob")) is ConversationStore.Opened.Added)
        backend.groupRows = listOf("g-1" to listOf("u-me", "u-carol", "u-dave"))
        assertTrue(store.refreshGroups())
        assertNotNull(store.accept(store.invitations.single()))
        backend.groupRows = emptyList()
        store.flush()
        assertUntouched()
    }

    private fun assertUntouched() {
        assertEquals(listOf("d-1" to "u-bob"), store.dms.map { it.conversationId to it.peerUserId })
        assertEquals(listOf(GroupConversation("g-1", listOf("u-carol", "u-dave"))), store.groups.map { it.copy(serverDisagrees = false) })
    }

    // ---- a group passed off as a direct conversation ----

    @Test fun deliverDMNeverMakesADirectEntryForAGroupsId() = runBlocking {
        loadedWithOneOfEach()
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("g-1", "u-mallory", "mallory"))
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("g-1", "u-carol", "carol"))
        assertUntouched()
        assertEquals(GroupRules.Route.GROUP, store.route("g-1"))
        assertEquals(listOf<ConversationStore.Notice>(conflict("g-1")), notices.toList())
    }

    @Test fun listUnboundDMNeverMakesADirectEntryForAGroupsId() = runBlocking {
        loadedWithOneOfEach()
        assertEquals(ConversationStore.Delivery.Refused, store.listUnboundDM("g-1", "u-mallory", "mallory"))
        assertUntouched()
        assertEquals(listOf<ConversationStore.Notice>(conflict("g-1")), notices.toList())
    }

    @Test fun refreshDmListNeverMakesADirectEntryForAGroupsId() = runBlocking {
        loadedWithOneOfEach()
        backend.dmRows = listOf(ListedDm("g-1", "u-mallory", "mallory"), ListedDm("d-2", "u-erin", "erin"), ListedDm("d-3", "u-frank", "frank"))
        backend.histories["g-1"] = from("u-mallory", "u-carol")
        backend.histories["d-2"] = from("u-erin")
        backend.histories["d-3"] = from("__me__")
        val changed = store.refreshDmList()
        assertEquals(2, changed.size)
        assertEquals(setOf("d-1", "d-2", "d-3"), store.dms.map { it.conversationId }.toSet())
        // What the server made is listed, but claims nothing; what the user made does.
        assertEquals(mapOf("d-1" to true, "d-2" to false, "d-3" to false), store.dms.associate { it.conversationId to it.claimed })
        assertEquals(false, store.dms.first { it.conversationId == "d-3" }.bound)
        assertEquals(listOf("u-carol", "u-dave"), store.groups.single().others)
        assertEquals(listOf<ConversationStore.Notice>(conflict("g-1")), notices.toList())
    }

    @Test fun aGroupAcceptedWhileRefreshDmListWasReadingHistoryWins() = runBlocking {
        assertTrue(store.load())
        // Not a group when the row is first looked at; the user accepts it while the history
        // read is suspended. The entry must not be written from the earlier check.
        backend.dmRows = listOf(ListedDm("x-1", "u-carol", "carol"))
        backend.histories["x-1"] = from("u-carol")
        backend.groupRows = listOf("x-1" to listOf("u-carol", "u-dave"))
        backend.during["dmHistory"] = {
            assertTrue(store.refreshGroups())
            assertNotNull(store.accept(store.invitations.single()))
        }
        assertTrue(store.refreshDmList().isEmpty())
        assertTrue(store.dms.isEmpty())
        assertEquals(listOf("x-1"), store.groups.map { it.conversationId })
        assertEquals(listOf<ConversationStore.Notice>(conflict("x-1")), notices.toList())
    }

    @Test fun openingADirectConversationUnderAGroupsIdIsRefused() = runBlocking {
        loadedWithOneOfEach()
        assertEquals(ConversationStore.Opened.Refused, store.addDM(dm("g-1", "u-mallory")))
        assertUntouched()
        assertEquals(listOf<ConversationStore.Notice>(conflict("g-1")), notices.toList())
    }

    @Test fun nothingOfAnInvitationOrAnIgnoredGroupIsListedAsDirect() = runBlocking {
        assertTrue(store.load())
        backend.groupRows = listOf("inv" to listOf("u-carol", "u-dave"), "ign" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        store.decline(store.invitations.first { it.conversationId == "ign" })
        assertEquals(GroupRules.Route.DECLINED, store.route("ign"))
        assertEquals(GroupRules.Route.INVITATION, store.route("inv"))
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("inv", "u-carol", null))
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("ign", "u-erin", null))
        assertEquals(ConversationStore.Delivery.Refused, store.listUnboundDM("ign", "u-erin", null))
        assertTrue(store.dms.isEmpty())
        assertTrue(store.refreshGroups())
        assertEquals(listOf("inv"), store.invitations.map { it.conversationId })
    }

    // ---- a direct conversation passed off as a group ----

    @Test fun aClaimedDirectIdListedAsAGroupMakesNoInvitation() = runBlocking {
        loadedWithOneOfEach()
        backend.groupRows = listOf("d-1" to listOf("u-carol", "u-mallory"), "d-1" to listOf("u-carol", "u-mallory"))
        assertTrue(store.refreshGroups())
        assertTrue(store.invitations.isEmpty())
        assertUntouched()
        assertEquals(GroupRules.Route.DIRECT, store.route("d-1"))
        assertEquals(listOf<ConversationStore.Notice>(conflict("d-1")), notices.toList())
    }

    @Test fun startingAGroupTheServerAnswersWithAHeldIdIsRefused() = runBlocking {
        loadedWithOneOfEach()
        for (answer in listOf("d-1", "g-1")) {
            backend.openAnswer = answer
            try { store.openGroup(listOf("u-erin", "u-frank")); fail("started under $answer") } catch (_: ConversationStore.ConflictException) {}
            assertUntouched()
        }
        // Reopening the same people is not a clash.
        backend.openAnswer = "g-1"
        assertEquals("g-1", store.openGroup(listOf("u-dave", "u-carol")).conversationId)
        assertUntouched()
    }

    @Test fun aDirectConversationOpenedWhileAGroupWasBeingStartedWins() = runBlocking {
        assertTrue(store.load())
        backend.openAnswer = "x-1"
        backend.during["openGroupDm"] = { store.addDM(dm("x-1", "u-bob")) }
        try { store.openGroup(listOf("u-carol", "u-dave")); fail("started") } catch (_: ConversationStore.ConflictException) {}
        assertTrue(store.groups.isEmpty())
        assertEquals(listOf("x-1"), store.dms.map { it.conversationId })
    }

    @Test fun openingADirectConversationUnderAnInvitationOrAnIgnoredGroupIsRefusedUpFront() = runBlocking {
        assertTrue(store.load())
        backend.groupRows = listOf("inv" to listOf("u-carol", "u-dave"), "ign" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        store.decline(store.invitations.first { it.conversationId == "ign" })
        assertEquals(ConversationStore.Opened.Refused, store.addDM(dm("inv", "u-bob")))
        assertEquals("refused, and the caller can say why", ConversationStore.Opened.RefusedIgnored, store.addDM(dm("ign", "u-bob")))
        assertTrue(store.dms.isEmpty())
        assertEquals(listOf("inv"), store.invitations.map { it.conversationId })
        assertEquals(listOf<ConversationStore.Notice>(conflict("inv"), conflict("ign")), notices.toList())
    }

    @Test fun anIgnoredGroupCanBeUnignoredAndThenComesBackAsAnInvitation() = runBlocking {
        assertTrue(store.load())
        backend.groupRows = listOf("ign" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        store.decline(store.invitations.single())
        assertTrue(store.refreshGroups())
        assertTrue(store.invitations.isEmpty())
        // The user stops ignoring it: the id is free again, and the listing shows the group.
        assertTrue(store.unignore("ign")); assertFalse(store.unignore("ign"))
        assertTrue(store.declined.isEmpty())
        drain()
        assertEquals("[]", backend.kv["w1|" + GroupRules.DECLINED_KEY])
        assertTrue(store.refreshGroups())
        assertEquals(listOf("ign"), store.invitations.map { it.conversationId })
        // …or, if the server no longer lists a group there, the id can be a direct conversation.
        store.decline(store.invitations.single())
        assertEquals(ConversationStore.Opened.RefusedIgnored, store.addDM(dm("ign", "u-bob")))
        store.unignore("ign")
        assertTrue(store.addDM(dm("ign", "u-bob")) is ConversationStore.Opened.Added)
    }

    // ---- a direct list that is lost as a whole ----

    @Test fun aWhollyUnreadableDirectListBlocksServerDrivenEntriesUntilTheUserActs() = runBlocking {
        backend.kv["w1|sidebar.dms"] = "{ not the list"
        assertTrue(store.load())
        assertTrue(store.review.allDirect); assertTrue(store.review.all)
        // The server lists a direct conversation, delivers into one, and lists a group — under
        // ids this device may have held as something else.
        backend.dmRows = listOf(ListedDm("c-1", "u-mallory", "mom"))
        backend.histories["c-1"] = from("u-me")
        backend.groupRows = listOf("c-2" to listOf("u-gil", "u-hana"))
        assertTrue(store.refreshDmList().isEmpty())
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("c-1", "u-mallory", "mom"))
        assertEquals(ConversationStore.Delivery.Refused, store.listUnboundDM("c-1", "u-mallory", "mom"))
        assertTrue(store.refreshGroups())
        assertTrue(store.dms.isEmpty())
        assertEquals("a group may sit under the id of a lost direct conversation", listOf(true), store.invitations.map { it.needsReview })
        // What the USER opens is theirs, and goes on receiving.
        assertTrue(store.addDM(dm("c-3", "u-bob")) is ConversationStore.Opened.Added)
        assertEquals(ConversationStore.Delivery.None, store.deliverDM("c-3", "u-bob", "bob"))
        drain()
        // It survives a relaunch…
        store = newStore()
        assertTrue(store.load())
        assertTrue(store.review.allDirect)
        assertTrue(store.refreshDmList().isEmpty())
        // …until the user says they have seen it: both flags go, and stay gone.
        assertTrue(store.refreshGroups())
        store.clearReview()
        assertFalse(store.review.all)
        assertEquals(listOf(false), store.invitations.map { it.needsReview })
        assertEquals(listOf("c-1"), store.refreshDmList().map { (it as ConversationStore.Delivery.Added).entry.conversationId })
        drain()
        store = newStore()
        assertTrue(store.load())
        assertEquals(ConversationStore.Review(), store.review)
    }

    @Test fun clearingTheReviewKeepsTheGroupsKnownByIdToHaveBeenHeld() = runBlocking {
        backend.kv["w1|sidebar.groups"] = """[{"conversationId":"g-2","memberUserIds":"oops"}]"""
        backend.kv["w1|" + GroupRules.DECLINED_KEY] = "{ nope"
        assertTrue(store.load())
        assertTrue(store.review.allGroups); assertFalse(store.review.allDirect)
        backend.groupRows = listOf("g-2" to listOf("u-gil", "u-hana"), "g-4" to listOf("u-ivy", "u-jon"))
        assertTrue(store.refreshGroups())
        assertEquals(listOf(true, true), store.invitations.map { it.needsReview })
        store.clearReview()
        assertEquals(listOf(true, false), store.invitations.map { it.needsReview })
        assertTrue(store.refreshGroups())
        assertEquals(listOf(true, false), store.invitations.map { it.needsReview })
    }

    // ---- small things ----

    @Test fun aSlotThatIsBeingWrittenIsStillHandedOverAtSignOut() = runBlocking {
        assertTrue(store.load())
        assertTrue(store.addDM(dm("d-1", "u-bob")) is ConversationStore.Opened.Added)
        val gate = CompletableDeferred<Unit>(); val entered = CompletableDeferred<Unit>()
        backend.gates["kvSet"] = gate; backend.entered["kvSet"] = entered
        val writing = launch(Dispatchers.Default) { store.flush() }
        entered.await()
        // The write is under way and has not landed; something more is changed meanwhile.
        assertTrue(store.addDM(dm("d-2", "u-carol")) is ConversationStore.Opened.Added)
        assertTrue(store.hasUnsaved)
        val handed = store.takeUnsaved()
        assertEquals(listOf("w1|sidebar.dms"), handed.map { it.first })
        assertTrue("d-1" in handed.single().second && "d-2" in handed.single().second)
        backend.gates.remove("kvSet"); gate.complete(Unit)
        writing.join()
    }

    @Test fun aLoadThatKeepsFailingIsCountedAndKeepsOneCopyPerContent() = runBlocking {
        backend.kv["w1|sidebar.groups"] = "{ not the groups"
        store.clock = { 1000L }
        assertTrue(store.load())
        assertEquals(0, store.loadFailures)
        // The next bind finds the same bytes back in place (the salvaged list could not be
        // written) — again and again.
        for (ms in listOf(2000L, 3000L)) {
            backend.kv["w1|sidebar.groups"] = "{ not the groups"
            store = newStore(); store.clock = { ms }
            assertTrue(store.load())
        }
        assertEquals("one copy per distinct content", listOf("w1|sidebar.groups.unreadable.1000"), backend.kv.keys.filter { it.startsWith("w1|sidebar.groups.unreadable.") })
        // A cache that cannot be read: counted, so it can be said; back to 0 once it reads.
        backend.kv.clear(); store = newStore()
        backend.cacheBroken = true
        assertFalse(store.load()); assertFalse(store.load())
        assertEquals(2, store.loadFailures)
        backend.cacheBroken = false
        assertTrue(store.load())
        assertEquals(0, store.loadFailures)
    }

    @Test fun acceptingUnderAClaimedDirectIdIsRefusedAndKeepsTheInvitation() = runBlocking {
        assertTrue(store.load())
        // A delivered (unclaimed) direct entry, then an invitation under the same id, then the
        // user WRITES in the direct conversation: it is theirs.
        assertTrue(store.deliverDM("x-1", "u-bob", null) is ConversationStore.Delivery.Added)
        backend.groupRows = listOf("x-1" to listOf("u-carol", "u-dave"))
        assertTrue(store.refreshGroups())
        val invitation = store.invitations.single()
        store.claimDM("x-1", "u-bob")
        assertNull(store.accept(invitation))
        assertEquals(listOf("x-1"), store.invitations.map { it.conversationId })
        assertTrue(store.groups.isEmpty())
        assertEquals(GroupRules.Route.DIRECT, store.route("x-1"))
        assertEquals(1, notices.size)
    }

    // ---- one direct entry, one peer ----

    @Test fun aSecondAccountNeverGetsAnEntryUnderAHeldDirectId() = runBlocking {
        loadedWithOneOfEach()
        val held = store.dms.single()
        val other = ConversationStore.Notice.OtherPeer("d-1")
        // A delivery "from mallory" inside bob's conversation: no entry (no "split" row either),
        // nothing to show or announce, said once.
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("d-1", "u-mallory", "bob"))
        assertFalse(store.deliverDM("d-1", "u-mallory", "bob").accepted)
        // A listing that names someone else for the id makes nothing and re-keys nothing.
        assertEquals(ConversationStore.Delivery.Refused, store.listUnboundDM("d-1", "u-zed", "bob"))
        // "Open a chat with mallory" answered with bob's id is refused: not bob's entry, not a second one.
        assertEquals(ConversationStore.Opened.Refused, store.addDM(dm("d-1", "u-mallory")))
        assertEquals(listOf(held), store.dms)
        assertEquals(listOf<ConversationStore.Notice>(other), notices.toList())
        // The held peer is still simply the held peer.
        assertEquals(ConversationStore.Delivery.None, store.deliverDM("d-1", "u-bob", null))
        assertTrue(store.deliverDM("d-1", "u-bob", null).accepted)
        assertEquals(held, (store.addDM(dm("d-1", "u-bob")) as ConversationStore.Opened.Existing).entry)
        // Through the listing path too: the server lists d-1 with history from bob AND mallory.
        backend.dmRows = listOf(ListedDm("d-1", "u-mallory", "bob")); backend.histories["d-1"] = from("u-bob", "u-mallory")
        assertTrue(store.refreshDmList().isEmpty())
        assertEquals(listOf(held), store.dms)
        assertEquals(1, notices.size)
    }

    @Test fun theFirstDecryptedSenderOfAnIdHoldsItAndAListedPeerIsOnlyAClaimUntilThen() = runBlocking {
        assertTrue(store.load())
        // Listed with nothing decrypted: unbound, the row's peer is the server's word…
        val listed = (store.listUnboundDM("x-1", "u-bob", "bob") as ConversationStore.Delivery.Added).entry
        assertFalse(listed.bound)
        // …a message from that same account binds it; one from another account gets nothing.
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("x-1", "u-mallory", null))
        assertTrue(store.deliverDM("x-1", "u-bob", null) is ConversationStore.Delivery.Bound)
        assertEquals(listOf("x-1" to "u-bob"), store.dms.map { it.conversationId to it.peerUserId })
        assertEquals(listOf<ConversationStore.Notice>(ConversationStore.Notice.OtherPeer("x-1")), notices.toList())
    }

    @Test fun splitAndDuplicateEntriesStoredByAnEarlierBuildAreReducedToTheHolder() = runBlocking {
        // Newest first, as stored: a "split" entry for mallory under bob's id, and an id whose
        // OLDEST entry is only what the server listed while the newer one was started here.
        backend.kv["w1|sidebar.dms"] = """[
            {"name":"","peerUserId":"u-mallory","peerDeviceId":"","conversationId":"old-1","bound":true,"origin":"split","claimed":false},
            {"name":"erin","peerUserId":"u-erin","peerDeviceId":"dev","conversationId":"old-2","bound":true,"origin":"local","claimed":true},
            {"name":"bob","peerUserId":"u-bob","peerDeviceId":"dev","conversationId":"old-1","bound":true,"origin":"local","claimed":true},
            {"name":"","peerUserId":"u-zed","peerDeviceId":"","conversationId":"old-2","bound":false,"origin":"listed","claimed":false}]"""
        val asStored = backend.kv["w1|sidebar.dms"]
        store.clock = { 500L }
        assertTrue(store.load())
        assertEquals(listOf("old-2" to "u-erin", "old-1" to "u-bob"), store.dms.map { it.conversationId to it.peerUserId })
        // Nothing is deleted without a copy: the list as it was is kept, and it is said.
        assertEquals(asStored, backend.kv["w1|sidebar.dms.duplicates.500"])
        assertEquals(listOf<ConversationStore.Notice>(ConversationStore.Notice.Duplicates("w1|sidebar.dms.duplicates.500")), notices.toList())
        assertTrue(store.dms.none { it.isSplit })
        drain()
        assertEquals(listOf("u-erin", "u-bob"), DmCodec.decode(backend.kv["w1|sidebar.dms"])!!.map { it.peerUserId })
        // Among equals the oldest (last) holds the id.
        val twice = listOf(DMConversation("", "u-b", "", "c", origin = DMConversation.ORIGIN_INBOUND, claimed = false), DMConversation("", "u-a", "", "c", origin = DMConversation.ORIGIN_INBOUND, claimed = false))
        assertEquals(listOf("u-a"), ConversationStore.holders(twice).map { it.peerUserId })
    }

    // ---- what of a batch of events may be shown and announced (the app's event handler) ----

    /** [group]: the event's sealed group marker (`DmEvent.isGroup`). */
    private data class Ev(val conversationId: String, val sender: String, val fromSelf: Boolean = false, val kind: String = "message", val group: Boolean = false)
    private suspend fun sort(vararg events: Ev) = store.sort(events.toList(), { it.conversationId }, { it.sender }, { it.fromSelf }, { it.group })

    @Test fun onlyWhatTheStoreAcceptedIsShownOrAnnounced() = runBlocking {
        loadedWithOneOfEach()
        // The server lists two more groups; the user ignores one. An (unclaimed) direct entry
        // already sits under each of those ids, made by an earlier delivery.
        assertTrue(store.deliverDM("inv", "u-erin", null) is ConversationStore.Delivery.Added)
        assertTrue(store.deliverDM("ign", "u-gil", null) is ConversationStore.Delivery.Added)
        backend.groupRows = listOf("g-1" to listOf("u-me", "u-carol", "u-dave"), "inv" to listOf("u-erin", "u-frank"), "ign" to listOf("u-gil", "u-hana"))
        assertTrue(store.refreshGroups())
        store.decline(store.invitations.first { it.conversationId == "ign" })
        notices.clear()
        backend.dmRows = listOf(ListedDm("d-new", "u-zed", "zed"), ListedDm("d-1", "u-mallory", "bob"))
        val sorted = sort(
            Ev("g-1", "u-carol", group = true),                 // a member, in the group
            Ev("g-1", "u-mallory", group = true),               // a ghost the server added: dropped
            Ev("g-1", "u-me", fromSelf = true, group = true),   // this account's own copy
            Ev("d-1", "u-bob"),                   // the held peer
            Ev("d-1", "u-mallory"),               // someone else under bob's id: refused
            Ev("inv", "u-erin"),                  // an unaccepted group, with an unclaimed entry
            Ev("ign", "u-gil"),                   // an ignored group, with an unclaimed entry
            Ev("d-new", "u-zed"), Ev("d-new", "u-zed", kind = "reaction"),   // new, direct
        )!!
        assertEquals(listOf("u-carol", "u-me"), sorted.grouped.map { it.sender })
        assertEquals(listOf("d-1" to "u-bob", "d-new" to "u-zed", "d-new" to "u-zed"), sorted.direct.map { it.conversationId to it.sender })
        // Nothing of the invitation or the ignored group is direct — an existing unclaimed
        // entry does not make it so.
        assertTrue((sorted.grouped + sorted.direct).none { it.conversationId == "inv" || it.conversationId == "ign" })
        assertTrue(sorted.invited.isEmpty())
        assertEquals("zed", (sorted.deliveries.single() as ConversationStore.Delivery.Added).claimedName)
        assertEquals(setOf(ConversationStore.Notice.Outsider("g-1"), ConversationStore.Notice.OtherPeer("d-1")), notices.toSet())
        assertEquals(setOf("d-new|u-zed", "d-1|u-bob", "inv|u-erin", "ign|u-gil"), store.dms.map { it.key }.toSet())
    }

    @Test fun anUnknownConversationIsAskedAboutOnceAndHeldBackWhenItCannotBe() = runBlocking {
        loadedWithOneOfEach()
        // Two unknown ids: one is a group started elsewhere, one is nothing the server lists.
        backend.groupRows = listOf("g-new" to listOf("u-erin", "u-frank"))
        var sorted = sort(Ev("g-new", "u-erin", group = true), Ev("d-new", "u-zed"))!!
        assertEquals(listOf("g-new"), sorted.invited.map { it.conversationId })
        assertEquals(listOf("d-new"), sorted.direct.map { it.conversationId })
        assertTrue(store.dms.none { it.conversationId == "g-new" })
        // The groups cannot be asked: an unknown conversation is not filed as 1:1.
        backend.serverDown = true
        sorted = sort(Ev("d-other", "u-yan"), Ev("d-1", "u-bob"))!!
        assertEquals(listOf("d-1"), sorted.direct.map { it.conversationId })
        assertTrue(store.dms.none { it.conversationId == "d-other" })
        // The stores cannot be read: nothing is decided at all.
        backend.serverDown = false; backend.cacheBroken = true
        assertNull(newStore().sort(listOf(Ev("d-1", "u-bob")), { it.conversationId }, { it.sender }, { it.fromSelf }, { it.group }))
    }

    // ---- only the user's own action claims an id ----

    @Test fun aServerMadeDirectEntryDoesNotBlockAcceptingAGroup() = runBlocking {
        assertTrue(store.load())
        assertTrue(store.listUnboundDM("x-1", "u-carol", "carol") is ConversationStore.Delivery.Added)
        assertTrue(store.deliverDM("x-2", "u-erin", "erin") is ConversationStore.Delivery.Added)
        backend.groupRows = listOf("x-1" to listOf("u-carol", "u-dave"), "x-2" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        assertEquals(listOf("x-1", "x-2"), store.invitations.map { it.conversationId })
        assertTrue(notices.isEmpty())
        // Until the user decides, the entry that exists keeps routing.
        assertEquals(GroupRules.Route.DIRECT, store.route("x-1"))
        assertNotNull(store.accept(store.invitations.first()))
        assertEquals(GroupRules.Route.GROUP, store.route("x-1"))
        assertEquals(listOf("x-2"), store.dms.map { it.conversationId })      // one store only
        // Writing in the other one makes it the user's: now it blocks.
        store.claimDM("x-2", "u-erin")
        assertNull(store.accept(store.invitations.single()))
        assertEquals(listOf("x-2"), store.dms.map { it.conversationId })
    }

    @Test fun entriesStoredBeforeTheClaimFieldExistedAreClaimed() = runBlocking {
        // Exactly what an earlier build wrote: origin "listed"/"inbound", no `claimed`.
        backend.kv["w1|sidebar.dms"] = """[{"name":"bob","peerUserId":"u-bob","peerDeviceId":"","conversationId":"old-1","bound":false,"origin":"listed"},
            {"name":"erin","peerUserId":"u-erin","peerDeviceId":"","conversationId":"old-2","bound":true,"origin":"inbound"}]"""
        assertTrue(store.load())
        assertTrue(store.dms.all { it.claimed })
        backend.groupRows = listOf("old-1" to listOf("u-carol", "u-dave"), "old-2" to listOf("u-carol", "u-dave"))
        assertTrue(store.refreshGroups())
        assertTrue(store.invitations.isEmpty())
        assertEquals(GroupRules.Route.DIRECT, store.route("old-1"))
        // …and stays claimed once written back in the new form.
        store.claimDM("old-1", "u-bob"); store.deliverDM("new-1", "u-zed", null); store.flush(); drain()
        assertEquals(mapOf("new-1" to false, "old-1" to true, "old-2" to true), DmCodec.decode(backend.kv["w1|sidebar.dms"])!!.associate { it.conversationId to it.claimed })
    }

    // ---- the load-order window, and a cache that cannot be read ----

    @Test fun nothingServerDrivenHappensBeforeBothStoresAreRead() = runBlocking(Dispatchers.Default) {
        backend.kv["w1|sidebar.groups"] = GroupRules.encode(listOf(GroupConversation("g-1", listOf("u-carol", "u-dave"))))
        backend.gates["kvGet"] = CompletableDeferred(); backend.entered["kvGet"] = CompletableDeferred()
        val loading = async { store.load() }
        backend.entered["kvGet"]!!.await()
        // The stores are being read. The server delivers into, and lists, the group's id as a DM.
        assertFalse(store.ready)
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("g-1", "u-mallory", null))
        assertEquals(ConversationStore.Delivery.Refused, store.listUnboundDM("g-1", "u-mallory", null))
        assertEquals(ConversationStore.Opened.Refused, store.addDM(dm("g-1", "u-mallory")))
        assertEquals(GroupRules.Route.UNKNOWN, store.route("g-1"))
        assertTrue(store.dms.isEmpty())
        backend.gates.remove("kvGet")!!.complete(Unit)
        assertTrue(loading.await())
        assertEquals(GroupRules.Route.GROUP, store.route("g-1"))
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("g-1", "u-mallory", null))
        assertTrue(store.dms.isEmpty())
        assertEquals(listOf<ConversationStore.Notice>(conflict("g-1")), notices.toList())
    }

    @Test fun aCacheThatCannotBeReadIsNotAnEmptyStore() = runBlocking {
        val stored = GroupRules.encode(listOf(GroupConversation("g-1", listOf("u-carol", "u-dave"))))
        backend.kv["w1|sidebar.groups"] = stored
        backend.dmRows = listOf(ListedDm("g-1", "u-mallory", "mallory"))
        backend.histories["g-1"] = from("u-mallory")
        backend.groupRows = listOf("g-1" to listOf("u-carol", "u-dave", "u-mallory"), "g-9" to listOf("u-x", "u-y"))
        // The read FAILS (the cache is not there to be read) while the server lists things.
        backend.cacheBroken = true
        assertFalse(store.load())
        assertTrue(store.refreshDmList().isEmpty())
        assertFalse(store.refreshGroups())
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("g-1", "u-mallory", null))
        assertNull(store.sort(listOf("g-1"), { it }, { "u-mallory" }, { false }, { true }))
        assertNull(store.accept(GroupConversation("g-9", listOf("u-x", "u-y"))))
        try { store.openGroup(listOf("u-x", "u-y")); fail("opened") } catch (_: IllegalStateException) {}
        assertTrue(store.dms.isEmpty()); assertTrue(store.invitations.isEmpty()); assertTrue(store.groups.isEmpty())
        drain()
        assertTrue("nothing is written over a store that could not be read", backend.writes.isEmpty())
        assertEquals(mapOf("w1|sidebar.groups" to stored), backend.kv.toMap())
        assertTrue(notices.isEmpty())
        // Readable again: read again, and the group that was there all along holds its id —
        // with the members this device fixed, not offered again as an invitation.
        backend.cacheBroken = false
        assertTrue(store.refreshGroups())
        assertEquals(listOf(GroupConversation("g-1", listOf("u-carol", "u-dave"), serverDisagrees = true)), store.groups)
        assertEquals(listOf("g-9"), store.invitations.map { it.conversationId })
        assertTrue(store.refreshDmList().isEmpty())
        assertTrue(store.dms.isEmpty())
    }

    // ---- a stored list that cannot be decoded is kept, said, and started again ----

    @Test fun anUndecodableListIsKeptAsideSaidAndStartedAgain() = runBlocking {
        val bad = "{ not the groups"
        backend.kv["w1|sidebar.groups"] = bad
        backend.kv["w1|sidebar.dms"] = DmCodec.encode(listOf(dm("d-1", "u-bob")))
        store.clock = { 1000L }
        assertTrue("not shut for good", store.load())
        assertEquals("the bytes are kept exactly", bad, backend.kv["w1|sidebar.groups.unreadable.1000"])
        assertEquals(listOf<ConversationStore.Notice>(ConversationStore.Notice.Unreadable("groups", "w1|sidebar.groups.unreadable.1000")), notices.toList())
        assertTrue(store.groups.isEmpty())
        assertEquals(listOf("d-1"), store.dms.map { it.conversationId })
        drain()
        assertEquals("[]", backend.kv["w1|sidebar.groups"])
        // It happens again later: a second copy; the first is not written over.
        backend.kv["w1|sidebar.groups"] = "[[["
        store = newStore(); store.clock = { 2000L }
        assertTrue(store.load())
        assertEquals(bad, backend.kv["w1|sidebar.groups.unreadable.1000"])
        assertEquals("[[[", backend.kv["w1|sidebar.groups.unreadable.2000"])
        assertEquals(2, notices.size)
    }

    @Test fun whatCanStillBeReadIsSalvagedAndALostGroupNeverComesBackAsAPlainInvitation() = runBlocking {
        // One element is damaged and one is not a group at all (one member); both ids are readable.
        val bad = """[{"conversationId":"g-1","memberUserIds":["u-carol","u-dave"]},{"conversationId":"g-2","memberUserIds":"oops"},
            {"conversationId":"g-3","memberUserIds":["u-erin","u-frank"]},{"conversationId":"g-5","memberUserIds":["u-solo"]},17]"""
        backend.kv["w1|sidebar.groups"] = bad
        store.clock = { 1000L }
        assertTrue(store.load())
        assertEquals("the readable groups are still joined", listOf("g-1", "g-3"), store.groups.map { it.conversationId })
        assertEquals(setOf("g-2", "g-5"), store.review.group)
        assertEquals(bad, backend.kv["w1|sidebar.groups.unreadable.1000"])
        assertEquals("the record is written before the salvaged list replaces the original",
            listOf("w1|sidebar.groups.unreadable.1000", "w1|sidebar.groups.latest.unreadable", "w1|conversations.review"), backend.writes.map { it.first }.take(3))
        drain()
        // The server lists the lost group with a ghost in it, and a group that really is new.
        backend.groupRows = listOf("g-2" to listOf("u-gil", "u-hana", "u-mallory"), "g-4" to listOf("u-ivy", "u-jon"))
        backend.dmRows = listOf(ListedDm("g-2", "u-mallory", "")); backend.histories["g-2"] = from("u-mallory")
        assertTrue(store.refreshGroups())
        assertEquals(listOf("g-2" to true, "g-4" to false), store.invitations.map { it.conversationId to it.needsReview })
        assertNull("never silently re-joined with the server's members", store.findGroup("g-2"))
        // Nothing server-driven makes it a direct conversation either; nor does "open a chat".
        assertTrue(store.refreshDmList().isEmpty())
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("g-2", "u-mallory", null))
        assertEquals(ConversationStore.Opened.Refused, store.addDM(dm("g-2", "u-mallory")))
        assertTrue(store.dms.isEmpty())
        // The user reviews it and joins: those members, and nothing left to review about it.
        val rejoined = (store.join(store.invitations.first()) as ConversationStore.Joined.Done).group
        assertEquals(listOf("u-gil", "u-hana", "u-mallory"), rejoined.others); assertFalse(rejoined.needsReview)
        assertEquals(setOf("g-5"), store.review.group)
        drain()
        // Next launch: everything reads; nothing is kept aside again.
        store = newStore()
        assertTrue(store.load())
        assertEquals(setOf("g-1", "g-2", "g-3"), store.groups.map { it.conversationId }.toSet())
        assertEquals(ConversationStore.Review(group = setOf("g-5")), store.review)
        assertEquals(1, backend.kv.keys.count { ".unreadable." in it })
    }

    @Test fun aLostDirectEntryIsNotRecreatedByTheServerOnlyByTheUser() = runBlocking {
        backend.kv["w1|sidebar.dms"] = """[{"name":"bob","peerUserId":"u-bob","peerDeviceId":"dev","conversationId":"d-1","bound":true,"origin":"local","claimed":true},{"conversationId":"d-x","peerUserId":42}]"""
        assertTrue(store.load())
        assertEquals(listOf("d-1"), store.dms.map { it.conversationId })
        assertEquals(setOf("d-x"), store.review.direct)
        // The server offers the lost id back — as a DM with someone, and as a group.
        backend.dmRows = listOf(ListedDm("d-x", "u-mallory", "bob")); backend.histories["d-x"] = from("u-mallory")
        backend.groupRows = listOf("d-x" to listOf("u-mallory", "u-zed"))
        assertTrue(store.refreshDmList().isEmpty())
        assertTrue(store.refreshGroups())
        assertEquals(ConversationStore.Delivery.Refused, store.deliverDM("d-x", "u-mallory", null))
        assertTrue(store.invitations.isEmpty())
        backend.openAnswer = "d-x"
        try { store.openGroup(listOf("u-carol", "u-dave")); fail("started") } catch (_: ConversationStore.ConflictException) {}
        // The user opens the chat again: theirs, and no longer lost.
        assertTrue(store.addDM(dm("d-x", "u-bob")) is ConversationStore.Opened.Added)
        assertTrue(store.review.direct.isEmpty())
    }

    @Test fun aGroupsListThatCannotBeReadAtAllMakesEveryListedGroupOneToReview() = runBlocking {
        backend.kv["w1|sidebar.groups"] = "{ not the groups"
        assertTrue(store.load())
        assertTrue(store.review.allGroups)
        backend.groupRows = listOf("g-1" to listOf("u-carol", "u-dave", "u-mallory"), "g-2" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        assertEquals(listOf(true, true), store.invitations.map { it.needsReview })
        assertTrue(store.groups.isEmpty())
        // …also when it is the review record itself that cannot be read.
        backend.kv.clear(); backend.kv["w1|conversations.review"] = "nope"
        store = newStore()
        assertTrue(store.load())
        assertTrue(store.review.allGroups)
        assertTrue("nothing listed becomes direct either", store.review.allDirect)
        assertEquals(listOf("nope"), backend.kv.filterKeys { it.startsWith("w1|conversations.review.unreadable.") }.values.toList())
    }

    @Test fun anUndecodableListThatCannotBeKeptLeavesTheStoreShut() = runBlocking {
        backend.kv["w1|sidebar.dms"] = "not json"
        backend.failWrites = true
        assertFalse(store.load()); assertFalse(store.ready)
        assertEquals(mapOf("w1|sidebar.dms" to "not json"), backend.kv.toMap())
        assertTrue(notices.isEmpty())
        backend.failWrites = false
        assertTrue(store.load())
        assertEquals(listOf("not json"), backend.kv.filterKeys { it.startsWith("w1|sidebar.dms.unreadable.") }.values.toList())
    }

    @Test fun whatCouldNotBeWrittenIsWrittenBeforeTheClientGoes() = runBlocking {
        assertTrue(store.load())
        backend.failWrites = true
        assertTrue(store.addDM(dm("d-1", "u-bob")) is ConversationStore.Opened.Added)
        drain()
        assertTrue(store.hasUnsaved); assertNull(backend.kv["w1|sidebar.dms"])
        // The app flushes before it drops the client on a switch (and after a rebind).
        backend.failWrites = false
        store.flush()
        assertFalse(store.hasUnsaved)
        assertEquals(listOf("d-1"), DmCodec.decode(backend.kv["w1|sidebar.dms"])!!.map { it.conversationId })
        // Sign-out cannot wait: the pending writes are handed over, once, as they are now.
        backend.failWrites = true
        store.claimDM("d-1", "u-bob"); store.addDM(dm("d-2", "u-zed")); drain()
        val handed = store.takeUnsaved()
        assertEquals(listOf("w1|sidebar.dms"), handed.map { it.first })
        assertEquals(listOf("d-2", "d-1"), DmCodec.decode(handed.single().second)!!.map { it.conversationId })
        assertFalse(store.hasUnsaved); assertTrue(store.takeUnsaved().isEmpty())
    }

    // ---- accept / start racing a refresh ----

    @Test fun anAcceptDuringARefreshIsNotReverted() = runBlocking {
        loadedWithOneOfEach()
        backend.groupRows = listOf("g-1" to listOf("u-carol", "u-dave"), "g-2" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        val invitation = store.invitations.single()
        // The listing has been answered; before the app sees it the user accepts g-2 and starts
        // g-3. The old code wrote the copy it took before the request back over both.
        backend.during["listGroupDms"] = {
            assertNotNull(store.accept(invitation))
            backend.openAnswer = "g-3"
            store.openGroup(listOf("u-gina", "u-hal"))
        }
        assertTrue(store.refreshGroups())
        assertEquals(setOf("g-1", "g-2", "g-3"), store.groups.map { it.conversationId }.toSet())
        assertTrue(store.invitations.isEmpty())
        drain()
        assertEquals(setOf("g-1", "g-2", "g-3"), GroupRules.decode(backend.kv["w1|sidebar.groups"]).map { it.conversationId }.toSet())
    }

    @Test fun acceptsAndRefreshesOnManyThreadsLoseNothing() = runBlocking(Dispatchers.Default) {
        assertTrue(store.load())
        val ids = (1..40).map { "g-$it" }
        backend.groupRows = ids.map { it to listOf("u-carol", "u-dave") }
        assertTrue(store.refreshGroups())
        val invited = store.invitations
        val saver = launch { repeat(200) { drain() } }
        (invited.map { inv -> async { store.accept(inv) } } +
            (1..40).map { async { store.refreshGroups() } } +
            (1..40).map { i -> async { store.deliverDM("d-$i", "u-p$i", null) } } +
            ids.map { id -> async { store.deliverDM(id, "u-mallory", null) } }).awaitAll()
        saver.join(); drain()
        assertEquals(ids.toSet(), store.groups.map { it.conversationId }.toSet())
        assertEquals((1..40).map { "d-$it" }.toSet(), store.dms.map { it.conversationId }.toSet())
        assertTrue(store.groups.all { it.others == listOf("u-carol", "u-dave") })
        // What is in the cache is the final state, not an earlier one that landed late.
        assertEquals(store.groups, GroupRules.decode(backend.kv["w1|sidebar.groups"]))
        assertEquals(store.dms, DmCodec.decode(backend.kv["w1|sidebar.dms"]))
    }

    @Test fun aListingNeverRemovesOrReMembersAnAcceptedGroup() = runBlocking {
        loadedWithOneOfEach()
        for (listed in listOf(emptyList(), listOf("g-1" to listOf("u-ghost", "u-other")), listOf("g-1" to emptyList()),
            listOf("g-1" to listOf("u-carol", "u-dave", "u-ghost"), "g-1" to listOf("u-dave", "u-carol")))) {
            backend.groupRows = listed
            assertTrue(store.refreshGroups())
            assertUntouched()
            if (listed.isNotEmpty()) assertTrue(store.groups.single().serverDisagrees)
        }
        backend.groupRows = listOf("g-2" to listOf("u-erin", "u-frank"), "g-2" to listOf("u-erin", "u-mallory"))
        assertTrue(store.refreshGroups())
        assertEquals(listOf(listOf("u-erin", "u-frank")), store.invitations.map { it.others })
    }

    @Test fun whenTheServerCannotBeAskedNothingChanges() = runBlocking {
        loadedWithOneOfEach()
        backend.serverDown = true
        assertFalse(store.refreshGroups())
        assertTrue(store.refreshDmList().isEmpty())
        assertUntouched()
    }

    // ---- saving, notices ----

    @Test fun savesLandInOrder() = runBlocking(Dispatchers.Default) {
        assertTrue(store.load())
        repeat(30) { i -> store.addDM(dm("c-$i", "u-$i")) }
        // Every save that was asked for, run at once on many threads.
        val jobs = generateSequence { pendingSaves.poll() }.toList().map { launch { it() } }
        jobs.forEach { it.join() }
        assertEquals(store.dms, DmCodec.decode(backend.kv["w1|sidebar.dms"]))
        assertEquals(30, store.dms.size)
    }

    @Test fun aNoticeIsSaidOnceAcrossLaunches() = runBlocking {
        loadedWithOneOfEach()
        repeat(3) { store.deliverDM("g-1", "u-mallory", null) }
        repeat(2) { store.notice(ConversationStore.Notice.Outsider("g-1")) }
        assertEquals(listOf(conflict("g-1"), ConversationStore.Notice.Outsider("g-1")), notices.toList())
        drain()
        // Next launch: a new store over the same cache.
        notices.clear(); store = newStore()
        assertTrue(store.load())
        store.deliverDM("g-1", "u-mallory", null)
        store.notice(ConversationStore.Notice.Outsider("g-1"))
        assertTrue(notices.isEmpty())
        assertUntouched()
    }

    // ---- a store only ever uses its own workspace's client ----

    @Test fun aStoreNeverReadsOrWritesThroughAnotherWorkspacesClient() = runBlocking {
        // What the app does: the backend of workspace w1's store takes its client from the
        // (workspace, client) pair that is bound right now.
        val other = FakeBackend()                      // workspace w2's cache and server
        other.kv["w1|sidebar.dms"] = DmCodec.encode(listOf(dm("theirs", "u-zed")))
        other.dmRows = listOf(ListedDm("theirs-2", "u-zed", "zed")); other.histories["theirs-2"] = from("u-zed")
        var bound: BoundClient<FakeBackend>? = BoundClient("w2", other)   // mid-switch: w2's client is up
        val routed = object : ConversationBackend {
            private fun c() = BoundClient.of(bound, "w1")
            override suspend fun kvGet(key: String) = c().kvGet(key)
            override suspend fun kvSet(key: String, value: String) = c().kvSet(key, value)
            override suspend fun listDms() = c().listDms()
            override suspend fun dmHistory(conversationId: String) = c().dmHistory(conversationId)
            override suspend fun listGroupDms() = c().listGroupDms()
            override suspend fun openGroupDm(members: List<String>) = c().openGroupDm(members)
        }
        val w1 = ConversationStore(routed, "w1", "u-me", { pendingSaves += it }, object : ConversationStore.Listener {
            override fun changed(dms: List<DMConversation>, groups: List<GroupConversation>, invitations: List<GroupConversation>) {}
            override fun notice(notice: ConversationStore.Notice) { notices += notice }
        })
        // Nothing of w2 is read as w1's, and w1's gate stays shut (not "empty").
        assertFalse(w1.load()); assertFalse(w1.ready)
        assertTrue(w1.refreshDmList().isEmpty()); assertFalse(w1.refreshGroups())
        assertTrue(w1.dms.isEmpty())
        bound = null
        assertFalse(w1.load())
        // w1's own client is bound: now it loads — from w1's cache.
        bound = BoundClient("w1", backend)
        assertTrue(w1.load()); assertTrue(w1.dms.isEmpty())
        assertTrue(w1.addDM(dm("mine", "u-bob")) is ConversationStore.Opened.Added)
        // The switch happens before the save runs: it is not written into w2's cache, and it
        // is not lost — it is written once w1's client is back.
        bound = BoundClient("w2", other)
        while (true) { (pendingSaves.poll() ?: break)() }; w1.flush()
        assertTrue(other.writes.isEmpty()); assertTrue(backend.writes.isEmpty())
        bound = BoundClient("w1", backend)
        w1.flush()
        assertEquals(listOf("mine"), DmCodec.decode(backend.kv["w1|sidebar.dms"])!!.map { it.conversationId })
        assertTrue(other.writes.isEmpty())
        assertEquals("ok", try { BoundClient.of(BoundClient("w2", "ok"), "w2") } catch (_: Exception) { "threw" })
        assertEquals("threw", try { BoundClient.of(BoundClient("w2", "ok"), "w1") } catch (_: Exception) { "threw" })
        assertEquals("threw", try { BoundClient.of<String>(null, "w1") } catch (_: Exception) { "threw" })
        // Up without its cache: usable for asking the server, never for the stores.
        val cacheless = BoundClient("w1", "c", cacheOpen = false)
        assertEquals("c", BoundClient.of(cacheless, "w1"))
        assertEquals("threw", try { BoundClient.withCache(cacheless, "w1") } catch (_: Exception) { "threw" })
        assertEquals("c", BoundClient.withCache(BoundClient("w1", "c"), "w1"))
        assertEquals("threw", try { BoundClient.withCache(BoundClient("w2", "c"), "w1") } catch (_: Exception) { "threw" })
    }

    private suspend fun drain() { while (true) { (pendingSaves.poll() ?: break)() }; store.flush() }

    // ---- two binds that overlap: only the latest puts a client up, under its own workspace ----

    @Test fun overlappingBindsNeverLabelOneWorkspacesClientAsAnothers() = runBlocking {
        val binding = ClientBinding<String>()
        val closed = mutableListOf<String>()
        // What the app's bind does: take a turn, open the cache (takes a while), then commit
        // under the workspace id IT was given — or close its client if superseded.
        suspend fun bind(workspaceId: String, opened: kotlinx.coroutines.CompletableDeferred<Unit>): Boolean {
            val turn = binding.begin()
            val client = "client-of-$workspaceId"
            opened.await()
            if (!binding.commit(turn, workspaceId, client)) { closed += client; return false }
            return true
        }
        // bind(w1) starts and is waiting on its cache; bind(w2) starts during that.
        val openA = kotlinx.coroutines.CompletableDeferred<Unit>(); val openB = kotlinx.coroutines.CompletableDeferred<Unit>()
        val first = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { bind("w1", openA) }
        val second = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { bind("w2", openB) }
        assertNull(binding.bound)
        // w1's cache opens first, while w2's bind is the current one: w1's client is NOT put up
        // — not as w2's (the bug), and not as w1's either.
        openA.complete(Unit); assertFalse(first.await())
        assertNull(binding.bound); assertEquals(listOf("client-of-w1"), closed)
        openB.complete(Unit); assertTrue(second.await())
        assertEquals("w2", binding.bound!!.workspaceId); assertEquals("client-of-w2", binding.bound!!.client)
        assertEquals("threw", try { BoundClient.of(binding.bound, "w1") } catch (_: Exception) { "threw" })

        // The other order: the later bind finishes first; the earlier one then changes nothing.
        val openC = kotlinx.coroutines.CompletableDeferred<Unit>(); val openD = kotlinx.coroutines.CompletableDeferred<Unit>()
        val third = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { bind("w1", openC) }
        val fourth = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { bind("w2", openD) }
        openD.complete(Unit); assertTrue(fourth.await())
        openC.complete(Unit); assertFalse(third.await())
        assertEquals("w2", binding.bound!!.workspaceId); assertEquals("client-of-w2", binding.bound!!.client)

        // Taking the client down (teardown, switching away) also ends a bind in flight.
        val openE = kotlinx.coroutines.CompletableDeferred<Unit>()
        val fifth = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { bind("w1", openE) }
        assertNull(binding.clear())
        openE.complete(Unit); assertFalse(fifth.await())
        assertNull(binding.bound)
    }

    // ---- a server answer belongs to the workspace whose client was asked ----

    @Test fun anAnswerHeldAcrossAWorkspaceSwitchIsDecidedNowhere() = runBlocking {
        loadedWithOneOfEach(); store.tag = "w1"
        val other = FakeBackend()
        val w2 = ConversationStore(other, "w2", "u-me", { pendingSaves += it }, object : ConversationStore.Listener {
            override fun changed(dms: List<DMConversation>, groups: List<GroupConversation>, invitations: List<GroupConversation>) {}
            override fun notice(notice: ConversationStore.Notice) { notices += notice }
        }).also { it.tag = "w2" }
        assertTrue(w2.load())
        var bound: BoundClient<String>? = BoundClient("w1", "client-1", turn = 1)
        var current: ConversationStore? = store
        // What the app's handlers do: take the ticket, ask the server, then check it.
        val ticket = StoreTicket.take(bound, current)!!
        assertTrue(ticket.isCurrent(bound, current))
        // The server holds its answer; the user switches to w2 meanwhile.
        bound = BoundClient("w2", "client-2", turn = 2); current = w2
        assertFalse("the batch is dropped", ticket.isCurrent(bound, current))
        assertTrue(ticket.store === store)               // …and would only ever have gone to w1's store
        assertTrue(w2.dms.isEmpty())
        // Mid-switch (the new workspace's store is up, its client is not — or the reverse): no ticket.
        assertNull(StoreTicket.take(BoundClient("w1", "client-1", turn = 1), w2))
        assertNull(StoreTicket.take<String>(null, w2))
        assertNull(StoreTicket.take(bound, null))
        // Back on w1 through a NEW bind: an answer asked of the old client is still not used.
        bound = BoundClient("w1", "client-3", turn = 3); current = store
        assertFalse(ticket.isCurrent(bound, current))
        assertTrue(StoreTicket.take(bound, current)!!.isCurrent(bound, current))
    }

    // ---- only the members the user was shown can be accepted ----

    @Test fun acceptingFixesOnlyTheMembersThatWereOnScreen() = runBlocking {
        loadedWithOneOfEach()
        backend.groupRows = listOf("g-2" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        val onScreen = store.invitations.single()
        // While the dialog is open, the server lists the conversation with someone else in it.
        backend.groupRows = listOf("g-2" to listOf("u-erin", "u-frank", "u-mallory"))
        assertTrue(store.refreshGroups())
        assertEquals(ConversationStore.Joined.Changed(store.invitations.single()), store.join(onScreen))
        assertNull(store.accept(onScreen))
        assertNull("a member set the user never saw is not fixed", store.findGroup("g-2"))
        assertEquals(listOf("g-2"), store.invitations.map { it.conversationId })
        // Shown again and accepted as shown: those members, exactly.
        val reviewed = store.invitations.single()
        val joined = (store.join(reviewed) as ConversationStore.Joined.Done).group
        assertEquals(setOf("u-erin", "u-frank", "u-mallory"), joined.others.toSet())
        // A second tap on the same dialog: the group as accepted; a stale dialog: nothing.
        assertEquals(ConversationStore.Joined.Done(store.findGroup("g-2")!!), store.join(reviewed))
        assertEquals(ConversationStore.Joined.Refused, store.join(onScreen))
        // Names heard meanwhile are not a change of members.
        backend.groupRows = listOf("g-3" to listOf("u-gil", "u-hana"))
        assertTrue(store.refreshGroups())
        assertTrue(store.join(store.invitations.single().copy(claimedNames = mapOf("u-gil" to "gil"))) is ConversationStore.Joined.Done)
    }

    @Test fun aNoticeWhoseRowCouldNotBeStoredIsSaidAgainNextLaunch() = runBlocking {
        loadedWithOneOfEach()
        activityWrites = false                       // Security activity cannot write right now
        repeat(3) { store.deliverDM("g-1", "u-mallory", null) }
        assertEquals("not twice in one launch", listOf<ConversationStore.Notice>(conflict("g-1")), notices.toList())
        drain()
        // Next launch: it was never stored, so it is said — and this time it is stored.
        notices.clear(); activityWrites = true; store = newStore()
        assertTrue(store.load())
        store.deliverDM("g-1", "u-mallory", null)
        assertEquals(listOf<ConversationStore.Notice>(conflict("g-1")), notices.toList())
        drain()
        notices.clear(); store = newStore()
        assertTrue(store.load())
        store.deliverDM("g-1", "u-mallory", null)
        assertTrue("stored: never again", notices.isEmpty())
    }

    // ---- the sealed group marker (DmEvent.isGroup) and A16 ----

    @Test fun theMarkerDecidesWhereAnEventMayBeFiled() {
        for (r in listOf(GroupRules.Route.GROUP, GroupRules.Route.INVITATION)) {
            assertTrue(GroupRules.markerFits(r, true)); assertFalse(GroupRules.markerFits(r, false))
        }
        for (r in listOf(GroupRules.Route.DIRECT, GroupRules.Route.UNKNOWN)) {
            assertFalse(GroupRules.markerFits(r, true)); assertTrue(GroupRules.markerFits(r, false))
        }
        assertFalse(GroupRules.markerFits(GroupRules.Route.DECLINED, true))
        assertFalse(GroupRules.markerFits(GroupRules.Route.DECLINED, false))
        // A16: only an unclaimed entry gives way, and never under an id fixed as 1:1.
        assertTrue(GroupRules.directGivesWay(claimed = false, fixedAsGroup = null))
        assertTrue(GroupRules.directGivesWay(claimed = false, fixedAsGroup = true))
        assertFalse(GroupRules.directGivesWay(claimed = false, fixedAsGroup = false))
        assertFalse(GroupRules.directGivesWay(claimed = true, fixedAsGroup = true))
        assertTrue(GroupRules.mayBecomeGroup(null)); assertTrue(GroupRules.mayBecomeGroup(true)); assertFalse(GroupRules.mayBecomeGroup(false))
    }

    @Test fun aGroupMarkedMessageIsNeverFiledAsADirectChat() = runBlocking {
        loadedWithOneOfEach()
        backend.dmRows = listOf(ListedDm("x-9", "u-zed", "zed"))
        // Unknown id, marked as a group, and the server does not list it as a group: no direct entry.
        val sorted = sort(Ev("x-9", "u-zed", group = true))!!
        assertTrue(sorted.direct.isEmpty()); assertTrue(sorted.grouped.isEmpty()); assertTrue(sorted.invited.isEmpty())
        assertTrue(store.dms.none { it.conversationId == "x-9" })
        // Marked, into bob's held (claimed) 1:1: dropped, the entry stays, said once.
        val into = sort(Ev("d-1", "u-bob", group = true))!!
        assertTrue(into.direct.isEmpty())
        assertUntouched()
        assertTrue(conflict("d-1") in notices)
    }

    @Test fun aBareMessageIsNeverFiledInAGroup() = runBlocking {
        loadedWithOneOfEach()
        backend.groupRows = listOf("g-1" to listOf("u-carol", "u-dave"), "g-inv" to listOf("u-erin", "u-frank"))
        val sorted = sort(Ev("g-1", "u-carol"), Ev("g-inv", "u-erin"), Ev("g-1", "u-carol", group = true))!!
        assertEquals(1, sorted.grouped.size)
        assertTrue(sorted.grouped.single().group)
        // A bare event in an invitation is not an invitation's message, nor a direct one.
        assertTrue(sorted.invited.isEmpty())
        assertTrue(sorted.direct.isEmpty())
        assertTrue(store.dms.none { it.conversationId == "g-1" || it.conversationId == "g-inv" })
        assertEquals(listOf("g-inv"), store.invitations.map { it.conversationId })
    }

    @Test fun anUnclaimedDirectEntryGivesWayToAGroupTheCoreFixed() = runBlocking {
        assertTrue(store.load())
        // A listing made an unclaimed entry; then a marked message arrives under the same id.
        assertTrue(store.listUnboundDM("x-1", "u-carol", "carol") is ConversationStore.Delivery.Added)
        backend.groupRows = listOf("x-1" to listOf("u-carol", "u-dave"))
        val sorted = sort(Ev("x-1", "u-carol", group = true))!!
        assertTrue(store.dms.isEmpty())
        assertEquals(listOf("x-1"), sorted.invited.map { it.conversationId })
        assertEquals(GroupRules.Route.INVITATION, store.route("x-1"))
        assertTrue(notices.isEmpty())
    }

    @Test fun anIdFixedAsOneToOneIsNeverTakenByAGroup() = runBlocking {
        assertTrue(store.load())
        // An unclaimed entry with erin; the core fixed the conversation as 1:1 (a bare message).
        assertTrue(store.deliverDM("x-2", "u-erin", "erin") is ConversationStore.Delivery.Added)
        backend.fixed["x-2"] = false
        backend.groupRows = listOf("x-2" to listOf("u-erin", "u-frank"))
        assertTrue(store.refreshGroups())
        // Not offered as a group, the entry stays, the clash is said.
        assertTrue(store.invitations.isEmpty())
        assertEquals(listOf("x-2"), store.dms.map { it.conversationId })
        assertTrue(conflict("x-2") in notices)
        // Starting a group whose answer is that id is refused too.
        backend.openAnswer = "x-2"
        try { store.openGroup(listOf("u-erin", "u-frank")); fail("took a 1:1 id") } catch (_: ConversationStore.ConflictException) {}
        assertTrue(store.groups.isEmpty())
        assertEquals(listOf("x-2"), store.dms.map { it.conversationId })
    }

    @Test fun aListedDirectRowForAGroupFixedIdMakesNoEntryAndAnUnclaimedOneGivesWay() = runBlocking {
        assertTrue(store.load())
        assertTrue(store.listUnboundDM("x-3", "u-gil", "gil") is ConversationStore.Delivery.Added)
        backend.fixed["x-3"] = true; backend.fixed["x-4"] = true
        backend.dmRows = listOf(ListedDm("x-3", "u-gil", "gil"), ListedDm("x-4", "u-hana", "hana"))
        backend.histories["x-3"] = from("u-gil"); backend.histories["x-4"] = from("u-hana")
        assertTrue(store.refreshDmList().isEmpty())
        assertTrue(store.dms.isEmpty())
        // A claimed entry never gives way.
        assertTrue(store.addDM(dm("x-5", "u-ivy")) is ConversationStore.Opened.Added)
        backend.fixed["x-5"] = true
        backend.dmRows = listOf(ListedDm("x-5", "u-ivy", "ivy")); backend.histories["x-5"] = from("u-ivy")
        store.refreshDmList()
        assertEquals(listOf("x-5"), store.dms.map { it.conversationId })
    }
}
