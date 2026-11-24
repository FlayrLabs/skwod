package io.skwod.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uniffi.skwod_core.SkwodClient

/**
 * Approve a join request and hand the new member their keys. Keys go out ONLY when the server
 * actually admitted this exact user AND the username lookup resolves to that same account — a
 * failed approve, or a username that now belongs to someone else, sends nothing.
 */
suspend fun approveAndProvision(client: SkwodClient, serverId: String, req: uniffi.skwod_core.JoinRequest): Boolean {
    try { client.approveJoinRequest(serverId, req.userId) } catch (_: Exception) { return false }
    // The hand-off is retried (their device may register a moment after the approval); the
    // membership sync of whoever has the channel open covers what still fails here.
    for (wait in Backoff.delays(3, 1_500, 10_000)) {
        val found = try { client.findUser(req.username) } catch (_: Exception) { null }
        if (found != null && !isSameAccount(found.userId, req.userId)) break     // not their name: send nothing
        if (found != null) {
            try { client.provisionMember(serverId, found.userId, found.deviceId); break } catch (_: Exception) {}
        }
        delay(wait)
    }
    return true
}

/** The identity check behind every username → device lookup that leads to keys being sent. */
fun isSameAccount(foundUserId: String?, expectedUserId: String): Boolean =
    foundUserId != null && expectedUserId.isNotEmpty() && foundUserId == expectedUserId

/** A joined channel, carrying the server it belongs to. Mirror of iOS `RealSpace`. */
data class RealSpace(
    val name: String,
    val channelName: String,
    val serverId: String,
    val channelId: String,
    val inviteCode: String = "",
    val spaceKeyHex: String = "",
)

/**
 * A 1:1 conversation entry in the list.
 *
 * An entry is bound to ONE peer account for ever. [peerUserId] is decided on this device — the
 * account the user chose when starting the chat, or the decrypted sender of a message — never
 * taken over by a later sender, and never rewritten from the server's participant list.
 * [name] is only the name that was CLAIMED when the entry was made; what is shown, and how far
 * it is trusted, comes from the contact book ([ContactBook.shown]).
 */
data class DMConversation(
    val name: String,
    val peerUserId: String,
    val peerDeviceId: String,
    val conversationId: String,
    /** False while the peer is only what the server's list says (no decrypted message from them yet, not started here). */
    val bound: Boolean = true,
    val origin: String = ORIGIN_LOCAL,
    /**
     * Does this entry CLAIM its conversation id ([GroupRules.mayClaim])? Only something the
     * user did makes a claim: starting the chat, writing in it. False = made by something that
     * arrived or was listed — it routes its own events, but does not keep a group from being
     * accepted under the same id. (Entries stored before this existed all count as claimed.)
     */
    val claimed: Boolean = true,
) {
    /** Identity of the entry: the same server conversation id under another peer is another entry. */
    val key: String get() = "$conversationId|$peerUserId"
    /**
     * A message that arrived inside a conversation already bound to someone else. It is kept
     * apart, shows only that sender's messages, and cannot be replied to from here.
     */
    val isSplit: Boolean get() = origin == ORIGIN_SPLIT

    companion object {
        /** Started on this device by the user (New chat). */
        const val ORIGIN_LOCAL = "local"
        /** Listed because a decrypted message arrived. */
        const val ORIGIN_INBOUND = "inbound"
        /** Listed from the server's conversation list only. */
        const val ORIGIN_LISTED = "listed"
        const val ORIGIN_SPLIT = "split"
    }
}

/** The stored form of the joined spaces (`<workspace>|sidebar.spaces`), unchanged since build 43. */
object SpaceCodec {
    private fun spaceOf(o: JSONObject): RealSpace =
        RealSpace(o.getString("name"), o.getString("channelName"), o.getString("serverId"),
            o.getString("channelId"), o.optString("inviteCode", ""), o.optString("spaceKeyHex", ""))

    /** STRICT: null = unreadable (never "none"); nothing stored = none. */
    fun decode(json: String?): List<RealSpace>? {
        if (json.isNullOrBlank()) return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { spaceOf(arr.getJSONObject(it)) }
        } catch (_: Exception) { null }
    }

    /** What can still be read of a stored list, element by element. */
    fun salvage(json: String): List<RealSpace> =
        try { JSONArray(json).let { arr -> (0 until arr.length()).mapNotNull { i -> try { spaceOf(arr.getJSONObject(i)) } catch (_: Exception) { null } } } } catch (_: Exception) { emptyList() }
}

/** One server inside the skwod, with its channels — a sidebar category. */
data class ServerGroup(val serverId: String, val name: String, val channels: List<RealSpace>)

/** A selectable destination. Home = DMs list (the skwod rail icon), Feed = posts/stories. */
sealed class SidebarItem {
    data object Home : SidebarItem()
    data object Feed : SidebarItem()
    data class Space(val space: RealSpace) : SidebarItem()
    data class Dm(val dm: DMConversation) : SidebarItem()
    /** A group conversation (3–10 people). */
    data class Group(val group: GroupConversation) : SidebarItem()
}

/**
 * Observable, persisted sidebar state for the active workspace — the Android peer of iOS `ChatModel`.
 * Holds the joined channels (grouped into servers), DMs, and the current selection. Lists survive
 * relaunches via the engine's encrypted kv store, keyed by the active workspace id. Membership
 * recovery re-provisions this device after a re-login/reinstall with no invite code needed.
 */
class AppChat(private val model: AppModel) {

    val spaces = mutableStateListOf<RealSpace>()
    val dms = mutableStateListOf<DMConversation>()
    private val selectionState = mutableStateOf<SidebarItem?>(null)
    /** Suppresses the last-channel persist while restoring the remembered selection on load. */
    private var loadingSelection = false
    var selection: SidebarItem?
        get() = selectionState.value
        set(v) {
            selectionState.value = v
            // Tell the relay which chat is on screen — its messages shouldn't notify.
            model.realtime.focusedTopic = when (v) {
                is SidebarItem.Space -> "channel:${v.space.channelId}"
                is SidebarItem.Dm -> "dm:${v.dm.conversationId}"
                is SidebarItem.Group -> "dm:${v.group.conversationId}"
                else -> null
            }
            // Remember the last-opened channel (kv-synced across devices) so re-entering reopens it.
            if (v is SidebarItem.Space && !loadingSelection) {
                model.launchIO { try { model.client?.kvSet("${model.current?.id}|lastChannel", v.space.channelId) } catch (_: Exception) {} }
            }
        }
    var homeMode by mutableStateOf(false)
    /** The server picked in the rail whose channels the middle column shows (follows the selection). */
    var railServerId by mutableStateOf<String?>(null)
    /** True while a just-joined server is being provisioned; the list shows a "setting up" spinner. */
    var provisioning by mutableStateOf(false)
    private var discoverCount = 0
    /** Bumped whenever the lists mutate so Composables keyed on it recompose. */
    var revision by mutableStateOf(0)
        private set

    private var loadedFor: String? = null

    /**
     * The 1:1 and group stores of the active workspace ([ConversationStore]): the only thing
     * that changes [dms], [GroupDms.list] and [GroupDms.invitations], which are its published
     * copies for the UI. One per workspace; whatever is still running against a previous
     * workspace's store finishes there and shows nowhere.
     */
    @Volatile private var storeRef: ConversationStore? = null
    private val storeLock = Any()
    val store: ConversationStore? get() {
        val w = model.current ?: return null
        storeRef?.takeIf { it.tag == w.id }?.let { return it }
        return synchronized(storeLock) {
            storeRef?.takeIf { it.tag == w.id } ?: run {
                park()
                // The store that was parked for this workspace with changes it could not
                // write — or a fresh one.
                (parked.remove(w.id) ?: newStore(w.id, w.userId)).also { storeRef = it; it.republish() }
            }
        }
    }

    /**
     * Stores that were replaced while they still had unsaved changes (their client was down):
     * taken up again — with everything they hold — the next time their workspace is active,
     * and written then ([flushStore]). In memory only: not across the app being closed.
     */
    private val parked = HashMap<String, ConversationStore>()
    /** Call under [storeLock]. */
    private fun park() { storeRef?.takeIf { it.ready && it.hasUnsaved }?.let { parked[it.tag] = it } }
    /** Nothing is kept for a workspace whose data was deleted. */
    fun forgetParked(workspaceId: String) = synchronized(storeLock) { parked.remove(workspaceId); Unit }
    /** What the stores still have to write, handed over to a caller that is about to close the client ([ConversationStore.takeUnsaved]). */
    fun takeUnsaved(): List<Pair<String, String>> = storeRef?.takeUnsaved() ?: emptyList()

    private fun newStore(wid: String, me: String?): ConversationStore {
        lateinit var made: ConversationStore
        val backend = object : ConversationBackend {
            // Only ever the cache and server of the workspace this store belongs to.
            // (Decided from ONE read of the client-and-its-workspace pair: during a switch
            // `current` and `client` do not change together.)
            private fun client(): SkwodClient = BoundClient.of(model.bound, wid)
            // The core's STRICT read and write: "no cache attached" and "the read failed" are
            // thrown (CoreException.NoCache / .Cache), never answered as "nothing stored"; a
            // write that did not happen is thrown too, so the store keeps it pending.
            private fun cache(): SkwodClient = BoundClient.withCache(model.bound, wid)
            override suspend fun kvGet(key: String): String? = cache().kvRead(key)
            override suspend fun kvSet(key: String, value: String) = cache().kvWrite(key, value)
            override suspend fun listDms() = client().listDms().map { ListedDm(it.conversationId, it.peerUserId, it.peerUsername) }
            override suspend fun dmHistory(conversationId: String) = client().history("dm:$conversationId").map { HistoryAuthor(it.authorId, it.isSystem) }
            override suspend fun listGroupDms() = withContext(Dispatchers.IO) { client().listGroupDms().map { it.conversationId to it.memberUserIds } }
            override suspend fun openGroupDm(members: List<String>) = withContext(Dispatchers.IO) { client().openGroupDm(members) }
            // The core's own decision (sealed group marker / first send), never the server's is_group.
            override suspend fun dmIsGroup(conversationId: String): Boolean? = client().dmIsGroup(conversationId)
        }
        val listener = object : ConversationStore.Listener {
            override fun changed(dms: List<DMConversation>, groups: List<GroupConversation>, invitations: List<GroupConversation>) {
                if (storeRef !== made) return
                if (this@AppChat.dms.toList() != dms) { this@AppChat.dms.clear(); this@AppChat.dms.addAll(dms) }
                model.groups.published(groups, invitations)
                touched()
            }
            override fun notice(notice: ConversationStore.Notice) { if (storeRef === made) model.groups.say(notice, made) }
            override fun state(reviewPending: Boolean, ignored: Set<String>, loadFailures: Int) {
                if (storeRef === made) model.groups.state(reviewPending, ignored, loadFailures)
            }
        }
        made = ConversationStore(backend, wid, me, model::launchIO, listener)
        made.tag = wid
        return made
    }

    /** serverId → the one channel that server's feed and stories live in (`feedChannel`). */
    private val feedChannels = java.util.concurrent.ConcurrentHashMap<String, String>()

    /** The feed channel of [serverId], asked from the core once and then remembered. */
    suspend fun feedChannel(serverId: String): String? {
        feedChannels[serverId]?.let { return it }
        val asked = model.bound ?: return null
        val client = asked.client
        val cid = try { withContext(Dispatchers.IO) { client.feedChannel(serverId) } } catch (_: Exception) { return null }
        if (cid.isEmpty()) return null
        // Answered for the workspace that was asked: after a switch it is not remembered (or
        // subscribed to) in the other one.
        if (model.bound !== asked) return null
        if (feedChannels.put(serverId, cid) != cid) touched()      // subscribe to its events
        return cid
    }

    /** The set of conversations changed somewhere else (a group appeared): resubscribe. */
    fun conversationsChanged() = touched()

    private fun touched() {
        revision++
        // Keep the live relay subscribed to every joined channel + DM (+ server topics for presence),
        // with names for notification titles.
        val topics = HashSet<String>()
        val names = HashMap<String, String>()
        for (s in spaces) {
            topics.add("channel:${s.channelId}"); topics.add("server:${s.serverId}")
            names[s.channelId] = s.channelName
        }
        for (d in dms) topics.add("dm:${d.conversationId}")
        for (g in model.groups.list) topics.add("dm:${g.conversationId}")
        // The feed channel of each server is hidden from the channel list but still has events.
        for (cid in feedChannels.values) topics.add("channel:$cid")
        model.realtime.setTopics(topics)
    }

    /** Channels grouped by server, newest server first (addSpace inserts at the front). */
    fun serverGroups(): List<ServerGroup> {
        val order = ArrayList<String>()
        val byServer = HashMap<String, MutableList<RealSpace>>()
        val nameOf = HashMap<String, String>()
        for (s in spaces) {
            if (byServer[s.serverId] == null) {
                order.add(s.serverId); byServer[s.serverId] = ArrayList(); nameOf[s.serverId] = s.name
            }
            byServer[s.serverId]!!.add(s)
        }
        return order.map { ServerGroup(it, nameOf[it] ?: "Server", byServer[it]!!) }
    }

    /** The channel HIGHLIGHTED in the list (first one when a server is opened) — visual only, does
     *  NOT navigate to the chat. Tapping it (openChannel) is what opens the conversation. */
    var highlightedChannelId by mutableStateOf<String?>(null)
        private set

    /** The server whose middle column shows: the selected channel's server, else the rail-picked
     *  one, else the first. Drives the "servers in the rail" layout. */
    fun currentServer(): ServerGroup? {
        val groups = serverGroups()
        val sid = (selection as? SidebarItem.Space)?.space?.serverId ?: railServerId
        return groups.firstOrNull { it.serverId == sid } ?: groups.firstOrNull()
    }

    /** True when `g` is the server the middle column shows (for the rail's selection pill). */
    fun isServerActive(g: ServerGroup): Boolean {
        if (homeMode || selection is SidebarItem.Feed) return false
        (selection as? SidebarItem.Space)?.let { return it.space.serverId == g.serverId }
        return railServerId == g.serverId
    }

    /** Open a server from the rail: show its CHANNEL LIST with the first channel highlighted, but
     *  stay on the list — do NOT slide into the chat. The user taps a channel to open it. */
    fun openServer(g: ServerGroup) {
        homeMode = false
        railServerId = g.serverId
        selection = null                                   // stay on the list page (no chat nav)
        highlightedChannelId = g.channels.firstOrNull()?.channelId
        touched()
    }

    /**
     * Open a specific channel's chat (this is what navigates to the conversation). The USER
     * opening it from the server's channel list is what confirms, on this device, which server
     * the channel belongs to (`channelOpened`) — never a listing, never a restore of the last
     * channel. Refused (false) when the channel is already confirmed in another server: the
     * `channel_remap_refused` notice that follows is surfaced.
     */
    fun openChannel(s: RealSpace) {
        homeMode = false
        highlightedChannelId = s.channelId
        selection = SidebarItem.Space(s)
        touched()
        if (s.serverId.isEmpty() || s.serverId == "demo" || s.channelId.isEmpty()) return
        model.launchIO {
            val c = model.client ?: return@launchIO
            val confirmed = try { c.channelOpened(s.serverId, s.channelId) } catch (_: Exception) { true }
            if (!confirmed && model.client === c) model.surfaceSecurityNotices()
        }
    }

    /** Show the skwod overview (the server list); no channel open. Passing null returns to the
     *  server list itself (clears the picked server + highlight). */
    fun showServerBoxes(serverId: String?) {
        homeMode = false
        railServerId = serverId
        if (serverId == null) highlightedChannelId = null
        selection = null
        touched()
    }

    /** True when a server is picked so the list shows ITS channels (with a back arrow) — whether or
     *  not a channel's chat is open. Driven by railServerId, not selection, so opening a server
     *  shows its channel list without navigating into a conversation. */
    val inChannelsMode: Boolean get() = railServerId != null || selection is SidebarItem.Space

    /** Load the persisted lists for the active workspace (call when it changes). `openLastChannel`
     *  restores the last-viewed channel (app launch); otherwise land on the overview (skwod switch). */
    suspend fun loadIfNeeded(openLastChannel: Boolean = false) {
        val wid = model.current?.id ?: return
        if (loadedFor == wid) {
            // Already loaded — except what could not be READ then: that is read again, never
            // taken for empty (and never written until it has been read).
            if (!spacesRead) readSpaces()
            if (!model.contacts.loaded) model.contacts.load()
            return
        }
        loadedFor = wid
        selection = null
        railServerId = null
        spacesRead = false
        spaces.clear()
        readSpaces()
        // BOTH conversation stores — the 1:1 list and the groups this device accepted, with
        // the member sets it fixed for them — are read before anything is asked of the server.
        // If they cannot be read, every server-driven path stays shut ([ConversationStore.ready])
        // and reads again on its next run.
        store?.load()
        val loadedDms = store?.dms ?: emptyList()
        // The contact book is separate from this list. On its first run it is seeded from it:
        // chats the user started here are KNOWN, everything else UNVERIFIED.
        if (model.contacts.load()) {
            model.contacts.migrate(loadedDms.map { ContactTrust.Legacy(it.peerUserId, it.name, it.origin == DMConversation.ORIGIN_LOCAL) })
        }
        touched()
        if (openLastChannel) restoreLastChannel()
    }

    /** Open the last channel viewed on this skwod (kv-synced across devices), else the first — so a
     *  skwod always lands on a conversation, never a blank overview. No-op if there are no channels. */
    suspend fun restoreLastChannel() {
        val last = try { model.client?.kvGet("${model.current?.id}|lastChannel") } catch (_: Exception) { null }
        val target = spaces.firstOrNull { it.channelId == last } ?: spaces.firstOrNull() ?: return
        loadingSelection = true
        railServerId = target.serverId
        highlightedChannelId = target.channelId
        selection = SidebarItem.Space(target)
        loadingSelection = false
    }

    /** Forget in-memory lists when the workspace switches so the next load re-reads its cache. */
    fun reset() { synchronized(storeLock) { park(); storeRef = null }; tombstones.clear(); loadedFor = null; spacesRead = false; feedChannels.clear(); spaces.clear(); dms.clear(); selection = null; homeMode = false; touched() }

    fun addSpace(s: RealSpace) {
        if (tombstones.hides(s.serverId)) return
        if (spaces.none { it.channelId == s.channelId }) spaces.add(0, s)
        homeMode = false
        selection = SidebarItem.Space(s)
        touched()
        persistSpaces()
    }

    private fun addSpaceQuietly(s: RealSpace) {
        if (spaces.any { it.channelId == s.channelId } || tombstones.hides(s.serverId)) return
        val wasEmpty = spaces.isEmpty()
        spaces.add(s); touched(); persistSpaces()
        // First channels to arrive after an empty load (re-login recovery) — open one so the skwod
        // lands on a conversation, not the blank overview.
        if (wasEmpty && selection == null && !homeMode) {
            model.launchIO { restoreLastChannel() }
        }
    }

    /**
     * Left, deleted, or no longer listed (build 47, [LeaveTombstones]): a leave in progress, or a
     * server gone for good on this phone. Every path that adds channels asks it first.
     */
    val tombstones = LeaveTombstones()

    /** The user confirmed Leave: the server goes NOW. Returns what to put back if it fails. */
    fun beginLeave(serverId: String): List<RealSpace>? {
        if (!tombstones.begin(serverId)) return null
        val before = spaces.toList()
        hideServer(serverId)
        return before
    }

    /** The host refused the leave: its channels come back where they were. */
    fun leaveFailed(serverId: String, before: List<RealSpace>) {
        if (!tombstones.failed(serverId)) return
        val restored = LeaveTombstones.restore(before, spaces.toList(), serverId, { it.serverId }, { it.channelId })
        spaces.clear(); spaces.addAll(restored)
        touched(); persistSpaces()
    }

    /** A server the user left or deleted: every channel of it goes from the list, for good. */
    fun removeServer(serverId: String) {
        tombstones.dropped(listOf(serverId))
        hideServer(serverId)
    }

    private fun hideServer(serverId: String) {
        spaces.removeAll { it.serverId == serverId }
        if ((selection as? SidebarItem.Space)?.space?.serverId == serverId) selection = null
        if (railServerId == serverId) railServerId = null
        touched(); persistSpaces()
    }

    fun removeSpace(s: RealSpace) {
        spaces.removeAll { it.channelId == s.channelId }
        if ((selection as? SidebarItem.Space)?.space?.channelId == s.channelId) selection = null
        touched(); persistSpaces()
    }

    /**
     * The user asked for a chat with [d]'s peer in "New chat" (they typed the name; the
     * directory resolved it to this account). If the conversation is ALREADY listed this only
     * selects it — opening something that exists never changes how far anyone is trusted.
     * A new one is listed and opened, and the contact is pinned as KNOWN only if their name
     * carries no flag (no look-alike of someone else, no unusual characters); otherwise it
     * starts UNVERIFIED and stays so until the user accepts the contact once the flag is gone.
     * (Selecting a conversation in the list never comes through here: it only sets `selection`.)
     *
     * [ticket] is what was current when the SERVER was asked whose conversation this is
     * ([openDm]): the entry is made in that workspace's store, and the contact noted in that
     * workspace's book, only while it is still the current one — in one step ([ifHolds]).
     */
    fun addDM(d: DMConversation, ticket: StoreTicket<SkwodClient>? = this.ticket()): OpenedDm {
        if (ticket == null) return OpenedDm.SWITCHED
        return ifHolds(ticket) {
            // Conversation ids are claimed first come, first served: one a group of this device
            // holds cannot also become a direct conversation — by the user's action either.
            // Refused and noted; neither store changes.
            val (entry, existed) = when (val opened = ticket.store.addDM(d)) {
                is ConversationStore.Opened.Refused -> return@ifHolds OpenedDm.REFUSED
                is ConversationStore.Opened.RefusedIgnored -> return@ifHolds OpenedDm.IGNORED_GROUP
                is ConversationStore.Opened.Existing -> opened.entry to true
                is ConversationStore.Opened.Added -> opened.entry to false
            }
            // The lookup the dialog just made returned exactly this account for this name.
            model.contacts.dmOpened(d.peerUserId, d.name, alreadyListed = existed, lookup = WaitingTrust.Lookup.Found(d.peerUserId))
            selection = SidebarItem.Dm(entry)
            OpenedDm.OPENED
        } ?: OpenedDm.SWITCHED
    }

    /** How "open a chat with …" ended, for whoever asked to show ([problem]: null = nothing to say). */
    enum class OpenedDm(val problem: String?) {
        OPENED(null),
        /** The user is in another workspace by now (or none is ready): nothing was done there. */
        SWITCHED(null),
        /** The server's answer conflicts with what this device holds; nothing changed. */
        REFUSED(GroupRules.CONFLICT_MESSAGE),
        /** The id is that of a group the user said to ignore. */
        IGNORED_GROUP(GroupRules.IGNORED_GROUP_MESSAGE),
        NOT_FOUND("No user / no device yet."),
    }

    /**
     * The user asked for a chat with [username]. Two server calls are made before anything is
     * stored — "who is this name" and "open the conversation" — and a server can hold either
     * answer until the user has switched to another workspace. So what is current is captured
     * FIRST ([StoreTicket]), both calls go through that workspace's own client, and the answer is
     * used only if the same workspace, client and store are still current: otherwise it is
     * dropped — no entry, no contact.
     */
    suspend fun openDm(username: String): OpenedDm {
        val ticket = ticket() ?: return OpenedDm.NOT_FOUND
        val client = ticket.bound.client
        val d = try {
            withContext(Dispatchers.IO) {
                val u = client.findUser(username)
                DMConversation(username, u.userId, u.deviceId, client.openDm(u.userId))
            }
        } catch (_: Exception) { return OpenedDm.NOT_FOUND }
        return addDM(d, ticket)
    }

    /** The user wrote in this conversation: whatever listed it first, it is theirs now. */
    fun claimDM(d: DMConversation) { store?.claimDM(d.conversationId, d.peerUserId) }

    /** What a server-driven change to the list means outside it: a claim noted, the open chat kept open. */
    fun delivered(result: ConversationStore.Delivery): Boolean = when (result) {
        is ConversationStore.Delivery.None, is ConversationStore.Delivery.Refused -> false
        is ConversationStore.Delivery.Added -> { model.contacts.claim(result.entry.peerUserId, result.claimedName); true }
        is ConversationStore.Delivery.Bound -> {
            if ((selection as? SidebarItem.Dm)?.dm?.key == result.old.key) selection = SidebarItem.Dm(result.entry)
            model.contacts.claim(result.entry.peerUserId, result.claimedName); true
        }
    }

    /**
     * A decrypted message from [sender] arrived in [conversationId] (or is in this device's
     * cache): make sure it has an entry ([DmBinding.route]). An existing entry is never re-keyed
     * to another peer — a sender who is not its peer gets an entry of their own. [claimed] is
     * the server's name for that account, kept only as a claim. Returns true if the list changed.
     */
    fun deliverDM(conversationId: String, sender: String, claimed: String?): Boolean =
        delivered(store?.deliverDM(conversationId, sender, claimed) ?: ConversationStore.Delivery.Refused)

    /** What is current right now, to hold on to across a server call ([StoreTicket]). */
    fun ticket(): StoreTicket<SkwodClient>? = StoreTicket.take(model.bound, store)
    /** Is what [ticket] captured still current? If not, what the call brought back is dropped. */
    fun holds(ticket: StoreTicket<SkwodClient>): Boolean = ticket.isCurrent(model.bound, storeRef)

    /**
     * Run [block] only if [ticket] still holds — and keep it holding while the block runs: the
     * store of another workspace cannot be put up meanwhile (that takes [storeLock]: [store],
     * [reset]). So "is this still the workspace that was asked?" and what is then shown, noted
     * or announced are ONE step; a switch on another thread waits for it or comes first.
     * Null when the ticket no longer holds (nothing ran). [block] must not suspend or wait.
     */
    fun <T> ifHolds(ticket: StoreTicket<SkwodClient>, block: () -> T): T? = synchronized(storeLock) { if (holds(ticket)) block() else null }

    /** [ifHolds] for code that has only the store it was working in. */
    fun <T> ifCurrent(origin: ConversationStore, block: () -> T): T? =
        synchronized(storeLock) { if (storeRef === origin && model.bound?.workspaceId == origin.tag) block() else null }

    /** Write what the conversation stores still have to write (before their client goes, or once it is back). */
    suspend fun flushStore() { storeRef?.flush() }

    fun showHome() { homeMode = true; selection = null }

    /**
     * Join a server with only an invite code. Token/username invites join at once; code invites
     * wait for the host's approval. Either way the join is tracked by [JoinFlow]: it survives a
     * relaunch, says what it is waiting for, and retries the key hand-off. Returns an error
     * string to show inline, or null once the join is under way.
     */
    suspend fun joinByCode(code: String): String? = model.joins.join(code)

    /** Who was asked for a server's keys, and whether any request actually went out. */
    class KeyRequest(val peerUserId: String?, val peerDeviceId: String?, val sent: Boolean)

    /**
     * Ask for [serverId]'s keys: a member (prefer the owner) AND my own other devices — whichever
     * is online provisions us (and only an own device's space key is accepted by the trust guard
     * anyway). Reports whether a request went through, so the caller can retry and say so.
     */
    suspend fun askForKeys(serverId: String, ownerId: String = ""): KeyRequest {
        val client = model.client ?: return KeyRequest(null, null, false)
        val me = model.current?.userId ?: return KeyRequest(null, null, false)
        var peerUser: String? = null; var peerDevice: String? = null; var sent = false
        val members = try { client.listMembers(serverId) } catch (_: Exception) { emptyList() }
        val provider = members.firstOrNull { it.userId == ownerId && it.userId != me } ?: members.firstOrNull { it.userId != me }
        if (provider != null) {
            val found = try { client.findUser(provider.username) } catch (_: Exception) { null }
            // The username lookup must resolve to the SAME account the member list named —
            // never ask (or later trust) a different account that happens to hold the name.
            if (found != null && found.userId == provider.userId) {
                peerUser = found.userId; peerDevice = found.deviceId
                try { client.requestProvision(serverId, found.userId, found.deviceId); sent = true } catch (_: Exception) {}
            }
        }
        val ownDevices = try { client.listOwnDevices() } catch (_: Exception) { emptyList() }
        for (device in ownDevices) {
            if (device == model.deviceId) continue
            if (peerUser == null) { peerUser = me; peerDevice = device }
            try { client.requestProvision(serverId, me, device); sent = true } catch (_: Exception) {}
        }
        return KeyRequest(peerUser, peerDevice, sent)
    }

    /** The servers the SERVER says this account is a member of, or null if it could not be asked. */
    suspend fun memberServerIds(): Set<String>? {
        // URL and token of ONE workspace, read together ([AppModel.endpoint]).
        val e = model.endpoint() ?: return null
        val servers = fetchServerList(e.base, e.token) ?: return null
        if (model.endpoint() != e) return null
        return servers.map { it.optString("server_id", "") }.filter { it.isNotEmpty() }.toSet()
    }

    /**
     * After a re-login/reinstall the sidebar cache + device keys are gone but memberships survive
     * server-side. Rediscover every server we belong to and ask a member (prefer the owner) to
     * re-provision this device — channels/keys reappear once their inbox sync answers.
     */
    suspend fun recoverMemberships() {
        val e = model.endpoint() ?: return
        val asked = model.bound ?: return
        val servers = fetchServerList(e.base, e.token) ?: return
        for (srv in servers) {
            // The list is the workspace's that was asked: stop once another one is in use.
            if (model.bound !== asked) return
            val sid = srv.optString("server_id", ""); if (sid.isEmpty()) continue
            if (spaces.any { it.serverId == sid } || tombstones.hides(sid)) continue
            val asked = askForKeys(sid, srv.optString("owner_id", ""))
            discover(sid, asked.peerUserId, asked.peerDeviceId, quiet = true)
        }
    }

    /** Discover channels the host added to servers we're already in (readable — we hold the space key). */
    suspend fun syncServerChannels() {
        val asked = model.bound ?: return
        val client = asked.client
        var added = false
        for (group in serverGroups()) {
            if (group.serverId.isEmpty() || group.serverId == "demo") continue
            val channels = try { client.listChannels(group.serverId) } catch (_: Exception) { continue }
            // A server can hold its answer across a workspace switch: what it lists then is not
            // written into the other skwod's sidebar (nor subscribed to on the other's server).
            if (model.bound !== asked) return
            // Left or deleted while that listing was in flight: it stays out.
            if (tombstones.hides(group.serverId)) continue
            for (ch in channels) {
                val name = ch.name ?: continue
                if (ch.kind == "voice") continue          // the call room has its own entry, not a chat
                if (spaces.any { it.channelId == ch.channelId }) continue
                spaces.add(RealSpace(group.name, name, group.serverId, ch.channelId)); added = true
            }
        }
        if (added) { touched(); persistSpaces() }
    }

    /** Poll the host DM for the provision bundle, then reveal channels once their names decrypt. */
    suspend fun discover(serverId: String, hostUserId: String?, hostDeviceId: String?, quiet: Boolean, rounds: Int = 40): Boolean {
        val asked = model.bound ?: return false
        val client = asked.client
        val me = model.current?.userId ?: return false
        discoverCount++; provisioning = true
        try {
        repeat(rounds) {
            if (hostUserId != null && hostDeviceId != null) {
                val convo = try { client.openDm(hostUserId) } catch (_: Exception) { null }
                if (convo != null) try { client.fetchDm(convo, hostUserId, hostDeviceId, me) } catch (_: Exception) {}
            }
            val channels = try { client.listChannels(serverId) } catch (_: Exception) { null }
            // Asked of one workspace: after a switch nothing of it is added to the other's sidebar.
            if (model.bound !== asked) return false
            // Text channels only: a voice channel is the call room, listed under "Voice channels".
            val named = channels?.filter { it.name != null && it.kind != "voice" } ?: emptyList()
            if (named.isNotEmpty()) {
                val spaceName = (try { client.serverName(serverId) } catch (_: Exception) { null }) ?: "Server"
                if (model.bound !== asked) return false
                // Left or deleted while this was being watched: it stays out.
                if (tombstones.hides(serverId)) return false
                for (ch in named) {
                    val space = RealSpace(spaceName, ch.name ?: "channel", serverId, ch.channelId)
                    if (quiet) addSpaceQuietly(space) else addSpace(space)
                }
                return true
            }
            delay(3000)
            if (model.bound !== asked) return false
        }
        return false
        } finally { discoverCount--; if (discoverCount == 0) provisioning = false }
    }

    // ---- server-side membership list (GET /api/servers) ----

    private suspend fun fetchServerList(base: String, token: String): List<JSONObject>? = withContext(Dispatchers.IO) {
        try {
            val url = java.net.URL("${base.trimEnd('/')}/api/servers")
            val conn = url.openConnection() as java.net.HttpURLConnection
            conn.setRequestProperty("Authorization", "Bearer $token")
            conn.connectTimeout = 10000; conn.readTimeout = 10000
            if (conn.responseCode != 200) return@withContext null
            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val arr = JSONObject(body).optJSONArray("servers") ?: return@withContext null
            (0 until arr.length()).map { arr.getJSONObject(it) }
        } catch (_: Exception) { null }
    }

    /** Build 49: put these decrypted server names on the joined spaces (a rename by the owner,
     *  on any device), and keep them. */
    fun applyServerNames(names: Map<String, String>) {
        var changed = false
        for (i in spaces.indices) {
            val name = names[spaces[i].serverId] ?: continue
            if (ServerName.problem(name) != null || spaces[i].name == name) continue
            spaces[i] = spaces[i].copy(name = name)
            changed = true
        }
        if (changed) persistSpaces()
    }

    // ---- persistence (JSON in the engine's encrypted kv, keyed by workspace) ----

    private fun kvKey(key: String): String = "${model.current?.id ?: ""}|$key"

    /** The joined spaces were READ from this workspace's cache. Until then they are not written. */
    @Volatile private var spacesRead = false

    private fun persistSpaces() {
        // A list that was never read is not the list: writing it would replace the stored one
        // (each entry carries the space's key and the invite it was joined with).
        if (!spacesRead) return
        val client = model.client ?: return
        val json = JSONArray().apply {
            spaces.forEach { s ->
                put(JSONObject().apply {
                    put("name", s.name); put("channelName", s.channelName); put("serverId", s.serverId)
                    put("channelId", s.channelId); put("inviteCode", s.inviteCode); put("spaceKeyHex", s.spaceKeyHex)
                })
            }
        }.toString()
        kvWrite(client, kvKey("sidebar.spaces"), json)
        // A server joined or left changes what a restore must bring back.
        model.account.touchKeyBackup()
    }

    /** Fire-and-forget write; kvSet is a suspend fn so we hop onto the model's IO scope. */
    private fun kvWrite(client: SkwodClient, key: String, value: String) {
        model.launchIO { try { client.kvSet(key, value) } catch (_: Exception) {} }
    }

    /**
     * Read the joined spaces STRICTLY (`kv_read`). A read that fails leaves them unread (and
     * unwritten: [persistSpaces]); a stored value that cannot be decoded is first kept under a
     * key of its own (read back), then the list continues with what can be salvaged, and it is
     * said in Security activity.
     */
    private suspend fun readSpaces() {
        val bound = model.bound ?: return
        val wid = model.current?.id?.takeIf { it == bound.workspaceId } ?: return
        val key = "$wid|sidebar.spaces"
        val json = try { bound.client.kvRead(key) } catch (_: Exception) { return }
        var keptAs: String? = null
        val stored: List<RealSpace> = SpaceCodec.decode(json) ?: run {
            val side = "$key.unreadable.${System.currentTimeMillis()}"
            try { bound.client.kvWrite(side, json!!); if (bound.client.kvRead(side) != json) return } catch (_: Exception) { return }
            keptAs = side
            SpaceCodec.salvage(json)
        }
        if (model.bound !== bound || loadedFor != wid || spacesRead) return
        // (Spaces joined while the list could not be read are kept; a server left since is not read back.)
        val joinedMeanwhile = spaces.filter { j -> stored.none { it.channelId == j.channelId } }
        spaces.clear(); spaces.addAll((joinedMeanwhile + stored).filter { !tombstones.hides(it.serverId) })
        spacesRead = true
        if (keptAs != null || joinedMeanwhile.isNotEmpty()) persistSpaces()
        keptAs?.let { model.account.log("spaces_unreadable", "Your list of servers could not be read",
            "The list of servers and channels Skwod keeps on this phone could not be fully read. Skwod kept what it could read; the rest comes back when the servers are synced. Nothing was deleted: the data as it was is kept on this phone (as “$it”).",
            System.currentTimeMillis()) }
    }
}
