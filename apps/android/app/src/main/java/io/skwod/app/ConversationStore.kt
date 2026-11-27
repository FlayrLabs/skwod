package io.skwod.app

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject

/** A direct conversation as the server lists it — claims from an untrusted party. */
data class ListedDm(val conversationId: String, val peerUserId: String, val peerUsername: String)

/** One row of a conversation's local (decrypted) history, as far as the stores care. */
data class HistoryAuthor(val authorId: String?, val isSystem: Boolean)

/**
 * What the conversation stores need from the core. [kvGet] THROWS when the cache could not be
 * read — null means only "nothing stored". Everything else is the server's word.
 */
interface ConversationBackend {
    suspend fun kvGet(key: String): String?
    suspend fun kvSet(key: String, value: String)
    suspend fun listDms(): List<ListedDm>
    suspend fun dmHistory(conversationId: String): List<HistoryAuthor>
    /**
     * conversation id → its members as listed. The core already leaves this account out
     * (`list_group_dms`); the store filters once more ([GroupRules.others]) so that nothing
     * depends on it — the stored set is the OTHERS on both platforms.
     */
    suspend fun listGroupDms(): List<Pair<String, List<String>>>
    suspend fun openGroupDm(members: List<String>): String
    /**
     * What this device fixed [conversationId] as the first time it was used (`dm_is_group`):
     * true = a group, false = 1:1, null = never used here. The core's own decision (the sealed
     * group marker, or the user's first send) — never the server's listing. Once non-null it
     * never changes.
     */
    suspend fun dmIsGroup(conversationId: String): Boolean? = null
}

/**
 * A core client together with the workspace whose cache it has open. Held as ONE value so that
 * "which client" and "whose" are never read at two different moments.
 */
class BoundClient<C>(
    val workspaceId: String, val client: C,
    /** Does this client have the workspace's encrypted cache OPEN? "No cache" is never "an empty cache". */
    val cacheOpen: Boolean = true,
    /** The bind turn that put this client up ([ClientBinding]). */
    val turn: Int = 0,
) {
    companion object {
        /**
         * The client to read or write [workspaceId]'s cache through: bound to exactly that
         * workspace AND with the cache open. Throws otherwise — the stores then stay unread
         * (gate shut) and unsaved changes stay pending.
         */
        fun <C> withCache(bound: BoundClient<C>?, workspaceId: String): C =
            bound?.takeIf { it.workspaceId == workspaceId && it.cacheOpen }?.client ?: throw IllegalStateException("cache not open")

        /**
         * The client to use for [workspaceId] — only the one bound to exactly that workspace.
         * Throws otherwise (no client, or another workspace's): a store then reads nothing and
         * writes nothing, it never uses whichever client happens to be there.
         */
        fun <C> of(bound: BoundClient<C>?, workspaceId: String): C =
            bound?.takeIf { it.workspaceId == workspaceId }?.client ?: throw IllegalStateException("not connected")
    }
}

/**
 * The one place a workspace's client is put up and taken down. Binding takes a while (the key,
 * opening the cache, the pin) and a second bind — or a teardown — can start meanwhile, on
 * another thread. Each bind therefore holds a TURN: [commit] puts a client up only for the turn
 * that is still the latest, and always under the workspace id the caller itself was given.
 */
class ClientBinding<C> {
    @Volatile var bound: BoundClient<C>? = null
        private set(value) { field = value; onChange?.invoke() }
    /** Build 51: told whenever a client is put up or taken down (open screens reload from it). */
    @Volatile var onChange: (() -> Unit)? = null
    private var turn = 0

    /** Start a bind: every earlier turn is over. (What was bound is taken down with [clear].) */
    @Synchronized fun begin(): Int { bound = null; return ++turn }
    /** Is [turn] still the latest? A bind that is not stops, closes its client and assigns nothing. */
    @Synchronized fun isCurrent(turn: Int): Boolean = turn == this.turn
    /** Put [client] up as [workspaceId]'s — unless this turn was superseded (false: nothing changed). */
    @Synchronized fun commit(turn: Int, workspaceId: String, client: C, cacheOpen: Boolean = true): Boolean {
        if (turn != this.turn) return false
        bound = BoundClient(workspaceId, client, cacheOpen, turn); return true
    }
    /** Take the client down and end any bind in flight. Returns what was up, for the caller to close. */
    @Synchronized fun clear(): C? { val was = bound?.client; bound = null; turn++; return was }
}

/**
 * What was current when a server call was made: the client (with its workspace and bind turn)
 * that was asked, and the store of that workspace. Whatever the call brings back — a batch of DM
 * events, a listing — belongs to THAT workspace only. A server that holds its answer while the
 * user switches workspaces must not get it decided in (or announced by) the other workspace:
 * the answer is used only while the same client and store are still current, and it is given to
 * the store that was captured, never to "the store" read again afterwards.
 */
class StoreTicket<C> private constructor(val bound: BoundClient<C>, val store: ConversationStore) {
    /** Still the same workspace, the same client and the same store? */
    fun isCurrent(bound: BoundClient<C>?, store: ConversationStore?): Boolean =
        bound != null && bound.workspaceId == this.bound.workspaceId && bound.turn == this.bound.turn && store === this.store

    companion object {
        /** null when there is nothing to decide in: no client bound, or the store is not that workspace's (mid-switch). */
        fun <C> take(bound: BoundClient<C>?, store: ConversationStore?): StoreTicket<C>? =
            if (bound != null && store != null && store.tag == bound.workspaceId) StoreTicket(bound, store) else null
    }
}

/** The stored form of the 1:1 list. */
object DmCodec {
    fun encode(dms: List<DMConversation>): String = JSONArray().apply {
        dms.forEach { d ->
            put(JSONObject().apply {
                put("name", d.name); put("peerUserId", d.peerUserId)
                put("peerDeviceId", d.peerDeviceId); put("conversationId", d.conversationId)
                put("bound", d.bound); put("origin", d.origin); put("claimed", d.claimed)
            })
        }
    }.toString()

    /** null = unreadable (never "none"); nothing stored = none. */
    fun decode(json: String?): List<DMConversation>? {
        if (json.isNullOrBlank()) return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                val device = o.optString("peerDeviceId", "")
                // Stored before entries recorded where they came from: only "New chat" ever
                // stored the peer's device id, so that is what tells a chat the user started
                // here from one that was merely listed.
                val origin = if (o.has("origin")) o.getString("origin")
                    else if (device.isNotEmpty() && !o.has("trust")) DMConversation.ORIGIN_LOCAL else DMConversation.ORIGIN_INBOUND
                // Stored before entries said whether they CLAIM their id: they all do.
                DMConversation(o.getString("name"), o.getString("peerUserId"), device, o.getString("conversationId"),
                    o.optBoolean("bound", true), origin, o.optBoolean("claimed", true))
            }
        } catch (_: Exception) { null }
    }

    /** What can still be read of a stored 1:1 list, element by element ([GroupRules.Salvaged]). */
    fun salvage(json: String): GroupRules.Salvaged<DMConversation> {
        val arr = try { JSONArray(json) } catch (_: Exception) { return GroupRules.Salvaged(emptyList(), emptyList(), false) }
        val items = ArrayList<DMConversation>(); val lost = ArrayList<String>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i)
            val one = o?.let { decode(JSONArray().put(it).toString())?.singleOrNull() }
            if (one != null) items += one else o?.optString("conversationId")?.takeIf { it.isNotEmpty() }?.let { lost += it }
        }
        return GroupRules.Salvaged(items, lost, true)
    }
}

/**
 * The 1:1 and group stores of ONE workspace, and the only code that changes them. The Android
 * peer of the Apple app's `ConversationStore.swift`.
 *
 * THE RULE ([GroupRules.mayClaim]). A conversation id belongs to whichever store this device
 * put it in first BY THE USER'S OWN ACTION: starting or writing in a direct conversation;
 * starting or accepting a group. Nothing server-driven (a listing, a delivery, an answer to
 * "open") creates an entry in the other store for a claimed id, or deletes, changes, hides or
 * re-routes a claimed entry. On a clash neither store changes, the owner keeps routing, the
 * conflicting data is dropped and it is said once (ever — the "said" set is stored).
 *
 * HOW IT IS KEPT.
 * - Nothing server-driven does anything until BOTH stores (and the ignored groups) have been
 *   read from the cache ([ready]). A store that could not be read keeps the gate shut and is
 *   read again next time — it is never treated as empty.
 * - Every change is made under ONE lock, in a step that re-checks the rule against both stores
 *   as they are at that moment. Nothing decided before a network call is written after it.
 * - Each store has one writer, which always writes the state as it is when it writes: two
 *   saves cannot land out of order, and a later change cannot be overwritten by an older one.
 *
 * ANDROID-ONLY STATE: `bound = false`. The Apple app lists a conversation the server names as
 * an unclaimed entry with the row's peer and never re-keys it. This app first reads the
 * conversation's local (decrypted) history: a sender found there makes a BOUND entry; only when
 * this device has nothing but its own messages is the row's peer taken, as an UNBOUND entry
 * (the server's word: shown as unverified, not a claim on the id). A decrypted message from
 * that same account later binds it. In both apps the entry's peer never changes to another
 * account: a different sender or listing is refused ([Notice.OtherPeer]) — the one exception
 * being an unbound entry that names NOBODY (empty peer, stored by old builds), which its first
 * decrypted sender binds.
 *
 * [launch] runs a block off the caller's thread (the app's IO scope). [listener] is called
 * under the lock, in order, with every new state.
 */
class ConversationStore(
    private val backend: ConversationBackend,
    private val workspaceId: String,
    private val me: String?,
    private val launch: (suspend () -> Unit) -> Unit,
    private val listener: Listener,
) {
    interface Listener {
        /** The lists changed. Called under the store's lock: publish, do not call back in. */
        fun changed(dms: List<DMConversation>, groups: List<GroupConversation>, invitations: List<GroupConversation>)
        /**
         * Something to put in Security activity — at most once per launch, and never again once
         * the receiver has reported its row stored ([ConversationStore.stored]).
         */
        fun notice(notice: Notice)
        /**
         * What the user has to be TOLD about the lists, and can act on: a whole list was lost
         * and server-listed conversations are held back ([Review.all], until [clearReview]);
         * the groups they ignored ([unignore]); how many times in a row the stores could not be
         * read. Called under the store's lock with every new state, like [changed].
         */
        fun state(reviewPending: Boolean, ignored: Set<String>, loadFailures: Int) {}
    }

    sealed class Notice {
        abstract val conversationId: String
        /** The server described a held conversation both as direct and as a group. */
        data class Conflict(override val conversationId: String) : Notice()
        /** Someone outside an accepted group's members sent something to it. */
        data class Outsider(override val conversationId: String) : Notice()
        /**
         * A direct conversation bound to one account was described (listed, delivered into, or
         * answered to "open") as being with a DIFFERENT account.
         */
        data class OtherPeer(override val conversationId: String) : Notice()
        /**
         * A stored list could not be decoded. Its bytes were kept under [keptAs] (nothing is
         * deleted) and the list starts again empty.
         */
        data class Unreadable(val list: String, val keptAs: String) : Notice() { override val conversationId: String get() = "" }
        /**
         * The 1:1 list held more than one entry under one conversation id (an earlier build
         * stored them). It was reduced to one per id; the list as it was is kept under [keptAs].
         */
        data class Duplicates(val keptAs: String) : Notice() { override val conversationId: String get() = "" }
        val key: String get() = when (this) {
            is Duplicates -> "duplicates-$keptAs"
            is Conflict -> "conflict-$conversationId"
            is Outsider -> "outsider-$conversationId"
            is OtherPeer -> "peer-$conversationId"
            is Unreadable -> "unreadable-$keptAs"
        }
    }

    /** What a delivery did to the 1:1 list. */
    sealed class Delivery {
        /** Nothing changed: the conversation is already listed with exactly this account. */
        data object None : Delivery()
        /**
         * Not listed and not to be shown or announced: the stores are not read; a group holds
         * the id; it is an invitation or an ignored group; or the conversation is held with
         * ANOTHER account.
         */
        data object Refused : Delivery()
        data class Added(val entry: DMConversation, val claimedName: String?) : Delivery()
        /** A listed-only entry now has its peer fixed by a decrypted sender. */
        data class Bound(val old: DMConversation, val entry: DMConversation, val claimedName: String?) : Delivery()
        /** May what arrived be shown and announced? Everything but [Refused]. */
        val accepted: Boolean get() = this !is Refused
    }

    sealed class Opened {
        data object Refused : Opened()
        /**
         * Refused because the id is that of a group the user said to IGNORE. Nothing changes; the
         * caller says so — the way out is to stop ignoring that group ([unignore]).
         */
        data object RefusedIgnored : Opened()
        data class Existing(val entry: DMConversation) : Opened()
        data class Added(val entry: DMConversation) : Opened()
    }

    /** The workspace this store was made for (set by its owner). */
    @Volatile var tag: String = ""
    private val lock = Any()
    private var dmList: List<DMConversation> = emptyList()
    private var groupList: List<GroupConversation> = emptyList()
    private var inviteList: List<GroupConversation> = emptyList()
    private var declinedIds: Set<String> = emptySet()
    private var noticed: List<String> = emptyList()
    @Volatile var ready = false
        private set

    val dms: List<DMConversation> get() = synchronized(lock) { dmList }
    val groups: List<GroupConversation> get() = synchronized(lock) { groupList }
    val invitations: List<GroupConversation> get() = synchronized(lock) { inviteList }
    val declined: Set<String> get() = synchronized(lock) { declinedIds }

    fun findGroup(conversationId: String): GroupConversation? = groups.firstOrNull { it.conversationId == conversationId }

    private fun key(name: String): String = "$workspaceId|$name"
    private fun groupIds(): Set<String> = groupList.mapTo(HashSet()) { it.conversationId }
    /** Ids a direct conversation CLAIMS (the user started it or wrote in it). */
    private fun claimedDirectIds(): Set<String> = dmList.filter { it.claimed }.mapTo(HashSet()) { it.conversationId }

    /**
     * What the core fixed conversations as on this device (`dm_is_group` / `DmEvent.isGroup`):
     * id → is a group. Only non-null answers are kept (they never change once fixed); in
     * memory only — the core is asked again after a restart.
     */
    private var fixedAs: Map<String, Boolean> = emptyMap()

    /** Remember what the core says [conversationId] is fixed as (a non-null answer). Under [lock]. */
    private fun learnFixed(conversationId: String, isGroup: Boolean?) {
        if (isGroup != null && fixedAs[conversationId] != isGroup) fixedAs = fixedAs + (conversationId to isGroup)
    }

    /** Ask the core (once per id while unknown). Not under [lock]. */
    private suspend fun askFixed(conversationId: String): Boolean? {
        synchronized(lock) { fixedAs[conversationId] }?.let { return it }
        val answer = try { backend.dmIsGroup(conversationId) } catch (_: Exception) { null }
        synchronized(lock) { learnFixed(conversationId, answer) }
        return answer
    }

    /**
     * A16: the core fixed [conversationId] as a GROUP, so unclaimed direct entries under it give
     * way ([GroupRules.directGivesWay]) — they could never show a message again. A claimed entry
     * stays (the clash is said once). Under [lock]; returns the notice to say, if any.
     */
    private fun yieldDirectToGroup(conversationId: String, fixed: Boolean? = fixedAs[conversationId]): Notice? {
        if (fixed != true) return null
        val before = dmList
        dmList = dmList.filter { it.conversationId != conversationId || !GroupRules.directGivesWay(it.claimed, fixed) }
        if (dmList != before) { save(Slot.DMS); publish() }
        return if (dmList.any { it.conversationId == conversationId }) Notice.Conflict(conversationId) else null
    }

    private fun publish() { listener.changed(dmList, groupList, inviteList); listener.state(reviewIds.all, declinedIds, loadFailures) }

    /** How many times in a row [load] could not make the stores usable (0 once it has). */
    @Volatile var loadFailures = 0
        private set
    /** Hand the lists to the listener again (a store taken up again after being set aside). */
    fun republish() = synchronized(lock) { if (ready) publish() }

    // ---- loading ----

    private val loadLock = Mutex()

    /** Milliseconds now — part of a kept copy's key, so one copy never overwrites another. */
    @Volatile var clock: () -> Long = System::currentTimeMillis

    /**
     * Read both stores, the ignored groups and the "said" set from the encrypted cache (no
     * network). False = not usable: the gate stays shut and the next call reads again.
     *
     * - A cache that cannot be READ is never "empty": nothing changes, read again next time.
     * - A stored list that is read but cannot be DECODED would keep the gate shut for good.
     *   Its bytes are first copied, as they are, under a key of their own
     *   (`<key>.unreadable.<ms>` — nothing is deleted) and read back; only then does the list
     *   start again empty, and it is said ([Notice.Unreadable]). If the copy cannot be written
     *   the gate stays shut.
     */
    suspend fun load(): Boolean {
        if (ready) return true
        val kept = ArrayList<Pair<Slot, String>>()
        var duplicatesKeptAs: String? = null
        val ok = loadLock.withLock {
            if (ready) return@withLock true
            val rawD: String?; val rawG: String?; val rawI: String?; val rawR: String?; val said: List<String>
            try {
                rawD = backend.kvGet(key(DMS_KEY)); rawG = backend.kvGet(key(GroupRules.STORE_KEY)); rawI = backend.kvGet(key(GroupRules.DECLINED_KEY))
                rawR = backend.kvGet(key(REVIEW_KEY))
                // A convenience only: unreadable means a notice may be said again.
                said = (try { GroupRules.decodeIdsOrNull(backend.kvGet(key(NOTICED_KEY)), ordered = true) } catch (_: Exception) { null })?.toList() ?: emptyList()
            } catch (_: Exception) { return@withLock false }
            /**
             * Copy a value under a key of its own; non-null only once it reads back. ONE copy
             * per distinct content: the key of the last copy is remembered
             * (`<key>.latest.<kind>`), and when that copy already holds exactly these bytes it
             * is the copy — a load that fails further on and is tried again (and again) does not
             * fill the cache with the same bytes under a new key each time.
             */
            suspend fun keep(name: String, kind: String, bytes: String): String? {
                val pointer = "${key(name)}.latest.$kind"
                return try {
                    val last = backend.kvGet(pointer)
                    if (!last.isNullOrEmpty() && backend.kvGet(last) == bytes) return last
                    val side = "${key(name)}.$kind.${clock()}"
                    backend.kvSet(side, bytes)
                    if (backend.kvGet(side) != bytes) return null
                    // (If this is not written the copy is still there; the next try makes another.)
                    try { backend.kvSet(pointer, side) } catch (_: Exception) {}
                    side
                } catch (_: Exception) { null }
            }
            var review = Review()
            if (!rawR.isNullOrBlank()) {
                val stored = Review.decode(rawR)
                if (stored != null) review = stored else {
                    // The record itself is unreadable: which ids it held is not known, so
                    // every listed group is one to review.
                    kept += Slot.REVIEW to (keep(REVIEW_KEY, "unreadable", rawR) ?: return@withLock false)
                    review = review.copy(allGroups = true, allDirect = true)
                }
            }
            var d = DmCodec.decode(rawD); var g = GroupRules.decodeOrNull(rawG); var ignored = GroupRules.decodeIdsOrNull(rawI)
            if (d == null) {
                kept += Slot.DMS to (keep(DMS_KEY, "unreadable", rawD!!) ?: return@withLock false)
                val saved = DmCodec.salvage(rawD)
                // Not a list at all: no id was recovered, every direct claim is forgotten.
                d = saved.items; review = review.copy(direct = review.direct + saved.lostIds, allDirect = review.allDirect || !saved.isArray)
            }
            if (g == null) {
                kept += Slot.GROUPS to (keep(GroupRules.STORE_KEY, "unreadable", rawG!!) ?: return@withLock false)
                val saved = GroupRules.salvage(rawG)
                g = saved.items; review = review.copy(group = review.group + saved.lostIds, allGroups = review.allGroups || !saved.isArray)
            }
            if (ignored == null) {
                kept += Slot.DECLINED to (keep(GroupRules.DECLINED_KEY, "unreadable", rawI!!) ?: return@withLock false)
                val saved = GroupRules.salvageIds(rawI)
                // Which groups the user said to ignore is not known any more: what is listed
                // is shown for review, not as a fresh invitation.
                ignored = saved.items.toSet(); review = review.copy(allGroups = review.allGroups || !saved.isArray)
            }
            // An id that survived in one of the lists is not lost.
            val alive = d.mapTo(HashSet()) { it.conversationId } + g.map { it.conversationId }
            review = review.copy(direct = review.direct - alive, group = review.group - alive)
            // The record is written (and read back) BEFORE any salvaged list replaces an original.
            if (kept.isNotEmpty()) {
                val json = review.encode()
                try { backend.kvSet(key(REVIEW_KEY), json); if (backend.kvGet(key(REVIEW_KEY)) != json) return@withLock false } catch (_: Exception) { return@withLock false }
            }
            // One id, one peer: the holder stays. The list as it was is kept first.
            val held = holders(d)
            if (held.size != d.size && kept.none { it.first == Slot.DMS }) duplicatesKeptAs = keep(DMS_KEY, "duplicates", rawD!!) ?: return@withLock false
            synchronized(lock) {
                dmList = held; groupList = g; inviteList = emptyList(); declinedIds = ignored; noticed = said; reviewIds = review
                ready = true
                if (held.size != d.size) save(Slot.DMS)
                // Written again (what was salvaged), so the next launch reads a list and not the
                // same undecodable bytes; the kept copy stays where it is.
                for ((slot, _) in kept) save(slot)
                publish()
            }
            true
        }
        for ((slot, side) in kept) notice(Notice.Unreadable(when (slot) {
            Slot.DMS -> "direct conversations"; Slot.GROUPS -> "groups"; Slot.REVIEW -> "conversations to review"; else -> "ignored groups" }, side))
        duplicatesKeptAs?.let { notice(Notice.Duplicates(it)) }
        // Counted, so the app can SAY that the conversations cannot be read (and offer to try
        // again) instead of showing an empty list for ever.
        synchronized(lock) {
            val failures = if (ok) 0 else loadFailures + 1
            if (failures != loadFailures) { loadFailures = failures; listener.state(reviewIds.all, declinedIds, loadFailures) }
        }
        return ok
    }

    /**
     * Conversation ids this device HELD but whose stored entries could not be read back (a list
     * was undecodable, in part or whole). Nothing is known about them any more except that they
     * were not new — so nothing server-driven may re-create them as if they were:
     * - [direct]: was a direct entry. No listing or delivery makes a direct entry for it, and no
     *   listing makes it a group invitation; the user opening that chat again clears it.
     * - [group]: was an accepted group. No direct entry is made for it; a listing shows it as
     *   "review this group" (never a plain invitation); joining or ignoring it clears it.
     * - [allGroups]: the groups (or ignored-groups) list could not be read AT ALL, so no ids were
     *   recovered: every listed group this device has not accepted is shown as "review".
     * - [allDirect]: the same for the DIRECT list — not one id of it was recovered, so every
     *   direct conversation this device held is forgotten, claims and all. While it is set
     *   nothing that arrives or is listed makes a direct entry (the user opening a chat still
     *   does), and every listed group is shown as "review": one of them may sit under the id of
     *   a direct conversation the user had.
     * [allGroups] and [allDirect] stand until the USER says they have seen it ([clearReview]).
     */
    data class Review(val direct: Set<String> = emptySet(), val group: Set<String> = emptySet(), val allGroups: Boolean = false,
                      val allDirect: Boolean = false) {
        /** Nothing listed can be told from something this device held. */
        val all: Boolean get() = allGroups || allDirect
        fun holds(conversationId: String) = conversationId in direct || conversationId in group
        fun encode(): String = JSONObject().put("direct", JSONArray(direct.sorted())).put("group", JSONArray(group.sorted()))
            .put("allGroups", allGroups).put("allDirect", allDirect).toString()
        companion object {
            fun decode(json: String): Review? = try {
                val o = JSONObject(json)
                fun ids(k: String) = o.optJSONArray(k)?.let { a -> (0 until a.length()).map { a.getString(it) }.toSet() } ?: emptySet()
                Review(ids("direct"), ids("group"), o.optBoolean("allGroups", false), o.optBoolean("allDirect", false))
            } catch (_: Exception) { null }
        }
    }
    private var reviewIds = Review()
    val review: Review get() = synchronized(lock) { reviewIds }

    /** Is something still to be written? (A write waits while this workspace's client is down.) */
    val hasUnsaved: Boolean get() = synchronized(lock) { dirty.isNotEmpty() || writing != null }

    // ---- saving: one writer per store, always the latest state ----

    private enum class Slot { DMS, GROUPS, DECLINED, NOTICED, REVIEW }
    private val dirty = HashSet<Slot>()
    /** The slot being written right now: no longer in [dirty], not yet known written. Under [lock]. */
    private var writing: Slot? = null
    private val writeLock = Mutex()

    /** Call under [lock]. */
    private fun save(slot: Slot) {
        dirty += slot
        launch { flush() }
    }

    /**
     * Everything still to be written, as (key, value) pairs — and it is no longer pending here.
     * For the one moment the store cannot write by itself any more: its client is about to be
     * taken down by something that cannot wait (sign-out), and the caller writes these through
     * that client before closing it.
     *
     * A slot that is being written at this very moment is included: its write may not land
     * before the client is gone, and it may carry less than the store holds now.
     */
    fun takeUnsaved(): List<Pair<String, String>> = synchronized(lock) {
        val slots = (dirty + listOfNotNull(writing)).toList(); dirty.clear()
        slots.map { encoded(it) }
    }

    /** Call under [lock]. */
    private fun encoded(slot: Slot): Pair<String, String> = when (slot) {
        Slot.DMS -> key(DMS_KEY) to DmCodec.encode(dmList)
        Slot.GROUPS -> key(GroupRules.STORE_KEY) to GroupRules.encode(groupList)
        Slot.DECLINED -> key(GroupRules.DECLINED_KEY) to GroupRules.encodeIds(declinedIds)
        Slot.NOTICED -> key(NOTICED_KEY) to JSONArray(noticed).toString()
        Slot.REVIEW -> key(REVIEW_KEY) to reviewIds.encode()
    }

    /** Write everything that was asked to be saved (and wait for writes already under way). */
    suspend fun flush() = writeLock.withLock {
        while (true) {
            // Encoded when it is written, not when it was asked for.
            val (slot, k, json) = synchronized(lock) {
                val slot = dirty.firstOrNull() ?: return@withLock
                dirty -= slot
                writing = slot
                val (k, json) = encoded(slot)
                Triple(slot, k, json)
            }
            // Could not be written (no client for this workspace right now): still to be saved.
            try { backend.kvSet(k, json) } catch (_: Exception) { synchronized(lock) { writing = null; dirty += slot }; return@withLock }
            synchronized(lock) { writing = null }
        }
    }

    // ---- notices ----

    /** Notices handed to the listener in this launch (not stored anywhere). */
    private val saidNow = HashSet<String>()

    /**
     * Say [notice] — once, ever. Nothing is said before the stores are read.
     *
     * "Ever" starts when the notice's row is STORED: it is remembered as said only once the
     * listener calls [stored]. If Security activity could not write it, it is not said twice in
     * this launch, and it is said again in the next.
     */
    fun notice(notice: Notice) {
        synchronized(lock) {
            if (!ready || notice.key in noticed || !saidNow.add(notice.key)) return
        }
        listener.notice(notice)
    }

    /** The row for [notice] is in Security activity: never say it again. */
    fun stored(notice: Notice) = synchronized(lock) {
        if (!ready || notice.key in noticed) return@synchronized
        noticed = (noticed + notice.key).takeLast(NOTICED_LIMIT)
        save(Slot.NOTICED)
    }

    // ---- routing ----

    /**
     * What a DM event's conversation is to this device ([GroupRules.route]). An entry that
     * exists keeps routing its own events. UNKNOWN while the stores are not read.
     */
    fun route(conversationId: String): GroupRules.Route {
        if (!ready) return GroupRules.Route.UNKNOWN
        val (route, clash) = synchronized(lock) {
            val accepted = groupIds(); val invited = inviteList.map { it.conversationId }
            GroupRules.route(conversationId, accepted, invited, declinedIds, dmList.map { it.conversationId }) to
                GroupRules.conflict(conversationId, accepted, invited, claimedDirectIds())
        }
        if (clash) notice(Notice.Conflict(conversationId))
        return route
    }

    // ---- server-driven: direct conversations ----

    /**
     * May something that ARRIVED make (or bind) a direct entry for this id? Never for an id a
     * group holds (said once), and never for a group the user has not accepted or said to
     * ignore. Call under [lock]; returns the notice to say after it, if any.
     */
    private fun mayListDirect(conversationId: String): Pair<Boolean, Notice?> {
        if (!ready) return false to null
        if (conversationId in groupIds()) return false to Notice.Conflict(conversationId)
        if (conversationId in declinedIds || inviteList.any { it.conversationId == conversationId }) return false to null
        // Held before, entry lost ([Review]): nothing that arrives re-creates it.
        if (reviewIds.holds(conversationId)) return false to null
        // This device fixed the conversation as a group (its sealed marker): never a direct chat.
        if (fixedAs[conversationId] == true) return false to null
        // The whole direct list was lost: nothing that arrives makes a NEW direct entry (it could
        // be for an id the user held as something else). Entries that exist go on.
        if (reviewIds.allDirect && dmList.none { it.conversationId == conversationId }) return false to null
        return true to null
    }

    /**
     * Is [conversationId] in the 1:1 store with someone OTHER than [peer]? A direct conversation
     * is bound to ONE account for good: nothing is then made, the entry is not touched, and it
     * is said once — exactly like a group clash. (A second entry under the id would let that
     * other account's text be shown, announced and answered as the first one's.) An entry the
     * server listed without naming anyone is nobody's yet. Call under [lock].
     */
    private fun heldByOther(conversationId: String, peer: String): Boolean =
        dmList.any { it.conversationId == conversationId && it.peerUserId != peer && !(it.peerUserId.isEmpty() && !it.bound) }

    /**
     * A decrypted message from [sender] arrived in [conversationId] (or is in this device's
     * cache): make sure it has an entry. ONE id, ONE peer: a sender who is not the peer of the
     * entry that holds the id gets NO entry — [Delivery.Refused], said once
     * ([Notice.OtherPeer]) — and the held entry is never re-keyed. [claimed] is the server's
     * name for that account, kept only as a claim. The entry is NOT a claim on the id (the user
     * did nothing). Refused as well for an id a group holds, an invitation or an ignored group —
     * also when an (unclaimed) entry already exists under it: nothing of those is shown.
     */
    fun deliverDM(conversationId: String, sender: String, claimed: String?): Delivery {
        if (sender.isEmpty()) return Delivery.Refused
        var say: Notice? = null
        val result: Delivery = synchronized(lock) {
            val (ok, n) = mayListDirect(conversationId); say = n
            if (!ok) return@synchronized Delivery.Refused
            if (heldByOther(conversationId, sender)) { say = Notice.OtherPeer(conversationId); return@synchronized Delivery.Refused }
            when (val route = DmBinding.route(dmList.map { DmBinding.Entry(it.conversationId, it.peerUserId, it.bound) }, conversationId, sender)) {
                is DmBinding.Route.Existing -> Delivery.None
                is DmBinding.Route.Bind -> {
                    val old = dmList[route.index]
                    val bound = old.copy(peerUserId = sender, bound = true, name = if (old.peerUserId == sender) old.name else (claimed ?: ""))
                    dmList = dmList.toMutableList().also { it[route.index] = bound }
                    save(Slot.DMS); publish()
                    Delivery.Bound(old, bound, claimed)
                }
                // (Never a second entry under a held id: [heldByOther] was checked above.)
                is DmBinding.Route.New -> {
                    val entry = DMConversation(claimed ?: "", sender, "", conversationId, bound = true, origin = DMConversation.ORIGIN_INBOUND, claimed = false)
                    dmList = listOf(entry) + dmList
                    save(Slot.DMS); publish()
                    Delivery.Added(entry, claimed)
                }
            }
        }
        say?.let(::notice)
        return result
    }

    /**
     * A conversation the server lists in which only we have spoken on this device: listed, but
     * bound to nothing trusted — [rowPeer] is the server's word. Never touches an existing
     * entry; a row naming someone else than the entry's peer is said once ([Notice.OtherPeer]).
     */
    fun listUnboundDM(conversationId: String, rowPeer: String, claimed: String?): Delivery {
        if (rowPeer.isEmpty()) return Delivery.Refused
        var say: Notice? = null
        val result: Delivery = synchronized(lock) {
            val (ok, n) = mayListDirect(conversationId); say = n
            if (!ok) return@synchronized Delivery.Refused
            if (heldByOther(conversationId, rowPeer)) { say = Notice.OtherPeer(conversationId); return@synchronized Delivery.Refused }
            if (dmList.any { it.conversationId == conversationId }) return@synchronized Delivery.None
            val entry = DMConversation(claimed ?: "", rowPeer, "", conversationId, bound = false, origin = DMConversation.ORIGIN_LISTED, claimed = false)
            dmList = listOf(entry) + dmList
            save(Slot.DMS); publish()
            Delivery.Added(entry, claimed)
        }
        say?.let(::notice)
        return result
    }

    /**
     * A batch of DM events that just landed, sorted by what THIS device holds — the one place
     * that decides what of it may be shown and announced. [E] is the event as the caller has it.
     */
    class Sorted<E>(
        /** In an accepted group, from this account or one of the group's stored members. */
        val grouped: List<E>,
        /** In a group this device has not accepted: "there is an invitation", nothing of the content. */
        val invited: List<E>,
        /** Direct, and ACCEPTED by the store: listed with exactly this sender. */
        val direct: List<E>,
        /** What changed in the 1:1 list on the way. */
        val deliveries: List<Delivery>,
    )

    /**
     * Sort [events] ([Sorted]). Null = the stores could not be read: nothing is decided.
     *
     * - A conversation this device does not know may be a group started elsewhere: the groups
     *   are asked ONCE for the batch before anything is filed; if they cannot be asked, those
     *   events are left out rather than filed as 1:1.
     * - In an accepted group only this account and the STORED members count; anyone else's
     *   event is dropped and said once ([Notice.Outsider]).
     * - An ignored group: nothing.
     * - Every direct event goes through [deliverDM]: what it refuses (a group, invitation or
     *   ignored group under the id — also when an unclaimed entry exists; a conversation held
     *   with another account) is in NO list here, so it is neither shown nor announced.
     * - [isGroup] is the event's sealed group marker (`DmEvent.isGroup`): a marked event is only
     *   ever grouped or an invitation, a bare one only ever direct ([GroupRules.markerFits]).
     *   A marked event for an id an UNCLAIMED direct entry holds makes that entry give way
     *   (A16) before the batch is routed; a claimed one stays and the event is dropped.
     */
    suspend fun <E> sort(events: List<E>, conversationId: (E) -> String, sender: (E) -> String, fromSelf: (E) -> Boolean,
                         isGroup: (E) -> Boolean,
                         names: () -> Map<String, String> = { emptyMap() }): Sorted<E>? {
        if (!load()) return null
        // A marked event is the core's word that the conversation is a group: unclaimed direct
        // entries under its id give way. (Not remembered: the core reports `false` also for a
        // conversation it has not fixed yet, so a bare event proves nothing beyond itself.)
        val said = synchronized(lock) {
            events.filter(isGroup).map(conversationId).distinct().mapNotNull { yieldDirectToGroup(it, fixed = true) }
        }
        said.forEach(::notice)
        val asked = if (events.any { route(conversationId(it)) == GroupRules.Route.UNKNOWN }) refreshGroups(names) else true
        // An event whose marker does not fit where its id routes is in no list at all.
        val routed = events.groupBy { route(conversationId(it)) }.mapValues { (r, list) -> list.filter { GroupRules.markerFits(r, isGroup(it)) } }
        val grouped = ArrayList<E>()
        for (e in routed[GroupRules.Route.GROUP].orEmpty()) {
            val group = findGroup(conversationId(e))
            if (group != null && GroupRules.accepts(sender(e), fromSelf(e), group.others)) grouped += e
            else if (group != null) notice(Notice.Outsider(group.conversationId))
        }
        val candidates = routed[GroupRules.Route.DIRECT].orEmpty() + (if (asked) routed[GroupRules.Route.UNKNOWN].orEmpty() else emptyList())
        // The server's row is a claim, and only about the account it names. Asked (through
        // this workspace's own client) only when some sender has no entry yet.
        var rows: Map<String, ListedDm>? = null
        val direct = ArrayList<E>(); val deliveries = ArrayList<Delivery>()
        val decided = HashMap<Pair<String, String>, Boolean>()
        for (e in candidates) {
            val id = conversationId(e); val from = sender(e)
            val ok = decided.getOrPut(id to from) {
                if (dms.none { it.conversationId == id && it.peerUserId == from && it.bound } && rows == null) {
                    rows = (try { backend.listDms() } catch (_: Exception) { emptyList() }).associateBy { it.conversationId }
                }
                val claimed = rows?.get(id)?.takeIf { it.peerUserId == from }?.peerUsername
                val delivery = deliverDM(id, from, claimed)
                if (delivery is Delivery.Added || delivery is Delivery.Bound) deliveries += delivery
                delivery.accepted
            }
            if (ok) direct += e
        }
        return Sorted(grouped, routed[GroupRules.Route.INVITATION].orEmpty(), direct, deliveries)
    }

    /**
     * The account's conversations as the server lists them — how a device learns of ones
     * started elsewhere. Routing metadata from an untrusted party: who a conversation is with
     * comes from the messages this device decrypted in it; where only we have spoken the entry
     * is listed UNBOUND; an id a group holds gets no entry at all. Returns what changed.
     */
    suspend fun refreshDmList(): List<Delivery> {
        if (!load()) return emptyList()
        val rows = try { backend.listDms() } catch (_: Exception) { return emptyList() }
        val out = ArrayList<Delivery>()
        // Oldest first, so the list (which inserts at the top) keeps the server's order.
        for (row in rows.asReversed()) {
            // An id one of this device's groups holds is not a DM, whatever the list says.
            if (findGroup(row.conversationId) != null) { notice(Notice.Conflict(row.conversationId)); continue }
            val history = try { backend.dmHistory(row.conversationId) } catch (_: Exception) { emptyList() }
            if (history.isEmpty()) continue
            // Fixed as a group on this device: the listing makes no direct entry (and an
            // unclaimed one under it gives way, A16).
            if (askFixed(row.conversationId) == true) {
                synchronized(lock) { yieldDirectToGroup(row.conversationId) }?.let(::notice)
                continue
            }
            // Rows the core wrote itself are told apart by what the row IS, never by its author or text.
            val senders = history.filter { !it.isSystem }.mapNotNull { it.authorId }.filter { it != me && it != "__me__" }.distinct()
            // Each of these re-checks both stores as they are NOW (the history read suspended).
            for (sender in senders) out += deliverDM(row.conversationId, sender, row.peerUsername.takeIf { row.peerUserId == sender })
            if (senders.isEmpty() && row.peerUserId != me) out += listUnboundDM(row.conversationId, row.peerUserId, row.peerUsername)
        }
        return out.filter { it is Delivery.Added || it is Delivery.Bound }
    }

    // ---- server-driven: groups ----

    private var listingStarted = 0
    private var listingApplied = 0

    /**
     * Ask which group conversations the server lists for this account, and fold that in:
     * accepted groups KEEP their members (a differing listing is only flagged), conversations
     * this device has not accepted become invitations. False when it could not be asked (or
     * the stores could not be read). [names]: claims this device has heard for people.
     */
    suspend fun refreshGroups(names: () -> Map<String, String> = { emptyMap() }): Boolean {
        if (!load()) return false
        val number = synchronized(lock) { ++listingStarted }
        val rows = try { backend.listGroupDms() } catch (_: Exception) { return false }
        val hints = names()
        // What this device fixed each listed, not-accepted id as (the core's answer, not the
        // listing's): an id fixed as 1:1 is never offered as a group.
        for (id in rows.map { it.first }.distinct()) if (findGroup(id) == null) askFixed(id)
        val conflicts = synchronized(lock) {
            // An older listing that comes back after a newer one says nothing new.
            if (number <= listingApplied) return true
            listingApplied = number
            // A16: unclaimed direct entries under an id fixed as a group give way first.
            val yielded = rows.map { it.first }.distinct().mapNotNull { yieldDirectToGroup(it) }
            val fixedDirect = fixedAs.filterValues { !it }.keys
            // Against the stores as they are NOW — a group accepted or started while the
            // request was in flight is an accepted group here, not something to write over.
            val result = GroupRules.reconcile(groupList, rows.map { it.first to GroupRules.others(it.second, me) }, declinedIds, claimedDirectIds() + fixedDirect,
                lostDirect = reviewIds.direct, reviewGroups = reviewIds.group, reviewAll = reviewIds.all)
            // Per group: only the flag, and names ADDED for members already in the set.
            val folded = result.accepted.associateBy { it.conversationId }
            val merged = groupList.map { g ->
                val f = folded[g.conversationId] ?: return@map g
                g.copy(serverDisagrees = f.serverDisagrees, claimedNames = g.others.mapNotNull { id -> (g.claimedNames[id] ?: hints[id])?.let { id to it } }.toMap())
            }
            val invited = result.invitations.map { g -> g.copy(claimedNames = g.others.mapNotNull { id -> hints[id]?.let { id to it } }.toMap()) }
            // (The server's listing is this account's OTHER members already — the core leaves
            // this account out of what it lists; [GroupRules.others] only makes that certain.)
            val groupsChanged = merged != groupList
            if (groupsChanged || invited != inviteList) {
                groupList = merged; inviteList = invited
                if (groupsChanged) save(Slot.GROUPS)
                publish()
            }
            (result.conflicts.map { Notice.Conflict(it) } + yielded).distinctBy { it.key }
        }
        conflicts.forEach(::notice)
        return true
    }

    /** Messages arrived in these groups: they move to the top of the list. */
    fun touchGroups(conversationIds: List<String>) = synchronized(lock) {
        val moved = conversationIds.distinct().mapNotNull { id -> groupList.firstOrNull { it.conversationId == id } }
        if (moved.isEmpty() || groupList.take(moved.size) == moved) return@synchronized
        groupList = moved + groupList.filter { it !in moved }
        save(Slot.GROUPS); publish()
    }

    // ---- the user's own actions (these are what CLAIM an id) ----

    /**
     * The user asked for a chat with [d]'s peer. Refused (and said once) when a group holds the
     * id — the server answered "open a DM" with a group's id — or when the id is held as the
     * conversation with ANOTHER account; neither store changes then.
     */
    fun addDM(d: DMConversation): Opened {
        var say: Notice? = null
        val result: Opened = synchronized(lock) {
            if (!ready) return@synchronized Opened.Refused
            // Also the id of a group this device was invited to, the user ignored, or held and
            // lost the entry of ([Review.group]): a direct conversation under it would be refused
            // every delivery afterwards — so it is refused here, up front, and said.
            if (d.conversationId in groupIds() || d.conversationId in declinedIds || d.conversationId in reviewIds.group
                || inviteList.any { it.conversationId == d.conversationId }) {
                say = Notice.Conflict(d.conversationId)
                return@synchronized if (d.conversationId in declinedIds && d.conversationId !in groupIds()) Opened.RefusedIgnored else Opened.Refused
            }
            // The server answered "open a chat with B" with the id of the conversation with A.
            if (heldByOther(d.conversationId, d.peerUserId)) { say = Notice.OtherPeer(d.conversationId); return@synchronized Opened.Refused }
            val i = dmList.indexOfFirst { it.conversationId == d.conversationId }
            if (i >= 0) {
                // (An entry the server listed without naming anyone becomes this peer's.)
                val mine = dmList[i].copy(claimed = true, peerUserId = d.peerUserId)
                if (mine != dmList[i]) { dmList = dmList.toMutableList().also { it[i] = mine }; save(Slot.DMS); publish() }
                return@synchronized Opened.Existing(dmList[i])
            }
            val entry = d.copy(claimed = true)
            dmList = listOf(entry) + dmList
            // The user opened this chat again: its id is held once more.
            if (d.conversationId in reviewIds.direct) { reviewIds = reviewIds.copy(direct = reviewIds.direct - d.conversationId); save(Slot.REVIEW) }
            save(Slot.DMS); publish()
            Opened.Added(entry)
        }
        say?.let(::notice)
        return result
    }

    /** The user wrote in a direct conversation that something else had listed: it is theirs now. */
    fun claimDM(conversationId: String, peerUserId: String) = synchronized(lock) {
        if (!ready || conversationId in groupIds()) return@synchronized
        val i = dmList.indexOfFirst { it.conversationId == conversationId && it.peerUserId == peerUserId }
        if (i < 0 || dmList[i].claimed) return@synchronized
        dmList = dmList.toMutableList().also { it[i] = it[i].copy(claimed = true) }
        save(Slot.DMS); publish()
    }

    /**
     * A group takes its id by the user's action: direct entries under it that nothing of the
     * user's made (unclaimed) give way, so the id is in one store only — unless this device
     * fixed the id as 1:1 ([GroupRules.directGivesWay]; callers refuse that case before). Call under [lock].
     */
    private fun take(group: GroupConversation) {
        val before = dmList
        val fixed = fixedAs[group.conversationId]
        dmList = dmList.filter { it.conversationId != group.conversationId || !GroupRules.directGivesWay(it.claimed, fixed) }
        inviteList = inviteList.filter { it.conversationId != group.conversationId }
        groupList = listOf(group.copy(needsReview = false)) + groupList.filter { it.conversationId != group.conversationId }
        // Looked at and taken by the user: nothing left to review about this id.
        if (group.conversationId in reviewIds.group) { reviewIds = reviewIds.copy(group = reviewIds.group - group.conversationId); save(Slot.REVIEW) }
        save(Slot.GROUPS)
        if (dmList != before) save(Slot.DMS)
        publish()
    }

    class ConflictException : IllegalStateException(GroupRules.CONFLICT_MESSAGE)

    /**
     * Start (or reopen) the group with exactly these people. The member set is the one the USER
     * just picked, and stays that. The server's answer is only an id: one a direct conversation
     * claims, or one a group with OTHER people holds, is refused and nothing changes.
     */
    suspend fun openGroup(others: List<String>, names: () -> Map<String, String> = { emptyMap() }): GroupConversation {
        if (!load()) throw IllegalStateException("Skwod is still loading your conversations — try again in a moment.")
        val members = GroupRules.others(others, me)
        val id = backend.openGroupDm(members)
        askFixed(id)
        val hints = names()
        val result: GroupConversation? = synchronized(lock) {
            val held = groupList.firstOrNull { it.conversationId == id }
            if (held != null) return@synchronized if (held.others.toSet() == members.toSet()) held else null
            if (!GroupRules.mayClaim(id, claimedDirectIds()) || id in reviewIds.direct || !GroupRules.mayBecomeGroup(fixedAs[id])) return@synchronized null
            GroupConversation(id, members, members.mapNotNull { m -> hints[m]?.let { m to it } }.toMap()).also(::take)
        }
        if (result == null) { notice(Notice.Conflict(id)); throw ConflictException() }
        return result
    }

    sealed class Joined {
        /** The group is accepted, with exactly the members the user was shown. */
        data class Done(val group: GroupConversation) : Joined()
        /**
         * The invitation is no longer the one the user was shown (a later listing named other
         * people). Nothing was accepted; [now] is the invitation as it is, to be looked at again.
         */
        data class Changed(val now: GroupConversation) : Joined()
        data object Refused : Joined()
    }

    /**
     * "Join group". [invitation] is what the USER WAS SHOWN: its members, exactly, become the
     * group's fixed set — so it is refused ([Joined.Changed]) when the invitation this device
     * holds now names other people than the ones on screen; a member set nobody looked at is
     * never fixed. Refused as well when a direct conversation claims the id: the invitation
     * stays, nothing changes, said once.
     */
    fun join(invitation: GroupConversation): Joined {
        var say: Notice? = null
        val result: Joined = synchronized(lock) {
            if (!ready) return@synchronized Joined.Refused
            val shown = inviteList.firstOrNull { it.conversationId == invitation.conversationId }
            if (shown == null || !GroupRules.canStart(shown.others.size)) {
                // Accepted meanwhile (another tap): that group, as it was accepted.
                val held = groupList.firstOrNull { it.conversationId == invitation.conversationId && it.others.toSet() == invitation.others.toSet() }
                return@synchronized held?.let { Joined.Done(it) } ?: Joined.Refused
            }
            if (shown.others.toSet() != invitation.others.toSet()) return@synchronized Joined.Changed(shown)
            if (!GroupRules.mayClaim(shown.conversationId, claimedDirectIds()) || !GroupRules.mayBecomeGroup(fixedAs[shown.conversationId])) { say = Notice.Conflict(shown.conversationId); return@synchronized Joined.Refused }
            groupList.firstOrNull { it.conversationId == shown.conversationId }?.let { return@synchronized Joined.Done(it) }
            Joined.Done(shown.copy(serverDisagrees = false, needsReview = false).also(::take))
        }
        say?.let(::notice)
        return result
    }

    /** [join], for callers that only want the accepted group. */
    fun accept(invitation: GroupConversation): GroupConversation? = (join(invitation) as? Joined.Done)?.group

    /** "Ignore this group": remembered; the conversation is not listed again on this device. */
    fun decline(invitation: GroupConversation) = synchronized(lock) {
        if (!ready) return@synchronized
        inviteList = inviteList.filter { it.conversationId != invitation.conversationId }
        if (invitation.conversationId in reviewIds.group) { reviewIds = reviewIds.copy(group = reviewIds.group - invitation.conversationId); save(Slot.REVIEW) }
        if (invitation.conversationId !in declinedIds) { declinedIds = declinedIds + invitation.conversationId; save(Slot.DECLINED) }
        publish()
    }

    /**
     * "Stop ignoring": the id is no longer barred. Nothing else changes here — if the server
     * still lists the group it comes back as an invitation with the next listing, to be looked
     * at and joined or ignored again. False when it was not ignored.
     */
    fun unignore(conversationId: String): Boolean = synchronized(lock) {
        if (!ready || conversationId !in declinedIds) return@synchronized false
        declinedIds = declinedIds - conversationId
        save(Slot.DECLINED); publish()
        true
    }

    /**
     * The user has seen that a whole list was lost ([Review.all]) and wants things to go on:
     * listings and deliveries make direct entries again, and a listed group is an invitation
     * again — except the ones known by id to have been held ([Review.group]), which stay "review".
     */
    fun clearReview() = synchronized(lock) {
        if (!ready || !reviewIds.all) return@synchronized
        reviewIds = reviewIds.copy(allGroups = false, allDirect = false)
        inviteList = inviteList.map { it.copy(needsReview = it.conversationId in reviewIds.group) }
        save(Slot.REVIEW); publish()
    }

    companion object {
        /**
         * One entry per conversation id: a direct conversation is bound to ONE peer account. Among
         * several entries under one id (earlier builds stored a second sender as a "split" entry)
         * the holder is the one the USER made — started here before anything else, then one that
         * claims the id before one that does not — and otherwise the oldest (entries are inserted
         * at the top, so the LAST). Order is kept.
         */
        fun holders(dms: List<DMConversation>): List<DMConversation> {
            fun rank(d: DMConversation) = (if (d.origin == DMConversation.ORIGIN_LOCAL) 2 else 0) + (if (d.claimed) 1 else 0)
            val holder = HashMap<String, Int>()
            dms.forEachIndexed { i, d -> val h = holder[d.conversationId]; if (h == null || rank(dms[h]) <= rank(d)) holder[d.conversationId] = i }
            return dms.filterIndexed { i, d -> holder[d.conversationId] == i }
        }

        const val DMS_KEY = "sidebar.dms"
        const val NOTICED_KEY = "security.noticed"
        const val REVIEW_KEY = "conversations.review"
        const val NOTICED_LIMIT = 1000
    }
}
