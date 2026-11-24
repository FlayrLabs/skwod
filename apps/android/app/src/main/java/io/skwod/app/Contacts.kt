package io.skwod.app

import androidx.compose.runtime.mutableStateOf
import org.json.JSONArray
import org.json.JSONObject

/**
 * How far a person's NAME can be relied on. One model, used wherever a name is shown (the DM
 * list, chat headers and rows, the member list, "Waiting to join", notifications, the feed).
 *
 * The server is not a source of trust: every name it supplies — the member list, `findUser`,
 * `listDms`, alone or agreeing with each other — is a claim. Only the person holding this device
 * can raise a name above that.
 */
enum class TrustLevel {
    /** Only server-claimed. Shown with an "unverified" marker. */
    UNVERIFIED,
    /** Pinned by an explicit action on this device: started the DM, tapped "Let in", accepted the contact. */
    KNOWN,
    /** The user compared the safety number. Shown with a badge. */
    VERIFIED,
}

/** One entry of the local contact book. */
data class Contact(val userId: String, val name: String, val level: TrustLevel, val known: Boolean? = null) {
    /** Build 49: made KNOWN by the user's own action — what un-verifying falls back to. Absent
     *  (older entries): known exactly when the stored level was at least KNOWN. */
    val explicitlyKnown: Boolean get() = known ?: (level >= TrustLevel.KNOWN)
}

/** The pure rules of the contact book and of conversation binding. Unit-tested on the JVM. */
object ContactTrust {
    const val UNKNOWN = "Unknown contact"

    /** Why a name is shown with a warning instead of as a name. Strongest first. */
    enum class Flag(val strong: Boolean, val mark: String) {
        NONE(false, ""),
        /** Reads like the name of someone the user knows — a contact, or an accepted member — under a DIFFERENT account. */
        IMPERSONATION(true, "possible impersonation"),
        /** Contains non-ASCII or invisible characters, which honest usernames here never have. */
        UNUSUAL(true, "unusual characters"),
        /** The directory says this name belongs to another account, or to nobody. */
        MISMATCH(true, "doesn't match this account"),
        /** The directory could not be asked (yet). */
        UNCHECKED(false, "couldn't check"),
    }

    /** A name as it is put on screen. */
    data class Shown(val name: String, val level: TrustLevel, val flag: Flag) {
        val impersonation: Boolean get() = flag == Flag.IMPERSONATION
        /** Shown in red: do not act on this name. */
        val strong: Boolean get() = flag.strong
        val verified: Boolean get() = level == TrustLevel.VERIFIED
        /** Show the "unverified" marker. */
        val unverified: Boolean get() = level == TrustLevel.UNVERIFIED
        /** Shown as an ordinary name: relied on by the user, and nothing wrong with it. */
        val trusted: Boolean get() = !unverified && flag == Flag.NONE
        /** Build 49: the name for [surface] — plain where a mark is drawn beside it
         *  ([NameTrustMark], or a "?" after a mention chip), the words everywhere else. */
        fun labelFor(surface: NameSurface): String = if (surface.form == NameForm.BADGE) name else label
        /** A mark must be drawn beside the plain name. */
        val needsMark: Boolean get() = unverified || flag != Flag.NONE || verified
        /** One-line text form, for places that cannot style (notifications, dialog titles). */
        val label: String get() = when {
            flag != Flag.NONE -> "$name (${flag.mark})"
            unverified -> "$name (unverified)"
            else -> name
        }
        /** The sentence to show with it, if any: (text, strong). */
        val warning: Pair<String, Boolean>? get() = when (flag) {
            Flag.IMPERSONATION -> "Possible impersonation. This account's name looks like the name of someone you already know — a contact, or a member of a server you share — but it is a DIFFERENT account. Do not trust it on the strength of the name; compare safety numbers." to true
            Flag.UNUSUAL -> "This name contains unusual or invisible characters, which real usernames here never have. It may be made to look like someone else's name. Treat this account as a stranger." to true
            Flag.MISMATCH -> "This name doesn't match this account: looking the name up does not lead to it. Don't rely on the name." to true
            Flag.UNCHECKED -> "Couldn't check this name against the account yet. Until it has been checked, treat it as unconfirmed." to false
            Flag.NONE -> if (unverified) "Unverified: this name is only what the server says. Compare safety numbers, or accept the contact if you know who this is." to false else null
        }
    }

    /**
     * Everyone whose name must not be worn by another account: the contacts the user pinned or
     * verified, PLUS the accepted members of every server the user shares (listed by the server,
     * not held by the core, not a pending join request) — whether or not the user ever messaged
     * them. Being in this set gives a member nothing (their own name stays UNVERIFIED until the
     * user acts); it only means nobody ELSE may look like them unflagged. Indexed by confusable
     * skeleton ([NameSkeleton]) so a lookup per name on screen is cheap.
     */
    class CollisionSet private constructor(private val bySkeleton: Map<String, Set<String>>) {
        fun collides(userId: String, name: String): Boolean {
            val skeleton = NameSkeleton.skeleton(name)
            if (skeleton.isEmpty()) return false
            return bySkeleton[skeleton]?.any { it != userId } == true
        }

        companion object {
            val EMPTY = CollisionSet(emptyMap())
            /** [roster]: accepted members, account id → name. */
            fun of(book: Map<String, Contact>, roster: Map<String, String> = emptyMap()): CollisionSet {
                val index = HashMap<String, MutableSet<String>>()
                fun add(id: String, name: String) {
                    val skeleton = NameSkeleton.skeleton(name)
                    if (id.isNotEmpty() && skeleton.isNotEmpty()) index.getOrPut(skeleton) { HashSet() }.add(id)
                }
                for (c in book.values) if (c.level != TrustLevel.UNVERIFIED) add(c.userId, c.name)
                for ((id, name) in roster) add(id, name)
                return CollisionSet(index)
            }
        }
    }

    /** Does [name] read like someone in the collision set who is a DIFFERENT account? */
    fun collides(userId: String, name: String, book: Map<String, Contact>, roster: Map<String, String> = emptyMap()): Boolean =
        CollisionSet.of(book, roster).collides(userId, name)

    /**
     * What to show for the account [userId]. [claimed] is whatever name the server supplied at
     * this spot (a member list, `listDms`, `findUser`) — used only when the book has nothing
     * better, and never raising the level. [lookup] is what the directory said when asked whom
     * that claimed name belongs to (`findUser`; null = not asked yet): a server-claimed name is
     * shown without a flag only when it leads back to exactly this account — and is then still
     * only "unverified".
     */
    fun display(userId: String, claimed: String?, book: Map<String, Contact>, others: CollisionSet = CollisionSet.of(book), lookup: WaitingTrust.Lookup? = null): Shown {
        val contact = book[userId]
        val level = contact?.level ?: TrustLevel.UNVERIFIED
        val pinned = level != TrustLevel.UNVERIFIED
        val raw = (if (pinned) contact?.name else null) ?: claimed?.takeIf { it.isNotBlank() } ?: contact?.name ?: ""
        val name = NameSkeleton.visible(raw).ifEmpty { UNKNOWN }
        val flag = when {
            name == UNKNOWN -> Flag.NONE
            // A verified contact was checked against its keys, not its name.
            level == TrustLevel.VERIFIED -> Flag.NONE
            others.collides(userId, raw) -> Flag.IMPERSONATION
            NameSkeleton.isUnusual(raw) -> Flag.UNUSUAL
            // A name the user pinned themself needs no directory.
            pinned -> Flag.NONE
            else -> when (lookup) {
                is WaitingTrust.Lookup.Found -> if (lookup.userId == userId) Flag.NONE else Flag.MISMATCH
                is WaitingTrust.Lookup.Nobody -> Flag.MISMATCH
                is WaitingTrust.Lookup.Failed, null -> Flag.UNCHECKED
            }
        }
        return Shown(name, level, flag)
    }

    /**
     * Record [name] for [userId] at [level]. The rules that keep the server out of it:
     * - a server claim (UNVERIFIED) never changes an entry the user pinned or verified;
     * - a level is never lowered by recording (see [unverify] for the one explicit demotion);
     * - a name that collides with another known contact cannot be PINNED as KNOWN — whatever
     *   led to the action (a directory lookup answering with a different account), the result
     *   would be two "merhan"s; it stays UNVERIFIED and is shown with the impersonation warning;
     * - verifying keeps the name the user already had for the account.
     */
    fun record(book: Map<String, Contact>, userId: String, name: String, level: TrustLevel, others: CollisionSet = CollisionSet.of(book)): Map<String, Contact> {
        if (userId.isEmpty()) return book
        val clean = NameSkeleton.visible(name)
        val old = book[userId]
        val next = when (level) {
            TrustLevel.UNVERIFIED -> when {
                old != null && old.level != TrustLevel.UNVERIFIED -> return book
                clean.isEmpty() -> return book
                else -> Contact(userId, clean, TrustLevel.UNVERIFIED)
            }
            TrustLevel.KNOWN -> when {
                old != null && old.level != TrustLevel.UNVERIFIED -> return book        // already pinned: keep its name
                clean.isEmpty() -> return book
                // …nor a look-alike of an accepted member, nor a name with unusual characters.
                others.collides(userId, name) || NameSkeleton.isUnusual(name) -> Contact(userId, clean, TrustLevel.UNVERIFIED)
                else -> Contact(userId, clean, TrustLevel.KNOWN)
            }
            TrustLevel.VERIFIED -> {
                // Verification is about keys, not names: it stands even with no name on record.
                // The name pinned is the one shown and checked — the old one only if the user had
                // already pinned it (KNOWN or above), matching Apple's `withVerification`.
                val keep = old?.takeIf { it.level >= TrustLevel.KNOWN }?.name?.takeIf { it.isNotEmpty() }
                Contact(userId, keep ?: clean, TrustLevel.VERIFIED, old?.explicitlyKnown ?: false)
            }
        }
        return if (next == old) book else book + (userId to next)
    }

    /**
     * An explicit action by the user that would pin [userId] as KNOWN under [name] (starting a
     * new chat with them, "Let in", "I know them — accept"). It only pins a name that would be
     * shown with NO flag: while it reads like someone else, has unusual characters, does not
     * match the account in the directory, or could not be checked, the contact stays UNVERIFIED
     * (the name is kept as a claim) and the warning stays on screen.
     */
    fun promote(book: Map<String, Contact>, userId: String, name: String, others: CollisionSet = CollisionSet.of(book), lookup: WaitingTrust.Lookup? = null): Map<String, Contact> =
        if (display(userId, name, book, others, lookup).flag != Flag.NONE) record(book, userId, name, TrustLevel.UNVERIFIED, others)
        else record(book, userId, name, TrustLevel.KNOWN, others)

    /**
     * A conversation was opened. Selecting one that is ALREADY listed is navigation, not a
     * statement about who it is with: it changes nothing. Only starting a NEW chat is the
     * explicit action — and even that pins only a clean name ([promote]).
     */
    fun onDmOpened(book: Map<String, Contact>, userId: String, name: String, alreadyListed: Boolean,
                   others: CollisionSet = CollisionSet.of(book), lookup: WaitingTrust.Lookup? = null): Map<String, Contact> =
        if (alreadyListed) book else promote(book, userId, name, others, lookup)

    /** The safety number is no longer verified (the user cleared it, or the keys changed): back
     *  to KNOWN only for someone the user made known themself, else UNVERIFIED. */
    fun unverify(book: Map<String, Contact>, userId: String): Map<String, Contact> {
        val old = book[userId] ?: return book
        return if (old.level == TrustLevel.VERIFIED)
            book + (userId to old.copy(level = if (old.explicitlyKnown) TrustLevel.KNOWN else TrustLevel.UNVERIFIED)) else book
    }

    /** Build 49: a READ of the core's state may only demote — never create or raise a name. */
    fun afterStatusRead(book: Map<String, Contact>, userId: String, verified: Boolean): Map<String, Contact> =
        if (!verified && book[userId]?.level == TrustLevel.VERIFIED) unverify(book, userId) else book

    /** Build 49: a mention of me reads "you" — never a name the server could have supplied
     *  (matching Apple). */
    const val SELF_MENTION = "you"

    /** May an explicit verification pin this name? Not a flagged one. */
    fun mayPinOnVerify(shown: Shown): Boolean = shown.flag == Flag.NONE

    // ---- persistence ----

    fun encode(book: Map<String, Contact>): String = JSONArray().apply {
        for (c in book.values) put(JSONObject().put("userId", c.userId).put("name", c.name).put("level", c.level.name).apply { c.known?.let { put("known", it) } })
    }.toString()

    /**
     * STRICT: null unless the whole value is a list in which every element is an entry (an
     * object with a user id). The book is then kept aside and salvaged ([decode]) rather than
     * silently shortened and written back.
     */
    fun decodeStrict(json: String?): Map<String, Contact>? {
        if (json.isNullOrBlank()) return emptyMap()
        val arr = try { JSONArray(json) } catch (_: Exception) { return null }
        for (i in 0 until arr.length()) if (arr.optJSONObject(i)?.optString("userId").isNullOrEmpty()) return null
        return decode(json)
    }

    /** Tolerant (what can be salvaged). An entry without a (known) level is UNVERIFIED: trust is never assumed. */
    fun decode(json: String?): Map<String, Contact> {
        if (json.isNullOrBlank()) return emptyMap()
        val arr = try { JSONArray(json) } catch (_: Exception) { return emptyMap() }
        val out = LinkedHashMap<String, Contact>()
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val id = o.optString("userId"); if (id.isEmpty()) continue
            val level = try { TrustLevel.valueOf(o.optString("level")) } catch (_: Exception) { TrustLevel.UNVERIFIED }
            out[id] = Contact(id, o.optString("name"), level, if (o.has("known")) o.optBoolean("known") else null)
        }
        return out
    }

    /** A conversation stored before the contact book existed. */
    data class Legacy(val peerUserId: String, val name: String, val startedHere: Boolean)

    /**
     * First run with a contact book: conversations this device started itself (the user typed
     * the name and opened the chat) become KNOWN; every other stored conversation, whatever it
     * was called, becomes UNVERIFIED.
     */
    fun migrate(conversations: List<Legacy>): Map<String, Contact> {
        var book: Map<String, Contact> = emptyMap()
        for (c in conversations.filter { it.startedHere }) book = record(book, c.peerUserId, c.name, TrustLevel.KNOWN)
        for (c in conversations.filter { !it.startedHere }) book = record(book, c.peerUserId, c.name, TrustLevel.UNVERIFIED)
        return book
    }
}

/**
 * Which sidebar entry a decrypted direct message belongs to.
 *
 * An entry is bound to ONE peer account for ever, and that binding is decided on this device
 * from who actually sent (the decrypted, authenticated sender) — never from the server's list of
 * participants, and never revised. A sender who is not the entry's peer does not take the entry
 * over: they get an entry of their own.
 */
object DmBinding {
    /** A listed entry: its server conversation id, its peer, and whether a decrypted sender (or the user starting it) fixed that peer. */
    data class Entry(val conversationId: String, val peerUserId: String, val bound: Boolean)

    sealed class Route {
        /** The entry at [index] is this conversation with this sender. */
        data class Existing(val index: Int) : Route()
        /** The entry at [index] was only known from the server's list; this sender is who it names (or it named nobody): bind it now. */
        data class Bind(val index: Int) : Route()
        /** Nobody's entry: list a new one for this sender. [split] = the conversation id is already another peer's. */
        data class New(val split: Boolean) : Route()
    }

    fun route(entries: List<Entry>, conversationId: String, sender: String): Route {
        val same = entries.withIndex().filter { it.value.conversationId == conversationId }
        same.firstOrNull { it.value.peerUserId == sender }?.let { return if (it.value.bound) Route.Existing(it.index) else Route.Bind(it.index) }
        // An entry the server listed without naming anyone may be bound by its first sender.
        same.firstOrNull { !it.value.bound && it.value.peerUserId.isEmpty() }?.let { return Route.Bind(it.index) }
        // Everything else — a bound entry with another peer, or a server row that named someone
        // else — is left exactly as it is.
        // "Split" = the conversation id already belongs (bound) to another peer.
        return Route.New(split = same.any { it.value.bound })
    }
}

/**
 * The contact book of the active workspace: `userId → name + level`, kept on this device
 * (encrypted, next to the session tokens) and SEPARATE from the conversation list. Compose state,
 * so every name on screen follows a change.
 */
class ContactBook(private val model: AppModel) {
    private val state = mutableStateOf<Map<String, Contact>>(emptyMap())
    /** Accepted members of the servers we share (id → name): part of the collision set, nothing more. */
    private val rosterState = mutableStateOf<Map<String, String>>(emptyMap())
    private val collisions = mutableStateOf(ContactTrust.CollisionSet.EMPTY)
    /** What the directory said for "userId|name" (in memory only: asked again each launch). */
    private val lookups = mutableStateOf<Map<String, WaitingTrust.Lookup>>(emptyMap())
    private val asked = java.util.concurrent.ConcurrentHashMap<String, Long>()
    private val queue = kotlinx.coroutines.channels.Channel<Pair<String, String>>(kotlinx.coroutines.channels.Channel.UNLIMITED)
    @Volatile private var worker: kotlinx.coroutines.Job? = null
    private var loadedFor: String? = null

    val all: Map<String, Contact> get() = state.value

    private fun key(workspaceId: String) = LocalData.contactsName(workspaceId)
    private fun rosterKey(workspaceId: String) = LocalData.rosterName(workspaceId)
    private fun reindex() { collisions.value = ContactTrust.CollisionSet.of(state.value, rosterState.value) }

    /** Was the active workspace's book read? (Until it is, nothing is written to it.) */
    val loaded: Boolean get() = loadedFor != null && loadedFor == model.current?.id

    /**
     * Load the active workspace's book. Returns true when there was none stored yet (first run:
     * migrate).
     *
     * STRICT: the book holds who the user verified and who they know. A read that FAILS is not
     * an empty book — nothing is marked loaded, nothing is written ([update] does nothing), and
     * the next call reads again. A book that is read but cannot be decoded is first copied,
     * as it is, under a key of its own (committed to disk); only then does it continue with the
     * entries that can be salvaged — anyone unreadable is UNVERIFIED again, never trusted — and
     * it is said in Security activity.
     */
    @Synchronized
    fun load(): Boolean {
        lookups.value = emptyMap(); asked.clear()
        fun unloaded(): Boolean { state.value = emptyMap(); rosterState.value = emptyMap(); reindex(); loadedFor = null; return false }
        val wid = model.current?.id ?: return unloaded()
        val stored: String?; val storedRoster: String?
        try { stored = model.secretRead(key(wid)); storedRoster = model.secretRead(rosterKey(wid)) } catch (_: Exception) { return unloaded() }
        var book = ContactTrust.decodeStrict(stored)
        if (book == null) {
            val side = "${key(wid)}.unreadable.${System.currentTimeMillis()}"
            if (!model.secretWrite(side, stored!!)) return unloaded()
            book = ContactTrust.decode(stored)
            if (!model.secretWrite(key(wid), ContactTrust.encode(book))) return unloaded()
            model.launchIO { model.account.log("contacts_unreadable", "Your contact list could not be read",
                "The list of people you know and have verified, which Skwod keeps on this phone, could not be fully read. Skwod kept what it could read; anyone it could not read is shown as unverified again until you confirm them. Nothing was deleted: the data as it was is kept on this phone (as “$side”).",
                System.currentTimeMillis(), wid) }
        }
        state.value = book
        // The roster as last seen, so the collision set is complete before the host answers.
        // (Only names for the collision check, re-read from the servers: salvaged as it is.)
        rosterState.value = ContactTrust.decode(storedRoster).mapValues { it.value.name }
        reindex()
        loadedFor = wid
        return stored == null
    }

    /** Build 49: the contact book one of our own devices handed over, for [workspaceId]
     *  ([SiblingRules.mergedBook]). False when another skwod's book is loaded. */
    fun mergeFromSibling(synced: Map<String, Contact>, workspaceId: String, vouched: Set<String>, mismatched: Set<String>): Boolean {
        if (workspaceId.isEmpty() || loadedFor != workspaceId || model.current?.id != workspaceId) return false
        update { book -> SiblingRules.mergedBook(book, synced, vouched, mismatched, rosterState.value).let { if (it == book) book else it } }
        return true
    }

    /** The book of [workspaceId] as a sibling payload (null for another skwod's book). */
    fun siblingPayload(workspaceId: String): String? = if (workspaceId.isNotEmpty() && loadedFor == workspaceId) SiblingBook.encode(state.value) else null

    @Synchronized
    private fun update(change: (Map<String, Contact>) -> Map<String, Contact>) {
        val wid = model.current?.id ?: return
        // Not read yet (the read failed earlier): read now, or change nothing.
        if (loadedFor != wid) { load(); if (loadedFor != wid) return }
        val next = change(state.value)
        if (next === state.value) return
        state.value = next
        reindex()
        model.secretPut(key(wid), ContactTrust.encode(next))
    }

    /**
     * The accepted members of every server we share, as the caller established them: listed by
     * the server, minus the core's held members, minus pending join requests. Replaces the
     * roster part of the collision set.
     */
    /**
     * The name on record for an account — the contact book's, else the accepted-member list's —
     * to be passed to [shown] as the CLAIM. Never shown directly.
     */
    fun claimedName(userId: String): String? = state.value[userId]?.name?.takeIf { it.isNotEmpty() } ?: rosterState.value[userId]

    /** Accepted members of the servers this account is in (user id → claimed name). */
    val roster: Map<String, String> get() = rosterState.value
    val book: Map<String, Contact> get() = state.value

    @Synchronized
    fun setRoster(accepted: Map<String, String>) {
        val wid = model.current?.id ?: return
        if (loadedFor != wid || rosterState.value == accepted) return
        rosterState.value = accepted
        reindex()
        model.secretPut(rosterKey(wid), ContactTrust.encode(accepted.mapValues { Contact(it.key, it.value, TrustLevel.UNVERIFIED) }))
    }

    fun forget(workspaceId: String) { model.secretPut(key(workspaceId), null); model.secretPut(rosterKey(workspaceId), null) }

    /**
     * Ask the directory whom a server-claimed name belongs to, once per (account, name), one
     * request at a time. Until it answers the name shows as "couldn't check"; a failed lookup is
     * tried again after a minute.
     */
    private fun ensureChecked(userId: String, name: String) {
        val k = "$userId|$name"
        val now = System.currentTimeMillis()
        val last = asked[k]
        val known = lookups.value[k]
        if (known != null && known !is WaitingTrust.Lookup.Failed) return
        if (last != null && now - last < 60_000) return
        asked[k] = now
        queue.trySend(userId to name)
        if (worker?.isActive != true) synchronized(this) {
            if (worker?.isActive != true) worker = model.launchJob {
                for ((id, claimed) in queue) {
                    val c = model.client
                    val answer = if (c == null || model.baseUrl == null) WaitingTrust.Lookup.Failed else directoryLookup(c, claimed)
                    // The answer is the directory of the workspace that was ASKED: if the user is
                    // in another one when it comes (a server can hold it), it says nothing about
                    // this book. (Asked again when the name is next shown.)
                    if (model.client !== c) { asked.remove("$id|$claimed"); continue }
                    lookups.value = lookups.value + ("$id|$claimed" to answer)
                }
            }
        }
    }

    /** The name to put on screen for [userId]; [claimed] is the server's name at that spot. */
    fun shown(userId: String?, claimed: String?): ContactTrust.Shown {
        val raw = claimed?.takeIf { it.isNotBlank() }
        if (userId.isNullOrEmpty()) {
            val name = NameSkeleton.visible(raw ?: "").ifEmpty { ContactTrust.UNKNOWN }
            return ContactTrust.Shown(name, TrustLevel.UNVERIFIED, if (raw != null && NameSkeleton.isUnusual(raw)) ContactTrust.Flag.UNUSUAL else ContactTrust.Flag.NONE)
        }
        val book = state.value
        val level = book[userId]?.level ?: TrustLevel.UNVERIFIED
        // Only a server-claimed name needs the directory cross-check.
        val name = if (level == TrustLevel.UNVERIFIED) raw ?: book[userId]?.name?.takeIf { it.isNotBlank() } else null
        val lookup = if (name == null) null else lookups.value["$userId|$name"].also { ensureChecked(userId, name) }
        return ContactTrust.display(userId, claimed, book, collisions.value, lookup)
    }

    /** First run: seed the book from the stored conversations ([ContactTrust.migrate]). */
    fun migrate(conversations: List<ContactTrust.Legacy>) = update { if (it.isEmpty()) ContactTrust.migrate(conversations) else it }

    /** A server-supplied name for a DM peer: remembered as a claim, nothing more. */
    fun claim(userId: String, name: String?) { if (!name.isNullOrBlank()) update { ContactTrust.record(it, userId, name, TrustLevel.UNVERIFIED) } }

    /** An explicit action by the user on this device: started the DM, let them in, accepted the contact. */
    /**
     * Pins KNOWN only if the name would be shown with no flag at all ([ContactTrust.promote]).
     * [lookup]: what the directory said for this name when the caller itself just asked;
     * otherwise the cached cross-check (none yet = "couldn't check" = not pinned).
     */
    fun markKnown(userId: String, name: String, lookup: WaitingTrust.Lookup? = null) = update {
        ContactTrust.promote(it, userId, name, collisions.value, lookup ?: lookups.value["$userId|$name"])
    }

    /** A chat was opened from the New chat dialog: see [ContactTrust.onDmOpened]. */
    fun dmOpened(userId: String, name: String, alreadyListed: Boolean, lookup: WaitingTrust.Lookup?) = update {
        ContactTrust.onDmOpened(it, userId, name, alreadyListed, collisions.value, lookup)
    }

    /** Follow the core's verification state for this contact (the user compared safety numbers — or no longer has). */
    /** The ONE raise path, gated here (not by callers): a verification pins only a name that is
     *  clean right now ([ContactTrust.mayPinOnVerify] on [shown]: no look-alike, no unusual
     *  characters, no failed name check). Returns false when refused. The only caller that raises
     *  is `SafetyNumberDialog.refreshStatus(explicitVerify = true)` (see Build49Test). */
    fun setVerified(userId: String, verified: Boolean, name: String?): Boolean {
        if (verified) {
            val shown = shown(userId, name)
            if (!ContactTrust.mayPinOnVerify(shown)) return false
            update { ContactTrust.record(it, userId, shown.name, TrustLevel.VERIFIED) }
        } else update { ContactTrust.unverify(it, userId) }
        return true
    }

    /** Build 49: the sibling merge's raise, bound to [workspaceId] inside the store's lock: a
     *  switch of skwod in between makes it a no-op. The caller re-reads the core after it
     *  ([noteStatusRead]) so a concurrent un-verify wins. */
    @Synchronized
    fun setVerifiedFromSibling(userId: String, name: String?, workspaceId: String): Boolean {
        if (workspaceId.isEmpty() || loadedFor != workspaceId || model.current?.id != workspaceId) return false
        return setVerified(userId, true, name)
    }

    /** A read of the core's state: may only demote ([ContactTrust.afterStatusRead]). */
    fun noteStatusRead(userId: String, verified: Boolean) = update { ContactTrust.afterStatusRead(it, userId, verified) }

    /** Known / verified people, as (account id, name) — what a new name is compared against. */
    fun knownPeople(): List<Pair<String, String>> = state.value.values.filter { it.level != TrustLevel.UNVERIFIED }.map { it.userId to it.name }

    /** The accepted members currently in the collision set, as (account id, name). */
    fun rosterPeople(): List<Pair<String, String>> = rosterState.value.map { it.key to it.value }
}
