package io.skwod.app

import org.json.JSONArray
import org.json.JSONObject

/**
 * Small pure rules that keep one skwod's server out of another skwod's state, and a server's
 * word out of what this device holds. Each is unit-tested on the JVM (`IsolationRulesTest`).
 */

/**
 * Where a workspace is reached RIGHT NOW and the session token to present there — one value.
 * A request is built from this pair, never from "the current workspace's token" plus "the
 * current base URL": those change at different moments during a switch, and reading them
 * separately sends one skwod's token to another skwod's server.
 */
data class Endpoint(val workspaceId: String, val base: String, val token: String)

/** The one place the live [Endpoint] is put up and taken down. */
class EndpointSlot {
    @Volatile private var live: Endpoint? = null

    /** [base] null (the host is not reached) leaves nothing up. */
    fun put(workspaceId: String, base: String?, token: String) {
        live = if (base.isNullOrEmpty() || workspaceId.isEmpty()) null else Endpoint(workspaceId, base, token)
    }

    fun clear() { live = null }

    /** The endpoint of exactly [workspaceId], or null: never whichever one happens to be up. */
    fun of(workspaceId: String?): Endpoint? = live?.takeIf { workspaceId != null && it.workspaceId == workspaceId }
}

/**
 * Ids that become part of a file name on this device. A server's instance id is the server's
 * choice (older builds used it as the workspace id, and so as the cache file's name): only a
 * plain id is ever accepted or turned into a path — anything else fails closed.
 */
object InstanceIds {
    private val SHAPE = Regex("[A-Za-z0-9-]{1,64}")
    fun isValid(id: String?): Boolean = id != null && SHAPE.matches(id)

    /** The cache file name for a workspace id — null (no file is opened or deleted) unless the id is plain. */
    fun cacheFileName(workspaceId: String): String? = if (isValid(workspaceId)) "skwod-$workspaceId.sqlite3" else null
}

/** What the realtime socket's events may do. */
object RealtimeRules {
    /**
     * An event counts only on a topic this socket asked for. A server that sends events for
     * other topics (another channel's `message`, someone else's user topic) is ignored.
     */
    fun subscribed(topic: String, wanted: Set<String>): Boolean = topic.isNotEmpty() && topic in wanted

    /** What a server event may do to the history this device holds. */
    enum class Local {
        /** Nothing is changed; the open view re-reads through the core. */
        REDRAW_ONLY,
    }

    /**
     * `channel_cleared` is the SERVER saying the channel was cleared. Nothing in it is signed by
     * a member with the right to clear, so it never deletes decrypted history here: it is only
     * a reason to re-read. (Purging on a signed, end-to-end clear is the core's decision.)
     */
    fun onChannelCleared(): Local = Local.REDRAW_ONLY
}

/** Notices that were raised for one workspace, once another is in use. */
object NoticeRules {
    /**
     * Every notice is still shown — but its action ("Accept devices") was offered for the
     * workspace that raised it, and would now run against whichever client is current.
     * After a switch a notice can only be acknowledged.
     */
    fun afterSwitch(pending: List<SecurityAlert>): List<SecurityAlert> = pending.map { if (it.action == null) it else it.copy(action = null) }
}

/**
 * Mutes and calls. A missed real call is worse than an extra ring, so:
 * - only a WHOLE-SKWOD mute silences a call, and only that skwod's ([audible]);
 * - a per-conversation mute silences nothing but that conversation, once it is identified;
 * - a mute that could not be read counts as NOT muted;
 * - something whose skwod cannot be told apart is silenced only if EVERY candidate skwod is
 *   whole-skwod muted ([silenced]).
 */
object RingMute {
    fun <T> audible(found: List<Pair<T, Ring>>, callsRing: (T) -> Boolean): List<Pair<T, Ring>> = found.filter { callsRing(it.first) }

    /** [mutes]: each candidate skwod's stored mutes, null where they could not be read. */
    fun silenced(mutes: List<MuteList?>, now: Long): Boolean =
        mutes.isNotEmpty() && mutes.all { it != null && !it.callsRing(now) }

    /** Does a call on a skwod with these stored mutes ring? Unreadable ([list] null) = it rings. */
    fun rings(list: MuteList?, now: Long): Boolean = list == null || list.callsRing(now)
}

/** Is the answer to something asked of one workspace's client still that workspace's to file? */
object Asked {
    /**
     * [asked]: the binding captured BEFORE the server was asked; [now]: the binding when it
     * answered. Only the very same binding counts — a server that holds its answer across a
     * workspace switch (or a rebind) gets nothing written anywhere.
     */
    fun <T : Any> holds(asked: T?, now: T?): Boolean = asked != null && asked === now
}

/** A store that must be READ before it may be written: a failed read is not "empty". */
class ReadGate {
    @Volatile private var readFor: String? = null
    /** The read of [owner]'s store succeeded (also when nothing was stored). */
    fun read(owner: String) { readFor = owner }
    fun reset() { readFor = null }
    /** May [owner]'s store be written? Only once it was read — never over what could not be. */
    fun mayWrite(owner: String?): Boolean = owner != null && readFor == owner
}

/** The app lock's own settings. */
object LockSettings {
    /**
     * Changing "Lock after" needs the owner when it WEAKENS the lock (a longer delay): whoever
     * holds the unlocked phone for a moment must not be able to stretch it to an hour. Making
     * it stricter needs nothing.
     */
    fun needsAuthentication(fromMinutes: Int, toMinutes: Int): Boolean = toMinutes > fromMinutes
}

/** Where a decrypted attachment is kept while it is viewed. */
object AttachmentCache {
    /**
     * The cache file's name. It names WHAT WAS VERIFIED — the digest and key of the end-to-end
     * descriptor — not just the blob id and file name, which another member (with a colluding
     * server) can reuse: a file cached for one descriptor is never returned for another.
     * Null when the blob id is not a plain id.
     */
    fun fileName(blobId: String, name: String, digestB64: String?, keyB64: String): String? {
        if (!Regex("^[A-Za-z0-9-]{1,64}$").matches(blobId)) return null
        val safeName = name.replace(Regex("[^A-Za-z0-9._() -]"), "_").trimStart('.').takeLast(120).ifEmpty { "file" }
        val bound = java.security.MessageDigest.getInstance("SHA-256").digest("${digestB64 ?: ""}|$keyB64".toByteArray())
            .take(8).joinToString("") { "%02x".format(it) }
        return "$blobId-$bound-$safeName"
    }
}

/** Whose reactions a conversation shows. */
object ReactionRules {
    /**
     * A reaction counts only if I made it or someone this conversation is WITH did: the one
     * peer of a 1:1 chat, or a member of a group's stored set. An account that merely knows a
     * message id cannot put a pill under it.
     */
    fun counts(reactor: String?, me: String?, peers: Collection<String>): Boolean =
        !reactor.isNullOrEmpty() && (reactor == "__me__" || (me != null && reactor == me) || reactor in peers)
}

/** When the connect form may contact a host by itself. */
object InviteDial {
    /**
     * A link is untrusted input: tapping one (or scanning a code, or taking it from the
     * clipboard) only PREFILLS the form. While the field still holds exactly what was put
     * there that way ([adopted]), nothing is dialed — the link's author would learn this
     * device's address and that Skwod is installed from one tap. The host is contacted when
     * the user presses the form's button, when they edit the field themselves, or when the
     * link names a skwod this device is already in ([knownHost]).
     */
    fun mayDial(field: String, adopted: String?, knownHost: Boolean): Boolean =
        knownHost || adopted == null || field.trim() != adopted.trim()

    const val HELD_NOTE = "This invite came from a link. Skwod contacts its host when you continue."
}

/** A member's name on a surface that cannot style it (a call tile, a reply preview, a system row). */
object MemberLabel {
    /** [shown] is the contact book's verdict ([ContactBook.shown]); never the server's name as it came. */
    fun of(shown: ContactTrust.Shown, userId: String?): String =
        if (shown.name == ContactTrust.UNKNOWN) (if (userId.isNullOrEmpty()) "Member" else "A member (${userId.take(6)}…)") else shown.label
}

/**
 * Which messages were already announced — by MESSAGE ID, kept across restarts, bounded.
 *
 * Deciding by the server's timestamp against this device's clock re-announces a future-dated
 * message after every restart. Two buckets, each with its own bound:
 * - [announce] with `sure = true`: a message this device decrypted and announced;
 * - everything else (a generic notice for something not decrypted, an id only noted as "not to
 *   be announced"): the UNSURE bucket. Whatever a server floods it with, it can only push out
 *   other unsure ids — never a real one, which would be announced again.
 * Seeing an id again keeps it (most recently seen last), so what is still in a channel's
 * window is not evicted by what came since.
 */
class AnnouncedLedger(
    announced: Collection<String> = emptyList(), unsure: Collection<String> = emptyList(),
    private val maxAnnounced: Int = MAX_ANNOUNCED, private val maxUnsure: Int = MAX_UNSURE,
) {
    companion object {
        const val MAX_ANNOUNCED = 1000
        const val MAX_UNSURE = 300
        /** Ids are server-chosen: anything longer than a plain id is not kept. */
        private const val MAX_ID = 128

        fun decode(json: String?, maxAnnounced: Int = MAX_ANNOUNCED, maxUnsure: Int = MAX_UNSURE): AnnouncedLedger {
            if (json.isNullOrBlank()) return AnnouncedLedger(maxAnnounced = maxAnnounced, maxUnsure = maxUnsure)
            return try {
                val o = JSONObject(json)
                fun list(key: String): List<String> = o.optJSONArray(key)?.let { a -> (0 until a.length()).mapNotNull { a.optString(it).takeIf { s -> s.isNotEmpty() } } } ?: emptyList()
                AnnouncedLedger(list("a"), list("u"), maxAnnounced, maxUnsure)
            } catch (_: Exception) { AnnouncedLedger(maxAnnounced = maxAnnounced, maxUnsure = maxUnsure) }
        }
    }

    private val sureIds = LinkedHashSet<String>()
    private val unsureIds = LinkedHashSet<String>()
    /** Changed since the last [encode]? */
    @get:Synchronized var dirty = false
        private set

    init {
        announced.forEach { if (usable(it)) sureIds.add(it) }
        unsure.forEach { if (usable(it) && it !in sureIds) unsureIds.add(it) }
        trim()
    }

    private fun usable(id: String) = id.isNotEmpty() && id.length <= MAX_ID

    private fun trim() {
        while (sureIds.size > maxAnnounced) sureIds.remove(sureIds.first())
        while (unsureIds.size > maxUnsure) unsureIds.remove(unsureIds.first())
    }

    /** Is [id] settled (announced, or noted as not to be announced)? Seeing it keeps it. */
    @Synchronized fun seen(id: String): Boolean = when {
        sureIds.remove(id) -> { sureIds.add(id); dirty = true; true }
        unsureIds.remove(id) -> { unsureIds.add(id); dirty = true; true }
        else -> false
    }

    /**
     * True exactly once per id: the caller announces it now. [sure]: this device decrypted it.
     * An id that cannot be kept (empty, oversized) is never announced — it could not be
     * remembered, and would be announced again every time.
     */
    @Synchronized fun announce(id: String, sure: Boolean): Boolean {
        if (!usable(id)) return false
        if (seen(id)) {
            // Decrypted now, announced generically before: it is a real one from here on.
            if (sure && unsureIds.remove(id)) { sureIds.add(id); trim() }
            return false
        }
        (if (sure) sureIds else unsureIds).add(id)
        trim(); dirty = true
        return true
    }

    /** Note [id] as not to be announced (my own copy, something older than what was seen). */
    @Synchronized fun skip(id: String) {
        if (!usable(id) || id in sureIds || id in unsureIds) return
        unsureIds.add(id); trim(); dirty = true
    }

    @Synchronized fun encode(): String {
        dirty = false
        return JSONObject().put("a", JSONArray(sureIds.toList())).put("u", JSONArray(unsureIds.toList())).toString()
    }

    @get:Synchronized val announcedCount: Int get() = sureIds.size
    @get:Synchronized val unsureCount: Int get() = unsureIds.size
}
