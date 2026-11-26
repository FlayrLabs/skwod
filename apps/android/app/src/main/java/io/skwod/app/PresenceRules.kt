package io.skwod.app

// Who shows as online (build 51); the twin of the Apple apps' PresenceRules.swift. Presence is what
// the HOST reports: it colours a dot and nothing else. Every time here is this device's own
// monotonic clock in milliseconds (`SystemClock.elapsedRealtime`), so neither wall clock matters.

/** Immutable. */
data class PresenceBook(
    val seen: Map<String, Seen> = emptyMap(),
    val heardAt: Long? = null,
    val polledAt: Long? = null,
) {
    data class Seen(val status: String, val at: Long)

    /** [status]: the one to list someone under, current or last seen. [current] false: not known
     *  now (never reported, or this device has lost the host). [dot]: what the dot shows. */
    data class View(val status: String, val current: Boolean) {
        val dot: String get() = if (current) status else "unknown"
    }

    /** A live event, as it arrives. */
    fun event(userId: String, status: String, now: Long): PresenceBook =
        if (userId.isEmpty() || status !in STATUSES) this
        else copy(seen = seen + (userId to Seen(status, now)), heardAt = maxOf(heardAt ?: now, now))

    /** A member list, asked for at [askedAt]: it says nothing newer than that, so an event (or a
     *  later question) that came while it was on its way stands. */
    fun polled(statuses: Map<String, String>, askedAt: Long): PresenceBook = copy(
        seen = seen + statuses.filter { (id, s) -> s in STATUSES && (seen[id]?.at ?: askedAt) <= askedAt }.mapValues { Seen(it.value, askedAt) },
        heardAt = maxOf(heardAt ?: askedAt, askedAt), polledAt = maxOf(polledAt ?: askedAt, askedAt))

    fun view(userId: String, now: Long): View {
        val connected = heardAt != null && now - heardAt < SILENCE_MS
        val have = seen[userId] ?: return View("offline", false)
        if (now - have.at < WINDOW_MS) return View(have.status, connected)
        // Old news: silent for that long (the lists since then no longer name them) is offline;
        // with nothing asked since (just back from the background) it is not known.
        if (connected && polledAt != null && polledAt > have.at) return View("offline", true)
        return View(have.status, false)
    }

    companion object {
        /** The host counts someone silent for this long as offline. */
        const val WINDOW_MS = 180_000L
        /** Nothing heard from the host for this long (it is asked every 30 s): the connection on
         *  THIS side is gone, and what is known about others is only what was last seen. */
        const val SILENCE_MS = 90_000L
        private val STATUSES = setOf("online", "idle", "dnd", "offline")
    }
}

/**
 * Who is presented as online while THIS device is, or is not, connected to the host (build 51; the
 * twin of `PresenceRoster` in PresenceRules.swift). With its own connection down it knows nothing
 * current about anyone: no "N online", nobody listed as online, no green dot.
 */
object PresenceRoster {
    /** The "N online" count — null (not shown) while not connected. */
    fun onlineCount(ids: List<String>, me: String?, live: Boolean, status: (String) -> String): Int? =
        if (!live) null else ids.count { it == me || status(it) != "offline" }

    data class Groups<T>(val online: List<T> = emptyList(), val offline: List<T> = emptyList(), val unknown: List<T> = emptyList())

    fun <T> groups(members: List<T>, live: Boolean, status: (T) -> String): Groups<T> =
        if (!live) Groups(unknown = members)
        else Groups(online = members.filter { status(it) != "offline" }, offline = members.filter { status(it) == "offline" })

    /** The dot while not connected: never live. */
    fun dot(dot: String, live: Boolean): String = if (live) dot else "unknown"

    fun unknownTitle(count: Int) = "Members — $count · not connected"
}

/**
 * What this device says about its own account. The host keeps ONE status per account and the last
 * device to speak sets it, so a device that is not in front repeats nothing.
 */
object PresenceAnnounce {
    /** Null: say nothing. */
    fun status(active: Boolean, chosen: String): String? = if (active) chosen else null
    /** Once a minute. Being invisible needs no repeating. */
    fun periodic(active: Boolean, chosen: String): String? = status(active, chosen)?.takeIf { it != "offline" }

    /** At most one correction in this long. */
    const val GAP_MS = 15_000L

    /** Another device of this account (0.50 and older say "offline" whenever they are not in
     *  front) just took the account offline while it is in use here: say so again. */
    fun corrects(eventUser: String, status: String, me: String, announced: String?, lastSentAt: Long?, now: Long): Boolean =
        me.isNotEmpty() && eventUser == me && status == "offline" && announced != null && announced != "offline" &&
            (lastSentAt == null || now - lastSentAt >= GAP_MS)
}
