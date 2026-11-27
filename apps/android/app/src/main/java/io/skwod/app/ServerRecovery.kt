package io.skwod.app

// Build 51: the servers of this account that this device does not show yet (newly linked, restored,
// reinstalled), and when to look for them again. The twin of the Apple apps' ServerRecovery.swift.

/** Immutable. Times in milliseconds. */
data class ServerRecovery(
    /** The account's servers as last answered, successfully and completely; null: never. */
    val servers: Set<String>? = null,
    /** Asked in vain since the last answer. */
    val failures: Int = 0,
    /** Passes since something gave reason to look again at once. */
    val passes: Int = 0,
    /** Missing servers whose name this device can read (it holds their key). */
    val keyed: Set<String> = emptySet(),
    private val asked: Map<String, Pair<Int, Long>> = emptyMap(),
) {
    /** What an empty server list says. */
    enum class State(val title: String, val detail: String) {
        /** This device is not one of the account's yet. */
        NOT_SET_UP("This device isn't set up yet", "Link it from another device, or restore your account, to see your servers."),
        LOADING("Loading your servers…", ""),
        /** A member, but nobody has handed this device the keys yet. */
        WAITING_FOR_KEYS("Waiting for keys from your other device or a member who is online", "Your servers appear here by themselves as soon as the keys arrive."),
        /** The keys are here; there is no text channel to show. */
        NO_CHANNELS("No channels to show yet", "Your servers here have no text channel you can read."),
        /** The skwod answered, completely: none. */
        NONE("You're not in any server here yet", "Join one with an invite code from a friend who hosts a Skwod."),
        FAILED("Couldn't load your servers", ""),
    }

    /** The skwod's list (null: it could not be asked, refused, or did not answer completely). */
    fun answered(list: Set<String>?): ServerRecovery =
        if (list == null) copy(failures = failures + 1) else copy(servers = list, failures = 0, keyed = keyed intersect list)

    /** Back in front, reconnected, linked, Retry: look now, and often again for a while. */
    fun nudged() = copy(passes = 0)
    fun passed() = copy(passes = passes + 1)
    fun found(server: String, holds: Boolean) = copy(keyed = if (holds) keyed + server else keyed - server)

    /** In the list, not on screen, and not left or removed here. */
    fun missing(shown: Set<String>, hidden: Set<String>): Set<String> = (servers ?: emptySet()) - shown - hidden

    /** Nothing left to look for. */
    fun settled(shown: Set<String>, hidden: Set<String>): Boolean = servers != null && failures == 0 && missing(shown, hidden).isEmpty()

    /** Until the next pass: it backs off to one a minute and keeps on. */
    fun delay(active: Boolean): Long = when {
        passes == 0 -> SPACING_MS
        active && passes <= STEPS_MS.size -> STEPS_MS[passes - 1]
        else -> 60_000
    }

    /** May members be asked for [server]'s keys (again)? At 10 s, 20 s, … up to every 5 minutes. */
    fun mayAsk(server: String, now: Long): Boolean {
        val (count, at) = asked[server] ?: return true
        return now - at >= minOf(10_000L shl (minOf(count, 10) - 1), 300_000L)
    }
    fun didAsk(server: String, now: Long) = copy(asked = asked + (server to ((asked[server]?.first ?: 0) + 1 to now)))

    /** What to say while the list is empty. */
    fun state(setUp: Boolean, shown: Set<String>, hidden: Set<String>): State {
        if (!setUp) return State.NOT_SET_UP
        val gone = missing(shown, hidden)
        return when {
            gone.isNotEmpty() -> if (keyed.containsAll(gone)) State.NO_CHANNELS else State.WAITING_FOR_KEYS
            failures >= 2 -> State.FAILED
            servers == null || failures > 0 -> State.LOADING
            else -> State.NONE
        }
    }

    companion object {
        /** Never less than this between two passes, whatever happens meanwhile. */
        const val SPACING_MS = 2_000L
        private val STEPS_MS = listOf(2_000L, 4_000L, 8_000L, 15_000L, 30_000L)
    }
}
