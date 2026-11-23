package io.skwod.app

/**
 * Build 47: leaving a server is authoritative on this device from the moment the user confirms
 * (the twin of Apple's `LeaveTombstones`).
 *
 * Before, nothing remembered a left server: a channel listing ([AppChat.syncServerChannels],
 * started by a `channels_changed` / `member_removed` nudge or on entering the skwod), a
 * discovery or a membership recovery that was already in flight finished after the leave and
 * put its channels back until the next server-list refresh took them out — the "flash back".
 *
 * A TOMBSTONE is set when Leave is confirmed; the channels go at once and every path that adds
 * channels asks [hides] first. It is LEAVING while the host has not answered (a refusal rolls it
 * back and the channels come back where they were) and LEFT once the host confirmed or the
 * server went for another reason (deleted, removed, no longer listed). It stays until the user
 * joins that server again on purpose ([rejoined]).
 */
class LeaveTombstones {
    enum class Mark { LEAVING, LEFT }

    private val marks = HashMap<String, Mark>()

    @Synchronized fun mark(serverId: String): Mark? = marks[serverId]

    /** Whether anything of [serverId] may be shown or added right now. */
    @Synchronized fun hides(serverId: String): Boolean = marks.containsKey(serverId)

    /** The user confirmed Leave. False when it is already being left (a second tap does nothing). */
    @Synchronized fun begin(serverId: String): Boolean {
        if (serverId.isEmpty() || marks.containsKey(serverId)) return false
        marks[serverId] = Mark.LEAVING
        return true
    }

    /** The host confirmed the membership is gone. */
    @Synchronized fun confirm(serverId: String) { if (serverId.isNotEmpty()) marks[serverId] = Mark.LEFT }

    /**
     * The host refused or could not be reached: the leave did not happen. Only a mark this leave
     * set is lifted. Returns whether the channels should come back.
     */
    @Synchronized fun failed(serverId: String): Boolean {
        if (marks[serverId] != Mark.LEAVING) return false
        marks.remove(serverId)
        return true
    }

    /** Servers gone for another reason (deleted, removed, no longer listed for this account). */
    @Synchronized fun dropped(ids: Collection<String>) { for (id in ids) if (id.isNotEmpty()) marks[id] = Mark.LEFT }

    /** The user joined this server (again) on purpose. */
    @Synchronized fun rejoined(serverId: String) { marks.remove(serverId) }

    /** Another workspace (account) is in use: what was left is not its business. */
    @Synchronized fun clear() { marks.clear() }

    companion object {
        /**
         * Put back what a failed leave took out, each where it was in [before]; whatever was
         * added meanwhile stays, after them.
         */
        fun <T> restore(before: List<T>, now: List<T>, serverId: String, server: (T) -> String, key: (T) -> String): List<T> {
            val nowKeys = now.map(key).toSet()
            val beforeKeys = before.map(key).toSet()
            return before.filter { server(it) == serverId || key(it) in nowKeys } + now.filter { key(it) !in beforeKeys }
        }
    }
}
