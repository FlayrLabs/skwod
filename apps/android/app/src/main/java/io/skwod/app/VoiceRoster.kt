package io.skwod.app

import org.json.JSONObject

/** One person in a server's voice room, as the server says (build 47, `voice_state`). */
data class VoiceParticipant(val userId: String, val muted: Boolean, val video: Boolean, val screen: Boolean, val joinedAt: Long)

/**
 * Who is in each server's voice room right now — the list under the voice channel in the
 * sidebar (the twin of Apple's `VoiceRoster`). Fed only by `voice_state` events
 * on a `server:<id>` topic; each carries the FULL roster of one room, so applying it replaces
 * that room. Emptied when the socket comes back (the server hands every roster again on
 * subscribing).
 *
 * Not here: who is speaking (only the call this phone is in knows it — [VoiceSpeaking]) and
 * "deafened" (a local setting). Names are never taken from the event: the label this phone has
 * for the user id is shown ([ContactTrust]).
 */
data class VoiceRoster(val rooms: Map<String, Map<String, List<VoiceParticipant>>> = emptyMap()) {

    /** A `voice_state` event: the roster after it, or null when it is refused or changes nothing. */
    fun apply(topic: String, payload: JSONObject): VoiceRoster? {
        val serverId = payload.optString("server_id")
        val channelId = payload.optString("channel_id")
        if (serverId.isEmpty() || topic != "server:$serverId" || channelId.isEmpty() || channelId.length > 128) return null
        val list = payload.optJSONArray("participants") ?: return null
        val seen = HashSet<String>()
        val people = ArrayList<VoiceParticipant>()
        for (i in 0 until minOf(list.length(), MAX_LISTED)) {
            val p = list.optJSONObject(i) ?: continue
            val uid = p.optString("user_id")
            if (uid.isEmpty() || uid.length > 128 || !seen.add(uid)) continue
            people.add(VoiceParticipant(uid, p.optBoolean("muted"), p.optBoolean("video"), p.optBoolean("screen"), p.optLong("joined_at")))
        }
        val old = rooms[serverId]?.get(channelId).orEmpty()
        if (old == people) return null
        if (old.isEmpty() && rooms[serverId].orEmpty().size >= MAX_ROOMS) return null
        val server = rooms[serverId].orEmpty().toMutableMap()
        if (people.isEmpty()) server.remove(channelId) else server[channelId] = people
        val next = rooms.toMutableMap()
        if (server.isEmpty()) next.remove(serverId) else next[serverId] = server
        return VoiceRoster(next)
    }

    /** Everyone in the server's voice room(s), in join order, without [hidden] (blocked). */
    fun participants(serverId: String, hidden: Set<String> = emptySet()): List<VoiceParticipant> {
        val seen = HashSet<String>()
        return rooms[serverId].orEmpty().toSortedMap().values.flatten()
            .sortedWith(compareBy({ it.joinedAt }, { it.userId }))
            .filter { it.userId !in hidden && seen.add(it.userId) }
    }

    /** How many are in the server's voice room(s): the count shown while the list is folded. */
    fun count(serverId: String, hidden: Set<String> = emptySet()): Int = participants(serverId, hidden).size

    companion object {
        const val MAX_LISTED = 64
        /** Non-empty rooms kept per server at most: what a host sends is bounded here, not by trust. */
        const val MAX_ROOMS = 64

        /** "3 in voice", or null for nobody. */
        fun countLabel(n: Int): String? = if (n > 0) "$n in voice" else null
    }
}
