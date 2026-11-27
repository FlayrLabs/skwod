package io.skwod.app

import org.json.JSONObject

// Build 51: choosing a server opens a channel. Decided here from what this phone holds, with
// nothing to wait for between deciding and opening. The twin of the Apple app's ChannelLanding.swift.

/**
 * The channel last opened in each server ([channels]: server id → channel id) of one skwod on this
 * phone, and the server last used, as JSON in the skwod's encrypted cache: which channels someone
 * reads is nobody else's business.
 */
data class ChannelMemory(val server: String? = null, val channels: Map<String, String> = emptyMap()) {
    fun opened(channel: String, id: String) = ChannelMemory(id, channels + (id to channel))
    /** Left or gone: nothing about it is kept. */
    fun forget(id: String) = ChannelMemory(server.takeIf { it != id }, channels - id)

    fun encode(): String = JSONObject().put("channels", JSONObject(channels)).apply { server?.let { put("server", it) } }.toString()

    companion object {
        fun storageKey(workspaceId: String) = "$workspaceId|channels.last"
        fun decode(json: String?): ChannelMemory? = try {
            if (json.isNullOrBlank()) null else JSONObject(json).let { o ->
                val c = o.getJSONObject("channels")
                ChannelMemory(if (o.isNull("server")) null else o.getString("server"), c.keys().asSequence().associateWith { c.getString(it) })
            }
        } catch (_: Exception) { null }
    }
}

/** A text channel in the list, in the order it shows. [readable]: the server has not refused this account its messages. */
data class LandingChannel(val id: String, val serverId: String, val readable: Boolean = true)

/**
 * When a channel opens by itself: only after the user picked its server (the rail, another skwod, a
 * join they started here) or at launch, and only while nothing is open. Nothing the host sends
 * opens or replaces anything. [byUser]: the user opened this very channel.
 */
data class Landing(val want: Want? = null, val byUser: Boolean = false) {
    /** [server] null: the skwod as a whole (launch, another skwod). [reveal]: slide to the chat as well. */
    data class Want(val server: String? = null, val reveal: Boolean = false)

    sealed class Place {
        data object Open : Place()
        data object Loading : Place()
        data class Channel(val id: String) : Place()
        /** No text channel there that the user may read. */
        data class Empty(val server: String) : Place()
        data object NoServers : Place()
        /** Nothing is open and nothing was asked for. */
        data object Closed : Place()
    }

    /** The user picked a server or skwod (or the app starts). */
    fun asked(want: Want) = copy(want = want)
    /** They went elsewhere: their direct messages. */
    fun left() = copy(want = null)
    fun opened() = Landing(byUser = true)
    fun landed() = Landing(byUser = false)
    /** A join ended and its channels are in the list. Decided later, or resumed: only listed. */
    fun joined(server: String, startedHere: Boolean, open: Boolean): Landing = when {
        startedHere && !open -> copy(want = Want(server, reveal = true))
        !startedHere && want?.server == null -> copy(want = null)
        else -> this
    }

    fun place(open: Boolean, ready: Boolean, settingUp: Boolean, memory: ChannelMemory, channels: List<LandingChannel>): Place {
        if (open) return Place.Open
        val want = want ?: return Place.Closed
        if (!ready) return Place.Loading
        val listed = channels.map { it.serverId }.distinct()
        // A server that was picked: that one or nothing, never another.
        val servers = want.server?.let { listOf(it) } ?: listed.sortedByDescending { it == memory.server }
        for (server in servers) {
            val usable = channels.filter { it.serverId == server && it.readable }
            (usable.firstOrNull { it.id == memory.channels[server] } ?: usable.firstOrNull())?.let { return Place.Channel(it.id) }
        }
        if (settingUp) return Place.Loading
        return servers.firstOrNull()?.let { Place.Empty(it) } ?: Place.NoServers
    }

    companion object {
        /** A composer's conversation: its view's identity, and what a send checks. */
        fun conversationKey(workspaceId: String?, serverId: String, channelId: String) = "${workspaceId ?: ""}|$serverId|$channelId"
        fun maySend(composedIn: String?, now: String) = composedIn == now

        /** The server's answer to reading one channel was "not allowed" or "no such channel". */
        fun isReadRefusal(detail: String?): Boolean {
            val d = detail?.lowercase() ?: return false
            return ("status 403" in d && "forbidden" in d) || "status 404" in d
        }
    }
}
