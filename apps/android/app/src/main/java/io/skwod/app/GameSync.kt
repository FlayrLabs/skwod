package io.skwod.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/**
 * Realtime, E2EE game state for in-channel games — the Android peer of iOS `GameSync`.
 *
 * Game moves ride the SAME Sender-Key channel path as chat: each update is a normal channel message,
 * tagged with the  STX prefix so the chat view hides it. The server only ever sees ciphertext. A
 * board refreshes when the relay reports a message in the channel (plus a slow safety timer);
 * deterministic last-write-wins (highest
 * seq, ties broken by mover id) makes simultaneous moves converge. The wire JSON is byte-compatible
 * with iOS/macOS, so a game can be played across platforms.
 */
const val GAME_TAG = "skwod/game|"

fun isGameContent(body: String): Boolean = body.startsWith(GAME_TAG)

/** A full board snapshot for chess (cross-platform wire model, matches iOS `ChessSnapshot`). */
data class ChessSnapshot(
    val seq: Int,
    val cells: List<String>,   // 64 entries row-major, "" empty or e.g. "wp","bk"
    val turn: String,          // "white" | "black"
    val white: String?,        // user id in the white seat (null = open)
    val black: String?,        // user id in the black seat (null = open)
    val by: String?,           // mover's user id — device-consistent tiebreak
) {
    fun toJson(): String = JSONObject().apply {
        put("seq", seq)
        put("cells", JSONArray(cells))
        put("turn", turn)
        put("white", white ?: JSONObject.NULL)
        put("black", black ?: JSONObject.NULL)
        put("by", by ?: JSONObject.NULL)
    }.toString()

    companion object {
        fun fromJson(s: String): ChessSnapshot? = try {
            val o = JSONObject(s)
            val arr = o.getJSONArray("cells")
            ChessSnapshot(
                o.getInt("seq"),
                (0 until arr.length()).map { arr.getString(it) },
                o.getString("turn"),
                o.optString("white").ifEmpty { null }.takeUnless { o.isNull("white") },
                o.optString("black").ifEmpty { null }.takeUnless { o.isNull("black") },
                o.optString("by").ifEmpty { null }.takeUnless { o.isNull("by") },
            )
        } catch (_: Exception) { null }
    }
}

/** A whiteboard event: an appended stroke or a clear (matches iOS `WhiteboardEvent`). */
data class WhiteboardEvent(
    val kind: String,                  // "stroke" | "clear"
    val strokeId: String?,
    val points: List<List<Double>>?,   // [[x,y], …] normalized 0…1
    val colorIndex: Int?,
    val width: Double?,
) {
    fun toJson(): String = JSONObject().apply {
        put("kind", kind)
        strokeId?.let { put("strokeId", it) }
        points?.let { pts -> put("points", JSONArray().apply { pts.forEach { p -> put(JSONArray(p)) } }) }
        colorIndex?.let { put("colorIndex", it) }
        width?.let { put("width", it) }
    }.toString()

    companion object {
        fun fromJson(s: String): WhiteboardEvent? = try {
            val o = JSONObject(s)
            val pts = o.optJSONArray("points")?.let { arr ->
                (0 until arr.length()).map { i ->
                    val p = arr.getJSONArray(i); listOf(p.getDouble(0), p.getDouble(1))
                }
            }
            WhiteboardEvent(
                o.getString("kind"),
                if (o.has("strokeId")) o.getString("strokeId") else null,
                pts,
                if (o.has("colorIndex")) o.getInt("colorIndex") else null,
                if (o.has("width")) o.getDouble("width") else null,
            )
        } catch (_: Exception) { null }
    }
}

/** One decoded game event with ordering/attribution metadata. */
data class GameEvent<T>(val authorId: String, val createdAt: Long, val event: T) {
    val mine: Boolean get() = authorId == "__me__"
}

/** Send + fetch E2EE game events on a channel. Thin wrapper over the channel message path. */
class GameSync(private val model: AppModel, private val channelId: String) {
    suspend fun sendChess(s: ChessSnapshot) = send(s.toJson())
    suspend fun sendBoard(e: WhiteboardEvent) = send(e.toJson())

    /** Returns false when the move could not be sent (the board says so instead of dropping it). */
    private suspend fun send(json: String): Boolean = withContext(Dispatchers.IO) {
        // Queued, like everything a person does: a move made while the connection is down is
        // delivered (once, in order) when it is back. False only when it could not be queued.
        val c = model.client ?: return@withContext false
        try { c.queueChannelMessage(channelId, GAME_TAG + json, null, emptyList(), emptyList()) } catch (_: Exception) { return@withContext false }
        Outbox.kick(model)
        true
    }

    /**
     * Run [block] now and whenever the relay reports a message in this channel (a game move is a
     * message like any other to the server), on reconnect, and on a slow safety timer.
     */
    suspend fun watch(block: suspend () -> Unit) {
        val topic = "channel:$channelId"
        model.realtime.refreshLoop(30_000, match = { it.topic == topic && it.event == "message" }, block = block)
    }

    suspend fun fetchChess(): List<GameEvent<ChessSnapshot>> =
        fetchRaw().mapNotNull { (a, t, body) -> ChessSnapshot.fromJson(body)?.let { GameEvent(a, t, it) } }

    suspend fun fetchBoard(): List<GameEvent<WhiteboardEvent>> =
        fetchRaw().mapNotNull { (a, t, body) -> WhiteboardEvent.fromJson(body)?.let { GameEvent(a, t, it) } }

    private suspend fun fetchRaw(): List<Triple<String, Long, String>> = withContext(Dispatchers.IO) {
        val me = model.current?.userId ?: return@withContext emptyList()
        // Game traffic has its own lane in the cache (`aux:<channel>`), filed there by the core:
        // it no longer competes with chat for the history window, and is not found by
        // filtering chat history.
        val rows = try { model.client?.fetchAuxMessages(channelId, me) ?: emptyList() } catch (_: Exception) { emptyList() }
        rows.mapNotNull { m ->
            val c = m.content ?: return@mapNotNull null
            if (!c.startsWith(GAME_TAG)) null
            else Triple(m.authorId ?: "", m.createdAt, c.substring(GAME_TAG.length))
        }.sortedBy { it.second }
    }
}
