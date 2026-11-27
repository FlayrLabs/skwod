package io.skwod.app

import androidx.compose.runtime.mutableStateOf
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** One realtime event as the relay delivered it. The payload never carries anything readable. */
class RtEvent(val topic: String, val event: String, val payload: JSONObject)

/**
 * Live client for the server's WebSocket relay (`/api/ws`) — the Android peer of iOS `Realtime`.
 *
 * - Presence: on connect and on every status change we send a presence frame; the server fans it
 *   out instantly, so other devices flip us online/offline without waiting for heartbeat + poll.
 * - Messages: `message` events on subscribed topics (and `sealed` on our own user topic, for DMs)
 *   become LOCAL notifications when that chat isn't focused or the app is backgrounded. The text
 *   is decrypted on this device by [MessageNotifier]; nothing readable ever travels in a push.
 * - Calls: a `ring` event on our user topic raises the incoming-call notification; `ring_cancel`
 *   takes it down again.
 * - Refresh: every event is also published on [events], and that is what the open views refresh
 *   on ([refreshLoop]) — nothing polls a whole conversation every second or two any more.
 * - Joining: `join_request` (someone is waiting for me to let them in), `join_approved` /
 *   `join_denied` (my own request was answered).
 *
 * The server sees ciphertext only and does not say what KIND of message an event is about:
 * chat, a like, a game move and an avatar all arrive as the same `message` event. Whether one
 * is announced is decided on this device after decrypting ([MessageNotifier]).
 *
 * The socket lives as long as the process does, and [ConnectionService] keeps the process alive
 * while the user is signed in — that is the whole notification transport on Android (no FCM).
 * For a p2p skwod `baseUrl` is the loopback proxy, so the socket rides the p2p session.
 */
class Realtime(private val model: AppModel) {

    /** Who is online, from live events and polled member lists: the newest word wins ([PresenceBook]). */
    val presence = mutableStateOf(PresenceBook())
    private fun clock() = android.os.SystemClock.elapsedRealtime()
    /** Who is in each server's voice room (build 47; [VoiceRoster], fed by `voice_state`). */
    val voiceRoster = mutableStateOf(VoiceRoster())

    /** channelId/conversationId → display name for notification titles. */
    @Volatile var chatNames: Map<String, String> = emptyMap()
    /** The topic currently on screen — its messages never notify. */
    @Volatile var focusedTopic: String? = null
    /** Whether the app is foregrounded; background messages always notify. */
    @Volatile var appActive = false

    private val http = OkHttpClient.Builder()
        .pingInterval(30, TimeUnit.SECONDS)   // keeps the socket alive + detects dead peers
        .build()
    @Volatile private var ws: WebSocket? = null
    @Volatile private var wanted: Set<String> = emptySet()
    @Volatile private var closedByUs = true
    @Volatile private var myUserId = ""
    /** The status this device announces; null while the app is away ([PresenceAnnounce]). */
    @Volatile private var announced: String? = null
    @Volatile private var announcedAt: Long? = null
    @Volatile private var baseUrl = ""
    @Volatile private var token = ""
    @Volatile private var reconnectDelayMs = 1000L

    /** Every event the relay delivers, for the views that refresh on them. */
    val events = MutableSharedFlow<RtEvent>(extraBufferCapacity = 128, onBufferOverflow = BufferOverflow.DROP_OLDEST)
    /** Bumped each time the socket (re)connects: whatever happened while it was down sent no event. */
    val connectEpoch = MutableStateFlow(0)
    /** Whether the socket is up right now (the safety timers run faster while it is not). */
    val connected = mutableStateOf(false)

    /**
     * Run [block] now, then again whenever an event matching [match] arrives, when the socket
     * reconnects, and on a slow safety timer ([safetyMs], never less than 30 s) — instead of
     * polling. Bursts collapse into one run. Never returns; cancel the calling coroutine.
     */
    /** Build 51: "catch up now" (`AppModel.catchUp`): every [refreshLoop] runs its block. */
    val catchUps = kotlinx.coroutines.flow.MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = kotlinx.coroutines.channels.BufferOverflow.DROP_OLDEST)

    suspend fun refreshLoop(safetyMs: Long = 30_000, match: (RtEvent) -> Boolean, block: suspend () -> Unit) {
        coroutineScope {
            val poke = Channel<Unit>(Channel.CONFLATED)
            launch { events.collect { if (match(it)) poke.trySend(Unit) } }
            launch { connectEpoch.drop(1).collect { poke.trySend(Unit) } }
            // Build 51: an app-wide catch-up (back in front, network back) runs every loop now.
            launch { catchUps.collect { poke.trySend(Unit) } }
            while (true) {
                try { block() } catch (e: CancellationException) { throw e } catch (_: Exception) {}
                withTimeoutOrNull(safetyMs.coerceAtLeast(30_000)) { poke.receive() }
            }
        }
    }

    /** The status to list someone under (online / offline sections), and the one their dot shows:
     *  "unknown" while this device cannot tell. */
    fun status(userId: String): String = presence.value.view(userId, clock()).status
    fun dot(userId: String): String = PresenceRoster.dot(presence.value.view(userId, clock()).dot, connected.value)

    /** The clock of [PresenceBook], for a list that is about to be asked for. */
    fun presenceClock(): Long = clock()

    /** A member list that was asked for at [askedAt]. */
    @Synchronized
    fun seedPresence(statuses: Map<String, String>, askedAt: Long) { presence.value = presence.value.polled(statuses, askedAt) }

    @Synchronized
    private fun seenPresence(userId: String, status: String, now: Long) { presence.value = presence.value.event(userId, status, now) }

    /** Moves when a poll brought nothing: what is shown may have become "unknown". */
    val unheard = mutableStateOf(0)

    /** Server ids parsed from the subscribed topics — the app-level presence poll walks these. */
    fun subscribedServerIds(): Set<String> =
        wanted.filter { it.startsWith("server:") }.map { it.removePrefix("server:") }.toSet()

    /** (Re)bind to a workspace and connect. Safe to call on every workspace switch. */
    fun configure(baseUrl: String, token: String, userId: String, status: String?) {
        // (Another account's people are not this one's.)
        if (myUserId != userId) presence.value = PresenceBook()
        this.baseUrl = baseUrl; this.token = token; this.myUserId = userId; this.announced = status
        // Exactly one user topic: ours on THIS skwod (each skwod is a separate account).
        wanted = wanted.filterNot { it.startsWith("user:") }.toSet() + (if (userId.isNotEmpty()) setOf("user:$userId") else emptySet())
        closedByUs = false
        reconnectDelayMs = 1000
        open()
    }

    /** Replace the desired topic set (joined channels + DMs + servers). */
    fun setTopics(channelTopics: Set<String>) {
        // Our own user topic carries `sealed` (a DM / key is waiting), `ring`, device events.
        val topics = if (myUserId.isEmpty()) channelTopics else channelTopics + "user:$myUserId"
        val add = topics - wanted
        val remove = wanted - topics
        wanted = topics
        val s = ws ?: return
        add.forEach { s.send(JSONObject().put("type", "subscribe").put("topic", it).toString()) }
        remove.forEach { s.send(JSONObject().put("type", "unsubscribe").put("topic", it).toString()) }
    }

    /** "I'm typing" into [topic] (`channel:<id>` / `dm:<id>`); the caller paces it ([TypingState.mayAnnounce]). */
    fun sendTyping(topic: String) {
        if (topic.isEmpty() || topic !in wanted) return
        ws?.send(JSONObject().put("type", "typing").put("topic", topic).toString())
    }

    /** Push a status change through the socket (instant fan-out). */
    fun sendPresence(status: String) {
        announced = status
        announcedAt = clock()
        ws?.send(JSONObject().put("type", "presence").put("status", status).toString())
    }

    /** Not in front any more. The socket stays, so the host is told — once: it is the whole
     *  account's status, and another device of it may be in use. Nothing repeats it. */
    fun away() {
        if (announced != null && announced != "offline") sendPresence("offline")
        announced = null
    }

    /** The network changed or the app came back: don't wait out the backoff. */
    fun reconnectNow() {
        if (closedByUs || baseUrl.isEmpty()) return
        reconnectDelayMs = 1000
        if (ws == null) open()
    }

    /** [keepPresence]: the same skwod, out of reach for now — what was last seen stays. */
    fun disconnect(keepPresence: Boolean = false) {
        closedByUs = true
        ws?.close(1000, "bye"); ws = null
        connected.value = false
        if (!keepPresence) presence.value = PresenceBook()
    }

    /**
     * The workspace this socket served is no longer the one in use: close it and forget whose
     * it was — its address, its token, its user topic and every topic it had asked for. Nothing
     * of one skwod (an event, a subscription naming its channels) reaches the next one.
     */
    fun leave() {
        disconnect()
        baseUrl = ""; token = ""; myUserId = ""; wanted = emptySet()
    }

    private fun open() {
        ws?.close(1000, "rebind")
        // (`RawSink`: never to a retired or SUSPECT front.)
        if (!RawSink.allows(baseUrl)) return
        val url = baseUrl.trimEnd('/')
            .replaceFirst("http://", "ws://").replaceFirst("https://", "wss://") + "/api/ws"
        // Token in the Authorization header, NOT ?token= — query strings leak into proxy/server
        // access logs at rest even over wss.
        val req = try {
            Request.Builder().url(url).header("Authorization", "Bearer $token").build()
        } catch (_: Exception) { return }
        ws = http.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                reconnectDelayMs = 1000
                connected.value = true
                connectEpoch.value = connectEpoch.value + 1
                // Whatever was posted while the socket was down produced no event: look for it.
                model.launchIO { model.notifier.catchUp() }
                model.onRealtimeConnected()
                // The rosters come again with the subscriptions; nothing from before the gap is kept.
                voiceRoster.value = VoiceRoster()
                announced?.let { announcedAt = clock(); webSocket.send(JSONObject().put("type", "presence").put("status", it).toString()) }
                // The minute's heartbeat, here and not in the sync loop, where one slow pass could
                // outlast the host's 3-minute window and show a person in use offline.
                model.launchIO {
                    while (ws === webSocket) {
                        kotlinx.coroutines.delay(60_000)
                        if (ws === webSocket) announced?.takeIf { it != "offline" }?.let { sendPresence(it) }
                    }
                }
                wanted.forEach { webSocket.send(JSONObject().put("type", "subscribe").put("topic", it).toString()) }
            }

            // Only the socket that is up now speaks: one that was replaced (a rebind, a switch)
            // may still deliver what it had buffered.
            override fun onMessage(webSocket: WebSocket, text: String) { if (ws === webSocket) handle(text) }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                if (ws === webSocket) { ws = null; connected.value = false; scheduleReconnect() }
                // Refused as unauthenticated: the session may be over. Ask, rather than
                // reconnecting for ever and calling it "unreachable".
                if (response?.code == 401) model.checkSessionNow()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                if (ws === webSocket) { ws = null; connected.value = false; scheduleReconnect() }
            }
        })
    }

    private fun scheduleReconnect() {
        if (closedByUs) return
        val delay = reconnectDelayMs
        reconnectDelayMs = (reconnectDelayMs * 2).coerceAtMost(60_000)
        Thread {
            Thread.sleep(delay)
            if (!closedByUs && ws == null) open()
        }.start()
    }

    private fun handle(text: String) {
        val obj = try { JSONObject(text) } catch (_: Exception) { return }
        if (obj.optString("type") != "event") return
        val topic = obj.optString("topic")
        val payload = obj.optJSONObject("payload") ?: JSONObject()
        val event = obj.optString("event")
        // Only topics this socket asked for: a server cannot hand us events for anything else.
        if (!RealtimeRules.subscribed(topic, wanted)) return
        val mine = myUserId.isNotEmpty() && topic == "user:$myUserId"
        when (event) {
            "presence" -> {
                val uid = payload.optString("user_id"); val status = payload.optString("status")
                // Not for someone this account blocked.
                if (uid.isNotEmpty() && status.isNotEmpty() && !BlockList.contains(uid)) {
                    val now = clock()
                    seenPresence(uid, status, now)
                    val mine = announced
                    if (mine != null && PresenceAnnounce.corrects(uid, status, myUserId, mine, announcedAt, now)) sendPresence(mine)
                }
            }
            // A channel message of ANY kind (chat, like, comment, avatar, game move — the server
            // cannot tell). The open views refresh on it via [events]; whether it is announced is
            // decided by the notifier once it has been decrypted.
            "message" -> {
                val foreign = payload.optString("author_id") != myUserId
                val onScreen = appActive && topic == focusedTopic
                // Nothing from someone this account blocked is announced (the core would not show it).
                if (foreign && !onScreen && topic.startsWith("channel:") && !BlockList.contains(payload.optString("author_id"))) {
                    model.launchIO { model.notifier.channelMessage(topic.removePrefix("channel:"), payload.optString("message_id")) }
                }
            }
            // The SERVER says the channel was cleared. That is its word alone — nothing in the
            // event is signed by a member with the right to clear — so it never deletes the
            // decrypted history this device holds ([RealtimeRules.onChannelCleared]): the open
            // view only re-reads on the event below. Whether a clear is honoured is the core's
            // decision, on a clear it can verify.
            "channel_cleared" -> when (RealtimeRules.onChannelCleared()) { RealtimeRules.Local.REDRAW_ONLY -> {} }
            // Something is waiting in our sealed mailbox (a DM, keys): fetch + decrypt it now.
            "sealed" -> if (mine) model.syncInboxNow()
            "ring" -> if (mine) {
                val serverId = payload.optString("server_id")
                // A muted conversation does not silence calls; a muted skwod does.
                if (serverId.isNotEmpty() && model.callsRing()) {
                    val ring = Ring(serverId, payload.optString("channel_id"), payload.optString("from"),
                        payload.optString("ring_id"), payload.optLong("expires_at", 0))
                    model.launchIO { model.notifier.ring(ring) }
                }
            }
            // The caller hung up, or we answered on another device: stop ringing here.
            "ring_cancel" -> if (mine) model.notifier.ringCancelled(
                payload.optString("channel_id"), payload.optString("ring_id").ifEmpty { null }, payload.optString("server_id").ifEmpty { null })
            "link_request" -> if (mine) model.linkRequests.intValue = model.linkRequests.intValue + 1
            // Another session of this account was ended (a password change): is ours still good?
            "sessions_revoked" -> if (mine) model.checkSessionNow()
            // The server says the account's key backup was downloaded by a session that is not
            // one of its devices. Nothing in it can be checked: shown and logged as its word.
            "backup_fetched" -> if (mine) model.launchIO { model.backupFetched(payload.optLong("at", 0)) }
            // More than one install is waiting to restore the same device.
            "device_recovery_multiple" -> if (mine) model.launchIO { model.recoveryMultiple(payload.optLong("at", 0)) }
            // Someone asked to join a server I can approve people for.
            "join_request" -> if (mine) model.launchIO { model.joins.onJoinRequest(payload.optString("server_id"), payload.optInt("pending", 1)) }
            // My own request to join was answered.
            "join_approved" -> if (mine) model.launchIO { model.joins.onApproved(payload.optString("server_id")) }
            "join_denied" -> if (mine) model.launchIO { model.joins.onDenied(payload.optString("server_id")) }
            // The server's shape changed: new channels to list, a new member to hand keys to.
            "channels_changed" -> model.launchIO { model.chat.syncServerChannels() }
            // Who is in a voice room of this server: the whole roster of one room.
            "voice_state" -> voiceRoster.value.apply(topic, payload)?.let { voiceRoster.value = it }
            // A server I am in was deleted, or I was removed from one: only "go and check" —
            // the list of my servers is asked again and whatever is no longer in it leaves.
            "server_deleted", "revoke" -> if (mine) model.launchIO { model.refreshServerList() }
            "member_joined" -> model.launchIO { model.waiting.refresh(payload.optString("server_id")); model.refreshRoster() }
        }
        // Devices and recovery: every one of these is only a nudge. What actually happened is
        // read back from the server by the core, and shown as the notices it concludes.
        when (val action = AccountEvents.action(event, mine, payload.optString("user_id"), myUserId)) {
            AccountEvents.Action.None -> {}
            AccountEvents.Action.OwnAccount -> model.launchIO { model.account.accountChanged() }
            is AccountEvents.Action.PeerDeviceRemoved -> model.launchIO { model.account.contactDeviceRemoved(action.userId) }
        }
        events.tryEmit(RtEvent(topic, event, payload))
    }
}
