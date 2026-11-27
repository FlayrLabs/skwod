package io.skwod.app

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import uniffi.skwod_core.AuthSession
import uniffi.skwod_core.SkwodClient
import java.io.File
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * One connected self-hosted server, held as a fully isolated identity (own account/session, own
 * device keypair, own encrypted cache). Being in several = several independent identities.
 */
data class Workspace(
    /**
     * The skwod's STABLE address as persisted: `https://…` for a classic server, or
     * `skwod://join/<node id>` for a p2p host. Never a loopback proxy URL — that changes every
     * launch and is resolved at run time ([AppModel.baseUrl]).
     */
    val server: String,
    val userId: String,
    val token: String,
    val expiresAt: Long,
    val name: String,
    /**
     * Stable, immutable id — the cache/keys/kv key. Set once at creation and never recomputed, so
     * the address can change without orphaning any local data. For skwods joined after identity
     * pinning it's the server's instance id; for older ones it's the URL hash (backfilled on load).
     */
    val localId: String,
    /** The server's instance id (identity match key across address moves). */
    val instanceId: String? = null,
    /** The server's pinned Ed25519 signing key (base64) — verified on every address change. */
    val pinnedKey: String? = null,
    /**
     * The skwod's beacon pubkey (secp256k1 x-only hex) + content key (32-byte hex), from the invite.
     * Used to look up the CURRENT address on public Nostr relays (over Tor) when the cached one dies.
     * null for pre-beacon joins.
     */
    val beaconPubkey: String? = null,
    val beaconContentKey: String? = null,
    /** Signed `created_at` of the last beacon note we adopted — a rollback floor so a relay can't
     *  suppress the newest note and pin us to a stale (re-registered) address. */
    val beaconTimestamp: Long = 0,
    /** My public username on THIS skwod (each skwod is a separate account). Shown in the you-bar so
     *  it never has to fall back to the raw userId. */
    val username: String? = null,
    /** p2p hosts: the host's node id (z-base-32) — its address AND its pinned transport identity.
     *  null for classic https servers. */
    val nodeId: String? = null,
    /**
     * p2p hosts that also have a domain: its `https://` address — learned ONLY from the host's
     * signed address record, fetched over the pinned p2p connection. Never taken from an invite
     * (anyone can write a `?u=` into a link).
     */
    val fallbackUrl: String? = null,
    /** `ts` of the last signed address record accepted for this skwod (a rollback floor). */
    val addressTs: Long = 0,
    /**
     * When [token] was issued (sign-in, or the last rotation), in ms. 0 = stored by a build that
     * did not record it. A token about a week old is swapped for a fresh one at launch.
     */
    val tokenIssuedAt: Long = 0,
    /** The key a rotation of [token] was (or is about to be) asked with — stored BEFORE the request,
     *  dropped with the old token: with it a rotation whose answer was lost can be asked again. */
    val rotationKey: String? = null,
    /**
     * The USER signed out of this skwod on this device (as opposed to the server ending the
     * session). Its cache, cache key and this record stay — signing in again is the same device —
     * but it is not opened at launch: its messages stay locked until the password is given again.
     */
    val signedOutByUser: Boolean = false,
    /** The name the host set for this skwod (`GET /api/instance/name`), cleaned and accepted ([SkwodName]). */
    val instanceName: String? = null,
    /** [name] is the user's own name for this skwod on this device (wins over [instanceName]). */
    val nameSetByUser: Boolean = false,
) {
    /** The server ended this session (401): the token was dropped and the user must log in again. */
    val isSignedOut: Boolean get() = token.isEmpty()

    val isP2P: Boolean get() = nodeId != null

    /** This workspace's address in the shape the rest of the app passes around. */
    val address: SkwodAddress
        get() = if (nodeId != null) SkwodAddress.P2p(nodeId, fallbackUrl) else SkwodAddress.Https(server)

    /** The stable workspace id (cache/kv key). */
    val id: String get() = localId

    /**
     * Always re-derived from the address so a name persisted before the *.skwod.io / localhost
     * mapping existed (e.g. a bare "skwod.io") is corrected on display rather than shown stale.
     */
    val displayName: String get() = SkwodName.display(if (nameSetByUser) name else null, instanceName, defaultName(server))

    companion object {
        fun slug(server: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(server.toByteArray())
            return digest.take(8).joinToString("") { "%02x".format(it) }
        }

        fun defaultName(server: String): String {
            // A p2p address is a key, not a name.
            if (server.startsWith("skwod:")) return "My Skwod"
            return try {
                val host = URI(server).host ?: return "My Skwod"
                // Instances hosted through skwod's own tunnel (chat.skwod.io) or on localhost show as
                // "My skwod" rather than a bare domain that reads like the app itself.
                // localhost / *.local / skwod's own tunnel / a free *.trycloudflare.com quick tunnel all
                // lack a friendly name — show "My skwod" rather than a bare domain (the server name shows).
                if (host == "localhost" || host == "127.0.0.1" || host.endsWith(".local") || host == "skwod.io" ||
                    host.endsWith(".skwod.io") || host.endsWith(".trycloudflare.com"))
                    return "My Skwod"
                val parts = host.split(".")
                if (parts.size > 2) parts.takeLast(2).joinToString(".") else host
            } catch (_: Exception) { "My Skwod" }
        }
    }
}

/** A ringing call: which server's voice room, and who rang. */
data class IncomingCall(
    val serverId: String, val channelId: String, val callerName: String,
    /** The server's id for this ring (a `ring_cancel` names it); empty from an old server. */
    val ringId: String = "",
    /** Unix ms after which the ring is over (0 = not given). Never shown past it. */
    val expiresAt: Long = 0,
    /** The skwod (workspace) it rings on; empty = the active one. Switched to only on answer. */
    val workspaceId: String = "",
)

/** One account on the skwod, from the owner's `api/auth/users` listing. */
data class Account(val userId: String, val username: String, val isMember: Boolean)

/** A server member with live presence + role ids, from `api/servers/{id}/members`. */
data class PresenceMember(val userId: String, val username: String, val status: String, val roleIds: List<String>)

/**
 * App-wide state across one or more workspaces. skwod hosts nothing: each workspace is a friend's
 * self-hosted server. Secrets (tokens + per-workspace cache keys) live in EncryptedSharedPreferences;
 * each workspace's engine state lives in its own SQLCipher cache file, restored on activation.
 */
class AppModel private constructor(private val ctx: Context) {

    companion object {
        /** Where the engine points while a p2p host is unreachable: loopback, a port nothing
         *  listens on. Requests fail fast and nothing ever leaves the device. */
        private const val OFFLINE_BASE = "http://127.0.0.1:9/offline"
        /** How long launch waits for a p2p host before opening on the local cache. */
        private const val LAUNCH_DIAL_WAIT_MS = 4000L
        /** Mailbox safety sync while the realtime socket is up (events do the real work). */
        private const val INBOX_SAFETY_MS = 30_000L
        /** …and while it is down, or the last pass failed. */
        private const val INBOX_FALLBACK_MS = 10_000L

        @Volatile private var instance: AppModel? = null
        fun get(ctx: Context): AppModel =
            instance ?: synchronized(this) {
                instance ?: run {
                    // Arti (the beacon's Tor client, in Rust) resolves its state dirs from $HOME,
                    // which app processes don't have — point it at our cache dir BEFORE any FFI call
                    // or every beacon lookup dies on bootstrap.
                    try {
                        android.system.Os.setenv("SKWOD_TOR_DIR", ctx.applicationContext.cacheDir.absolutePath, true)
                    } catch (_: Exception) {}
                    AppModel(ctx.applicationContext).also { model ->
                        instance = model
                        // Daily update check for as long as the process lives (the connection
                        // service keeps it alive in the background). No scheduler dependency.
                        Updater.startAutomaticChecks(ctx.applicationContext)
                        // Foreground = an activity is visible. Registered here, not in the
                        // activity: after a reboot the process runs with only the connection
                        // service, and must know it is in the BACKGROUND so messages notify.
                        android.os.Handler(android.os.Looper.getMainLooper()).post {
                            androidx.lifecycle.ProcessLifecycleOwner.get().lifecycle.addObserver(
                                object : androidx.lifecycle.DefaultLifecycleObserver {
                                    override fun onStart(owner: androidx.lifecycle.LifecycleOwner) { model.onForeground() }
                                    override fun onStop(owner: androidx.lifecycle.LifecycleOwner) { model.onBackground() }
                                })
                        }
                    }
                }
            }
    }

    private val prefs by lazy {
        // Back the master key with StrongBox (a discrete secure element / Titan-M-class chip) when the
        // device has one, so the key can't be extracted even if the TEE is compromised. StrongBox is
        // absent on many devices and throws StrongBoxUnavailableException at use time, so we build a
        // StrongBox-backed key first and transparently fall back to the plain TEE-backed AES256_GCM key
        // if it can't be created — same at-rest scheme, just the strongest hardware the device offers.
        //
        // NOTE: we deliberately do NOT set setUserAuthenticationRequired(true) here. This master key
        // protects the tokens the always-on background sync loop (processControlInbox / presence
        // heartbeat) needs to read while the app is backgrounded and the device is locked; an
        // auth-bound key would make those reads fail whenever the screen is locked and silently break
        // presence + inbox delivery. Auth-binding would need a separately-keyed store for only the
        // most sensitive at-rest material that the background loop never touches — not retrofittable
        // without splitting the secrets store, so it's left as-is and tracked.
        val mk = try {
            MasterKey.Builder(ctx)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setRequestStrongBoxBacked(true)
                .build()
        } catch (_: Exception) {
            MasterKey.Builder(ctx).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        }
        EncryptedSharedPreferences.create(ctx, "skwod-secrets", mk,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }

    val settings: AppSettings get() = AppSettings.get(ctx)

    init { Sounds.warm(ctx) }   // so the first sound after start is not skipped as "not loaded"

    // ---- mutes: per conversation and per skwod, on this device only ----

    /** Bumped on every change, so lists redraw their muted marks. */
    val muteRevision = androidx.compose.runtime.mutableIntStateOf(0)
    private val muteLists = java.util.concurrent.ConcurrentHashMap<String, MuteList>()

    /** The current skwod's mutes. Kept with the other secrets (encrypted at rest, not backed up). */
    fun mutes(): MuteList {
        val id = current?.id ?: return MuteList()
        return muteLists.getOrPut(id) { MuteList.parse(try { prefs.getString(LocalData.mutesName(id), null) } catch (_: Exception) { null }) }
    }

    private fun storeMutes(list: MuteList) {
        val id = current?.id ?: return
        muteLists[id] = list
        try { prefs.edit().putString(LocalData.mutesName(id), list.toJson()).apply() } catch (_: Exception) {}
        muteRevision.intValue = muteRevision.intValue + 1
    }

    fun mute(key: String, duration: MuteList.Duration) = storeMutes(mutes().mute(key, duration, System.currentTimeMillis()))
    fun unmute(key: String) = storeMutes(mutes().unmute(key))
    /** Is exactly [key] (a conversation scope, or [MuteList.SKWOD]) muted? */
    fun muteHolds(key: String): Boolean = mutes().holds(key, System.currentTimeMillis())
    /** Is a message in [scope] muted (the conversation, or the whole skwod)? */
    fun isMuted(scope: String): Boolean = mutes().isMuted(scope, System.currentTimeMillis())
    fun callsRing(): Boolean = mutes().callsRing(System.currentTimeMillis())

    /** One of the app's own sounds ([Sounds]); whether to is the caller's decision ([AlertPolicy]). */
    fun playSound(which: Int) = Sounds.play(ctx, which)

    /** Changed only through [RecordBox]: one lock, on the list as it is. */
    private val records = RecordBox<Workspace>({ it.localId }, { SkwodName.revalidate(it) }, { list, durable -> writeWorkspaces(list, durable) })
    val workspaces: List<Workspace> get() = records.list
    /** Change fields of one record as it is now ([current] follows). */
    private fun patch(localId: String, durable: Boolean = false, only: (Workspace) -> Boolean = { true }, change: (Workspace) -> Workspace): Workspace? =
        records.patch(localId, durable, only, change)?.also { r -> if (current?.localId == localId) current = r }

    /**
     * The URL to talk to the active skwod on RIGHT NOW: the https address of a classic server, or
     * the loopback proxy of the live p2p session. null while a p2p host has not been reached yet
     * this launch. Never persisted, shown or logged.
     */
    val baseUrl: String? get() = endpoint()?.base

    /**
     * [baseUrl] together with the session token to present there, as ONE value that names its
     * workspace ([Endpoint]). Put up by [bind], taken down the moment the workspace changes —
     * so between "the workspace changed" and "its host was reached" there is no URL at all,
     * rather than the previous skwod's URL under the new skwod's token.
     */
    private val endpoints = EndpointSlot()

    /** The active workspace's live URL and its token, read together — what every request is built from. */
    fun endpoint(): Endpoint? = endpoints.of(current?.id)?.takeIf {
        // Build 51: the one sink — never a retired front, never one SUSPECT (back from the
        // background, not yet proved ours).
        RawSink.allows(it.base)
    }

    /** How the active skwod is being reached, for the indicator. */
    val connection: ConnectionQuality
        get() {
            val w = current ?: return ConnectionQuality.Connecting
            // Say what is actually true: with no network, or with requests failing, "connected"
            // would be a lie even though the transport still remembers its last path.
            if (!P2PManager.networkAvailable.value) return ConnectionQuality.NoNetwork
            val node = w.nodeId ?: return if (syncFailures.intValue >= 2) ConnectionQuality.Reconnecting else ConnectionQuality.Server
            val q = P2PManager.quality.value[w.id] ?: ConnectionQuality.Connecting
            return if (q.isUsable && syncFailures.intValue >= 2) ConnectionQuality.Reconnecting else q
        }

    /** Consecutive failed syncs with the active skwod (0 = the last one worked). */
    private val syncFailures = androidx.compose.runtime.mutableIntStateOf(0)

    /** An invite that arrived by deep link / QR / paste and is waiting to prefill the connect screen. */
    var pendingInvite by mutableStateOf<String?>(null)
    /** The username to prefill with [pendingInvite] when a skwod asks to be logged in to again. */
    var pendingLoginName by mutableStateOf<String?>(null)

    /**
     * The active skwod's host refuses this app's protocol ([SessionRefusal.Action.UPDATE_APP]):
     * a persistent banner with "Update Skwod" — never a sign-out. Cleared by the next good sync
     * and when the workspace changes.
     */
    var hostNewer by mutableStateOf<String?>(null)

    /** Show the banner; the dialog only the first time it comes up. */
    private fun raiseHostNewer(detail: String) {
        val first = hostNewer == null
        hostNewer = detail
        if (first) enqueueNotice(SecurityAlert("Update Skwod", updateRequiredText(detail)))
    }

    /** `localId:tokenIssuedAt` of the session already rebuilt once because the host refused its binding. */
    @Volatile private var rebindTried: String? = null
    /** The client for which an unbound, not-yet-a-device session was already sent to "set up this device". */
    @Volatile private var linkRoutedFor: SkwodClient? = null

    /** The text of a failure, for [SessionRefusal.decide]. */
    private fun errorText(e: Throwable): String = coreErrorDetail(e) ?: e.message.orEmpty()

    /**
     * A tile / row for [w] was tapped. The skwod already on screen is not torn down (no flash of
     * the login, no new engine); a skwod whose session is over opens its login and leaves the
     * active one running. Returns true when it switched.
     */
    suspend fun tapSkwod(w: Workspace): Boolean {
        val latest = workspaces.firstOrNull { it.localId == w.localId } ?: w
        return when (SkwodTap.outcome(latest, current, engineUp = client != null && !pinFailed)) {
            SkwodTap.Outcome.STAY -> false
            SkwodTap.Outcome.LOG_IN -> {
                pendingLoginName = latest.username
                pendingInvite = latest.server
                false
            }
            SkwodTap.Outcome.SWITCH -> { activate(latest); true }
        }
    }
    /**
     * Joins in progress for the active workspace: after signing up with an invite its code also
     * joins the invite's server, and a join that needs approval waits there — persisted, visible,
     * resumed on the next launch.
     */
    val joins: JoinFlow by lazy { JoinFlow(this) }

    /**
     * A join code that arrived in a tapped link (or a scanned code) for a skwod we are ALREADY
     * in, waiting for the user to say yes. A link is untrusted input: opening one never joins a
     * server (membership, key requests) by itself.
     */
    data class PendingJoin(val code: String, val skwodName: String, val workspaceId: String)
    var confirmJoin by mutableStateOf<PendingJoin?>(null)

    /**
     * An invite arrived from outside the app (already validated as an invite by the caller).
     * For a skwod we are in, it only ASKS (see [confirmJoin]); otherwise it prefills the connect
     * screen, where joining needs credentials and a tap.
     */
    fun handleIncomingLink(raw: String) {
        val parsed = try { InviteLink.parse(raw) } catch (_: InviteException) { return }
        val known = workspaceFor(parsed.address)
        val code = parsed.joinCode
        if (known != null && code != null) {
            confirmJoin = PendingJoin(code, known.displayName, known.id)
            return
        }
        pendingInvite = raw
    }

    /** The user confirmed the join a link asked for: switch to that skwod, then join with the code. */
    fun acceptPendingJoin() {
        val join = confirmJoin ?: return
        confirmJoin = null
        launchIO {
            val w = workspaces.firstOrNull { it.id == join.workspaceId } ?: return@launchIO
            if (current?.id != w.id) activate(w)
            if (current?.id == w.id && !pinFailed) joins.begin(join.code)
        }
    }
    /** The server whose voice room is ringing (set by a `ring` event), or null. */
    var incomingCall by mutableStateOf<IncomingCall?>(null)
    /** Set when the user answered a ring: MainScreen opens that server's call. */
    var answeredCallServer by mutableStateOf<String?>(null)
    /** Bumped when another device of this account asks to be linked (realtime `link_request`). */
    val linkRequests = androidx.compose.runtime.mutableIntStateOf(0)
    /** An account reset is waiting out its 7-day hold; drives the "Reset is waiting" dialog. */
    var resetPending by mutableStateOf<String?>(null)
    var current: Workspace? = null
        private set
    val client: SkwodClient? get() = binding.bound?.client
    /**
     * [client] together with the workspace whose cache it has open — put up in ONE step, only
     * once the client is ready ([bind]), and taken down before the client goes. Anything that
     * belongs to one workspace ([AppChat.store]) takes its client from here, never from
     * `client` + `current`, which change at different moments during a switch.
     */
    val bound: BoundClient<SkwodClient>? get() = binding.bound
    /** Where the client is put up ([bind], by turn) and taken down ([dropClient]). */
    private val binding = ClientBinding<SkwodClient>().also { b -> b.onChange = { clientTurn.intValue = b.bound?.turn ?: 0 } }
    /**
     * Build 51: the bind turn of the client that is up (0: none), as Compose state. An open
     * conversation is keyed on it: it reloads from (and catches up through) every new client —
     * one put up after it was opened (launch), or after a re-bind (a replaced p2p session).
     */
    val clientTurn = androidx.compose.runtime.mutableIntStateOf(0)
    /** Build 51: coalesces become-active / network-back / reconnected catch-ups ([CatchUpGate]). */
    private val catchUpGate = CatchUpGate()
    @Volatile private var lastChannelSweep: Long? = null
    @Volatile private var socketCameUpSinceSweep = true
    /** Close and forget the client; any [bind] still in flight is over and will assign nothing. */
    private fun dropClient() { binding.clear()?.let { try { it.close() } catch (_: Exception) {} } }
    var deviceId: String? = null
        private set

    /** Called by the device-link / reset flow once this device is registered. */
    fun deviceLinked(id: String) {
        deviceId = id; needsDeviceLink = false
        launchIO { deviceBecameActive() }
    }

    /** Persisted sidebar state (joined channels, DMs, selection) for the active workspace. */
    val chat: AppChat by lazy { AppChat(this) }

    /** Live WebSocket relay: instant presence + message notifications for the active workspace. */
    val realtime: Realtime by lazy { Realtime(this) }

    /**
     * Who is waiting to be let into each server of the active workspace (join requests + members
     * the core is holding) — the "Waiting to join" list and its badge.
     */
    val waiting: WaitingRoom by lazy { WaitingRoom(this) }

    /** E2EE avatars (profile pics, server icons, skwod icons) for the active workspace. */
    val avatars: AvatarStore by lazy { AvatarStore(this) }

    /** Long-lived scope for fire-and-forget engine writes (kv persistence, etc.). */
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    fun launchIO(block: suspend () -> Unit) { ioScope.launch { block() } }
    /** Like [launchIO], for work the caller may need to cancel. */
    fun launchJob(block: suspend () -> Unit): kotlinx.coroutines.Job = ioScope.launch { block() }

    /** Small secrets other parts of the app keep next to the tokens (encrypted at rest). */
    internal fun secretGet(key: String): String? = try { prefs.getString(key, null) } catch (_: Exception) { null }
    /**
     * STRICT read: THROWS when the encrypted store could not be read — null means only "nothing
     * stored". For anything that would otherwise be taken for empty and written back
     * (the contact book: it holds who the user verified).
     */
    internal fun secretRead(key: String): String? = prefs.getString(key, null)
    /** STRICT write: true only once the value is on disk (`commit`, not `apply`). */
    internal fun secretWrite(key: String, value: String): Boolean =
        try { prefs.edit().putString(key, value).commit() } catch (_: Exception) { false }
    internal fun secretPut(key: String, value: String?) {
        try { prefs.edit().apply { if (value == null) remove(key) else putString(key, value) }.apply() } catch (_: Exception) {}
    }

    /** Compatibility accessor for views that expect a session on the active workspace. */
    val session: AuthSession? get() = current?.let { AuthSession(it.userId, it.token, it.expiresAt) }

    /**
     * The cache file of [w]. The name is derived exactly as it always was — but only from a
     * plain id ([InstanceIds]): older builds used the server's instance id as the workspace id,
     * and an id with a path in it would open (or delete) another skwod's file. Throws otherwise;
     * [bind] then opens nothing and says so.
     */
    private fun cachePath(w: Workspace): String =
        File(ctx.filesDir, InstanceIds.cacheFileName(w.id) ?: throw IllegalStateException("workspace id is not a file name")).absolutePath

    /**
     * Per-workspace 32-byte cache key (64 hex), persisted encrypted — or null when the secure
     * store could not be READ right now. A failed read is never taken for "no key yet": minting
     * a new key then would orphan the encrypted cache, and with it this device's identity
     * ([CacheKeyPolicy]; the Apple app's `Keychain.cacheKeyHex` draws the same line). A key is
     * only used once it is known to be stored: one that was not written would lock the cache
     * out at the next launch.
     */
    private fun cacheKeyHex(w: Workspace): String? {
        val key = LocalData.cacheKeyName(w.id)
        val read = try {
            val store = prefs
            if (!store.contains(key)) CacheKeyPolicy.Read.Absent
            else store.getString(key, null)?.let { CacheKeyPolicy.Read.Stored(it) } ?: CacheKeyPolicy.Read.Unreadable
        } catch (_: Exception) { CacheKeyPolicy.Read.Unreadable }
        return when (val decision = CacheKeyPolicy.decide(read)) {
            is CacheKeyPolicy.Decision.Use -> decision.hex
            CacheKeyPolicy.Decision.Unavailable -> null
            CacheKeyPolicy.Decision.Mint -> try {
                val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
                val hex = bytes.joinToString("") { "%02x".format(it) }
                if (prefs.edit().putString(key, hex).commit() && prefs.getString(key, null) == hex) hex else null
            } catch (_: Exception) { null }
        }
    }

    /**
     * A security event the user must see: a contact's safety number changed, this device moved to
     * the Signal protocol, or the app/server need updating. Shown as a dialog at the root.
     */
    var securityNotice by mutableStateOf<Pair<String, String>?>(null)

    /** What the notice on screen lets the user do about it (null = just acknowledge). */
    var noticeAction by mutableStateOf<NoticeAction?>(null)

    /** Notices waiting behind the one on screen. EVERY notice is shown; none is dropped. */
    private val pendingNotices = ArrayDeque<SecurityAlert>()

    /** Show `alert` now, or queue it behind the notice already on screen. */
    @Synchronized
    fun enqueueNotice(alert: SecurityAlert) {
        if (securityNotice == (alert.title to alert.message) || pendingNotices.contains(alert)) return
        if (securityNotice == null) { securityNotice = alert.title to alert.message; noticeAction = alert.action }
        else pendingNotices.addLast(alert)
    }

    /** The user acknowledged the notice on screen: show the next one, if any. */
    @Synchronized
    fun dismissNotice() {
        val next = pendingNotices.removeFirstOrNull()
        securityNotice = next?.let { it.title to it.message }
        noticeAction = next?.action
    }

    /** The user chose the notice's action ("Accept devices"). */
    fun performNoticeAction() {
        val action = noticeAction
        dismissNotice()
        launchIO {
            val c = client ?: return@launchIO
            try {
                when (action) {
                    // Only the set the notice was raised for (audit L2): if more is listed
                    // since, nothing is accepted and the conversation's banner shows it.
                    is NoticeAction.AcceptDevices -> c.acceptIdentityChange(action.userId, "", action.shown)
                    is NoticeAction.RecoveryKey -> account.recoveryKeyPrompt = action.reason
                    null -> {}
                }
            } catch (_: Exception) {}
        }
    }

    /** A person's name for a notice: the DM name if we have one, else a short id. */
    private fun nameOf(userId: String): String {
        val claimed = chat.dms.firstOrNull { it.peerUserId == userId }?.name?.takeIf { it.isNotEmpty() }
        val shown = contacts.shown(userId, claimed)
        return if (shown.name == ContactTrust.UNKNOWN) "A member (${userId.take(6)}…)" else shown.label
    }

    /**
     * This account already has a device, so this one must be linked from it (or the account reset)
     * before it can do anything encrypted. Drives `DeviceLinkDialog`.
     */
    var needsDeviceLink by mutableStateOf(false)

    /**
     * Open the engine for `w`. `base` is the live URL, or null when a p2p host can't be reached
     * right now: the cache is still opened (history stays readable) against a dead loopback
     * address, nothing is registered, and [reconnectLoop] rebinds once the host answers.
     *
     * Returns false when a later bind (or a teardown) superseded this one while it was working:
     * its client was closed, nothing was assigned, and the caller stops too.
     */
    /**
     * [credential]: through a p2p front, what `sign_in` handed out — the client and every raw
     * request present ONLY that; the token never crosses loopback (nothing at all without one).
     */
    private suspend fun bind(w: Workspace, base: String?, credential: String? = null): Boolean {
        // Nothing at all to the offline base (nothing reachable is there to be told anything).
        val wire = if (base == null) "" else WireRule.of(isFront(base), credential, w.token) ?: ""
        dropClient()
        // This bind's turn: what it puts up is under `w.id`, the workspace THIS call was given,
        // and only if no later bind or teardown has started since.
        val turn = binding.begin()
        fun superseded(c: SkwodClient): Boolean {
            if (binding.isCurrent(turn)) return false
            try { c.close() } catch (_: Exception) {}
            return true
        }
        deviceId = null
        endpoints.put(w.id, base, wire)
        stopped = null; recoveryWaiting = false
        // No key, no cache — and without the cache nothing may be registered or sent. A key the
        // Keystore would not give us right now is NOT replaced by a new one.
        val keyHex = cacheKeyHex(w) ?: run {
            if (!binding.isCurrent(turn)) return false
            stopBind("Couldn't unlock this skwod's data",
                "Android's secure storage did not give Skwod the key to the encrypted data it keeps for ${w.displayName} on this phone, so nothing was opened or changed. Close Skwod and open it again; if this keeps happening, restart the phone.")
            return true
        }
        if (!binding.isCurrent(turn)) return false
        val c = SkwodClient(base ?: OFFLINE_BASE, wire)
        // A cache that will not open under its key is moved aside by the core (returns false).
        // One that could not be opened AT ALL (I/O, a lock) throws: then nothing may be
        // registered — a device made now would be forgotten at the next launch.
        try { c.attachCache(cachePath(w), keyHex) } catch (_: Exception) {
            if (superseded(c)) return false
            try { c.close() } catch (_: Exception) {}
            stopBind("Couldn't open this skwod's data",
                "Skwod could not open the encrypted data it keeps for ${w.displayName} on this phone, so nothing was set up or changed. Close Skwod and open it again; if this keeps happening, restart the phone.")
            return true
        }
        if (superseded(c)) return false
        try {
            val resetAt = c.cacheWasReset()
            if (resetAt != null && c.kvGet("cache.resetTold") != resetAt.toString()) {
                c.kvSet("cache.resetTold", resetAt.toString())
                if (binding.isCurrent(turn)) enqueueNotice(SecurityAlert("This device's data could not be read",
                    "The encrypted data Skwod kept for ${w.displayName} on this phone would not open, so it was set aside and this device starts again. Link it from another device or restore with your recovery key to get your messages back."))
            }
        } catch (_: Exception) {}
        // The invite pinned this server's identity key: the sealed-sender trust root is only
        // accepted if that key signed it (set before anything is sent or received).
        val pinned = w.pinnedKey
        if (pinned != null) {
            try { c.setPinnedServerKey(pinned) } catch (_: Exception) {
                // The pin could not be applied. Carrying on would mean accepting whatever key the
                // server presents (trust on first use) for a skwod we HAVE a pin for — so stop:
                // no device is registered, nothing is synced and nothing encrypted happens until
                // this is resolved. (Same as the Apple app.)
                if (superseded(c)) return false
                try { c.close() } catch (_: Exception) {}
                stopBind("Couldn't verify this skwod",
                    "The server identity saved for this skwod could not be loaded, so Skwod can't check that it is talking to the right server. Nothing was sent. Try again; if this keeps happening, leave this skwod and join again with a fresh invite.")
                return true
            }
        }
        if (superseded(c)) return false
        pinFailed = false
        // What this device calls itself (sealed to the account's own devices), before it registers.
        try { c.setDeviceLabel(DeviceLabel.suggested(android.os.Build.MODEL)) } catch (_: Exception) {}
        // Only now, and in one step, is this client up — as THIS workspace's ([bound]) — or not at all.
        // (On Android a client is only ever put up with its cache attached — every failure above stops the bind.)
        if (!binding.commit(turn, w.id, c, cacheOpen = c.cacheAttached())) { try { c.close() } catch (_: Exception) {}; return false }
        // The session is bound to this device before anything authenticated is asked of the
        // server and before the realtime socket opens (a build-45 server refuses an unbound
        // session). Offline / host not answering: retried by the sync loop and on reconnect.
        if (base != null && !w.isSignedOut) ensureSessionBound()
        if (!binding.isCurrent(turn)) return false
        // What this workspace's lists could not write while no client was up (a rebind).
        launchIO { chat.flushStore() }
        BlockList.adopt(this)
        // Fresh device — or one upgrading from the pre-libsignal protocol (builds ≤ 40), which
        // keeps its history + space keys but registers a brand-new identity. Never offline.
        routeDeviceState(registerIfNew = base != null && !w.isSignedOut)
        if (!binding.isCurrent(turn)) return false
        account.loadActivity()
        if (base != null) surfaceSecurityNotices()
        return binding.isCurrent(turn)
    }

    /** Stop binding: no engine, nothing registered, and the user is told why. */
    private fun stopBind(title: String, message: String) {
        dropClient(); deviceId = null; endpoints.clear(); pinFailed = true
        enqueueNotice(SecurityAlert(title, message))
    }

    /** This install was removed from the account, or stopped because the account was restored elsewhere. */
    var stopped by mutableStateOf<InstallRoute.Screen?>(null)
        private set
    /** A restore onto this install is waiting (an approval, the PIN, or the hold). */
    var recoveryWaiting by mutableStateOf(false)
        private set
    /** The core's word for where this install stands, as last read (for the DEBUG hooks). */
    @Volatile var lastDeviceState: String = ""
        private set

    /** Devices, the recovery key, restores and the security activity list of the active workspace. */
    val account: AccountFlows by lazy { AccountFlows(this) }

    /**
     * Read where this install stands with the account and show the matching screen. Called
     * after binding and after any typed failure (`DeviceRemoved`, `DeviceSuperseded`,
     * `RecoveryPending`). [registerIfNew]: an install with no device registers one — which is
     * also what tells us the account already has devices (`LinkRequired`).
     */
    suspend fun routeDeviceState(registerIfNew: Boolean = false) {
        val c = client ?: return
        val state = try { c.deviceState().name } catch (_: Exception) { return }
        lastDeviceState = state
        when (val screen = InstallRoute.forState(state)) {
            InstallRoute.Screen.APP -> {
                deviceId = try { c.currentDeviceId() } catch (_: Exception) { null }
                stopped = null; recoveryWaiting = false; needsDeviceLink = false
            }
            InstallRoute.Screen.REMOVED, InstallRoute.Screen.SUPERSEDED -> {
                deviceId = null; recoveryWaiting = false; needsDeviceLink = false
                stopped = screen
                // Nothing this install sends is accepted any more: stop asking.
                stopBackgroundSync(); realtime.disconnect()
            }
            InstallRoute.Screen.WAITING -> { deviceId = null; stopped = null; recoveryWaiting = true }
            InstallRoute.Screen.SET_UP -> {
                deviceId = null; stopped = null; recoveryWaiting = false
                if (!InstallRoute.mayRegister(cacheOpened = true, online = registerIfNew && baseUrl != null, screen = screen)) return
                try { deviceId = c.registerDevice() } catch (e: uniffi.skwod_core.CoreException.UpdateRequired) {
                    raiseHostNewer(e.detail)
                } catch (_: uniffi.skwod_core.CoreException.LinkRequired) {
                    // A session token alone can't add a device: link it, restore it, or reset.
                    needsDeviceLink = true
                } catch (e: uniffi.skwod_core.CoreException.ResetPending) {
                    resetPending = e.detail
                } catch (e: uniffi.skwod_core.CoreException.DeviceLimit) {
                    enqueueNotice(SecurityAlert("Too many devices", e.detail.ifEmpty {
                        "This account already has the most devices it can have. Remove one from another device (Profile → Encryption → Devices), then try again." }))
                } catch (_: Exception) {
                    // Offline, or the server is not answering: the next activate tries again.
                }
                if (deviceId != null) needsDeviceLink = false
            }
        }
    }

    /**
     * A typed failure from the core that means "this install is not the device any more" (or not
     * yet): re-read the state and show its screen. Returns true if [e] was one.
     */
    suspend fun routeIfDeviceError(e: Throwable): Boolean {
        if (!InstallRoute.isDeviceError(coreErrorKind(e))) return false
        routeDeviceState()
        return true
    }

    /** The client whose session `bindSession()` bound (once per client: later calls return at once in the core too). */
    @Volatile private var sessionBoundFor: SkwodClient? = null

    /**
     * Bind the active client's session to this device ([SkwodClient.bindSession]). True when it
     * is bound, or there is nothing to bind yet (not a device of the account: registering,
     * linking and restoring bind by themselves). `Superseded` / `DeviceRemoved` go to the
     * device-state screens; a transport error answers false and is retried later.
     */
    suspend fun ensureSessionBound(): Boolean {
        val c = client ?: return false
        if (baseUrl == null) return false
        if (sessionBoundFor === c) return true
        return try {
            val bound = withContext(Dispatchers.IO) { c.bindSession() }
            if (bound && client === c) sessionBoundFor = c
            true
        } catch (e: Exception) {
            routeIfDeviceError(e)
            false
        }
    }

    /**
     * The host answered "device bind required" ([SessionRefusal.Action.BIND_REQUIRED]). Never a
     * sign-out: bind the session; an install that is not a device of the account yet (a second
     * phone that just logged in) goes to "set up this device"; a session the core had already
     * bound is rebuilt on a fresh client ONCE. Returns true when that rebuild was started (the
     * calling sync loop stops: activating starts a new one).
     */
    private suspend fun recoverFromBindRefusal(c: SkwodClient): Boolean {
        val w = current ?: return false
        val bound = try { withContext(Dispatchers.IO) { c.bindSession() } }
            catch (e: kotlinx.coroutines.CancellationException) { throw e }
            catch (e: Exception) { routeIfDeviceError(e); return false }
        if (client !== c) return false
        if (!bound) {
            sessionBoundFor = null
            // Once per client, and not while a set-up / reset / restore is already on screen:
            // "Not now" stays "not now" until the skwod is opened again.
            if (linkRoutedFor !== c && !needsDeviceLink && resetPending == null && !recoveryWaiting) {
                linkRoutedFor = c
                routeDeviceState(registerIfNew = true)
            }
            return false
        }
        // Bound just now: the next pass asks again.
        if (sessionBoundFor !== c) { sessionBoundFor = c; return false }
        val key = "${w.localId}:${w.tokenIssuedAt}"
        if (rebindTried == key) return false
        rebindTried = key
        launchIO { current?.takeIf { it.localId == w.localId && !it.isSignedOut }?.let { activate(it) } }
        return true
    }

    /**
     * This install just became a working device (linked, restored, or reset): take its state,
     * start syncing again if that had stopped, and rebuild the sidebar from what came back.
     */
    suspend fun deviceBecameActive() {
        // The screen this is called from goes away in the middle of it (and its scope with it).
        launchJob { takeUpDevice() }.join()
    }

    private suspend fun takeUpDevice() {
        // Linking and restoring bind the session themselves; asking again is free and makes sure.
        ensureSessionBound()
        routeDeviceState()
        if (deviceId == null) return
        // A socket refused while the session was bound to nothing: open it again now.
        realtime.reconnectNow()
        resetPending = null; account.pinPrompt = null; needsDeviceLink = false
        val w = current ?: return
        if (syncJob == null && !w.isSignedOut) {
            startBackgroundSync()
            // Exactly this workspace's bound wire (never another's, never the token to a front).
            baseUrl?.let { b -> endpoints.of(w.id)?.takeIf { it.base == b }?.let { goLive(w, b, it.token) } }
        }
        // Only now can this device be handed keys: ask the account's other devices (and the
        // servers' owners) to provision it, so its servers and channels appear without a relaunch.
        chat.recoverMemberships(); refreshDmList(); joins.resume()
        account.accountChanged()
        account.maybePromptForRecoveryKey()
    }

    /**
     * The engine could not be bound for the active workspace ([client] is null): its pinned
     * server key could not be applied, the cache key could not be read, or the cache would not
     * open. Nothing reconnects or goes live until the workspace is activated again.
     */
    @Volatile var pinFailed = false
        private set

    private fun updateRequiredText(detail: String): String =
        "This Skwod and this app use different versions of the encryption protocol, so they can't talk to each other yet. Update Skwod on this phone, or ask your host to update the server.\n\n$detail"

    /**
     * Pull pending security notices out of the core and queue EVERY one of them for display
     * (never silent, never just the first). Notices about a contact are also written by the core
     * as a persistent system row in that contact's conversation.
     */
    /** Build 49: hand the contact book and the avatars to our other devices (sealed, core-limited).
     *  Bound to the skwod it started for: the same binding and client after every await. */
    suspend fun shareWithSiblings() {
        val asked = bound ?: return
        val c = asked.client
        val wid = asked.workspaceId
        fun still() = Asked.holds(asked, bound) && client === c && current?.id == wid
        avatars.loadIfNeeded()
        if (!still()) return
        contacts.siblingPayload(wid)?.let { book ->
            try { withContext(Dispatchers.IO) { c.shareWithSiblings("contacts.v1", book.toByteArray()) } } catch (_: Exception) {}
        }
        if (!still()) return
        val entries = avatars.siblingEntries(wid) ?: return
        val mine = current?.userId?.let { AvatarStore.userKey(it) }
        for (batch in SiblingRules.batches(entries, mine)) {
            if (!still()) return
            val body = org.json.JSONArray().apply { batch.forEach { e -> put(org.json.JSONObject().put("key", e.key).put("img", e.img ?: "").put("ts", e.ts)) } }.toString()
            try { withContext(Dispatchers.IO) { c.shareWithSiblings("avatars.v1", body.toByteArray()) } } catch (_: Exception) { return }
        }
    }

    /** What was asked of our other devices this launch: how often, and when last. */
    private val siblingRequests = java.util.concurrent.ConcurrentHashMap<String, Pair<Int, Long>>()

    /** Build 49: take what our other devices handed over — into the skwod it was taken for; a
     *  newly linked device asks until it has it ([SiblingRules.mayRequest]). */
    private suspend fun drainSiblings() {
        val asked = bound ?: return
        val c = asked.client
        val wid = asked.workspaceId
        fun still() = Asked.holds(asked, bound) && client === c && current?.id == wid
        val prefs = ctx.getSharedPreferences("skwod-b49", Context.MODE_PRIVATE)
        // (For THIS device of the account: one linked again starts over.)
        val answered = deviceId?.let { "answered-$wid-$it" }
        if (answered != null) {
            val now = android.os.SystemClock.elapsedRealtime()
            val before = siblingRequests[answered]
            if (SiblingRules.mayRequest(prefs.getBoolean(answered, false), before?.first ?: 0, before?.second, now)) {
                val sent = try { withContext(Dispatchers.IO) { c.requestSiblingState() } } catch (_: Exception) { 0u }
                if (sent > 0u && still()) siblingRequests[answered] = ((before?.first ?: 0) + 1) to now
            }
        }
        // This skwod's stores first: payloads are taken only once they can be merged.
        contacts.load()
        avatars.loadIfNeeded()
        if (!still()) return
        val payloads = try { withContext(Dispatchers.IO) { c.takeSiblingPayloads() } } catch (_: Exception) { emptyList() }
        if (!still()) return
        for (p in payloads) {
            // Our own account is ours: its avatar comes from our own device (no snapshot entry).
            val vouched = p.vouchedUsers.toSet() + listOfNotNull(current?.userId)
            val mismatched = p.mismatchedUsers.toSet()
            when (p.kind) {
                // Names at most KNOWN; the verifications were merged by the core — shown VERIFIED
                // where the core now says so (through the gated raise path).
                "contacts.v1" -> {
                    val book = SiblingBook.decode(String(p.body))
                    if (!contacts.mergeFromSibling(book, wid, vouched, mismatched)) continue
                    if (answered != null && SiblingRules.answers(book, p.vouchedUsers)) prefs.edit().putBoolean(answered, true).apply()
                    for (uid in book.filter { it.value.level == TrustLevel.VERIFIED && it.key in vouched && it.key !in mismatched }.keys.take(500)) {
                        val st = try { withContext(Dispatchers.IO) { c.contactStatus(uid) } } catch (_: Exception) { null } ?: continue
                        if (!still()) return
                        if (!st.verified || !contacts.setVerifiedFromSibling(uid, book[uid]?.name, wid)) continue
                        // Read again: an un-verify that happened meanwhile wins.
                        val again = try { withContext(Dispatchers.IO) { c.contactStatus(uid) } } catch (_: Exception) { null } ?: continue
                        if (!still()) return
                        contacts.noteStatusRead(wid, uid, again.verified)
                    }
                }
                "avatars.v1" -> {
                    val arr = try { org.json.JSONArray(String(p.body)) } catch (_: Exception) { continue }
                    val entries = (0 until minOf(arr.length(), 64)).mapNotNull { i ->
                        arr.optJSONObject(i)?.let { o -> SiblingRules.AvatarEntry(o.optString("key"), o.optString("img").ifEmpty { null }, o.optLong("ts")) }
                    }
                    avatars.mergeFromSibling(entries, wid, vouched, mismatched)
                }
            }
        }
    }

    suspend fun surfaceSecurityNotices() {
        val c = client ?: return
        val notices = try { c.takeSecurityNotices() } catch (_: Exception) { emptyList() }
        // A notice names a device by its id; the account's own devices have names.
        if (notices.any { it.deviceId.isNotEmpty() } && baseUrl != null) account.refreshDeviceNames()
        for (n in notices) {
            // Someone waiting to join is a list to work through, not an interruption: it shows in
            // the members view ("Waiting to join") with a badge on the members button.
            if (n.kind == "join_request") {
                n.serverId?.let { waiting.refresh(it) }
                continue
            }
            // A restore waiting for an answer is a sheet with a code and two buttons — never an
            // alert to tap away, and never answered by the app. It is still logged.
            if (n.kind == "recovery_requested") {
                account.noteRecoveryRequest(n.deviceId, n.requestId, n.fingerprint, n.atMs.toLong())
                continue
            }
            // Build 49: one of our own devices asks for what it is missing; or one was just linked.
            if (n.kind == "sibling_state_requested") { launchIO { shareWithSiblings() }; continue }
            if (n.kind == "device_linked") launchIO { shareWithSiblings(); avatars.resendMine() }
            var alert = SecurityNotices.alert(n.kind, n.userId, n.deviceId, n.wasVerified, n.serverId, ::nameOf,
                n.fingerprint, account::deviceLabel) ?: continue
            // "Accept" on this notice accepts the device set as it is NOW, when the notice is
            // raised — not whatever is listed by the time the button is tapped (audit L2).
            (alert.action as? NoticeAction.AcceptDevices)?.let { a ->
                val shown = try { c.contactStatus(a.userId).acceptFingerprint } catch (_: Exception) { "" }
                alert = alert.copy(action = a.copy(shown = shown))
            }
            enqueueNotice(alert)
            // …and kept: Profile → Encryption → Security activity.
            account.log(n.kind, alert.title, alert.message, n.atMs.toLong())
        }
        drainSiblings()
    }

    /**
     * The realtime `backup_fetched` event ([at] = the server's time, ms): a notice, kept in
     * Security activity. One per [at] (the socket may deliver an event twice across a reconnect).
     */
    suspend fun backupFetched(at: Long) {
        val c = client ?: return
        val stamp = if (at > 0) at else System.currentTimeMillis()
        val last = try { c.kvGet("security.backupFetchedAt")?.toLongOrNull() } catch (_: Exception) { null }
        if (BackupFetched.alreadySaid(last, at)) return
        if (at > 0) try { c.kvSet("security.backupFetchedAt", at.toString()) } catch (_: Exception) {}
        if (client !== c) return
        val alert = SecurityNotices.alert("backup_fetched", "", "", false, null, ::nameOf) ?: return
        enqueueNotice(alert)
        account.log("backup_fetched", alert.title, alert.message, stamp)
    }

    /**
     * The realtime `device_recovery_multiple` event (server L1): more than one install is waiting
     * to restore the same device. A notice, kept in Security activity. (The event is also an
     * own-account nudge — `AccountEvents` — so the device list is read again and every waiting
     * request gets its own prompt.)
     */
    suspend fun recoveryMultiple(at: Long) {
        val alert = SecurityNotices.alert("recovery_multiple", "", "", false, null, ::nameOf) ?: return
        enqueueNotice(alert)
        account.log("recovery_multiple", alert.title, alert.message, if (at > 0) at else System.currentTimeMillis())
    }

    private val restoreLock = kotlinx.coroutines.sync.Mutex()
    @Volatile private var restored = false
    /** The stored workspace list was read (so writing it back cannot drop a skwod we could not see). */
    @Volatile private var workspacesLoaded = false

    /**
     * Restore persisted workspaces and open the last-active one — once per process. The activity,
     * the foreground service and the boot receiver all call this; whoever is first does the work.
     * A host that is not answering does NOT block this: the app opens on its local cache.
     */
    suspend fun restoreOnce(): Boolean = restoreLock.withLock {
        if (restored) return@withLock workspaces.isNotEmpty()
        restored = true
        AttachmentService.purgeCache(ctx)          // decrypted copies never survive a launch
        Uploads.sweepStaging(ctx)                  // nor does a staged outgoing file a crash left behind
        val loaded = loadWorkspaces()
        if (loaded == null) {
            // The secure store could not be read. That is not "no skwods": try again at the
            // next call rather than showing a first-run screen that would overwrite the list.
            restored = false
            return@withLock false
        }
        // Two records for the same skwod and account (earlier builds could make one): keep the
        // one with a live session. Only the other RECORD goes — no cache file is deleted.
        // Only on proven identity (the host key, or the same https address): an instance id and
        // pinned key are what a host SAID when first pinned, and must never merge or drop a
        // record (security review, build 46).
        val merged = WorkspaceDedupe.merge(loaded, crossAddress = false)
        records.load(merged.kept); workspacesLoaded = true
        if (merged.dropped.isNotEmpty()) {
            prefs.getString("current", null)?.let { cur -> merged.replacedBy[cur]?.let { prefs.edit().putString("current", it).apply() } }
            records.edit { it }
        }
        // "Block screenshots" is on for a NEW install (no preference, no skwod yet) only.
        settings.decideScreenSecurity(hasWorkspace = workspaces.isNotEmpty())
        AppLock.start(settings)
        // A skwod the user signed out of stays on this device, locked: it is not opened here.
        val open = workspaces.filter { !it.signedOutByUser }
        if (open.isEmpty()) return@withLock false
        val target = open.firstOrNull { it.id == prefs.getString("current", null) } ?: open[0]
        activate(target, openLastChannel = true)   // launch → land on your last channel
        true
    }

    /** Resolve the URL for `w` right now: dial a p2p host by its key, or use the https address. */
    private suspend fun resolveBase(w: Workspace): String? {
        val node = w.nodeId ?: return w.server
        // The front dialed by the log-in screen becomes this workspace's (one per host+account).
        P2PManager.adopt(node, w.id)
        P2PManager.liveBase(w.id, node)?.let { live ->
            // SUSPECT (back from the background): proved ours — or moved — first; still suspect: none.
            if (!(try { uniffi.skwod_core.isFrontSuspect(live) } catch (_: Throwable) { true })) return live
            P2PManager.ensureFront(w.id, CallState.active.value)
            val again = P2PManager.liveBase(w.id, node) ?: return null
            return if (try { uniffi.skwod_core.isFrontSuspect(again) } catch (_: Throwable) { true }) null else again
        }
        // Opening the app must not wait on the host: give the dial a few seconds (the usual case
        // is well under that), then open on the local cache and let the dial finish in the
        // background — reconnectIfNeeded() binds the engine to the session once it is up.
        val dial = ioScope.async { try { P2PManager.connect(ctx, node, key = w.id) } catch (_: Exception) { null } }
        return kotlinx.coroutines.withTimeoutOrNull(LAUNCH_DIAL_WAIT_MS) { dial.await() }
    }

    /** `openLastChannel` = restore the last-viewed channel (app launch); false = land on the skwod
     *  overview (tapping a skwod tile to switch — the user explicitly wants the server list). */
    suspend fun activate(target: Workspace, openLastChannel: Boolean = false) {
        // (The stored record, never a copy from before something changed it.)
        var w = workspaces.firstOrNull { it.localId == target.localId } ?: target
        // The previous workspace's client goes BEFORE `current` changes: between here and
        // [bind] there is no client at all, rather than workspace A's client under B's name.
        if (current?.id != w.id) {
            // What the previous workspace's lists still have to write is written through ITS
            // client, while that client is still up — not dropped with it.
            chat.flushStore()
            dropClient()
            // …and its socket: no event of the skwod being left is handled under the next one.
            realtime.leave()
            // What one host said about this app's version says nothing about another's.
            hostNewer = null
            // A notice still waiting keeps its text, not its action ([NoticeRules.afterSwitch]).
            synchronized(this) {
                noticeAction = null
                val kept = NoticeRules.afterSwitch(pendingNotices.toList())
                pendingNotices.clear(); pendingNotices.addAll(kept)
            }
        }
        // In the same step as `current`: until [bind] has reached THIS workspace's host there
        // is no URL — never the previous skwod's, to which the new token would be sent.
        endpoints.clear()
        current = w
        prefs.edit().putString("current", w.id).apply()
        chat.reset()
        waiting.reset()
        joins.reset()
        notifier.reset()
        syncFailures.intValue = 0
        if (w.isSignedOut) {
            // The server ended this session earlier. Open the local cache (history stays
            // readable), talk to nobody, and ask the user to log in again.
            if (!bind(w, null)) return
            stopBackgroundSync(); realtime.disconnect()
            if (!pinFailed) chat.loadIfNeeded(openLastChannel)
            askToLogInAgain(w)
            ConnectionService.sync(ctx)
            return
        }
        var base = resolveBase(w)
        if (current?.id != w.id) return
        // Build 51: through a p2p front the stored token is SIGNED IN at every bind (also the
        // first bind after updating from 0.50: no new log-in); without a credential nothing is
        // bound to the front (offline; the sync loop dials again) — never the token itself.
        // A token about a week old is swapped for a fresh one BEFORE the engine is built on it.
        val armed = base?.let { arm(w.id, it) }
        if (current?.id != w.id) return
        if (armed != null) w = armed.workspace
        else {
            // Signed out or removed meanwhile; or no sign-in right now: offline.
            w = workspaces.firstOrNull { it.localId == w.localId && !it.isSignedOut } ?: return
            base = null
        }
        val credential = armed?.credential
        if (!bind(w, base, credential)) return
        val mine = binding.bound?.takeIf { it.workspaceId == w.id }
        canCreateServers = true; isInstanceOwner = false
        if (pinFailed || stopped != null) {
            // Stopped in bind(): no engine. Don't load, sync, dial or open the relay for this
            // skwod — the user has been told, and activating it again retries.
            stopBackgroundSync()
            realtime.disconnect()
            ConnectionService.sync(ctx)
            return
        }
        chat.loadIfNeeded(openLastChannel)
        startBackgroundSync()
        startNetworkMonitoring()
        // Still this workspace and still this bind (no newer bind or sign-out since).
        if (base != null && current?.id == w.id && mine != null && binding.bound === mine)
            goLive(w, base, WireRule.of(isFront(base), credential, w.token))
        ConnectionService.sync(ctx)
        ConnectionService.updateStatus(ctx, connection.title)
        if (base != null) launchIO { account.maybePromptForRecoveryKey() }
    }

    /**
     * (Only under [arm]'s lock.) Swap the stored session token for a fresh one when it is about a
     * week old ([SessionPolicy]); null: not done. Must run before `SkwodClient` is built: the old token keeps working for
     * only a few minutes afterwards. Any failure leaves the token as it is — if the session is
     * really over, the sync loop finds out from `sessionState()` and asks for a new login.
     */
    private suspend fun rotateIfDue(w: Workspace, base: String, credential: String?): Workspace? {
        val now = System.currentTimeMillis()
        if (w.isSignedOut || !SessionPolicy.shouldRotate(w.tokenIssuedAt, now)) return null
        // Through a front: rotated with the credential (the front injects the token).
        val presenting = WireRule.of(isFront(base), credential, w.token) ?: return null
        val same = { r: Workspace -> LiveRecordRule.stillValid(r.localId, r.isSignedOut, r.token, w.localId, w.token) }
        val flow = RotationFlow<Workspace, uniffi.skwod_core.AuthSession>(
            storeKey = {
                val key = liveRecord(w)?.rotationKey ?: uniffi.skwod_core.newRotationKey()
                patch(w.localId, durable = true, only = same) { it.copy(rotationKey = key) }?.rotationKey
            },
            ask = { key ->
                try { uniffi.skwod_core.rotateSession(base, presenting, key).takeIf { it.userId == w.userId && it.token.isNotEmpty() } }
                catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (_: Exception) { null }
            },
            // Signed out (or another token stored) meanwhile: never overwritten with this one.
            persist = { fresh -> patch(w.localId, durable = true, only = same) { it.copy(token = fresh.token, expiresAt = fresh.expiresAt, tokenIssuedAt = now, rotationKey = null) } },
            // Told with it: a cancelled bind must not leave the front on the old token.
            then = { r -> if (credential != null) try { P2PManager.session(w.id, w.nodeId)?.rotateToken(credential, r.token) } catch (_: Exception) {} },
        )
        return when (val out = flow.run()) {
            is RotationFlow.Outcome.Rotated -> { rotationRetries.remove(w.localId); out.record }
            RotationFlow.Outcome.NotDue -> null
            RotationFlow.Outcome.Again -> { rotateAgain(w.localId, w.id, base); null }
        }
    }
    private val rotationRetries = java.util.concurrent.ConcurrentHashMap<String, Int>()

    /** A rotation that did not come to its end is asked again, while the old token's grace runs. */
    private fun rotateAgain(localId: String, id: String, base: String) {
        val waits = longArrayOf(10_000, 30_000, 60_000)
        val n = rotationRetries[localId] ?: 0
        if (n >= waits.size) return
        rotationRetries[localId] = n + 1
        launchIO {
            kotlinx.coroutines.delay(waits[n])
            val before = workspaces.firstOrNull { it.localId == localId && it.rotationKey != null } ?: return@launchIO
            val armed = arm(id, base) ?: return@launchIO
            // (Through a front the credential stays; an https client holds the token itself.)
            if (armed.workspace.token != before.token && armed.credential == null && current?.localId == localId) activate(armed.workspace)
        }
    }

    /** Set while the active workspace's session is over and the user has not logged in again. */
    var signedOutOf by mutableStateOf<String?>(null)
        private set

    private fun askToLogInAgain(w: Workspace) {
        signedOutOf = w.id
        enqueueNotice(SecurityAlert("Signed out of ${w.displayName}",
            if (w.signedOutByUser) "You signed out of ${w.displayName} on this phone. Your messages and keys are still here, locked. Log in again with your password to carry on where you left off — no relinking."
            else "Your session on ${w.displayName} has ended — it expired, or it was signed out from another device. Log in again to keep chatting. The messages already on this phone are still here."))
        // Opens the connect form in Log in mode, prefilled with this skwod's address (and the
        // username). The cache, its key and the device stay: logging in again is the same device.
        pendingLoginName = w.username
        pendingInvite = w.server
    }

    /**
     * The server answered 401 for [w]: this is "signed out", not "unreachable". Drop the dead
     * token (and only this workspace's), stop syncing, and show the login.
     */
    /** "Set up this device again" on a superseded install: its session is refused, log in again. */
    fun endSupersededSession() {
        stopped = null
        current?.let { handleSignedOut(it) }
    }

    private fun handleSignedOut(w: Workspace) {
        if (current?.localId != w.localId || w.isSignedOut) return
        // (Only the session it was about: a token stored since is kept.)
        val cleared = patch(w.localId, only = { it.token == w.token && !it.isSignedOut }) { it.copy(token = "", expiresAt = 0, tokenIssuedAt = 0, rotationKey = null) } ?: return
        stopBackgroundSync()
        realtime.disconnect()
        secretPut(LocalData.routesName(w.id), null)
        // Its front injects nothing any more (re-armed only by a new sign-in).
        if (w.nodeId != null) P2PManager.session(w.id)?.let { s -> launchIO { try { s.clearSession(w.token) } catch (_: Exception) {} } }
        endpoints.clear()
        incomingCall = null; Notifications.cancelIncomingCall(ctx)
        askToLogInAgain(cleared)
        ConnectionService.updateStatus(ctx, "Signed out — log in again")
    }

    /**
     * Ask the server whether our session still stands, wherever the app would otherwise conclude
     * "unreachable". Returns true when the workspace was signed out (and handled).
     */
    private suspend fun signedOutCheck(workspace: Workspace? = current, asked: BoundClient<SkwodClient>? = binding.bound): Boolean {
        val w = workspace ?: return false
        val mine = asked ?: return false
        if (baseUrl == null || w.isSignedOut || mine.workspaceId != w.id) return false
        val confirmed = try { mine.client.sessionState() == uniffi.skwod_core.SessionState.SIGNED_OUT }
            catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (_: Exception) { return false }
        // About the session that is bound and stored NOW, or about nothing: the token is kept.
        if (!SignOutRule.mayEnd(confirmed, binding.bound === mine && current?.localId == w.localId, liveRecord(w) != null)) return false
        handleSignedOut(w)
        return true
    }

    /** The realtime socket was refused as unauthenticated. */
    fun checkSessionNow() { launchIO { signedOutCheck() } }

    /** The realtime socket is up (first connect, or back after a drop). */
    fun onRealtimeConnected() {
        launchIO {
            // Blocks first (one made on another device hides its subject here), then whatever
            // was queued while there was no connection, then unfinished uploads.
            BlockList.refresh(this)
            Outbox.flush(this)
            Uploads.resume(this)
            syncDmsNow()
            checkPendingRings()
            joins.resume()
        }
        // Build 51: every conversation, not only the open one, catches up after a gap.
        socketCameUpSinceSweep = true
        catchUp()
    }

    /** What a workspace presents now: its stored record and (through a front) its credential. */
    private class Armed(val workspace: Workspace, val credential: String?)
    private val arming = SerialByKey()

    /**
     * Sign the STORED record of [id] in to the front at [base] (nothing to do for an https server)
     * and, with [rotate], swap a token about a week old for a fresh one. One at a time per
     * workspace: overlapping activates, re-binds, ring checks and rotations see each other's
     * result. The fresh token is stored before anything else can fail. Null: signed out or
     * removed, or no sign-in right now — never a reason to drop the stored token.
     */
    private suspend fun arm(id: String, base: String, rotate: Boolean = true): Armed? = arming.run(id) {
        val front = isFront(base)
        val session = if (!front) null else {
            val w = workspaces.firstOrNull { it.id == id } ?: return@run null
            P2PManager.session(w.id, w.nodeId)?.takeIf { it.baseUrl() == base } ?: return@run null
        }
        ArmFlow<Workspace>(
            stored = { workspaces.firstOrNull { it.id == id && !it.isSignedOut } },
            isStored = { liveRecord(it) != null },
            signIn = { try { session?.signIn(it.token) } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (_: Exception) { null } },
            rotate = { w, c -> rotateIfDue(w, base, c) },
            rotateToken = { c, w -> try { session?.rotateToken(c, w.token) ?: false } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (_: Exception) { false } },
            clear = { kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { try { session?.clearCredential(it) } catch (_: Exception) {} } },
        ).run(front, rotate)?.let { (w, c) -> Armed(w, c) }
    }

    /** A front URL (or one shaped like it: fail closed). */
    private fun isFront(base: String): Boolean =
        try { uniffi.skwod_core.isFrontBase(base) || uniffi.skwod_core.isFrontSuspect(base) } catch (_: Throwable) { true }

    /** The live record of [w] — only if it is still signed in with the same token ([LiveRecordRule]). */
    private fun liveRecord(w: Workspace): Workspace? {
        val live = workspaces.firstOrNull { it.localId == w.localId }
        return live?.takeIf { LiveRecordRule.stillValid(it.localId, it.isSignedOut, it.token, w.localId, w.token) }
    }

    /** Everything that needs a reachable host: the live relay, avatars, permissions. [wire]: exactly
     *  what [bind] presents for [base] ([WireRule]) — none: the relay is not opened. */
    private fun goLive(w: Workspace, base: String, wire: String?) {
        signedOutOf = null
        launchIO { avatars.loadIfNeeded() }
        // Live relay: instant presence flips + message notifications for this workspace. Through
        // a front it presents the credential bind used, never the token; without one, nothing.
        if (wire.isNullOrEmpty()) realtime.disconnect(keepPresence = true)
        else realtime.configure(base, wire, w.userId, effectiveStatus())
        launchIO { refreshServerCreatePermission() }
        // Conversations of the ACCOUNT (also the ones started on another of our devices), then
        // whatever is waiting in the mailbox.
        launchIO { refreshRoster(); refreshDmList(); groups.refresh(); syncDmsNow(); reports.refresh() }
        launchIO { refreshServerList(); refreshInstanceName() }
        joins.resume()
    }

    /**
     * A p2p host that wasn't reachable when the workspace opened: keep trying, and rebind the
     * engine to the live session the moment it answers. Called from the sync loop and on
     * foreground / network changes.
     */
    private val reconnectLock = kotlinx.coroutines.sync.Mutex()
    @Volatile private var lastHealthProbeAt = 0L
    /** What a connection check came to. */
    private enum class Check { HEALTHY, REBOUND, BUSY_OR_FAILED }

    private val proofRetry = java.util.concurrent.atomic.AtomicBoolean(false)

    private suspend fun reconnectIfNeeded(urgent: Boolean = false): Check {
        if (pinFailed) return Check.BUSY_OR_FAILED
        val w = current ?: return Check.BUSY_OR_FAILED
        val node = w.nodeId ?: return if (endpoint() != null) Check.HEALTHY else Check.BUSY_OR_FAILED
        if (!reconnectLock.tryLock()) return Check.BUSY_OR_FAILED
        try {
            // (The raw binding: a SUSPECT front reads as no base for requests, but it is bound.)
            if (endpoints.of(w.id)?.base == null) { dialAndBind(w, node); return Check.REBOUND }
            // Build 51: is the front still usable? Checked now and then while in front, at once
            // when back in front / the network changed, and at once whatever the timer says when
            // its listener failed. A dead connection is replaced BEHIND the front (nothing to
            // re-bind); only a front that had to move is bound again.
            val now = System.currentTimeMillis()
            val proxyDead = try { P2PManager.session(w.id)?.proxyClosed() == true } catch (_: Exception) { true }
            val suspect = endpoint() == null
            if (!proxyDead && !suspect && !SessionHealthRule.due(lastHealthProbeAt, now, appForeground, urgent)) { P2PManager.refresh(w.id); return Check.HEALTHY }
            lastHealthProbeAt = now
            when (val outcome = P2PManager.checkHealth(w.id, urgent, callActive = CallState.active.value)) {
                is P2PManager.HealthOutcome.Moved -> {
                    return rebind(w, outcome.base)
                }
                P2PManager.HealthOutcome.Unchanged -> {
                    // Moved under another check (the foreground challenge): bind again.
                    val live = P2PManager.liveBase(w.id, node)
                    if (live != null && live != endpoints.of(w.id)?.base) return rebind(w, live)
                    // The front itself is gone (closed elsewhere, or another host now): dial and bind again.
                    if (live == null) {
                        RawSink.cancel(endpoints.of(w.id)?.base)
                        bind(w, null); dialAndBind(w, node)
                        return Check.REBOUND
                    }
                    return if (FrontProof.isHealthy(FrontProof.PROVED, endpoint() != null)) Check.HEALTHY else Check.BUSY_OR_FAILED
                }
                P2PManager.HealthOutcome.Unproved -> {
                    // Asked again soon (a re-key delayed by a call, a check that was running).
                    if (proofRetry.compareAndSet(false, true)) launchIO {
                        kotlinx.coroutines.delay(3000)
                        proofRetry.set(false)
                        if (appForeground || CallState.active.value) reconnectIfNeeded(urgent = true)
                    }
                    return Check.BUSY_OR_FAILED
                }
            }
        } finally { reconnectLock.unlock() }
    }

    /** (Under [reconnectLock].) The front is at [base] now: everything is bound to it again. */
    private suspend fun rebind(w: Workspace, base: String): Check {
        if (current?.id != w.id) return Check.BUSY_OR_FAILED
        // What is still in flight to the old URL is cut.
        RawSink.cancel(endpoints.of(w.id)?.base)
        realtime.disconnect()
        return if (armAndBind(w, base)) Check.REBOUND else Check.BUSY_OR_FAILED
    }

    private suspend fun armAndBind(w: Workspace, base: String): Boolean {
        val armed = arm(w.id, base)
        if (current?.id != w.id) return false
        if (armed == null) { if (liveRecord(w) != null) bind(w, null); return false }
        val live = armed.workspace
        if (!bind(live, base, armed.credential)) return false
        val mine = binding.bound?.takeIf { it.workspaceId == live.id }
        if (pinFailed || stopped != null) { stopBackgroundSync(); return false }
        if (current?.id != live.id || mine == null || binding.bound !== mine) return false
        // (The sync loop ends when it asks for a re-bind: it starts again on the new client.)
        startBackgroundSync()
        goLive(live, base, WireRule.of(isFront(base), armed.credential, live.token))
        return true
    }

    /** Dial the host and bind the client to the front (left on the offline base if it fails). */
    private suspend fun dialAndBind(w: Workspace, node: String) {
        val base = try { P2PManager.connect(ctx, node, retry = true, key = w.id) } catch (_: Exception) { null } ?: return
        if (current?.id != w.id || current?.isSignedOut != false) return
        armAndBind(w, base)
    }

    /** "Retry" on the "Host is offline" banner: dial now, not when the next pass would. */
    fun retryConnection() { launchIO { if (reconnectIfNeeded(urgent = true) == Check.HEALTHY) { ensureSessionBound(); realtime.reconnectNow() } else ensureSessionBound() } }

    /**
     * The relay setting changed: every connection is replaced under the new setting BEHIND its
     * front (turning relays off closes the relayed ones at once, in the core) — nothing is
     * re-bound; an offline workspace is dialed under the new setting.
     */
    suspend fun redial() {
        if (!P2PManager.applyRelaySetting(ctx)) {
            // Fail closed: nothing stays connected under a setting that could not be applied.
            realtime.disconnect()
            endpoints.clear()
            enqueueNotice(SecurityAlert("Disconnected",
                "Skwod couldn't confirm that relayed connections were closed, so it disconnected from every host. Close Skwod and open it again to reconnect without a relay."))
            return
        }
        if (baseUrl == null) reconnectIfNeeded(urgent = true) else realtime.reconnectNow()
        catchUp()
    }

    /** Wi-Fi ↔ cellular, airplane mode off, back from the background. */
    fun onNetworkChanged() {
        launchIO {
            P2PManager.networkChanged()
            val check = reconnectIfNeeded(urgent = true)
            ensureSessionBound()
            // Only a healthy front gets its socket re-opened here (a re-bind opened its own).
            if (check == Check.HEALTHY) realtime.reconnectNow()
            ConnectionService.updateStatus(ctx, connection.title)
            catchUp()
        }
    }

    /**
     * Build 51: bring every conversation up to date — the open one first (its screen refreshes
     * on [Realtime.catchUps]), then the mailbox (direct and group messages), then every other
     * joined channel through the core's cursor-based catch-up (cheap when nothing is new). Asked
     * for on become-active, network back and every (re)connect; coalesced ([CatchUpGate]), and
     * it stops at the first failure rather than wait out a timeout per channel.
     */
    fun catchUp() {
        if (!catchUpGate.request()) return
        launchIO {
            do {
                catchUpGate.waitTurn()
                catchUpOnce()
            } while (catchUpGate.finished())
        }
    }

    private suspend fun catchUpOnce() {
        val asked = bound ?: return
        val me = current?.userId ?: return
        realtime.catchUps.tryEmit(Unit)
        try { syncDmsNow() } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (_: Exception) {}
        chat.recoverIfNeeded()
        if (baseUrl == null || !connection.isUsable) return
        val now = System.currentTimeMillis()
        if (!CatchUpGate.sweepDue(lastChannelSweep, now, socketCameUpSinceSweep)) return
        lastChannelSweep = now; socketCameUpSinceSweep = false
        val open = (chat.selection as? SidebarItem.Space)?.space?.channelId?.takeIf { chat.chatPageVisible }
        val channels = (chat.spaces.map { it.channelId } + chat.feedChannelIds()).filter { it.isNotEmpty() && it != "demo" && it != open }.distinct()
        for (channelId in channels.take(40)) {
            if (bound !== asked) return
            try { withContext(Dispatchers.IO) { asked.client.fetchChannelMessages(channelId, me) } } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (_: Exception) { return }
            drainDmEvents()
        }
    }

    private fun startNetworkMonitoring() {
        // Build 51: a session whose loopback proxy failed for good is replaced at once.
        P2PManager.onProxyClosed = { key -> if (current?.id == key) launchIO { reconnectIfNeeded(urgent = true) } }
        P2PManager.routes = P2PManager.DirectRoutes({ id -> workspaces.any { it.id == id && !it.isSignedOut } }, ::secretGet, ::secretPut)
        P2PManager.startMonitoring(ctx) { onNetworkChanged() }
    }

    /** Local, on-device message notifications (decrypted here, never by a push service). */
    val notifier: MessageNotifier by lazy { MessageNotifier(this, ctx) }

    /** Check the mobile subscription via Play Billing (on-device). The chat server never sees payment. */
    fun entitlement(): Boolean = !BuildConfig.SKWOD_PAYWALL || PaywallGate.entitled(ctx)

    /** A blob-store client bound to the active workspace, or null if not signed in. */
    fun blobStore(): BlobStore? {
        val e = endpoint() ?: return null
        if (e.token.isEmpty()) return null
        return BlobStore(e.base, e.token)
    }

    /**
     * My presence status. Stored values match the server's accepted set exactly — online | idle |
     * dnd | offline — where "offline" is presented to the user as "Invisible" (same as iOS). Anything
     * else is coerced so a stale/unknown value can never make the heartbeat 400 and silently stop.
     */
    var myStatus: String
        get() = normalizeStatus(prefs.getString("myStatus", "online") ?: "online")
        set(v) {
            prefs.edit().putString("myStatus", normalizeStatus(v)).apply()
            launchIO { heartbeatPresence() }
        }

    private fun normalizeStatus(v: String): String =
        if (v in setOf("online", "idle", "dnd", "offline")) v else "offline"

    /**
     * Whether the app is currently in the foreground. When it stops being (user closed/backgrounded
     * the app), we say offline once ([Realtime.away]) instead of waiting out the server's 3-minute
     * stale window — so "I closed the app" reads as offline to everyone right away.
     */
    @Volatile var appForeground = false
        private set

    /** Called by the process lifecycle observer when the app enters the foreground / background. */
    fun onForeground() {
        AppLock.onForeground(settings, System.currentTimeMillis())
        // Suspect until proved ours (the health check below) — every front but the one carrying a
        // live call, which is challenged at once all the same (and is suspect if that fails).
        val audioLive = (ctx.getSystemService(Context.AUDIO_SERVICE) as? android.media.AudioManager)?.mode == android.media.AudioManager.MODE_IN_COMMUNICATION
        val exempt = ForegroundRule.exempt(CallState.workspace, CallState.active.value, audioLive)
        P2PManager.suspendAll(except = exempt)
        appForeground = true; realtime.appActive = true
        connectionWatch.wake()
        launchIO {
            // The exempt front first: challenged before anything is sent through it.
            if (exempt != null) P2PManager.ensureFront(exempt, callActive = true)
            heartbeatPresence()
            // Back in front: the network may have changed while we were away, so re-probe the path
            // and re-dial a host that was offline.
            onNetworkChanged()
        }
        ConnectionService.sync(ctx)
        launchIO { AttachmentService.expireCache(ctx) }
        launchIO { Updater.autoCheck(ctx, foreground = true) }
        // Opened (perhaps from a call or message notification): what is waiting, what is ringing.
        launchIO { syncDmsNow(); checkPendingRings() }
    }
    fun onBackground() {
        AppLock.onBackground(System.currentTimeMillis())
        // Build 51: the fronts are SUSPECT until proved ours on the way back.
        if (!CallState.active.value) P2PManager.suspendAll()
        appForeground = false; realtime.appActive = false
        notifier.markSeen()            // everything up to now was on screen or already announced
        realtime.away()
    }

    /** The status this device announces right now; null in the background ([PresenceAnnounce]). */
    private fun effectiveStatus(): String? = PresenceAnnounce.status(appForeground, myStatus)

    /** Say my current status: over the socket, or (without one) to the server's API. [periodic]:
     *  the once-a-minute repeat, which a live socket does by itself ([Realtime]). */
    suspend fun heartbeatPresence(periodic: Boolean = false) = withContext(Dispatchers.IO) {
        val status = (if (periodic) PresenceAnnounce.periodic(appForeground, myStatus) else effectiveStatus()) ?: return@withContext
        if (!periodic) realtime.sendPresence(status)
        if (realtime.connected.value) return@withContext
        // URL and token as one value of one workspace ([endpoint]) — never read separately.
        val e = endpoint() ?: return@withContext
        try {
            val c = java.net.URL("${e.base.trimEnd('/')}/api/profiles/me/status").openConnection() as java.net.HttpURLConnection
            c.requestMethod = "PUT"
            c.setRequestProperty("Authorization", "Bearer ${e.token}")
            c.setRequestProperty("Content-Type", "application/json")
            c.doOutput = true
            c.connectTimeout = 10000; c.readTimeout = 10000
            c.outputStream.use { it.write(JSONObject().put("status", status).toString().toByteArray()) }
            c.responseCode
        } catch (_: Exception) {}
    }

    /**
     * App-level background loop for the active workspace — the Android peer of iOS `startInboxSync`.
     * Runs regardless of which screen is shown (the old heartbeat lived in the you-bar composable and
     * DIED whenever the user opened a chat, so they'd read offline to everyone after 3 minutes). Each
     * ~5s it drains the E2EE control inbox (a host fulfilling members' provision requests, anyone
     * installing relayed sender keys) and every ~60s it heartbeats presence.
     */
    private var syncJob: kotlinx.coroutines.Job? = null
    private val rebindPacer = RebindPacer()
    private val connectionWatch = ConnectionWatch(ioScope)
    /** Relays are off and there has been no direct way to the host for a while ([DirectOnlyRule]). */
    var cannotReachDirectly by mutableStateOf(false)
        private set
    private val directOnly = DirectOnlyRule()
    private fun noteReachability() {
        val w = current?.takeIf { it.nodeId != null && !it.isSignedOut }
        cannotReachDirectly = directOnly.note(w?.id, connection.isUsable, !settings.publicFallback, System.currentTimeMillis())
    }

    /** "Turn on" in that notice (asked for, and confirmed). */
    fun useRelayWhenNeeded() {
        settings.publicFallback = true
        cannotReachDirectly = false
        launchIO { redial() }
    }
    private fun startBackgroundSync() {
        syncJob?.cancel()
        // The indicator and the reconnect run on their own ([ConnectionWatch]).
        connectionWatch.start({ appForeground }) { noteReachability(); if (current?.isSignedOut == false) reconnectIfNeeded() }
        syncJob = ioScope.launch {
            var tick = 0
            var failures = 0
            var lastStatus = ""
            var lastInbox = 0L
            while (true) {
                // One pass is one client, its bind and its workspace — taken together, here: what is
                // asked through it is applied to nothing else.
                val asked = binding.bound; val workspace = current?.takeIf { it.id == asked?.workspaceId }
                val c = asked?.client; val me = workspace?.userId
                if (c != null && me != null && !workspace.isSignedOut) {
                    // A bind that could not reach the server earlier is tried again here.
                    if (baseUrl != null && sessionBoundFor !== c) ensureSessionBound()
                    if (baseUrl != null) {
                        // The WebSocket (`sealed`) says when something is waiting, so this is
                        // only the safety net: every 30 s while the socket is up, faster while it
                        // is down or the last pass failed.
                        val now = System.currentTimeMillis()
                        val every = if (realtime.connected.value && failures == 0) INBOX_SAFETY_MS else INBOX_FALLBACK_MS
                        if (now - lastInbox >= every) {
                            lastInbox = now
                            try {
                                chat.ticket().let { t -> handleDmEvents(c.syncDms(), t) }
                                c.processControlInbox(me)
                                failures = 0; syncFailures.intValue = 0
                                rebindPacer.succeeded(workspace.id)
                                hostNewer = null
                                surfaceSecurityNotices()
                                drainDmEvents()
                            } catch (e: kotlinx.coroutines.CancellationException) { throw e
                            } catch (e: Exception) {
                                // (Superseded by another bind while it ran: that one's business.)
                                if (binding.bound !== asked && binding.bound != null) continue
                                // A refusal is sorted BEFORE anything is called "unreachable", and
                                // only a 401 on /api/auth/me ([signedOutCheck]) ends the session.
                                val action = SessionRefusal.decide(coreErrorKind(e), errorText(e),
                                    boundDevice = deviceId != null && sessionBoundFor === c,
                                    reboundAlready = rebindTried == current?.let { "${it.localId}:${it.tokenIssuedAt}" })
                                when (action) {
                                    // This install is not the device any more (removed, superseded)
                                    // or not yet (a restore is waiting): show that, not "unreachable".
                                    SessionRefusal.Action.DEVICE_STATE -> {
                                        routeDeviceState()
                                        if (stopped != null) return@launch
                                        kotlinx.coroutines.delay(5000); continue
                                    }
                                    SessionRefusal.Action.UPDATE_APP -> { failures = 0; raiseHostNewer(errorText(e)); continue }
                                    SessionRefusal.Action.BIND_REQUIRED -> {
                                        failures = 0
                                        if (recoverFromBindRefusal(c)) return@launch
                                        continue
                                    }
                                    SessionRefusal.Action.SIGNED_OUT, SessionRefusal.Action.TRANSIENT -> {}
                                }
                                // Before calling this "unreachable": did the server sign us out?
                                // (The host's confirmed 401 about the current token; anything else
                                // keeps the session.)
                                val ended = signedOutCheck(workspace, asked)
                                when (SyncFailureRule.step(ended, deviceStopped = false, signInReplaced = e is uniffi.skwod_core.CoreException.SignInReplaced)) {
                                    SyncFailureRule.Step.SIGNED_OUT -> return@launch
                                    // Local (nothing was sent): bind again — this workspace, if this
                                    // client is still the one bound. Backing off, capped.
                                    SyncFailureRule.Step.REBIND -> rebindPacer.next(workspace.id)?.let { wait ->
                                        launchIO {
                                            kotlinx.coroutines.delay(wait)
                                            if (binding.bound === asked && current?.id == workspace.id) liveRecord(workspace)?.let { activate(it) }
                                        }
                                        return@launch
                                    }
                                    else -> {}
                                }
                                // Classic https server unreachable — likely its (quick-tunnel) address
                                // moved. After a couple of misses, resolve the new address from the
                                // beacon (over Tor) and follow it, fingerprint-verified. A p2p address
                                // is a key and never moves: the transport re-dials by itself.
                                failures++
                                syncFailures.intValue = syncFailures.intValue + 1
                                if (failures >= 2) { failures = 0; if (current?.isP2P == false) tryBeaconRecovery() }
                            }
                        }
                        if (tick % 12 == 0) heartbeatPresence(periodic = true)
                        if (tick % 6 == 0) refreshPrimaryChannel()
                        if (tick % 12 == 6) checkAddressRecord()
                        // Seed everyone's presence app-wide (~30s) so every surface has dots (DM rows,
                        // members) even without an open members sheet or a live socket event.
                        if (tick % 6 == 3 && appForeground) pollPresence()
                    }
                    val status = connection.title
                    if (status != lastStatus) { lastStatus = status; ConnectionService.updateStatus(ctx, status) }
                    tick++
                }
                // In the background the WebSocket (`sealed` / `message` events) drives the work;
                // the poll is only a safety net, so it runs slowly to spare the battery.
                kotlinx.coroutines.delay(if (appForeground) 5000 else 30000)
            }
        }
    }
    private fun stopBackgroundSync() { syncJob?.cancel(); syncJob = null; connectionWatch.stop() }

    /** The realtime socket says something is waiting in our sealed mailbox: fetch it now. */
    fun syncInboxNow() {
        launchIO {
            val c = client ?: return@launchIO
            val me = current?.userId ?: return@launchIO
            if (baseUrl == null) return@launchIO
            try {
                chat.ticket().let { t -> handleDmEvents(c.syncDms(), t) }
                c.processControlInbox(me)
                surfaceSecurityNotices()
                drainDmEvents()
                chat.mailboxSynced()
            } catch (e: Exception) { routeIfDeviceError(e) }
        }
    }

    // ---- direct messages: incoming ones appear, own devices stay in sync ----

    /** Bumped whenever DMs landed in the cache, so an open conversation re-reads it. */
    val dmRevision = androidx.compose.runtime.mutableIntStateOf(0)

    /** Sync the sealed mailbox now and list / announce the DMs it brought. */
    suspend fun syncDmsNow() {
        val c = client ?: return
        if (baseUrl == null || current?.isSignedOut != false) return
        // What the server answers belongs to the workspace that is current NOW ([StoreTicket]).
        val ticket = chat.ticket()
        val events = try { c.syncDms() } catch (_: Exception) { return }
        handleDmEvents(events, ticket)
    }

    /**
     * DMs drained by some OTHER core call (`fetchChannelMessages`, `processControlInbox`, …):
     * no network. Call after those, or a DM that rode along would never be listed or announced.
     */
    suspend fun drainDmEvents() {
        val c = client ?: return
        val ticket = chat.ticket()
        val events = try { c.takeDmEvents() } catch (_: Exception) { return }
        handleDmEvents(events, ticket)
    }

    /**
     * For each DM that just landed: make sure it has an entry in the list (also for a
     * conversation this device never opened), then announce it unless it is a copy of something
     * we sent from another device. The entry is decided by the event's `peerUserId` — the
     * decrypted, authenticated other party — never by the server's participant list, and an
     * existing entry is never handed to a different peer ([AppChat.deliverDM]).
     *
     * [ticket] was taken BEFORE the client was asked. The whole batch is dropped unless the same
     * workspace, client and store are still current — a server that held its answer while the
     * user switched workspaces gets nothing filed or announced in the other one — and the batch
     * is decided in the captured store, checked again once it has been.
     */
    private suspend fun handleDmEvents(all: List<uniffi.skwod_core.DmEvent>, ticket: StoreTicket<SkwodClient>?) {
        // Reports ride the same mailbox and make no DM event: the owner's inbox re-reads its
        // (local) list after every sync.
        reports.refresh()
        if (all.isEmpty()) return
        // Nothing from (or with) someone this account blocked is listed or announced. The core
        // already leaves them out of what it reads back; an event is checked HERE, before
        // anything is shown, so a blocked person cannot reach the notification shade.
        val events = NotifyPolicy.withoutBlocked(all, { it.peerUserId }, ::isBlockedUser)
        if (events.isEmpty()) return
        if (ticket == null || !chat.holds(ticket)) return
        // Where each event belongs — and whether anything of it may be shown or announced — is
        // decided by the store, from what THIS device holds ([ConversationStore.sort]): nothing
        // before both stores are read; a group's event updates the GROUP (and only from one of
        // its stored members); an invitation shows no content; an ignored group nothing; and a
        // direct event counts only if the store ACCEPTED it for exactly that sender.
        val sorted = ticket.store.sort(events, { it.conversationId }, { it.peerUserId }, { it.fromSelf }, { it.isGroup }, { groups.hints(ticket.store) }) ?: return
        // "Still the workspace that was asked?" and everything that is then noted and announced
        // are ONE step ([AppChat.ifHolds]): a switch on another thread comes before it (nothing
        // happens) or after it — never between the check and the notification.
        chat.ifHolds(ticket) {
            if (sorted.grouped.isNotEmpty()) groups.touched(sorted.grouped.map { it.conversationId })
            for (id in sorted.invited.filter { it.kind == "message" && !it.fromSelf }.map { it.conversationId }.distinct()) notifier.groupInvitation(id)
            sorted.deliveries.forEach { chat.delivered(it) }
            // An edit, a delete or a reaction redraws the conversation; only a new message notifies.
            // Only what the store accepted is in these lists — never an event of an invitation, an
            // ignored group, an outsider, or a sender the conversation is not held with.
            val shown = sorted.grouped + sorted.direct
            notifier.dmEvents(shown.filter { it.kind == "message" })
            // Open conversations re-read only for something that is actually shown.
            if (shown.isNotEmpty()) dmRevision.intValue = dmRevision.intValue + 1
        }
    }

    /** Blocked, as far as this device knows — the app's list or the core's (no network). */
    fun isBlockedUser(userId: String?): Boolean {
        if (userId.isNullOrEmpty()) return false
        if (BlockList.contains(userId)) return true
        return try { client?.isBlocked(userId) ?: false } catch (_: Exception) { false }
    }

    /** Group conversations (3–10 people) of the active workspace. */
    val groups: GroupDms by lazy { GroupDms(this) }

    /** Reports that reached this device (the skwod owner's inbox). */
    val reports: ReportsInbox by lazy { ReportsInbox(this) }

    /**
     * The account's conversations as the server lists them — how a device learns of ones started
     * elsewhere. The list is routing metadata from an untrusted party:
     *
     * - a conversation with no messages on this device is not listed (that is what the empty
     *   key hand-off conversation with a host is);
     * - who it is with comes from the messages this device decrypted in it: each sender gets (or
     *   already has) their own entry;
     * - where only we have spoken, the row's peer is all there is: the entry is listed UNBOUND
     *   and unverified, and nothing the server says later rewrites an existing entry;
     * - the row's `peerUsername` is only ever recorded as a claim (UNVERIFIED).
     */
    suspend fun refreshDmList() {
        if (client == null || current?.userId == null || baseUrl == null) return
        // Does nothing until both conversation stores are read ([ConversationStore.refreshDmList]).
        val ticket = chat.ticket() ?: return
        val changed = ticket.store.refreshDmList()
        // The listing was this workspace's: nothing of it is noted in another one's book.
        chat.ifHolds(ticket) { changed.forEach { chat.delivered(it) } }
    }

    /** The contact book of the active workspace: whose names the user actually relies on. */
    val contacts: ContactBook by lazy { ContactBook(this) }

    private val rosterLock = kotlinx.coroutines.sync.Mutex()

    /**
     * Re-read who the ACCEPTED members of our servers are and hand them to the contact book's
     * collision set: listed by the server, not held by the core (`heldMembers`), not a pending
     * join request. Nobody else may wear one of these names unflagged — also the name of a
     * member the user has never messaged. A server whose list cannot be read keeps the roster
     * as it was (the set only ever shrinks on a successful read).
     */
    suspend fun refreshRoster() {
        val c = client ?: return
        if (baseUrl == null) return
        val wid = current?.id ?: return
        if (!rosterLock.tryLock()) return
        try {
            val servers = chat.spaces.map { it.serverId }.filter { it.isNotEmpty() && it != "demo" }.distinct()
            if (servers.isEmpty()) return
            val accepted = LinkedHashMap<String, String>()
            for (sid in servers) {
                val listed = try { c.listMembers(sid) } catch (_: Exception) { return }
                val held = (try { c.heldMembers(sid) } catch (_: Exception) { return }).toSet()
                // Only people allowed to approve get the request list; for everyone else it is
                // empty or refused, and pending requesters are not listed as members anyway.
                val pending = (try { c.listJoinRequests(sid).map { it.userId } } catch (_: Exception) { emptyList() }).toSet()
                for (m in listed) if (m.userId !in held && m.userId !in pending) accepted.putIfAbsent(m.userId, m.username)
            }
            if (current?.id == wid) contacts.setRoster(accepted)
        } finally { rosterLock.unlock() }
    }

    // ---- calls: which room is actually ringing ----

    /**
     * Ask EVERY signed-in skwod what is ringing for this account right now. One skwod ringing →
     * that call is presented (labelled with its skwod; the workspace is only switched if the
     * user answers). Several ringing at once → the user is asked "Who's calling?" — a
     * server-reported value such as `expires_at` never picks the call. A ring past its deadline
     * is dropped. (Android has no push wake: this runs at launch, when the app comes to the
     * front and whenever the realtime socket connects.)
     */
    suspend fun checkPendingRings() {
        // Never while a call is up, ringing, being chosen, or already answered.
        if (CallState.active.value || callOpening || incomingCall != null || answeredCallServer != null || ringChoices.isNotEmpty()) return
        val active = current
        val found = ArrayList<Pair<Workspace, Ring>>()
        for (w in workspaces.toList()) {
            if (w.isSignedOut) continue
            val rings = try {
                if (w.localId == active?.localId) {
                    if (baseUrl == null) continue
                    client?.pendingRings() ?: continue
                } else {
                    // Another skwod: a throwaway client on its session, only to ask. A p2p host
                    // is asked only if its session is already up (no dialing from here).
                    val base = (if (w.isP2P) P2PManager.liveBase(w.id) else w.server) ?: continue
                    // Through its own front: presenting only a credential.
                    val armed = arm(w.id, base, rotate = false) ?: continue
                    val presenting = WireRule.of(isFront(base), armed.credential, armed.workspace.token) ?: continue
                    val other = SkwodClient(base, presenting)
                    try { other.pendingRings() } finally { try { other.close() } catch (_: Exception) {} }
                }
            } catch (_: Exception) { continue }
            for (r in rings) found.add(w to Ring(r.serverId, r.channelId, r.fromUserId, r.ringId, r.expiresAt))
        }
        if (CallState.active.value || callOpening || incomingCall != null || answeredCallServer != null) return
        // A muted skwod does not ring — whichever skwod is on screen — and is no "choice" either.
        val audible = RingMute.audible(found) { callsRingOn(it) }
        when (val decision = RingPolicy.decide(audible, System.currentTimeMillis())) {
            is RingPolicy.Decision.None -> {}
            is RingPolicy.Decision.Single -> notifier.ring(decision.ring, decision.workspace)
            is RingPolicy.Decision.Ambiguous -> {
                ringChoices = decision.choices.map { (w, r) -> RingChoice(w.localId, w.displayName, r) }
                // Not in front: say so; the choice itself is made in the app.
                if (!appForeground) Notifications.message(ctx, "rings", "Skwod", "Calls are ringing on more than one Skwod. Open Skwod to choose.", NotifyPolicy.Text.FIXED)
                val shown = ringChoices
                kotlinx.coroutines.delay(Notifications.RING_TIMEOUT_MS)
                if (ringChoices === shown) ringChoices = emptyList()
            }
        }
    }

    /**
     * Does a call on [w] ring? Read from THAT skwod's mutes (the same stored list [mutes] reads
     * for the active one), not the active skwod's.
     */
    private fun callsRingOn(w: Workspace): Boolean {
        // Mutes that cannot be read count as NOT muted (and are not remembered as "none"): a
        // missed real call is worse than an extra ring ([RingMute]).
        val list = muteLists[w.id] ?: try { MuteList.parse(prefs.getString("mutes-${w.id}", null)).also { muteLists[w.id] = it } } catch (_: Exception) { null }
        return RingMute.rings(list, System.currentTimeMillis())
    }

    /**
     * True from the moment the user answers until the call screen closes. While it is set no
     * ring is presented and — above all — the workspace is never switched by a ring.
     */
    @Volatile var callOpening = false

    /** One of several skwods ringing at once, for the "Who's calling?" picker. */
    data class RingChoice(val workspaceId: String, val workspaceName: String, val ring: Ring)
    var ringChoices by mutableStateOf<List<RingChoice>>(emptyList())

    /** The user picked which skwod's call to take: that is an answer. */
    fun answerChoice(choice: RingChoice) {
        ringChoices = emptyList()
        answerIncoming(IncomingCall(choice.ring.serverId, choice.ring.channelId, choice.workspaceName, choice.ring.ringId, choice.ring.expiresAt, choice.workspaceId))
    }

    /**
     * The user answered [call]. If it rings on another skwod than the one on screen, switch to
     * that skwod FIRST and only then open the call — the workspace never changes once a call has
     * been answered.
     */
    fun answerIncoming(call: IncomingCall) {
        Notifications.cancelIncomingCall(ctx)
        incomingCall = null
        launchIO {
            if (CallState.active.value || callOpening || answeredCallServer != null) return@launchIO
            callOpening = true
            val target = call.workspaceId
            if (target.isNotEmpty() && target != current?.localId) {
                val w = workspaces.firstOrNull { it.localId == target && !it.isSignedOut } ?: run { callOpening = false; return@launchIO }
                activate(w)
                if (current?.localId != target || pinFailed) { callOpening = false; return@launchIO }
            }
            answeredCallServer = call.serverId
        }
    }

    /**
     * Out-of-band recovery for a classic https skwod whose cached address is dead: resolve its
     * CURRENT address from its beacon (public Nostr relays, over Tor so relays never learn who's
     * looking), then follow it through [reconnectIfKnown] — which still proves the new address
     * holds the pinned key, so a forged beacon note can't redirect us. No-op for p2p workspaces
     * and pre-beacon workspaces. Nothing here is logged.
     */
    private suspend fun tryBeaconRecovery() {
        val w = current ?: return
        val pub = w.beaconPubkey ?: return
        val ck = w.beaconContentKey ?: return
        val pinned = w.pinnedKey ?: return
        // The core enforces proof-of-possession IN CODE and rejects rolled-back notes older than the
        // last one we adopted, so a forged/suppressed beacon note can't redirect us.
        val res = try {
            uniffi.skwod_core.resolveBeaconVerified(pub, ck, pinned, w.beaconTimestamp.toULong(), emptyList())
        } catch (_: Exception) { null } ?: return
        if (res.address != w.server) {
            patch(w.localId) { it.copy(beaconTimestamp = res.createdAt.toLong()) }
            reconnectIfKnown(res.address)
        }
    }

    /** The URL to sign up / log in against for `address` (dials a p2p host by its key). */
    private suspend fun dial(address: SkwodAddress): String = when (address) {
        is SkwodAddress.Https -> address.url
        is SkwodAddress.P2p -> {
            // The Rust core owns the node-id encoding: refuse anything it would not dial.
            uniffi.skwod_core.p2pParseInvite(InviteLink.P2P_PREFIX + address.nodeId)
            P2PManager.connect(ctx, address.nodeId)
        }
    }

    /**
     * Ask the host whether an invite's code would still let someone in — with no account, before
     * the name/password screen. Throws when the host cannot be reached.
     */
    suspend fun checkInvite(address: SkwodAddress, joinCode: String): uniffi.skwod_core.InviteCheck =
        uniffi.skwod_core.checkInvite(dial(address), joinCode)

    suspend fun signUp(address: SkwodAddress, username: String, password: String, joinCode: String,
                       beaconPubkey: String? = null, beaconContentKey: String? = null): Boolean {
        val base = dial(address)
        val name = username.trim().lowercase()
        // Remembered BEFORE the account exists, so being killed between "signed up" and
        // "joined" does not lose the code: it is picked up at the next launch (or login).
        joins.remember(address.stored, name, joinCode)
        val s = try { uniffi.skwod_core.signup(base, username, password, joinCode) } catch (e: Exception) {
            // Refused outright (no account was made): nothing to resume. A timeout keeps it.
            val refused = (e as? uniffi.skwod_core.CoreException.Engine)?.detail?.let { d -> listOf("400", "403", "409", "429").any { d.contains(it) } } == true
            if (refused) joins.forgetUnbound(address.stored, name, joinCode)
            throw e
        }
        return adopt(s, address, base, beaconPubkey, beaconContentKey, name)
    }

    suspend fun logIn(address: SkwodAddress, username: String, password: String): Boolean {
        val base = dial(address)
        val s = uniffi.skwod_core.login(base, username, password)
        return adopt(s, address, base, username = username.trim().lowercase())
    }

    /**
     * The NEW device's QR pairing (build 48), between [pairingStart] and success or [pairingDrop].
     * No password at any point (docs/SECURITY.md "Adding a device by QR").
     */
    class PairingRun internal constructor(
        val offer: uniffi.skwod_core.PairingOffer,
        internal val address: SkwodAddress,
        internal val base: String,
        internal val localId: String,
        internal var client: uniffi.skwod_core.SkwodClient?,
    ) {
        /** Set once approved: the session the server issued, used by [pairingEnter]. */
        internal var paired: uniffi.skwod_core.PairedDevice? = null
    }

    /** One poll of a QR pairing on the new device. */
    sealed class PairStep {
        object Waiting : PairStep()
        data class Confirm(val emoji: String) : PairStep()
        /** Approved: say so (with the host's key) before [pairingEnter]. */
        object Approved : PairStep()
    }

    /**
     * Dial the host by its node id, set up this device's store under the workspace id it will
     * keep, and open a session-less pair request. Call only after the person said yes to "Join …
     * as …?". The emoji come from [pairingPoll] once the other device has seen this one.
     */
    suspend fun pairingStart(offer: uniffi.skwod_core.PairingOffer): PairingRun {
        if (!workspacesLoaded) {
            records.load(loadWorkspaces() ?: throw IllegalStateException("Couldn't read this phone's secure storage. Close Skwod and open it again."))
            workspacesLoaded = true
        }
        if (workspaces.any { it.nodeId == offer.nodeId && it.userId == offer.userId && !it.isSignedOut }) {
            throw IllegalStateException("This account is already on this device.")
        }
        RelayHints.set(offer.nodeId, offer.relayUrl)
        val address = SkwodAddress.P2p(offer.nodeId, null)
        val base = dial(address)
        val localId = workspaces.firstOrNull { it.nodeId == offer.nodeId && it.userId == offer.userId }?.localId
            ?: WorkspaceMatch.newLocalId(workspaces, address, offer.userId)
        val file = InstanceIds.cacheFileName(localId) ?: throw IllegalStateException("workspace id is not a file name")
        val probe = Workspace(address.stored, offer.userId, "", 0, "", localId = localId, nodeId = offer.nodeId)
        val key = cacheKeyHex(probe) ?: throw IllegalStateException("Skwod couldn't set up its encrypted storage. Try again.")
        val c = uniffi.skwod_core.SkwodClient(base, "")
        val run = PairingRun(offer, address, base, localId, c)
        try {
            c.attachCache(File(ctx.filesDir, file).absolutePath, key)
            uniffi.skwod_core.fetchServerIdentity(base).let { c.setPinnedServerKey(it.serverPublic) }
            c.pairBegin(offer, (System.currentTimeMillis() / 1000).toULong())
            return run
        } catch (e: Exception) {
            pairingDrop(run)
            throw e
        }
    }

    /** One poll: waiting, the emoji to show, or approved (this device is linked and registered). */
    suspend fun pairingPoll(run: PairingRun): PairStep {
        if (run.paired != null) return PairStep.Approved
        val c = run.client ?: return PairStep.Waiting
        return when (val p = try { c.pairPoll(run.offer) } catch (e: Exception) { pairingDrop(run); throw e }) {
            is uniffi.skwod_core.PairProgress.Waiting -> PairStep.Waiting
            is uniffi.skwod_core.PairProgress.Confirm -> PairStep.Confirm(p.emoji)
            is uniffi.skwod_core.PairProgress.Paired -> {
                run.client = null   // the pairing client lets go of the store; signing in opens it again
                run.paired = p.device
                PairStep.Approved
            }
        }
    }

    /** "Continue" after "Approved on your other device": sign in with the paired session. */
    suspend fun pairingEnter(run: PairingRun): Boolean {
        val paired = run.paired ?: return false
        return adopt(paired.session, run.address, run.base, username = run.offer.username, pairedLocalId = run.localId)
    }

    /** Remove what an unfinished pairing created (never a signed-out workspace's own store). */
    fun pairingDrop(run: PairingRun) {
        run.client = null
        run.paired = null
        if (workspaces.any { it.localId == run.localId }) return
        InstanceIds.cacheFileName(run.localId)?.let { name ->
            for (suffix in listOf("", "-wal", "-shm")) File(ctx.filesDir, name + suffix).delete()
        }
        try { prefs.edit().remove(LocalData.cacheKeyName(run.localId)).commit() } catch (_: Exception) {}
    }

    /** The workspace for a skwod we are already signed in to at `address`, if any. */
    /** Address match only (node id, or exact https URL) — the caller also checks the account. */
    fun workspaceFor(address: SkwodAddress): Workspace? = when (address) {
        is SkwodAddress.P2p -> workspaces.firstOrNull { it.nodeId == address.nodeId }
        is SkwodAddress.Https -> workspaces.firstOrNull { !it.isP2P && it.server == address.url }
    }

    private suspend fun adopt(s: AuthSession, address: SkwodAddress, base: String,
                              beaconPubkey: String? = null, beaconContentKey: String? = null,
                              username: String? = null, pairedLocalId: String? = null): Boolean {
        val stored = address.stored
        val nodeId = (address as? SkwodAddress.P2p)?.nodeId
        // The list is about to be written back: it must have been read first, or the skwods
        // this device is signed out of (and their keys' records) would be dropped.
        if (!workspacesLoaded) {
            records.load(loadWorkspaces() ?: throw IllegalStateException("Couldn't read this phone's secure storage. Close Skwod and open it again."))
            workspacesLoaded = true
        }
        // Pin the server's cryptographic identity. For a p2p host this is fetched THROUGH the
        // connection already authenticated by the node id, so it is the right host's key.
        val identity = try { uniffi.skwod_core.fetchServerIdentity(base) } catch (_: Exception) { null }
        // The instance id is the server's choice and is stored (and names avatars): always the
        // core's safe form (`safeInstanceId`, the same function the Apple app and the core use).
        val instanceId = identity?.let { uniffi.skwod_core.safeInstanceId(it.instanceId) }
        // Is this a skwod we already hold a workspace (cache + keys) for? Only on proof: the
        // iroh-authenticated node id for p2p, a pinned-key challenge for classic https. What the
        // server CLAIMS (its instance id) never selects a workspace — see WorkspaceMatch.
        // …and logging in through a skwod's OTHER address (p2p ↔ https) reuses its entry only when
        // that address proves the entry's pinned key; unproven is refused, never a second entry
        // (the same skwod showed up twice, one of them dead). See [LoginReuse].
        val decision = LoginReuse.decide(workspaces, address, s.userId, instanceId) { pinned ->
            uniffi.skwod_core.verifyServerIdentity(base, pinned)
        }
        if (decision is LoginReuse.Decision.Refuse) throw SkwodIdentityException(LoginReuse.REFUSED)
        val existing = (decision as? LoginReuse.Decision.Reuse)?.existing
        // A p2p skwod logged into through its https address keeps its p2p address (the key is its identity).
        val keepsP2p = (decision as? LoginReuse.Decision.Reuse)?.keepsP2p == true
        val localId = existing?.localId ?: pairedLocalId ?: WorkspaceMatch.newLocalId(workspaces, address, s.userId)
        val w = Workspace(if (keepsP2p) existing!!.server else stored, s.userId, s.token, s.expiresAt,
            existing?.name ?: Workspace.defaultName(stored),
            localId = localId, instanceId = existing?.instanceId ?: instanceId,
            // A key that was pinned stays pinned; a first join pins what the authenticated host presents.
            pinnedKey = existing?.pinnedKey ?: identity?.serverPublic,
            beaconPubkey = beaconPubkey ?: existing?.beaconPubkey,
            beaconContentKey = beaconContentKey ?: existing?.beaconContentKey,
            username = username ?: existing?.username,
            nodeId = if (keepsP2p) existing!!.nodeId else nodeId,
            // Never from the invite's `?u=`: only what the host's signed record told us earlier.
            fallbackUrl = existing?.fallbackUrl,
            addressTs = existing?.addressTs ?: 0,
            tokenIssuedAt = System.currentTimeMillis(),
            instanceName = existing?.instanceName,
            nameSetByUser = existing?.nameSetByUser ?: false)
        // One entry per skwod and account: an older dead record of this same skwod goes with it.
        records.edit { all -> WorkspaceDedupe.merge(all.filter { it.localId != localId } + w, crossAddress = false).kept }
        // A join started before this account existed on this device now belongs to it.
        joins.bind(stored, w.username, localId)
        rememberServer(stored, w.displayName)   // address only (no secrets), survives sign-out
        activate(w)
        return true
    }

    // --- Known servers: addresses (NO credentials/tokens/keys) the user has signed into, kept
    //     across sign-out so the login screen can offer a one-tap log back in. Not sensitive, so
    //     stored in a plain SharedPreferences, not the encrypted secrets store.
    private val knownPrefs by lazy { ctx.getSharedPreferences("skwod-known-servers", Context.MODE_PRIVATE) }

    /** (address, name) pairs, most-recent first. */
    fun knownServers(): List<Pair<String, String>> = try {
        val arr = org.json.JSONArray(knownPrefs.getString("list", "[]"))
        (0 until arr.length()).map { val o = arr.getJSONObject(it); o.getString("address") to o.getString("name") }
    } catch (_: Exception) { emptyList() }

    private fun rememberServer(address: String, name: String) {
        val addr = address.trim(); if (addr.isEmpty()) return
        val list = knownServers().filter { it.first != addr }.toMutableList()
        list.add(0, addr to name)
        val arr = org.json.JSONArray()
        list.take(10).forEach { arr.put(JSONObject().put("address", it.first).put("name", it.second)) }
        knownPrefs.edit().putString("list", arr.toString()).apply()
    }

    /** Background refresh of avatars broadcast to this skwod's first channel. */
    private suspend fun refreshPrimaryChannel() {
        val c = client ?: return
        val me = current?.userId ?: return
        val space = chat.spaces.firstOrNull() ?: return
        val asked = bound ?: return
        val msgs = try { c.fetchChannelMessages(space.channelId, me) } catch (_: Exception) { return }
        val authority = avatars.authority(space.serverId)
        // What was fetched is the workspace's that was asked: after a switch it is dropped, not
        // filed in the other one's avatar store.
        if (bound !== asked) return
        avatars.ingest(msgs, authority)
    }

    /**
     * Address moves. A new address for a skwod we already belong to is accepted ONLY as a record
     * signed by the instance key we pinned, with a timestamp newer than the last one we accepted
     * (`fetchAddressRecord` checks both) — never from a channel message, whoever wrote it, and
     * never from an invite. It is fetched from the server we are connected to right now.
     *
     * - Classic https skwod: follow it through [reconnectIfKnown], which still makes the NEW
     *   address prove the pinned key (bound to that address) before any token is sent there.
     * - p2p skwod: the record names the host's https address. It is only remembered (for the
     *   share link); a key never moves, and this app does not switch a p2p skwod to https.
     */
    private suspend fun checkAddressRecord() {
        val w = current ?: return
        val base = baseUrl ?: return
        val pinned = w.pinnedKey ?: return
        val rec = try { uniffi.skwod_core.fetchAddressRecord(base, pinned, w.addressTs) } catch (_: Exception) { null } ?: return
        // (Into the record as it is now; only if it is still the one that was asked, at that base.)
        if (current?.localId != w.localId || baseUrl != base) return
        patch(w.localId, only = { !it.isSignedOut }) { if (it.isP2P) it.copy(addressTs = rec.ts, fallbackUrl = rec.address) else it.copy(addressTs = rec.ts) } ?: return
        if (!w.isP2P && rec.address != w.server) reconnectIfKnown(rec.address)
    }

    /** The display name of a known skwod at `address` — ONLY after proving the address holds that
     *  skwod's pinned key. instanceId alone is public and an impostor can echo it, so matching on it
     *  would let an attacker render a trusted "it just moved" cue; PoP makes the cue trustworthy. */
    suspend fun knownSkwodName(address: String): String? {
        if (!address.startsWith("https://")) return null
        val identity = try { uniffi.skwod_core.fetchServerIdentity(address) } catch (_: Exception) { return null }
        // (A skwod we were signed out of has no session to reconnect with: it needs a login.)
        val known = workspaces.firstOrNull { !it.isP2P && !it.isSignedOut && it.instanceId != null && it.instanceId == identity.instanceId } ?: return null
        val pinned = known.pinnedKey ?: return null
        val proven = try { uniffi.skwod_core.verifyServerIdentity(address, pinned) } catch (_: Exception) { false }
        return if (proven) known.displayName else null
    }

    /** True if `address` presents the instanceId of a skwod you're in but FAILS its pinned-key
     *  proof — an impostor. Used to refuse sending credentials to a spoofed address. */
    suspend fun impersonatesKnownSkwod(address: String): Boolean {
        if (!address.startsWith("https://")) return false
        val identity = try { uniffi.skwod_core.fetchServerIdentity(address) } catch (_: Exception) { return false }
        val known = workspaces.firstOrNull { !it.isP2P && it.instanceId != null && it.instanceId == identity.instanceId } ?: return false
        val pinned = known.pinnedKey ?: return false
        return try { !uniffi.skwod_core.verifyServerIdentity(address, pinned) } catch (_: Exception) { true }
    }

    /**
     * Reconnect to a skwod you're ALREADY in that has moved to `newServer` — no re-login. Returns
     * true only if `newServer` proves it holds the pinned key of a known skwod (so a fake "reconnect
     * here" link pointing at an impostor is rejected). Keeps the same account, cache, and keys.
     */
    suspend fun reconnectIfKnown(newServer: String): Boolean {
        if (!newServer.startsWith("https://")) return false   // classic servers only; a p2p key never moves
        val identity = try { uniffi.skwod_core.fetchServerIdentity(newServer) } catch (_: Exception) { return false }
        val known = workspaces.firstOrNull { !it.isP2P && it.instanceId != null && it.instanceId == identity.instanceId } ?: return false
        // Signed out there: there is no session to reconnect with — the user has to log in.
        if (known.isSignedOut) return false
        val pinned = known.pinnedKey ?: return false
        val proven = try { uniffi.skwod_core.verifyServerIdentity(newServer, pinned) } catch (_: Exception) { false }
        if (!proven) return false
        // (Only the address, into the record as it is now: the same session continues there.)
        val moved = patch(known.localId, only = { !it.isP2P && !it.isSignedOut && it.pinnedKey == pinned }) { it.copy(server = newServer) } ?: return false
        activate(moved)
        return true
    }

    // ---- authed HTTP to the active workspace's server (for endpoints not on the E2EE FFI) ----

    /** GET `path`, returning the body on 200 or null otherwise. */
    suspend fun httpGet(path: String): String? = withContext(Dispatchers.IO) {
        val e = endpoint() ?: return@withContext null
        try {
            val c = java.net.URL("${e.base.trimEnd('/')}/$path").openConnection() as java.net.HttpURLConnection
            c.setRequestProperty("Authorization", "Bearer ${e.token}")
            c.connectTimeout = 10000; c.readTimeout = 10000
            if (c.responseCode != 200) null else c.inputStream.bufferedReader().use { it.readText() }
        } catch (_: Exception) { null }
    }

    /** Send a body-less request (PUT/DELETE), returning the HTTP status code (0 on failure). */
    suspend fun httpSend(path: String, method: String, jsonBody: String? = null): Int = withContext(Dispatchers.IO) {
        val e = endpoint() ?: return@withContext 0
        try {
            val c = java.net.URL("${e.base.trimEnd('/')}/$path").openConnection() as java.net.HttpURLConnection
            c.requestMethod = method
            if (jsonBody != null) {
                c.setRequestProperty("Content-Type", "application/json")
                c.doOutput = true
            }
            c.setRequestProperty("Authorization", "Bearer ${e.token}")
            c.connectTimeout = 10000; c.readTimeout = 10000
            if (jsonBody != null) c.outputStream.use { it.write(jsonBody.toByteArray()) }
            c.responseCode
        } catch (_: Exception) { 0 }
    }

    // ---- server-creation permission (host-only + grantable) ----

    /** Whether I may create servers in this skwod. Defaults open until checked (open instances). */
    var canCreateServers by mutableStateOf(true)
        private set
    /** Whether I am this skwod's instance owner (the host) — gates owner-only management UI. */
    var isInstanceOwner by mutableStateOf(false)
        private set

    suspend fun refreshServerCreatePermission() {
        val body = httpGet("api/instance/can-create-servers") ?: return
        try {
            val o = JSONObject(body)
            canCreateServers = o.optBoolean("can_create", true)
            isInstanceOwner = o.optBoolean("is_owner", false)
        } catch (_: Exception) {}
    }

    /** Owner-only: accounts granted server-creation. Returns list of (userId, username) or null. */
    suspend fun listServerCreators(): List<Pair<String, String>>? {
        val body = httpGet("api/instance/server-creators") ?: return null
        return try {
            val arr = JSONObject(body).getJSONArray("creators")
            (0 until arr.length()).map { val o = arr.getJSONObject(it); o.getString("user_id") to o.getString("username") }
        } catch (_: Exception) { null }
    }

    suspend fun grantServerCreator(userId: String): Boolean = httpSend("api/instance/server-creators/$userId", "PUT") == 200
    suspend fun revokeServerCreator(userId: String): Boolean = httpSend("api/instance/server-creators/$userId", "DELETE") == 200

    // ---- account moderation (owner sees/deletes accounts; anyone self-deletes) ----

    /** Owner-only: every account on this skwod, or null if not the owner. */
    suspend fun listAccounts(): List<Account>? {
        val body = httpGet("api/auth/users") ?: return null
        return try {
            val arr = JSONObject(body).getJSONArray("users")
            (0 until arr.length()).map {
                val o = arr.getJSONObject(it)
                Account(o.getString("user_id"), o.getString("username"), o.optBoolean("is_member", false))
            }
        } catch (_: Exception) { null }
    }

    /**
     * Delete an account on this skwod (the owner's tool). Through the core: the server wants the
     * request signed by this device — a session token alone no longer deletes an account (build 45).
     */
    suspend fun deleteAccount(userId: String): Boolean {
        val c = client ?: return false
        return withContext(Dispatchers.IO) { runCatching { c.deleteAccount(userId) }.isSuccess }
    }

    /**
     * The instance owner's "delete and ban" for someone else's account, signed by this device
     * through the core. Returns null when done, else a sentence to show.
     */
    suspend fun deleteAccountAndBan(userId: String): String? {
        val c = client ?: return "Not connected — try again in a moment."
        if (userId == current?.userId) return "You can't ban your own account."
        return try { withContext(Dispatchers.IO) { c.deleteAccountAndBan(userId) }; null }
        catch (e: Exception) {
            if (routeIfDeviceError(e)) "This device can't do that any more."
            else "Couldn't delete and ban — only the owner of this Skwod can, and the server must be reachable."
        }
    }

    // ---- members with presence + roles (for the members panel; the FFI MemberInfo lacks these) ----

    /** Fetch every subscribed server's member statuses and seed the realtime presence store. */
    private suspend fun pollPresence() {
        val statuses = HashMap<String, String>()
        val askedAt = realtime.presenceClock()
        for (sid in realtime.subscribedServerIds()) {
            if (sid.isEmpty() || sid == "demo") continue
            for (m in listPresenceMembers(sid)) statuses[m.userId] = m.status
        }
        if (statuses.isNotEmpty()) realtime.seedPresence(statuses, askedAt) else realtime.unheard.value++
    }

    /** Resolve my public username on the active skwod from any member list (fallback when it wasn't
     *  stored at login), backfilling the workspace so we don't look it up again. */
    suspend fun resolveMyUsername(): String? {
        val asked = current ?: return null
        val me = asked.userId
        val c = client ?: return null
        for (sid in chat.spaces.map { it.serverId }.filter { it.isNotEmpty() }.distinct()) {
            val mine = try { c.listMembers(sid).firstOrNull { it.userId == me } } catch (_: Exception) { null }
            // The answer is about the workspace that was asked: after a switch it names nobody here.
            if (current?.localId != asked.localId || client !== c) return null
            if (mine != null) {
                patch(asked.localId) { it.copy(username = mine.username) }
                return mine.username
            }
        }
        return null
    }

    /** Server members with live presence + role ids, via HTTP (same endpoint the Mac members panel uses). */
    suspend fun listPresenceMembers(serverId: String): List<PresenceMember> {
        val body = httpGet("api/servers/$serverId/members") ?: return emptyList()
        return try {
            val arr = JSONObject(body).getJSONArray("members")
            (0 until arr.length()).map {
                val o = arr.getJSONObject(it)
                val ra = o.optJSONArray("role_ids")
                val roles = if (ra != null) (0 until ra.length()).map { j -> ra.getString(j) } else emptyList()
                PresenceMember(o.getString("user_id"), o.getString("username"), o.optString("status", "offline"), roles)
            }
        } catch (_: Exception) { emptyList() }
    }

    /** Owner-only: remove a member from the server (their account survives; they can rejoin). */
    suspend fun kickMember(serverId: String, userId: String): Boolean {
        val ok = httpSend("api/servers/$serverId/members/$userId", "DELETE") == 200
        if (ok) rotateServerKeys(serverId)
        return ok
    }

    /** server_id → owner_id, from the last complete `GET /api/servers` of the active skwod. */
    var serverOwners by mutableStateOf<Map<String, String>>(emptyMap())
        private set

    /**
     * Ask the skwod which servers this account is in, and who owns them. A server listed here
     * that the answer does NOT contain was deleted, or this account was removed from it: it leaves
     * the list (its keys stay — the user did not ask to forget anything). Only a complete,
     * successful answer prunes. Called on going live and on `server_deleted` / `revoke` (which
     * are only "go and check": nothing in their payload is trusted).
     */
    suspend fun refreshServerList() {
        val wid = current?.localId ?: return
        val owners = ServerList.owners(httpGet("api/servers")) ?: return
        if (current?.localId != wid) return
        serverOwners = owners
        chat.serversListed(owners.keys)
        val gone = ServerList.gone(chat.spaces.map { it.serverId }, owners.keys)
        for (sid in gone) chat.removeServer(sid)
        // A server renamed by its owner (on any device): the decrypted names.
        val c = client ?: return
        val names = try { withContext(Dispatchers.IO) { c.serverNames() } } catch (_: Exception) { return }
        if (current?.localId == wid) chat.applyServerNames(names)
    }

    /** Build 49: rename a server for everyone in it (the host checks MANAGE_SERVER). The core seals
     *  the name under the space key. Returns a sentence when it failed. */
    suspend fun renameServer(serverId: String, raw: String): String? {
        ServerName.problem(raw)?.let { return it }
        val c = client ?: return "Not connected — try again."
        val wid = current?.localId
        val stored = try { withContext(Dispatchers.IO) { c.renameServer(serverId, raw) } }
        catch (e: kotlinx.coroutines.CancellationException) { throw e }
        catch (e: Exception) {
            routeIfDeviceError(e)
            return if ("status 403" in e.toString()) "Only the server's owner or an admin can rename it." else "Couldn't rename the server — check your connection and try again."
        }
        if (current?.localId == wid) chat.applyServerNames(mapOf(serverId to stored))
        return null
    }

    /**
     * The name the host gave this skwod (`GET /api/instance/name`; older hosts answer 404 and
     * nothing changes). Cleaned, and not taken when it reads like another entry's name or a
     * generic one ([SkwodName]).
     */
    suspend fun refreshInstanceName() {
        val w = current ?: return
        val raw = httpGet("api/instance/name") ?: return
        val name = SkwodName.parse(raw)
        val others = workspaces.filter { it.localId != w.localId }.flatMap { o ->
            listOfNotNull(if (o.nameSetByUser) o.name else null, Workspace.defaultName(o.server), o.instanceName) }
        val accepted = name?.takeIf { SkwodName.accepted(it, others) }
        val latest = workspaces.firstOrNull { it.localId == w.localId } ?: return
        if (latest.instanceName == accepted) return
        patch(w.localId) { it.copy(instanceName = accepted) }
    }

    /**
     * The instance owner names the skwod on its host (core `setInstanceName`, device-signed, op
     * `instance-name`). Held first to the rule every member applies ([SkwodName.hostName]), so
     * the owner never sets a name members would refuse; empty clears it. A sentence on failure.
     */
    suspend fun setInstanceName(raw: String): String? {
        val c = client ?: return "Not connected — try again."
        val spaced = raw.trim().replace(Regex(" +"), " ")
        if (spaced.isNotEmpty()) {
            val ok = SkwodName.hostName(spaced)
                ?: return "A skwod name uses letters, digits, spaces, - _ ' & and emoji, and can't look like an address or a reserved name."
            if (ok != spaced) return "A skwod name is at most ${SkwodName.MAX} characters."
        }
        try { withContext(Dispatchers.IO) { c.setInstanceName(spaced) } }
        catch (e: kotlinx.coroutines.CancellationException) { throw e }
        catch (e: Exception) {
            routeIfDeviceError(e)
            val text = e.message ?: ""
            return when {
                "status 403" in text -> "Only the person who runs this skwod can rename it."
                "status 400" in text -> "The host refused that name — try letters, digits and emoji."
                else -> "Couldn't rename the skwod. Check the connection and try again."
            }
        }
        refreshInstanceName()
        return null
    }

    /**
     * "Remove this duplicate": drop the RECORD of a second entry for a skwod and account this
     * phone has twice (never the open one). Its cache file and key are left on the phone.
     */
    fun removeDuplicate(localId: String): Boolean {
        val w = workspaces.firstOrNull { it.localId == localId } ?: return false
        if (current?.localId == localId || !WorkspaceLabel.hasTwin(w, workspaces)) return false
        if (!w.isSignedOut) endSession(w, null)
        records.edit { all -> all.filter { it.localId != localId } }
        return true
    }

    /** The server's PINNED owner (the core's `spaceOwner`), or null when none is pinned / unknown. */
    suspend fun pinnedServerOwner(serverId: String): String? {
        val c = client ?: return null
        return try { withContext(Dispatchers.IO) { c.spaceOwner(serverId) } } catch (_: Exception) { null }
    }

    /** server id → whose @everyone counts there ([Mentions.everyoneSenders]), for the open skwod. */
    val everyoneSenders = androidx.compose.runtime.mutableStateMapOf<String, Set<String>>()
    private val everyoneAskedAt = HashMap<String, Long>()

    /**
     * Whose @everyone counts in [serverId]: the pinned owner, and the admins the server lists
     * (Administrator / Manage Server) who are members this device is not holding and has not
     * blocked. Asked at most every 5 minutes; the last answer is kept in [everyoneSenders].
     */
    suspend fun refreshEveryoneSenders(serverId: String, force: Boolean = false): Set<String> {
        val c = client ?: return emptySet()
        val asked = current?.localId ?: return emptySet()
        val now = System.currentTimeMillis()
        val known = everyoneSenders[serverId]
        if (!force && known != null && now - (everyoneAskedAt[serverId] ?: 0L) < 300_000L) return known
        everyoneAskedAt[serverId] = now
        val pinned = pinnedServerOwner(serverId)
        val members = listPresenceMembers(serverId)
        val roles = try { withContext(Dispatchers.IO) { c.listRoles(serverId) } } catch (_: Exception) { emptyList() }
        // Unknown whom this device holds: fail closed (null — only the pinned owner counts).
        val held: Set<String>? = try { withContext(Dispatchers.IO) { c.heldMembers(serverId) }.toSet() } catch (_: Exception) { null }
        if (current?.localId != asked || client !== c) return emptySet()
        // Assigned roles only: the default (@everyone) role's bits are not an admin's.
        val bits = roles.map { Mentions.RoleBits(it.roleId, it.permissions, it.isDefault) }
        val perms = members.take(5000).associate { m -> m.userId to Mentions.everyonePermissions(m.roleIds, bits) }
        val blocked = perms.keys.filter { isBlockedUser(it) }.toSet()
        val set = Mentions.everyoneSenders(pinned, perms, held, blocked)
        everyoneSenders[serverId] = set
        return set
    }

    private val badgePrefs by lazy { ctx.getSharedPreferences("skwod-mention-badges", Context.MODE_PRIVATE) }

    /** Unseen mentions of me ([MentionBadgeLedger]): the red "@ n" on rows and tiles. */
    var mentionBadges by mutableStateOf(MentionBadgeLedger.fromJson(badgePrefs.getString("ledger", null)))
        private set

    /** Mentions of me that arrived in [topic] while it was not on screen. Each message counts once. */
    fun addMentionBadges(ids: List<String>, topic: String) {
        val wid = current?.localId ?: return
        if (realtime.appActive && realtime.focusedTopic == topic) return
        val next = mentionBadges.add(ids, topic, wid)
        if (next != mentionBadges) { mentionBadges = next; badgePrefs.edit().putString("ledger", next.toJson()).apply() }
    }

    /** The conversation was opened: its "@ n" goes. */
    fun clearMentionBadges(topic: String) {
        val wid = current?.localId ?: return
        val next = mentionBadges.clear(topic, wid)
        if (next != mentionBadges) { mentionBadges = next; badgePrefs.edit().putString("ledger", next.toJson()).apply() }
    }

    fun mentionCount(topics: Collection<String>): Int = current?.localId?.let { mentionBadges.count(topics, it) } ?: 0

    /**
     * Leave a server (not its owner): the host removes the membership (`DELETE
     * /api/servers/{id}/members/{me}` — leaving is removing yourself; no device proof is asked),
     * then this device forgets the server's keys and owner pin (`forgetSpace`) and drops it from
     * the list. Messages already cached stay in the encrypted cache. Null = done, else a sentence.
     */
    suspend fun leaveServer(serverId: String): String? {
        val c = client ?: return "Not connected — try again."
        val me = session?.userId ?: return "Not connected — try again."
        // Authoritative here from the confirmation on ([LeaveTombstones]): the server goes now,
        // and nothing already in flight can bring it back while the host answers.
        val asked = bound
        val before = chat.beginLeave(serverId) ?: return null
        val status = httpSend("api/servers/$serverId/members/$me", "DELETE")
        // Another skwod (or account) is in use now: its list is not touched.
        if (bound !== asked) {
            if (status == 200 || status == 404) try { withContext(Dispatchers.IO) { c.forgetSpace(serverId) } } catch (_: Exception) {}
            return null
        }
        // 404: not a member any more (already left, or removed) — still drop it here.
        if (status != 200 && status != 404) {
            chat.leaveFailed(serverId, before)
            return if (status == 400) "You own this server — delete it instead." else "Couldn't leave the server — try again."
        }
        chat.tombstones.confirm(serverId)
        try { withContext(Dispatchers.IO) { c.forgetSpace(serverId) } } catch (_: Exception) {}
        chat.removeServer(serverId)
        return null
    }

    /**
     * Delete a server for everyone (its owner only): signed by this device in the core
     * (`deleteSpace`, op `delete-server`), then forgotten here (`forgetSpace`) and dropped from
     * the list. Null = done, else a sentence.
     */
    suspend fun deleteServer(serverId: String): String? {
        val c = client ?: return "Not connected — try again."
        try { withContext(Dispatchers.IO) { c.deleteSpace(serverId) } }
        catch (e: kotlinx.coroutines.CancellationException) { throw e }
        catch (e: Exception) { routeIfDeviceError(e); return "Couldn't delete the server. Only its owner can, from a device of their account." }
        try { withContext(Dispatchers.IO) { c.forgetSpace(serverId) } } catch (_: Exception) {}
        chat.removeServer(serverId)
        return null
    }

    /** Ban: kick + a server-side ban row every rejoin path checks (requires Ban Members). */
    suspend fun banMember(serverId: String, userId: String): Boolean {
        val ok = httpSend("api/servers/$serverId/bans/$userId", "POST") == 200
        if (ok) rotateServerKeys(serverId)
        return ok
    }

    /** After removing a member, rotate every channel's sender key on the server immediately so the
     *  removed member can't decrypt anything sent afterward (chat or voice). Best-effort — other
     *  members also rotate on their own next membership sync. */
    /** The post-removal key rotation, for a removal made through the core (the reports inbox's ban). */
    suspend fun rotateKeysAfterRemoval(serverId: String) = rotateServerKeys(serverId)

    private suspend fun rotateServerKeys(serverId: String) {
        val c = client ?: return
        val me = session?.userId ?: return
        try { withContext(Dispatchers.IO) { c.syncServerMembership(serverId, me) } } catch (_: Exception) {}
    }

    /**
     * Delete MY account + all server-side data, then wipe locally. Returns null on success (caller
     * signs out), or an error message. A server owner can't self-delete (400).
     */
    suspend fun deleteMyAccount(): String? {
        val me = current?.userId ?: return "Not signed in."
        // Signed by this device, through the core (see [deleteAccount]).
        if (!deleteAccount(me)) {
            return "Couldn't delete your data. The owner of a Skwod can't delete their own account; otherwise check your connection and try again."
        }
        // The account is gone from the server: what this phone held for it goes too. Only
        // this skwod's — the user's other skwods are other accounts and are not touched.
        current?.let { forgetLocally(it, LocalData.Departure.ACCOUNT_DELETED) }
        return null
    }

    /**
     * Sign out of the active skwod only ("Sign out of ‹skwod›" — and what "Leave" used to be).
     * Returns true when another signed-in skwod took over, false when none is left (the caller
     * shows the log-in screen).
     */
    suspend fun leaveCurrent(): Boolean {
        val w = current ?: return workspaces.any { !it.isSignedOut }
        dropSessions(listOf(w))
        val next = workspaces.firstOrNull { !it.isSignedOut }
        if (next != null) { activate(next); return true }
        ConnectionService.stop(ctx)
        return false
    }

    /** Sign out of every skwod on this device. */
    fun signOut() {
        dropSessions(workspaces.toList())
        ConnectionService.stop(ctx)
    }

    /**
     * Signing out drops the session token and NOTHING else ([LocalData.removedBy]): the cache
     * file, the cache key, the contact book and the workspace record stay, so signing back in on
     * this device is the same device — `attachCache` returns true and nothing has to be linked.
     * (Builds before 44 deleted the cache and its key here, which locked people out of their own
     * account.) "Erase this device" ([eraseThisDevice]) is the separate, explicit wipe.
     */
    private fun dropSessions(targets: List<Workspace>) {
        val liveId = current?.localId
        val ids = targets.map { it.localId }.toSet()
        for (w in targets) {
            endSession(w, if (w.localId == liveId) baseUrl else null, ids)
        }
        records.edit { all -> all.map { if (it.localId in ids) LocalData.signedOut(it).copy(rotationKey = null) else it } }
        for (w in targets) secretPut(LocalData.routesName(w.id), null)
        AttachmentService.purgeCache(ctx)   // decrypted copies never outlive the session that made them
        if (liveId != null && liveId in ids) { teardownLive(); current = null }
    }

    /** Close the engine of the active workspace and clear everything on screen that came from it. */
    /**
     * [keepsCache]: this workspace's cache stays on the phone (signing out). What its lists
     * still had to write is then written through the client that has the cache open, before
     * that client is closed — this function cannot wait, so both happen on the IO scope, in
     * that order. False when the cache is about to be deleted: closed at once, nothing written.
     */
    private fun teardownLive(keepsCache: Boolean = true) {
        stopBackgroundSync()
        realtime.disconnect()
        val unsaved = if (keepsCache) chat.takeUnsaved() else emptyList()
        if (unsaved.isEmpty()) dropClient() else {
            val leaving = binding.clear()
            launchIO {
                for ((k, v) in unsaved) try { leaving?.kvWrite(k, v) } catch (_: Exception) {}
                try { leaving?.close() } catch (_: Exception) {}
            }
        }
        deviceId = null; endpoints.clear()
        synchronized(this) { pendingNotices.clear() }
        securityNotice = null; noticeAction = null
        waiting.reset(); confirmJoin = null; pinFailed = false
        joins.reset(); signedOutOf = null
        chat.reset(); groups.reset(); reports.reset(); account.reset()
        incomingCall = null; ringChoices = emptyList(); resetPending = null; needsDeviceLink = false
        stopped = null; recoveryWaiting = false
        Notifications.cancelAll(ctx)
    }

    /**
     * "Erase this device": the device leaves the account (signed, by the core — which also
     * deletes the cache file), then this app deletes the cache KEY and the workspace record.
     * [asLost] erases it as lost: never restorable, and the recovery key is retired at once.
     * Throws what the core threw; nothing local is touched unless the core call succeeded.
     * Returns true when another signed-in skwod took over.
     */
    suspend fun eraseThisDevice(asLost: Boolean, evenIfOffline: Boolean): Boolean {
        val c = client ?: throw IllegalStateException("Not connected.")
        val w = current ?: throw IllegalStateException("Not connected.")
        if (asLost) c.eraseDeviceAsLost(evenIfOffline) else c.eraseDevice(evenIfOffline)
        return forgetLocally(w, LocalData.Departure.ERASE)
    }

    /**
     * Delete what this phone holds for [w] — exactly the parts [LocalData.removedBy] names for
     * [why]. Local only: whether the device is still on the account was decided before this.
     */
    private suspend fun forgetLocally(w: Workspace, why: LocalData.Departure): Boolean {
        val parts = LocalData.removedBy(why)
        val live = current?.localId == w.localId
        val ended = if (LocalData.Part.SESSION_TOKEN in parts) endSession(w, if (live) baseUrl else null) else null
        if (live) { teardownLive(keepsCache = LocalData.Part.CACHE_FILE !in parts); current = null }
        if (LocalData.Part.CACHE_FILE in parts) { chat.forgetParked(w.id); deleteCache(w); Uploads.purgeWork(ctx, w.id) }
        if (LocalData.Part.CACHE_KEY in parts) {
            // The cache key, the mutes and whatever else is kept under this skwod's id — one list.
            // The names the store holds (for side copies) — read on their own: a store that
            // cannot be listed must not stop the cache key being deleted.
            val held = try { prefs.all.keys.toList() } catch (_: Exception) { emptyList() }
            try {
                val secrets = prefs.edit()
                val notify = ctx.getSharedPreferences(MessageNotifier.PREFS, android.content.Context.MODE_PRIVATE).edit()
                LocalData.forgetItems(w.id, removeSecret = { secrets.remove(it) }, removeNotify = { notify.remove(it) }, secretNamesHeld = held)
                secrets.commit(); notify.commit()
            } catch (_: Exception) {}
            muteLists.remove(w.id)
            muteRevision.intValue = muteRevision.intValue + 1
            UploadLimit.forget(w.id)
        }
        if (LocalData.Part.WORKSPACE_RECORD in parts) {
            contacts.forget(w.id); joins.forgetWorkspace(w.id); notifier.forget(w.id)
            records.edit { all -> all.filter { it.localId != w.localId } }
        }
        AttachmentService.purgeCache(ctx)
        if (ended == null && w.nodeId != null) P2PManager.disconnect(w.id)
        val next = workspaces.firstOrNull { !it.isSignedOut }
        if (next != null) { activate(next); return true }
        try { prefs.edit().remove("current").apply() } catch (_: Exception) {}
        ConnectionService.stop(ctx)
        return false
    }

    /**
     * Tell the server this session is over, so the token stops working there too (dropping it
     * locally leaves it valid until it expires — and any open socket alive). Best-effort and
     * bounded: signing out must work offline. Only the workspace we are connected to can be
     * reached; a p2p workspace that is not dialed is skipped.
     */
    private fun revokeSession(w: Workspace, base: String?) {
        if (w.isSignedOut) return
        val url = base ?: (if (!w.isP2P && w.server.startsWith("https://")) w.server else null) ?: return
        // Never the token to a front (or anything shaped like one): that is endSession's.
        if (try { uniffi.skwod_core.isFrontBase(url) || uniffi.skwod_core.isFrontSuspect(url) } catch (_: Throwable) { true }) return
        val token = w.token
        Thread {
            try {
                val c = java.net.URL("${url.trimEnd('/')}/api/auth/logout").openConnection() as java.net.HttpURLConnection
                c.requestMethod = "POST"
                c.connectTimeout = 4000; c.readTimeout = 4000
                c.setRequestProperty("Authorization", "Bearer $token")
                c.doOutput = true
                c.outputStream.use { it.write(ByteArray(0)) }
                c.responseCode
                c.disconnect()
            } catch (_: Exception) {}
        }.start()
    }
    /**
     * Build 51: the session of [w] ends here. Through its p2p front the host is told over the
     * member connection itself ([P2pSession.logout], bounded) — never through the loopback port —
     * and the front's token is cleared before that returns; only then is the front closed. An
     * https skwod is told as before. Returns the job doing it.
     */
    /** [ending]: every entry that ends now. */
    private fun endSession(w: Workspace, base: String?, ending: Set<String> = setOf(w.localId)): kotlinx.coroutines.Job? {
        // Another entry of this device, which stays, uses the very same session: only this one's
        // front goes.
        if (!SessionEnd.SIGN_OUT.tellsHost(w.token, workspaces.filter { it.localId != w.localId && it.localId !in ending }.map { it.token })) {
            val s = P2PManager.detach(w.id) ?: return null
            return ioScope.launch { try { s.disconnect() } catch (_: Exception) {}; try { s.close() } catch (_: Exception) {} }
        }
        val boundIsFront = base?.let { try { uniffi.skwod_core.isFrontBase(it) || uniffi.skwod_core.isFrontSuspect(it) } catch (_: Throwable) { true } } ?: false
        when (SignOutRoute.of(base, boundIsFront, w.nodeId != null)) {
            SignOutRoute.Route.SERVER, SignOutRoute.Route.NONE -> { revokeSession(w, base); return null }
            SignOutRoute.Route.FRONT -> {}
        }
        // Out of the map NOW: a sign-in that follows dials its own front.
        val s = P2PManager.detach(w.id) ?: return null
        val token = w.token
        return ioScope.launch {
            // The core takes and clears the token, then logs out with it; a front that held no
            // token (never signed in here) is signed in once to say so.
            val told = try { s.endSession(false, 4000u) } catch (_: Exception) { false }
            if (!told && token.isNotEmpty() && (try { s.signIn(token) } catch (_: Exception) { null }) != null) {
                try { s.endSession(false, 4000u) } catch (_: Exception) {}
            }
            try { s.disconnect() } catch (_: Exception) {}
            try { s.close() } catch (_: Exception) {}
        }
    }



    /** The encrypted cache AND its SQLite side files (`-wal`, `-shm`, `-journal`). */
    private fun deleteCache(w: Workspace) {
        // An id that is not a plain file name never names a file to delete.
        val path = try { cachePath(w) } catch (_: IllegalStateException) { return }
        // `.unreadable` is the one generation the core keeps of a cache it had to set aside.
        for (base in listOf(path, "$path.unreadable")) for (suffix in listOf("", "-wal", "-shm", "-journal")) File(base + suffix).delete()
    }

    // ---- workspace persistence (JSON in EncryptedSharedPreferences) ----

    /** (Under [records]' lock.) [durable]: on disk before it returns, and whether it is. */
    private fun writeWorkspaces(list: List<Workspace>, durable: Boolean): Boolean {
        val arr = JSONArray()
        for (w in list) {
            arr.put(JSONObject().apply {
                put("server", w.server); put("userId", w.userId); put("token", w.token)
                put("expiresAt", w.expiresAt); put("name", w.name); put("localId", w.localId)
                w.instanceId?.let { put("instanceId", it) }; w.pinnedKey?.let { put("pinnedKey", it) }
                w.beaconPubkey?.let { put("beaconPubkey", it) }
                w.beaconContentKey?.let { put("beaconContentKey", it) }
                put("beaconTimestamp", w.beaconTimestamp)
                w.username?.let { put("username", it) }
                w.nodeId?.let { put("nodeId", it) }; w.fallbackUrl?.let { put("fallbackUrl", it) }
                put("addressTs", w.addressTs)
                put("tokenIssuedAt", w.tokenIssuedAt)
                w.rotationKey?.let { put("rotationKey", it) }
                if (w.signedOutByUser) put("signedOutByUser", true)
                w.instanceName?.let { put("instanceName", it) }
                if (w.nameSetByUser) put("nameSetByUser", true)
            })
        }
        val edit = prefs.edit().putString("workspaces", arr.toString())
        if (durable) return try { edit.commit() } catch (_: Exception) { false }
        edit.apply()
        return true
    }

    /** The stored workspaces; null when the secure store could not be read (NOT the same as none). */
    private fun loadWorkspaces(): List<Workspace>? {
        val json = try { prefs.getString("workspaces", null) } catch (_: Exception) { return null } ?: return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                val server = o.getString("server")
                // Backfill: workspaces persisted before identity pinning had no localId — key them by
                // the OLD url hash so their existing cache/keys aren't orphaned.
                val localId = o.optString("localId", "").ifEmpty { Workspace.slug(server) }
                Workspace(server, o.getString("userId"), o.getString("token"),
                    o.getLong("expiresAt"), o.optString("name", Workspace.defaultName(server)),
                    localId = localId,
                    // Stored by an older build: brought to the core's safe form ([uniffi.skwod_core.safeInstanceId]).
                    instanceId = if (o.has("instanceId")) uniffi.skwod_core.safeInstanceId(o.getString("instanceId")) else null,
                    pinnedKey = if (o.has("pinnedKey")) o.getString("pinnedKey") else null,
                    beaconPubkey = if (o.has("beaconPubkey")) o.getString("beaconPubkey") else null,
                    beaconContentKey = if (o.has("beaconContentKey")) o.getString("beaconContentKey") else null,
                    beaconTimestamp = o.optLong("beaconTimestamp", 0),
                    username = if (o.has("username")) o.getString("username") else null,
                    nodeId = if (o.has("nodeId")) o.getString("nodeId") else null,
                    // A fallback stored before signed records existed came from an invite: drop it.
                    fallbackUrl = if (o.has("fallbackUrl") && o.optLong("addressTs", 0) > 0) o.getString("fallbackUrl") else null,
                    addressTs = o.optLong("addressTs", 0),
                    tokenIssuedAt = o.optLong("tokenIssuedAt", 0),
                    rotationKey = if (o.has("rotationKey")) o.getString("rotationKey") else null,
                    signedOutByUser = o.optBoolean("signedOutByUser", false),
                    instanceName = if (o.has("instanceName")) SkwodName.clean(o.getString("instanceName")) else null,
                    nameSetByUser = o.optBoolean("nameSetByUser", false))
            }
        } catch (_: Exception) { emptyList() }
    }
}
