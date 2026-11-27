package io.skwod.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.Color
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import uniffi.skwod_core.P2pHealth
import uniffi.skwod_core.P2pSession
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.skwod_core.p2pConnectHinted
import uniffi.skwod_core.p2pConnectTimeoutSecs

/** How we are reaching the active skwod right now, in words a person can act on. */
sealed class ConnectionQuality {
    /** A classic https server — nothing to report. */
    data object Server : ConnectionQuality()
    /** Dialing the host (first connect of this launch). */
    data object Connecting : ConnectionQuality()
    /** Straight to the host's machine. */
    data class Direct(val rttMs: Int) : ConnectionQuality()
    /** Through a relay, because no direct route exists right now. */
    data class Relayed(val rttMs: Int) : ConnectionQuality()
    /** We had a connection and lost it; it is being re-dialed ([SessionHealthRule]). */
    data object Reconnecting : ConnectionQuality()
    /** The host could not be reached at all (their machine is off, asleep or offline). */
    data object Offline : ConnectionQuality()
    /** This phone has no network at all (airplane mode, no signal). */
    data object NoNetwork : ConnectionQuality()

    val title: String
        get() = when (this) {
            Server -> "Connected"
            Connecting -> "Connecting…"
            is Direct -> "Connected directly"
            is Relayed -> "Connected through a relay"
            Reconnecting -> "Reconnecting…"
            Offline -> "Host is offline"
            NoNetwork -> "No internet connection"
        }

    /** One plain sentence explaining the state and what, if anything, it means for privacy. */
    val detail: String
        get() = when (this) {
            Server -> "You're connected to this Skwod's server. Messages are end-to-end encrypted."
            Connecting -> "Looking for your host's computer…"
            is Direct -> "Your phone talks straight to your host's computer. Nothing sits in between."
            is Relayed -> "A direct route to your host isn't available right now, so a relay passes the traffic along. The relay can see that your two devices are talking, but never what is said — everything stays end-to-end encrypted. It switches to direct by itself when it can."
            Reconnecting -> "The connection dropped. Skwod is trying again."
            Offline -> "Your host's computer can't be reached. It may be off, asleep or offline. Skwod keeps trying, and your messages on this phone are still here."
            NoNetwork -> "This phone is offline. Skwod reconnects by itself when the network is back, and your messages on this phone are still here."
        }

    val color: Color
        get() = when (this) {
            Server, is Direct -> Color(0xFF4ADE80)
            is Relayed -> Color(0xFFFACC15)
            Connecting, Reconnecting -> Color(0xFFFB923C)
            Offline, NoNetwork -> Color(0xFFF87171)
        }

    val isUsable: Boolean get() = this is Server || this is Direct || this is Relayed

    val rtt: Int
        get() = when (this) {
            is Direct -> rttMs
            is Relayed -> rttMs
            else -> 0
        }
}

/**
 * Owns the live p2p sessions — one per host key — and the loopback URL each one exposes.
 *
 * The loopback URL (`http://127.0.0.1:<port>/<secret>`) is a per-process value: it is never
 * persisted, never shown and never logged. What is persisted is the host's node id; this object
 * turns that into a usable base URL on launch and keeps the session healthy across foreground and
 * network changes (`networkChanged()` is REQUIRED on Android: the QUIC socket does not notice a
 * Wi-Fi ↔ cellular switch by itself).
 */
/** The host could not be reached in time (the app's backstop; the core normally fails first). */
class P2PConnectTimeout : Exception("could not reach the host: timed out")

/** A dial that finished after the relay setting changed: it is not used. */
class P2PStaleDial : Exception("dialed under a relay setting that has changed")

/**
 * Build 51: THE one check every raw request of the app passes ("may I send to this base right
 * now?") — never a retired front URL, never a SUSPECT front — and the in-flight raw requests of a
 * base whose front moved are cut ([cancel]).
 */
object RawSink {
    fun allows(base: String?): Boolean {
        if (base.isNullOrEmpty()) return false
        return try { !uniffi.skwod_core.isRetiredBase(base) && !uniffi.skwod_core.isFrontSuspect(base) } catch (_: Throwable) { false }
    }

    private val live = java.util.WeakHashMap<java.net.HttpURLConnection, String>()
    fun track(c: java.net.HttpURLConnection, base: String) = synchronized(live) { live[c] = base; Unit }

    /** Cut every tracked request to [base]. */
    fun cancel(base: String?) {
        if (base.isNullOrEmpty()) return
        val cut = synchronized(live) { live.entries.filter { UrlScope.isUnder(it.value, base) }.map { it.key } }
        for (c in cut) try { c.disconnect() } catch (_: Exception) {}
    }
}

object P2PManager {
    /** Connection state per host key, for the indicator. */
    val quality = mutableStateOf<Map<String, ConnectionQuality>>(emptyMap())

    private val sessions = HashMap<String, P2pSession>()
    private val inflight = HashMap<String, CompletableDeferred<P2pSession>>()
    private val lock = Mutex()
    @Volatile private var monitoring = false
    @Volatile private var lastSignature: String? = null

    /**
     * Whether the phone has a default network right now. The transport keeps reporting its last
     * path for a while after the network is gone, so the indicator must not rely on it alone.
     */
    val networkAvailable = mutableStateOf(true)

    private fun setQuality(nodeId: String, q: ConnectionQuality?) {
        synchronized(quality) {
            quality.value = if (q == null) quality.value - nodeId else quality.value + (nodeId to q)
        }
    }

    // Build 51: one stable loopback FRONT per (host, account) — keyed by the workspace id once
    // there is one (by the host's node id before sign-in, until a workspace adopts it). Its port
    // and base URL never change while the app runs: a dead connection is replaced INSIDE the core
    // ([P2pSession.reconnect]) and a listener the OS took away comes back ([ensureFront]). The
    // token never crosses loopback: clients present the credential [P2pSession.signIn] hands out.

    /** The front's base URL for [key] if one is up. */
    fun liveBase(key: String, nodeId: String? = null): String? = session(key, nodeId)?.baseUrl()

    /** The front of [key] — only if it is for [nodeId] (when given): never another host's. */
    fun session(key: String, nodeId: String? = null): P2pSession? {
        val s = synchronized(sessions) { sessions[key] } ?: return null
        return if (nodeId == null || (try { s.nodeId() } catch (_: Exception) { null }) == nodeId) s else null
    }

    /** Sign-out: out of the map AT ONCE (a new sign-in dials its own front); the caller ends it.
     *  A dial in flight for [key] is invalidated (its key generation moves on). */
    fun detach(key: String): P2pSession? {
        synchronized(probeFailures) { probeFailures.remove(key) }
        setQuality(key, null)
        return synchronized(sessions) { keyGen[key] = (keyGen[key] ?: 0) + 1; sessions.remove(key) }
    }

    @Volatile private var relayGateSet = false
    /** The core refuses relay-allowed dials until it knows the stored setting; every dial of the
     *  app goes through [connect], and every change of it through [applyRelaySetting]. */
    private fun relayGate(ctx: Context) = synchronized(sessions) {
        if (!relayGateSet) { uniffi.skwod_core.p2pRelaysInit(AppSettings.get(ctx).publicFallback); relayGateSet = true }
    }

    /** Per key: bumped by [detach]/[disconnect] (under the `sessions` lock). */
    private val keyGen = HashMap<String, Int>()

    /** A workspace takes over the pre-sign-in front of its host, unless it has its own already. */
    fun adopt(nodeId: String, key: String) {
        if (key == nodeId) return
        synchronized(sessions) {
            if (sessions[key] != null) return
            if ((try { sessions[nodeId]?.nodeId() } catch (_: Exception) { null }) != nodeId) return
            val s = sessions.remove(nodeId) ?: return
            sessions[key] = s
        }
        quality.value[nodeId]?.let { q -> setQuality(nodeId, null); setQuality(key, q) }
    }

    /** Bumped by [applyRelaySetting]: a dial started before it is never used ([DialRule]). */
    @Volatile private var dialGeneration = 0

    /**
     * Dial the host for [key] (or reuse its front) and return the base URL to use wherever a
     * server URL goes. Concurrent callers share one dial. Throws when the host can't be reached.
     */
    suspend fun connect(ctx: Context, nodeId: String, retry: Boolean = false, key: String = nodeId): String {
        session(key)?.let { s ->
            if ((try { s.nodeId() } catch (_: Exception) { null }) == nodeId) return s.baseUrl()
            // The workspace now names another host: its old front is closed first (its token is
            // forgotten here only — nothing is ended on any host).
            detach(key)
            try { s.disconnect() } catch (_: Exception) {}
            try { s.close() } catch (_: Exception) {}
        }
        val (deferred, owner) = lock.withLock {
            liveBase(key)?.let { return it }
            inflight[key]?.let { it to false } ?: (CompletableDeferred<P2pSession>().also { inflight[key] = it } to true)
        }
        if (!owner) return deferred.await().baseUrl()
        relayGate(ctx)
        val (generation, kg) = synchronized(sessions) { dialGeneration to (keyGen[key] ?: 0) }
        val fallback = AppSettings.get(ctx).publicFallback
        val before = quality.value[key]
        if (before == null || (before == ConnectionQuality.Offline && !retry)) setQuality(key, ConnectionQuality.Connecting)
        try {
            val session = withTimeoutOrNull((p2pConnectTimeoutSecs().toLong() + 5) * 1000) {
                p2pConnectHinted(nodeId, fallback, RelayHints.get(nodeId), routes?.load(key))
            } ?: throw P2PConnectTimeout()
            // Dialed under a relay setting that no longer holds (relays turned off meanwhile): never used.
            // …or for a key signed out meanwhile. The check and the insert are under the lock the
            // generations are bumped under: nothing slips in between.
            val inserted = synchronized(sessions) {
                DialRule.usable(generation, dialGeneration, fallback, AppSettings.get(ctx).publicFallback, kg, keyGen[key] ?: 0)
                    .also { if (it) sessions[key] = session }
            }
            if (!inserted) {
                Thread { try { kotlinx.coroutines.runBlocking { session.disconnect() } } catch (_: Exception) {}; try { session.close() } catch (_: Exception) {} }.start()
                throw P2PStaleDial()
            }
            watchProxy(session, key)
            lock.withLock { if (inflight[key] === deferred) inflight.remove(key) }
            deferred.complete(session)
            refresh(key)
            return session.baseUrl()
        } catch (e: Exception) {
            lock.withLock { if (inflight[key] === deferred) inflight.remove(key) }
            setQuality(key, ConnectionQuality.Offline)
            deferred.completeExceptionally(e)
            throw e
        }
    }

    /** Re-read direct/relayed + latency for one front (cheap; local only). */
    suspend fun refresh(key: String) {
        val s = session(key) ?: return
        routes?.takeIf { it.mayKeep(key) }?.let { kept -> (try { s.takeRoutes() } catch (_: Exception) { null })?.let { kept.save(key, it) } }
        // The host did not answer the last probe: "Reconnecting…" until it answers again.
        if (synchronized(probeFailures) { probeFailures[key] ?: 0 } > 0) { setQuality(key, ConnectionQuality.Reconnecting); return }
        val p = try { s.path() } catch (_: Exception) { return }
        setQuality(key, when (p.kind) {
            "direct" -> ConnectionQuality.Direct(p.rttMs.toInt())
            "relay" -> ConnectionQuality.Relayed(p.rttMs.toInt())
            else -> ConnectionQuality.Reconnecting
        })
    }

    private val probeFailures = HashMap<String, Int>()
    private val probing = HashSet<String>()

    /** What a health check did: nothing the app has to do, or the front moved (re-bind). */
    sealed class HealthOutcome {
        data object Unchanged : HealthOutcome()
        data class Moved(val base: String, val credential: String?) : HealthOutcome()
        /** Not proved ours, or being checked right now: never "healthy" ([FrontProof]). */
        data object Unproved : HealthOutcome()
    }

    /**
     * Is the front for [key] still usable? [P2pSession.check] answers two things: the front's
     * listener alive and PROVED ours (in process) — if not, it listens again ([ensureFront]); and
     * the host answering over the connection — if not (one failure when urgent, two in a row
     * otherwise, [SessionHealthRule]) the connection is replaced inside the core, paced there.
     * Neither changes the base URL, except a move. Errors count as failures (fail closed).
     */
    /** [callActive]: only DELAYS a re-key ([ensureFront]); a proof that failed leaves the front suspect. */
    suspend fun checkHealth(key: String, urgent: Boolean, callActive: Boolean = false): HealthOutcome {
        val s = session(key) ?: return HealthOutcome.Unchanged
        if (!synchronized(probing) { probing.add(key) }) return HealthOutcome.Unproved
        try {
            // Still SUSPECT (back from the background): proved ours — or re-keyed — first.
            if (try { uniffi.skwod_core.isFrontSuspect(s.baseUrl()) } catch (_: Throwable) { true }) {
                val r = ensureFront(key, callActive)
                if (r != HealthOutcome.Unchanged) return r
            }
            val health = try {
                if (s.proxyClosed()) P2pHealth(proxyOk = false, upstreamOk = false)
                else s.check(SessionHealthRule.PROBE_TIMEOUT_MS.toUInt())
            } catch (_: Exception) { P2pHealth(proxyOk = false, upstreamOk = false) }
            if (session(key) !== s) return HealthOutcome.Unchanged
            if (!health.proxyOk) {
                // (SUSPECT already, in the core. The host was not asked: the check stopped here.)
                val r = ensureFront(key, callActive)
                return if (r == HealthOutcome.Unchanged) HealthOutcome.Unproved else r
            }
            val (failures, outcome) = SessionHealthRule.next(synchronized(probeFailures) { probeFailures[key] ?: 0 }, true, health.upstreamOk, urgent)
            synchronized(probeFailures) { probeFailures[key] = failures }
            when (outcome) {
                SessionHealthRule.Outcome.HEALTHY -> refresh(key)
                SessionHealthRule.Outcome.DEGRADED -> setQuality(key, ConnectionQuality.Reconnecting)
                SessionHealthRule.Outcome.REPLACE -> {
                    setQuality(key, ConnectionQuality.Reconnecting)
                    val ok = try { s.reconnect(null); true } catch (_: Exception) { false }
                    if (ok) { synchronized(probeFailures) { probeFailures[key] = 0 }; refresh(key) }
                }
            }
            return HealthOutcome.Unchanged
        } finally {
            synchronized(probing) { probing.remove(key) }
        }
    }

    /**
     * Prove the front ours, or re-key it. [HealthOutcome.Unchanged] only when it IS proved.
     * [callActive]: a challenge merely unanswered waits with the re-key (and stays suspect); a
     * port that is not ours re-keys all the same.
     */
    suspend fun ensureFront(key: String, callActive: Boolean = false): HealthOutcome {
        val s = session(key) ?: return HealthOutcome.Unchanged
        val state = try { if (callActive) s.ensureFrontDeferring() else s.ensureFront() } catch (_: Exception) { return HealthOutcome.Unproved }
        if (session(key) !== s) return HealthOutcome.Unproved
        val suspect = try { uniffi.skwod_core.isFrontSuspect(s.baseUrl()) } catch (_: Throwable) { true }
        return when (FrontProof.of(state.relistened, state.failed, suspect)) {
            FrontProof.PROVED -> HealthOutcome.Unchanged
            FrontProof.MOVED -> HealthOutcome.Moved(state.baseUrl, state.credential)
            FrontProof.UNPROVED -> HealthOutcome.Unproved
        }
    }

    /** Going to the background, and back in front: every front is SUSPECT until [ensureFront]
     *  proves it ours. [except]: [ForegroundRule.exempt]. */
    fun suspendAll(except: String? = null) {
        for ((key, s) in synchronized(sessions) { sessions.toMap() }) if (key != except) try { s.suspend() } catch (_: Exception) {}
    }

    /**
     * The relay setting changed: every connection is replaced under the new setting behind its
     * front (turning relays off closes the relayed ones at once, in the core). Dials in flight
     * were started under the old setting: their waiters fail, and they are discarded.
     */
    /** False: turning relays off failed in the core — every session is disconnected (fail closed).
     *  Off takes effect at once; the rest is in order ([RelayRuns]). */
    suspend fun applyRelaySetting(ctx: Context): Boolean = withContext(NonCancellable) {
        relayGate(ctx)
        synchronized(sessions) { ++dialGeneration }
        val dials = lock.withLock { inflight.values.toList().also { inflight.clear() } }
        for (d in dials) d.completeExceptionally(P2PStaleDial())
        relayRuns.changed(
            setting = { AppSettings.get(ctx).publicFallback },
            revoke = { uniffi.skwod_core.p2pRelaysRevoke() },
            turnOn = { uniffi.skwod_core.p2pRelaysOn() },
            // Confirmed by the core: nothing in this process may use a relay any more.
            turnOff = { uniffi.skwod_core.p2pRelaysOff() },
            // Every session at once, and not cancellable: a caller going away does not leave one
            // session on the old setting.
            redial = { fallback ->
                coroutineScope {
                    synchronized(sessions) { sessions.toMap() }.map { (key, s) ->
                        async {
                            setQuality(key, ConnectionQuality.Reconnecting)
                            try { s.reconnect(fallback) } catch (_: Exception) {}
                            refresh(key)
                        }
                    }.awaitAll()
                }
            },
            disconnectAll = {
                for (s in synchronized(sessions) { sessions.values.toList() }) RawSink.cancel(try { s.baseUrl() } catch (_: Exception) { null })
                disconnectAll()
            },
        )
    }
    private val relayRuns = RelayRuns()

    /** Told (with the front's key) the moment a front's listener fails for good. */
    @Volatile var onProxyClosed: ((String) -> Unit)? = null

    /** Build 51: where a skwod's host was last reached directly (the core's, opaque), for dialing it with
     *  relays off. It says where the host is: the encrypted store only, and only while signed in. */
    class DirectRoutes(val mayKeep: (String) -> Boolean, private val get: (String) -> String?, private val put: (String, String) -> Unit) {
        fun load(key: String): String? = if (mayKeep(key)) get(LocalData.routesName(key)) else null
        fun save(key: String, blob: String) = put(LocalData.routesName(key), blob)
    }
    @Volatile var routes: DirectRoutes? = null

    private fun watchProxy(s: P2pSession, key: String) {
        Thread {
            try { kotlinx.coroutines.runBlocking { s.waitProxyClosed() } } catch (_: Exception) { return@Thread }
            if (session(key) === s) onProxyClosed?.invoke(key)
        }.apply { isDaemon = true; name = "skwod-proxy-watch" }.start()
    }

    /** Wi-Fi ↔ cellular, or back from the background: tell every session so it re-probes its path. */
    suspend fun networkChanged() {
        for ((key, s) in synchronized(sessions) { sessions.toMap() }) {
            try { s.networkChanged() } catch (_: Exception) {}
            refresh(key)
        }
    }

    /** Close one front (leaving a skwod, signing out — after its logout went out). */
    suspend fun disconnect(key: String) {
        val s = synchronized(sessions) { keyGen[key] = (keyGen[key] ?: 0) + 1; sessions.remove(key) }
        synchronized(probeFailures) { probeFailures.remove(key) }
        try { s?.disconnect() } catch (_: Exception) {}
        try { s?.close() } catch (_: Exception) {}
        setQuality(key, null)
    }

    /** Close everything (sign-out of every skwod). */
    suspend fun disconnectAll() {
        for (id in synchronized(sessions) { sessions.keys.toList() }) disconnect(id)
    }

    /**
     * Watch the default network. Only the transport set and reachability are looked at — never an
     * address — and a change is reported once per distinct state.
     */
    fun startMonitoring(ctx: Context, onChange: () -> Unit) {
        if (monitoring) return
        monitoring = true
        val cm = ctx.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        fun signature(caps: NetworkCapabilities?): String {
            if (caps == null) return "none"
            return listOf(NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_CELLULAR,
                NetworkCapabilities.TRANSPORT_ETHERNET, NetworkCapabilities.TRANSPORT_VPN)
                .joinToString(",") { if (caps.hasTransport(it)) "1" else "0" } +
                "|" + caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }
        fun report(sig: String) {
            val previous = lastSignature
            lastSignature = sig
            if (previous != null && previous != sig) onChange()
        }
        try {
            networkAvailable.value = cm.activeNetwork != null
            cm.registerDefaultNetworkCallback(object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    networkAvailable.value = true
                    report("up:" + signature(cm.getNetworkCapabilities(network)) + ":" + network.hashCode())
                }
                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = report("up:" + signature(caps) + ":" + network.hashCode())
                override fun onLost(network: Network) {
                    // For the DEFAULT-network callback, onLost means there is no default network
                    // any more (a replacement arrives as onAvailable instead).
                    networkAvailable.value = false
                    report("none")
                }
            })
        } catch (_: Exception) { monitoring = false }
    }
}
