package io.skwod.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.Color
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import uniffi.skwod_core.P2pSession
import uniffi.skwod_core.p2pConnect

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
    /** We had a connection and lost it; the next request re-dials. */
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

    /** The loopback base URL for `nodeId` if a session is already up. */
    fun liveBase(nodeId: String): String? = synchronized(sessions) { sessions[nodeId] }?.baseUrl()

    fun session(nodeId: String): P2pSession? = synchronized(sessions) { sessions[nodeId] }

    /**
     * Dial the host (or reuse the live session) and return the loopback base URL to use wherever a
     * server URL goes. Concurrent callers share one dial. Throws when the host can't be reached.
     */
    suspend fun connect(ctx: Context, nodeId: String, retry: Boolean = false): String {
        liveBase(nodeId)?.let { return it }
        val (deferred, owner) = lock.withLock {
            liveBase(nodeId)?.let { return it }
            inflight[nodeId]?.let { it to false } ?: (CompletableDeferred<P2pSession>().also { inflight[nodeId] = it } to true)
        }
        if (!owner) return deferred.await().baseUrl()
        val before = quality.value[nodeId]
        // A background retry of a host that is known to be offline keeps saying "offline"
        // instead of flickering to "connecting" every few seconds.
        if (before == null || (before == ConnectionQuality.Offline && !retry)) setQuality(nodeId, ConnectionQuality.Connecting)
        try {
            val session = p2pConnect(nodeId, AppSettings.get(ctx).publicFallback)
            synchronized(sessions) { sessions[nodeId] = session }
            lock.withLock { inflight.remove(nodeId) }
            deferred.complete(session)
            refresh(nodeId)
            return session.baseUrl()
        } catch (e: Exception) {
            lock.withLock { inflight.remove(nodeId) }
            setQuality(nodeId, ConnectionQuality.Offline)
            deferred.completeExceptionally(e)
            throw e
        }
    }

    /** Re-read direct/relayed + latency for one host (cheap; local only). */
    suspend fun refresh(nodeId: String) {
        val s = session(nodeId) ?: return
        val p = try { s.path() } catch (_: Exception) { return }
        setQuality(nodeId, when (p.kind) {
            "direct" -> ConnectionQuality.Direct(p.rttMs.toInt())
            "relay" -> ConnectionQuality.Relayed(p.rttMs.toInt())
            else -> ConnectionQuality.Reconnecting
        })
    }

    /** Wi-Fi ↔ cellular, or back from the background: tell every session so it re-probes its path. */
    suspend fun networkChanged() {
        val all = synchronized(sessions) { sessions.toMap() }
        for ((id, s) in all) {
            try { s.networkChanged() } catch (_: Exception) {}
            refresh(id)
        }
    }

    /** Close one session (leaving a skwod). */
    suspend fun disconnect(nodeId: String) {
        val s = synchronized(sessions) { sessions.remove(nodeId) }
        try { s?.disconnect() } catch (_: Exception) {}
        try { s?.close() } catch (_: Exception) {}
        setQuality(nodeId, null)
    }

    /** Close everything (sign-out, or the relay setting changed and sessions must be re-dialed). */
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
