package io.skwod.app

import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch

/**
 * Build 51: when the connection behind a p2p front is replaced (the peer of
 * `ConnectionRecovery.swift`). The app checks the front IN PROCESS ([P2pSession.check]): a front
 * not proved ours listens again; a host that does not answer gets a fresh connection behind the
 * same front ([P2pSession.reconnect], paced in the core). Pure, so it is tested ([Build51Test]).
 */
object SessionHealthRule {
    /** How long one probe may take. */
    const val PROBE_TIMEOUT_MS = 6_000
    /** Failed probes in a row before a session is replaced on the periodic check. */
    const val FAILURES_BEFORE_REPLACING = 2
    /** How often the session is probed while the app is in front. */
    const val FOREGROUND_INTERVAL_MS = 20_000L

    enum class Outcome { HEALTHY, DEGRADED, REPLACE }

    /**
     * `urgent`: back in front, the network changed, or Retry — one failed probe is enough then.
     * Returns the failures to carry forward and what to do.
     */
    fun next(failures: Int, proxyOk: Boolean, upstreamOk: Boolean, urgent: Boolean): Pair<Int, Outcome> {
        // The loopback proxy is dead or not ours: nothing can go through it, ever again.
        if (!proxyOk) return 0 to Outcome.REPLACE
        if (upstreamOk) return 0 to Outcome.HEALTHY
        val n = failures + 1
        return if (urgent || n >= FAILURES_BEFORE_REPLACING) 0 to Outcome.REPLACE else n to Outcome.DEGRADED
    }

    /** Is a periodic probe due? (Urgent ones always are; never while the app is in the background.) */
    fun due(lastProbeAtMs: Long, nowMs: Long, foreground: Boolean, urgent: Boolean): Boolean =
        urgent || (foreground && nowMs - lastProbeAtMs >= FOREGROUND_INTERVAL_MS)
}

/**
 * Build 51 (review): what asking a front to prove itself came to. A call may delay a re-key (in
 * the core: `ensureFrontDeferring`); it never turns a proof that failed into a trusted front.
 */
enum class FrontProof {
    /** Proved ours, as it was. */ PROVED,
    /** Re-keyed: every client is bound again. */ MOVED,
    /** Not proved (or not asked): suspect, nothing is sent; ask again. */ UNPROVED;

    companion object {
        fun of(relistened: Boolean, failed: Boolean, stillSuspect: Boolean): FrontProof =
            if (failed || (stillSuspect && !relistened)) UNPROVED else if (relistened) MOVED else PROVED

        /** Does this, with what may be sent to the front now, stand for a healthy connection? */
        fun isHealthy(proof: FrontProof, maySend: Boolean): Boolean = proof == PROVED && maySend
    }
}

/**
 * Build 51 (review): back in front, EVERY front is suspect until proved. The one exemption: the
 * front carrying a call that is connected with live audio — and that one is challenged at once
 * all the same.
 */
object ForegroundRule {
    fun exempt(callWorkspace: String?, connected: Boolean, audioLive: Boolean): String? =
        if (connected && audioLive) callWorkspace else null
}

/**
 * Build 51 (review): the relay setting, in order and failing closed. Off: the core confirms that
 * nothing relay-allowed is left first; only then is anything dialed again — otherwise every
 * session is disconnected and the user told (false). On: the core allows it first.
 */
object RelayOptOut {
    /** [current]: is this still the newest change? Superseded, the later run does the rest. */
    suspend fun apply(relaysOn: Boolean, current: () -> Boolean = { true }, turnOn: () -> Unit, turnOff: suspend () -> Unit, redial: suspend () -> Unit, disconnectAll: suspend () -> Unit): Boolean {
        if (!current()) return true
        if (relaysOn) turnOn() else {
            try { turnOff() } catch (_: Throwable) { disconnectAll(); return false }
        }
        if (!current()) return true
        redial()
        return true
    }
}

/** Build 51: is [url] a request to the front at [base] (same port AND secret)? */
object UrlScope {
    fun isUnder(url: String?, base: String): Boolean {
        if (url == null || base.isEmpty()) return false
        val b = base.trimEnd('/')
        return url == b || url.startsWith("$b/") || url.startsWith("$b?")
    }
}

/** Build 51: how a session is ended — by what it is bound through. */
object SignOutRoute {
    enum class Route { SERVER, FRONT, NONE }
    fun of(boundBase: String?, boundIsFront: Boolean, isP2P: Boolean): Route = when {
        !boundBase.isNullOrEmpty() -> if (boundIsFront) Route.FRONT else Route.SERVER
        isP2P -> Route.FRONT
        else -> Route.NONE
    }
}

/** Build 51: a dial is used only under the settings it was started with (relays turned OFF meanwhile: never). */
object DialRule {
    /** [keyGeneration]/[currentKeyGeneration]: the front's key was detached or disconnected meanwhile (sign-out). */
    fun usable(dialGeneration: Int, currentGeneration: Int, dialFallback: Boolean, currentFallback: Boolean,
               keyGeneration: Int = 0, currentKeyGeneration: Int = 0): Boolean =
        dialGeneration == currentGeneration && dialFallback == currentFallback && keyGeneration == currentKeyGeneration
}

/**
 * Build 51: what a client presents for a base. Through a front ONLY its credential (none: nothing
 * — the caller must not send); to an https server the account token. Never the token to a front.
 */
object WireRule {
    fun of(baseIsFront: Boolean, credential: String?, token: String): String? =
        if (baseIsFront) credential?.takeIf { it.isNotEmpty() } else token.takeIf { it.isNotEmpty() }
}

/** Build 51: after an await, is the workspace still the one we started with (not signed out, same token)? */
object LiveRecordRule {
    fun stillValid(liveLocalId: String?, liveSignedOut: Boolean, liveToken: String?, startLocalId: String, startToken: String): Boolean =
        liveLocalId == startLocalId && !liveSignedOut && liveToken == startToken && startToken.isNotEmpty()
}

/**
 * Build 51: become-active, network back and a re-established connection all ask for a catch-up,
 * often together. One runs at a time; a request during a run makes exactly one more run after
 * it; runs start at least [MIN_GAP_MS] apart. Thread-safe; tested ([Build51Test]).
 */
class CatchUpGate(private val now: () -> Long = System::currentTimeMillis) {
    private var running = false
    private var again = false
    private var lastStart = Long.MIN_VALUE / 2

    /** True: the caller starts a run. False: one is going and will run once more. */
    @Synchronized fun request(): Boolean {
        if (running) { again = true; return false }
        running = true
        return true
    }

    /** How long the run must wait before starting (the previous one started too recently). */
    @Synchronized fun waitMs(): Long = (lastStart + MIN_GAP_MS - now()).coerceAtLeast(0)

    suspend fun waitTurn() {
        val wait = waitMs()
        if (wait > 0) kotlinx.coroutines.delay(wait)
        synchronized(this) { lastStart = now() }
    }

    /** The run ended. True: run again (something asked meanwhile). */
    @Synchronized fun finished(): Boolean {
        if (again) { again = false; return true }
        running = false
        return false
    }

    companion object {
        const val MIN_GAP_MS = 2_000L
        /** Every joined channel is swept after a socket gap, otherwise at most this often. */
        const val SWEEP_FLOOR_MS = 60_000L
        fun sweepDue(lastSweepMs: Long?, nowMs: Long, socketCameUpSince: Boolean): Boolean =
            lastSweepMs == null || socketCameUpSince || nowMs - lastSweepMs >= SWEEP_FLOOR_MS
    }
}

/** Build 51: a failed catch-up is retried with backoff, a bounded number of times, and said. */
object FetchRetryRule {
    const val MAX_ATTEMPTS = 5

    /** Milliseconds before retry [attempt] (1-based); null = stop and offer "Retry". */
    fun delayMs(attempt: Int): Long? =
        if (attempt < 1 || attempt > MAX_ATTEMPTS) null else minOf(2_000L shl (attempt - 1), 30_000L)

    enum class Status { OK, RETRYING, FAILED }

    /** [stripShowing]: the strip across the top already says the skwod can't be reached; the list does not say it twice. */
    fun status(failures: Int, stripShowing: Boolean = false): Status = when {
        failures == 0 || stripShowing -> Status.OK
        failures > MAX_ATTEMPTS -> Status.FAILED
        else -> Status.RETRYING
    }
}

/**
 * Build 51: where the message list goes. It opens at the NEWEST message (the "N new messages
 * since…" bar jumps up to the first unread; the "New" divider stays). An arrival follows the
 * reader down only if they were at (or near) the bottom, or it is their own / they just sent;
 * someone reading history gets the "↓ N new" pill instead.
 */
object ChatScrollRule {
    enum class Arrival { FOLLOW, PILL, NOTHING }

    /**
     * Is the reader still "at the bottom"? Reaching the end always is. Leaving it takes the
     * reader scrolling: rows that arrive or a layout change move only the end, and a reader who
     * was at the bottom still is — the next arrival follows them down instead of the pill.
     */
    fun stillAtBottom(was: Boolean, userScrolling: Boolean, nowAtEnd: Boolean): Boolean =
        if (nowAtEnd) true else if (userScrolling) false else was

    fun onArrival(atBottom: Boolean, newestIsMine: Boolean, justSent: Boolean, newFromOthers: Int): Arrival = when {
        atBottom || newestIsMine || justSent -> Arrival.FOLLOW
        newFromOthers > 0 -> Arrival.PILL
        else -> Arrival.NOTHING
    }
}

/** Build 51 (review): the one rule for ending a session because of what a server answered. */
object SignOutRule {
    /**
     * [confirmed]: the core says the HOST refused the CURRENT token, twice. [sameBind]: the client
     * that asked is still the one bound. [sameRecord]: the stored record is still that session.
     */
    fun mayEnd(confirmed: Boolean, sameBind: Boolean, sameRecord: Boolean): Boolean = confirmed && sameBind && sameRecord
}

/**
 * Build 51 (review): everything that signs a workspace in to its front, rotates its token or asks
 * on its behalf runs one at a time per workspace, in order.
 */
class SerialByKey {
    private val locks = java.util.concurrent.ConcurrentHashMap<String, kotlinx.coroutines.sync.Mutex>()
    suspend fun <T> run(key: String, body: suspend () -> T): T {
        val lock = locks.getOrPut(key) { kotlinx.coroutines.sync.Mutex() }
        lock.lock()
        try { return body() } finally { lock.unlock() }
    }
}

/**
 * Build 51 (review): changes of the relay setting. OFF takes effect the moment it is chosen
 * (`revoke`), whatever an earlier change is still doing; confirming it and dialing again wait
 * their turn, and a change superseded by a later one leaves the rest to it.
 */
class RelayRuns {
    private val lock = Any()
    private var generation = 0
    private val queue = kotlinx.coroutines.sync.Mutex()

    suspend fun changed(setting: () -> Boolean, revoke: () -> Unit, turnOn: () -> Unit, turnOff: suspend () -> Unit,
                        redial: suspend (Boolean) -> Unit, disconnectAll: suspend () -> Unit): Boolean {
        val mine = synchronized(lock) { generation++; if (!setting()) revoke(); generation }
        queue.lock()
        try {
            val on = setting()
            fun current() = synchronized(lock) { mine == generation && on == setting() }
            return RelayOptOut.apply(on, ::current,
                // (The check and the turn-on are one step: never after a later OFF revoked.)
                turnOn = { synchronized(lock) { if (mine == generation && setting()) turnOn() } },
                turnOff = turnOff, redial = { redial(on) }, disconnectAll = disconnectAll)
        } finally { queue.unlock() }
    }
}

/**
 * Build 51 (review): re-binding after "this client's sign-in was replaced" (the core's typed, local
 * error). Backing off, and capped: past the cap the ordinary reconnect takes over until a pass
 * succeeds.
 */
class RebindPacer {
    private class State(var attempts: Int, var last: Long)
    private val states = HashMap<String, State>()

    /** How long to wait before the next re-bind of [workspace]; null: not now. */
    @Synchronized fun next(workspace: String, now: Long = System.currentTimeMillis()): Long? {
        val s = states.getOrPut(workspace) { State(0, now) }
        if (s.attempts >= DELAYS_MS.size) {
            if (now - s.last < REARM_MS) return null
            s.last = now
            return 0
        }
        s.last = now
        return DELAYS_MS[s.attempts++]
    }
    @Synchronized fun succeeded(workspace: String) { states.remove(workspace) }
    companion object {
        val DELAYS_MS = longArrayOf(0, 2_000, 8_000, 30_000)
        /** Past the delays: again only this long after the last one (armed again, never for good). */
        const val REARM_MS = 60_000L
    }
}

/**
 * What a failed sync pass leads to, in this order: the session's end and a stopped device come
 * before everything — nothing a host can say puts a re-bind in front of them.
 */
object SyncFailureRule {
    enum class Step { SIGNED_OUT, DEVICE_STOPPED, REBIND, OTHER }
    fun step(signedOut: Boolean, deviceStopped: Boolean, signInReplaced: Boolean): Step = when {
        signedOut -> Step.SIGNED_OUT
        deviceStopped -> Step.DEVICE_STOPPED
        signInReplaced -> Step.REBIND
        else -> Step.OTHER
    }
}

/**
 * Build 51 (review): what signing a workspace in to its front is, step by step — over what the app
 * and the core provide, so that every interleaving of it is tested. Runs under [SerialByKey].
 */
class ArmFlow<R : Any>(
    /** The stored record, if it is signed in. */
    private val stored: () -> R?,
    /** Is this exact session (same token) still the stored one? */
    private val isStored: (R) -> Boolean,
    /** The credential the front hands out for it; null: not right now. */
    private val signIn: suspend (R) -> String?,
    /** A fresh token from the host, PERSISTED; null: not due, or not now. */
    private val rotate: suspend (R, String?) -> R?,
    /** Tell the front; false: the credential is not the one signed in any more. */
    private val rotateToken: suspend (String, R) -> Boolean,
    /** Take back exactly this credential. */
    private val clear: suspend (String) -> Unit,
) {
    suspend fun run(throughFront: Boolean, rotating: Boolean): Pair<R, String?>? {
        var record = stored() ?: return null
        var credential: String? = null
        if (throughFront) {
            val c = signIn(record) ?: return null
            if (!isStored(record)) { clear(c); return null }
            credential = c
        }
        if (rotating) rotate(record, credential)?.let { fresh ->
            record = fresh
            val c = credential
            // Replaced meanwhile: signed in again with the fresh token, so that no dead credential
            // is ever bound.
            if (c != null && !rotateToken(c, fresh)) credential = signIn(fresh) ?: return null
        }
        if (!isStored(record)) { credential?.let { clear(it) }; return null }
        return record to credential
    }
}

/**
 * Build 51 (review): the list of records, and the ONE way to change it: under one lock, on the list
 * as it is then. A change names the fields it changes; nobody writes back a copy read earlier (over
 * a token that was rotated, or a sign-out, meanwhile). [persist] gets the new list and whether it
 * must be on disk before it counts; what could not be written does not count.
 */
class RecordBox<R>(private val keyOf: (R) -> String, private val settle: (List<R>) -> List<R> = { it }, private val persist: (List<R>, Boolean) -> Boolean) {
    private val lock = Any()
    @Volatile var list: List<R> = emptyList()
        private set

    /** Loaded from disk: nothing is written. */
    fun load(records: List<R>) = synchronized(lock) { list = settle(records) }

    fun edit(durable: Boolean = false, change: (List<R>) -> List<R>): Boolean = synchronized(lock) {
        val next = settle(change(list))
        if (durable) {
            if (!persist(next, true)) return@synchronized false
            list = next
        } else {
            list = next
            persist(next, false)
        }
        true
    }

    /** Change the record [key] as it is now. Null: there is none, [only] refused it, or it could not be written. */
    fun patch(key: String, durable: Boolean = false, only: (R) -> Boolean = { true }, change: (R) -> R): R? = synchronized(lock) {
        val now = list.firstOrNull { keyOf(it) == key } ?: return@synchronized null
        if (!only(now)) return@synchronized null
        if (!edit(durable) { all -> all.map { if (keyOf(it) == key) change(it) else it } }) return@synchronized null
        list.firstOrNull { keyOf(it) == key }
    }
}

/** Build 51 (review): what tells the host that a session is over. */
enum class SessionEnd(private val tells: Boolean) {
    SIGN_OUT(true), REMOVED(true), ACCOUNT_ENDED(true),
    MOVED(false), HOST_CHANGED(false), RELAYS_OFF(false), SUPERSEDED(false);

    /** …and even then not while another entry of this device uses the very same session. */
    fun tellsHost(token: String, others: List<String>): Boolean = tells && token.isNotEmpty() && token !in others
}

/**
 * Build 51 (review): rotating a session's token so that no interruption loses it. The key is stored
 * before the host is asked; the fresh token is used only once it is stored; until then everything
 * goes on with the old one, and the same key asks again. Once the host is asked, cancellation waits
 * (and is then not swallowed): the answer is what must reach the disk.
 */
class RotationFlow<R : Any, S : Any>(
    /** Store a key with the record (it keeps one it has); null: could not be written — not asked. */
    private val storeKey: () -> String?,
    /** The fresh session from the host; null: no answer, or refused. */
    private val ask: suspend (String) -> S?,
    /** Write token, dates, and no key — durably, into the stored record if it is still that session. */
    private val persist: (S) -> R?,
    /** What must follow at once (the front told). */
    private val then: suspend (R) -> Unit = {},
) {
    sealed class Outcome<out R> {
        data object NotDue : Outcome<Nothing>()
        class Rotated<R>(val record: R) : Outcome<R>()
        data object Again : Outcome<Nothing>()
    }

    suspend fun run(): Outcome<R> {
        val key = storeKey() ?: return Outcome.NotDue
        val out = kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
            val fresh = ask(key) ?: return@withContext Outcome.Again
            val record = persist(fresh) ?: return@withContext Outcome.Again
            then(record)
            Outcome.Rotated(record)
        }
        // (Cancelled meanwhile: now it counts.)
        kotlinx.coroutines.currentCoroutineContext().ensureActive()
        return out
    }
}

/**
 * Build 51 (review): what the connection indicator lives on. On its own: the sync pass can wait half
 * a minute for a host that has gone, and "Reconnecting…" must not wait with it.
 *
 * In front it looks every few seconds, and one look never holds up the next. In the background there
 * is no indicator, and what a look does to a host that is off is dial it: there the next look comes
 * half a minute after the last one ENDED. [wake] (back in front) ends that wait.
 */
class ConnectionWatch(private val scope: kotlinx.coroutines.CoroutineScope,
                      private val frontMs: Long = FRONT_MS, private val backgroundMs: Long = BACKGROUND_MS) {
    private var job: kotlinx.coroutines.Job? = null
    private val woken = kotlinx.coroutines.channels.Channel<Unit>(kotlinx.coroutines.channels.Channel.CONFLATED)
    @Synchronized fun start(inFront: () -> Boolean, look: suspend (Int) -> Unit) {
        if (job?.isActive == true) return   // (asked again from inside a look: it goes on)
        job = scope.launch {
            var tick = 0
            while (true) {
                val now = tick++
                woken.tryReceive()   // (this look is what it asked for)
                val looking = launch { look(now) }
                val front = inFront()
                val waiting = launch {
                    if (!front) looking.join()
                    kotlinx.coroutines.delay(if (front) frontMs else backgroundMs)
                }
                kotlinx.coroutines.selects.select<Unit> {
                    waiting.onJoin {}
                    woken.onReceive {}
                }
                waiting.cancel()
            }
        }
    }
    fun wake() { woken.trySend(Unit) }
    @Synchronized fun stop() { job?.cancel(); job = null }
    companion object {
        const val FRONT_MS = 5_000L
        const val BACKGROUND_MS = 30_000L
    }
}

/**
 * Build 51: relays are off and the host was not reached for a while — said as that, instead of an
 * endless "Reconnecting…". Relays are never turned on by the app itself.
 */
class DirectOnlyRule {
    private var workspace: String? = null
    private var sinceMs = 0L

    /** [usable]: the connection works (or there is nothing to connect to). True: say so. */
    @Synchronized fun note(id: String?, usable: Boolean, relaysOff: Boolean, nowMs: Long): Boolean {
        if (id == null || usable || !relaysOff) { workspace = null; return false }
        if (workspace != id) { workspace = id; sinceMs = nowMs }
        return nowMs - sinceMs >= AFTER_MS
    }

    companion object {
        const val AFTER_MS = 25_000L
        fun text(name: String) = "Can't reach $name directly from this network. Turn on 'Allow relays' to connect."
        const val WHAT_A_RELAY_SEES = "A relay passes the encrypted traffic along when there is no direct way. It sees your IP address, your host's, when you are connected and how much is sent. It cannot read anything."
    }
}
