package io.skwod.app

import kotlinx.coroutines.async
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Build 51: messages that are always current. */
class Build51Test {
    // ---- a dead p2p session is replaced ([SessionHealthRule]) ----

    @Test fun anAnsweringSessionIsHealthyAndForgetsEarlierFailures() {
        assertEquals(0 to SessionHealthRule.Outcome.HEALTHY, SessionHealthRule.next(1, proxyOk = true, upstreamOk = true, urgent = false))
    }

    @Test fun oneSlowAnswerOnTheTimerIsNotADeadSession() {
        val first = SessionHealthRule.next(0, proxyOk = true, upstreamOk = false, urgent = false)
        assertEquals(1 to SessionHealthRule.Outcome.DEGRADED, first)
        assertEquals(0 to SessionHealthRule.Outcome.REPLACE, SessionHealthRule.next(first.first, proxyOk = true, upstreamOk = false, urgent = false))
    }

    @Test fun comingBackToTheAppReplacesASilentSessionAtOnce() {
        assertEquals(SessionHealthRule.Outcome.REPLACE, SessionHealthRule.next(0, proxyOk = true, upstreamOk = false, urgent = true).second)
    }

    @Test fun aDeadOrForeignProxyIsReplacedAtOnceWhateverElse() {
        for (failures in 0..1) for (urgent in listOf(false, true))
            assertEquals(SessionHealthRule.Outcome.REPLACE, SessionHealthRule.next(failures, proxyOk = false, upstreamOk = true, urgent = urgent).second)
    }

    @Test fun theTimerProbesOnlyInFrontAndNotTooOften() {
        val t = 1_000_000L
        assertFalse(SessionHealthRule.due(t - 5_000, t, foreground = true, urgent = false))
        assertTrue(SessionHealthRule.due(t - SessionHealthRule.FOREGROUND_INTERVAL_MS, t, foreground = true, urgent = false))
        assertFalse("never on a timer in the background", SessionHealthRule.due(0, t, foreground = false, urgent = false))
        assertTrue("a network change always probes", SessionHealthRule.due(t, t, foreground = false, urgent = true))
        assertTrue(SessionHealthRule.PROBE_TIMEOUT_MS <= 10_000)
    }

    // ---- catch-up, retries, scrolling ----

    @Test fun catchUpRequestsThatArriveTogetherMakeOneRunAndOneMore() {
        var t = 10_000L
        val gate = CatchUpGate { t }
        assertTrue(gate.request())
        assertFalse(gate.request()); assertFalse(gate.request())
        assertTrue("runs once more", gate.finished())
        assertFalse("then stops", gate.finished())
        assertTrue(gate.request())
    }

    @Test fun everyChannelIsSweptAfterAGapNotOnEveryResume() {
        assertTrue(CatchUpGate.sweepDue(null, 0, socketCameUpSince = false))
        assertTrue(CatchUpGate.sweepDue(1_000, 2_000, socketCameUpSince = true))
        assertFalse(CatchUpGate.sweepDue(1_000, 6_000, socketCameUpSince = false))
        assertTrue(CatchUpGate.sweepDue(1_000, 1_000 + CatchUpGate.SWEEP_FLOOR_MS, socketCameUpSince = false))
    }

    @Test fun catchUpRunsAreSpacedOut() = kotlinx.coroutines.runBlocking {
        var t = 10_000L
        val gate = CatchUpGate { t }
        gate.request(); gate.waitTurn(); gate.finished()
        t += 500
        gate.request()
        assertEquals(CatchUpGate.MIN_GAP_MS - 500, gate.waitMs())
        t += 10_000
        assertEquals(0L, gate.waitMs())
    }

    @Test fun aFailedFetchIsRetriedWithBoundedBackoffThenOffersRetry() {
        assertEquals(2_000L, FetchRetryRule.delayMs(1))
        assertEquals(4_000L, FetchRetryRule.delayMs(2))
        assertEquals(30_000L, FetchRetryRule.delayMs(5))
        assertEquals(null, FetchRetryRule.delayMs(FetchRetryRule.MAX_ATTEMPTS + 1))
        assertEquals(FetchRetryRule.Status.OK, FetchRetryRule.status(0))
        assertEquals(FetchRetryRule.Status.RETRYING, FetchRetryRule.status(1))
        assertEquals(FetchRetryRule.Status.FAILED, FetchRetryRule.status(FetchRetryRule.MAX_ATTEMPTS + 1))
        assertEquals("the strip already says it", FetchRetryRule.Status.OK, FetchRetryRule.status(1, stripShowing = true))
        assertEquals("back once the strip is gone", FetchRetryRule.Status.RETRYING, FetchRetryRule.status(1, stripShowing = false))
    }

    @Test fun aNewMessageFollowsOnlyAReaderAtTheBottom() {
        assertEquals(ChatScrollRule.Arrival.FOLLOW, ChatScrollRule.onArrival(atBottom = true, newestIsMine = false, justSent = false, newFromOthers = 1))
        assertEquals(ChatScrollRule.Arrival.PILL, ChatScrollRule.onArrival(atBottom = false, newestIsMine = false, justSent = false, newFromOthers = 2))
        assertEquals(ChatScrollRule.Arrival.FOLLOW, ChatScrollRule.onArrival(atBottom = false, newestIsMine = true, justSent = false, newFromOthers = 0))
        assertEquals(ChatScrollRule.Arrival.FOLLOW, ChatScrollRule.onArrival(atBottom = false, newestIsMine = false, justSent = true, newFromOthers = 0))
        assertEquals(ChatScrollRule.Arrival.NOTHING, ChatScrollRule.onArrival(atBottom = false, newestIsMine = false, justSent = false, newFromOthers = 0))
    }

    @Test fun onlyTheReaderLeavesTheBottom() {
        assertTrue("rows arrived: still at the bottom", ChatScrollRule.stillAtBottom(was = true, userScrolling = false, nowAtEnd = false))
        assertFalse("scrolled up", ChatScrollRule.stillAtBottom(was = true, userScrolling = true, nowAtEnd = false))
        assertTrue("back down", ChatScrollRule.stillAtBottom(was = false, userScrolling = true, nowAtEnd = true))
        assertFalse("reading history stays put", ChatScrollRule.stillAtBottom(was = false, userScrolling = false, nowAtEnd = false))
    }
    @Test fun aLiveBaseOpensThroughTheOneTrackedHelper() = kotlinx.coroutines.runBlocking {
        val opened = mutableListOf<String>()
        val store = BlobStore("http://127.0.0.1:5001/aaaa", "t", allows = { true }, track = { _, _ -> }, opener = { url ->
            opened += url.toString()
            object : java.net.HttpURLConnection(url) {
                override fun connect() {}
                override fun disconnect() {}
                override fun usingProxy() = false
                override fun getResponseCode() = 404
            }
        })
        try { store.download("b1") } catch (_: AttachmentException) {}
        try { store.downloadTo("b2", java.io.File.createTempFile("blob", ".bin")) } catch (_: AttachmentException) {}
        assertEquals(listOf("http://127.0.0.1:5001/aaaa/api/blobs/b1", "http://127.0.0.1:5001/aaaa/api/blobs/b2"), opened)
    }

    // ---- stable fronts ----

    @Test fun aStaleDialIsDiscarded() {
        assertTrue(DialRule.usable(3, 3, dialFallback = true, currentFallback = true))
        assertFalse("relay setting changed meanwhile", DialRule.usable(3, 4, dialFallback = true, currentFallback = true))
        assertFalse("relays turned off meanwhile", DialRule.usable(3, 3, dialFallback = true, currentFallback = false))
    }

    @Test fun aBlobStoreWithoutACredentialSendsNoAuthorization() = kotlinx.coroutines.runBlocking {
        var auth: String? = "unset"
        val store = BlobStore("http://127.0.0.1:5001/aaaa", "", allows = { true }, track = { _, _ -> }, opener = { url ->
            object : java.net.HttpURLConnection(url) {
                override fun connect() {}
                override fun disconnect() {}
                override fun usingProxy() = false
                override fun getResponseCode(): Int { auth = getRequestProperty("Authorization"); return 404 }
            }
        })
        try { store.download("b1") } catch (_: AttachmentException) {}
        assertEquals("no credential: no Authorization at all (never the token)", null, auth)
    }

    @Test fun aSessionIsEndedByWhatItIsBoundThrough() {
        assertEquals(SignOutRoute.Route.SERVER, SignOutRoute.of("https://chat.example.org", false, true))
        assertEquals(SignOutRoute.Route.FRONT, SignOutRoute.of("http://127.0.0.1:5001/aa", true, true))
        assertEquals(SignOutRoute.Route.FRONT, SignOutRoute.of(null, false, true))
        assertEquals(SignOutRoute.Route.NONE, SignOutRoute.of("", false, false))
    }

    @Test fun onlyRequestsToThatFrontAreCutWhenItMoves() {
        val base = "http://127.0.0.1:5001/aaaa"
        assertTrue(UrlScope.isUnder("http://127.0.0.1:5001/aaaa/api/blobs/x", base))
        assertFalse(UrlScope.isUnder("http://127.0.0.1:5001/aaaab/api", base))
        assertFalse(UrlScope.isUnder("http://127.0.0.1:5002/aaaa/api", base))
        assertFalse(UrlScope.isUnder(null, base))
    }

    @Test fun aRefusedBaseSendsNothing() {
        var opened = 0
        val store = BlobStore("http://127.0.0.1:5001/aaaa", "", { opened++; it.openConnection() as java.net.HttpURLConnection }, { false }, { _, _ -> })
        try { kotlinx.coroutines.runBlocking { store.download("blob", null, 10) }; fail("refused") } catch (_: Exception) {}
        assertEquals(0, opened)
    }

    @Test fun theTokenNeverGoesToAFrontAndAFrontWithoutACredentialGetsNothing() {
        assertEquals("front-abc", WireRule.of(true, "front-abc", "real-token"))
        assertEquals(null, WireRule.of(true, null, "real-token"))
        assertEquals(null, WireRule.of(true, "", "real-token"))
        assertEquals("real-token", WireRule.of(false, "front-abc", "real-token"))
        assertEquals(null, WireRule.of(false, null, ""))
    }

    @Test fun aSignOutDuringAnAwaitStopsTheBind() {
        assertTrue(LiveRecordRule.stillValid("w1", false, "t", "w1", "t"))
        assertFalse("signed out meanwhile", LiveRecordRule.stillValid("w1", true, "t", "w1", "t"))
        assertFalse("another token stored meanwhile", LiveRecordRule.stillValid("w1", false, "t2", "w1", "t"))
        assertFalse("removed", LiveRecordRule.stillValid(null, false, null, "w1", "t"))
        assertFalse("no token at all", LiveRecordRule.stillValid("w1", false, "", "w1", ""))
    }

    @Test fun aDialForAKeySignedOutMeanwhileIsNotUsed() {
        assertTrue(DialRule.usable(1, 1, true, true, 3, 3))
        assertFalse(DialRule.usable(1, 1, true, true, 3, 4))
        assertFalse(DialRule.usable(1, 2, true, true, 3, 3))
    }

    @Test fun aCatchUpAfterOpeningFillsTheNewSinceBar() {
        val m = ReadMarker("r", 100)
        val items = mutableListOf(UnreadItem("r", 100, false, false))
        assertEquals(null, UnreadRule.atOpen(items, m, 1_000))
        items += listOf(UnreadItem("c1", 200, false, false), UnreadItem("c2", 300, false, false), UnreadItem("c3", 400, false, false))
        assertEquals(1 to 3, UnreadRule.atOpen(items, m, 1_000))
        items += UnreadItem("live", 2_000, false, false)
        assertEquals(1 to 3, UnreadRule.atOpen(items, m, 1_000))
        assertEquals(null, UnreadRule.atOpen(items, null, 1_000))
    }

    @Test fun aProofThatFailedIsNeverAHealthyFront() {
        assertEquals(FrontProof.PROVED, FrontProof.of(false, false, false))
        assertEquals(FrontProof.MOVED, FrontProof.of(true, false, false))
        assertEquals("a re-key delayed by a call", FrontProof.UNPROVED, FrontProof.of(false, true, true))
        assertEquals("suspected meanwhile", FrontProof.UNPROVED, FrontProof.of(false, false, true))
        assertEquals(FrontProof.UNPROVED, FrontProof.of(true, true, true))
        for (maySend in listOf(true, false)) {
            assertFalse(FrontProof.isHealthy(FrontProof.UNPROVED, maySend))
            assertFalse(FrontProof.isHealthy(FrontProof.MOVED, maySend))
        }
        assertTrue(FrontProof.isHealthy(FrontProof.PROVED, true))
        assertFalse(FrontProof.isHealthy(FrontProof.PROVED, false))
    }

    @Test fun onlyTheFrontOfAConnectedCallWithLiveAudioIsExemptOnForeground() {
        assertEquals("w", ForegroundRule.exempt("w", connected = true, audioLive = true))
        assertEquals(null, ForegroundRule.exempt("w", connected = false, audioLive = true))
        assertEquals(null, ForegroundRule.exempt("w", connected = true, audioLive = false))
        assertEquals(null, ForegroundRule.exempt(null, connected = true, audioLive = true))
    }

    @Test fun aRelayChangeThatWasSupersededLeavesTheRestToTheLaterOne() = kotlinx.coroutines.runBlocking {
        val log = ArrayList<String>()
        var newest = true
        assertTrue(RelayOptOut.apply(false, { newest }, { log += "on" }, { log += "off"; newest = false }, { log += "dial" }, { log += "disconnect" }))
        assertEquals("changed while it ran: nothing dialed under it", listOf("off"), log)
        log.clear()
        RelayOptOut.apply(true, { false }, { log += "on" }, {}, { log += "dial" }, {})
        assertEquals("superseded before its turn: never turned on", emptyList<String>(), log)
    }

    @Test fun aRelayOptOutThatFailsDisconnectsEverythingAndDialsNothing() = kotlinx.coroutines.runBlocking {
        val log = ArrayList<String>()
        suspend fun run(on: Boolean, fail: Boolean) = RelayOptOut.apply(on, { true }, { log += "on" }, { log += "off"; if (fail) throw RuntimeException("x") }, { log += "dial" }, { log += "disconnect" })
        assertFalse(run(on = false, fail = true)); assertEquals(listOf("off", "disconnect"), log)
        log.clear()
        assertTrue(run(on = false, fail = false)); assertEquals(listOf("off", "dial"), log)
        log.clear()
        assertTrue(run(on = true, fail = true)); assertEquals(listOf("on", "dial"), log)
    }

    @Test fun onlyAConfirmedAnswerAboutTheBoundSessionEndsIt() {
        assertTrue(SignOutRule.mayEnd(confirmed = true, sameBind = true, sameRecord = true))
        assertFalse("a local error, no answer", SignOutRule.mayEnd(false, true, true))
        assertFalse("another bind meanwhile", SignOutRule.mayEnd(true, false, true))
        assertFalse("a rotated token stored meanwhile", SignOutRule.mayEnd(true, true, false))
    }

    /** Overlapping activate, dialAndBind and ring check of ONE workspace: an install whose token
     *  has no issue date rotates once, and each sees what the one before it stored. */
    @Test fun armingIsOneAtATimePerWorkspace() = kotlinx.coroutines.runBlocking {
        val serial = SerialByKey()
        var token = "old"; var issued = 0L; var rotations = 0; var inside = 0; var most = 0
        suspend fun arm(): String = serial.run("w") {
            inside++; most = maxOf(most, inside)
            val mine = token
            kotlinx.coroutines.delay(5)
            if (issued == 0L) {
                rotations++
                kotlinx.coroutines.delay(5)
                assertEquals("nobody else rotated it meanwhile", mine, token)
                token = "fresh$rotations"; issued = 1
            }
            inside--
            token
        }
        val all = kotlinx.coroutines.coroutineScope { List(3) { this.async { arm() } }.map { it.await() } }
        assertEquals(listOf("fresh1", "fresh1", "fresh1"), all)
        assertEquals(1, rotations); assertEquals(1, most)
        assertEquals("x", serial.run("x") { "x" })
    }

    @Test fun relaysOffRevokesAtOnceWhateverTheEarlierChangeIsDoing() = kotlinx.coroutines.runBlocking {
        val runs = RelayRuns()
        var setting = true
        val log = java.util.Collections.synchronizedList(ArrayList<String>())
        val release = kotlinx.coroutines.CompletableDeferred<Unit>()
        val dialing = kotlinx.coroutines.CompletableDeferred<Unit>()
        suspend fun change(redial: suspend () -> Unit) = runs.changed({ setting }, { log += "revoke" }, { log += "on" }, { log += "off" }, { redial() }, { log += "disconnect" })
        val on = async { change { log += "dialing"; dialing.complete(Unit); release.await(); log += "dialed" } }
        dialing.await()                       // its redial hangs: the host is unreachable
        setting = false
        val off = async { change { log += "redial" } }
        kotlinx.coroutines.delay(50)
        assertEquals("revoked at once; only the confirmation waits", listOf("on", "dialing", "revoke"), log.toList())
        release.complete(Unit)
        on.await(); off.await()
        assertEquals(listOf("on", "dialing", "revoke", "dialed", "off", "redial"), log.toList())
    }

    @Test fun theEndOfASessionComesBeforeARebind() {
        assertEquals(SyncFailureRule.Step.SIGNED_OUT, SyncFailureRule.step(true, true, true))
        assertEquals(SyncFailureRule.Step.DEVICE_STOPPED, SyncFailureRule.step(false, true, true))
        assertEquals(SyncFailureRule.Step.REBIND, SyncFailureRule.step(false, false, true))
        assertEquals(SyncFailureRule.Step.OTHER, SyncFailureRule.step(false, false, false))
    }

    @Test fun rebindingBacksOffAndIsCapped() {
        val p = RebindPacer()
        assertEquals(listOf(0L, 2_000L, 8_000L, 30_000L, null, null), List(6) { p.next("a", 1_000) })
        assertEquals("each workspace has its own", 0L, p.next("b", 1_000))
        assertEquals(null, p.next("a", 60_999))
        assertEquals("armed again every minute", 0L, p.next("a", 61_000))
        assertEquals(null, p.next("a", 61_001))
        assertEquals(0L, p.next("a", 121_000))
        p.succeeded("a")
        assertEquals(listOf(0L, 2_000L), List(2) { p.next("a", 1_000) })
    }

    /** The false sign-out and the lost session, forced: two binds of one workspace — in every order
     *  their steps can interleave — with one thing happening anywhere between (a rotation's answer
     *  lost, the old token's grace over, a re-key, a sign-out by the user, the host ending the
     *  session, one bind cancelled), and a third actor (a ring check) in a sample of orders; through
     *  a front and over https; rotation due or not. The host can refuse here: its tokens are
     *  superseded, expire and are deleted as the server does it. */
    @Test fun noInterleavingLosesTheSessionOrSignsOutFalsely() = kotlinx.coroutines.runBlocking {
        val all = interleavings(mapOf('A' to 4, 'B' to 4, 'E' to 1))
        assertEquals(630, all.size)
        val rnd = java.util.Random(51)
        // (A bind, a ring check and the event: in every order; all four: a sample.)
        val third = interleavings(mapOf('A' to 4, 'C' to 2, 'E' to 1)) + List(160) { "AAAABBBBCCE".toList().shuffled(rnd).joinToString("") }
        for (front in listOf(true, false)) for (event in BindWorld.Event.entries) for (due in listOf(true, false))
            for (order in (if (due) all else all.take(90)) + third) {
                val w = BindWorld(due, front, event)
                w.play(order)
                w.wrong()?.let { fail("$it — $event front=$front due=$due $order") }
            }
    }

    /** …and the logic of 070b2f383 in the same world: this test does force the race. */
    @Test fun theOldLogicFailsInTheSameWorld() = kotlinx.coroutines.runBlocking {
        val wrong = interleavings(mapOf('A' to 4, 'B' to 4)).count { o -> BindWorld(true, true, BindWorld.Event.NONE, old = true).also { it.play(o) }.wrong() != null }
        assertTrue("the old logic: $wrong of 70 orders go wrong", wrong > 0)
        println("old logic: $wrong of 70 orders go wrong")
    }

    private fun interleavings(who: Map<Char, Int>): List<String> {
        if (who.values.all { it == 0 }) return listOf("")
        return who.filter { it.value > 0 }.flatMap { (c, n) -> interleavings(who + (c to n - 1)).map { "$c$it" } }
    }

    /** One workspace, its front and its host; every step of every actor waits for its turn.
     *  (One thread: [kotlinx.coroutines.runBlocking].) */
    private class BindWorld(private val due: Boolean, private val throughFront: Boolean, private val event: Event, private val old: Boolean = false) {
        enum class Event { NONE, LOSE_REPLY, GRACE_OVER, REKEY, USER_SIGN_OUT, HOST_ENDS, CANCEL_A }
        private data class Rec(val token: String, val key: String?, val issued: Boolean)
        // What is stored — through the app's own record box.
        private val records = RecordBox<Rec>({ "w" }) { _, _ -> true }.also { it.load(listOf(Rec("t1", null, !due))) }
        private val rec get() = records.list.first()
        private var signedOut = false; private var userOut = false
        // The host.
        private class Tok(var superseded: Boolean = false, var expired: Boolean = false, var used: Boolean = false, var key: String? = null, var successor: String? = null)
        private val tokens = hashMapOf("t1" to Tok(used = true))
        private var minted = 1; private var rotations = 0; private var ended = false
        private var loseNext = event == Event.LOSE_REPLY
        // The front.
        private var front: Pair<String, String>? = null; private var credentials = 0
        // The app.
        private var bound = ""; private var turn = 0
        private val serial = SerialByKey()
        private val turns = "ABCDE".associateWith { kotlinx.coroutines.channels.Channel<Unit>(1000) }

        private fun host(t: String): Boolean {
            val tok = tokens[t] ?: return false
            if (ended || tok.expired) return false
            tok.used = true
            return true
        }
        private fun hostRotate(t: String, k: String): String? {
            val tok = tokens[t] ?: return null
            if (ended || tok.expired) return null
            if (tok.superseded) {
                val s = tok.successor; val unheld = tokens[s]
                if (tok.key != k || s == null || unheld == null || unheld.used || unheld.superseded) return null
                tokens.remove(s)
            }
            minted++; rotations++
            val fresh = "t$minted"
            tok.superseded = true; tok.key = tok.key ?: k; tok.successor = fresh; tok.used = true
            tokens[fresh] = Tok()
            if (loseNext) { loseNext = false; return null }
            return fresh
        }
        private fun signIn(t: String): String {
            front?.let { if (!old && it.second == t) return it.first }
            credentials++
            front = "c$credentials" to t
            return "c$credentials"
        }
        /** What a client presenting [wire] is told; null: refused here, not sent. */
        private fun ask(wire: String): Boolean? {
            if (!throughFront) return host(wire)
            val f = front
            if (f == null || f.first != wire) return if (old) false else null
            return host(f.second)
        }
        /** The token [wire] stands for now (the core's `real_token`). */
        private fun real(wire: String): String? = if (throughFront) front?.takeIf { it.first == wire }?.second else wire
        /** The core's `session_check`: ended? */
        private fun confirmedEnd(wire: String): Boolean {
            if (old) return ask(wire) == false
            val t = real(wire) ?: return false
            repeat(2) { if (ask(wire) != false || real(wire) != t) return false }
            return true
        }
        private suspend fun step(who: String) = turns.getValue(who[0]).receive()

        suspend fun play(order: String): Unit = kotlinx.coroutines.supervisorScope {
            val a = async { bind("A") }
            val jobs = arrayListOf<kotlinx.coroutines.Job>(a, async { bind("B") })
            jobs += async { step("E"); happen({ a.cancel() }, { jobs += async { bind("D") } }) }
            if ('C' in order) jobs += async { ring("C") }
            for (who in order) { turns.getValue(who).trySend(Unit); repeat(8) { kotlinx.coroutines.yield() } }
            settle(jobs)
            if (old) return@supervisorScope
            // What the app does next on its own: bind again after a bind that was cancelled, or after
            // a rotation that did not come to its end (while the old
            // token's grace still runs).
            if (!signedOut && !userOut && (event == Event.CANCEL_A || (due && !rec.issued))) settle(arrayListOf<kotlinx.coroutines.Job>(async { bind("D") }))
            if (event == Event.HOST_ENDS && !signedOut && !userOut) end(bound, rec.token)
            graceOver()
        }
        private suspend fun settle(jobs: List<kotlinx.coroutines.Job>) {
            while (jobs.toList().any { !it.isCompleted }) { turns.values.forEach { if (it.isEmpty) it.trySend(Unit) }; kotlinx.coroutines.yield() }
        }
        private fun happen(cancelA: () -> Unit, moved: () -> Unit) { when (event) {
            Event.NONE, Event.LOSE_REPLY -> {}
            Event.GRACE_OVER -> graceOver()
            // The app binds again whenever its front moved (Moved → rebind).
            Event.REKEY -> front?.let { credentials++; front = "c$credentials" to it.second; moved() }
            Event.USER_SIGN_OUT -> { userOut = true; records.edit { listOf(Rec("", null, true)) }; front = null }
            Event.HOST_ENDS -> ended = true
            Event.CANCEL_A -> cancelA()
        } }
        /** (Minutes later: never before the fresh token is stored.) */
        private fun graceOver() { for ((t, tok) in tokens) if (tok.superseded && t != rec.token) tok.expired = true }

        private fun stored(t: String) = !signedOut && !userOut && rec.token == t
        private fun end(wire: String, record: String, sameBind: Boolean = true) {
            if (SignOutRule.mayEnd(confirmedEnd(wire), sameBind, stored(record))) { signedOut = true; records.edit { listOf(Rec("", null, true)) }; front = null }
        }
        private fun rotation(who: String, t: String, wire: String) = RotationFlow<String, String>(
            storeKey = { records.patch("w", true, { stored(t) }) { it.copy(key = it.key ?: "k-$who") }?.key },
            ask = { k -> step(who); real(wire)?.let { hostRotate(it, k) } },
            persist = { fresh -> records.patch("w", true, { stored(t) }) { Rec(fresh, null, true) }?.token },
            then = { fresh -> if (front?.first == wire) front = wire to fresh })
        private suspend fun arm(who: String, rotating: Boolean): Pair<String, String>? = serial.run("w") {
            ArmFlow<String>(
                stored = { rec.token.takeIf { !signedOut && !userOut } }, isStored = { stored(it) },
                signIn = { t -> step(who); signIn(t) },
                rotate = { t, c -> if (rec.issued) null else (rotation(who, t, c ?: t).run() as? RotationFlow.Outcome.Rotated)?.record },
                rotateToken = { c, t -> if (front?.first == c) { front = c to t; true } else false },
                clear = { if (front?.first == it) front = null },
            ).run(throughFront, rotating)?.let { (t, c) -> t to (c ?: t) }
        }
        private suspend fun bind(who: String) {
            step(who)
            val mine = ++turn
            if (old) {
                val t = rec.token; val c = signIn(t)
                step(who)
                val f = front
                val fresh = if (!rec.issued && f?.first == c) hostRotate(f.second, "k") else null
                if (fresh != null && rec.token == t) { records.edit { listOf(Rec(fresh, null, true)) }; if (front?.first == c) front = c to fresh }
                step(who); bound = c
                step(who); if (confirmedEnd(c)) signedOut = true
                return
            }
            val (record, wire) = arm(who, rotating = true) ?: return
            if (mine != turn) return   // a later bind decides
            step(who)
            if (mine != turn || !stored(record)) return
            bound = wire
            end(wire, record, sameBind = mine == turn)
        }
        private suspend fun ring(who: String) {
            step(who)
            val (record, wire) = arm(who, rotating = false) ?: return
            step(who)
            if (ask(wire) != true) end(wire, record)
        }

        /** What went wrong, if anything. */
        fun wrong(): String? {
            if (event == Event.USER_SIGN_OUT && userOut) {
                if (rec.token.isNotEmpty()) return "a record that was signed out got a token again"
                return if (front == null) null else "the front is armed after a sign-out"
            }
            if (event == Event.HOST_ENDS && ended) return if (signedOut) null else "the host ended the session and the app did not notice"
            if (signedOut) return "signed out of a session the host holds"
            if (!host(rec.token)) return "the stored token is dead: the session is lost"
            if (ask(bound) != true) return "what is bound does not work"
            val live = tokens.values.count { !it.superseded && !it.expired }
            if (live != 1) return "$live live tokens on the host"
            val expected = if (due) (if (event == Event.LOSE_REPLY) 2 else 1) else 0
            return if (rotations != expected) "rotated $rotations times, not $expected" else null
        }
    }

    /** The front says the credential is not the one signed in any more (a re-key while the host
     *  rotated): signed in again with the fresh token — no dead credential is handed on; not at all
     *  when it cannot be. And what a sign-out meanwhile made unwanted is taken back. */
    @Test fun armingNeverHandsOnADeadCredential() = kotlinx.coroutines.runBlocking {
        var stored = "t1"; val cleared = ArrayList<String>(); val asked = ArrayList<String>()
        fun flow(stillStored: (String) -> Boolean = { true }, signIn: (String) -> String?) = ArmFlow<String>({ stored }, stillStored,
            { asked += it; signIn(it) }, { _, _ -> stored = "t2"; "t2" }, { _, _ -> false }, { cleared += it })
        val credentials = ArrayDeque(listOf("c1", "c2"))
        assertEquals("t2" to "c2", flow { credentials.removeFirst() }.run(true, true)); assertEquals(listOf("t1", "t2"), asked)
        stored = "t1"; credentials += "c1"
        assertEquals(null, flow { credentials.removeFirstOrNull() }.run(true, true))
        stored = "t1"
        assertEquals(null, flow({ false }) { "c9" }.run(true, false)); assertEquals(listOf("c9"), cleared)
    }

    @Test fun onlyTheEndOfASessionTellsTheHost() {
        for (why in listOf(SessionEnd.SIGN_OUT, SessionEnd.REMOVED, SessionEnd.ACCOUNT_ENDED)) assertTrue(why.tellsHost("t", listOf("u", "")))
        for (why in listOf(SessionEnd.MOVED, SessionEnd.HOST_CHANGED, SessionEnd.RELAYS_OFF, SessionEnd.SUPERSEDED)) assertFalse(why.tellsHost("t", emptyList()))
        assertFalse("another entry uses the same session", SessionEnd.REMOVED.tellsHost("t", listOf("t")))
        assertFalse(SessionEnd.SIGN_OUT.tellsHost("", emptyList()))
    }

    /** Every writer of the records changes its own fields, on the record as it is: none undoes
     *  another's (a rotated token, a sign-out); what cannot be written does not count. */
    @Test fun recordWritersNeverUndoEachOther() {
        data class R(val id: String, val token: String, val address: Int, val name: Int)
        var writable = true
        val disk = java.util.concurrent.atomic.AtomicReference<List<R>>()
        val box = RecordBox<R>({ it.id }) { l, _ -> if (writable) disk.set(l); writable }
        box.load(listOf(R("w", "t0", 0, 0), R("x", "t0", 0, 0)))
        val threads = listOf<(Int) -> Unit>(
            { i -> box.patch("w", durable = true) { it.copy(token = "t$i") } },
            { _ -> box.patch("w") { it.copy(address = it.address + 1) } },
            { _ -> box.patch("w") { it.copy(name = it.name + 1) } },
            { _ -> box.patch("x") { it.copy(name = it.name + 1) } },
        ).map { work -> Thread { for (i in 1..500) work(i) }.also { it.start() } }
        threads.forEach { it.join() }
        assertEquals(listOf(R("w", "t500", 500, 500), R("x", "t0", 0, 500)), box.list)
        assertEquals(box.list, disk.get())
        writable = false
        assertEquals("not on disk: it does not count", null, box.patch("w", durable = true) { it.copy(token = "lost") })
        assertEquals("t500", box.list.first().token)
        assertEquals("refused", null, box.patch("w", only = { it.token == "other" }) { it.copy(token = "no") })
        assertEquals(null, box.patch("gone") { it })
    }

    @Test fun aRotationThatCannotBeStoredIsNotUsedAndIsAskedAgainWithItsKey() = kotlinx.coroutines.runBlocking {
        var key: String? = null; val asked = ArrayList<String>(); var writable = false; var token = "t1"
        suspend fun run(answer: String?) = RotationFlow<String, String>({ key = key ?: "k"; key }, { asked += it; answer },
            { if (!writable) null else { token = it; key = null; it } }).run()
        for (answer in listOf(null, "t2")) assertEquals(RotationFlow.Outcome.Again, run(answer))
        assertEquals("t1", token); assertEquals("k", key)
        writable = true
        assertEquals("t3", (run("t3") as RotationFlow.Outcome.Rotated).record)
        assertEquals("the same key each time", listOf("k", "k", "k"), asked); assertEquals(null, key)
        assertEquals("no key on disk, no request", RotationFlow.Outcome.NotDue, RotationFlow<String, String>({ null }, { fail("asked"); null }, { null }).run())
    }

    /** Cancelled while the host is being asked: the answer is stored and passed on all the same —
     *  and the cancellation is not swallowed. */
    @Test fun aCancelledRotationIsStillStored() = kotlinx.coroutines.runBlocking {
        val answer = kotlinx.coroutines.CompletableDeferred<String>()
        var token = "t1"; var told = ""; var after = false
        val job = async {
            RotationFlow<String, String>({ "k" }, { answer.await() }, { token = it; it }, { told = it }).run()
            after = true
        }
        kotlinx.coroutines.yield()
        job.cancel()
        kotlinx.coroutines.yield()
        answer.complete("t2")
        job.join()
        assertEquals("t2", token); assertEquals("t2", told)
        assertTrue(job.isCancelled); assertFalse("cancelled, not carried on", after)
    }

    @Test fun theConnectionIsLookedAtWhileASyncPassWaits() = kotlinx.coroutines.runBlocking {
        val looks = java.util.concurrent.atomic.AtomicInteger()
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default)
        val watch = ConnectionWatch(scope, frontMs = 10)
        watch.start({ true }) { looks.incrementAndGet(); kotlinx.coroutines.delay(30_000) }   // each look hangs
        kotlinx.coroutines.delay(300)
        assertTrue("${looks.get()}", looks.get() > 3)
        watch.stop()
        kotlinx.coroutines.delay(60)
        val n = looks.get()
        kotlinx.coroutines.delay(80)
        assertEquals(n, looks.get())
    }

    /** The host is off and the app is in the background: each look dials (one dial at a time, as
     *  `reconnectIfNeeded`), and the next dial comes a whole background wait after the last ended. */
    @Test fun aHostThatIsOffIsDialedFarApartInTheBackground() = kotlinx.coroutines.runBlocking {
        assertEquals(30_000L, ConnectionWatch.BACKGROUND_MS); assertEquals(5_000L, ConnectionWatch.FRONT_MS)
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default)
        val watch = ConnectionWatch(scope, frontMs = 10, backgroundMs = 200)
        val one = kotlinx.coroutines.sync.Mutex()
        val began = java.util.Collections.synchronizedList(mutableListOf<Long>())
        val ended = java.util.Collections.synchronizedList(mutableListOf<Long>())
        val front = java.util.concurrent.atomic.AtomicBoolean(false)
        watch.start({ front.get() }) {
            if (!one.tryLock()) return@start
            try { began += System.nanoTime() / 1_000_000; kotlinx.coroutines.delay(60); ended += System.nanoTime() / 1_000_000 } finally { one.unlock() }
        }
        kotlinx.coroutines.delay(1_200)
        val dials = began.size
        assertTrue("it still dials: $dials", dials >= 2)
        assertTrue("$dials", dials <= 5)
        for (i in 1 until began.size) assertTrue("gap ${began[i] - ended[i - 1]}", began[i] - ended[i - 1] >= 190)
        // Back in front: looked at at once, and often from there.
        front.set(true)
        val at = began.size
        watch.wake()
        kotlinx.coroutines.delay(150)
        assertTrue("${began.size} after $at", began.size > at)
        kotlinx.coroutines.delay(300)
        assertTrue("${began.size} after $at", began.size >= at + 3)
        watch.stop()
    }

    @Test fun comingBackToTheFrontEndsTheBackgroundWait() = kotlinx.coroutines.runBlocking {
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default)
        val watch = ConnectionWatch(scope, frontMs = 10, backgroundMs = 600_000)
        val looks = java.util.concurrent.atomic.AtomicInteger()
        val front = java.util.concurrent.atomic.AtomicBoolean(false)
        watch.start({ front.get() }) { looks.incrementAndGet() }
        kotlinx.coroutines.delay(200)
        assertEquals("in the background: one look, then the long wait", 1, looks.get())
        front.set(true); watch.wake()
        kotlinx.coroutines.delay(400)
        assertTrue("${looks.get()}", looks.get() > 3)
        watch.stop()
    }

    @Test fun noDirectRouteIsSaidAfterAWhileAndOnlyWithRelaysOff() {
        val r = DirectOnlyRule()
        assertFalse(r.note("a", false, true, 0)); assertFalse(r.note("a", false, true, 24_000))
        assertTrue(r.note("a", false, true, 25_000))
        assertFalse("another skwod starts anew", r.note("b", false, true, 26_000))
        assertFalse("with relays it says what it always did", r.note("b", false, false, 90_000))
        assertFalse(r.note("b", false, true, 91_000)); assertFalse(r.note("b", true, true, 120_000))
        assertFalse(r.note(null, false, true, 200_000))
    }

    @Test fun routesAreKeptOnlyForASignedInSkwod() {
        val store = mutableMapOf("routes-a" to "x", "routes-b" to "y")
        val routes = P2PManager.DirectRoutes({ it == "a" }, store::get, { k, v -> store[k] = v })
        assertEquals("x", routes.load("a")); assertNull(routes.load("b"))
        routes.save("a", "z"); assertEquals("z", store["routes-a"])
    }

}
