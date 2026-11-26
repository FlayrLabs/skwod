package io.skwod.app

import io.skwod.app.ServerRecovery.State
import org.junit.Assert.*
import org.junit.Test

/** The same table as the Apple apps' ServerRecoveryTests. */
class ServerRecoveryTest {
    private val none = emptySet<String>()
    private fun state(r: ServerRecovery, setUp: Boolean = true, hidden: Set<String> = none) = r.state(setUp, none, hidden)

    @Test fun whatAnEmptyListSays() {
        val r = ServerRecovery()
        assertEquals(State.LOADING, state(r))
        assertEquals(State.NOT_SET_UP, state(r, setUp = false))
        assertEquals(State.LOADING, state(r.answered(null)))
        assertEquals(State.FAILED, state(r.answered(null).answered(null)))
        assertEquals(State.NONE, state(r.answered(none)))
        assertEquals(State.LOADING, state(r.answered(none).answered(null)))
        assertEquals(State.FAILED, state(r.answered(none).answered(null).answered(null)))
        assertEquals(State.NONE, state(r.answered(null).answered(null).answered(none)))
        assertEquals(State.WAITING_FOR_KEYS, state(r.answered(setOf("s"))))
        assertEquals(State.WAITING_FOR_KEYS, state(r.answered(setOf("s")).answered(null).answered(null)))
        assertEquals(State.NO_CHANNELS, state(r.answered(setOf("s")).found("s", true)))
        assertEquals(State.WAITING_FOR_KEYS, state(r.answered(setOf("s", "t")).found("s", true)))
        assertEquals(State.NONE, state(r.answered(setOf("s")), hidden = setOf("s")))
    }

    @Test fun itNeverGivesUpAndBacksOff() {
        var r = ServerRecovery().answered(setOf("s"))
        val delays = ArrayList<Long>()
        repeat(200) { assertFalse(r.settled(none, none)); r = r.passed(); delays += r.delay(true) }
        assertEquals(listOf(2_000L, 4_000, 8_000, 15_000, 30_000, 60_000, 60_000), delays.take(7))
        assertTrue(delays.sum() > 3_600_000)
        assertTrue(delays.all { it in ServerRecovery.SPACING_MS..60_000 })
        assertEquals(60_000L, ServerRecovery().passed().delay(false))
        assertEquals(ServerRecovery.SPACING_MS, r.nudged().delay(true))
        assertTrue(r.settled(setOf("s"), none))
    }

    @Test fun aRefusedRequestIsNotTheEnd() {
        val r = ServerRecovery().answered(null)
        assertFalse(r.settled(none, none))
        assertEquals(setOf("t"), r.answered(setOf("s", "t")).missing(setOf("s"), none))
    }

    @Test fun membersAreAskedLessAndLessOften() {
        var r = ServerRecovery()
        assertTrue(r.mayAsk("s", 0))
        r = r.didAsk("s", 0)
        assertFalse(r.mayAsk("s", 9_999)); assertTrue(r.mayAsk("s", 10_000)); assertTrue(r.mayAsk("t", 1))
        for (i in 0 until 20) r = r.didAsk("s", i * 1_000L)
        assertFalse(r.mayAsk("s", 19_000 + 299_000)); assertTrue(r.mayAsk("s", 19_000 + 300_000))
        assertFalse(r.nudged().mayAsk("s", 20_000))
    }
}
