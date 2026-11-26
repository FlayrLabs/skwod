package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** Build 51: what a person sends goes where they sent it (`ComposeTests.swift` is the twin). */
class ComposeTest {
    @Test fun nothingOfOneSkwodGoesThroughAnothersClient() {
        val a = BoundClient("a", "client-a"); val b = BoundClient("b", "client-b")
        assertSame(a, Compose.sender(a, "a"))
        assertNull("another skwod's client is already up", Compose.sender(b, "a"))
        assertNull(Compose.sender<String>(null, "a"))
        assertNull("without its cache nothing can be queued", Compose.sender(BoundClient("a", "client-a", cacheOpen = false), "a"))
        assertNull("a screen that belongs to no skwod sends nothing", Compose.sender(a, null))
        assertNull(Compose.sender(BoundClient("", "x"), ""))
    }

    @Test fun textComesBackToItsOwnComposer() {
        assertEquals("one", Compose.givenBack("one", ""))
        assertEquals("one\ntwo", Compose.givenBack("one", "two"))
        assertNotEquals(Compose.directKey("a", "x"), Compose.directKey("b", "x"))
        assertNotEquals(Compose.directKey("a", "x"), Compose.directKey("a", "y"))
    }
}
