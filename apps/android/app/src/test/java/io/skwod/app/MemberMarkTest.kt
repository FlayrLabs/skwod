package io.skwod.app

import org.junit.Assert.*
import org.junit.Test

/** An ordinary member's mark is quiet; a warning stays a warning. The Apple apps' MemberMarkTests. */
class MemberMarkTest {
    private val book = mapOf("u-alice" to Contact("u-alice", "alice", TrustLevel.KNOWN))
    private fun shown(id: String, name: String, lookup: WaitingTrust.Lookup?) = ContactTrust.display(id, name, book, lookup = lookup)

    @Test fun onlyANameNothingSpeaksAgainstIsQuiet() {
        assertTrue(ContactTrust.quiet(shown("u-carol", "carol", null), words = false))
        assertTrue(ContactTrust.quiet(shown("u-carol", "carol", WaitingTrust.Lookup.Failed), words = false))
        assertFalse("where one decides about people", ContactTrust.quiet(shown("u-carol", "carol", null), words = true))
        assertFalse(ContactTrust.quiet(shown("u-carol", "carol", WaitingTrust.Lookup.Found("u-other")), words = false))
        assertFalse(ContactTrust.quiet(shown("u-carol", "carol", WaitingTrust.Lookup.Nobody), words = false))
        assertFalse(ContactTrust.quiet(shown("u-ghost", "a1ice", null), words = false))
        assertFalse(ContactTrust.quiet(shown("u-odd", "carоl", null), words = false))
        assertFalse(ContactTrust.mayPinOnVerify(shown("u-carol", "carol", null)))
        assertEquals("carol (couldn't check)", shown("u-carol", "carol", null).label)
    }

    @Test fun aNewDeviceAsksUntilASiblingHasAnswered() {
        assertTrue(SiblingRules.mayRequest(false, 0, null, 100))
        assertFalse(SiblingRules.mayRequest(false, 1, 100, 100 + 600_000))
        assertTrue(SiblingRules.mayRequest(false, 1, 100, 100 + 660_000))
        assertFalse(SiblingRules.mayRequest(false, SiblingRules.MAX_REQUESTS, 100, 99_999_999))
        assertFalse(SiblingRules.mayRequest(true, 0, null, 100))
        assertFalse(SiblingRules.answers(book, emptyList()))
        assertTrue(SiblingRules.answers(book, listOf("u-alice")))
        assertTrue(SiblingRules.answers(emptyMap(), emptyList()))
    }
}
