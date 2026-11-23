package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Persistent system rows and the "Waiting to join" list. */
class SecurityRowsTest {
    private val stx = "\u0002"
    private val names: (String) -> String = { id -> mapOf("u-sam" to "sam", "u-me" to "You")[id] ?: "A member (${id.take(6)}…)" }
    private fun row(json: String) = SecurityNotices.systemRow("${stx}skwod/sys|$json", names)

    @Test fun aJoinSaysWhoLetThemIn() {
        val r = row("""{"kind":"member_joined","user_id":"u-sam","device_id":"","by_user_id":"u-me","was_verified":false}""")!!
        assertEquals("sam joined (let in by you).", r.text)
        assertFalse(r.warning); assertNull(r.actionLabel)
        // The core writes JSON null when nobody is recorded.
        val unknown = row("""{"kind":"member_joined","user_id":"u-sam","device_id":"","by_user_id":null,"was_verified":false}""")!!
        assertEquals("sam joined.", unknown.text)
    }

    @Test fun aHeldMemberIsAWarningWithAReviewAction() {
        val r = row("""{"kind":"member_held","user_id":"u-ghost-123","device_id":"","by_user_id":null,"was_verified":false}""")!!
        assertTrue(r.warning)
        assertEquals("Review", r.actionLabel)
        assertEquals("member_held", r.kind); assertEquals("u-ghost-123", r.userId)
        assertTrue(r.text.contains("waiting to join") && r.text.contains("not given them any keys"))
    }

    @Test fun deviceAndIdentityRows() {
        val added = row("""{"kind":"device_added","user_id":"u-sam","device_id":"0123456789abcdef","by_user_id":null,"was_verified":false}""")!!
        assertTrue(added.text.startsWith("sam added a device (device 01234567…)"))
        assertFalse(added.warning)
        val changed = row("""{"kind":"identity_changed","user_id":"u-sam","device_id":"","by_user_id":null,"was_verified":true}""")!!
        assertTrue(changed.warning); assertEquals("View safety number", changed.actionLabel)
        assertTrue(changed.text.contains("different security key"))
        val unverifiedChange = row("""{"kind":"identity_changed","user_id":"u-sam","device_id":"","by_user_id":null,"was_verified":false}""")!!
        assertFalse(unverifiedChange.warning)
        val unvouched = row("""{"kind":"unverified_contact_device","user_id":"u-sam","device_id":"ffff0000aaaa","by_user_id":null,"was_verified":false}""")!!
        assertTrue(unvouched.warning); assertEquals("View safety number", unvouched.actionLabel)
    }

    @Test fun anythingElseIsNotASystemRow() {
        assertNull(row("""{"kind":"something_new","user_id":"u-sam"}"""))
        assertNull(SecurityNotices.systemRow("${stx}skwod/sys|not json", names))
        assertNull(SecurityNotices.systemRow("hello", names))
        // The tag must lead the body: a user message that merely contains it is not a system row.
        assertNull(SecurityNotices.systemRow("""look: ${stx}skwod/sys|{"kind":"member_joined","user_id":"u-sam"}""", names))
    }

    @Test fun joinRequestsAreNotAlertsAnyMore() {
        assertNull(SecurityNotices.alert("join_request", "u-sam", "", false, "srv", names))
    }

    @Test fun theWaitingListMergesRequestsAndHeldMembers() {
        val out = WaitingRoom.merge(
            requests = listOf("u-req" to "rita"),
            held = listOf("u-zed", "u-req", "u-me", "u-abe"),
            names = mapOf("u-abe" to "abe"),
            me = "u-me",
        )
        assertEquals(listOf(
            WaitingMember("u-req", "rita", WaitingMember.Source.REQUEST),       // a request is listed once, as a request
            WaitingMember("u-abe", "abe", WaitingMember.Source.HELD),
            // u-zed is held by the core but no longer listed by the server: not waiting.
        ), out)
        assertTrue(WaitingRoom.merge(emptyList(), listOf("u-me"), emptyMap(), "u-me").isEmpty())
    }

    @Test fun aSettledHeldRowIsNoLongerAWarning() {
        val held = row("""{"kind":"member_held","user_id":"u-sam"}""")!!
        assertTrue(held.warning && held.actionLabel == "Review")
        assertEquals(held, held.settledIfNotWaiting(stillWaiting = true, nameOf = names))
        val settled = held.settledIfNotWaiting(stillWaiting = false, nameOf = names)
        assertTrue(!settled.warning && settled.actionLabel == null && settled.text.startsWith("sam was listed by the server"))
        // Other rows are never rewritten.
        val joined = row("""{"kind":"member_joined","user_id":"u-sam"}""")!!
        assertEquals(joined, joined.settledIfNotWaiting(stillWaiting = false, nameOf = names))
    }

    // ---- "Waiting to join" labels: a name is only a name when it checks out ----

    private val friends = listOf("u-merhan" to "Merhan")
    private fun found(id: String) = WaitingTrust.Lookup.Found(id)

    @Test fun aNameThatResolvesToTheAccountIsTrusted() {
        assertEquals(WaitingTrust.Verdict.OK, WaitingTrust.assess("u-new", "sam", found("u-new"), friends))
        // The friend themself (same account id) is not an impersonation of themself.
        assertEquals(WaitingTrust.Verdict.OK, WaitingTrust.assess("u-merhan", "Merhan", found("u-merhan"), friends))
    }

    @Test fun aNameThatLeadsElsewhereOrNowhereIsFlagged() {
        assertEquals(WaitingTrust.Verdict.NAME_MISMATCH, WaitingTrust.assess("u-ghost", "sam", found("u-sam"), friends))
        assertEquals(WaitingTrust.Verdict.NAME_MISMATCH, WaitingTrust.assess("u-ghost", "sam", WaitingTrust.Lookup.Nobody, friends))
        assertEquals(WaitingTrust.Verdict.NAME_MISMATCH, WaitingTrust.assess("u-ghost", "  ", found("u-ghost"), friends))
        assertEquals(WaitingTrust.Verdict.UNCHECKED, WaitingTrust.assess("u-new", "sam", WaitingTrust.Lookup.Failed, friends))
    }

    /** THE ATTACK: the host lists a ghost account under a friend's name. */
    @Test fun aKnownNameOnADifferentAccountIsAnImpersonation() {
        // Even when the (hostile) directory agrees that the name is the ghost's.
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", "Merhan", found("u-ghost"), friends))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", " merhan ", found("u-ghost"), friends))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", "MERHAN", WaitingTrust.Lookup.Failed, friends))
    }

    @Test fun onlyACheckedNameCanBeLetIn() {
        for (v in WaitingTrust.Verdict.values()) {
            val w = WaitingMember("u", "sam", WaitingMember.Source.HELD, trust = v, fingerprint = "123456789012345678901234567890")
            assertEquals(v == WaitingTrust.Verdict.OK, w.canLetIn)
            assertEquals(v == WaitingTrust.Verdict.OK, WaitingTrust.warning(w) == null)
        }
        assertTrue(WaitingTrust.warning(WaitingMember("u", "Merhan", WaitingMember.Source.HELD, trust = WaitingTrust.Verdict.IMPERSONATION))!!.second)
        assertEquals("12345 67890", WaitingMember("u", "sam", WaitingMember.Source.HELD, fingerprint = "123456789012345678901234567890").shortFingerprint)
        assertNull(WaitingMember("u", "sam", WaitingMember.Source.HELD).shortFingerprint)
    }

    // ---- look-alike names: what the eye sees decides, not the code points ----

    private fun verdict(name: String, id: String = "u-ghost") = WaitingTrust.assess(id, name, found(id), friends)

    /** "merhan" with a zero-width space / joiner / BOM / soft hyphen inside reads as "merhan". */
    @Test fun aZeroWidthCharacterDoesNotMakeADifferentName() {
        for (invisible in listOf("\u200B", "\u200D", "\uFEFF", "\u00AD", "\u2060", "\u034F", "\u3164", "\uFE0F", "\u202E")) {
            val name = "mer${invisible}han"
            assertEquals("merhan", WaitingTrust.normalize(name))
            assertEquals(invisible.codePointAt(0).toString(16), WaitingTrust.Verdict.IMPERSONATION, verdict(name))
        }
        // A tag character (U+E0061, outside the BMP) is invisible too.
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("merhan" + String(Character.toChars(0xE0061))))
        // Even with nobody to collide with, such a name is never OK.
        assertEquals(WaitingTrust.Verdict.UNUSUAL_CHARACTERS, WaitingTrust.assess("u-new", "sa\u200Bm", found("u-new"), friends))
        assertEquals("sam", WaitingMember("u-new", "sa\u200Bm", WaitingMember.Source.HELD).displayName)
    }

    /** `mеrhan` with a Cyrillic е (U+0435), and a Greek-ο variant: same skeleton as "merhan". */
    @Test fun aCyrillicOrGreekLookAlikeIsAnImpersonation() {
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("m\u0435rhan"))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("\u043C\u0435rh\u0430n"))          // м е … а
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("M\u0415RHAN"))                      // upper-case Cyrillic Е
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", "b\u03BFb", found("u-ghost"), listOf("u-bob" to "bob")))
        assertEquals(NameSkeleton.skeleton("merhan"), NameSkeleton.skeleton("m\u0435rhan"))
        // A look-alike of nobody in particular is still not a name to act on.
        assertEquals(WaitingTrust.Verdict.UNUSUAL_CHARACTERS, WaitingTrust.assess("u-new", "s\u0430m", found("u-new"), friends))
    }

    /** Full-width `ｍｅｒｈａｎ` is "merhan" after NFKC. */
    @Test fun fullWidthLettersAreTheSameName() {
        val fullWidth = "\uFF4D\uFF45\uFF52\uFF48\uFF41\uFF4E"
        assertEquals("merhan", WaitingTrust.normalize(fullWidth))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict(fullWidth))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("\uFF2D\uFF25\uFF32\uFF28\uFF21\uFF2E"))    // ＭＥＲＨＡＮ
        assertEquals(WaitingTrust.Verdict.UNUSUAL_CHARACTERS, WaitingTrust.assess("u-new", "\uFF53\uFF41\uFF4D", found("u-new"), friends))
    }

    /** Scripts mixed inside one name, accents, and the Latin/digit confusions. */
    @Test fun mixedScriptsAndConfusableLatinCollideToo() {
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("m\u0435r\u04BB\u03B1n"))          // Cyrillic е, һ + Greek α
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("m\u00E9rhan"))                      // é
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, verdict("me\u0301rhan"))                     // e + combining acute
        val people = listOf("u-bill" to "bill", "u-olo" to "olo", "u-tom" to "tom")
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", "bi11", found("u-ghost"), people))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", "biIl", found("u-ghost"), people))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", "0l0", found("u-ghost"), people))
        assertEquals(WaitingTrust.Verdict.IMPERSONATION, WaitingTrust.assess("u-ghost", "torn", found("u-ghost"), people))
        // Mixed scripts with nobody to imitate: still never OK.
        assertEquals(WaitingTrust.Verdict.UNUSUAL_CHARACTERS, WaitingTrust.assess("u-new", "z\u043E\u03B5", found("u-new"), people))
    }

    /** A plain ASCII name that is simply someone else stays an ordinary, lettable name. */
    @Test fun aPlainDifferentNameIsStillOk() {
        assertEquals(WaitingTrust.Verdict.OK, verdict("marhan"))
        assertEquals(WaitingTrust.Verdict.OK, verdict("merhan2"))
        assertEquals(WaitingTrust.Verdict.OK, verdict("sam_42"))
        assertEquals(WaitingTrust.Verdict.OK, WaitingTrust.assess("u-new", "Sam", found("u-new"), friends))
        assertFalse(NameSkeleton.isUnusual("  sam_42 "))
        assertTrue(NameSkeleton.isUnusual("sam\u0007"))            // a control character
        assertTrue(NameSkeleton.isUnusual("s\u00E4m"))
        // The friend's own account under an oddly-typed form of their name is not an
        // impersonation of themself — but it is not OK either.
        assertEquals(WaitingTrust.Verdict.UNUSUAL_CHARACTERS, WaitingTrust.assess("u-merhan", "m\u0435rhan", found("u-merhan"), friends))
    }

    /** The list never trusts: an unpinned fingerprint is labelled, and no verdict but OK lets in. */
    @Test fun anUnpinnedFingerprintIsLabelledUnverified() {
        val fp = "123456789012345678901234567890"
        assertEquals("12345 67890 (unverified)", WaitingMember("u", "sam", WaitingMember.Source.HELD, fingerprint = fp).fingerprintLabel)
        assertEquals("12345 67890", WaitingMember("u", "sam", WaitingMember.Source.HELD, fingerprint = fp, fingerprintPinned = true).fingerprintLabel)
        assertEquals("unknown", WaitingMember("u", "sam", WaitingMember.Source.HELD).fingerprintLabel)
        val odd = WaitingMember("u", "s\u0430m", WaitingMember.Source.REQUEST, trust = WaitingTrust.Verdict.UNUSUAL_CHARACTERS)
        assertFalse(odd.canLetIn)
        assertTrue(WaitingTrust.warning(odd)!!.second)
    }
}
