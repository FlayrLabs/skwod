package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Build 49: unread since this device last read a conversation ([UnreadRule]). Same cases as the
 *  Apple app's Build49Tests. */
class Build49Test {
    private fun item(id: String, t: Long, mine: Boolean = false, system: Boolean = false) = UnreadItem(id, t, mine, system)
    private val convo = listOf(item("a", 1), item("b", 2), item("c", 3, mine = true), item("d", 4), item("e", 5, system = true), item("f", 6))

    @Test fun neverOpenedMeansNothingUnread() {
        assertNull(UnreadRule.firstUnreadIndex(convo, null))
        assertEquals(0, UnreadRule.unreadCount(convo, null))
    }

    @Test fun firstUnreadIsAfterTheMarker() {
        val m = ReadMarker("d", 4)
        assertEquals(5, UnreadRule.firstUnreadIndex(convo, m))
        assertEquals(1, UnreadRule.unreadCount(convo, m))
    }

    @Test fun myOwnMessageMeansIWasHere() {
        val m = ReadMarker("a", 1)
        assertEquals(3, UnreadRule.firstUnreadIndex(convo, m))
        assertEquals(2, UnreadRule.unreadCount(convo, m))
    }

    @Test fun markerOutsideThePageFallsBackToTime() {
        assertEquals(3, UnreadRule.firstUnreadIndex(convo, ReadMarker("zz", 3)))
        assertEquals(3, UnreadRule.firstUnreadIndex(convo, ReadMarker("old", 0)))
        assertEquals(2, UnreadRule.unreadCount(listOf(item("x", 10), item("y", 11)), ReadMarker("old", 0)))
        assertNull(UnreadRule.firstUnreadIndex(convo, ReadMarker("f", 6)))
    }

    @Test fun markerNeverMovesBackwards() {
        val m = ReadMarker("f", 6)
        assertEquals(m, UnreadRule.advanced(m, item("b", 2)))
        assertEquals(ReadMarker("g", 7), UnreadRule.advanced(m, item("g", 7)))
        assertEquals(ReadMarker("b", 2), UnreadRule.advanced(null, item("b", 2)))
    }

    @Test fun newBelow() {
        assertEquals(2, UnreadRule.newBelow(convo, "b"))
        assertEquals(0, UnreadRule.newBelow(convo, "f"))
        assertEquals(0, UnreadRule.newBelow(convo, null))
        assertEquals(0, UnreadRule.newBelow(convo, "missing"))
    }

    @Test fun keysAndRoundTrip() {
        assertEquals("w1|read.c1", UnreadRule.storageKey("w1", "c1"))
        val m = ReadMarker("abc", 42)
        assertEquals(m, ReadMarker.decode(m.encode()))
        assertNull(ReadMarker.decode("not json"))
        assertNull(ReadMarker.decode(null))
        assertEquals("1 new message since 4:12 PM", UnreadRule.barText(1, "4:12 PM"))
        assertEquals("3 new messages since 4:12 PM", UnreadRule.barText(3, "4:12 PM"))
    }

    @Test fun serverNameRule() {
        assertNull(ServerName.problem("  Weekend Crew "))
        assertEquals("A server name needs 1 to 100 characters.", ServerName.problem("   "))
        assertNull(ServerName.problem("x".repeat(100)))
        assertEquals("A server name needs 1 to 100 characters.", ServerName.problem("x".repeat(101)))
        assertEquals("A server name can't contain line breaks, control or invisible characters.", ServerName.problem("two\nlines"))
        assertEquals("A server name can't contain line breaks, control or invisible characters.", ServerName.problem("evil\u202Etxt"))
    }

    @Test fun onlyTheOwnerIsOfferedRename() {
        assertTrue(ServerMenu.Item.RENAME in ServerMenu.items(ServerMenu.Ownership.OWNER))
        assertFalse(ServerMenu.Item.RENAME in ServerMenu.items(ServerMenu.Ownership.MEMBER))
        assertFalse(ServerMenu.Item.RENAME in ServerMenu.items(ServerMenu.Ownership.UNVERIFIED, hostSaysOwner = true))
    }

    @Test fun serverNameBytes() {
        assertNull(ServerName.problem("😀".repeat(100)))
        assertEquals("A server name needs 1 to 100 characters.", ServerName.problem("😀".repeat(101)))
    }

    @Test fun syncedContactNeverBeatsWhatTheUserSetHere() {
        val synced = Contact("r", "Robin", TrustLevel.VERIFIED)
        assertEquals(Contact("r", "Robin", TrustLevel.KNOWN, true), SiblingRules.mergedContact(null, synced, true, false, emptyMap()))
        assertNull(SiblingRules.mergedContact(Contact("r", "Rob", TrustLevel.KNOWN), synced, true, false, emptyMap()))
        assertNull(SiblingRules.mergedContact(null, synced, true, true, emptyMap()))
        assertNull("not in the sender snapshot", SiblingRules.mergedContact(null, synced, false, false, emptyMap()))
        assertEquals(Contact("r", "Robin", TrustLevel.KNOWN, true), SiblingRules.mergedContact(Contact("r", "srv", TrustLevel.UNVERIFIED), synced, true, false, emptyMap()))
    }

    @Test fun syncedNameCannotPassItselfOffAsSomeoneKnown() {
        val book = mapOf("a" to Contact("a", "alice", TrustLevel.KNOWN))
        assertEquals(TrustLevel.UNVERIFIED, SiblingRules.mergedContact(null, Contact("m", "alice", TrustLevel.KNOWN), true, false, book)?.level)
        val merged = SiblingRules.mergedBook(book, mapOf("a" to Contact("a", "Alicia", TrustLevel.KNOWN), "c1" to Contact("c1", "carol", TrustLevel.KNOWN),
            "c2" to Contact("c2", "carol", TrustLevel.KNOWN)), setOf("a", "c1", "c2"), emptySet())
        assertEquals("alice", merged["a"]?.name)
        assertEquals(TrustLevel.KNOWN, merged["c1"]?.level)
        assertEquals(TrustLevel.UNVERIFIED, merged["c2"]?.level)
    }

    @Test fun syncedAvatarsAreValidatedBoundedAndClearsWin() {
        val ok: (ByteArray) -> Boolean = { it.isNotEmpty() && it[0] == 1.toByte() }
        val dec: (String) -> ByteArray? = { s -> when (s) { "small" -> ByteArray(1000) { 1 }; "huge" -> ByteArray(SiblingRules.MAX_AVATAR_BYTES + 1) { 1 }; "bad" -> byteArrayOf(2); else -> null } }
        val now = 1_000_000L
        val entries = listOf(
            SiblingRules.AvatarEntry("user:a", "small", 10), SiblingRules.AvatarEntry("user:b", "huge", 10),
            SiblingRules.AvatarEntry("user:c", "bad", 10), SiblingRules.AvatarEntry("user:mallory", "small", 10),
            SiblingRules.AvatarEntry("user:stranger", "small", 10),
            SiblingRules.AvatarEntry("user:d", "small", now + 600_000), SiblingRules.AvatarEntry("user:e", "small", 5),
            SiblingRules.AvatarEntry("other:x", "small", 10), SiblingRules.AvatarEntry("user:f", "nope", 10),
            SiblingRules.AvatarEntry("user:g", null, 20),
        )
        val vouched = setOf("a", "b", "c", "mallory", "d", "e", "f", "g")
        val got = SiblingRules.acceptedAvatars(entries, vouched, setOf("mallory"), mapOf("user:e" to 9L, "user:g" to 15L), now, dec, ok)
        assertEquals(setOf("user:a", "user:g"), got.keys)
        assertNull(got["user:g"]?.first)
    }

    /** Every surface a name appears on, and its form — table-driven. */
    @Test fun everySurfaceHasItsForm() {
        val table = listOf(
            NameSurface.MESSAGE_HEADER to NameForm.BADGE, NameSurface.MEMBER_ROW to NameForm.BADGE, NameSurface.DM_ROW to NameForm.BADGE,
            NameSurface.MENTION_CHIP to NameForm.BADGE, NameSurface.PROFILE_CARD to NameForm.BADGE,
            NameSurface.MENTION_PICKER to NameForm.TEXT, NameSurface.REPLY_PREVIEW to NameForm.TEXT, NameSurface.NOTIFICATION to NameForm.TEXT,
            NameSurface.INCOMING_CALL to NameForm.TEXT, NameSurface.DIALOG_TITLE to NameForm.TEXT, NameSurface.KICK_BAN_DIALOG to NameForm.TEXT,
            NameSurface.ACTION_SHEET to NameForm.TEXT, NameSurface.APPROVAL_ROW to NameForm.TEXT, NameSurface.JOIN_CONFIRMATION to NameForm.TEXT,
            NameSurface.GROUP_CONFIRMATION to NameForm.TEXT, NameSurface.SECURITY_NOTICE to NameForm.TEXT, NameSurface.TYPING to NameForm.TEXT,
            NameSurface.BLOCK_REPORT_TARGET to NameForm.TEXT,
        )
        assertEquals(NameSurface.values().toSet(), table.map { it.first }.toSet())
        val shown = ContactTrust.Shown("sam", TrustLevel.UNVERIFIED, ContactTrust.Flag.NONE)
        for ((surface, form) in table) {
            assertEquals(surface.name, form, surface.form)
            assertEquals(surface.name, if (form == NameForm.BADGE) "sam" else "sam (unverified)", shown.labelFor(surface))
        }
        assertTrue(shown.needsMark)
        assertEquals("sam ?", shown.labelFor(NameSurface.MENTION_CHIP) + chipMark(shown))
    }

    /** A status read never raises trust; un-verify falls back to KNOWN only for the explicitly known. */
    @Test fun statusReadNeverRaisesTrust() {
        val empty = emptyMap<String, Contact>()
        assertEquals(empty, ContactTrust.afterStatusRead(empty, "u", true))
        val unv = mapOf("u" to Contact("u", "a", TrustLevel.UNVERIFIED))
        assertEquals(unv, ContactTrust.afterStatusRead(unv, "u", true))
        val verifiedKnown = mapOf("u" to Contact("u", "a", TrustLevel.VERIFIED, known = true))
        assertEquals(TrustLevel.KNOWN, ContactTrust.afterStatusRead(verifiedKnown, "u", false)["u"]?.level)
        val verifiedOnly = mapOf("u" to Contact("u", "a", TrustLevel.VERIFIED, known = false))
        assertEquals(TrustLevel.UNVERIFIED, ContactTrust.afterStatusRead(verifiedOnly, "u", false)["u"]?.level)
        assertFalse(ContactTrust.mayPinOnVerify(ContactTrust.Shown("x", TrustLevel.UNVERIFIED, ContactTrust.Flag.IMPERSONATION)))
    }

    /** The raise path has a registry: only the explicit verify in the safety-number dialog and the
     *  sibling merge call `setVerified(…, true, …)`; everything else demotes or reads. */
    @Test fun onlyTheExplicitVerifyRaisesTrust() {
        val root = java.io.File("src/main/java")
        val raisers = root.walkTopDown().filter { it.extension == "kt" }.flatMap { f ->
            f.readLines().filter { l -> l.contains("setVerified(") && !l.contains("fun setVerified") && !l.trim().startsWith("//") && !l.trim().startsWith("*") }
                .filter { l -> !l.contains(", false,") }.map { f.name }
        }.toList()
        // The explicit verify, and the store's workspace-bound sibling raise
        // (`setVerifiedFromSibling`, after the core verified that exact set); both gated.
        assertEquals(setOf("SafetyNumberScreen.kt", "Contacts.kt"), raisers.toSet())
        assertEquals(1, raisers.count { it == "Contacts.kt" })
    }

    @Test fun emojiSearchAndRecents() {
        assertTrue(EmojiCatalog.search("thumbs up").contains("👍"))
        assertTrue(EmojiCatalog.search("squid").contains("🦑"))
        assertTrue(EmojiCatalog.search("").isEmpty())
        var r = emptyList<String>()
        for (e in listOf("😀", "👍", "😀")) r = EmojiCatalog.used(e, r)
        assertEquals(listOf("😀", "👍"), r)
        assertEquals(8, EmojiCatalog.categories.size)
        assertTrue(EmojiCatalog.all.size > 300)
    }

    @Test fun selfMentionIsAlwaysYou() {
        assertEquals("you", ContactTrust.SELF_MENTION)
        // Both mention-name lambdas use it for me (no server-resolved username).
        for (f in listOf("src/main/java/io/skwod/app/ui/SpacesScreen.kt", "src/main/java/io/skwod/app/ui/DmsScreen.kt")) {
            val text = java.io.File(f).readText()
            assertTrue(f, text.contains("ContactTrust.SELF_MENTION"))
            assertFalse(f, text.contains("current?.username ?: \"you\""))
        }
    }

    @Test fun serverNameRefusesInvisibleAndBlankLooking() {
        for (bad in listOf("a\u200Bb", "\u2060x", "x\uFEFF", "\u00ADsoft", "\u3164", "\u2800", "Crew \u3164name")) assertNotNull(bad, ServerName.problem(bad))
        assertNull(ServerName.problem("Café 🎉"))
    }

    /** The contacts.v1 format is the Apple app's: this fixture is also decoded by Build49Tests (Swift). */
    @Test fun siblingBookFormatMatchesApple() {
        val fixture = """{"u-a":{"name":"alice","level":"known","known":true},"u-b":{"name":"bob","level":"verified"}}"""
        val decoded = SiblingBook.decode(fixture)
        assertEquals(Contact("u-a", "alice", TrustLevel.KNOWN, true), decoded["u-a"])
        assertEquals(Contact("u-b", "bob", TrustLevel.VERIFIED, null), decoded["u-b"])
        val again = org.json.JSONObject(SiblingBook.encode(decoded))
        assertEquals("known", again.getJSONObject("u-a").getString("level"))
        assertEquals(decoded, SiblingBook.decode(again.toString()))
    }

    @Test fun serverNameRefusesSeparatorsAndIgnorables() {
        for (bad in listOf("\uFE0F", "a\uFE0Fb", String(Character.toChars(0xE0100)), "crew\u2028name", "x\u2029y", "\u180Bx", "x\uFE00", "\uFFF0x"))
            assertNotNull(bad, ServerName.problem(bad))
        assertNull(ServerName.problem("❤️ crew"))
        assertNull(ServerName.problem("Weekend ✌️"))
    }

    @Test fun verifiedOnlySyncedContactStaysUnverifiedAndUnverifyReturnsThere() {
        val merged = SiblingRules.mergedContact(null, Contact("v", "vera", TrustLevel.VERIFIED, false), true, false, emptyMap())!!
        assertEquals(TrustLevel.UNVERIFIED, merged.level)
        assertEquals(false, merged.known)
        var book = ContactTrust.record(mapOf("v" to merged), "v", "vera", TrustLevel.VERIFIED)
        assertEquals(TrustLevel.VERIFIED, book["v"]?.level)
        book = ContactTrust.unverify(book, "v")
        assertEquals(TrustLevel.UNVERIFIED, book["v"]?.level)
        assertEquals(TrustLevel.KNOWN, SiblingRules.mergedContact(null, Contact("k", "kim", TrustLevel.VERIFIED, true), true, false, emptyMap())?.level)
    }
}
