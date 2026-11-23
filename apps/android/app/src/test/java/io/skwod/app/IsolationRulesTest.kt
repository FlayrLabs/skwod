package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The rules in `IsolationRules.kt`: one skwod's server stays out of another's state, and a server's word out of this device's. */
class IsolationRulesTest {

    // ---- A1: base URL and token are one value of one workspace ----

    @Test fun aTokenIsNeverPairedWithAnotherWorkspacesUrl() {
        val slot = EndpointSlot()
        slot.put("ws-a", "https://a.example", "token-a")
        assertEquals(Endpoint("ws-a", "https://a.example", "token-a"), slot.of("ws-a"))
        // The workspace changed to B and B's host has not been reached yet: there is NO endpoint
        // for B — not A's URL, to which B's token would be sent.
        assertNull(slot.of("ws-b"))
        assertNull(slot.of(null))
        // B is reached: the pair is B's, whole.
        slot.put("ws-b", "http://127.0.0.1:4100", "token-b")
        assertEquals("token-b", slot.of("ws-b")!!.token)
        assertEquals("http://127.0.0.1:4100", slot.of("ws-b")!!.base)
        assertNull(slot.of("ws-a"))
    }

    @Test fun anUnreachedHostLeavesNoEndpoint() {
        val slot = EndpointSlot()
        slot.put("ws-a", "https://a.example", "token-a")
        slot.put("ws-a", null, "token-a")
        assertNull(slot.of("ws-a"))
        slot.put("ws-a", "https://a.example", "token-a"); slot.clear()
        assertNull(slot.of("ws-a"))
        slot.put("", "https://a.example", "t")
        assertNull(slot.of(""))
    }

    // ---- A2: a server-chosen id never shapes a path ----

    @Test fun onlyAPlainInstanceIdIsAccepted() {
        assertTrue(InstanceIds.isValid("3f2c1a9e-77aa-4c0e-9b1d-0a1b2c3d4e5f"))
        assertTrue(InstanceIds.isValid("a1b2c3d4e5f60718"))
        assertTrue(InstanceIds.isValid("A".repeat(64)))
        for (bad in listOf(null, "", "A".repeat(65), "uploads/../skwod-other", "..", "a/b", "a\\b", "a.b", "a b", "a\u0000b", "a\nb", "ä", "a_b", "skwod-x.sqlite3"))
            assertFalse("accepted: $bad", InstanceIds.isValid(bad))
    }

    @Test fun theCacheFileNameIsWhatItAlwaysWasOrNothing() {
        // Existing caches are found under the same name as before.
        assertEquals("skwod-a1b2c3d4e5f60718.sqlite3", InstanceIds.cacheFileName("a1b2c3d4e5f60718"))
        assertEquals("skwod-3f2c1a9e-77aa-4c0e-9b1d-0a1b2c3d4e5f.sqlite3", InstanceIds.cacheFileName("3f2c1a9e-77aa-4c0e-9b1d-0a1b2c3d4e5f"))
        // An id with a path in it names no file: nothing is opened, nothing deleted.
        assertNull(InstanceIds.cacheFileName("uploads/../skwod-a1b2c3d4e5f60718"))
        assertNull(InstanceIds.cacheFileName(""))
    }

    // ---- A3 / A6: what realtime events may do ----

    @Test fun aServersChannelClearedNeverPurgesLocalHistory() {
        assertEquals(RealtimeRules.Local.REDRAW_ONLY, RealtimeRules.onChannelCleared())
        // …and there is no other answer it could give.
        assertEquals(listOf(RealtimeRules.Local.REDRAW_ONLY), RealtimeRules.Local.entries.toList())
    }

    @Test fun eventsForTopicsNeverSubscribedAreIgnored() {
        val wanted = setOf("user:me", "channel:c1", "server:s1", "dm:d1")
        assertTrue(RealtimeRules.subscribed("channel:c1", wanted))
        assertTrue(RealtimeRules.subscribed("user:me", wanted))
        assertFalse(RealtimeRules.subscribed("channel:other", wanted))
        assertFalse(RealtimeRules.subscribed("user:someone-else", wanted))
        assertFalse(RealtimeRules.subscribed("", wanted))
        // After leaving a workspace nothing is wanted: nothing is handled.
        assertFalse(RealtimeRules.subscribed("user:me", emptySet()))
    }

    // ---- muted skwods do not ring, on screen or not ----

    @Test fun aMutedSkwodDoesNotRingWhicheverSkwodIsOnScreen() {
        val ring = Ring("s", "c", "u", "r1", 0)
        val found = listOf("current" to ring, "other-muted" to ring.copy(ringId = "r2"), "other" to ring.copy(ringId = "r3"))
        val audible = RingMute.audible(found) { it != "other-muted" }
        assertEquals(listOf("current", "other"), audible.map { it.first })
        // Only the muted skwod rings: nothing is presented, and it is not offered as a choice.
        val onlyMuted = RingMute.audible(listOf("other-muted" to ring)) { false }
        assertTrue(RingPolicy.decide(onlyMuted, 1_000) is RingPolicy.Decision.None)
        // A muted skwod next to one that rings does not turn it into "Who's calling?".
        val one = RingMute.audible(listOf("other-muted" to ring, "other" to ring)) { it == "other" }
        assertEquals(RingPolicy.Decision.Single("other", ring), RingPolicy.decide(one, 1_000))
        // The per-skwod rule itself: a muted skwod silences calls, a muted conversation does not.
        assertFalse(MuteList.parse("""{"skwod":-1}""").callsRing(5))
        assertTrue(MuteList.parse("""{"dm:x":-1}""").callsRing(5))
    }

    @Test fun aNoticeKeepsItsTextButNotItsActionAfterASwitch() {
        val plain = SecurityAlert("Update required", "…")
        val acting = SecurityAlert("Safety number changed", "…", NoticeAction.AcceptDevices("user-in-a"))
        val after = NoticeRules.afterSwitch(listOf(plain, acting))
        // Nothing is dropped; "Accept devices" can no longer run against another skwod's client.
        assertEquals(listOf("Update required", "Safety number changed"), after.map { it.title })
        assertTrue(after.all { it.action == null })
    }

    // ---- the mute rule: a missed real call is worse than an extra ring ----

    @Test fun onlyAWholeSkwodMuteSilencesAndOnlyWhenEveryCandidateIsMuted() {
        val skwodMuted = MuteList.parse("""{"skwod":-1}""")
        val conversationMuted = MuteList.parse("""{"dm:x":-1,"channel:y":-1}""")
        val nothing = MuteList()
        // The skwod cannot be told apart: silenced only if EVERY candidate is whole-skwod muted.
        assertTrue(RingMute.silenced(listOf(skwodMuted, skwodMuted), 5))
        assertFalse(RingMute.silenced(listOf(skwodMuted, nothing), 5))
        assertFalse(RingMute.silenced(listOf(skwodMuted, conversationMuted), 5))
        // No candidates is not "all muted".
        assertFalse(RingMute.silenced(emptyList(), 5))
        // Mutes that could not be read count as NOT muted.
        assertFalse(RingMute.silenced(listOf(skwodMuted, null), 5))
        assertTrue(RingMute.rings(null, 5))
        assertTrue(RingMute.rings(MuteList.parse("not json"), 5))
        assertFalse(RingMute.rings(skwodMuted, 5))
        // A per-conversation mute silences that conversation and nothing else: not a call, not
        // another conversation.
        assertTrue(RingMute.rings(conversationMuted, 5))
        assertTrue(conversationMuted.isMuted("dm:x", 5))
        assertFalse(conversationMuted.isMuted("dm:other", 5))
        // An expired skwod mute silences nothing.
        assertTrue(RingMute.rings(MuteList(mapOf("skwod" to 4L)), 5))
    }

    // ---- A6: an answer that outlives a workspace switch ----

    @Test fun anAnswerIsFiledOnlyUnderTheBindingThatWasAsked() {
        val a = BoundClient("ws-a", "client-a")
        val aAgain = BoundClient("ws-a", "client-a")      // the same workspace, bound again
        val b = BoundClient("ws-b", "client-b")
        assertTrue(Asked.holds(a, a))
        assertFalse(Asked.holds(a, b))
        assertFalse(Asked.holds(a, aAgain))
        assertFalse(Asked.holds(a, null))
        assertFalse(Asked.holds<BoundClient<String>>(null, null))
    }

    // ---- A17: a failed read is not an empty store ----

    @Test fun aStoreThatWasNotReadIsNeverWritten() {
        val gate = ReadGate()
        assertFalse(gate.mayWrite("ws-a"))
        gate.read("ws-a")
        assertTrue(gate.mayWrite("ws-a"))
        assertFalse(gate.mayWrite("ws-b"))               // another workspace's store was not read
        assertFalse(gate.mayWrite(null))
        gate.reset()
        assertFalse(gate.mayWrite("ws-a"))
    }

    // ---- A12: the lock's own settings ----

    @Test fun weakeningTheAppLockNeedsTheOwner() {
        assertTrue(LockSettings.needsAuthentication(fromMinutes = 1, toMinutes = 60))
        assertTrue(LockSettings.needsAuthentication(0, 1))
        assertFalse(LockSettings.needsAuthentication(60, 0))
        assertFalse(LockSettings.needsAuthentication(5, 5))
    }

    // ---- A14: the decrypted-attachment cache ----

    @Test fun aCachedAttachmentIsNeverReturnedForAnotherDescriptor() {
        val mine = AttachmentCache.fileName("blob-1", "photo.jpg", "digestA", "keyA")!!
        assertEquals(mine, AttachmentCache.fileName("blob-1", "photo.jpg", "digestA", "keyA"))
        // Same blob id and name, another digest or key: another file.
        assertFalse(mine == AttachmentCache.fileName("blob-1", "photo.jpg", "digestB", "keyA"))
        assertFalse(mine == AttachmentCache.fileName("blob-1", "photo.jpg", "digestA", "keyB"))
        assertFalse(mine == AttachmentCache.fileName("blob-1", "photo.jpg", null, "keyA"))
        // The sender's blob id and name never shape the path.
        assertNull(AttachmentCache.fileName("../blob", "photo.jpg", "d", "k"))
        val odd = AttachmentCache.fileName("blob-1", "../../etc/passwd", "d", "k")!!
        assertFalse(odd.contains("/")); assertTrue(odd.startsWith("blob-1-"))
    }

    // ---- A15: someone else's pictures ----

    @Test fun inboundPicturesAreOnlyKnownFormatsOfABoundedSize() {
        assertTrue(SafeImage.inboundFormat(SafeImage.Format.JPEG))
        assertTrue(SafeImage.inboundFormat(SafeImage.Format.HEIF))
        assertFalse(SafeImage.inboundFormat(SafeImage.Format.OTHER))
        // A BMP / ICO / anything unrecognised is OTHER by its own header.
        assertEquals(SafeImage.Format.OTHER, SafeImage.sniff(byteArrayOf('B'.code.toByte(), 'M'.code.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
        assertTrue(SafeImage.plausibleInbound(4096, 4096))
        assertTrue(SafeImage.plausibleInbound(6000, 6000))
        assertFalse(SafeImage.plausibleInbound(8000, 8000))      // 64 MP: fine for my own photo, not auto-decoded for someone else's
        assertTrue(SafeImage.plausible(8000, 8000))
        assertFalse(SafeImage.plausibleInbound(0, 10))
    }

    // ---- A11: every approval goes through the waiting room's name check ----

    @Test fun aJoinRequestIsLetInOnlyWhenItsNameChecksOut() {
        val known = listOf("alice-id" to "alice")
        fun entry(id: String, name: String, lookup: WaitingTrust.Lookup) =
            WaitingMember(id, name, WaitingMember.Source.REQUEST, trust = WaitingTrust.assess(id, name, lookup, known))
        assertTrue(entry("bob-id", "bob", WaitingTrust.Lookup.Found("bob-id")).canLetIn)
        // A look-alike of someone known, a name that leads elsewhere, an entry nobody checked.
        assertFalse(entry("mallory-id", "alice", WaitingTrust.Lookup.Found("mallory-id")).canLetIn)
        assertFalse(entry("bob-id", "bob", WaitingTrust.Lookup.Found("someone-else")).canLetIn)
        assertFalse(WaitingMember("bob-id", "bob", WaitingMember.Source.REQUEST).canLetIn)
    }

    // ---- A8: reactions ----

    @Test fun aThirdAccountsReactionIsNotShownInAOneToOneChat() {
        val peers = listOf("peer")
        assertTrue(ReactionRules.counts("peer", "me", peers))
        assertTrue(ReactionRules.counts("me", "me", peers))
        assertTrue(ReactionRules.counts("__me__", "me", peers))
        assertFalse(ReactionRules.counts("outsider", "me", peers))
        assertFalse(ReactionRules.counts("", "me", peers))
        assertFalse(ReactionRules.counts(null, "me", peers))
        // A group: its stored members, nobody else.
        assertTrue(ReactionRules.counts("b", "me", listOf("a", "b")))
        assertFalse(ReactionRules.counts("c", "me", listOf("a", "b")))
    }

    // ---- A7: a tapped link dials nobody ----

    @Test fun aLinkThatWasOnlyOpenedDoesNotDialItsHost() {
        val link = "skwod://join/abcdefgh#code"
        // Prefilled from a tapped link / scan / clipboard, untouched: nothing is dialed.
        assertFalse(InviteDial.mayDial(link, adopted = link, knownHost = false))
        assertFalse(InviteDial.mayDial(" $link ", adopted = link, knownHost = false))
        // The user typed or changed the field themselves.
        assertTrue(InviteDial.mayDial(link, adopted = null, knownHost = false))
        assertTrue(InviteDial.mayDial(link + "x", adopted = link, knownHost = false))
        // A skwod this device is already in learns nothing new from being asked.
        assertTrue(InviteDial.mayDial(link, adopted = link, knownHost = true))
    }

    // ---- A4: member names on channel / call surfaces follow the contact book ----

    @Test fun aServerSuppliedMemberNameIsNeverShownAsItCame() {
        val book = mapOf("alice-id" to Contact("alice-id", "alice", TrustLevel.KNOWN))
        val roster = mapOf("alice-id" to "alice", "bob-id" to "bob")
        val others = ContactTrust.CollisionSet.of(book, roster)
        // The server swaps the names: Alice (pinned) is still Alice…
        val alice = ContactTrust.display("alice-id", "bob", book, others)
        assertEquals("alice", MemberLabel.of(alice, "alice-id"))
        // …and Bob, relabelled "alice", is flagged — never shown as her.
        val bob = ContactTrust.display("bob-id", "alice", book, others, WaitingTrust.Lookup.Found("bob-id"))
        assertEquals("alice (possible impersonation)", MemberLabel.of(bob, "bob-id"))
        // A name that is only the server's claim carries its marker.
        val carol = ContactTrust.display("carol-id", "carol", book, others, WaitingTrust.Lookup.Found("carol-id"))
        assertEquals("carol (unverified)", MemberLabel.of(carol, "carol-id"))
        // No name at all: a short id, not a blank.
        val nobody = ContactTrust.display("dave-id-123", null, book, others)
        assertEquals("A member (dave-i…)", MemberLabel.of(nobody, "dave-id-123"))
        assertEquals("Member", MemberLabel.of(nobody, ""))
    }

    // ---- C8a: what a lock screen can show ----

    @Test fun withAppLockOrHiddenPreviewsOnlyTheGenericFormIsEverPosted() {
        val locked = NotifyPolicy.shape("Dana", "meet me at 8", "dm:c1", appLockEnabled = true)
        assertEquals(NotifyPolicy.Shape(NotifyPolicy.GENERIC_TITLE, NotifyPolicy.GENERIC_TEXT, NotifyPolicy.GENERIC_TOPIC), locked)
        val hidden = NotifyPolicy.shape("Dana", "meet me at 8", "dm:c1", appLockEnabled = false, hidePreviews = true)
        assertEquals(NotifyPolicy.GENERIC_TITLE, hidden.title); assertEquals(NotifyPolicy.GENERIC_TEXT, hidden.text)
        // The decision is the persisted setting's, not "locked right now".
        assertTrue(NotifyPolicy.redacted(hidePreviews = false, appLockEnabled = true, lockedNow = false))
        assertFalse(NotifyPolicy.redacted(hidePreviews = false, appLockEnabled = false, lockedNow = true))
    }

    // ---- C8b: announced once, by message id, across restarts ----

    @Test fun aMessageIsAnnouncedOnceAlsoAfterARestart() {
        val first = AnnouncedLedger()
        assertTrue(first.announce("m-future", sure = true))
        assertFalse(first.announce("m-future", sure = true))
        assertTrue(first.dirty)
        val stored = first.encode()
        assertFalse(first.dirty)
        // The process restarts; the server still dates the message in the future, so it passes
        // every timestamp check again — the ledger is what stops it.
        val restarted = AnnouncedLedger.decode(stored)
        assertFalse(restarted.announce("m-future", sure = true))
        assertTrue(restarted.announce("m-new", sure = true))
    }

    @Test fun unsureIdsCannotEvictAnnouncedOnes() {
        val ledger = AnnouncedLedger(maxAnnounced = 4, maxUnsure = 3)
        assertTrue(ledger.announce("real-1", sure = true))
        assertTrue(ledger.announce("real-2", sure = true))
        // A server floods ids nothing could be decrypted for, and ones only noted as skipped.
        for (i in 0 until 500) { ledger.announce("junk-$i", sure = false); ledger.skip("skip-$i") }
        assertEquals(2, ledger.announcedCount)
        assertEquals(3, ledger.unsureCount)
        assertFalse(ledger.announce("real-1", sure = true))
        assertFalse(ledger.announce("real-2", sure = true))
        // …and it survives being stored.
        val again = AnnouncedLedger.decode(ledger.encode(), maxAnnounced = 4, maxUnsure = 3)
        assertFalse(again.announce("real-1", sure = true))
        assertEquals(3, again.unsureCount)
    }

    @Test fun theLedgerIsBoundedAndKeepsWhatIsStillSeen() {
        val ledger = AnnouncedLedger(maxAnnounced = 3, maxUnsure = 2)
        assertTrue(ledger.announce("future", sure = true))
        for (i in 0 until 10) {
            assertTrue(ledger.announce("m-$i", sure = true))
            // The future-dated message is still in the channel's window at every catch-up.
            assertFalse(ledger.announce("future", sure = true))
        }
        assertEquals(3, ledger.announcedCount)
        assertFalse(ledger.announce("future", sure = true))
        assertTrue(ledger.announce("m-0", sure = true))      // long evicted, and not seen since
    }

    @Test fun skippedAndUnusableIdsAreNeverAnnounced() {
        val ledger = AnnouncedLedger()
        ledger.skip("own-copy")
        assertFalse(ledger.announce("own-copy", sure = true))
        // An id that cannot be remembered would be announced on every pass: it never is.
        assertFalse(ledger.announce("", sure = true))
        assertFalse(ledger.announce("x".repeat(129), sure = true))
        assertEquals(1, ledger.announcedCount)        // only "own-copy", now known to be real
        // A generic notice for something not decrypted yet becomes a real entry once it is.
        assertTrue(ledger.announce("late", sure = false))
        assertFalse(ledger.announce("late", sure = true))
        assertEquals(2, ledger.announcedCount)
    }

    @Test fun aDamagedOrMissingLedgerStartsEmptyAndDropsNothingElse() {
        assertTrue(AnnouncedLedger.decode(null).announce("a", sure = true))
        assertTrue(AnnouncedLedger.decode("not json").announce("a", sure = true))
        val l = AnnouncedLedger.decode("""{"a":["x","", 5],"u":["y","x"]}""")
        assertFalse(l.announce("x", sure = true))
        assertFalse(l.announce("y", sure = true))
    }
}
