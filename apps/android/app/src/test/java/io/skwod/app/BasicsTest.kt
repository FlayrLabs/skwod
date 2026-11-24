package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The small decisions behind build 43b: what notifies, rings, sessions, joins, uploads, history. */
class BasicsTest {
    private val stx = "\u0002"

    // ---- notifications: only real chat from someone else ----

    @Test fun plumbingNeverNotifies() {
        for (kind in listOf("game", "like", "comment", "avatar", "addr", "sys")) {
            assertFalse(kind, NotifyPolicy.notifies("${stx}skwod/$kind|{\"x\":1}"))
            assertFalse(kind, NotifyPolicy.notifies("skwod/$kind|{}"))                 // with or without the STX
            assertFalse(kind, NotifyPolicy.shouldNotify("${stx}skwod/$kind|{}", "u-sam", "u-me", isDeleted = false))
            assertNull(kind, NotifyPolicy.preview("${stx}skwod/$kind|{}"))
        }
        assertFalse(NotifyPolicy.notifies(""))
    }

    @Test fun realChatFromSomeoneElseNotifies() {
        assertTrue(NotifyPolicy.shouldNotify("hello", "u-sam", "u-me", isDeleted = false))
        assertEquals("hello", NotifyPolicy.preview("hello"))
        assertTrue(NotifyPolicy.shouldNotify("${stx}skwod/attach|{}", "u-sam", "u-me", isDeleted = false))
        assertEquals("Sent an attachment", NotifyPolicy.preview("${stx}skwod/attach|{}"))
        assertEquals("Shared a song", NotifyPolicy.preview("${stx}skwod/music|{}"))
        assertEquals("Posted to the feed", NotifyPolicy.preview("${stx}skwod/feed|{}"))
        // Text that merely mentions a tag is ordinary chat.
        assertTrue(NotifyPolicy.notifies("look: skwod/game|x"))
        assertNull(NotifyPolicy.tag("look: skwod/game|x"))
        assertEquals("skwod/game|", NotifyPolicy.tag("${stx}skwod/game|{}"))
        // Could not be decrypted yet: still a message from someone.
        assertTrue(NotifyPolicy.shouldNotify(null, "u-sam", "u-me", isDeleted = false))
    }

    @Test fun myOwnSystemAndDeletedMessagesNeverNotify() {
        assertFalse(NotifyPolicy.shouldNotify("hello", "u-me", "u-me", isDeleted = false))
        assertFalse(NotifyPolicy.shouldNotify("hello", "__me__", "u-me", isDeleted = false))
        // A row the core wrote itself is told by its FLAG — not by an author id or its text.
        assertFalse(NotifyPolicy.shouldNotify("hello", "u-sam", "u-me", isDeleted = false, isSystem = true))
        assertFalse(NotifyPolicy.shouldNotify("hello", "u-sam", "u-me", isDeleted = false, isUndecryptable = true))
        assertFalse(NotifyPolicy.shouldNotify("hello", null, "u-me", isDeleted = false))
        assertFalse(NotifyPolicy.shouldNotify("hello", "u-sam", "u-me", isDeleted = true))
        // The core has the last word when it is stricter.
        assertFalse(NotifyPolicy.shouldNotify("hello", "u-sam", "u-me", isDeleted = false) { false })
        // An unknown control-tagged body has nothing to show.
        assertNull(NotifyPolicy.preview("${stx}something-new"))
    }

    // ---- rings ----

    private fun ring(id: String, expires: Long, channel: String = "c-$id") = Ring("srv", channel, "u-sam", id, expires)

    @Test fun aRingPastItsDeadlineIsNeverShown() {
        assertTrue(RingPolicy.isLive(expiresAt = 2_000, now = 1_000))
        assertFalse(RingPolicy.isLive(expiresAt = 1_000, now = 1_000))
        assertFalse(RingPolicy.isLive(expiresAt = 500, now = 1_000))
        assertTrue(RingPolicy.isLive(expiresAt = 0, now = 1_000))                       // an old server gives no deadline
        assertEquals(45_000, RingPolicy.ringFor(0, 1_000, 45_000))
        assertEquals(9_000, RingPolicy.ringFor(10_000, 1_000, 45_000))                  // cut short by expires_at
        assertEquals(45_000, RingPolicy.ringFor(900_000, 1_000, 45_000))                // never longer than the app's cap
        assertEquals(0, RingPolicy.ringFor(500, 1_000, 45_000))
    }

    /** `expires_at` is the server's value: it may end a ring early, never stretch it past the app's own duration. */
    @Test fun aRingsDeadlineIsClampedToTheAppsOwnDuration() {
        val now = 1_000_000L; val cap = 45_000L
        assertEquals(now + 10_000, RingPolicy.clampExpiry(now + 10_000, now, cap))           // earlier than the cap: honoured
        assertEquals(now + cap, RingPolicy.clampExpiry(now + 3_600_000, now, cap))           // "rings for an hour": no
        assertEquals(now + cap, RingPolicy.clampExpiry(Long.MAX_VALUE, now, cap))
        assertEquals(now + cap, RingPolicy.clampExpiry(0, now, cap))                         // no deadline given: the app's own
        assertEquals(now - 5, RingPolicy.clampExpiry(now - 5, now, cap))                     // already over stays over
        assertEquals(cap, RingPolicy.ringFor(Long.MAX_VALUE, now, cap))
        assertEquals(0, RingPolicy.ringFor(now - 5, now, cap))
    }

    /** One skwod ringing → that call. Several → the user picks; `expires_at` never chooses. */
    @Test fun severalSkwodsRingingAsksTheUser() {
        val now = 10_000L
        assertTrue(RingPolicy.decide(emptyList<Pair<String, Ring>>(), now) is RingPolicy.Decision.None)
        assertTrue(RingPolicy.decide(listOf("a" to ring("old", 9_000)), now) is RingPolicy.Decision.None)
        val single = RingPolicy.decide(listOf("a" to ring("old", 9_000), "b" to ring("live", 30_000)), now)
        assertEquals(RingPolicy.Decision.Single("b", ring("live", 30_000)), single)
        // Two rings on the SAME skwod are still one skwod: the first one listed, no picker.
        val same = RingPolicy.decide(listOf("b" to ring("r1", 20_000), "b" to ring("r2", 99_000)), now) as RingPolicy.Decision.Single
        assertEquals("r1", same.ring.ringId)
        // Two skwods: a picker with both, in the order asked — a far-future expires_at wins nothing.
        val both = RingPolicy.decide(listOf("a" to ring("soon", 12_000), "b" to ring("claims-forever", Long.MAX_VALUE), "c" to ring("dead", 1)), now)
        both as RingPolicy.Decision.Ambiguous
        assertEquals(listOf("a", "b"), both.choices.map { it.first })
        val swapped = RingPolicy.decide(listOf("b" to ring("claims-forever", Long.MAX_VALUE), "a" to ring("soon", 12_000)), now) as RingPolicy.Decision.Ambiguous
        assertEquals(listOf("b", "a"), swapped.choices.map { it.first })
    }

    @Test fun ringCancelEndsOnlyTheRingItNames() {
        val current = ring("r1", 30_000, channel = "voice-1")
        assertTrue(RingPolicy.cancels(current, "voice-1", "r1"))
        assertFalse(RingPolicy.cancels(current, "voice-1", "r2"))                       // a different ring on the same channel
        assertTrue(RingPolicy.cancels(current, "voice-1", null))                        // "answered elsewhere" names no ring
        assertFalse(RingPolicy.cancels(current, "voice-2", null))
        assertFalse(RingPolicy.cancels(null, "voice-1", "r1"))
        assertTrue(RingPolicy.cancels(Ring("srv", "", "", "", 0), "", null, serverId = "srv"))
    }

    // ---- sessions ----

    @Test fun aWeekOldTokenIsRotated() {
        val day = 24L * 60 * 60 * 1000
        val now = 100 * day
        assertFalse(SessionPolicy.shouldRotate(now - 6 * day, now))
        assertTrue(SessionPolicy.shouldRotate(now - 7 * day, now))
        assertTrue(SessionPolicy.shouldRotate(now - 40 * day, now))
        assertTrue(SessionPolicy.shouldRotate(0, now))                                  // stored before the date was kept
        assertTrue(SessionPolicy.shouldRotate(now + day, now))                          // the clock went backwards
        assertFalse(SessionPolicy.shouldRotate(now, now))
    }

    @Test fun backoffDoublesAndIsCapped() {
        assertEquals(listOf(2_000L, 4_000L, 8_000L, 16_000L, 30_000L, 30_000L), Backoff.delays(6, 2_000, 30_000))
        assertTrue(Backoff.delays(0, 1_000, 5_000).isEmpty())
        assertEquals(40, Backoff.delays(40, 1_000, 60_000).size)
        assertTrue(Backoff.delays(40, 1_000, 60_000).all { it in 1_000..60_000 })
    }

    // ---- uploads ----

    @Test fun anUploadRefusalShowsTheServersSentence() {
        val quota = """{"error":"You have used all 2 GB of your storage here."}"""
        assertEquals("You have used all 2 GB of your storage here.", BlobErrors.message(413, BlobErrors.errorField(quota)))
        assertEquals("The host's disk is nearly full.", BlobErrors.message(507, BlobErrors.errorField("""{"error":"The host's disk is nearly full."}""")))
        assertEquals("Join a server first.", BlobErrors.message(403, BlobErrors.errorField("""{"error":"Join a server first."}""")))
        // No (or an unreadable) body: still a specific sentence, never the generic one.
        for (status in listOf(403, 413, 507, 429)) {
            assertFalse("$status", BlobErrors.message(status, BlobErrors.errorField("<html>")) == BlobErrors.GENERIC)
        }
        assertEquals(BlobErrors.GENERIC, BlobErrors.message(500, null))
        assertEquals(BlobErrors.GENERIC, BlobErrors.message(0, null))
        assertNull(BlobErrors.errorField(null)); assertNull(BlobErrors.errorField("")); assertNull(BlobErrors.errorField("{}"))
    }

    @Test fun aDmAttachmentCarriesItsDownloadToken() {
        val a = ChatAttachment("a.jpg", "image/jpeg", 10, "image", "blob-1", "a2V5", null, null, "ZGlnZXN0", token = "tok-123")
        val back = ChatAttachment.fromJson(a.toJson())!!
        assertEquals("tok-123", back.token)
        assertEquals(a, back)
        // A channel attachment has none, and its JSON does not mention one.
        val channel = a.copy(token = null)
        assertFalse(channel.toJson().contains("token"))
        assertNull(ChatAttachment.fromJson(channel.toJson())!!.token)
        assertNull(ChatAttachment.fromJson("""{"name":"a","mime":"m","size":1,"kind":"file","blobId":"b","keyB64":"k","token":""}""")!!.token)
    }

    // ---- invites ----

    @Test fun aDeadInviteIsReportedBeforeSignup() {
        assertNull(InviteProblems.message(valid = true, reason = null))
        assertTrue(InviteProblems.message(false, "expired")!!.contains("expired"))
        assertTrue(InviteProblems.message(false, "used")!!.contains("used"))
        assertTrue(InviteProblems.message(false, "unknown")!!.contains("doesn't know"))
        assertTrue(InviteProblems.message(false, null) != null)
    }

    // ---- a join survives a relaunch ----

    private val now = 1_800_000_000_000L
    private fun record(code: String = "SKWD-ABCD-EFGH", workspace: String = "ws-1", stage: PendingJoinRecord.Stage = PendingJoinRecord.Stage.NOT_SENT, server: String? = null, at: Long = now) =
        PendingJoinRecord(workspace, "skwod://join/abc", "sam", code, server, stage, at)

    @Test fun pendingJoinsRoundTrip() {
        val list = listOf(record(), record("tok_en-2", stage = PendingJoinRecord.Stage.REQUESTED, server = "srv-9"), record("c3", workspace = "", stage = PendingJoinRecord.Stage.ADMITTED))
        assertEquals(list, PendingJoinCodec.decode(PendingJoinCodec.encode(list), now + 1000))
        assertTrue(PendingJoinCodec.decode(PendingJoinCodec.encode(emptyList()), now).isEmpty())
    }

    @Test fun malformedOrStalePendingJoinsAreDropped() {
        assertTrue(PendingJoinCodec.decode(null, now).isEmpty())
        assertTrue(PendingJoinCodec.decode("not json", now).isEmpty())
        assertTrue(PendingJoinCodec.decode("""[{"code":"bad code!","address":"x","createdAt":$now}]""", now).isEmpty())
        assertTrue(PendingJoinCodec.decode("""[{"code":"ok","address":"","createdAt":$now}]""", now).isEmpty())
        assertTrue(PendingJoinCodec.decode("""[42, {"code":"ok","address":"x"}]""", now).isEmpty())           // no date
        val old = PendingJoinCodec.encode(listOf(record(at = now - PendingJoinCodec.MAX_AGE_MS - 1)))
        assertTrue(PendingJoinCodec.decode(old, now).isEmpty())
        // An unknown stage falls back to "not sent" (the code is presented again), not dropped.
        val odd = PendingJoinCodec.decode("""[{"code":"ok","address":"x","stage":"NEW_STAGE","createdAt":$now}]""", now)
        assertEquals(PendingJoinRecord.Stage.NOT_SENT, odd.single().stage)
    }

    @Test fun aJoinStartedBeforeTheAccountExistedIsBoundToIt() {
        val unbound = record(workspace = "")
        val other = record("other", workspace = "").copy(username = "rita")
        val bound = PendingJoinCodec.bound(listOf(unbound, other), "skwod://join/abc", "sam", "ws-7")
        assertEquals("ws-7", bound[0].workspaceId)
        assertEquals("", bound[1].workspaceId)                                           // someone else's sign-up
        assertEquals(listOf(unbound, other), PendingJoinCodec.bound(listOf(unbound, other), "https://elsewhere", "sam", "ws-7"))
        // One record per (workspace, code).
        val updated = PendingJoinCodec.upsert(listOf(record()), record(stage = PendingJoinRecord.Stage.REQUESTED, server = "srv"))
        assertEquals(1, updated.size); assertEquals(PendingJoinRecord.Stage.REQUESTED, updated[0].stage)
        assertEquals(2, PendingJoinCodec.upsert(listOf(record()), record("another")).size)
    }

    // ---- history ----

    @Test fun olderPagesGoInFrontAndTheLiveWindowWins() {
        data class M(val id: String, val at: Long, val text: String = "")
        val fresh = listOf(M("c", 30), M("d", 40, "edited"))
        assertEquals(fresh, HistoryWindow.merge(emptyList(), fresh, { it.id }, { it.at }))
        val older = listOf(M("a", 10), M("b", 20), M("d", 40, "stale"), M("a", 10))
        val merged = HistoryWindow.merge(older, fresh, { it.id }, { it.at })
        assertEquals(listOf("a", "b", "c", "d"), merged.map { it.id })
        assertEquals("edited", merged.last().text)
        assertEquals("That message is too big to send.", HistoryWindow.sendError("That message is too big to send.", "x"))
        assertEquals("Couldn't send — try again.", HistoryWindow.sendError(null, "Couldn't send — try again."))
        assertEquals("fallback", HistoryWindow.sendError("  ", "fallback"))
    }

    // ---- one name-trust model: the contact book ----

    private val bookOfFriends = ContactTrust.record(ContactTrust.record(emptyMap(), "u-merhan", "merhan", TrustLevel.KNOWN), "u-rita", "rita", TrustLevel.VERIFIED)

    /** Member list + findUser + listDms may all agree: it is still only the server's word. */
    @Test fun aServerOnlyNameIsNeverShownAsTrusted() {
        // Nothing in the book: whatever the server claims is UNVERIFIED.
        // Even with the directory agreeing (findUser returns this very account).
        val claimed = ContactTrust.display("u-sam", "sam", bookOfFriends, lookup = WaitingTrust.Lookup.Found("u-sam"))
        assertEquals("sam", claimed.name); assertEquals(TrustLevel.UNVERIFIED, claimed.level)
        assertEquals(ContactTrust.Flag.NONE, claimed.flag)
        assertTrue(claimed.unverified); assertFalse(claimed.trusted); assertEquals("sam (unverified)", claimed.label)
        assertFalse(claimed.warning!!.second)
        // Recording server claims (member list, then a matching findUser, then listDms) changes nothing about the level.
        var book = bookOfFriends
        repeat(3) { book = ContactTrust.record(book, "u-sam", "sam", TrustLevel.UNVERIFIED) }
        assertEquals(TrustLevel.UNVERIFIED, book["u-sam"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, ContactTrust.display("u-sam", "sam", book, lookup = WaitingTrust.Lookup.Found("u-sam")).level)
        // Being an accepted member of a shared server does not raise a member's own level either.
        val roster = ContactTrust.CollisionSet.of(bookOfFriends, mapOf("u-sam" to "sam"))
        val member = ContactTrust.display("u-sam", "sam", bookOfFriends, roster, WaitingTrust.Lookup.Found("u-sam"))
        assertEquals(TrustLevel.UNVERIFIED, member.level); assertFalse(member.trusted); assertEquals("sam (unverified)", member.label)
        // A server claim never renames or demotes someone the user pinned or verified.
        assertEquals(bookOfFriends, ContactTrust.record(bookOfFriends, "u-merhan", "someone-else", TrustLevel.UNVERIFIED))
        assertEquals("merhan", ContactTrust.display("u-merhan", "someone-else", bookOfFriends).name)
        assertEquals("rita", ContactTrust.display("u-rita", "eve", bookOfFriends).name)
        // No name at all.
        assertEquals(ContactTrust.UNKNOWN, ContactTrust.display("u-x", null, bookOfFriends).name)
        assertEquals(ContactTrust.UNKNOWN, ContactTrust.display("u-x", "\u200B", bookOfFriends).name)
    }

    /** THE ATTACK: a ghost account under a (look-alike of a) known contact's name. */
    @Test fun aLookAlikeOfAKnownContactGetsTheStrongWarning() {
        for (name in listOf("merhan", "Merhan", "m\u0435rhan", "mer\u200Bhan", "\uFF4D\uFF45\uFF52\uFF48\uFF41\uFF4E", "rnerhan", "r1ta")) {
            val shown = ContactTrust.display("u-ghost", name, bookOfFriends)
            assertTrue(name, shown.impersonation); assertFalse(name, shown.trusted)
            assertTrue(name, shown.warning!!.second)
            assertTrue(name, shown.label.contains("impersonation"))
        }
        // The real contacts are not imitating themselves.
        assertFalse(ContactTrust.display("u-merhan", "merhan", bookOfFriends).impersonation)
        assertTrue(ContactTrust.display("u-merhan", null, bookOfFriends).trusted)
        // An UNVERIFIED entry protects nobody: only KNOWN / VERIFIED names are collided with.
        val claims = ContactTrust.record(emptyMap(), "u-a", "sam", TrustLevel.UNVERIFIED)
        assertFalse(ContactTrust.display("u-b", "sam", claims).impersonation)
        // An explicit action cannot pin a second "merhan": it stays unverified, with the warning.
        val tried = ContactTrust.record(bookOfFriends, "u-ghost", "merhan", TrustLevel.KNOWN)
        assertEquals(TrustLevel.UNVERIFIED, tried["u-ghost"]!!.level)
        assertTrue(ContactTrust.display("u-ghost", null, tried).impersonation)
        assertEquals(TrustLevel.KNOWN, tried["u-merhan"]!!.level)
    }

    /** The regression: an accepted member the user has NEVER messaged must not be imitable either. */
    @Test fun aLookAlikeOfAnAcceptedMemberYouNeverMessagedGetsTheStrongWarning() {
        // "olivia" is only a roster-approved member of a shared server: not in the contact book at all.
        val others = ContactTrust.CollisionSet.of(bookOfFriends, mapOf("u-olivia" to "olivia", "u-me" to "ahmed"))
        for (name in listOf("olivia", "0livia", "ol\u0456via", "oli\u200Bvia", "OLIVIA", "ahmed")) {
            // Even when the (hostile) directory says the name is the ghost's own.
            val shown = ContactTrust.display("u-ghost", name, bookOfFriends, others, WaitingTrust.Lookup.Found("u-ghost"))
            assertEquals(name, ContactTrust.Flag.IMPERSONATION, shown.flag)
            assertTrue(name, shown.strong && shown.warning!!.second && !shown.trusted)
        }
        assertTrue(ContactTrust.collides("u-ghost", "0livia", emptyMap(), mapOf("u-olivia" to "olivia")))
        // Olivia herself is not flagged for her own name — and is still only UNVERIFIED.
        val herself = ContactTrust.display("u-olivia", "olivia", bookOfFriends, others, WaitingTrust.Lookup.Found("u-olivia"))
        assertEquals(ContactTrust.Flag.NONE, herself.flag); assertEquals(TrustLevel.UNVERIFIED, herself.level)
        // Without the roster in the set, the same ghost would have slipped through.
        assertEquals(ContactTrust.Flag.NONE, ContactTrust.display("u-ghost", "olivia", bookOfFriends, ContactTrust.CollisionSet.of(bookOfFriends), WaitingTrust.Lookup.Found("u-ghost")).flag)
        // And an explicit action cannot pin a look-alike of a member as KNOWN.
        assertEquals(TrustLevel.UNVERIFIED, ContactTrust.record(bookOfFriends, "u-ghost", "0livia", TrustLevel.KNOWN, others)["u-ghost"]!!.level)
        assertEquals(TrustLevel.KNOWN, ContactTrust.record(bookOfFriends, "u-olivia", "olivia", TrustLevel.KNOWN, others)["u-olivia"]!!.level)
    }

    /** Non-ASCII or invisible characters are a strong warning by themselves — no collision needed. */
    @Test fun anUnusualCharacterNameIsFlaggedWithNoCollisionAtAll() {
        val nobody = ContactTrust.CollisionSet.EMPTY
        for (name in listOf("z\u043Ee", "zo\u200Be", "\uFF5A\uFF4F\uFF45", "zo\u00EB", "zoe\u202E")) {
            val shown = ContactTrust.display("u-new", name, emptyMap(), nobody, WaitingTrust.Lookup.Found("u-new"))
            assertEquals(name, ContactTrust.Flag.UNUSUAL, shown.flag)
            assertTrue(name, shown.strong && shown.warning!!.second)
            assertTrue(name, shown.label.contains("unusual characters"))
        }
        assertEquals(ContactTrust.Flag.NONE, ContactTrust.display("u-new", "zoe_2", emptyMap(), nobody, WaitingTrust.Lookup.Found("u-new")).flag)
        // Such a name cannot be pinned as KNOWN either; a verified contact (checked by keys) is exempt.
        assertEquals(TrustLevel.UNVERIFIED, ContactTrust.record(emptyMap(), "u-new", "z\u043Ee", TrustLevel.KNOWN)["u-new"]!!.level)
        val verified = ContactTrust.record(emptyMap(), "u-new", "zo\u00EB", TrustLevel.VERIFIED)
        assertEquals(ContactTrust.Flag.NONE, ContactTrust.display("u-new", null, verified).flag)
    }

    /** `findUser(name)` must lead back to exactly this account, or the name is not shown unflagged. */
    @Test fun aServerClaimedNameWhoseLookupReturnsAnotherIdIsFlagged() {
        val other = ContactTrust.display("u-ghost", "sam", bookOfFriends, lookup = WaitingTrust.Lookup.Found("u-sam"))
        assertEquals(ContactTrust.Flag.MISMATCH, other.flag); assertTrue(other.strong)
        assertEquals("sam (doesn't match this account)", other.label)
        assertEquals(ContactTrust.Flag.MISMATCH, ContactTrust.display("u-ghost", "sam", bookOfFriends, lookup = WaitingTrust.Lookup.Nobody).flag)
        // The directory could not be asked, or has not answered yet: flagged, but not as an attack.
        for (lookup in listOf(WaitingTrust.Lookup.Failed, null)) {
            val unchecked = ContactTrust.display("u-sam", "sam", bookOfFriends, lookup = lookup)
            assertEquals(ContactTrust.Flag.UNCHECKED, unchecked.flag); assertFalse(unchecked.strong)
            assertEquals("sam (couldn't check)", unchecked.label); assertFalse(unchecked.warning!!.second)
        }
        // A matching lookup: no flag, the quiet "unverified" marker — and still never more than UNVERIFIED.
        val ok = ContactTrust.display("u-sam", "sam", bookOfFriends, lookup = WaitingTrust.Lookup.Found("u-sam"))
        assertEquals("sam (unverified)", ok.label); assertEquals(TrustLevel.UNVERIFIED, ok.level)
        // A name the user pinned needs no directory: a lookup answer (even a hostile one) changes nothing.
        assertEquals(ContactTrust.Flag.NONE, ContactTrust.display("u-merhan", "x", bookOfFriends, lookup = WaitingTrust.Lookup.Found("u-ghost")).flag)
        assertEquals(ContactTrust.Flag.NONE, ContactTrust.display("u-x", null, bookOfFriends, lookup = null).flag)          // no name at all
    }

    // ---- opening a conversation is not vouching for it ----

    private val withMembers = ContactTrust.CollisionSet.of(bookOfFriends, mapOf("u-olivia" to "olivia"))
    private fun matches(id: String) = WaitingTrust.Lookup.Found(id)

    @Test fun selectingAnExistingConversationChangesNoLevel() {
        // An inbound, server-named conversation is listed; its contact is a claim.
        val book = ContactTrust.record(bookOfFriends, "u-in", "nia", TrustLevel.UNVERIFIED)
        assertEquals(book, ContactTrust.onDmOpened(book, "u-in", "nia", alreadyListed = true, others = withMembers, lookup = matches("u-in")))
        // …also when the name is clean, also for a look-alike, also for someone already known or verified.
        assertEquals(book, ContactTrust.onDmOpened(book, "u-ghost", "merhan", alreadyListed = true, others = withMembers, lookup = matches("u-ghost")))
        assertEquals(book, ContactTrust.onDmOpened(book, "u-merhan", "merhan", alreadyListed = true, others = withMembers, lookup = matches("u-merhan")))
        assertEquals(book, ContactTrust.onDmOpened(book, "u-rita", "rita", alreadyListed = true, others = withMembers, lookup = null))
        assertEquals(TrustLevel.UNVERIFIED, book["u-in"]!!.level)
    }

    @Test fun startingADmWithAFlaggedPersonLeavesThemUnverified() {
        fun start(id: String, name: String, lookup: WaitingTrust.Lookup?) =
            ContactTrust.onDmOpened(bookOfFriends, id, name, alreadyListed = false, others = withMembers, lookup = lookup)
        // A look-alike of a known contact, and of an accepted member the user never messaged.
        for (name in listOf("merhan", "m\u0435rhan", "0livia", "r1ta")) {
            val book = start("u-ghost", name, matches("u-ghost"))
            assertEquals(name, TrustLevel.UNVERIFIED, book["u-ghost"]!!.level)
            assertTrue(name, ContactTrust.display("u-ghost", name, book, withMembers, matches("u-ghost")).strong)
        }
        // Unusual characters; a name the directory gives to another account; a name that could not be checked.
        assertEquals(TrustLevel.UNVERIFIED, start("u-new", "z\u043Ee", matches("u-new"))["u-new"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, start("u-new", "sam", matches("u-sam"))["u-new"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, start("u-new", "sam", WaitingTrust.Lookup.Nobody)["u-new"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, start("u-new", "sam", WaitingTrust.Lookup.Failed)["u-new"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, start("u-new", "sam", null)["u-new"]!!.level)
        // "I know them — accept" goes through the same gate: refused while any flag stands…
        val flagged = start("u-ghost", "merhan", matches("u-ghost"))
        assertEquals(flagged, ContactTrust.promote(flagged, "u-ghost", "merhan", withMembers, matches("u-ghost")))
        val unchecked = start("u-new", "sam", null)
        assertEquals(unchecked, ContactTrust.promote(unchecked, "u-new", "sam", withMembers, WaitingTrust.Lookup.Failed))
        // …and allowed once the name checks out.
        assertEquals(TrustLevel.KNOWN, ContactTrust.promote(unchecked, "u-new", "sam", withMembers, matches("u-new"))["u-new"]!!.level)
        // Nobody already trusted is touched by any of this.
        assertEquals(TrustLevel.KNOWN, flagged["u-merhan"]!!.level); assertEquals(TrustLevel.VERIFIED, flagged["u-rita"]!!.level)
    }

    @Test fun startingADmWithAnUnflaggedPersonMakesThemKnown() {
        val book = ContactTrust.onDmOpened(bookOfFriends, "u-sam", "sam", alreadyListed = false, others = withMembers, lookup = matches("u-sam"))
        assertEquals(Contact("u-sam", "sam", TrustLevel.KNOWN), book["u-sam"])
        assertTrue(ContactTrust.display("u-sam", "sam", book, withMembers).trusted)
        // An accepted member can be messaged under their own name (they are not imitating themself).
        val olivia = ContactTrust.onDmOpened(bookOfFriends, "u-olivia", "olivia", alreadyListed = false, others = withMembers, lookup = matches("u-olivia"))
        assertEquals(TrustLevel.KNOWN, olivia["u-olivia"]!!.level)
        // Starting a chat never lowers a verified contact.
        assertEquals(bookOfFriends, ContactTrust.onDmOpened(bookOfFriends, "u-rita", "rita", alreadyListed = false, others = withMembers, lookup = matches("u-rita")))
    }

    @Test fun verifyingPromotesToVerified() {
        var book = ContactTrust.record(emptyMap(), "u-sam", "sam", TrustLevel.UNVERIFIED)
        book = ContactTrust.record(book, "u-sam", "sam", TrustLevel.KNOWN)                      // the user accepted the contact
        assertEquals(TrustLevel.KNOWN, book["u-sam"]!!.level)
        assertTrue(ContactTrust.display("u-sam", "sam", book).trusted)
        assertNull(ContactTrust.display("u-sam", "sam", book).warning)
        book = ContactTrust.record(book, "u-sam", "whatever-the-server-says-now", TrustLevel.VERIFIED)
        assertEquals(Contact("u-sam", "sam", TrustLevel.VERIFIED, known = true), book["u-sam"])  // keeps the name the user had (and that they knew them)
        assertTrue(ContactTrust.display("u-sam", null, book).verified)
        // Recording a lower level later never lowers it…
        assertEquals(book, ContactTrust.record(book, "u-sam", "sam", TrustLevel.KNOWN))
        assertEquals(book, ContactTrust.record(book, "u-sam", "sam", TrustLevel.UNVERIFIED))
        // …only losing the verification does, and only down to KNOWN.
        assertEquals(TrustLevel.KNOWN, ContactTrust.unverify(book, "u-sam")["u-sam"]!!.level)
        assertEquals(bookOfFriends, ContactTrust.unverify(bookOfFriends, "u-merhan"))
        // Verifying someone straight from UNVERIFIED works too.
        assertEquals(TrustLevel.VERIFIED, ContactTrust.record(emptyMap(), "u-new", "nia", TrustLevel.VERIFIED)["u-new"]!!.level)
    }

    @Test fun oldEntriesBecomeUnverified() {
        // Stored without a level (or with one this build does not know): UNVERIFIED.
        val decoded = ContactTrust.decode("""[{"userId":"u-a","name":"abe"},{"userId":"u-b","name":"bea","level":"ADMIN"},{"userId":"u-c","name":"cy","level":"KNOWN"},{"name":"nobody"}]""")
        assertEquals(TrustLevel.UNVERIFIED, decoded["u-a"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, decoded["u-b"]!!.level)
        assertEquals(TrustLevel.KNOWN, decoded["u-c"]!!.level)
        assertEquals(3, decoded.size)
        assertTrue(ContactTrust.decode(null).isEmpty()); assertTrue(ContactTrust.decode("nonsense").isEmpty())
        assertEquals(bookOfFriends, ContactTrust.decode(ContactTrust.encode(bookOfFriends)))
        // Migrating the stored conversation list: only chats this device STARTED are KNOWN.
        val book = ContactTrust.migrate(listOf(
            ContactTrust.Legacy("u-merhan", "merhan", startedHere = true),
            ContactTrust.Legacy("u-in", "inbound_name", startedHere = false),
            ContactTrust.Legacy("u-ghost", "merhan", startedHere = false)))
        assertEquals(TrustLevel.KNOWN, book["u-merhan"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, book["u-in"]!!.level)
        assertEquals(TrustLevel.UNVERIFIED, book["u-ghost"]!!.level)
        assertTrue(ContactTrust.display("u-ghost", null, book).impersonation)
    }

    // ---- a conversation entry is bound to one peer for ever ----

    private fun entry(conv: String, peer: String, bound: Boolean = true) = DmBinding.Entry(conv, peer, bound)

    @Test fun reKeyingAConversationIsRefused() {
        val entries = listOf(entry("c1", "u-merhan"), entry("c2", "u-rita"))
        // The bound peer's own messages land in their entry.
        assertEquals(DmBinding.Route.Existing(0), DmBinding.route(entries, "c1", "u-merhan"))
        // Another sender inside c1 does NOT take the entry over: a new, separate entry.
        assertEquals(DmBinding.Route.New(split = true), DmBinding.route(entries, "c1", "u-ghost"))
        // …and once listed, that sender keeps their own entry; merhan's is untouched.
        val after = entries + entry("c1", "u-ghost")
        assertEquals(DmBinding.Route.Existing(2), DmBinding.route(after, "c1", "u-ghost"))
        assertEquals(DmBinding.Route.Existing(0), DmBinding.route(after, "c1", "u-merhan"))
        // A conversation nobody has an entry for.
        assertEquals(DmBinding.Route.New(split = false), DmBinding.route(entries, "c9", "u-sam"))
    }

    @Test fun aServerListedConversationBindsOnlyToItsOwnFirstSender() {
        // Known only from listDms (the row named u-merhan), no decrypted message yet: unbound.
        val listed = listOf(entry("c1", "u-merhan", bound = false))
        // The named account speaks first: now it is bound.
        assertEquals(DmBinding.Route.Bind(0), DmBinding.route(listed, "c1", "u-merhan"))
        // Someone ELSE speaks first: the row's entry is left alone, the sender gets their own —
        // a normal one (nothing was bound to anyone there).
        assertEquals(DmBinding.Route.New(split = false), DmBinding.route(listed, "c1", "u-ghost"))
        // A row that named nobody may be bound by its first sender.
        assertEquals(DmBinding.Route.Bind(0), DmBinding.route(listOf(entry("c1", "", bound = false)), "c1", "u-sam"))
        // The entry's identity carries the peer: same conversation id, two entries, two keys.
        assertTrue(DMConversation("merhan", "u-merhan", "", "c1").key != DMConversation("", "u-ghost", "", "c1", origin = DMConversation.ORIGIN_SPLIT).key)
        assertTrue(DMConversation("", "u-ghost", "", "c1", origin = DMConversation.ORIGIN_SPLIT).isSplit)
        assertFalse(DMConversation("merhan", "u-merhan", "", "c1").isSplit)
    }

    // ---- attachments: nothing unbounded is fetched ----

    private val mb = 1024L * 1024

    @Test fun anOversizedDescriptorIsRefusedBeforeFetching() {
        assertTrue(AttachmentLimits.acceptable(0))
        assertTrue(AttachmentLimits.acceptable(AttachmentLimits.MAX_BYTES))
        assertFalse(AttachmentLimits.acceptable(AttachmentLimits.MAX_BYTES + 1))
        assertFalse(AttachmentLimits.acceptable(-1))
        assertFalse(AttachmentLimits.acceptable(Long.MAX_VALUE))
        assertFalse(AttachmentLimits.acceptable(11 * mb, AttachmentLimits.AUTO_MAX_BYTES))
        assertEquals(100 * mb, AttachmentLimits.MAX_BYTES); assertEquals(10 * mb, AttachmentLimits.AUTO_MAX_BYTES)
        // The ciphertext allowance follows the DECLARED size, with room for padding + IV + MAC…
        assertTrue(AttachmentLimits.maxCiphertext(1000) in 1000 + 64..10_000)
        assertTrue(AttachmentLimits.maxCiphertext(10 * mb) in (10 * mb + 10 * mb / 20)..(12 * mb))
        // …and never beyond what the hard cap allows, whatever is declared.
        assertEquals(AttachmentLimits.maxCiphertext(AttachmentLimits.MAX_BYTES), AttachmentLimits.maxCiphertext(Long.MAX_VALUE))
        assertEquals(4096, AttachmentLimits.maxCiphertext(-5))
        // Content-Length: over the cap is refused; absent (-1) is allowed through to the bounded read.
        assertTrue(AttachmentLimits.contentLengthOk(500, 1000)); assertTrue(AttachmentLimits.contentLengthOk(1000, 1000))
        assertFalse(AttachmentLimits.contentLengthOk(1001, 1000)); assertTrue(AttachmentLimits.contentLengthOk(-1, 1000))
    }

    @Test fun theFeedNeverDownloadsUnaskedAndChatOnlySmallPictures() {
        fun auto(kind: String, size: Long, feed: Boolean, metered: Boolean) = AttachmentLimits.mayAutoDownload(kind, size, feed, metered)
        // The feed: NEVER, at any size, on any connection (a fetch would tell the host who viewed what).
        for (size in listOf(1L, 2 * mb, 10 * mb, 90 * mb)) for (metered in listOf(true, false)) {
            assertFalse("$size $metered", auto("image", size, feed = true, metered = metered))
        }
        // Chat: the small cap applies on a metered connection.
        assertFalse(auto("image", 11 * mb, feed = false, metered = true))
        assertTrue(auto("image", 5 * mb, feed = false, metered = true))
        assertTrue(auto("image", 11 * mb, feed = false, metered = false))
        // Never anything but a picture, never over the hard cap, never a nonsense size.
        for (kind in listOf("video", "audio", "file", "")) assertFalse(kind, auto(kind, 1000, feed = false, metered = false))
        assertFalse(auto("image", AttachmentLimits.MAX_BYTES + 1, feed = false, metered = false))
        assertFalse(auto("image", -1, feed = true, metered = false))
    }

    /** A stream that never ends (a missing or lying Content-Length) is cut off at the cap. */
    @Test fun aStreamLongerThanTheCapIsAbandoned() {
        class Endless : java.io.InputStream() {
            var served = 0L
            override fun read(): Int { served++; return 1 }
            override fun read(b: ByteArray, off: Int, len: Int): Int { served += len; return len }
        }
        val endless = Endless()
        try { AttachmentLimits.readBounded(endless, 1_000_000); org.junit.Assert.fail("read past the cap") }
        catch (e: AttachmentLimits.TooLarge) { assertEquals(1_000_000, e.limit) }
        assertTrue("stopped reading soon after the cap", endless.served <= 1_000_000 + 2 * 64 * 1024)
        // One byte over is over; exactly the cap, and anything shorter, is read whole.
        try { AttachmentLimits.readBounded(java.io.ByteArrayInputStream(ByteArray(1001)), 1000); org.junit.Assert.fail() } catch (_: AttachmentLimits.TooLarge) {}
        assertEquals(1000, AttachmentLimits.readBounded(java.io.ByteArrayInputStream(ByteArray(1000)), 1000).size)
        val data = ByteArray(200_000) { (it % 251).toByte() }
        assertTrue(data.contentEquals(AttachmentLimits.readBounded(java.io.ByteArrayInputStream(data), 1_000_000)))
        assertEquals(0, AttachmentLimits.readBounded(java.io.ByteArrayInputStream(ByteArray(0)), 10).size)
    }
}
