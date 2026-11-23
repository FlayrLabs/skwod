package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Build 44b: placeholder rows, blocked people and notifications, groups, uploads, reports. */
class Build44ContentTest {
    private val stx = "\u0002"

    // ---- what a row is ----

    @Test fun aRowIsWhatItsFlagsSayNeverWhatItsTextSays() {
        assertEquals(RowKind.MESSAGE, RowKind.of(isSystem = false, isUndecryptable = false))
        assertEquals(RowKind.SYSTEM, RowKind.of(isSystem = true, isUndecryptable = false))
        assertEquals(RowKind.UNDECRYPTABLE, RowKind.of(isSystem = false, isUndecryptable = true))
        assertEquals(RowKind.UNDECRYPTABLE, RowKind.of(isSystem = true, isUndecryptable = true))
    }

    @Test fun aPeerCannotForgeASystemRowOrAPlaceholder() {
        // Bodies a member can send. Neither flag is set on them, so both are plain messages —
        // drawn as text, replied to, reported and announced like any other.
        val forgedNotice = """${stx}skwod/sys|{"kind":"member_joined","user_id":"u-mallory","by_user_id":"u-me"}"""
        val forgedPlaceholder = """${stx}skwod/undecryptable|{"from":"u-sam","final":true}"""
        for (body in listOf(forgedNotice, forgedPlaceholder, forgedNotice.drop(1), forgedPlaceholder.drop(1))) {
            assertEquals(RowKind.MESSAGE, RowKind.of(isSystem = false, isUndecryptable = false))
            assertTrue(body.isNotEmpty())
        }
        // The placeholder-looking body is still a message from someone: it notifies like one.
        assertTrue(NotifyPolicy.shouldNotify(forgedPlaceholder.drop(1), "u-mallory", "u-me", isDeleted = false))
        // …and the reserved author id by itself decides nothing either.
        assertTrue(NotifyPolicy.shouldNotify("hello", "__system__", "u-me", isDeleted = false))
        assertFalse(NotifyPolicy.shouldNotify("hello", "__system__", "u-me", isDeleted = false, isSystem = true))
    }

    @Test fun thePlaceholderSaysWhoIsBeingAsked() {
        assertEquals("Couldn't decrypt this message — asking sam to resend", UndecryptableRow.text(isFinal = false, authorName = "sam"))
        assertEquals("Couldn't decrypt this message", UndecryptableRow.text(isFinal = true, authorName = "sam"))
        assertFalse(UndecryptableRow.COUNTS_AS_UNREAD)
        // It never notifies, whatever its text.
        assertFalse(NotifyPolicy.shouldNotify("anything", "u-sam", "u-me", isDeleted = false, isUndecryptable = true))
        assertFalse(NotifyPolicy.shouldNotify(null, "u-sam", "u-me", isDeleted = false, isUndecryptable = true))
    }

    // ---- blocked people never notify ----

    private data class Ev(val from: String?, val text: String)

    @Test fun dmNotificationsForBlockedPeopleAreDropped() {
        val blocked = setOf("u-troll")
        val events = listOf(Ev("u-sam", "hi"), Ev("u-troll", "you there?"), Ev("u-ana", "lunch?"), Ev("u-troll", "answer me"))
        val announced = NotifyPolicy.withoutBlocked(events, { it.from }) { it in blocked }
        assertEquals(listOf(Ev("u-sam", "hi"), Ev("u-ana", "lunch?")), announced)
        // Blocking everyone who wrote leaves nothing to announce.
        assertTrue(NotifyPolicy.withoutBlocked(events, { it.from }) { true }.isEmpty())
        // Nobody blocked: nothing is lost.
        assertEquals(events, NotifyPolicy.withoutBlocked(events, { it.from }) { false })
    }

    @Test fun channelNotificationsForBlockedPeopleAreDroppedToo() {
        val isBlocked: (String) -> Boolean = { it == "u-troll" }
        assertFalse(NotifyPolicy.shouldNotify("hello", "u-troll", "u-me", isDeleted = false, isBlocked = isBlocked))
        assertFalse(NotifyPolicy.shouldNotify(null, "u-troll", "u-me", isDeleted = false, isBlocked = isBlocked))   // even undecrypted
        assertTrue(NotifyPolicy.shouldNotify("hello", "u-sam", "u-me", isDeleted = false, isBlocked = isBlocked))
    }

    // ---- groups ----

    @Test fun aGroupIsThreeToTenPeople() {
        assertFalse(GroupRules.canStart(1)); assertTrue(GroupRules.canStart(2)); assertTrue(GroupRules.canStart(9)); assertFalse(GroupRules.canStart(10))
        assertEquals("3 of 9", GroupRules.counter(3))
        assertEquals(listOf("u-a", "u-b"), GroupRules.others(listOf("u-me", "u-a", "u-b", "u-a", ""), "u-me"))
    }

    @Test fun aGroupIsTitledWithItsMembersNamesAsThisDeviceShowsThem() {
        assertEquals("ana, sam (unverified), li", GroupRules.title(listOf("ana", "sam (unverified)", "li")))
        assertEquals("Group", GroupRules.title(emptyList()))
        val long = GroupRules.title(List(9) { "member-number-$it" }, max = 30)
        assertEquals(30, long.length); assertTrue(long.endsWith("…")); assertTrue(long.startsWith("member-number-0, "))
        assertFalse(GroupRules.title(listOf("abcdefgh", "ijk"), max = 10).contains(",…"))
    }

    @Test fun changingAGroupsPeopleStartsANewGroupAndSaysSo() {
        assertEquals("This starts a new group with ana, sam and li. Messages already sent stay in the old one.",
            GroupRules.newGroupConfirm(listOf("ana", "sam", "li")))
        assertEquals("ana and sam", GroupRules.sentenceList(listOf("ana", "sam")))
        assertEquals(listOf("u-a", "u-b", "u-c"), GroupRules.changed(listOf("u-a", "u-b"), added = listOf("u-c")))
        assertEquals(listOf("u-a", "u-c"), GroupRules.changed(listOf("u-a", "u-b", "u-c"), removed = "u-b"))
        // Two others minus one is a 1:1 chat, not a group.
        assertNull(GroupRules.changed(listOf("u-a", "u-b"), removed = "u-b"))
        assertNull(GroupRules.changed(List(9) { "u-$it" }, added = listOf("u-x")))
    }

    @Test fun aGroupReplyQuotesOnlyItsMembers() {
        val members = listOf("u-a", "u-b")
        assertTrue(DmReplyPolicy.quotable("u-a", false, "u-me", members)); assertTrue(DmReplyPolicy.quotable("__me__", false, "u-me", members))
        assertFalse(DmReplyPolicy.quotable("u-stranger", false, "u-me", members)); assertFalse(DmReplyPolicy.quotable("u-a", true, "u-me", members))
    }

    // ---- uploads ----

    @Test fun aPendingAttachmentIsFoundByTheCoresPlaceholder() {
        val rows = listOf(UploadRules.Row("aaaa", 10, 100, false), UploadRules.Row("bbbb", 100, 100, true))
        assertEquals("aaaa", UploadRules.uploadId("upload:aaaa"))
        assertNull(UploadRules.uploadId("3f2a8c1e-0000-4000-8000-000000000000"))     // a real blob id
        assertNull(UploadRules.uploadId("upload:"))
        assertEquals(rows[0], UploadRules.progressFor("upload:aaaa", rows))
        assertNull(UploadRules.progressFor("upload:zzzz", rows))
        assertEquals(0.1f, UploadRules.fraction(rows[0]), 0.0001f)
        assertEquals(0f, UploadRules.fraction(UploadRules.Row("x", 5, 0, false)), 0f)
        assertEquals("Uploading… 10B/100B", UploadRules.line(rows[0]) { "${it}B" })
        assertTrue(UploadRules.anyPending(rows)); assertFalse(UploadRules.anyPending(rows.drop(1))); assertFalse(UploadRules.anyPending(emptyList()))
    }

    @Test fun aQueuedAttachmentBodyNamesThePlaceholderAsAWholeValue() {
        val a = ChatAttachment("clip.mp4", "video/mp4", 12, "video", "upload:aaaa", "a2V5", digestB64 = "ZGlnZXN0")
        val body = ChatTags.ATTACH + a.toJson()
        // `<tag>{json}`: the shape the core requires to set the real blob id structurally.
        assertTrue(body.startsWith(ChatTags.ATTACH + "{")); assertTrue(ChatTags.ATTACH.endsWith("skwod/attach|"))
        assertEquals("upload:aaaa", org.json.JSONObject(body.removePrefix(ChatTags.ATTACH)).getString("blobId"))
        assertEquals("upload:aaaa", ChatTags.parse(body).attachment?.blobId)
    }

    @Test fun copyingStopsAtTheCap() {
        val out = java.io.ByteArrayOutputStream()
        assertEquals(10L, AttachmentLimits.copyBounded(java.io.ByteArrayInputStream(ByteArray(10)), out, 10))
        assertEquals(10, out.size())
        try {
            AttachmentLimits.copyBounded(java.io.ByteArrayInputStream(ByteArray(200_000)), java.io.ByteArrayOutputStream(), 100_000)
            throw AssertionError("should have stopped")
        } catch (e: AttachmentLimits.TooLarge) { assertEquals(100_000L, e.limit) }
    }

    // ---- music in chat ----

    @Test fun aSongInChatIsTheSameCardTheFeedSends() {
        val track = MusicTrack("Song", "Artist", "https://music.apple.com/us/album/x/1?i=2", "https://is1-ssl.mzstatic.com/a.jpg", null, "2")
        val body = ChatTags.MUSIC + track.toJson()
        val parsed = ChatTags.parse(body)
        assertEquals("Song", parsed.music?.title); assertEquals("Artist", parsed.music?.artist)
        assertEquals(track.url, parsed.music?.url)
        assertEquals("Shared a song", NotifyPolicy.preview(body))
    }

    // ---- reports ----

    @Test fun aReportCardSaysWhatTheOwnersOwnCopyBacks() {
        assertEquals("ana reported sam", ReportRules.headline("ana", "sam"))
        assertEquals("ana reported a message", ReportRules.headline("ana", null))
        assertEquals(ReportRules.Match.UNKNOWN, ReportRules.match("bad words", found = false, cachedBodies = emptyList()))
        assertEquals(ReportRules.Match.MATCHES, ReportRules.match("bad words", true, listOf("bad words")))
        assertEquals(ReportRules.Match.MATCHES, ReportRules.match(" bad words ", true, listOf("skwod/attach|{}", "bad words")))
        assertEquals(ReportRules.Match.DIFFERS, ReportRules.match("bad words", true, listOf("nice words")))
        assertEquals("This is what the reporter says was written. Skwod can't prove who wrote it.", ReportRules.Match.UNKNOWN.caption)
        assertEquals("Matches the message on this device.", ReportRules.Match.MATCHES.caption)
        assertEquals("Differs from the message on this device.", ReportRules.Match.DIFFERS.caption)
    }

    // ---- group membership is fixed on this device ----

    private val joined = GroupConversation("g-1", listOf("u-a", "u-b"), mapOf("u-a" to "ana"))

    @Test fun aGhostTheServerAddsNeverJoinsTheStoredGroup() {
        val r = GroupRules.reconcile(listOf(joined), listOf("g-1" to listOf("u-a", "u-b", "u-ghost")), emptySet())
        val g = r.accepted.single()
        // The set messages are sealed to is exactly what it was; the listing is only flagged.
        assertEquals(listOf("u-a", "u-b"), g.others); assertTrue(g.serverDisagrees)
        assertEquals(mapOf("u-a" to "ana"), g.claimedNames)
        assertTrue(r.invitations.isEmpty())
        // The same for a listing that DROPS someone.
        assertEquals(listOf("u-a", "u-b"), GroupRules.reconcile(listOf(joined), listOf("g-1" to listOf("u-a")), emptySet()).accepted.single().others)
        // Rows by the ghost are not shown in the conversation either.
        assertFalse(GroupRules.rowShown("u-ghost", "u-me", g.others))
        assertTrue(GroupRules.rowShown("u-a", "u-me", g.others)); assertTrue(GroupRules.rowShown("__me__", "u-me", g.others)); assertTrue(GroupRules.rowShown("u-me", "u-me", g.others))
    }

    @Test fun aGhostCannotPostIntoAnAcceptedGroup() {
        val members = joined.others
        // The server added u-ghost to the conversation; this device never accepted them.
        assertFalse(GroupRules.accepts("u-ghost", fromSelf = false, members = members))
        assertTrue(GroupRules.accepts("u-a", false, members)); assertTrue(GroupRules.accepts("u-b", false, members))
        // This account's own copies (sent from another of its devices) are accepted.
        assertTrue(GroupRules.accepts("u-me", fromSelf = true, members = members))
        assertFalse(GroupRules.accepts("u-me", fromSelf = false, members = members))
        assertEquals("Someone outside a group tried to post in it", GroupRules.OUTSIDER_TITLE)
        assertEquals("An account that is not one of the people you joined “ana, li” with sent something to it. Skwod did not show it.",
            GroupRules.outsiderMessage("ana, li"))
    }

    @Test fun theSameSetInAnotherOrderIsNotADisagreement() {
        val r = GroupRules.reconcile(listOf(joined.copy(serverDisagrees = true)), listOf("g-1" to listOf("u-b", "u-a", "u-a")), emptySet())
        assertFalse(r.accepted.single().serverDisagrees)
        assertEquals(listOf("u-a", "u-b"), r.accepted.single().others)       // and the stored order stays
    }

    @Test fun anUnseenConversationIsAnInvitationAndADeclinedOneIsNotListed() {
        val listed = listOf("g-1" to listOf("u-a", "u-b"), "g-new" to listOf("u-x", "u-y", "u-z"), "g-no" to listOf("u-p", "u-q"),
            "g-tiny" to listOf("u-solo"), "g-new" to listOf("u-x", "u-y", "u-z"))
        val r = GroupRules.reconcile(listOf(joined), listed, declined = setOf("g-no"))
        assertEquals(listOf("g-1"), r.accepted.map { it.conversationId })
        // Not accepted, so not a group yet: an invitation, once, with the members it would have.
        assertEquals(listOf(GroupConversation("g-new", listOf("u-x", "u-y", "u-z"))), r.invitations)
        assertEquals("4 people · tap to see who", GroupRules.invitationLine(3))
    }

    @Test fun anAcceptedGroupMissingFromTheListingIsKept() {
        val r = GroupRules.reconcile(listOf(joined), emptyList(), emptySet())
        assertEquals(listOf(joined), r.accepted); assertTrue(r.invitations.isEmpty())
        // Declining something never touches a group that was accepted.
        assertEquals(listOf(joined), GroupRules.reconcile(listOf(joined), listOf("g-1" to listOf("u-a", "u-b")), setOf("g-1")).accepted)
    }

    @Test fun aDmEventIsRoutedByWhatThisDeviceHolds() {
        fun route(id: String) = GroupRules.route(id, accepted = listOf("g-1"), invitations = listOf("g-new"), declined = listOf("g-no"), direct = listOf("d-1"))
        assertEquals(GroupRules.Route.GROUP, route("g-1"))
        assertEquals(GroupRules.Route.INVITATION, route("g-new"))     // no 1:1 row, no content
        assertEquals(GroupRules.Route.DECLINED, route("g-no"))
        assertEquals(GroupRules.Route.DIRECT, route("d-1"))
        assertEquals(GroupRules.Route.UNKNOWN, route("who-knows"))    // ask for the groups first
        assertEquals("Group invitation", GroupRules.INVITATION_TITLE)
        assertEquals("You were added to a group. Open Skwod to see who is in it.", GroupRules.INVITATION_NOTICE)
    }

    // ---- one id, two descriptions: the store that claimed it first keeps it ----

    @Test fun aDmIdListedAsAGroupMakesNoInvitationAndStaysDirect() {
        val direct = setOf("d-1")
        val r = GroupRules.reconcile(listOf(joined), listOf("d-1" to listOf("u-x", "u-y"), "g-new" to listOf("u-x", "u-y")), emptySet(), direct)
        assertEquals(listOf("g-new"), r.invitations.map { it.conversationId })     // no invitation for d-1
        assertEquals(listOf("d-1"), r.conflicts)
        assertEquals(listOf(joined), r.accepted)
        // The DM is untouched and routes direct — also if an invitation or an "ignored group"
        // under its id were somehow in memory.
        assertEquals(GroupRules.Route.DIRECT, GroupRules.route("d-1", r.accepted.map { it.conversationId }, r.invitations.map { it.conversationId }, emptyList(), direct))
        assertEquals(GroupRules.Route.DIRECT, GroupRules.route("d-1", emptyList(), listOf("d-1"), emptyList(), direct))
        assertEquals(GroupRules.Route.DIRECT, GroupRules.route("d-1", emptyList(), emptyList(), listOf("d-1"), direct))
        assertTrue(GroupRules.conflict("d-1", emptyList(), listOf("d-1"), direct))
        assertFalse(GroupRules.mayClaim("d-1", direct))               // nor may the user accept or start a group under it
    }

    @Test fun anAcceptedGroupsIdListedAsADmMakesNoDmAndStaysTheGroup() {
        val groupIds = listOf(joined.conversationId)
        // The server-driven DM paths ask this before creating an entry: refused.
        assertFalse(GroupRules.mayClaim("g-1", groupIds))
        assertTrue(GroupRules.mayClaim("d-new", groupIds))
        // Even with a DM entry under the id (it cannot be made any more), the group routes as the group…
        assertEquals(GroupRules.Route.GROUP, GroupRules.route("g-1", groupIds, emptyList(), emptyList(), direct = listOf("g-1")))
        assertTrue(GroupRules.conflict("g-1", groupIds, emptyList(), direct = listOf("g-1")))
        // …and the stored group — members included — is exactly what it was.
        val r = GroupRules.reconcile(listOf(joined), listOf("g-1" to listOf("u-a", "u-b")), emptySet(), direct = setOf("g-1"))
        assertEquals(listOf(joined), r.accepted)
        assertEquals(listOf("u-a", "u-b"), r.accepted.single().others)
    }

    @Test fun noListingEverDeletesOrReRoutesAClaimedEntry() {
        val direct = setOf("d-1", "g-1")       // worst case: the DM store somehow holds the group's id too
        val listings = listOf(
            emptyList(),
            listOf("g-1" to listOf("u-a", "u-b")),
            listOf("g-1" to listOf("u-ghost", "u-other")),
            listOf("g-1" to emptyList<String>()),
            listOf("d-1" to listOf("u-a", "u-b"), "g-1" to listOf("u-a", "u-b", "u-ghost")),
            listOf("d-1" to listOf("u-x", "u-y"), "d-1" to listOf("u-x", "u-y", "u-z")))
        for (listed in listings) for (declined in listOf(emptySet(), setOf("g-1", "d-1"))) {
            val r = GroupRules.reconcile(listOf(joined), listed, declined, direct)
            // The accepted group is still there, with the members it was joined with…
            assertEquals(listOf("g-1"), r.accepted.map { it.conversationId })
            assertEquals(joined.others, r.accepted.single().others); assertEquals(joined.claimedNames, r.accepted.single().claimedNames)
            // …the DM never becomes an invitation…
            assertTrue(r.invitations.none { it.conversationId == "d-1" })
            // …and both still route to their owner.
            val accepted = r.accepted.map { it.conversationId }; val invited = r.invitations.map { it.conversationId }
            assertEquals(GroupRules.Route.GROUP, GroupRules.route("g-1", accepted, invited, declined, direct))
            assertEquals(GroupRules.Route.DIRECT, GroupRules.route("d-1", accepted, invited, declined, direct))
        }
        assertEquals("This conversation's server data conflicts", GroupRules.CONFLICT_TITLE)
        assertEquals("The server described one of your conversations in two different ways — as a direct conversation and as a group. Skwod kept it as it was and ignored the rest.",
            GroupRules.CONFLICT_MESSAGE)
    }

    @Test fun storedGroupsSurviveARoundTrip() {
        val groups = listOf(joined.copy(serverDisagrees = true), GroupConversation("g-2", listOf("u-c", "u-d", "u-e")))
        assertEquals(groups, GroupRules.decode(GroupRules.encode(groups)))
        assertTrue(GroupRules.decode(null).isEmpty()); assertTrue(GroupRules.decode("{not json").isEmpty())
        // A stored entry that is not a group (one other person) is not brought back as one.
        assertTrue(GroupRules.decode("""[{"conversationId":"g","memberUserIds":["u-a"]}]""").isEmpty())
        assertEquals(setOf("g-no", "g-x"), GroupRules.decodeIds(GroupRules.encodeIds(setOf("g-x", "g-no"))))
        assertTrue(GroupRules.decodeIds("nope").isEmpty())
    }

    // ---- notifications with app lock on ----

    @Test fun appLockEnabledRedactsWhetherOrNotTheAppIsLockedRightNow() {
        for (lockedNow in listOf(true, false)) {
            assertTrue(NotifyPolicy.redacted(hidePreviews = false, appLockEnabled = true, lockedNow = lockedNow))
            assertTrue(NotifyPolicy.redacted(hidePreviews = true, appLockEnabled = false, lockedNow = lockedNow))
            // Without the setting, "locked right now" redacts nothing (it cannot even occur).
            assertFalse(NotifyPolicy.redacted(hidePreviews = false, appLockEnabled = false, lockedNow = lockedNow))
        }
    }

    @Test fun theLastGateLeavesNoSenderTextOrThread() {
        val on = NotifyPolicy.shape("sam", "see you at 8", "dm:conv-123", appLockEnabled = true)
        assertEquals(NotifyPolicy.Shape("Skwod", "New message", "messages"), on)
        // Two conversations become one generic thread: not even how many are active is shown.
        assertEquals(on, NotifyPolicy.shape("#general · Lounge", "ana: hi", "channel:c-9", appLockEnabled = true))
        assertEquals(NotifyPolicy.Shape("sam", "see you at 8", "dm:conv-123"), NotifyPolicy.shape("sam", "see you at 8", "dm:conv-123", appLockEnabled = false))
        assertEquals("Skwod call", NotifyPolicy.callLabel("sam · Lounge", appLockEnabled = true))
        assertEquals("sam · Lounge", NotifyPolicy.callLabel("sam · Lounge", appLockEnabled = false))
    }

    // ---- upload staging ----

    private fun tempRoot(): java.io.File = java.nio.file.Files.createTempDirectory("skwod-uploads-test").toFile()

    @Test fun plaintextStagingAndCiphertextWorkAreSeparatePerSkwod() {
        val root = tempRoot()
        try {
            val staging = UploadPaths.staging(root, "ws1"); val work = UploadPaths.work(root, "ws1")
            assertFalse(staging == work)
            assertFalse(staging.path.startsWith(work.path)); assertFalse(work.path.startsWith(staging.path))
            assertTrue(staging.path.startsWith(root.path)); assertTrue(work.path.startsWith(root.path))
            assertFalse(UploadPaths.staging(root, "ws2") == staging); assertFalse(UploadPaths.work(root, "ws2") == work)
            // An id is never allowed to shape the path.
            val odd = UploadPaths.staging(root, "../../etc")
            assertEquals(java.io.File(root, UploadPaths.STAGING), odd.parentFile)
            assertFalse(odd.name.contains("..")); assertFalse(odd.name.contains("/"))
            assertEquals("abc123", UploadPaths.dirName("abc123"))
        } finally { root.deleteRecursively() }
    }

    @Test fun theLaunchSweepDeletesEveryStagedFileAndNoCiphertext() {
        val root = tempRoot(); val legacy = java.io.File(tempRoot(), "skwod-outgoing")
        try {
            for (ws in listOf("ws1", "ws2")) UploadPaths.staging(root, ws).apply { mkdirs() }.resolve("pick-1").writeText("plaintext")
            legacy.apply { mkdirs() }.resolve("pick-old").writeText("plaintext")
            val blob = UploadPaths.work(root, "ws1").apply { mkdirs() }.resolve("u.blob").apply { writeText("ciphertext") }
            assertEquals(3, UploadPaths.sweepStaging(root, listOf(legacy)))
            assertFalse(java.io.File(root, UploadPaths.STAGING).exists()); assertFalse(legacy.exists())
            assertTrue(blob.exists())                          // an upload in flight resumes after the restart
            assertEquals(0, UploadPaths.sweepStaging(root))    // nothing there is fine
        } finally { root.deleteRecursively(); legacy.parentFile?.deleteRecursively() }
    }

    @Test fun erasingASkwodTakesItsStagedFilesAndItsUploadsAndOnlyIts() {
        val root = tempRoot()
        try {
            val mine = listOf(UploadPaths.staging(root, "ws1").apply { mkdirs() }.resolve("pick"), UploadPaths.work(root, "ws1").apply { mkdirs() }.resolve("u.blob"))
            val other = listOf(UploadPaths.staging(root, "ws2").apply { mkdirs() }.resolve("pick"), UploadPaths.work(root, "ws2").apply { mkdirs() }.resolve("u.blob"))
            (mine + other).forEach { it.writeText("x") }
            assertTrue(UploadPaths.purge(root, "ws1"))
            mine.forEach { assertFalse(it.exists()) }; other.forEach { assertTrue(it.exists()) }
            assertTrue(UploadPaths.purge(root, "never-existed"))
        } finally { root.deleteRecursively() }
    }

    // What the owner's device holds: channel c-1 is in server srv-A, and message m-1 there was written by u-sam.
    private val channels = mapOf("c-1" to "srv-A", "c-2" to "srv-B")
    private val bySam = ReportRules.CachedRow("u-sam", "bad words")
    private fun resolve(subject: String?, server: String?, channel: String? = "c-1", message: String? = "m-1", cached: ReportRules.CachedRow? = bySam) =
        ReportRules.resolve(subject, server, channel, message, cached, channels, "u-owner")

    @Test fun anHonestReportResolvesToTheRealAuthorAndTheChannelsOwnServer() {
        val t = resolve("u-sam", "srv-A") as ReportRules.Resolution.Target
        assertEquals("u-sam", t.authorId); assertEquals("srv-A", t.serverId); assertEquals("c-1", t.channelId); assertEquals("m-1", t.messageId)
        assertEquals("bad words", t.text)
        assertTrue(t.warnings.isEmpty()); assertTrue(t.canRemove); assertTrue(t.canModerate)
        // A report that names nobody and no server claims nothing that could disagree.
        val bare = resolve(null, null) as ReportRules.Resolution.Target
        assertTrue(bare.warnings.isEmpty()); assertEquals("u-sam", bare.authorId); assertEquals("srv-A", bare.serverId)
    }

    @Test fun aReportPointingAtSomeoneElsesMessageIsRefused() {
        // The reporter names u-victim, but the message id they gave is u-sam's message.
        val t = resolve("u-victim", "srv-A") as ReportRules.Resolution.Target
        assertEquals(listOf("The reporter named a different person than the one who wrote this message."), t.warnings)
        // Nothing is offered — and what WOULD be touched is never the reporter's pick.
        assertFalse(t.canRemove); assertFalse(t.canModerate)
        assertEquals("u-sam", t.authorId)
    }

    @Test fun aReportNamingAnotherServerThanTheChannelsIsRefused() {
        // The message is in srv-A; the report says srv-B (to get its author banned THERE).
        val t = resolve("u-sam", "srv-B") as ReportRules.Resolution.Target
        assertEquals(listOf("The reporter named a different server than the one this message is in."), t.warnings)
        assertFalse(t.canRemove); assertFalse(t.canModerate)
        assertEquals("srv-A", t.serverId)
        // Both wrong: both are said.
        assertEquals(2, (resolve("u-victim", "srv-B") as ReportRules.Resolution.Target).warnings.size)
    }

    @Test fun withoutACachedMessageNothingIsResolved() {
        val none = ReportRules.Resolution.Unresolved
        assertEquals(none, resolve("u-sam", "srv-A", cached = null))
        assertEquals(none, resolve("u-sam", "srv-A", channel = null)); assertEquals(none, resolve("u-sam", "srv-A", message = ""))
        // A channel this device does not know the server of cannot be acted in.
        assertEquals(none, resolve("u-sam", "srv-A", channel = "c-unknown"))
        // A deleted row, a notice the core wrote and a placeholder are not messages to act on.
        assertEquals(none, resolve("u-sam", "srv-A", cached = bySam.copy(isDeleted = true)))
        assertEquals(none, resolve("u-sam", "srv-A", cached = bySam.copy(isSystem = true)))
        assertEquals(none, resolve("u-sam", "srv-A", cached = bySam.copy(isUndecryptable = true)))
    }

    @Test fun theOwnersOwnMessageCanBeRemovedButTheOwnerIsNotKicked() {
        for (author in listOf("__me__", "u-owner")) {
            val t = resolve("u-owner", "srv-A", cached = ReportRules.CachedRow(author, "mine")) as ReportRules.Resolution.Target
            assertTrue(t.authorIsMe); assertTrue(t.canRemove); assertFalse(t.canModerate)
        }
        // A row with no author names nobody to act on.
        assertFalse((resolve(null, "srv-A", cached = ReportRules.CachedRow(null, "x")) as ReportRules.Resolution.Target).canModerate)
    }

    @Test fun theManualStepAcceptsOnlyTheOwnersOwnPick() {
        val mine = listOf("srv-A", "srv-B"); val members = listOf("u-sam", "u-ana", "u-owner")
        assertTrue(ReportRules.manualChoiceValid("srv-A", "u-sam", mine, members, "u-owner"))
        assertFalse(ReportRules.manualChoiceValid("srv-other", "u-sam", mine, members, "u-owner"))   // not a server of this account
        assertFalse(ReportRules.manualChoiceValid("srv-A", "u-stranger", mine, members, "u-owner"))  // not in that server's member list
        assertFalse(ReportRules.manualChoiceValid("srv-A", "u-owner", mine, members, "u-owner"))
        assertFalse(ReportRules.manualChoiceValid(null, "u-sam", mine, members, "u-owner"))
        assertEquals("Kick sam from Lounge?", ReportRules.confirmTitle(false, "sam", "Lounge"))
        assertEquals("Ban sam from Lounge?", ReportRules.confirmTitle(true, "sam", "Lounge"))
        assertEquals("The reporter says: sam in Lounge", ReportRules.hint("sam", "Lounge"))
        assertNull(ReportRules.hint(null, null))
    }

    @Test fun reportEntryAndBadge() {
        assertEquals("reported: spam", ReportRules.banReason("spam"))
        assertTrue(ReportRules.entryVisible(1, false)); assertTrue(ReportRules.entryVisible(0, true)); assertFalse(ReportRules.entryVisible(0, false))
        assertEquals("99+", ReportRules.badge(120)); assertEquals("3", ReportRules.badge(3))
    }
}
