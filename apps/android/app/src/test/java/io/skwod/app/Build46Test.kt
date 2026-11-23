package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Build 46: a refused session never logs anyone out, "Log in" needs only the address, username
 * and password, join codes are typed freely, one entry per skwod, and the composer's paste rules.
 */
class Build46Test {
    private val node = "ybndrfg8ejkmcpqxot1uwisza345h769ybndrfg8ejkmcpqxot1u"

    // ---- paste staging ----

    @Test fun aPasteStaysInTheConversationItStartedIn() {
        assertTrue(StagingRule.belongs("c1", "c1"))
        // Switched while the picture was being read: dropped, never staged in the next chat.
        assertFalse(StagingRule.belongs("c1", "c2"))
        assertFalse(StagingRule.belongs("dm-1", "c1"))
        // A surface with no conversation id stages nothing.
        assertFalse(StagingRule.belongs("", ""))
        assertFalse(StagingRule.belongs("", "c1"))
    }

    // ---- session refusal ----

    @Test fun onlyARealSessionCheckSignsOut() {
        assertEquals(SessionRefusal.Action.SIGNED_OUT, SessionRefusal.decide("Engine", "status 401", sessionSignedOut = true))
        // A 401 / 403 anywhere else keeps the session (the caller asks sessionState() first).
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide("Engine", "HTTP 401 unauthorized"))
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide("Engine", "HTTP 403 forbidden"))
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide(null, "timed out"))
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide("Engine", "HTTP 502"))
    }

    @Test fun anOlderAppIsAnUpdateNotASignOut() {
        assertEquals(SessionRefusal.Action.UPDATE_APP, SessionRefusal.decide("UpdateRequired", "protocol 3 required"))
        assertEquals(SessionRefusal.Action.UPDATE_APP, SessionRefusal.decide("Engine", "http status 426: {\"error\":\"update required\"}"))
        // A number that merely contains 426 is not one.
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide("Engine", "message 14260 not found"))
    }

    @Test fun onlyTheTypedErrorOrA426StatusMeansUpdate() {
        assertEquals(426, SessionRefusal.httpStatus("http status 426: x"))
        assertEquals(426, SessionRefusal.httpStatus("http status 426"))
        assertEquals(403, SessionRefusal.httpStatus("http status 403: {\"error\":\"http status 426\"}"))
        assertNull(SessionRefusal.httpStatus("http status 4260: x"))
        assertNull(SessionRefusal.httpStatus("timed out after 426 ms"))
        // A "426" or "upgrade required" in the server's words is not one.
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide("Engine", "http status 403: {\"error\":\"message 426 not found\"}"))
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide("Engine", "server answered 426 Upgrade Required"))
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide("Engine", "http status 404: upgrade required"))
        assertEquals(SessionRefusal.Action.TRANSIENT, SessionRefusal.decide(null, "426"))
    }

    @Test fun bindRequiredBindsOrLinksAndIsAnUpdateOnlyAfterARealRebind() {
        val text = "HTTP 403: {\"error\":\"device bind required\"}"
        // A freshly logged-in second phone (not a device yet): bind → link flow, never "update".
        assertEquals(SessionRefusal.Action.BIND_REQUIRED, SessionRefusal.decide("Engine", text))
        assertEquals(SessionRefusal.Action.BIND_REQUIRED, SessionRefusal.decide("Engine", text, boundDevice = false, reboundAlready = true))
        // A bound device: rebind once on a fresh client first.
        assertEquals(SessionRefusal.Action.BIND_REQUIRED, SessionRefusal.decide("Engine", text, boundDevice = true))
        // Bound, rebound, still refused: the host and this app disagree.
        assertEquals(SessionRefusal.Action.UPDATE_APP, SessionRefusal.decide("Engine", text, boundDevice = true, reboundAlready = true))
        assertTrue(SessionRefusal.isBindRequired("Device Bind Required"))
        assertFalse(SessionRefusal.isBindRequired("403 forbidden"))
    }

    @Test fun removedOrSupersededGoToTheirScreens() {
        assertEquals(SessionRefusal.Action.DEVICE_STATE, SessionRefusal.decide("DeviceRemoved", ""))
        assertEquals(SessionRefusal.Action.DEVICE_STATE, SessionRefusal.decide("DeviceSuperseded", ""))
        assertEquals(SessionRefusal.Action.DEVICE_STATE, SessionRefusal.decide("RecoveryPending", ""))
        assertEquals(SessionRefusal.Action.DEVICE_STATE, SessionRefusal.decide("Engine", "403 {\"error\":\"device removed\"}"))
        assertEquals(SessionRefusal.Action.DEVICE_STATE, SessionRefusal.decide("Engine", "409 device superseded"))
    }

    // ---- log in: the address alone ----

    @Test fun logInTakesEveryAddressSpellingWithoutACode() {
        val p2p = SkwodAddress.P2p(node)
        assertEquals(p2p, LoginAddress.forLogin("https://skwod.io/join#$node"))
        assertEquals(p2p, LoginAddress.forLogin("https://skwod.io/join#$node.ABCD2345"))     // the code is ignored
        assertEquals(p2p, LoginAddress.forLogin("skwod://join/$node"))
        assertEquals(p2p, LoginAddress.forLogin("  $node  "))                                 // the bare host key
        assertEquals(p2p, LoginAddress.forLogin(node.uppercase()))                            // in any case
        assertEquals(p2p, LoginAddress.forLogin("$node.ABCD2345"))
        assertEquals(SkwodAddress.Https("https://chat.example.org"), LoginAddress.forLogin("chat.example.org"))
        assertEquals(SkwodAddress.Https("https://chat.example.org"), LoginAddress.forLogin("https://chat.example.org#ABCD2345"))
        // A broken code after the address does not block logging in.
        assertEquals(SkwodAddress.Https("https://chat.example.org"), LoginAddress.forLogin("https://chat.example.org#not a code!".replace(" ", "")))
        try { LoginAddress.forLogin("not an address at all"); fail() } catch (_: InviteException) {}
    }

    @Test fun aBareHostKeyIsNotAHostName() {
        // Before build 46 it became https://<key>.
        assertEquals(SkwodAddress.P2p(node), LoginAddress.parse(node).address)
        assertNull(LoginAddress.parse(node).joinCode)
        assertEquals("ABCD2345", LoginAddress.parse("$node.ABCD2345").joinCode)
        assertFalse(LoginAddress.isBareNodeId(node.drop(1)))
    }

    @Test fun onlyCreateAccountNeedsACode() {
        assertFalse(AuthForm.codeNeeded(createAccount = false))
        assertTrue(AuthForm.codeNeeded(createAccount = true))
        assertTrue(AuthForm.canSubmit(false, node, "sam", "pw", code = null))
        assertFalse(AuthForm.canSubmit(false, "", "sam", "pw", null))
        assertFalse(AuthForm.canSubmit(true, node, "sam", "password1", code = null))
        assertTrue(AuthForm.canSubmit(true, node, "sam", "password1", code = "ABCD2345"))
        assertFalse(AuthForm.canSubmit(true, node, "sam", "short", code = "ABCD2345"))
        // The link's code wins; else the typed one, tidied.
        assertEquals("LINKCODE", AuthForm.signupCode("LINKCODE", "abcd 2345"))
        assertEquals("ABCD2345", AuthForm.signupCode(null, "abcd 2345"))
        assertNull(AuthForm.signupCode(null, "   "))
        assertNull(AuthForm.signupCode(null, "no!"))
    }

    @Test fun theModeFollowsTheLinkOnlyWhenTheUserDidNotPickOne() {
        assertTrue(AuthForm.modeAfterAdopting(createAccount = false, hasCode = true, fromUserAction = false))
        assertFalse(AuthForm.modeAfterAdopting(createAccount = true, hasCode = false, fromUserAction = false))
        // On Log in, pasting a whole invite keeps Log in (the code is ignored).
        assertFalse(AuthForm.modeAfterAdopting(createAccount = false, hasCode = true, fromUserAction = true))
        // On Create account, pasting an address keeps it (the code is typed next).
        assertTrue(AuthForm.modeAfterAdopting(createAccount = true, hasCode = false, fromUserAction = true))
    }

    // ---- join codes ----

    @Test fun joinCodesAreTidiedNotRefused() {
        assertEquals("ABCD2345", JoinCode.normalise("abcd2345"))
        assertEquals("ABCD2345", JoinCode.normalise(" abcd 2345 "))
        assertEquals("ABCD2345", JoinCode.normalise("ABCD-2345"))
        assertEquals("SKWD-ABCD-EFGH", JoinCode.normalise("skwd abcd efgh"))
        assertEquals("SKWD-ABCD-EFGH", JoinCode.normalise("SKWDABCDEFGH"))
        assertEquals("SKWD-ABCD-EFGH", JoinCode.normalise("skwd--abcd-efgh-"))
        assertEquals("", JoinCode.normalise("   "))
        // Anything else is passed on as typed (upper case, no spaces) for the host to judge.
        assertEquals("ABC-DEF", JoinCode.normalise("abc-def"))
    }

    @Test fun joinWithACodeTakesTheCodeOutOfAnyLink() {
        assertEquals("ABCD2345", JoinCode.extract("https://skwod.io/join#$node.ABCD2345"))
        assertEquals("ABCD2345", JoinCode.extract("skwod://join/$node#ABCD2345"))
        assertEquals("ABCD2345", JoinCode.extract("https://chat.example.org#ABCD2345"))
        assertEquals("ABCD2345", JoinCode.extract("abcd-2345"))
    }

    // ---- one entry per skwod ----

    private fun w(local: String, user: String = "u1", token: String = "tok", issued: Long = 0, node: String? = null,
                  server: String = node?.let { "skwod://join/$it" } ?: "https://chat.example.org",
                  instance: String? = "inst", pinned: String? = "key", byUser: Boolean = false) =
        Workspace(server, user, token, 0, "x", localId = local, instanceId = instance, pinnedKey = pinned,
            nodeId = node, tokenIssuedAt = issued, signedOutByUser = byUser)

    @Test fun duplicatesKeepTheLiveNewestSession() {
        val dead = w("a", token = "", node = node)
        val live = w("b", token = "t", issued = 5, node = node)
        val r = WorkspaceDedupe.merge(listOf(dead, live))
        assertEquals(listOf(live), r.kept)
        assertEquals(listOf(dead), r.dropped)
        assertEquals(mapOf("a" to "b"), r.replacedBy)
        // Two live ones: nothing that still has a session is ever dropped.
        val older = w("c", token = "t1", issued = 1)
        val newer = w("d", token = "t2", issued = 9)
        assertEquals(listOf(older, newer), WorkspaceDedupe.merge(listOf(older, newer)).kept)
        assertTrue(WorkspaceDedupe.merge(listOf(older, newer)).dropped.isEmpty())
        // A user's own sign-out loses to a live session too.
        val signedOut = w("e", token = "", byUser = true, server = "https://chat.example.org/")
        assertEquals(listOf(newer), WorkspaceDedupe.merge(listOf(signedOut, newer)).kept)
        // Two dead ones: one record stays (the user logs in again there).
        assertEquals(1, WorkspaceDedupe.merge(listOf(signedOut, w("f", token = ""))).kept.size)
    }

    @Test fun aServerClaimedIdentityNeverMergesAcrossAddresses() {
        val p = w("p", node = node, issued = 1)
        val h = w("h", issued = 2)                                  // same instance id and pinned key, over https
        // Both values are what a host SAID when first pinned: a spoofing host could copy them.
        assertFalse(WorkspaceDedupe.sameSkwod(p, h))
        assertFalse(WorkspaceDedupe.sameSkwod(p, w("h2", pinned = "other")))
        assertFalse(WorkspaceDedupe.sameSkwod(p, w("h3", instance = null, pinned = null)))
        // A dead p2p record and a live https one stay apart (the rail marks neither as gone).
        val deadP2p = w("p2", token = "", node = node)
        assertEquals(listOf(deadP2p, h), WorkspaceDedupe.merge(listOf(deadP2p, h)).kept)
        // The same host key IS proof: the dead copy's record goes, its files stay.
        assertEquals(listOf(p), WorkspaceDedupe.merge(listOf(deadP2p, p)).kept)
    }

    @Test fun differentAccountsOrSkwodsAreNeverMerged() {
        val a = w("a", user = "u1", node = node)
        val b = w("b", user = "u2", node = node)
        val c = w("c", node = "y".repeat(52), instance = "other", pinned = "k2")
        val r = WorkspaceDedupe.merge(listOf(a, b, c))
        assertEquals(listOf(a, b, c), r.kept)
        assertTrue(r.dropped.isEmpty())
    }

    @Test fun twinEntriesAreLabelledApart() {
        val a = w("a", node = node).copy(username = "sam")
        val b = w("b", node = "y".repeat(52), instance = "i2").copy(username = "kim")
        val key = InviteLink.shortKey(node)
        assertEquals("My Skwod · $key · @sam", WorkspaceLabel.of(a, listOf(a, b)))
        // The short host key is always beside a p2p skwod's name.
        assertEquals("My Skwod · $key", WorkspaceLabel.of(a, listOf(a)))
        assertEquals("Signed out — tap to log in again", WorkspaceLabel.state(w("d", token = "")))
        assertNull(WorkspaceLabel.state(a))
    }

    @Test fun tappingTheOpenSkwodTearsNothingDown() {
        val open = w("a", token = "t")
        val other = w("b", token = "t", server = "https://other.example")
        val dead = w("c", token = "", server = "https://dead.example")
        assertEquals(SkwodTap.Outcome.STAY, SkwodTap.outcome(open, open, engineUp = true))
        assertEquals(SkwodTap.Outcome.SWITCH, SkwodTap.outcome(open, open, engineUp = false))   // nothing up: open it again
        assertEquals(SkwodTap.Outcome.SWITCH, SkwodTap.outcome(other, open, engineUp = true))
        // A skwod whose session ended opens its login and leaves the open one running.
        assertEquals(SkwodTap.Outcome.LOG_IN, SkwodTap.outcome(dead, open, engineUp = true))
        assertEquals(SkwodTap.Outcome.LOG_IN, SkwodTap.outcome(dead, dead, engineUp = true))
    }

    // ---- pasting a picture ----

    @Test fun onlyAPictureFromSomeoneElsesProviderIsPasted() {
        assertTrue(ClipboardImage.isImage(listOf("text/plain", "image/png")))
        assertFalse(ClipboardImage.isImage(listOf("text/plain", "text/uri-list")))
        val own = setOf("io.skwod.app.fileprovider")
        assertTrue(ClipboardImage.mayRead("content", "com.google.android.inputmethod.latin.fileprovider", own))
        assertFalse(ClipboardImage.mayRead("content", "io.skwod.app.fileprovider", own))
        assertFalse(ClipboardImage.mayRead("file", "", own))
        assertFalse(ClipboardImage.mayRead("content", null, own))
    }

    // ---- server and skwod menus ----

    @Test fun theOwnerDeletesEveryoneElseLeaves() {
        val owner = ServerMenu.items(ServerMenu.Ownership.OWNER)
        val member = ServerMenu.items(ServerMenu.Ownership.MEMBER)
        assertTrue(ServerMenu.Item.DELETE in owner && ServerMenu.Item.LEAVE !in owner)
        assertTrue(ServerMenu.Item.LEAVE in member && ServerMenu.Item.DELETE !in member)
        assertTrue(ServerMenu.Item.PERMISSIONS in owner && ServerMenu.Item.PERMISSIONS !in member)
        assertTrue(ServerMenu.Item.ICON in owner && ServerMenu.Item.ICON !in member)
        for (both in listOf(ServerMenu.Item.MUTE, ServerMenu.Item.INVITE)) assertTrue(both in owner && both in member)
        // The destructive item is always last.
        assertEquals(ServerMenu.Item.DELETE, owner.last()); assertEquals(ServerMenu.Item.LEAVE, member.last())
        assertEquals(listOf("channel:a", "channel:b"), ServerMenu.muteKeys(listOf("a", "", "b")))
    }

    @Test fun onlyTheOpenSkwodHasItsActions() {
        assertEquals(listOf(SkwodMenu.Item.LOG_IN), SkwodMenu.items(isOpen = true, signedOut = true))
        assertEquals(listOf(SkwodMenu.Item.LOG_IN), SkwodMenu.items(isOpen = false, signedOut = true))
        assertEquals(listOf(SkwodMenu.Item.OPEN), SkwodMenu.items(isOpen = false, signedOut = false))
        val open = SkwodMenu.items(isOpen = true, signedOut = false)
        assertTrue(SkwodMenu.Item.SIGN_OUT in open && SkwodMenu.Item.REMOVE_FROM_DEVICE in open && SkwodMenu.Item.MUTE in open)
        assertEquals("Skwod: example.org", SkwodMenu.heading("example.org"))
        assertEquals("My Skwod", SkwodMenu.heading("My Skwod"))
    }

    // ---- build 46, part 2: logging in through the other address, owners, names ----

    private fun lw(local: String, user: String = "u1", node: String? = null, server: String = node?.let { "skwod://join/$it" } ?: "https://chat.example.org",
                   instance: String? = "inst", pinned: String? = "key") =
        Workspace(server, user, "tok", 0, "x", localId = local, instanceId = instance, pinnedKey = pinned, nodeId = node)

    @Test fun theOtherAddressReusesTheEntryOnlyOnProof() = kotlinx.coroutines.runBlocking {
        val p2p = lw("p", node = node)
        val https = SkwodAddress.Https("https://chat.example.org")
        // Through https, proven: the p2p entry, keeping its p2p address.
        assertEquals(LoginReuse.Decision.Reuse(p2p, keepsP2p = true),
            LoginReuse.decide(listOf(p2p), https, "u1", "inst") { it == "key" })
        // Not proven: refused, never a second entry.
        assertEquals(LoginReuse.Decision.Refuse, LoginReuse.decide(listOf(p2p), https, "u1", "inst") { false })
        assertEquals(LoginReuse.Decision.Refuse, LoginReuse.decide(listOf(p2p), https, "u1", "inst") { error("offline") })
        // Another account, or another skwod: a new entry.
        assertEquals(LoginReuse.Decision.New, LoginReuse.decide(listOf(p2p), https, "u2", "inst") { true })
        assertEquals(LoginReuse.Decision.New, LoginReuse.decide(listOf(p2p), https, "u1", "other") { true })
        assertEquals(LoginReuse.Decision.New, LoginReuse.decide(listOf(p2p), https, "u1", null) { true })
        // Through p2p onto an https entry, proven: reused (it becomes the p2p address).
        val classic = lw("h")
        assertEquals(LoginReuse.Decision.Reuse(classic, keepsP2p = false),
            LoginReuse.decide(listOf(classic), SkwodAddress.P2p(node), "u1", "inst") { true })
        // Never onto a DIFFERENT p2p host, whatever it proves.
        assertEquals(LoginReuse.Decision.New, LoginReuse.decide(listOf(p2p), SkwodAddress.P2p("y".repeat(52)), "u1", "inst") { true })
        // The same host key needs no challenge.
        assertEquals(LoginReuse.Decision.Reuse(p2p, keepsP2p = false), LoginReuse.decide(listOf(p2p), SkwodAddress.P2p(node), "u1", null) { false })
        // The same https address whose key can't be proven now: refused.
        assertEquals(LoginReuse.Decision.Refuse, LoginReuse.decide(listOf(classic), https, "u1", "inst") { false })
    }

    @Test fun ownersComeFromTheServerListAndPruneOnlyOnAFullAnswer() {
        val json = """{"servers":[{"server_id":"s1","owner_id":"me"},{"server_id":"s2","owner_id":"them"}]}"""
        val owners = ServerList.owners(json)!!
        assertTrue(ServerList.hostSaysOwner(owners, "s1", "me"))
        assertFalse(ServerList.hostSaysOwner(owners, "s2", "me"))
        assertFalse(ServerList.hostSaysOwner(owners, "s1", null))
        assertEquals(setOf("s3"), ServerList.gone(listOf("s1", "s2", "s3", "", "demo"), owners.keys))
        assertNull(ServerList.owners(null))
        assertNull(ServerList.owners("not json"))
        assertNull(ServerList.owners("""{"servers":[{"owner_id":"x"}]}"""))
        assertEquals(emptyMap<String, String>(), ServerList.owners("""{"servers":[]}"""))
    }

    @Test fun duplicatesCanBeRemovedAndTheOwnerRenamesOnTheHost() {
        val a = lw("a", node = node); val b = lw("b", node = node); val c = lw("c", node = "y".repeat(52))
        assertTrue(WorkspaceLabel.hasTwin(a, listOf(a, b, c)))
        assertFalse(WorkspaceLabel.hasTwin(c, listOf(a, b, c)))
        assertEquals(listOf(SkwodMenu.Item.OPEN, SkwodMenu.Item.REMOVE_DUPLICATE), SkwodMenu.items(isOpen = false, signedOut = false, duplicate = true))
        assertFalse(SkwodMenu.Item.REMOVE_DUPLICATE in SkwodMenu.items(isOpen = true, signedOut = false, duplicate = true))
        assertTrue(SkwodMenu.Item.RENAME in SkwodMenu.items(isOpen = true, signedOut = false, instanceOwner = true))
        assertFalse(SkwodMenu.Item.RENAME in SkwodMenu.items(isOpen = true, signedOut = false, instanceOwner = true, renameAvailable = false))
        assertFalse(SkwodMenu.Item.RENAME in SkwodMenu.items(isOpen = false, signedOut = false, instanceOwner = true))
        assertFalse(SkwodMenu.Item.RENAME in SkwodMenu.items(isOpen = true, signedOut = false, instanceOwner = false, renameAvailable = true))
    }

    @Test fun skwodNamesAreCleanedAndNeverImitateAnother() {
        assertEquals("Sam's Place", SkwodName.clean("  Sam\u200B's\u202E Place \n"))
        assertEquals(32, SkwodName.clean("x".repeat(80))!!.length)
        assertNull(SkwodName.clean(" \u200B "))
        assertEquals("Hi", SkwodName.parse("""{"name":"Hi"}"""))
        assertNull(SkwodName.parse("""{"name":null}"""))
        assertNull(SkwodName.parse("<html>"))
        assertFalse(SkwodName.accepted("My skwod", emptyList()))
        assertFalse(SkwodName.accepted("SKW0D", emptyList()))
        assertFalse(SkwodName.accepted("Thіs Mac", emptyList()))         // Cyrillic і
        assertFalse(SkwodName.accepted("Fam1ly", listOf("Family")))
        assertTrue(SkwodName.accepted("Family", listOf("Work")))
        assertEquals("Mine", SkwodName.display("Mine", "Host's", "example.org"))
        assertEquals("Host's", SkwodName.display(null, "Host's", "example.org"))
        assertEquals("example.org", SkwodName.display(null, null, "example.org"))
        val named = lw("n", node = node).copy(instanceName = "Family")
        assertEquals("Family", named.displayName)
        assertEquals("Mine", named.copy(name = "Mine", nameSetByUser = true).displayName)
    }

    // ---- typing indicators ----

    @Test fun typersExpireAndLeaveWithTheirMessage() {
        var t = TypingState()
        t = t.add("sam", me = "me", blocked = false, enabled = true, now = 1000)
        t = t.add("kim", me = "me", blocked = false, enabled = true, now = 2000)
        t = t.add("sam", me = "me", blocked = false, enabled = true, now = 3000)   // de-duplicated, refreshed
        assertEquals(listOf("sam", "kim"), t.typers(3000))
        assertEquals(listOf("sam"), t.typers(7500))                 // kim's last event was 5.5 s ago
        assertTrue(t.expire(9000).until.isEmpty())
        assertEquals(listOf("kim"), t.remove("sam").typers(3000))   // sam's message arrived
        assertEquals(t, t.remove("nobody"))
    }

    @Test fun neverMeNeverBlockedNeverWithTheSettingOff() {
        val t = TypingState()
        assertEquals(t, t.add("me", me = "me", blocked = false, enabled = true, now = 1))
        assertEquals(t, t.add("bad", me = "me", blocked = true, enabled = true, now = 1))
        assertEquals(t, t.add("sam", me = "me", blocked = false, enabled = false, now = 1))
        assertEquals(t, t.add("", me = "me", blocked = false, enabled = true, now = 1))
        assertFalse(TypingState.mayAnnounce(enabled = false, draft = "hi", lastSentAt = 0, now = 10_000))
        assertFalse(TypingState.mayAnnounce(enabled = true, draft = "  ", lastSentAt = 0, now = 10_000))
        assertTrue(TypingState.mayAnnounce(enabled = true, draft = "hi", lastSentAt = 0, now = 10_000))
        assertFalse(TypingState.mayAnnounce(enabled = true, draft = "hi", lastSentAt = 9_000, now = 10_000))
        assertTrue(TypingState.mayAnnounce(enabled = true, draft = "hi", lastSentAt = 7_000, now = 10_000))
        assertEquals("privacy.typingIndicators", TypingState.SETTING_KEY)
    }

    @Test fun typingText() {
        assertNull(TypingState.text(emptyList()))
        assertEquals("Sam is typing…", TypingState.text(listOf("Sam")))
        assertEquals("Sam and Kim are typing…", TypingState.text(listOf("Sam", "Kim")))
        assertEquals("Several people are typing…", TypingState.text(listOf("A", "B", "C")))
    }

    // ---- security review: the pinned owner decides; host names never pose as addresses ----

    @Test fun thePinnedOwnerDecidesAndTheHostOnlyHints() {
        assertEquals(ServerMenu.Ownership.OWNER, ServerMenu.ownership(pinnedOwner = "me", me = "me"))
        assertEquals(ServerMenu.Ownership.MEMBER, ServerMenu.ownership(pinnedOwner = "them", me = "me"))
        assertEquals(ServerMenu.Ownership.UNVERIFIED, ServerMenu.ownership(pinnedOwner = null, me = "me"))
        assertEquals(ServerMenu.Ownership.UNVERIFIED, ServerMenu.ownership(pinnedOwner = "me", me = null))
        // The pin wins over the host's owner_id either way.
        assertEquals(ServerMenu.Item.LEAVE, ServerMenu.items(ServerMenu.Ownership.MEMBER, hostSaysOwner = true).last())
        val pinnedOwner = ServerMenu.items(ServerMenu.Ownership.OWNER, hostSaysOwner = false)
        assertEquals(ServerMenu.Item.DELETE, pinnedOwner.last())
        assertFalse(ServerMenu.Item.LEAVE in pinnedOwner)            // Leave forgets keys: never for the pinned owner
        // Nothing pinned: the hint picks the item, and it always warns; no owner tools.
        val hinted = ServerMenu.items(ServerMenu.Ownership.UNVERIFIED, hostSaysOwner = true)
        assertEquals(ServerMenu.Item.DELETE, hinted.last())
        assertFalse(ServerMenu.Item.PERMISSIONS in hinted || ServerMenu.Item.ICON in hinted)
        assertEquals(ServerMenu.Item.LEAVE, ServerMenu.items(ServerMenu.Ownership.UNVERIFIED, hostSaysOwner = false).last())
        assertTrue(ServerMenu.warns(ServerMenu.Ownership.UNVERIFIED))
        assertFalse(ServerMenu.warns(ServerMenu.Ownership.OWNER) || ServerMenu.warns(ServerMenu.Ownership.MEMBER))
    }

    @Test fun hostNamesNeverLookLikeAddressesAndLoseEveryClash() {
        for (bad in listOf("bank.example", "https:x", "a/b", "me@host", "x:443")) assertFalse(bad, SkwodName.accepted(bad, emptyList()))
        // Re-checked against the whole list: an address-based or user-set name wins a clash.
        val chat = lw("c", server = "https://chat.example.org", instance = "i1")     // shows "example.org"
        val evil = lw("e", node = node, instance = "i2").copy(instanceName = "Work")
        val mine = lw("m", server = "https://work.example", instance = "i3").copy(name = "Work", nameSetByUser = true)
        val out = SkwodName.revalidate(listOf(chat, evil, mine))
        assertNull(out[1].instanceName)
        assertEquals("Work", out[2].displayName)
        // Two host names that read alike: neither is kept.
        val a = lw("a", node = node, instance = "i4").copy(instanceName = "Family")
        val b = lw("b", node = "y".repeat(52), instance = "i5").copy(instanceName = "Fam1ly")
        assertTrue(SkwodName.revalidate(listOf(a, b)).all { it.instanceName == null })
        // A fine one stays.
        assertEquals("Family", SkwodName.revalidate(listOf(a, chat))[0].instanceName)
    }

    @Test fun aHostNamedHttpsEntryShowsItsRealAddress() {
        val h = lw("h", server = "https://chat.example.org").copy(instanceName = "Family")
        assertEquals("Family · chat.example.org", WorkspaceLabel.of(h, listOf(h)))
        // Without a host name the address heuristic is the name; nothing is added.
        val plain = lw("p", server = "https://chat.example.org")
        assertEquals("example.org", WorkspaceLabel.of(plain, listOf(plain)))
        // The user's own name: no address needed.
        val own = h.copy(name = "Ours", nameSetByUser = true)
        assertEquals("Ours", WorkspaceLabel.of(own, listOf(own)))
    }

    @Test fun hostNamesRefuseLookAlikePunctuation() {
        for (cp in listOf(0x3002, 0x2024, 0xFF0E, 0xA789, 0x2215, 0xFF20, 0xFF1A, 0xFE52, 0x2044)) {
            val name = "bank" + String(Character.toChars(cp)) + "example"
            assertFalse("U+%04X".format(cp), SkwodName.accepted(name, emptyList()))
        }
        // The final rule: ASCII letters/digits, space, - _ ' &, and real emoji only.
        assertTrue(SkwodName.accepted("Sam & Kim's 🎉", emptyList()))
        assertTrue(SkwodName.accepted("Party 🎉", emptyList()))
        assertTrue(SkwodName.accepted("\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67", emptyList()))   // 👨‍👩‍👧
        assertTrue(SkwodName.accepted("Love \u2764\uFE0F", emptyList()))                                      // ❤️
        assertEquals("\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67", SkwodName.clean("\uD83D\uDC68\u200D\uD83D\uDC69\u200D\uD83D\uDC67"))
        for (refused in listOf("東京", "Ποδόσφαιρο", "Семья", "cafe\u0301", "Café", "家族-2", "Family!",
                "a\u200Db", "\u200D\uD83C\uDF89", "x\uFE0F", "\uD83C\uDFFD", "\uD83C\uDDFA", "Crew \u00A9", "Crew\u2122")) {
            assertFalse(refused, SkwodName.accepted(refused, emptyList()))
        }
        // Skin tones and flags (regional-indicator pairs) are emoji too (the shared rule, build 46).
        assertTrue(SkwodName.accepted("\uD83D\uDC4B\uD83C\uDFFD", emptyList()))
        assertTrue(SkwodName.accepted("\uD83C\uDDFA\uD83C\uDDF8", emptyList()))
        // Refused → the entry keeps its default name (and the host key beside it).
        val p = lw("p", node = node).copy(instanceName = "東京")
        assertNull(SkwodName.revalidate(listOf(p))[0].instanceName)
        assertEquals("My Skwod · ${InviteLink.shortKey(node)}", WorkspaceLabel.of(SkwodName.revalidate(listOf(p))[0], listOf(p)))
        // A name the user sets on this device is not held to the host rule.
        assertEquals("東京", p.copy(name = "東京", nameSetByUser = true, instanceName = null).displayName)
    }

    // ---- @mentions (wire format shared with the Apple apps) ----

    @Test fun mentionsRoundTripInvisibly() {
        val text = "hi @sam and @kim"
        val body = Mentions.encode(text, listOf(Mentions.Mention("u-sam", 3, 4), Mentions.Mention("u-kim", 12, 4)), everyone = false)
        assertTrue(body.startsWith(text + Mentions.SEPARATOR))
        // Everything after the separator is TAG characters, which no renderer shows.
        assertTrue(body.substring(text.length + 1).codePoints().toArray().all { it in 0xE0020..0xE007E })
        val d = Mentions.decode(body)
        assertEquals(text, d.text)
        assertEquals(listOf(Mentions.Mention("u-sam", 3, 4), Mentions.Mention("u-kim", 12, 4)), d.mentions)
        assertFalse(d.everyone)
        // The exact payload Apple writes.
        val payload = String(body.substring(text.length + 1).codePoints().toArray().map { (it - 0xE0000).toChar() }.toCharArray())
        assertEquals("""M1{"m":[["u-sam",3,4],["u-kim",12,4]]}""", payload)
        assertTrue(Mentions.decode(Mentions.encode("@everyone hi", emptyList(), everyone = true)).everyone)
        // Nothing to say: nothing appended.
        assertEquals("plain", Mentions.encode("plain", emptyList()))
        // Display, copy, edit and notifications never see the trailer.
        assertEquals(text, ChatTags.parse(body).text)
        assertEquals(text, NotifyPolicy.preview(body))
    }

    @Test fun aBadTrailerIsDroppedNotShown() {
        fun tags(s: String) = s.map { String(Character.toChars(0xE0000 + it.code)) }.joinToString("")
        assertEquals(Mentions.Decoded("hi"), Mentions.decode("hi" + Mentions.SEPARATOR + tags("M2{}")))
        assertEquals(Mentions.Decoded("hi"), Mentions.decode("hi" + Mentions.SEPARATOR + tags("M1{not json")))
        // Not all tag characters: not a trailer at all.
        assertEquals("a" + Mentions.SEPARATOR + "b", Mentions.decode("a" + Mentions.SEPARATOR + "b").text)
        // Ranges must start with '@' and lie inside the text; the rest are ignored.
        val d = Mentions.decode("x @a" + Mentions.SEPARATOR + tags("""M1{"m":[["u1",0,2],["u2",2,2],["u3",2,9],["",2,2]]}"""))
        assertEquals("x @a", d.text)
        assertEquals(listOf(Mentions.Mention("u2", 2, 2)), d.mentions)
        // Over the cap: no mentions.
        val many = (0 until 51).joinToString(",") { """["u",0,2]""" }
        assertTrue(Mentions.decode("@a" + Mentions.SEPARATOR + tags("""M1{"m":[$many]}""")).mentions.isEmpty())
    }

    @Test fun aMentionRangeNeverHidesText() {
        val body = "@Sam please read this carefully"
        assertTrue(Mentions.valid(body, listOf(Mentions.Mention("u", 0, body.length))).isEmpty())
        assertTrue(Mentions.valid(body, listOf(Mentions.Mention("u", 0, 11))).isEmpty())
        assertEquals(1, Mentions.valid(body, listOf(Mentions.Mention("u", 0, 4))).size)
        assertFalse(Mentions.isMentionRange("@" + "a".repeat(64), 0, 65))
        assertTrue(Mentions.isMentionRange("@" + "a".repeat(63), 0, 64))
        // Rendering re-checks against the text it shows: an attachment's mentions are its caption's own.
        val caption = Mentions.encode("look @kim", listOf(Mentions.Mention("u-kim", 5, 4)))
        val parsed = ChatTags.parse(ChatTags.ATTACH + ChatAttachment("a.jpg", "image/jpeg", 1, "image", "b", "k", caption = caption).toJson())
        assertEquals("look @kim", parsed.text)
        assertEquals(listOf(Mentions.Mention("u-kim", 5, 4)), parsed.mentions.mentions)
    }

    @Test fun theComposerInsertsATokenEveryAppAccepts() {
        assertEquals("@Sam", Mentions.token("Sam"))
        assertEquals("@Sam_Smith_unverified", Mentions.token("Sam Smith (unverified)"))
        assertEquals("@Hangul_filler", Mentions.token("Hangul\u3164filler"))
        assertEquals("@member", Mentions.token("😀"))
        assertEquals("@Zoë", Mentions.token("  Zoë\n"))
        assertEquals("@a_b", Mentions.token("a@b"))
        assertEquals("@member", Mentions.token(" \u200B "))
        val long = Mentions.token("山".repeat(80))
        assertTrue(long.length <= Mentions.MAX_RANGE)
        assertTrue(Mentions.isMentionRange(long, 0, long.length))
        // Compose → send → receive: a spaced label still arrives as a mention.
        val label = Mentions.token("Sam Smith (unverified)")
        val draft = Mentions.complete("hi @sa", label)
        val d = Mentions.decode(Mentions.encode(draft, Mentions.locate(draft, listOf("u-sam" to label))))
        assertEquals(listOf(Mentions.Mention("u-sam", 3, 21)), d.mentions)
    }

    @Test fun theComposerPlacesPicksWhereTheyAre() {
        assertEquals("sa", Mentions.query("hello @sa"))
        assertNull(Mentions.query("mail@sa"))
        assertNull(Mentions.query("@sam is"))
        assertEquals("hello @sam ", Mentions.complete("hello @sa", "@sam"))
        val picks = listOf("u-sam" to "@sam")
        assertEquals(listOf(Mentions.Mention("u-sam", 3, 4)), Mentions.locate("hi @sam!", picks))
        assertTrue(Mentions.locate("hi @samuel", picks).isEmpty())     // not the same token
        assertTrue(Mentions.locate("hi sam", picks).isEmpty())         // deleted
    }

    @Test fun theDefaultRoleNeverOpensTheEveryoneGate() {
        val roles = listOf(Mentions.RoleBits("everyone", 8192L or 4L, isDefault = true),
            Mentions.RoleBits("admin", 8192L, isDefault = false), Mentions.RoleBits("mod", 64L, isDefault = false))
        assertEquals(0L, Mentions.everyonePermissions(emptyList(), roles))
        assertEquals(64L, Mentions.everyonePermissions(listOf("mod"), roles))
        assertEquals(64L, Mentions.everyonePermissions(listOf("everyone", "mod"), roles))
        assertEquals(8192L, Mentions.everyonePermissions(listOf("admin"), roles))
        val perms = mapOf("plain" to Mentions.everyonePermissions(emptyList(), roles),
            "modded" to Mentions.everyonePermissions(listOf("mod"), roles),
            "admin" to Mentions.everyonePermissions(listOf("admin"), roles))
        assertEquals(setOf("o", "admin"), Mentions.everyoneSenders("o", perms, held = emptySet(), blocked = emptySet()))
    }

    @Test fun anUnknownHeldListCountsNoAdmin() {
        val perms = mapOf("admin" to 8192L, "manager" to 4L)
        assertEquals(setOf("o"), Mentions.everyoneSenders("o", perms, held = null, blocked = emptySet()))
        assertEquals(emptySet<String>(), Mentions.everyoneSenders(null, perms, held = null, blocked = emptySet()))
        assertEquals(setOf("o", "admin", "manager"), Mentions.everyoneSenders("o", perms, held = emptySet(), blocked = emptySet()))
    }

    @Test fun everyoneOnlyFromTheOwnerOrAdmins() {
        // The same cases as Apple's testEveryoneIsHonouredFromThePinnedOwnerAndVerifiedAdmins.
        val perms = mapOf("admin" to 8192L, "manager" to (4L or 64L), "member" to (64L or 128L), "heldAdmin" to 8192L,
            "blockedAdmin" to 4L, "mentioner" to 16384L)
        val allowed = Mentions.everyoneSenders("o", perms, held = setOf("heldAdmin"), blocked = setOf("blockedAdmin"))
        assertEquals(setOf("o", "admin", "manager"), allowed)
        assertEquals(emptySet<String>(), Mentions.everyoneSenders("o", emptyMap(), emptySet(), setOf("o")))
        assertEquals(emptySet<String>(), Mentions.everyoneSenders(null, mapOf("" to 8192L), emptySet(), emptySet()))
        assertTrue(Mentions.everyoneHonoured("o", emptySet(), pinnedOwner = "o"))
        assertTrue(Mentions.everyoneHonoured("admin", allowed))
        assertFalse("admins only (build 46)", Mentions.everyoneHonoured("mentioner", allowed))
        assertFalse(Mentions.everyoneHonoured("member", allowed))
        assertFalse(Mentions.everyoneHonoured(null, allowed))
        val all = Mentions.Decoded("@everyone", everyone = true)
        assertTrue(Mentions.mentionsMe(all, "me", "o", everyoneHonoured = true))
        assertFalse(Mentions.mentionsMe(all, "me", "m", everyoneHonoured = false))
        assertTrue(Mentions.mentionsMe(Mentions.Decoded("@me", listOf(Mentions.Mention("me", 0, 3))), "me", "x", false))
        assertTrue(Mentions.mentionsMe(Mentions.Decoded("ok"), "me", "x", false, replyToMine = true))
        assertFalse(Mentions.mentionsMe(Mentions.Decoded("@me", listOf(Mentions.Mention("me", 0, 3))), "me", "me", false))
    }

    @Test fun aMentionAlwaysAlertsUnlessTheSkwodIsMutedOrTheSenderBlocked() {
        for (conv in listOf(false, true)) for (skwod in listOf(false, true)) for (blocked in listOf(false, true)) {
            assertEquals("conv=$conv skwod=$skwod blocked=$blocked", !skwod && !blocked,
                MentionAlert.alerts(conv, skwod, mentioned = true, senderBlocked = blocked))
            assertEquals(!conv && !skwod && !blocked, MentionAlert.alerts(conv, skwod, mentioned = false, senderBlocked = blocked))
        }
        assertEquals("Sam mentioned you in #general", MentionAlert.title("Sam", "#general", redacted = false))
        assertEquals("You were mentioned", MentionAlert.title("Sam", "#general", redacted = true))
    }

    // ---- sender-controlled mention trailers (vectors shared with the Apple tests) ----

    private fun tags(s: String) = s.map { String(Character.toChars(0xE0000 + it.code)) }.joinToString("")

    @Test fun hostileMentionTrailersNeverCrashAndReadNothingBad() {
        val cases = SharedVectors.load("mention-trailers.json").getJSONArray("cases")
        assertTrue(cases.length() > 20)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val visible = c.getString("visible")
            val d = Mentions.decode(visible + Mentions.SEPARATOR + tags(c.getString("payload")))
            assertEquals(name, visible, d.text)
            val want = c.getJSONArray("mentions").let { a -> (0 until a.length()).map { j -> a.getJSONArray(j).let { Mentions.Mention(it.getString(0), it.getInt(1), it.getInt(2)) } } }
            assertEquals(name, want, d.mentions)
            assertEquals(name, c.getBoolean("everyone"), d.everyone)
        }
    }

    @Test fun mentionBoundsNeverAdd() {
        assertFalse(Mentions.inBounds(Int.MAX_VALUE, Int.MAX_VALUE, 3))
        assertFalse(Mentions.inBounds(1, Int.MAX_VALUE, 3))
        assertFalse(Mentions.inBounds(Int.MIN_VALUE, 2, 3))
        assertTrue(Mentions.inBounds(1, 2, 3))
        assertNull(Mentions.exactInt(Double.NaN)); assertNull(Mentions.exactInt(Double.POSITIVE_INFINITY))
        assertNull(Mentions.exactInt(1.5)); assertNull(Mentions.exactInt(true)); assertNull(Mentions.exactInt("2"))
        assertNull(Mentions.exactInt(4294967298L)); assertEquals(7, Mentions.exactInt(7))
        // valid() given wrapped values directly (a caller that skipped decode) drops them.
        assertTrue(Mentions.valid("@ab", listOf(Mentions.Mention("u", 1, Int.MAX_VALUE))).isEmpty())
        val r = java.util.Random(46)
        val s = longArrayOf(Long.MAX_VALUE, Long.MIN_VALUE, -1, 0, 1, 2, Int.MAX_VALUE.toLong(), 0)
        repeat(2000) {
            s[7] = r.nextLong()
            Mentions.decode("@ab" + Mentions.SEPARATOR + tags("""M1{"m":[["u",${s[r.nextInt(8)]},${s[r.nextInt(8)]}]]}"""))
        }
    }

    @Test fun hostSkwodNamesFollowTheSharedRule() {
        val v = SharedVectors.load("skwod-names.json")
        val cases = v.getJSONArray("cases")
        assertTrue(cases.length() > 50)
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val name = c.getString("name")
            val want = if (c.isNull("expect")) null else c.getString("expect")
            val label = name.codePoints().toArray().joinToString(" ") { Integer.toHexString(it) }
            assertEquals(label, want, SkwodName.hostName(name))
            // accepted() agrees: exactly the names the rule keeps unchanged.
            if (want != null) assertTrue(label, SkwodName.accepted(want, emptyList()))
        }
        val clash = v.getJSONArray("clash")
        for (i in 0 until clash.length()) {
            val c = clash.getJSONObject(i)
            val others = c.getJSONArray("others").let { a -> (0 until a.length()).map { a.getString(it) } }
            val got = SkwodName.hostName(c.getString("name"))?.takeIf { SkwodName.accepted(it, others) }
            assertEquals(if (c.isNull("expect")) null else c.getString("expect"), got)
        }
    }
}
