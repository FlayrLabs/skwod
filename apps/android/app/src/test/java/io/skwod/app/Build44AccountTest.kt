package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Build 44a: devices, recovery key, restore, sign-out, app lock — the decisions, not the screens. */
class Build44AccountTest {
    private val day = 24L * 60 * 60 * 1000
    private val hour = 60L * 60 * 1000
    private val now = 1_800_000_000_000L

    // ---- sign-out keeps the device; erase is separate ----

    private val workspace = Workspace("https://chat.example", "u-me", "tok", 99, "x", localId = "abc123",
        instanceId = "inst", pinnedKey = "pin", username = "me", tokenIssuedAt = 5)

    @Test fun signingOutDropsTheSessionTokenAndNothingElse() {
        assertEquals(setOf(LocalData.Part.SESSION_TOKEN), LocalData.removedBy(LocalData.Departure.SIGN_OUT))
        // The cache, its key and the record all stay: signing back in is the same device.
        for (kept in listOf(LocalData.Part.CACHE_FILE, LocalData.Part.CACHE_KEY, LocalData.Part.WORKSPACE_RECORD)) {
            assertFalse(kept in LocalData.removedBy(LocalData.Departure.SIGN_OUT))
        }
    }

    @Test fun aSignedOutRecordStillFindsItsOwnCache() {
        val out = LocalData.signedOut(workspace)
        assertTrue(out.isSignedOut); assertTrue(out.signedOutByUser)
        assertEquals("", out.token); assertEquals(0L, out.expiresAt)
        // What names the cache file and its key, and what proves the server, is untouched.
        assertEquals(workspace.localId, out.localId); assertEquals(workspace.id, out.id)
        assertEquals(workspace.userId, out.userId); assertEquals(workspace.pinnedKey, out.pinnedKey)
        assertEquals(workspace.instanceId, out.instanceId); assertEquals(workspace.server, out.server)
    }

    @Test fun signingBackInIsTheSameStoreButAnotherAccountGetsItsOwn() = kotlinx.coroutines.runBlocking {
        val held = listOf(LocalData.signedOut(workspace))
        val address = SkwodAddress.Https("https://chat.example")
        val same = WorkspaceMatch.find(held, address, "u-me", "inst") { it == "pin" }
        assertEquals("abc123", same?.localId)
        // A different user signing in to the same skwod must never be handed that cache.
        assertNull(WorkspaceMatch.find(held, address, "u-other", "inst") { it == "pin" })
        val fresh = WorkspaceMatch.newLocalId(held, address, "u-other")
        assertFalse(fresh == "abc123")
    }

    @Test fun eraseAndAccountDeletionRemoveEverything() {
        assertEquals(LocalData.Part.entries.toSet(), LocalData.removedBy(LocalData.Departure.ERASE))
        assertEquals(LocalData.Part.entries.toSet(), LocalData.removedBy(LocalData.Departure.ACCOUNT_DELETED))
    }

    @Test fun eraseIsHiddenBehindTheWarningUntilConfirmed() {
        assertTrue(EraseCopy.eraseOffered(safe = true, confirmedUnsafe = false))
        assertFalse(EraseCopy.eraseOffered(safe = false, confirmedUnsafe = false))
        assertTrue(EraseCopy.eraseOffered(safe = false, confirmedUnsafe = true))
        assertTrue(EraseCopy.offersOffline("Engine"))
        assertFalse(EraseCopy.offersOffline("Invalid")); assertFalse(EraseCopy.offersOffline(null))
    }

    // ---- the cache key: unreadable is not absent ----

    @Test fun anUnreadableKeyIsNeverReplaced() {
        val good = "ab".repeat(32)
        assertEquals(CacheKeyPolicy.Decision.Use(good), CacheKeyPolicy.decide(CacheKeyPolicy.Read.Stored(good)))
        assertEquals(CacheKeyPolicy.Decision.Mint, CacheKeyPolicy.decide(CacheKeyPolicy.Read.Absent))
        // The Keystore threw: minting here would orphan the cache and the device's identity.
        assertEquals(CacheKeyPolicy.Decision.Unavailable, CacheKeyPolicy.decide(CacheKeyPolicy.Read.Unreadable))
        // A stored value that is not a key can decrypt nothing: re-minting loses nothing.
        assertEquals(CacheKeyPolicy.Decision.Mint, CacheKeyPolicy.decide(CacheKeyPolicy.Read.Stored("nope")))
        assertFalse(CacheKeyPolicy.wellFormed("AB".repeat(32)))
    }

    // ---- routing ----

    @Test fun theInstallStateChoosesTheScreen() {
        assertEquals(InstallRoute.Screen.APP, InstallRoute.forState("ACTIVE"))
        assertEquals(InstallRoute.Screen.REMOVED, InstallRoute.forState("REMOVED"))
        assertEquals(InstallRoute.Screen.SUPERSEDED, InstallRoute.forState("SUPERSEDED"))
        assertEquals(InstallRoute.Screen.WAITING, InstallRoute.forState("RECOVERY_PENDING"))
        assertEquals(InstallRoute.Screen.SET_UP, InstallRoute.forState("UNREGISTERED"))
    }

    @Test fun typedDeviceFailuresReReadTheState() {
        for (kind in listOf("DeviceRemoved", "DeviceSuperseded", "RecoveryPending")) assertTrue(InstallRoute.isDeviceError(kind))
        for (kind in listOf("Engine", "Invalid", "PinRequired", "RecoveryChanged", null)) assertFalse(InstallRoute.isDeviceError(kind))
    }

    @Test fun nothingIsRegisteredWhenTheCacheDidNotOpen() {
        assertTrue(InstallRoute.mayRegister(cacheOpened = true, online = true, screen = InstallRoute.Screen.SET_UP))
        // attachCache threw: never fall through to registerDevice.
        assertFalse(InstallRoute.mayRegister(cacheOpened = false, online = true, screen = InstallRoute.Screen.SET_UP))
        assertFalse(InstallRoute.mayRegister(cacheOpened = true, online = false, screen = InstallRoute.Screen.SET_UP))
        for (s in listOf(InstallRoute.Screen.APP, InstallRoute.Screen.REMOVED, InstallRoute.Screen.SUPERSEDED, InstallRoute.Screen.WAITING)) {
            assertFalse(InstallRoute.mayRegister(cacheOpened = true, online = true, screen = s))
        }
    }

    @Test fun restoreFailuresGoToTheRightScreen() {
        assertEquals(RestoreErrors.Kind.WAITING, RestoreErrors.classify("RecoveryPending", "x"))
        assertEquals(RestoreErrors.Kind.PIN, RestoreErrors.classify("PinRequired", null))
        assertEquals(RestoreErrors.Kind.PIN, RestoreErrors.classify("PinIncorrect", null))
        assertEquals(RestoreErrors.Kind.WRONG_KEY, RestoreErrors.classify("Invalid", "wrong passphrase"))
        assertEquals(RestoreErrors.Kind.FAILED, RestoreErrors.classify("Invalid", "backup KDF parameters malformed"))
        assertEquals(RestoreErrors.Kind.STOPPED, RestoreErrors.classify("DeviceRemoved", null))
        assertEquals(RestoreErrors.Kind.FAILED, RestoreErrors.classify("Engine", "timeout"))
    }

    @Test fun realtimeEventsAreOnlyNudges() {
        val own = AccountEvents.Action.OwnAccount
        for (e in listOf("device_added", "link_request", "device_recovery_requested", "device_rekeyed", "account_restored",
            "recovery_key_changed", "backup_updated", "sessions_revoked")) {
            assertEquals(own, AccountEvents.action(e, onOwnTopic = true, payloadUserId = "", me = "u-me"))
            // The same name on a server topic nudges nothing about this account.
            assertEquals(AccountEvents.Action.None, AccountEvents.action(e, onOwnTopic = false, payloadUserId = "", me = "u-me"))
        }
        assertEquals(own, AccountEvents.action("device_removed", true, "u-me", "u-me"))
        assertEquals(own, AccountEvents.action("device_removed", false, "u-me", "u-me"))
        // Someone else's device: theirs to re-read, on either topic.
        assertEquals(AccountEvents.Action.PeerDeviceRemoved("u-sam"), AccountEvents.action("device_removed", false, "u-sam", "u-me"))
        assertEquals(AccountEvents.Action.PeerDeviceRemoved("u-sam"), AccountEvents.action("device_removed", true, "u-sam", "u-me"))
        assertEquals(AccountEvents.Action.None, AccountEvents.action("message", true, "u-sam", "u-me"))
    }

    // ---- PIN ----

    @Test fun thePinScreenSaysHowManyTriesAreLeft() {
        assertNull(PinPrompt(PinPrompt.Purpose.RESET).message)
        assertEquals("Wrong PIN. 3 tries left.", PinPrompt(PinPrompt.Purpose.RESET, 3).message)
        assertEquals("Wrong PIN. 1 try left.", PinPrompt(PinPrompt.Purpose.RESTORE, 1).message)
        val locked = PinPrompt(PinPrompt.Purpose.RESET, 0)
        assertEquals("Too many wrong PINs. Try again in 15 minutes.", locked.message)
        assertTrue(locked.locked); assertFalse(PinPrompt(PinPrompt.Purpose.RESET, 2).locked); assertFalse(PinPrompt(PinPrompt.Purpose.RESET).locked)
    }

    // ---- recovery key ----

    @Test fun theLastSixCharactersAreCheckedLeniently() {
        val key = "ABCD-EFGH-JKLM-NPQR-ST23-4567"
        assertEquals("234567", RecoveryKeyCheck.tail(key))
        assertTrue(RecoveryKeyCheck.matches("234567", key))
        assertTrue(RecoveryKeyCheck.matches(" 23-45 67 ", key))
        val lettered = "abcd-efgh-jkxy"
        assertTrue(RecoveryKeyCheck.matches("GH-JKXY", lettered)); assertTrue(RecoveryKeyCheck.matches("ghjkxy", lettered))
        assertFalse(RecoveryKeyCheck.matches("234568", key))
        assertFalse(RecoveryKeyCheck.matches("34567", key))            // five is not six
        assertFalse(RecoveryKeyCheck.matches("T234567", key))          // nor is seven
        assertFalse(RecoveryKeyCheck.matches("", key))
        // A key too short to have six characters can never be "confirmed".
        assertFalse(RecoveryKeyCheck.matches("abc", "a-b-c"))
    }

    @Test fun theFirstRunPromptRespectsTheSnooze() {
        assertTrue(RecoveryPrompt.due(active = true, backupOn = false, busyElsewhere = false, snoozedUntilMs = 0, nowMs = now))
        assertFalse(RecoveryPrompt.due(true, backupOn = true, busyElsewhere = false, snoozedUntilMs = 0, nowMs = now))
        assertFalse(RecoveryPrompt.due(false, false, false, 0, now))
        assertFalse(RecoveryPrompt.due(true, false, busyElsewhere = true, snoozedUntilMs = 0, nowMs = now))
        val until = RecoveryPrompt.snoozeUntil(now)
        assertEquals(now + 7 * day, until)
        assertFalse(RecoveryPrompt.due(true, false, false, until, now + 6 * day))
        assertTrue(RecoveryPrompt.due(true, false, false, until, now + 7 * day))
    }

    @Test fun theSavedScreenSaysWhenTheKeyBecomesInstant() {
        val date: (Long) -> String = { "D$it" }
        assertEquals("Restoring with this key is instant.", RecoveryPrompt.savedBody(null, now, date))
        assertEquals("Restoring with this key is instant.", RecoveryPrompt.savedBody(now - 1, now, date))
        val later = RecoveryPrompt.savedBody(now + day, now, date)
        assertTrue(later.startsWith("From D${now + day}, restoring with this key is instant."))
        assertTrue(later.contains("7-day wait"))
        assertEquals("Instant restore ready", RecoveryPrompt.rowStatus(null, now, date))
        assertEquals("Instant from D${now + day}", RecoveryPrompt.rowStatus(now + day, now, date))
    }

    @Test fun theReasonDecidesTheHeaderAndNotNow() {
        assertNull(RecoveryKeyReason.FIRST_RUN.header); assertNull(RecoveryKeyReason.MANUAL.header)
        assertEquals("Your old recovery key was retired with that device.", RecoveryKeyReason.DEVICE_REMOVED.header)
        assertEquals("Your old recovery key no longer works.", RecoveryKeyReason.COMPROMISED.header)
        assertEquals("Your account has no recovery key now.", RecoveryKeyReason.NEEDED.header)
        assertTrue(RecoveryKeyReason.FIRST_RUN.offersNotNow)
        assertFalse(RecoveryKeyReason.NEEDED.offersNotNow); assertFalse(RecoveryKeyReason.DEVICE_REMOVED.offersNotNow)
    }

    // ---- countdown ----

    @Test fun theHoldCountsDownInWords() {
        assertEquals("in 6 days 23 hours", HoldCountdown.text(now + 6 * day + 23 * hour + 30 * 60_000, now))
        assertEquals("in 7 days", HoldCountdown.text(now + 7 * day, now))
        assertEquals("in 1 day 1 hour", HoldCountdown.text(now + day + hour, now))
        assertEquals("in 5 hours", HoldCountdown.text(now + 5 * hour + 59 * 60_000, now))
        assertEquals("in 1 hour", HoldCountdown.text(now + hour, now))
        assertEquals("in 12 minutes", HoldCountdown.text(now + 12 * 60_000, now))
        assertEquals("any moment now", HoldCountdown.text(now + 60_000, now))
        assertEquals("any moment now", HoldCountdown.text(now - day, now))
    }

    // ---- restore requests ----

    @Test fun everyRestoreRequestGetsItsOwnPromptAndApprovingOneEndsTheOthers() {
        var queue = RecoveryRequests.noted(emptyList(), "dev-1", "req-1", "AAAA-BBBB")
        assertEquals(listOf(RecoveryRequest("dev-1", "req-1", "AAAA-BBBB")), queue)
        // The same notice again is not a second prompt.
        assertEquals(queue, RecoveryRequests.noted(queue, "dev-1", "req-1", "AAAA-BBBB"))
        // Another install asking to restore the same device: a request of its own, BESIDE the
        // first — with its own id and code (server audit L1). Nothing is replaced.
        queue = RecoveryRequests.noted(queue, "dev-1", "req-2", "CCCC-DDDD")
        assertEquals(listOf(RecoveryRequest("dev-1", "req-1", "AAAA-BBBB"), RecoveryRequest("dev-1", "req-2", "CCCC-DDDD")), queue)
        // Another device's request waits behind them.
        queue = RecoveryRequests.noted(queue, "dev-2", "req-9", "EEEE-FFFF")
        assertEquals(3, queue.size); assertEquals("req-1", queue[0].requestId)
        // A notice with no id cannot be answered, so it is never queued.
        assertEquals(queue, RecoveryRequests.noted(queue, "dev-3", null, "X")); assertEquals(queue, RecoveryRequests.noted(queue, "dev-3", "", "X"))
        assertEquals(listOf(queue[1]), RecoveryRequests.matching(queue, "cccc dddd"))
        assertTrue(RecoveryRequests.matching(queue, "").isEmpty())
        // Blocking one leaves the other; approving one ends every request for that device.
        assertEquals(listOf("req-2", "req-9"), RecoveryRequests.answered(queue, queue[0], approved = false).map { it.requestId })
        assertEquals(listOf("req-9"), RecoveryRequests.answered(queue, queue[1], approved = true).map { it.requestId })
        assertTrue(RecoveryRequests.REPLACED.contains("Nothing was approved"))
    }

    // ---- devices ----

    @Test fun thisDeviceIsListedFirstThenByAge() {
        val rows = listOf(
            DeviceRows.Row("d-old", "Pixel", 100, now, false, true),
            DeviceRows.Row("d-me", null, 300, now, true, true),
            DeviceRows.Row("d-new", "Mac", 200, 0, false, false))
        assertEquals(listOf("d-me", "d-old", "d-new"), DeviceRows.sorted(rows).map { it.deviceId })
        assertEquals("Unnamed device", DeviceLabel.shown(null)); assertEquals("Unnamed device", DeviceLabel.shown("  "))
        assertEquals("Rename", DeviceRows.action(rows[1])); assertEquals("Remove", DeviceRows.action(rows[0]))
        assertEquals("2 of 5 devices", DeviceRows.countLine(2, 5)); assertEquals("2 of 5", DeviceRows.count(2, 5))
        assertTrue(DeviceRows.atLimit(5, 5)); assertFalse(DeviceRows.atLimit(4, 5)); assertFalse(DeviceRows.atLimit(0, 0))
        assertEquals("You've reached the 5-device limit. Remove one to link another.", DeviceRows.limitLine(5))
        assertEquals("Added X · Active now", DeviceRows.secondLine(rows[0], now + 60_000) { "X" })
        assertEquals("Added X · Not active yet", DeviceRows.secondLine(rows[2], now) { "X" })
        assertEquals("d-old", DeviceRows.find(rows, "pixel")?.deviceId)
        assertEquals("d-new", DeviceRows.find(rows, "d-n")?.deviceId)
        assertNull(DeviceRows.find(rows, "d-"))        // ambiguous prefix: nothing is removed on a guess
    }

    @Test fun deviceNamesAreBoundedAndOneLine() {
        assertEquals("Pixel 9", DeviceLabel.suggested("Pixel 9"))
        assertEquals("Android", DeviceLabel.suggested(null)); assertEquals("Android", DeviceLabel.suggested("  "))
        assertEquals("a b", DeviceLabel.cleaned(" a\nb "))
        assertEquals(40, DeviceLabel.cleaned("x".repeat(90)).length)
    }

    @Test fun activityIsWordedRelatively() {
        assertEquals("Active now", AccountDates.active(now - 4 * 60_000, now))
        assertEquals("Active 5 minutes ago", AccountDates.active(now - 5 * 60_000, now))
        assertEquals("Active 1 hour ago", AccountDates.active(now - hour, now))
        assertEquals("Active 2 days ago", AccountDates.active(now - 2 * day, now))
        assertEquals("just now", AccountDates.ago(now, now))
    }

    // ---- security notices + activity ----

    private val names: (String) -> String = { "sam" }

    @Test fun theNewNoticeKindsHaveTheirWords() {
        val label: (String) -> String = { id -> if (id == "d-1") "Pixel 9" else SecurityNotices.device(id) }
        val restored = SecurityNotices.alert("account_restored", "u-me", "d-1", false, null, names, null, label)!!
        assertEquals("Your account was restored on a new device", restored.title)
        assertTrue(restored.message.startsWith("Pixel 9 was restored from your recovery key"))
        val removed = SecurityNotices.alert("device_removed", "u-me", "0123456789abcdef", false, null, names, null, label)!!
        assertEquals("A device was removed", removed.title)
        assertTrue(removed.message.startsWith("Device 01234567… was removed from your account"))
        assertEquals(NoticeAction.RecoveryKey(RecoveryKeyReason.DEVICE_REMOVED), removed.action)
        assertEquals("Make a new key", removed.action!!.label)
        val needed = SecurityNotices.alert("recovery_key_needed", "u-me", "", false, null, names)!!
        assertEquals("Save a new recovery key", needed.title); assertEquals("Your account has no recovery key now.", needed.message)
        assertEquals("Save a recovery key", needed.action!!.label)
        assertEquals("Your recovery key changed", SecurityNotices.alert("recovery_key_changed", "u-me", "", false, null, names)!!.title)
        assertEquals("A skwod's owner changed", SecurityNotices.alert("owner_changed", "u-me", "srv", false, null, names)!!.title)
        val requested = SecurityNotices.alert("recovery_requested", "u-me", "d-2", false, null, names, "ABCD-EFGH")!!
        assertEquals("A restore was requested", requested.title); assertEquals("Code ABCD-EFGH.", requested.message)
        // Existing kinds keep their words.
        assertEquals("sam added a device", SecurityNotices.alert("new_device", "u-sam", "d", false, null, names)!!.title)
    }

    @Test fun theActivityListIsNewestFirstBoundedAndDeduplicated() {
        var list = emptyList<SecurityEvent>()
        for (i in 1..120) list = SecurityActivity.added(list, SecurityEvent("k", "t$i", "m", i.toLong()))
        assertEquals(SecurityActivity.MAX, list.size)
        assertEquals(120L, list.first().atMs); assertEquals(21L, list.last().atMs)
        val again = SecurityActivity.added(list, SecurityEvent("k", "t120", "m", 120))
        assertTrue(again === list)
        val round = SecurityActivity.decode(SecurityActivity.encode(list))
        assertEquals(list, round)
        assertTrue(SecurityActivity.decode(null).isEmpty()); assertTrue(SecurityActivity.decode("not json").isEmpty())
        // The Apple app writes the same list with `atMs`.
        assertEquals(7L, SecurityActivity.decode("""[{"kind":"k","title":"t","message":"m","atMs":7}]""").single().atMs)
    }

    // ---- app lock + screen security ----

    @Test fun theLockClosesAtLaunchAndAfterTheChosenTimeAway() {
        assertTrue(AppLockPolicy.lockedAtLaunch(true)); assertFalse(AppLockPolicy.lockedAtLaunch(false))
        fun back(awayMs: Long, minutes: Int, on: Boolean = true, call: Boolean = false) =
            AppLockPolicy.locksOnReturn(on, now - awayMs, now, minutes, call)
        assertTrue(back(0, 0))                       // "Immediately"
        assertFalse(back(59_000, 1)); assertTrue(back(60_000, 1))
        assertFalse(back(4 * 60_000, 5)); assertTrue(back(61 * 60_000L, 60))
        assertFalse(back(10 * hour, 1, on = false))
        assertFalse(back(10 * hour, 1, call = true))         // never mid-call
        // Never backgrounded (a fresh foreground with no record): launch already locked it.
        assertFalse(AppLockPolicy.locksOnReturn(true, null, now, 0, false))
        // A clock that went backwards counts as long enough.
        assertTrue(AppLockPolicy.locksOnReturn(true, now + hour, now, 15, false))
    }

    private val open = AppLockPolicy.State(locked = false)
    private val closed = AppLockPolicy.State(locked = true)
    private fun fg(s: AppLockPolicy.State, at: Long, minutes: Int = 1, on: Boolean = true, call: Boolean = false) =
        AppLockPolicy.foregrounded(s, on, minutes, call, at)

    @Test fun aNormalUnlockOpensTheAppAndItsOwnPromptDoesNotRelockIt() {
        var s = AppLockPolicy.promptStarted(closed, forUnlock = true, nowMs = now)
        assertTrue(s.promptIsUnlock)
        // The credential screen takes the app out of the foreground and back: still just locked.
        s = AppLockPolicy.backgrounded(s, now + 1_000)
        assertNull(s.backgroundedAt)
        s = fg(s, now + 5_000, minutes = 0)
        assertTrue(s.locked)
        s = AppLockPolicy.promptFinished(s, success = true)
        assertFalse(s.locked); assertNull(s.backgroundedAt); assertNull(s.promptStartedAt)
        // "Immediately" does not close it again on the spot…
        assertFalse(fg(s, now + 5_100, minutes = 0).locked)
        // …but the next real trip away does.
        assertTrue(fg(AppLockPolicy.backgrounded(s, now + 10_000), now + 10_500, minutes = 0).locked)
    }

    @Test fun cancelThenBackgroundThenReturnIsLocked() {
        // An open app; a prompt (turning the lock off) comes up and is cancelled.
        var s = AppLockPolicy.promptStarted(open, forUnlock = false, nowMs = now)
        s = AppLockPolicy.promptFinished(s, success = false)
        assertFalse(s.locked)
        // The app is then put away and comes back after the delay: it must be locked.
        s = AppLockPolicy.backgrounded(s, now + 2_000)
        assertEquals(now + 2_000, s.backgroundedAt)
        assertFalse(fg(s, now + 30_000, minutes = 1).locked)
        assertTrue(fg(s, now + 2_000 + 60_000, minutes = 1).locked)
    }

    @Test fun aFailedOrCancelledPromptNeverForgetsTheBackground() {
        // Backgrounded first, prompt answered (cancel / failure) afterwards: the record stays.
        var s = AppLockPolicy.backgrounded(open, now)
        s = AppLockPolicy.promptStarted(s, forUnlock = false, nowMs = now + 1_000)
        s = AppLockPolicy.promptFinished(s, success = false)
        assertEquals(now, s.backgroundedAt)
        assertTrue(fg(s, now + 61_000, minutes = 1).locked)
        // A cancelled UNLOCK leaves the app locked.
        val cancelled = AppLockPolicy.promptFinished(AppLockPolicy.promptStarted(closed, true, now), success = false)
        assertTrue(cancelled.locked)
        // A success of some OTHER prompt is not an unlock.
        assertTrue(AppLockPolicy.promptFinished(AppLockPolicy.promptStarted(closed, false, now), success = true).locked)
    }

    @Test fun backgroundingDuringTheEnableOrDisablePromptCounts() {
        // The app is open and the user is in the middle of the "turn off app lock" prompt.
        var s = AppLockPolicy.promptStarted(open, forUnlock = false, nowMs = now)
        assertFalse(s.promptIsUnlock)
        s = AppLockPolicy.backgrounded(s, now + 3_000)
        assertEquals(now + 3_000, s.backgroundedAt)           // recorded as usual
        // Back after the delay — prompt still unanswered — the app is locked.
        s = fg(s, now + 3_000 + 5 * 60_000, minutes = 5)
        assertTrue(s.locked)
        // And asking for the unlock prompt while NOT locked gets no exemption either.
        val notLocked = AppLockPolicy.promptStarted(open, forUnlock = true, nowMs = now)
        assertFalse(notLocked.promptIsUnlock)
        assertEquals(now + 1, AppLockPolicy.backgrounded(notLocked, now + 1).backgroundedAt)
    }

    @Test fun aStuckPromptFlagTimesOut() {
        val stuck = AppLockPolicy.promptStarted(closed, forUnlock = true, nowMs = now)
        assertTrue(stuck.prompting(now + 59_000)); assertFalse(AppLockPolicy.mayPrompt(stuck, now + 59_000))
        // After a minute it no longer blocks a new prompt, and no longer exempts the background.
        assertFalse(stuck.prompting(now + 60_000)); assertTrue(AppLockPolicy.mayPrompt(stuck, now + 60_000))
        assertEquals(now + 61_000, AppLockPolicy.backgrounded(stuck, now + 61_000).backgroundedAt)
        // A clock that went backwards does not keep it alive either.
        assertFalse(stuck.prompting(now - 1))
        // An open app with a stuck (never answered) settings prompt still locks on return.
        val open2 = AppLockPolicy.promptStarted(open, forUnlock = false, nowMs = now)
        assertTrue(fg(AppLockPolicy.backgrounded(open2, now + 120_000), now + 200_000, minutes = 1).locked)
    }

    @Test fun theEarliestBackgroundMomentIsKeptAndACallDefersTheLock() {
        var s = AppLockPolicy.backgrounded(open, now)
        s = AppLockPolicy.backgrounded(s, now + 50_000)
        assertEquals(now, s.backgroundedAt)
        // Mid-call nothing locks, and the absence is not forgotten.
        val inCall = fg(s, now + 10 * 60_000, minutes = 1, call = true)
        assertFalse(inCall.locked); assertEquals(now, inCall.backgroundedAt)
        assertTrue(fg(inCall, now + 11 * 60_000, minutes = 1).locked)
        // With the lock off nothing is kept and nothing locks.
        val off = fg(s, now + 10 * 60_000, on = false)
        assertFalse(off.locked); assertNull(off.backgroundedAt)
    }

    @Test fun lockAfterOffersTheFiveChoices() {
        assertEquals(listOf("Immediately", "1 minute", "5 minutes", "15 minutes", "1 hour"), AppLockPolicy.options.map { it.second })
        assertEquals(1, AppLockPolicy.DEFAULT_MINUTES)
        assertEquals(1, AppLockPolicy.normalized(7)); assertEquals(15, AppLockPolicy.normalized(15)); assertEquals(0, AppLockPolicy.normalized(0))
        assertEquals("1 hour", AppLockPolicy.label(60))
    }

    @Test fun screenshotsAreBlockedByDefaultOnNewInstallsOnly() {
        assertTrue(ScreenSecurityDefault.value(stored = null, hasWorkspace = false))      // new install
        assertFalse(ScreenSecurityDefault.value(stored = null, hasWorkspace = true))      // existing install keeps "off"
        assertTrue(ScreenSecurityDefault.value(stored = true, hasWorkspace = true))       // a choice is a choice
        assertFalse(ScreenSecurityDefault.value(stored = false, hasWorkspace = false))
        assertNotNull(EraseCopy.UNSAFE)
    }
}
