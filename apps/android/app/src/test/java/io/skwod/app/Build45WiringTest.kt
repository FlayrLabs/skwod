package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Build 45, second and third batches as the app wires them: wiped names, the hold banner, notices, realtime events. */
class Build45WiringTest {
    @Test fun erasingASkwodDeletesEverythingKeptUnderItsIdAndNothingOfAnother() {
        val secrets = HashMap<String, String>()
        for (id in listOf("ws-a", "ws-ab")) {
            for (n in LocalData.secretNames(id)) secrets[n] = "x"
            secrets["${LocalData.contactsName(id)}.unreadable.1700000000000"] = "x"
        }
        secrets["workspaces"] = "[]"
        val held = secrets.keys.toList()
        LocalData.forgetItems("ws-a", removeSecret = { secrets.remove(it) }, removeNotify = {}, secretNamesHeld = held)
        // The announced-messages ledger, the contact book, its roster and its side copies go too.
        assertFalse(secrets.containsKey("announced-ws-a"))
        assertFalse(secrets.containsKey("contacts-ws-a"))
        assertFalse(secrets.containsKey("roster-ws-a"))
        assertFalse(secrets.containsKey("contacts-ws-a.unreadable.1700000000000"))
        // A skwod whose id merely starts the same is untouched.
        assertEquals((LocalData.secretNames("ws-ab") + "contacts-ws-ab.unreadable.1700000000000" + "workspaces").toSet(), secrets.keys)
    }

    @Test fun aContactsRekeyedDeviceReReadsTheirDevicesLikeARemovedOne() {
        assertEquals(AccountEvents.Action.PeerDeviceRemoved("u-sam"), AccountEvents.action("device_rekeyed", false, "u-sam", "u-me"))
        assertEquals(AccountEvents.Action.PeerDeviceRemoved("u-sam"), AccountEvents.action("device_rekeyed", true, "u-sam", "u-me"))
        assertEquals(AccountEvents.Action.OwnAccount, AccountEvents.action("device_rekeyed", false, "u-me", "u-me"))
        assertEquals(AccountEvents.Action.OwnAccount, AccountEvents.action("device_rekeyed", true, "", "u-me"))
        assertEquals(AccountEvents.Action.None, AccountEvents.action("device_rekeyed", false, "", "u-me"))
    }

    @Test fun aDownloadedBackupIsSaidOncePerEvent() {
        val alert = SecurityNotices.alert("backup_fetched", "", "", false, null, { it })!!
        assertEquals("Your key backup was downloaded by a sign-in that is not one of your devices. If this was not you, change your password and save a new recovery key.", alert.message)
        assertFalse(BackupFetched.alreadySaid(null, 1000))
        assertTrue(BackupFetched.alreadySaid(1000, 1000))
        assertTrue(BackupFetched.alreadySaid(2000, 1000))
        assertFalse(BackupFetched.alreadySaid(1000, 2000))
        assertFalse(BackupFetched.alreadySaid(5000, 0))
    }

    @Test fun build45NoticesAreShownNotDropped() {
        for (kind in listOf("channel_remap_refused", "owner_change_refused", "backup_fetched", "identity_changed", "unverified_contact_device"))
            assertTrue(kind, SecurityNotices.alert(kind, "u-sam", "dev12345678", false, "s-1", { "sam" }) != null)
        // identity_changed may be a refused impersonation: nothing in it claims sends are held.
        val changed = SecurityNotices.alert("identity_changed", "u-sam", "dev12345678", true, null, { "sam" })!!
        assertFalse(changed.message.contains("will not send"))
        assertTrue(changed.message.contains("different security key"))
    }

    // ---- the hold banner ----

    @Test fun theBannerComesFromTheContactsStatusNotFromANotice() {
        // A refused impersonation: an identity_changed notice, but nothing is held — no banner.
        assertEquals(IdentityHold.Banner.NONE, IdentityHold.banner(sendsHeld = false, devices = 1, unvouchedDevices = 0, sendFailedHeld = false))
        // A verified contact's devices changed.
        assertEquals(IdentityHold.Banner.HELD, IdentityHold.banner(true, 1, 0, false))
        // They replaced their phone and this device only looked afterwards: their only device is unvouched.
        assertEquals(IdentityHold.Banner.HELD, IdentityHold.banner(false, 0, 1, false))
        // A send just failed because it reached nobody.
        assertEquals(IdentityHold.Banner.HELD, IdentityHold.banner(false, 1, 0, true))
        // A further, unvouched device beside trusted ones: sends still go to the trusted ones.
        assertEquals(IdentityHold.Banner.UNVOUCHED_DEVICE, IdentityHold.banner(false, 2, 1, false))
        assertEquals("sam's security key changed. Messages to them are on hold until you accept or verify",
            IdentityHold.title(IdentityHold.Banner.HELD, "sam"))
    }

    @Test fun whatFailedWhileHeldIsRetriedAndReadsAsNotDelivered() {
        // The core outbox's own sentence for an IdentityChanged send.
        assertTrue(IdentityHold.isHeldFailure("Their safety number changed. Check it, then send again."))
        assertFalse(IdentityHold.isHeldFailure("That is too big to send."))
        val states = linkedMapOf<String, SendState>("m1" to SendState.Failed("l1", "Their safety number changed. Check it, then send again."),
            "m2" to SendState.Sending, "m3" to SendState.Failed("l3", "The server refused it (500)."))
        assertEquals(listOf("l1", "l3"), IdentityHold.toRetry(states))
        // A send the server refused keeps a state (never shown as sent).
        val view = OutboxPolicy.view(listOf(OutboxPolicy.Row("l1", "m1", "send", "failed", null)))
        assertTrue(view.byMessage["m1"] is SendState.Failed)
    }
}
