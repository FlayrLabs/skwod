package io.skwod.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** When the app sounds and notifies for a message ([AlertPolicy]) — the Apple apps' rule, in Kotlin. */
class AlertPolicyTest {
    private fun incoming(appActive: Boolean = false, onScreen: Boolean = false) =
        AlertPolicy.Incoming(appActive = appActive, onScreen = onScreen, now = 100_000)

    @Test fun theChatOnScreenIsSilent() {
        assertEquals(AlertPolicy.NOTHING, AlertPolicy.received(incoming(appActive = true, onScreen = true)))
    }

    @Test fun inFrontAnotherChatIsTheAppsSoundAndASilentNotification() {
        assertEquals(AlertPolicy.Outcome(banner = true, bannerSound = false, inAppSound = true),
            AlertPolicy.received(incoming(appActive = true)))
    }

    @Test fun notInFrontIsANotificationWithSoundAndNoInAppSound() {
        assertEquals(AlertPolicy.Outcome(banner = true, bannerSound = true, inAppSound = false),
            AlertPolicy.received(incoming(appActive = false)))
    }

    @Test fun neverForOwnBlockedOrMutedMessages() {
        for (active in listOf(true, false)) {
            assertEquals(AlertPolicy.NOTHING, AlertPolicy.received(incoming(active).copy(fromSelf = true)))
            assertEquals(AlertPolicy.NOTHING, AlertPolicy.received(incoming(active).copy(blocked = true)))
            assertEquals(AlertPolicy.NOTHING, AlertPolicy.received(incoming(active).copy(muted = true)))
        }
    }

    @Test fun doNotDisturbInterruptsWithNothing() {
        assertEquals(AlertPolicy.NOTHING, AlertPolicy.received(incoming(appActive = true).copy(doNotDisturb = true)))
        assertEquals(AlertPolicy.NOTHING, AlertPolicy.received(incoming(appActive = false).copy(doNotDisturb = true)))
    }

    @Test fun theSoundSwitchSilencesBothSoundsAndKeepsTheNotification() {
        assertEquals(AlertPolicy.Outcome(banner = true), AlertPolicy.received(incoming(appActive = true).copy(soundOn = false)))
        assertEquals(AlertPolicy.Outcome(banner = true), AlertPolicy.received(incoming(appActive = false).copy(soundOn = false)))
    }

    @Test fun aBurstIsOneSound() {
        val m = incoming(appActive = true).copy(lastSoundAt = 100_000, now = 100_400)
        assertEquals(AlertPolicy.Outcome(banner = true), AlertPolicy.received(m))
        assertTrue(AlertPolicy.received(m.copy(now = 101_000)).inAppSound)
        assertTrue("a clock that went backwards never mutes for good", AlertPolicy.received(m.copy(now = 50_000)).inAppSound)
    }

    @Test fun theSentSoundIsForAcceptedComposedMessagesOnly() {
        assertTrue(AlertPolicy.sentSound(composedWaiting = 1, accepted = 1, soundOn = true))
        assertFalse("queued, not accepted yet", AlertPolicy.sentSound(composedWaiting = 1, accepted = 0, soundOn = true))
        assertFalse("likes and game moves the app sent by itself", AlertPolicy.sentSound(composedWaiting = 0, accepted = 3, soundOn = true))
        assertFalse(AlertPolicy.sentSound(composedWaiting = 2, accepted = 2, soundOn = false))
    }

    /** A caller that passes a name and the text gets neither shown with "Hide message content" on, or app lock. */
    @Test fun aNamedTitleAndBodyAreGenericWithPreviewsHiddenAndWithAppLock() {
        val hidden = NotifyPolicy.shape("Dana Whitfield", "meet me at 8", "dm:conv-1", appLockEnabled = false, hidePreviews = true)
        assertEquals(listOf("Skwod", "New message"), listOf(hidden.title, hidden.text))
        val locked = NotifyPolicy.shape("Dana Whitfield", "meet me at 8", "dm:conv-1", appLockEnabled = true, hidePreviews = false)
        assertEquals(listOf("Skwod", "New message"), listOf(locked.title, locked.text))
        assertFalse(locked.topic.contains("conv-1"))
        val shown = NotifyPolicy.shape("Dana Whitfield", "meet me at 8", "dm:conv-1", appLockEnabled = false, hidePreviews = false)
        assertEquals(listOf("Dana Whitfield", "meet me at 8"), listOf(shown.title, shown.text))
        // A sentence of the app's own that names nobody survives hidden previews, not app lock.
        val fixed = NotifyPolicy.shape("Skwod", "Someone is waiting to join a server.", "join:s", false, hidePreviews = true, kind = NotifyPolicy.Text.FIXED)
        assertEquals("Someone is waiting to join a server.", fixed.text)
        assertEquals("New message", NotifyPolicy.shape("Skwod", "x", "join:s", true, hidePreviews = false, kind = NotifyPolicy.Text.FIXED).text)
    }
}
