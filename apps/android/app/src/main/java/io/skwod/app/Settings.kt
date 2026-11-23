package io.skwod.app

import android.content.Context
import androidx.compose.runtime.mutableStateOf

/**
 * Device-local preferences. Nothing secret lives here (tokens and keys are in the Keystore-backed
 * store in [AppModel]); these are behaviour switches, kept in app-private storage that is excluded
 * from backup and device transfer.
 */
class AppSettings(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("skwod-settings", Context.MODE_PRIVATE)

    private fun flag(key: String, default: Boolean) = object {
        val state = mutableStateOf(prefs.getBoolean(key, default))
        var value: Boolean
            get() = state.value
            set(v) { state.value = v; prefs.edit().putBoolean(key, v).apply() }
    }

    private val hideContentFlag = flag("hideMessageContent", false)
    private val screenSecurityFlag = flag("screenSecurity", false)
    private val recentsPrivacyFlag = flag("recentsPrivacy", true)
    private val publicFallbackFlag = flag("p2pPublicFallback", true)
    private val keepConnectedFlag = flag("keepConnected", true)
    private val batteryAskedFlag = flag("batteryAsked", false)
    private val autoUpdateCheckFlag = flag("autoUpdateCheck", true)
    private val soundSentFlag = flag("soundSent", true)
    private val soundReceivedFlag = flag("soundReceived", true)

    /** A soft sound once a message the user wrote has been accepted by the server. */
    var soundSent: Boolean
        get() = soundSentFlag.value
        set(v) { soundSentFlag.value = v }

    /** A short sound (the app's, or the notification's) for a message in a chat not on screen. */
    var soundReceived: Boolean
        get() = soundReceivedFlag.value
        set(v) { soundReceivedFlag.value = v }

    private val typingIndicatorsFlag = flag(TypingState.SETTING_KEY, true)

    /** "Send typing indicators" (on by default): off = neither sent nor shown ([TypingState]). */
    var typingIndicators: Boolean
        get() = typingIndicatorsFlag.value
        set(v) { typingIndicatorsFlag.value = v }

    private val storyMusicTapToPlayFlag = flag("storyMusicTapToPlay", false)

    /**
     * "Play story music only when I tap": nothing is fetched for a story's song until the viewer
     * taps it ([StoryMusicPolicy]). Off by default — the song starts when the story opens.
     */
    var storyMusicTapToPlay: Boolean
        get() = storyMusicTapToPlayFlag.value
        set(v) { storyMusicTapToPlayFlag.value = v }

    /** Notifications say "New message" instead of showing who wrote what. */
    var hideMessageContent: Boolean
        get() = hideContentFlag.value
        set(v) { hideContentFlag.value = v }

    /**
     * FLAG_SECURE: no screenshots, screen recording or casting of the app. On for a NEW install,
     * and whatever it was for an existing one ([decideScreenSecurity]).
     */
    var screenSecurity: Boolean
        get() = screenSecurityFlag.value
        set(v) { screenSecurityFlag.value = v }

    /**
     * Settle the screen-security default once, at the first launch that knows whether this
     * install already has a skwod: no stored preference AND no workspace = a new install, which
     * starts with screenshots blocked. An existing install keeps what it had (off, unless the
     * user turned it on). The answer is stored, so it is never decided twice.
     */
    fun decideScreenSecurity(hasWorkspace: Boolean) {
        if (prefs.contains("screenSecurity")) return
        screenSecurity = ScreenSecurityDefault.value(null, hasWorkspace)
    }

    private val appLockFlag = flag("appLock", false)

    /** Ask for the fingerprint / face / device passcode to open Skwod. */
    var appLock: Boolean
        get() = appLockFlag.value
        set(v) { appLockFlag.value = v }

    private val appLockMinutesState = mutableStateOf(AppLockPolicy.normalized(prefs.getInt("appLockMinutes", AppLockPolicy.DEFAULT_MINUTES)))

    /** "Lock after": minutes in the background before the lock closes again (0 = immediately). */
    var appLockMinutes: Int
        get() = appLockMinutesState.value
        set(v) { val m = AppLockPolicy.normalized(v); appLockMinutesState.value = m; prefs.edit().putInt("appLockMinutes", m).apply() }

    /** Hide the app's content in the recent-apps overview. On by default. */
    var recentsPrivacy: Boolean
        get() = recentsPrivacyFlag.value
        set(v) { recentsPrivacyFlag.value = v }

    /**
     * Whether a relay may carry the connection when no direct route to the host exists (default
     * on: it is what makes joining work behind almost any router). Off = direct connections only.
     */
    var publicFallback: Boolean
        get() = publicFallbackFlag.value
        set(v) { publicFallbackFlag.value = v }

    /** Keep the connection open in the background (foreground service) so messages notify. */
    var keepConnected: Boolean
        get() = keepConnectedFlag.value
        set(v) { keepConnectedFlag.value = v }

    /** The battery-optimization explanation was shown once already. */
    var batteryAsked: Boolean
        get() = batteryAskedFlag.value
        set(v) { batteryAskedFlag.value = v }

    /**
     * Look for a new version once a day (one anonymous request to GitHub, which sees this
     * device's IP address). On by default; off = only when the user taps "Check for updates".
     */
    var autoUpdateCheck: Boolean
        get() = autoUpdateCheckFlag.value
        set(v) { autoUpdateCheckFlag.value = v }

    /** Bookkeeping for the daily check: when it last ran, and which build it found / announced. */
    var updateLastCheck: Long
        get() = prefs.getLong("updateLastCheck", 0L)
        set(v) { prefs.edit().putLong("updateLastCheck", v).apply() }
    var updateKnownBuild: Int
        get() = prefs.getInt("updateKnownBuild", 0)
        set(v) { prefs.edit().putInt("updateKnownBuild", v).apply() }
    var updateNotifiedBuild: Int
        get() = prefs.getInt("updateNotifiedBuild", 0)
        set(v) { prefs.edit().putInt("updateNotifiedBuild", v).apply() }

    companion object {
        @Volatile private var instance: AppSettings? = null
        fun get(ctx: Context): AppSettings =
            instance ?: synchronized(this) { instance ?: AppSettings(ctx.applicationContext).also { instance = it } }
    }
}
