package io.skwod.app

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * The app lock: the fingerprint / face / device passcode stands between whoever holds the
 * unlocked phone and the chats. A current, unlocked device is fully authoritative for the
 * account (FFI-CHANGES, build 44a), so this — and removing the device from another one — is the
 * mitigation. When it is on, the app locks at every launch and when it comes back from the
 * background after the chosen time ([AppLockPolicy]).
 *
 * Authentication uses the platform prompt, with the device credential as a fallback, so it works
 * on a phone with no fingerprint enrolled: `android.hardware.biometrics.BiometricPrompt` on
 * Android 10+, the keyguard's confirm-credential screen on Android 8 and 9 (the platform prompt
 * exists on Android 9, but its device-credential fallback — `setDeviceCredentialAllowed` — only
 * arrived with Android 10; without it a phone with no fingerprint could never unlock). No key is bound to the
 * prompt: the lock gates the UI, it does not re-encrypt the cache (which the background
 * connection must be able to read while the phone is locked — see the note on the master key in
 * [AppModel]).
 */
object AppLock {
    /** While true the activity composes the lock screen and NOTHING else of the app. */
    var locked by mutableStateOf(false)
        private set

    @Volatile private var started = false
    /** The lock's whole memory; every change goes through [AppLockPolicy]'s state machine. */
    private var state = AppLockPolicy.State()
    private var pending: ((Boolean) -> Unit)? = null

    @Synchronized private fun update(change: (AppLockPolicy.State) -> AppLockPolicy.State) {
        state = change(state)
        if (locked != state.locked) locked = state.locked
    }

    /** Once per process, as soon as the settings are known: the app locks at launch, always. */
    fun start(settings: AppSettings) {
        if (started) return
        started = true
        update { it.copy(locked = AppLockPolicy.lockedAtLaunch(settings.appLock)) }
    }

    fun onBackground(now: Long) = update { AppLockPolicy.backgrounded(it, now) }

    fun onForeground(settings: AppSettings, now: Long) =
        update { AppLockPolicy.foregrounded(it, settings.appLock, settings.appLockMinutes, CallState.active.value, now) }

    /** DEBUG hooks and the settings switch: close or open the lock without a prompt. */
    fun set(lock: Boolean) = update { it.copy(locked = lock, backgroundedAt = if (lock) it.backgroundedAt else null) }

    /** A screen lock (PIN, pattern, password or biometrics) is set up on this phone. */
    fun available(ctx: Context): Boolean =
        (ctx.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)?.isDeviceSecure == true

    /** What the prompt asks for, in the user's words. */
    const val METHOD = "fingerprint"

    /** Unlock: one successful authentication opens the app (the state machine opens it, on success only). */
    fun unlock(activity: Activity, onResult: (Boolean) -> Unit = {}) = authenticate(activity, "Unlock Skwod", forUnlock = true, onResult = onResult)

    /**
     * Ask the user to prove it is them. [onResult] runs on the main thread, once. On a phone
     * with no screen lock at all there is nothing to ask: that is a failure, never a pass.
     * A cancelled or failed prompt changes nothing about the lock.
     */
    fun authenticate(activity: Activity, title: String, forUnlock: Boolean = false, onResult: (Boolean) -> Unit) {
        val now = System.currentTimeMillis()
        if (!AppLockPolicy.mayPrompt(state, now)) return
        if (!available(activity)) { onResult(false); return }
        update { AppLockPolicy.promptStarted(it, forUnlock, now) }
        val done = { ok: Boolean ->
            activity.runOnUiThread {
                pending = null
                update { AppLockPolicy.promptFinished(it, ok) }
                onResult(ok)
            }
        }
        try {
            if (Build.VERSION.SDK_INT >= 29) platformPrompt(activity, title, done)
            else {
                // Android 8 and 9: the keyguard's own confirm screen, answered in onActivityResult.
                val km = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                @Suppress("DEPRECATION")
                val intent: Intent? = km.createConfirmDeviceCredentialIntent(title, null)
                if (intent == null) { done(false); return }
                pending = done
                @Suppress("DEPRECATION")
                activity.startActivityForResult(intent, REQUEST_CREDENTIAL)
            }
        } catch (_: Exception) { done(false) }
    }

    @androidx.annotation.RequiresApi(29)
    private fun platformPrompt(activity: Activity, title: String, done: (Boolean) -> Unit) {
        val builder = android.hardware.biometrics.BiometricPrompt.Builder(activity).setTitle(title)
        if (Build.VERSION.SDK_INT >= 30) {
            builder.setAllowedAuthenticators(
                android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_WEAK or
                    android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        } else {
            @Suppress("DEPRECATION")
            builder.setDeviceCredentialAllowed(true)
        }
        builder.build().authenticate(CancellationSignal(), activity.mainExecutor,
            object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult?) = done(true)
                // Cancelled, locked out, no hardware: the lock stays closed and "Unlock" tries again.
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) = done(false)
                // A finger that did not match: the system prompt stays up and asks again.
                override fun onAuthenticationFailed() {}
            })
    }

    const val REQUEST_CREDENTIAL = 4401

    /** From the activity's `onActivityResult` (the Android 8 / 9 path). */
    fun onCredentialResult(requestCode: Int, resultCode: Int) {
        if (requestCode != REQUEST_CREDENTIAL) return
        pending?.invoke(resultCode == Activity.RESULT_OK)
    }
}
