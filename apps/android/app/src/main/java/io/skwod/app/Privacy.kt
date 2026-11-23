package io.skwod.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.view.WindowManager

/**
 * Copying secrets (invites, join codes, device-link codes, recovery keys). The clip is flagged
 * sensitive so Android 13+ hides it in the clipboard preview / keyboard suggestions, and it is
 * cleared after 60 s — but only if the clipboard still holds what we put there.
 */
object SecureClipboard {
    private const val LABEL = "skwod"
    private const val CLEAR_AFTER_MS = 60_000L
    private val handler = Handler(Looper.getMainLooper())
    private var pendingClear: Runnable? = null

    fun copy(ctx: Context, text: String) {
        val app = ctx.applicationContext
        val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        val clip = ClipData.newPlainText(LABEL, text)
        clip.description.extras = PersistableBundle().apply {
            // ClipDescription.EXTRA_IS_SENSITIVE (API 33); the literal works on older releases too.
            putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
        }
        try { cm.setPrimaryClip(clip) } catch (_: Exception) { return }
        pendingClear?.let { handler.removeCallbacks(it) }
        val clear = Runnable { clearIfOurs(cm, text) }
        pendingClear = clear
        handler.postDelayed(clear, CLEAR_AFTER_MS)
    }

    private fun clearIfOurs(cm: ClipboardManager, text: String) {
        try {
            // Reading the clipboard needs focus on Android 10+; when we can't read it we still
            // clear, because the only thing we know is that we put a secret there.
            val current = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
            if (current != null && current != text) return
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
            else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        } catch (_: Exception) {}
    }
}

/** Screenshot / recent-apps privacy for the activity window, from the user's settings. */
object ScreenPrivacy {
    /** Apply from any UI context (inside a dialog the context is a wrapper, not the activity). */
    fun apply(ctx: Context) {
        var c: Context? = ctx
        while (c != null && c !is Activity) c = (c as? android.content.ContextWrapper)?.baseContext
        (c as? Activity)?.let { apply(it) }
    }

    fun apply(activity: Activity) {
        val s = AppSettings.get(activity)
        // Android 13+ can hide the recents thumbnail without blocking screenshots. Older releases
        // have no such switch, so recents privacy there means FLAG_SECURE as well.
        val secure = s.screenSecurity || (s.recentsPrivacy && Build.VERSION.SDK_INT < 33)
        if (secure) activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) activity.setRecentsScreenshotEnabled(!(s.recentsPrivacy || s.screenSecurity))
    }
}
