package io.skwod.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.Person

/**
 * Every notification the app raises is LOCAL: built on this device from what this device
 * decrypted. There is no FCM, no push gateway and no Google dependency on Android.
 */
object Notifications {
    const val CHANNEL_CONNECTION = "skwod.connection"
    const val CHANNEL_MESSAGES = "skwod.messages"
    const val CHANNEL_CALLS = "skwod.calls"
    const val CHANNEL_ONGOING_CALL = "skwod.call.ongoing"
    const val CHANNEL_UPDATES = "skwod.updates"

    const val ID_CONNECTION = 1
    const val ID_ONGOING_CALL = 2
    const val ID_INCOMING_CALL = 3
    const val ID_UPDATE = 4

    const val ACTION_ANSWER = "io.skwod.app.action.ANSWER"
    const val ACTION_DECLINE = "io.skwod.app.action.DECLINE"
    const val ACTION_HANGUP = "io.skwod.app.action.HANGUP"
    const val ACTION_OPEN = "io.skwod.app.action.OPEN"
    const val EXTRA_SERVER_ID = "server_id"
    const val EXTRA_TOPIC = "topic"

    /** How long an unanswered call rings (same as the Apple app). */
    const val RING_TIMEOUT_MS = 45_000L

    fun ensureChannels(ctx: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val mgr = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_CONNECTION, "Connection", NotificationManager.IMPORTANCE_LOW).apply {
            description = "Shown while Skwod stays connected to your Skwod so new messages can notify you."
            setShowBadge(false); enableVibration(false); setSound(null, null)
            lockscreenVisibility = Notification.VISIBILITY_SECRET
        })
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_MESSAGES, "Messages", NotificationManager.IMPORTANCE_HIGH).apply {
            lockscreenVisibility = Notification.VISIBILITY_PRIVATE
        })
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_CALLS, "Incoming calls", NotificationManager.IMPORTANCE_HIGH).apply {
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setSound(RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE),
                AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build())
            enableVibration(true)
        })
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_ONGOING_CALL, "Ongoing call", NotificationManager.IMPORTANCE_LOW).apply {
            setShowBadge(false); setSound(null, null)
        })
        mgr.createNotificationChannel(NotificationChannel(CHANNEL_UPDATES, "App updates", NotificationManager.IMPORTANCE_DEFAULT).apply {
            description = "Tells you when a new version of Skwod is ready to install."
            setShowBadge(false)
        })
    }

    private fun openApp(ctx: Context, action: String, request: Int, extras: Intent.() -> Unit = {}): PendingIntent {
        // The nonce marks the intent as OURS: MainActivity is exported, so an action or an extra
        // alone proves nothing about who sent it.
        val i = Intent(ctx, MainActivity::class.java).setAction(action)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(IntentGuard.EXTRA_NONCE, IntentGuard.nonce).apply(extras)
        return PendingIntent.getActivity(ctx, request, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }

    private fun broadcast(ctx: Context, action: String, request: Int): PendingIntent {
        val i = Intent(ctx, NotificationActionReceiver::class.java).setAction(action)
        return PendingIntent.getBroadcast(ctx, request, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }

    /** The minimal, silent "skwod is connected" notification the foreground service must show. */
    fun connection(ctx: Context, status: String): Notification {
        ensureChannels(ctx)
        return NotificationCompat.Builder(ctx, CHANNEL_CONNECTION)
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentTitle("Skwod")
            .setContentText(status)
            .setOngoing(true).setSilent(true).setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_DEFERRED)
            .setContentIntent(openApp(ctx, ACTION_OPEN, 10))
            .build()
    }

    /**
     * A new message. `title`/`text` are what this device decrypted; with "hide message content"
     * on (or nothing decryptable) the caller passes generic text.
     *
     * What a lock screen can show:
     * - app lock ENABLED, or "Hide message content" on (for text that names someone or quotes
     *   something): the notification itself is reduced to the generic form below
     *   ([NotifyPolicy.shape]) — there is nothing else in it to show, anywhere;
     * - both off: the notification carries the text, marked VISIBILITY_PRIVATE with a generic
     *   public version. Android then shows the generic version on a secure lock screen only if
     *   the user's SYSTEM setting hides sensitive notification content; otherwise it shows the
     *   text. The app cannot make that choice for the system — "Hide message content" is the
     *   switch that holds whatever the system is set to.
     */
    fun message(ctx: Context, topic: String, title: String, text: String, kind: NotifyPolicy.Text, silent: Boolean = false) {
        // The one place every message-like notification passes through — from the UI process or
        // from one the connection service started alone. With app lock ENABLED it is reduced
        // to the generic form here, whatever the caller built and whether or not the lock is
        // closed at this moment.
        // …and with "Hide message content" on, text that names someone or quotes something
        // ([kind], which every caller must state) is replaced the same way.
        val settings = AppSettings.get(ctx)
        val shape = NotifyPolicy.shape(title, text, topic, settings.appLock, settings.hideMessageContent, kind)
        @Suppress("NAME_SHADOWING") val topic = shape.topic
        @Suppress("NAME_SHADOWING") val title = shape.title
        @Suppress("NAME_SHADOWING") val text = shape.text
        ensureChannels(ctx)
        val public = NotificationCompat.Builder(ctx, CHANNEL_MESSAGES)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle(NotifyPolicy.GENERIC_TITLE).setContentText(NotifyPolicy.GENERIC_TEXT).build()
        val n = NotificationCompat.Builder(ctx, CHANNEL_MESSAGES)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            // In front the app's own sound is the one sound; and the sound switch may be off.
            .setSilent(silent)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setContentIntent(openApp(ctx, ACTION_OPEN, topic.hashCode()) { putExtra(EXTRA_TOPIC, topic) })
            .build()
        // Notification permission (Android 13+) may be missing — notify() throws SecurityException then.
        try { NotificationManagerCompat.from(ctx).notify(topic.hashCode(), n) } catch (_: SecurityException) {}
    }

    /**
     * The incoming-call screen ([IncomingCallActivity], not exported): the only thing that may
     * show over the lock screen, and it shows the caller + Answer / Decline, nothing else.
     */
    private fun callScreen(ctx: Context, action: String, request: Int, serverId: String): PendingIntent {
        val i = Intent(ctx, IncomingCallActivity::class.java).setAction(action)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(IntentGuard.EXTRA_NONCE, IntentGuard.nonce).putExtra(EXTRA_SERVER_ID, serverId)
        return PendingIntent.getActivity(ctx, request, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
    }

    /** Ring: a full-screen call notification with Answer / Decline. */
    fun incomingCall(ctx: Context, serverId: String, callerName: String, ringForMs: Long = RING_TIMEOUT_MS) {
        @Suppress("NAME_SHADOWING") val callerName = NotifyPolicy.callLabel(callerName, AppSettings.get(ctx).appLock)
        ensureChannels(ctx)
        // Answer goes through the call screen too, so the keyguard is dismissed (the user
        // authenticates) before the call — or any other app content — appears.
        val answer = callScreen(ctx, ACTION_ANSWER, 20, serverId)
        val decline = broadcast(ctx, ACTION_DECLINE, 21)
        val person = Person.Builder().setName(callerName).setImportant(true).build()
        val n = NotificationCompat.Builder(ctx, CHANNEL_CALLS)
            .setSmallIcon(android.R.drawable.sym_call_incoming)
            .setContentTitle(callerName)
            .setContentText("Incoming Skwod call")
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setOngoing(true).setAutoCancel(false)
            .setTimeoutAfter(ringForMs.coerceIn(1_000, RING_TIMEOUT_MS))
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setFullScreenIntent(callScreen(ctx, ACTION_OPEN, 22, serverId), true)
            .setContentIntent(callScreen(ctx, ACTION_OPEN, 22, serverId))
            .setStyle(NotificationCompat.CallStyle.forIncomingCall(person, decline, answer))
            .addPerson(person)
            .build()
        try { NotificationManagerCompat.from(ctx).notify(ID_INCOMING_CALL, n) } catch (_: SecurityException) {}
    }

    fun cancelIncomingCall(ctx: Context) {
        NotificationManagerCompat.from(ctx).cancel(ID_INCOMING_CALL)
    }

    /** The "in a call" notification that keeps the call's foreground service visible. */
    fun ongoingCall(ctx: Context): Notification {
        ensureChannels(ctx)
        val hangup = broadcast(ctx, ACTION_HANGUP, 30)
        val person = Person.Builder().setName("Skwod call").build()
        return NotificationCompat.Builder(ctx, CHANNEL_ONGOING_CALL)
            .setSmallIcon(android.R.drawable.sym_call_outgoing)
            .setContentTitle("Skwod call")
            .setContentText("End-to-end encrypted")
            .setOngoing(true).setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setContentIntent(openApp(ctx, ACTION_OPEN, 31))
            .setStyle(NotificationCompat.CallStyle.forOngoingCall(person, hangup))
            .build()
    }

    /**
     * "Update available" — raised once per new build by the daily check ([Updater.autoCheck]).
     * Tapping it only opens the app, where the update banner offers the install (Android requires
     * the user's own tap on its installer sheet; nothing installs from here).
     */
    fun updateAvailable(ctx: Context, version: String, build: Int) {
        ensureChannels(ctx)
        val n = NotificationCompat.Builder(ctx, CHANNEL_UPDATES)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("Update available")
            .setContentText("Skwod $version ($build) is ready. Tap to open Skwod and update.")
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setContentIntent(openApp(ctx, ACTION_OPEN, 40))
            .build()
        try { NotificationManagerCompat.from(ctx).notify(ID_UPDATE, n) } catch (_: SecurityException) {}
    }

    fun cancelAll(ctx: Context) {
        try { NotificationManagerCompat.from(ctx).cancelAll() } catch (_: Exception) {}
    }
}
